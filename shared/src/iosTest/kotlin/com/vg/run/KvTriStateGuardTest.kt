@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package com.vg.run

import platform.Foundation.NSData
import platform.Foundation.NSUserDefaults
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Regression tests: transient Keychain failures on the
 * credential / DB-key / counter kv reads must NEVER read as "absent".
 *
 * The bug: kvGet/kvContains collapsed every non-success OSStatus (locked keybag
 * errSecInteractionNotAllowed, errSecAuthFailed, …) to nil/false — identical to
 * a genuinely missing item. Downstream that meant: a correct PIN evaluated as
 * WRONG (counting toward the 5-attempt emergency wipe), isConfigured() flipped
 * false on a provisioned install (first-run setup re-provisions OVER the real
 * vault), and purgeHalfCredentialPairIfNeeded() removed live credentials on an ambiguous
 * read. The fix mirrors the device-key path's KeychainLoadResult tri-state:
 * only errSecItemNotFound is "absent"; every other failure surfaces as
 * KeyUnavailableException, which the vault stack already defers on.
 */
class KvTriStateGuardTest {

    /**
     * KeychainBridge fake with per-key fault injection:
     *  - [erroring]: kvGet reports a transient failure (non-notFound status).
     *  - [putFailing]: kvPut silently drops the write (locked-keybag behavior —
     *    the real KeychainHelper.kvPut returns Void and only logs).
     * The device-key path is healthy so CryptoProvider never interferes.
     */
    private class FaultInjectingBridge : KeychainBridge {
        val kv = mutableMapOf<String, String>()
        val erroring = mutableSetOf<String>()
        val putFailing = mutableSetOf<String>()
        val removedKeys = mutableListOf<String>()
        var errorStatus = -25308 // errSecInteractionNotAllowed (device locked)

        private var deviceKey: NSData? = null
        override fun loadKey(): KeychainLoadResult = deviceKey
            ?.let { KeychainLoadResult(data = it, keyMissing = false, status = 0) }
            ?: KeychainLoadResult(data = null, keyMissing = true, status = -25300)
        // Store an INDEPENDENT copy, as the real Keychain does (securityd owns its
        // own copy; SecItemCopyMatching decodes a fresh CFData per read). Aliasing
        // the caller's NSData would hand later loads the buffer getOrCreateKey
        // zeroes after storeKey — i.e. an all-zero device key.
        override fun storeKey(key: NSData) { deviceKey = key.toByteArray().toNSData() }
        override fun deleteKey() { deviceKey = null }

        override fun kvGet(key: String): KvReadResult = when {
            key in erroring -> KvReadResult(value = null, itemMissing = false, status = errorStatus)
            key in kv       -> KvReadResult(value = kv[key], itemMissing = false, status = 0)
            else            -> KvReadResult(value = null, itemMissing = true, status = -25300)
        }
        override fun kvPut(key: String, value: String) {
            if (key !in putFailing) kv[key] = value
        }
        override fun kvRemove(key: String): Boolean { removedKeys.add(key); kv.remove(key); return true }
        override fun kvDeleteAll() { kv.clear() }
    }

    private val defaults = NSUserDefaults.standardUserDefaults

    @AfterTest
    fun tearDown() {
        KeychainBridgeHolder.bridge = null
        defaults.removeObjectForKey(LEGACY_TEST_KEY)
        defaults.synchronize()
    }

    private fun freshStore(bridge: FaultInjectingBridge): KeyValueStore {
        KeychainBridgeHolder.bridge = bridge
        return KeyValueStore()
    }

    // --- KeyValueStore tri-state mechanics ---------------------------------

    @Test
    fun getString_transientError_throwsKeyUnavailable_neverNull() {
        val bridge = FaultInjectingBridge()
        bridge.kv["k"] = "v"          // the item EXISTS…
        bridge.erroring.add("k")      // …but the read glitches
        val store = freshStore(bridge)

        assertFailsWith<KeyUnavailableException> { store.getString("k") }
    }

    @Test
    fun getString_confirmedMissing_returnsNull() {
        val store = freshStore(FaultInjectingBridge())
        assertNull(store.getString("absent_key"))
    }

    @Test
    fun contains_transientError_throws_confirmedMissing_false() {
        val bridge = FaultInjectingBridge()
        bridge.erroring.add("glitchy")
        val store = freshStore(bridge)

        assertFailsWith<KeyUnavailableException> { store.contains("glitchy") }
        assertFalse(store.contains("absent_key"))
    }

    @Test
    fun keychainNativeKey_isNeverServedFromUserDefaults() {
        // The NSUserDefaults fallback is gated to the keys that
        // actually had a pre-Keychain era (IosUserDefaultsKeys.all). vlt_abk (the
        // Lever B auth-bound scheme marker), vlt_rp and vlt_cn are Keychain-native:
        // a planted plist entry must be invisible to both read primitives, or an
        // examiner-writable file can assert vault control state that is supposed to
        // live under kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly.
        val store = freshStore(FaultInjectingBridge())
        for (native in listOf(
            VaultStoreKeys.AUTHBOUND_SCHEME,
            VaultStoreKeys.RECOVERY_PENDING,
            VaultStoreKeys.PENDING_DBKEY,
            VaultStoreKeys.BATCH_JOURNAL,
        )) {
            assertFalse(native in IosUserDefaultsKeys.all,
                "\"$native\" is Keychain-native — it must not be in the legacy fallback list")
            defaults.setObject("planted", native)
            defaults.synchronize()
            try {
                assertNull(store.getString(native),
                    "getString must ignore a planted NSUserDefaults copy of \"$native\"")
                assertFalse(store.contains(native),
                    "contains must ignore a planted NSUserDefaults copy of \"$native\"")
            } finally {
                defaults.removeObjectForKey(native)
                defaults.synchronize()
            }
        }
    }

    @Test
    fun legacyMigration_keepsDefaultsCopy_untilKeychainWriteReadsBack() {
        val bridge = FaultInjectingBridge()
        bridge.putFailing.add(LEGACY_TEST_KEY)
        val store = freshStore(bridge)
        defaults.setObject("legacy-value", LEGACY_TEST_KEY)

        // Keychain write silently fails → the only remaining copy (defaults)
        // must survive; the read still serves the legacy value.
        assertEquals("legacy-value", store.getString(LEGACY_TEST_KEY))
        assertEquals("legacy-value", defaults.stringForKey(LEGACY_TEST_KEY))

        // Once the Keychain write lands, the defaults copy is dropped.
        bridge.putFailing.remove(LEGACY_TEST_KEY)
        assertEquals("legacy-value", store.getString(LEGACY_TEST_KEY))
        assertEquals("legacy-value", bridge.kv[LEGACY_TEST_KEY])
        assertNull(defaults.stringForKey(LEGACY_TEST_KEY))
    }

    // --- VaultSelector destructive-path guards ---

    private fun vaultSelector(bridge: FaultInjectingBridge): VaultSelector =
        VaultSelector(
            store        = freshStore(bridge),
            crypto       = CryptoProvider(),  // lazy; healthy device key
            vaultFactory = object : VaultFactory {
                override fun create(dbKey: ByteArray, isProvision: Boolean): VaultDatabase =
                    throw IllegalStateException("vault must not be opened")
                // These tests never provision, so the guard's probe must never be
                // consulted either — assert that rather than returning a value.
                override fun vaultFileExists(): Boolean =
                    throw IllegalStateException("vault file must not be probed")
                // PROVISION-1: same rule for the rollback's unlink — these tests never
                // provision, so nothing may ever delete a vault file behind them.
                override fun deleteVaultFileAfterFailedProvision(): Unit =
                    throw IllegalStateException("vault file must not be deleted")
                // Same rule for the key probe: these tests never touch the vault.
                override fun probeKey(dbKey: ByteArray): Boolean =
                    throw IllegalStateException("vault key must not be probed")
            },
        )

    @Test
    fun isConfigured_transientDbKeyRead_reportsConfigured_andNeverPurges() {
        val bridge = FaultInjectingBridge()
        bridge.kv[VaultStoreKeys.CREDENTIAL_VERIFIER] = "cred-blob"
        bridge.kv[VaultStoreKeys.WRAPPED_DBKEY] = "dbkey-blob"
        bridge.erroring.add(VaultStoreKeys.WRAPPED_DBKEY)
        val selector = vaultSelector(bridge)

        // Scenario 2: must NOT flip to "not configured" (→ re-provision over
        // the real vault) on an ambiguous read.
        assertTrue(selector.isConfigured())

        // Scenario 3: purgeHalfCredentialPairIfNeeded must NOT remove live credentials when
        // the DB-key read was a glitch, not a confirmed absence.
        assertFalse(VaultStoreKeys.CREDENTIAL_VERIFIER in bridge.removedKeys)
        assertFalse(VaultStoreKeys.WRAPPED_DBKEY in bridge.removedKeys)
        assertEquals("cred-blob", bridge.kv[VaultStoreKeys.CREDENTIAL_VERIFIER])
    }

    @Test
    fun isConfigured_confirmedAbsent_stillReportsUnconfigured() {
        // Sanity: a genuinely fresh install must still reach first-run setup.
        assertFalse(vaultSelector(FaultInjectingBridge()).isConfigured())
    }

    @Test
    fun unlock_transientCredentialRead_returnsError_notDenied() {
        val bridge = FaultInjectingBridge()
        bridge.kv[VaultStoreKeys.CREDENTIAL_VERIFIER] = "cred-blob"
        bridge.kv[VaultStoreKeys.WRAPPED_DBKEY] = "dbkey-blob"
        bridge.erroring.add(VaultStoreKeys.CREDENTIAL_VERIFIER)
        val selector = vaultSelector(bridge)

        // Scenario 1: a transient read failure on the stored verifier is NOT a
        // wrong PIN — Denied would count toward the 5-attempt emergency wipe.
        assertEquals(VaultSelector.UnlockResult.Error, selector.unlock("111111"))
    }

    @Test
    fun verifyCredential_transientRead_reportsFalse_withoutThrowing() {
        val bridge = FaultInjectingBridge()
        bridge.kv[VaultStoreKeys.CREDENTIAL_VERIFIER] = "cred-blob"
        bridge.erroring.add(VaultStoreKeys.CREDENTIAL_VERIFIER)
        val selector = vaultSelector(bridge)
        selector.changePinMinDelayMs = 0L  // test-only: skip the anti-probe delay

        // The change-PIN gate defers (benign false) and must not let the Kotlin
        // exception cross the non-@Throws Swift boundary.
        assertFalse(selector.verifyCredential("111111"))
    }

    private companion object {
        // Must be a key with a REAL pre-Keychain UserDefaults era — the fallback
        // is now gated to IosUserDefaultsKeys.all, so an invented key (the old
        // "m1_tristate_test_legacy_key") would no longer exercise the migration
        // at all. The pre-v2 plaintext PIN counter is in the list and nothing
        // else in this suite touches it.
        val LEGACY_TEST_KEY = IosUserDefaultsKeys.PIN_FAILED_ATTEMPTS_LEGACY
    }
}
