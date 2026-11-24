@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package com.vg.run

import platform.Foundation.NSData
import platform.Foundation.NSFileManager
import platform.Foundation.NSTemporaryDirectory
import platform.Foundation.NSUUID
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * RÚN-02 on iOS, with the REAL CryptoProvider:
 *  - every Kotlin consumer Swift reaches through a NON-@Throws bridge absorbs the
 *    refused mint (device key missing + erase unresolved ⇒ KeyUnavailableException)
 *    instead of letting it cross into Swift, where it would abort the process;
 *  - the Keychain delete classification Swift delegates to Kotlin;
 *  - the post-wipe residue rule against real directory state.
 */
class IosWipeEraseConsumersTest {

    /** Device key MISSING (so getOrCreateKey would mint); kv items present. */
    private class MissingKeyBridge : KeychainBridge {
        val kv = mutableMapOf<String, String>()
        var stores = 0
        override fun loadKey(): KeychainLoadResult = KeychainLoadResult(data = null, keyMissing = true, status = -25300)
        override fun storeKey(key: NSData) { stores++ }
        override fun deleteKey() = Unit
        override fun deleteKeyChecked(): KeychainDeleteResult = KeychainDeleteResult(1, -25300)
        override fun kvDeleteAllChecked(): KeychainDeleteResult = KeychainDeleteResult(1, -25300)
        override fun deleteBlockListChecked(): KeychainDeleteResult = KeychainDeleteResult(1, -25300)
        override fun kvGet(key: String): KvReadResult =
            if (key in kv) KvReadResult(kv[key], itemMissing = false, status = 0)
            else KvReadResult(null, itemMissing = true, status = -25300)
        override fun kvPut(key: String, value: String) { kv[key] = value }
        override fun kvRemove(key: String): Boolean { kv.remove(key); return true }
        override fun kvDeleteAll() { kv.clear() }
    }

    private lateinit var bridge: MissingKeyBridge
    private val fm = NSFileManager.defaultManager
    private lateinit var dir: String

    @BeforeTest
    fun setUp() {
        bridge = MissingKeyBridge()
        KeychainBridgeHolder.bridge = bridge
        WipeEraseLatch.begin()   // a wipe in flight ⇒ every mint is refused
        dir = NSTemporaryDirectory() + "run02c-" + NSUUID().UUIDString
        fm.createDirectoryAtPath(dir, withIntermediateDirectories = true, attributes = null, error = null)
    }

    @AfterTest
    fun tearDown() {
        KeychainBridgeHolder.bridge = null
        WipeEraseLatch.resetForTest()
        fm.removeItemAtPath(dir, null)
    }

    @Test
    fun pinAttemptCounters_nonThrowsEntryPoints_absorbTheRefusal() {
        bridge.kv[PinAttemptsStore.STORAGE_KEY] = encodeBase64(ByteArray(40))
        val pins = PinAttemptsStore(KeyValueStore(), CryptoProvider())
        // Swift calls these WITHOUT `try` (non-@Throws): they must not throw.
        assertFalse(pins.tryWrite(1))
        pins.reset()
        pins.recordWrongAttemptInWindowAndCheckLimit()
        assertFalse(pins.establishVerified())
        // The @Throws reader surfaces the catchable defer type (Swift `try`s it).
        assertFailsWith<KeyUnavailableException> { pins.readOrNullOnTamper() }
        assertEquals(0, bridge.stores, "no key was minted along the way")
    }

    @Test
    fun debugModeAndPushConsent_absorbTheRefusal() {
        bridge.kv[DebugMode.KEY] = "c2VhbGVkLWJ5LWEtZ29uZS1rZXktMDEyMzQ1Njc4OWFi"
        val store = KeyValueStore()
        assertFalse(DebugMode.isEnabled(store, CryptoProvider()))
        DebugMode.applyAtStartup(store, CryptoProvider())        // RunApp.init
        assertEquals(NotificationLevel.OFF, NotificationLevelStore.provenLevel(store, CryptoProvider(), null, null))
        NotificationLevelStore.clearLevel(store, CryptoProvider(), null)
        assertEquals(0, bridge.stores)
    }

    @Test
    fun vaultSelectorReaders_absorbTheRefusal_andNeverReportOrphaned() {
        bridge.kv[VaultStoreKeys.CREDENTIAL_VERIFIER] = "Y3JlZC1ibG9iLXNlYWxlZC1ieS1hLWdvbmUta2V5"
        bridge.kv[VaultStoreKeys.WRAPPED_DBKEY] = "ZGJrZXktYmxvYi1zZWFsZWQtYnktYS1nb25lLWtleQ"
        val vs = VaultSelector(
            store = KeyValueStore(),
            crypto = CryptoProvider(),
            vaultFactory = object : VaultFactory {
                override fun create(dbKey: ByteArray, isProvision: Boolean): VaultDatabase = error("no open")
                override fun vaultFileExists(): Boolean = true
                override fun deleteVaultFileAfterFailedProvision() = error("no delete")
                override fun probeKey(dbKey: ByteArray): Boolean = false
            },
        )
        assertTrue(vs.credentialsReadable(), "a refused key defers the orphan check — never a wipe")
        vs.isPassphraseMode(); vs.credentialKindProven(); vs.protectionLevelOrNull()
        vs.protectionLevelForFloorCheck(); vs.protectionLevelForEnforcement(); vs.maximumShieldLevel()
        vs.maxConsecutiveAttemptsForInterruptedWipe(); vs.currentProtectionLevel(); vs.displayProtectionLevel()
        vs.isDbKeyAuthBound(); vs.hasRecoveryCode(); vs.needsLeverBReharden()
        assertFalse(vs.setProtectionLevel(ProtectionLevel.MAXIMUM))
        assertEquals(VaultSelector.UnlockResult.Error, vs.unlock("482913"))
        assertEquals(0, bridge.stores)
    }

    @Test
    fun keychainDeleteClassification_matchesTheContract() {
        fun c(d: Int, p: Int) = classifyKeychainDelete(d, p).toEraseResult()
        assertEquals(EraseResult(EraseOutcome.DELETED, 0), c(0, -25300))
        assertEquals(EraseResult(EraseOutcome.ALREADY_ABSENT, -25300), c(-25300, -25300))
        assertEquals(EraseResult(EraseOutcome.UNRESOLVED, -25308), c(-25308, -25300), "refused delete, probe 'absent'")
        assertEquals(EraseResult(EraseOutcome.UNRESOLVED, -25308), c(0, -25308), "probe could not answer")
        assertEquals(EraseResult(EraseOutcome.UNRESOLVED, 0), c(0, 0), "still visible after a 'successful' delete")
        assertEquals(EraseResult(EraseOutcome.UNRESOLVED, -34018), c(-34018, 0))

        val del = KeychainDeleteResult(0, 0)
        val abs = KeychainDeleteResult(1, -25300)
        val bad = KeychainDeleteResult(2, -25308)
        assertEquals(EraseOutcome.UNRESOLVED, combineKeychainDeletes(del, bad).toEraseResult().outcome)
        assertEquals(EraseOutcome.UNRESOLVED, combineKeychainDeletes(bad, abs).toEraseResult().outcome)
        assertEquals(EraseOutcome.DELETED, combineKeychainDeletes(abs, del).toEraseResult().outcome)
        assertEquals(EraseOutcome.ALREADY_ABSENT, combineKeychainDeletes(abs, abs).toEraseResult().outcome)
        assertEquals(EraseOutcome.UNRESOLVED, combineKeychainDeletes(KeychainDeleteResult(9, 0), del).toEraseResult().outcome)
    }

    @Test
    fun postWipeResidue_againstRealDirectories() {
        fun residue(dirs: List<String?>) =
            WipeErasePolicy.postWipeResidue(credentialPair = true, iosVaultFilesPresence(dirs) == false, journalConfirmedAbsent = true)
        fm.createFileAtPath("$dir/run.db", contents = null, attributes = null)
        assertFalse(residue(listOf(dir)), "credentials + a vault file ⇒ NEVER erased")
        assertFalse(residue(listOf("$dir/empty", dir)), "a file in EITHER directory ⇒ never erased")
        fm.removeItemAtPath("$dir/run.db", null)
        assertFalse(residue(listOf(dir, null)), "a directory that cannot be resolved ⇒ never erased")
        assertTrue(residue(listOf(dir)), "proven absent everywhere ⇒ the residue rule")
    }
}
