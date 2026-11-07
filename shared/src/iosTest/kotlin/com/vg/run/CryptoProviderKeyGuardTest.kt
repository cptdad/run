@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package com.vg.run

import platform.Foundation.NSData
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Regression tests for the locked-device key-destruction bug.
 *
 * The bug: getOrCreateKey() treated ANY failed Keychain read as "no key" and
 * deleted + regenerated, so launching while the device was locked
 * (errSecInteractionNotAllowed) crypto-erased the vault. The fix only
 * regenerates when the item is GENUINELY absent (errSecItemNotFound); any
 * other status must NOT delete or regenerate.
 */
class CryptoProviderKeyGuardTest {

    private class FakeKeychainBridge(var result: KeychainLoadResult) : KeychainBridge {
        var deleteCalls = 0
        var storeCalls = 0
        /** The bridge-boundary NSData getOrCreateKey handed us, kept so the
         *  test can assert it was zeroed once the call returned. */
        var lastStoredData: NSData? = null
        override fun loadKey(): KeychainLoadResult = result
        override fun storeKey(key: NSData) {
            storeCalls++
            lastStoredData = key
            // Subsequent loads (incl. getOrCreateKey's verify step) see the new key.
            // Deliberately the SAME NSData — the most adversarial aliasing model, so
            // a memset placed before the verify read would fail the provision loudly.
            result = KeychainLoadResult(data = key, keyMissing = false, status = 0)
        }
        override fun deleteKey() { deleteCalls++ }

        // Generic keyed storage — not exercised by this device-key guard test;
        // an in-memory map keeps the KeychainBridge contract satisfiable so the
        // iosTest module compiles (these were added to the interface after this
        // fake was written).
        private val kv = mutableMapOf<String, String>()
        override fun kvGet(key: String): KvReadResult =
            KvReadResult(value = kv[key], itemMissing = key !in kv, status = if (key in kv) 0 else -25300)
        override fun kvPut(key: String, value: String) { kv[key] = value }
        override fun kvRemove(key: String): Boolean { kv.remove(key); return true }
        override fun kvDeleteAll() { kv.clear() }
    }

    @AfterTest
    fun tearDown() { KeychainBridgeHolder.bridge = null }

    // Security framework status codes: errSecItemNotFound = -25300,
    // errSecInteractionNotAllowed (device locked) = -25308.

    @Test
    fun lockedDevice_refusesToRegenerate() {
        val fake = FakeKeychainBridge(
            KeychainLoadResult(data = null, keyMissing = false, status = -25308)
        )
        KeychainBridgeHolder.bridge = fake

        assertFailsWith<KeyUnavailableException> { getOrCreateKey() }
        assertEquals(0, fake.deleteCalls, "must NOT delete the (possibly still-present) key while locked")
        assertEquals(0, fake.storeCalls, "must NOT regenerate the key while locked")
    }

    @Test
    fun genuinelyMissing_generatesAndStores() {
        val fake = FakeKeychainBridge(
            KeychainLoadResult(data = null, keyMissing = true, status = -25300)
        )
        KeychainBridgeHolder.bridge = fake

        val key = getOrCreateKey()
        assertEquals(32, key.size, "first-run key must be 32 bytes")
        assertEquals(1, fake.storeCalls, "first run must store a freshly generated key")
    }

    @Test
    fun existingKey_returnedWithoutRegeneration() {
        val existing = ByteArray(32) { it.toByte() }
        val fake = FakeKeychainBridge(
            KeychainLoadResult(data = existing.toNSData(), keyMissing = false, status = 0)
        )
        KeychainBridgeHolder.bridge = fake

        val key = getOrCreateKey()
        assertTrue(key.contentEquals(existing), "must return the existing key unchanged")
        assertEquals(0, fake.storeCalls)
        assertEquals(0, fake.deleteCalls)
    }

    /**
     * The NSData carrying the freshly generated ROOT
     * device key into storeKey() is a private toNSData() copy this module OWNS;
     * ARC frees it WITHOUT zeroing, so it used to leave the at-rest root key
     * legible in a freed heap block on every first run / post-wipe re-provision.
     * (The NSData that loadKey() RETURNS is Security.framework's, not ours, and is
     * deliberately NOT wiped: we do not own that buffer.)
     *
     * Three properties; the last two are the brick guards:
     *  1. the bridge-boundary copy is all-zero once getOrCreateKey() has returned;
     *  2. the key RETURNED is the real random 32 bytes, not the zeroed buffer — a
     *     wipe-before-copy regression would key every vault with all-zero material;
     *  3. the store-verify still succeeds, i.e. the memset lands strictly AFTER the
     *     read-back (the fake aliases the stored NSData into the verify result, so a
     *     wipe placed before the verify would fail provisioning outright).
     */
    @Test
    fun firstRun_wipesTheDeviceKeyBridgeCopy_strictlyAfterStoreAndVerify() {
        val fake = FakeKeychainBridge(
            KeychainLoadResult(data = null, keyMissing = true, status = -25300)
        )
        KeychainBridgeHolder.bridge = fake

        val key = getOrCreateKey()

        assertEquals(1, fake.storeCalls, "store-verify must succeed — the wipe must not precede the verify read")
        assertEquals(32, key.size, "first-run key must be 32 bytes")
        assertTrue(key.any { it != 0.toByte() }, "returned device key must be the real key, not the zeroed buffer")

        val stored = fake.lastStoredData!!.toByteArray()
        assertEquals(32, stored.size, "fake captured no bytes — the test would prove nothing")
        assertTrue(
            stored.all { it == 0.toByte() },
            "the toNSData() copy of the ROOT device key must be zeroed once getOrCreateKey has returned"
        )
    }

    /**
     * Integration guard: a locked device must surface KeyUnavailableException
     * all the way up through PinAttemptsStore.read() — NOT a TamperException —
     * so the unlock screens defer instead of wiping the vault.
     */
    @Test
    fun pinAttemptsRead_whileLocked_surfacesKeyUnavailable_notTamper() {
        KeychainBridgeHolder.bridge = FakeKeychainBridge(
            KeychainLoadResult(data = null, keyMissing = false, status = -25308))
        val store = KeyValueStore()                 // no-arg per IosAppController
        store.putString(PinAttemptsStore.STORAGE_KEY, encodeBase64(ByteArray(40)))
        val crypto = CryptoProvider()               // lazy; loads key on first use
        try {
            assertFailsWith<KeyUnavailableException> {
                PinAttemptsStore(store, crypto).read()
            }
        } finally {
            store.remove(PinAttemptsStore.STORAGE_KEY)
        }
    }
}
