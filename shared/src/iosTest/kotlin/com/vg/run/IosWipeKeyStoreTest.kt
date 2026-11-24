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
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * RÚN-02: the iOS [WipeKeyStore] over the Swift bridges and NSFileManager. The
 * bridge result codes map to [EraseOutcome] exactly; an unregistered bridge holder is
 * UNRESOLVED, never the old silent `bridge?.deleteKey()` skip; the vault-file erase
 * proves absence in a real directory.
 */
class IosWipeKeyStoreTest {

    private class ScriptedKeychain(
        var device: KeychainDeleteResult = KeychainDeleteResult(0, 0),
        var sweep: KeychainDeleteResult = KeychainDeleteResult(0, 0),
        var blockList: KeychainDeleteResult = KeychainDeleteResult(1, -25300),
    ) : KeychainBridge {
        override fun loadKey(): KeychainLoadResult = KeychainLoadResult(data = null, keyMissing = true, status = -25300)
        override fun storeKey(key: NSData) = Unit
        override fun deleteKey() = Unit
        override fun deleteKeyChecked(): KeychainDeleteResult = device
        override fun kvDeleteAllChecked(): KeychainDeleteResult = sweep
        override fun deleteBlockListChecked(): KeychainDeleteResult = blockList
        override fun kvGet(key: String): KvReadResult = KvReadResult(value = null, itemMissing = true, status = -25300)
        override fun kvPut(key: String, value: String) = Unit
        override fun kvRemove(key: String): Boolean = true
        override fun kvDeleteAll() = Unit
    }

    private class ScriptedEnclave(var result: KeychainDeleteResult = KeychainDeleteResult(1, -25300)) : SecureEnclaveBridge {
        override fun isAvailable(): Boolean = false
        override fun ensureKey(): Boolean = false
        override fun wrap(data: NSData): NSData? = null
        override fun unwrap(data: NSData): NSData? = null
        override fun isKeyPresent(): Boolean = false
        override fun deleteKey() = Unit
        override fun deleteKeyChecked(): KeychainDeleteResult = result
    }

    private val fm = NSFileManager.defaultManager
    private lateinit var dir: String

    @BeforeTest
    fun setUp() {
        dir = NSTemporaryDirectory() + "run02-" + NSUUID().UUIDString
        fm.createDirectoryAtPath(dir, withIntermediateDirectories = true, attributes = null, error = null)
    }

    @AfterTest
    fun tearDown() {
        KeychainBridgeHolder.bridge = null
        SecureEnclaveBridgeHolder.bridge = null
        fm.removeItemAtPath(dir, null)
    }

    private fun touch(path: String) {
        fm.createFileAtPath(path, contents = null, attributes = null)
    }

    @Test
    fun bridgeResultCodes_mapToEraseOutcomes() {
        val kc = ScriptedKeychain()
        val se = ScriptedEnclave()
        KeychainBridgeHolder.bridge = kc
        SecureEnclaveBridgeHolder.bridge = se
        val store = IosWipeKeyStore(protectedData = { true }, vaultDirs = { listOf(dir) })

        for ((code, outcome) in listOf(0 to EraseOutcome.DELETED, 1 to EraseOutcome.ALREADY_ABSENT,
                2 to EraseOutcome.UNRESOLVED, 7 to EraseOutcome.UNRESOLVED)) {
            kc.device = KeychainDeleteResult(code, -1234)
            kc.sweep = KeychainDeleteResult(code, -1234)
            kc.blockList = KeychainDeleteResult(code, -1234)
            se.result = KeychainDeleteResult(code, -1234)
            for (item in listOf(WipeItem.DEVICE_KEY, WipeItem.HARDWARE_KEY, WipeItem.KV_SWEEP, WipeItem.BLOCK_LIST)) {
                val r = store.erase(item)
                assertEquals(outcome, r.outcome, "$item code=$code")
                assertEquals(-1234, r.status, "the OSStatus survives the bridge")
            }
        }
    }

    @Test
    fun anUnregisteredBridge_isUnresolved_neverASkip() {
        val store = IosWipeKeyStore(protectedData = { true }, vaultDirs = { listOf(dir) })
        for (item in listOf(WipeItem.DEVICE_KEY, WipeItem.HARDWARE_KEY, WipeItem.KV_SWEEP, WipeItem.BLOCK_LIST)) {
            assertEquals(EraseResult.unresolved(EraseResult.STATUS_NO_BRIDGE), store.erase(item), "$item")
        }
        val report = WipeEraser.run(store, WipeItem.entries.toList(), passes = 1)
        assertFalse(report.complete, "a wipe with no bridge can never report completion")
    }

    @Test
    fun vaultFiles_deletedThenAlreadyAbsent_inEveryDirectory() {
        val other = "$dir/caches"
        fm.createDirectoryAtPath(other, withIntermediateDirectories = true, attributes = null, error = null)
        touch("$dir/run.db"); touch("$dir/run.db-journal"); touch("$other/run_b.db-wal")
        assertEquals(true, iosVaultFilesPresence(listOf(dir, other)))

        val first = iosDeleteAllVaultFiles(listOf(dir, other))
        assertEquals(EraseOutcome.DELETED, first.outcome)
        assertFalse(fm.fileExistsAtPath("$dir/run.db"))
        assertFalse(fm.fileExistsAtPath("$dir/run.db-journal"))
        assertFalse(fm.fileExistsAtPath("$other/run_b.db-wal"))

        assertEquals(EraseOutcome.ALREADY_ABSENT, iosDeleteAllVaultFiles(listOf(dir, other)).outcome, "idempotent")
        assertEquals(false, iosVaultFilesPresence(listOf(dir, other)), "confirmed absent in both")
    }

    @Test
    fun vaultFilePresence_isNeverAbsentWhenADirectoryIsUnresolvable() {
        assertNull(iosVaultFilesPresence(listOf(dir, null)), "an unresolved directory proves nothing")
        assertEquals(false, iosVaultFilesPresence(listOf(dir)))
        assertEquals(false, iosPathPresence("$dir/nothing-here"))
        assertTrue(iosPathPresence(dir) == true)
    }
}
