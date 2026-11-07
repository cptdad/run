@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package com.vg.run

import platform.Foundation.NSArray
import platform.Foundation.NSData
import platform.Foundation.NSFileManager
import platform.Foundation.NSMutableArray
import platform.Foundation.NSMutableDictionary
import platform.Foundation.NSNumber
import platform.Foundation.NSString
import platform.Foundation.numberWithLongLong
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The iOS half of the SQLCipher DB-key rotation, driven
 * through the REAL [VaultSelector], the REAL [KeyValueStore] (Keychain-backed),
 * the REAL [IosVaultDatabase] and the REAL [iosProbeVaultKey].
 *
 * These three properties exist ONLY on iOS and had zero live coverage:
 *
 *  1. **The promotion's read-back gate.** `kvPut` no-ops SILENTLY on a locked
 *     keybag while `kvRemove` — a bare `SecItemDelete` needing no class key —
 *     succeeds unconditionally. A promotion that dropped its `vlt_c` write and
 *     then removed `vlt_cn` would leave the OLD key over a NEW-key file with the
 *     only record of the new key deleted: a permanent, total brick.
 *  2. **The rolled-back re-key.** `sqlite3_rekey_v2` returns SQLITE_OK on its
 *     ROLLBACK branch too, after installing the new key in the codec's WRITE
 *     context of the still-live handle and never undoing it — so the file can
 *     still move to the new key on the next commit. `vlt_cn` must therefore
 *     survive a probe-reported rollback.
 *  3. `IosVaultDatabase.rekey` and `iosProbeVaultKey` themselves.
 *
 * The Swift/SQLCipher layer is replaced by a scriptable [FakeDbBridge] holding one
 * piece of state — WHICH KEY THE FILE IS ON — because that is the only thing the
 * whole design reasons about. Everything above it (credential KDF, AEAD wraps, the
 * store, the reconcile, the probes) is the shipped code. The AES-GCM and Argon2
 * bridges are deterministic stand-ins with real AEAD semantics (a wrong key or a
 * flipped byte fails the tag), which is what the vault logic depends on.
 */
class IosDbKeyRotationTest {

    // ---------------------------------------------------------------- fakes --

    /** Keychain KV with the two field failure modes: silent put, transient read. */
    private class TestKeychainBridge : KeychainBridge {
        val kv = mutableMapOf<String, String>()
        /** Keys whose `kvPut` silently does nothing — the locked-keybag behaviour. */
        val putFailing = mutableSetOf<String>()

        private var deviceKey: NSData? = null
        override fun loadKey(): KeychainLoadResult = deviceKey
            ?.let { KeychainLoadResult(data = it, keyMissing = false, status = 0) }
            ?: KeychainLoadResult(data = null, keyMissing = true, status = -25300)
        override fun storeKey(key: NSData) { deviceKey = key.toByteArray().toNSData() }
        override fun deleteKey() { deviceKey = null }

        override fun kvGet(key: String): KvReadResult =
            if (key in kv) KvReadResult(kv[key], itemMissing = false, status = 0)
            else KvReadResult(null, itemMissing = true, status = -25300)
        override fun kvPut(key: String, value: String) { if (key !in putFailing) kv[key] = value }
        override fun kvRemove(key: String): Boolean { kv.remove(key); return true }
        override fun kvDeleteAll() { kv.clear() }
    }

    /**
     * Deterministic AEAD with the properties the vault relies on: a wrong key or a
     * tampered byte fails to open, and every seal is unique. NOT AES — it stands in
     * for CryptoKit, which cannot be linked into this test binary.
     */
    private class FakeAesGcm : AesGcmBridge {
        private var seq = 0L

        private fun keystream(key: ByteArray, iv: ByteArray, aad: ByteArray, len: Int): ByteArray {
            var out = ByteArray(0)
            var block = 0
            while (out.size < len) {
                out += sha256(key + iv + aad + byteArrayOf(block.toByte()))
                block++
            }
            return out.copyOfRange(0, len)
        }

        private fun tag(key: ByteArray, iv: ByteArray, aad: ByteArray, ct: ByteArray): ByteArray =
            sha256(key + iv + aad + ct + "tag".encodeToByteArray()).copyOfRange(0, 16)

        override fun encrypt(plaintext: NSData, key: NSData, aad: NSData): NSData {
            val pt = plaintext.toByteArray()
            val k = key.toByteArray()
            val a = aad.toByteArray()
            seq++
            val iv = sha256("iv".encodeToByteArray() + seq.toString().encodeToByteArray()).copyOfRange(0, 12)
            val ks = keystream(k, iv, a, pt.size)
            val ct = ByteArray(pt.size) { (pt[it].toInt() xor ks[it].toInt()).toByte() }
            return (iv + ct + tag(k, iv, a, ct)).toNSData()
        }

        override fun decrypt(ciphertext: NSData, key: NSData, aad: NSData): NSData? {
            val c = ciphertext.toByteArray()
            if (c.size < 28) return null
            val iv = c.copyOfRange(0, 12)
            val ct = c.copyOfRange(12, c.size - 16)
            val mac = c.copyOfRange(c.size - 16, c.size)
            val k = key.toByteArray()
            val a = aad.toByteArray()
            if (!tag(k, iv, a, ct).contentEquals(mac)) return null   // wrong key / tampered
            val ks = keystream(k, iv, a, ct.size)
            return ByteArray(ct.size) { (ct[it].toInt() xor ks[it].toInt()).toByte() }.toNSData()
        }
    }

    /** Deterministic KDF stand-in — cost parameters are irrelevant to this logic. */
    private class FakeArgon2 : Argon2Bridge {
        override fun argon2id(
            password: NSData, salt: NSData,
            memoryKiB: Int, iterations: Int, parallelism: Int, keyLength: Int,
        ): NSData? {
            var out = ByteArray(0)
            var block = 0
            while (out.size < keyLength) {
                out += sha256(password.toByteArray() + salt.toByteArray() + byteArrayOf(block.toByte()))
                block++
            }
            return out.copyOfRange(0, keyLength).toNSData()
        }
    }

    /** What the scripted [FakeDbBridge.rekey] does. */
    private enum class RekeyScript {
        /** The page rewrite committed: the file really moves to the new key. */
        COMMIT,
        /** The ROLLBACK branch: SQLITE_OK is returned, the file does NOT move — and
         *  the new key stays installed in the write context ([VaultFile.poisonedKey]). */
        ROLLBACK,
        /** A visible error (non-zero result code). */
        ERROR,
    }

    /** The only state the rotation design reasons about: which key opens the file. */
    private class VaultFile {
        var key: ByteArray? = null            // null = not yet created
        var script = RekeyScript.COMMIT
        /** The key a rolled-back re-key left in the live handle's WRITE context. */
        var poisonedKey: ByteArray? = null
        var rekeyCalls = 0
        var lastRekeyKey: ByteArray? = null
        /** The bridge the re-key ran on — i.e. the LIVE session handle (probes and
         *  later unlocks each get their own bridge and must not be mistaken for it). */
        var rekeyedBridge: Any? = null
        /** True once that live handle was closed — the review-2026-08-03 retire. */
        var liveHandleClosedAfterRekey = false

        /**
         * The poisoned write context finally reaching the file (the next commit).
         * Only an OPEN handle can commit — after the retire this
         * is a no-op, which is the fix's whole point.
         */
        fun applyPoisonedWrite() { if (!liveHandleClosedAfterRekey) key = poisonedKey?.copyOf() }

        /** The one window the retire cannot cover: a commit already in flight when
         *  the re-key returned, landing BEFORE the close. Bypasses the open-handle
         *  check deliberately — the kept `vlt_cn` record is what recovers this. */
        fun applyRacingPoisonedWrite() { key = poisonedKey?.copyOf() }
    }

    private class FakeDbBridge(private val file: VaultFile) : DatabaseBridge {
        override fun open(path: String, key: ByteArray): Int {
            val current = file.key
            if (current == null) {          // provision open: CREATE semantics
                file.key = key.copyOf()
                return 0
            }
            return if (key.contentEquals(current)) 0 else 26   // SQLITE_NOTADB
        }

        override fun rekey(key: ByteArray): Int {
            file.rekeyCalls++
            file.lastRekeyKey = key.copyOf()
            file.rekeyedBridge = this
            return when (file.script) {
                RekeyScript.COMMIT -> { file.key = key.copyOf(); 0 }
                // SQLITE_OK on the rollback branch — the lie the whole design assumes.
                RekeyScript.ROLLBACK -> { file.poisonedKey = key.copyOf(); 0 }
                RekeyScript.ERROR -> 1
            }
        }

        override fun execute(sql: String, params: NSArray): Boolean = true

        override fun query(sql: String, params: NSArray): NSArray {
            val rows = NSMutableArray()
            when {
                sql.contains("cipher_version") -> {
                    val row = NSMutableDictionary()
                    row.setObject("4.6.1-fake" as NSString, forKey = "cipher_version" as NSString)
                    rows.addObject(row)
                }
                sql.contains("count(*)") -> {
                    val row = NSMutableDictionary()
                    row.setObject(NSNumber.numberWithLongLong(7L), forKey = "n" as NSString)
                    rows.addObject(row)
                }
            }
            return rows
        }

        override fun close() {
            if (file.rekeyedBridge === this) file.liveHandleClosedAfterRekey = true
        }
    }

    // -------------------------------------------------------------- fixture --

    private val file = VaultFile()
    private lateinit var keychain: TestKeychainBridge
    /** How many times the selector fired [VaultSelector]'s onRekeyHandleRetired —
     *  the "session must re-lock" signal. */
    private var retiredCount = 0

    private fun installBridges() {
        keychain = TestKeychainBridge()
        KeychainBridgeHolder.bridge = keychain
        AesGcmBridgeHolder.bridge = FakeAesGcm()
        Argon2BridgeHolder.bridge = FakeArgon2()
        DatabaseBridgeHolder.factory = DatabaseBridgeFactory { FakeDbBridge(file) }
        file.key = null
        file.script = RekeyScript.COMMIT
        file.poisonedKey = null
        file.rekeyCalls = 0
        file.lastRekeyKey = null
        file.rekeyedBridge = null
        file.liveHandleClosedAfterRekey = false
        retiredCount = 0
    }

    private fun deleteVaultFiles() {
        val fm = NSFileManager.defaultManager
        for (suffix in listOf("", "-wal", "-shm", "-journal")) {
            fm.removeItemAtPath(iosVaultDbPath() + suffix, null)
        }
    }

    /** A file large enough to pass the #28 size guards — its CONTENT is irrelevant,
     *  the fake bridge decides which key opens it. */
    private fun materialiseVaultFile() {
        NSFileManager.defaultManager.createFileAtPath(
            iosVaultDbPath(),
            contents = ByteArray(2048) { 0x42 }.toNSData(),
            attributes = null,
        )
    }

    private fun selector(vault: VaultDatabase? = null): VaultSelector =
        VaultSelector(
            store = KeyValueStore(),
            crypto = CryptoProvider(),
            vaultFactory = iosVaultFactory(),
            vaultProvider = { vault },
            onRekeyHandleRetired = { retiredCount++ },
        ).apply { changePinMinDelayMs = 0L }

    /** Provision a plain PIN vault and leave a real (dummy) file on disk. */
    private fun provisionPinVault(): VaultSelector {
        installBridges()
        deleteVaultFiles()
        val vs = selector()
        assertTrue(
            vs.setRealCredential(PIN, passphraseMode = false, level = ProtectionLevel.CASUAL),
            "fixture: provision must succeed",
        )
        // The provision open created the "file" in the fake; give the real size guards
        // something to see (unlock refuses to open a missing/truncated vault).
        materialiseVaultFile()
        return vs
    }

    /** Unlock, keep the handle, and drive the tier upgrade that triggers the rotation. */
    private fun upgradeToPassphrase(vs: VaultSelector): VaultDatabase {
        val opened = vs.unlock(PIN)
        assertTrue(opened is VaultSelector.UnlockResult.Opened, "fixture: the PIN must open the vault")
        val live = (opened as VaultSelector.UnlockResult.Opened).vault
        assertEquals(
            VaultSelector.ChangePinResult.SUCCESS,
            selector(live).changeCredentialAndMode(PIN, PHRASE, newModePassphrase = true),
            "fixture: the tier upgrade must report SUCCESS",
        )
        return live
    }

    @AfterTest
    fun tearDown() {
        deleteVaultFiles()
        KeychainBridgeHolder.bridge = null
        AesGcmBridgeHolder.bridge = null
        Argon2BridgeHolder.bridge = null
        DatabaseBridgeHolder.factory = null
    }

    // ------------------------------------------------- the promotion's gate --

    /**
     * THE iOS-only brick, and the reason `promotePendingRotation` reads back before
     * it removes anything: the `vlt_c` write is silently dropped (locked keybag)
     * while `remove` would still succeed. Removing `vlt_cn` there leaves `vlt_c`
     * holding the OLD key over a NEW-key file, with the only record of the new key
     * deleted — permanently unopenable.
     */
    @Test
    fun promotionWhoseVltCWriteIsSilentlyDropped_keepsThePendingRecord_andStaysOpenable() {
        // Reach the state a promotion is needed in: an unresolved record over a file
        // that is on the PENDING key. (The rolled-back-then-poisoned route gets there
        // without an in-line promotion, which is exactly how the field reaches it —
        // since the review-2026-08-03 retire closes the live handle at rotate time,
        // the only way the file still moves is a commit already in flight when the
        // re-key returned, i.e. the RACING write below.)
        val vs = provisionPinVault()
        file.script = RekeyScript.ROLLBACK
        val live = upgradeToPassphrase(vs)
        file.applyRacingPoisonedWrite()
        live.close()

        val store = KeyValueStore()
        val vltCBeforeThePromotion = store.getString(VaultStoreKeys.WRAPPED_DBKEY)
        assertNotNull(store.getString(PENDING_KEY), "precondition: an unresolved rotation record")

        // THE locked keybag: `kvPut` returns without writing while `kvRemove` — a bare
        // SecItemDelete needing no class key — would still succeed.
        keychain.putFailing.add(VaultStoreKeys.WRAPPED_DBKEY)

        val blocked = selector().unlock(PHRASE)
        assertTrue(
            blocked is VaultSelector.UnlockResult.Opened,
            "the vault must still open through the pending record",
        )
        (blocked as VaultSelector.UnlockResult.Opened).vault.close()

        assertNotNull(
            store.getString(PENDING_KEY),
            "an unproven promotion may NEVER drop the pending record — with vlt_c stuck " +
                "on the OLD key it is the only record of the key the file is on",
        )
        assertEquals(
            vltCBeforeThePromotion, store.getString(VaultStoreKeys.WRAPPED_DBKEY),
            "the dropped write really did leave vlt_c on the old key",
        )

        // Keybag unlocked: the retry PROVES the copy and only then retires the record.
        keychain.putFailing.remove(VaultStoreKeys.WRAPPED_DBKEY)
        val healed = selector().unlock(PHRASE)
        assertTrue(healed is VaultSelector.UnlockResult.Opened, "the retry must open the vault")
        (healed as VaultSelector.UnlockResult.Opened).vault.close()
        assertNull(store.getString(PENDING_KEY), "a PROVEN promotion retires the record")
        assertTrue(
            selector().unlock(PHRASE) is VaultSelector.UnlockResult.Opened,
            "and the promoted vlt_c must open the vault on its own",
        )
    }

    // ----------------------------------------------- the rolled-back re-key --

    /**
     * `sqlite3_rekey_v2` reported SQLITE_OK on its ROLLBACK branch, so the probes
     * say "only the OLD key opens it" — and dropping `vlt_cn` on that evidence is
     * exactly the brick this branch must not create, because the rolled-back re-key
     * left the NEW key installed in the live handle's WRITE context. Since the
     * review-2026-08-03 retire, that handle is CLOSED at rotate time — so the only
     * poisoned write that can still land is one already in flight when the re-key
     * returned (the race the close cannot cover, modelled here), and the KEPT
     * record is the only thing that can still open the vault.
     */
    @Test
    fun rolledBackRekeyThatLaterMovesTheFile_isRecoveredByTheKeptPendingRecord() {
        val vs = provisionPinVault()
        file.script = RekeyScript.ROLLBACK
        val live = upgradeToPassphrase(vs)

        val store = KeyValueStore()
        assertNotNull(
            store.getString(PENDING_KEY),
            "a probe-reported rollback must KEEP both key records — sqlite3_rekey_v2 " +
                "already installed the new key in this handle's write context",
        )

        // The racing commit lands on the file before the retire's close took hold.
        file.applyRacingPoisonedWrite()
        live.close()

        val opened = selector().unlock(PHRASE)
        assertTrue(
            opened is VaultSelector.UnlockResult.Opened,
            "the kept pending record must still open the vault after the file moved",
        )
        (opened as VaultSelector.UnlockResult.Opened).vault.close()
        assertNull(KeyValueStore().getString(PENDING_KEY),
            "the confirmed open then promotes and retires the record")
        assertTrue(
            selector().unlock(PHRASE) is VaultSelector.UnlockResult.Opened,
            "and the promoted record opens it on every later unlock",
        )
    }

    /**
     * Review 2026-08-03 — the retire itself, end to end: after a probe-reported
     * rollback the LIVE handle must be CLOSED before the rotation returns
     * ([VaultDatabase.rekey]'s "prefer closing… over continuing to write" contract,
     * previously ignored), and the session owner must be told to re-lock. The
     * poisoned write context then has nowhere to land: the file stays on `vlt_c`'s
     * key and the next unlock drops the pending record on that positive evidence —
     * no mixed-key file, no promotion over unread pages, no data loss.
     */
    @Test
    fun rolledBackRekey_retiresTheLiveHandle_soThePoisonedWriteCannotLand() {
        val vs = provisionPinVault()
        val provisionKey = file.key!!.copyOf()
        file.script = RekeyScript.ROLLBACK
        upgradeToPassphrase(vs)

        assertTrue(
            file.liveHandleClosedAfterRekey,
            "the rotation must CLOSE the poisoned live handle before returning",
        )
        assertEquals(1, retiredCount, "…and tell the session owner to re-lock, exactly once")

        // The next commit through the (now closed) handle: must be a no-op.
        file.applyPoisonedWrite()
        assertTrue(
            provisionKey.contentEquals(file.key!!),
            "no write may reach the file through the retired handle — it must stay on the old key",
        )

        // The forced re-unlock recovers: vlt_c opens the file, the record is dropped.
        val opened = selector().unlock(PHRASE)
        assertTrue(opened is VaultSelector.UnlockResult.Opened, "the stored key must open the vault")
        (opened as VaultSelector.UnlockResult.Opened).vault.close()
        assertNull(KeyValueStore().getString(PENDING_KEY),
            "the never-landed record is dropped once vlt_c is proven to open the file")
    }

    /**
     * The same branch when the rollback really was total (the handle never touches
     * the file again): keeping the record must cost ONE deferral cycle, never a
     * stuck state. `vlt_c` opens the file, which is the positive evidence the
     * reconcile drops the record on.
     */
    @Test
    fun rolledBackRekeyThatNeverMovesTheFile_convergesOnTheNextUnlock() {
        val vs = provisionPinVault()
        file.script = RekeyScript.ROLLBACK
        upgradeToPassphrase(vs).close()

        assertNotNull(KeyValueStore().getString(PENDING_KEY),
            "precondition: the record is kept at rotate time")

        val opened = selector().unlock(PHRASE)
        assertTrue(opened is VaultSelector.UnlockResult.Opened, "the vault must open on the stored key")
        (opened as VaultSelector.UnlockResult.Opened).vault.close()
        assertNull(KeyValueStore().getString(PENDING_KEY),
            "the never-landed record is dropped once vlt_c is proven to open the file")
    }

    /**
     * The undecidable case, which is where a wipe would be catastrophic: the file is
     * on a key NEITHER record names (locked sidecar, mid-restore, a swapped file).
     * The credential VERIFIED, so this must be the neutral [VaultSelector.UnlockResult.Error]
     * — never `Denied`, which counts toward the emergency wipe and would let an honest
     * user with the correct passphrase destroy their own vault — and NOTHING may be
     * removed: either record may be the one that matters once the file is readable again.
     */
    @Test
    fun neitherKeyOpensTheFile_isTheNeutralError_andKeepsBothRecords() {
        val vs = provisionPinVault()
        file.script = RekeyScript.ROLLBACK
        upgradeToPassphrase(vs).close()

        val store = KeyValueStore()
        val vltC = store.getString(VaultStoreKeys.WRAPPED_DBKEY)
        val vltCn = store.getString(PENDING_KEY)
        assertNotNull(vltCn, "precondition: an unresolved rotation record")

        file.key = ByteArray(32) { 0x5A }   // neither the old nor the pending key

        assertEquals(
            VaultSelector.UnlockResult.Error, selector().unlock(PHRASE),
            "an undecidable rotation state must be the neutral Error, never Denied",
        )
        assertEquals(vltC, store.getString(VaultStoreKeys.WRAPPED_DBKEY),
            "an ambiguous path must not touch vlt_c")
        assertEquals(vltCn, store.getString(PENDING_KEY),
            "…nor remove vlt_cn — it may be the only record of the key the file is on")
    }

    /** A re-key that fails VISIBLY must leave the same brick-safe state — and
     * it must ALSO retire the handle: from up here a `false`
     *  after the native call ran is indistinguishable from a poisoned context. */
    @Test
    fun visiblyFailedRekey_keepsTheVaultOpenable() {
        val vs = provisionPinVault()
        file.script = RekeyScript.ERROR
        upgradeToPassphrase(vs).close()

        assertEquals(1, retiredCount,
            "a visibly failed re-key did not verifiably commit — the handle must be retired too")
        val opened = selector().unlock(PHRASE)
        assertTrue(opened is VaultSelector.UnlockResult.Opened,
            "a failed re-key must never cost the user their vault")
        (opened as VaultSelector.UnlockResult.Opened).vault.close()
        assertNull(KeyValueStore().getString(PENDING_KEY),
            "and the record must not survive a proven open on vlt_c")
    }

    /** The committed path, end to end: the file moves and the record is retired
     *  in-line, so the steady state after an upgrade carries no pending record —
     *  and the SESSION KEEPS ITS HANDLE: a probe-proven commit
     *  leaves both codec contexts on the new key, so no forced re-lock. */
    @Test
    fun committedRekey_promotesInLine_andTheNewCredentialOpensTheVault() {
        val vs = provisionPinVault()
        file.script = RekeyScript.COMMIT
        val live = upgradeToPassphrase(vs)

        assertEquals(0, retiredCount, "a proven commit must NOT retire the live handle")
        assertFalse(file.liveHandleClosedAfterRekey,
            "…the session keeps writing through it under the committed key")
        live.close()

        assertNull(KeyValueStore().getString(PENDING_KEY), "a completed rotation leaves no pending record")
        assertTrue(file.rekeyCalls > 0, "the live handle must actually have been re-keyed")
        val opened = selector().unlock(PHRASE)
        assertTrue(opened is VaultSelector.UnlockResult.Opened, "the new passphrase must open the vault")
        (opened as VaultSelector.UnlockResult.Opened).vault.close()
    }

    // ------------------------------------------- probeKey / rekey mechanics --

    /**
     * [iosProbeVaultKey]'s contract, which nothing exercised: true ONLY for the key
     * the file is on, never a throw, and — the load-bearing part — it must never
     * CREATE the file it was asked about (`sqlite3_open` has CREATE semantics, so
     * the size guard is the only thing standing between a probe and a manufactured
     * empty vault).
     */
    @Test
    fun probeKey_answersOnlyForTheFilesKey_andNeverCreatesTheFile() {
        installBridges()
        deleteVaultFiles()
        file.key = ByteArray(32) { it.toByte() }
        val factory = iosVaultFactory()

        // No file on disk: false, and NO file may appear.
        assertFalse(factory.probeKey(file.key!!), "a missing vault file must probe false")
        assertFalse(iosVaultFileExists(), "the probe must never manufacture the vault file")

        materialiseVaultFile()
        assertTrue(factory.probeKey(file.key!!), "the file's own key must probe true")
        assertFalse(factory.probeKey(ByteArray(32) { (it + 1).toByte() }), "a wrong key must probe false")
        assertTrue(iosVaultFileExists(), "the probe must leave the file in place")

        // A truncated stub is "not a real vault", never a fresh empty one.
        deleteVaultFiles()
        NSFileManager.defaultManager.createFileAtPath(
            iosVaultDbPath(), contents = ByteArray(16).toNSData(), attributes = null)
        assertFalse(factory.probeKey(file.key!!), "a truncated file must probe false")
    }

    /**
     * [IosVaultDatabase.rekey]: the bridge is called exactly once with the RAW key
     * bytes (the Swift side owns the `x'<hex>'` encoding — swapping that for
     * Android's raw-byte convention orphans the file), and `true` is returned only
     * for SQLITE_OK. A non-zero code must be a quiet `false`, never a throw.
     */
    @Test
    fun rekey_passesTheRawKeyOnce_andReportsTrueOnlyForSqliteOk() {
        installBridges()
        deleteVaultFiles()
        val original = ByteArray(32) { (it * 3 + 1).toByte() }
        file.key = original.copyOf()
        materialiseVaultFile()

        val db = IosVaultDatabase(dbKey = original, isProvision = false)
        val fresh = ByteArray(32) { (it * 7 + 5).toByte() }

        file.script = RekeyScript.COMMIT
        assertTrue(db.rekey(fresh), "SQLITE_OK must report true")
        assertEquals(1, file.rekeyCalls, "the bridge must be called exactly once")
        assertTrue(fresh.contentEquals(file.lastRekeyKey!!),
            "the RAW key bytes must reach the bridge — the keyspec encoding is the Swift side's job")

        file.script = RekeyScript.ERROR
        assertFalse(db.rekey(original), "a non-zero result code must report false, not throw")
        db.close()
    }

    private companion object {
        const val PIN = "135790"
        const val PHRASE = "runes harbor violet stapler mountain ledger"
        const val PENDING_KEY = VaultStoreKeys.PENDING_DBKEY
    }
}
