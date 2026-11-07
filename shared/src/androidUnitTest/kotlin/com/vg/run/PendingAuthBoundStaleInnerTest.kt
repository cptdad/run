package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The prepared Lever-B blob ([VaultSelector.finalizeDbKeyAuthBinding]'s input) wraps
 * the INNER layer `vlt_c` had at enable time. On iOS the VaultSelector outlives lock(),
 * so an unlock between enable and finalize can run the KDF migration (new salt ⇒ new
 * KEK ⇒ new inner). Committing the held blob then left a vault every unlock answered
 * Error until the recovery code was used. Finalize now refuses when `vlt_c` moved,
 * writing nothing; the vault stays plain and opens with the PIN, and the next unlock
 * revokes the orphan recovery code on the armed `vlt_rp` marker.
 */
class PendingAuthBoundStaleInnerTest {

    private val cipher = FakeDeviceKeyCipher()
    private val store = RecordingSelectorStore()
    private val factory = FakeVaultFactory()
    private val protector = FakeDbKeyProtector(cipher)

    private fun selector(): VaultSelector =
        VaultSelector(store = store, crypto = cipher, vaultFactory = factory, dbKeyProtector = protector)
            .also { it.changePinMinDelayMs = 0 }

    /** A legacy v2 (PBKDF2-600k) vault, so the next unlock rewrites `vlt_a` + `vlt_c`. */
    private fun plantV2Vault() {
        val dbKey = generateSecureRandom(VaultKdf.DBKEY_LENGTH)
        val salt = generateSecureRandom(VaultKdf.SALT_LENGTH)
        val stretched = VaultKdf.stretch(PIN.encodeToByteArray(), VaultKdf.KdfParams(VaultKdf.KDF_VERSION_2, salt, ByteArray(0)))
        val verifier = sha256WithLabel(stretched, VaultCryptoContexts.LABEL_VERIFIER.encodeToByteArray())
        val kek = sha256WithLabel(stretched, VaultCryptoContexts.LABEL_DBKEY_KEK.encodeToByteArray())
        store.kv["vlt_a"] = encodeBase64(
            cipher.seal(
                VaultKdf.buildCredentialBlob(VaultKdf.KDF_VERSION_2, salt, verifier),
                VaultCryptoContexts.CREDENTIAL.encodeToByteArray(),
            ),
        )
        store.kv["vlt_c"] = protector.wrap(
            aesGcmEncrypt(
                DbKeyPayloadCodec.encodeDbKeyPayload(dbKey, null), kek,
                VaultCryptoContexts.DBKEY_INNER.encodeToByteArray(),
            ),
            authBound = false,
        )
        factory.fileKey = dbKey.copyOf()
    }

    @Test
    fun finalize_afterAnInterveningKdfMigration_refuses_writesNothing_andTheVaultStillOpens() {
        plantV2Vault()
        val vs = selector()
        assertIs<VaultSelector.RecoveryEnableResult.Enabled>(vs.enableDbKeyAuthBindingWithRecovery(PIN))
        // The lock/unlock in between: the KDF migration re-wraps `vlt_c` under a new KEK.
        assertIs<VaultSelector.UnlockResult.Opened>(vs.unlock(PIN))
        store.ops.clear()

        assertFalse(vs.finalizeDbKeyAuthBinding(ProtectionLevel.PRIVATE))
        assertEquals(emptyList(), store.drain(), "a refused finalize writes nothing")
        assertFalse(DbKeyScheme.isAuthBound(store.kv.getValue("vlt_c")))
        assertFalse(vs.finalizeDbKeyAuthBinding(ProtectionLevel.PRIVATE), "the stale prepared blob is dropped")

        // Brick-safety: the PIN still opens the vault, and this unlock (no pending blob,
        // marker armed, blob proven plain) revokes the orphan recovery code.
        assertIs<VaultSelector.UnlockResult.Opened>(vs.unlock(PIN))
        assertEquals(listOf(StoreOp.Remove("vlt_rc"), StoreOp.Remove("vlt_rp")), store.drain())
        assertFalse("vlt_rc" in store.kv.keys)
    }

    @Test
    fun finalize_withNoInterveningChange_stillCommits() {
        plantV2Vault()
        val vs = selector()
        assertIs<VaultSelector.RecoveryEnableResult.Enabled>(vs.enableDbKeyAuthBindingWithRecovery(PIN))
        assertTrue(vs.finalizeDbKeyAuthBinding(ProtectionLevel.PRIVATE))
        assertTrue(DbKeyScheme.isAuthBound(store.kv.getValue("vlt_c")))
        assertIs<VaultSelector.UnlockResult.Opened>(vs.unlock(PIN))
    }

    /**
     * The iOS locked-keybag shape of a finalize: the batch LANDS but the read-back
     * right after it misses. [hideNextDbKeyRead] makes the first `vlt_c` read after a
     * batch carrying `vlt_c` answer null, once; every write goes to [inner] unchanged.
     */
    private class ReadBackMissStore(private val inner: RecordingSelectorStore) : SelectorStore {
        var hideNextDbKeyRead = false
        var armed = true
        override fun getString(key: String): String? {
            if (key == "vlt_c" && hideNextDbKeyRead) { hideNextDbKeyRead = false; return null }
            return inner.getString(key)
        }
        override fun contains(key: String): Boolean = inner.contains(key)
        override fun putStringSync(key: String, value: String) = inner.putStringSync(key, value)
        override fun putStringsSync(values: Map<String, String>) {
            inner.putStringsSync(values)
            if (armed && "vlt_c" in values) hideNextDbKeyRead = true
        }
        override fun remove(key: String): Boolean = inner.remove(key)
    }

    @Test
    fun finalize_retryAfterALandedBatchWhoseReadBackMissed_succeedsWithoutRewriting() {
        plantV2Vault()
        val missing = ReadBackMissStore(store)
        val vs = VaultSelector(store = missing, crypto = cipher, vaultFactory = factory, dbKeyProtector = protector)
            .also { it.changePinMinDelayMs = 0 }
        val code = assertIs<VaultSelector.RecoveryEnableResult.Enabled>(vs.enableDbKeyAuthBindingWithRecovery(PIN))
        store.ops.clear()

        // First finalize: the batch lands, its read-back misses ⇒ false, pending kept.
        assertFalse(vs.finalizeDbKeyAuthBinding(ProtectionLevel.PRIVATE))
        assertEquals(listOf(StoreOp.Batch(listOf("vlt_c", "vlt_abk", "vlt_lvl"))), store.drain())
        assertTrue(DbKeyScheme.isAuthBound(store.kv.getValue("vlt_c")), "the batch did land")

        // Retry: `vlt_c` already IS the prepared blob ⇒ success, nothing re-written; the
        // marker is disarmed exactly as on the normal success path.
        assertTrue(vs.finalizeDbKeyAuthBinding(ProtectionLevel.PRIVATE))
        assertEquals(listOf(StoreOp.Remove("vlt_rp")), store.drain())
        // The pending state is consumed: a third call has nothing to finalize.
        assertFalse(vs.finalizeDbKeyAuthBinding(ProtectionLevel.PRIVATE))
        assertEquals(emptyList(), store.drain())

        // Brick-safety: the vault opens with the PIN, and the recovery code the user
        // saved still reconstructs the DB key (it was never replaced). The read-miss is
        // switched off so the unlock's own KDF-migration batch reads back normally.
        missing.armed = false
        assertIs<VaultSelector.UnlockResult.Opened>(vs.unlock(PIN))
        assertTrue("vlt_rc" in store.kv.keys)
        val secret = Base32.decode(code.recoveryCode)!!
        val recKek = sha256WithLabel(secret, VaultCryptoContexts.LABEL_RECOVERY_KEK.encodeToByteArray())
        val recCtx = VaultCryptoContexts.RECOVERY.encodeToByteArray()
        val dbKey = aesGcmDecrypt(cipher.open(decodeBase64(store.kv.getValue("vlt_rc")), recCtx), recKek, recCtx)
        assertTrue(dbKey.contentEquals(factory.fileKey))
    }

    private companion object {
        const val PIN = "135790"
    }
}
