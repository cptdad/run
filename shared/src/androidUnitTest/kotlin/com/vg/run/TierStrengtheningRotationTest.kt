package com.vg.run

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * RUN-01 — every protection-tier STRENGTHENING re-keys the database, so a wrapper
 * archived before the transition no longer yields the key the file is encrypted with.
 *
 * Before the fix only Decent → Maximum re-keyed (golden T6). Decent → Secure (the
 * Lever B enable) and Secure → Maximum (credential change while Lever B + `vlt_rc` are
 * live, then the drop) kept the provision-time key, so an archived weak-era `vlt_a` +
 * `vlt_c` + the old PIN + the device key opened TODAY's vault.
 *
 * Runs the REAL [VaultSelector] over the golden fakes (androidUnitTest, JVM): the file
 * is identified by the key it is on, a re-key moves it, and every "does this archived
 * wrapper still open the vault?" question is answered by an INDEPENDENT decoder plus
 * [FakeVaultFactory.probeKey] — never by the implementation's own helpers. The crash
 * points around the recovery-code acknowledgment and the hardware-binding removal are
 * driven by store write drops, a rolled-back re-key, blind probes and a cancelled
 * biometric — each asserting the brick-safety half too: the PIN (or passphrase) still
 * opens the vault, and no recovery code is ever shown that does not open the file.
 */
class TierStrengtheningRotationTest {

    private val cipher = FakeDeviceKeyCipher()
    private val store = RecordingSelectorStore()
    private val fileFactory = FakeVaultFactory()
    private val factory = SwitchableProbeFactory(fileFactory)
    private val hardware = FakeDbKeyProtector(cipher)
    private val protector = CancellableProtector(hardware)
    private var retired = 0

    private fun selector(vault: VaultDatabase? = null): VaultSelector =
        VaultSelector(
            store = store, crypto = cipher, vaultFactory = factory, dbKeyProtector = protector,
            vaultProvider = { vault }, onRekeyHandleRetired = { retired++ },
        ).also { it.changePinMinDelayMs = 0 }

    private val liveHandle = RekeyableVault(fileFactory)

    /** A provisioned Decent (CASUAL) PIN vault, wired to a live handle like RunViewModel. */
    private fun decentVault(vault: VaultDatabase? = liveHandle): VaultSelector {
        val vs = selector(vault)
        assertTrue(vs.setRealCredential(PIN, passphraseMode = false, level = ProtectionLevel.CASUAL))
        store.ops.clear()
        return vs
    }

    // ------------------------------------------------- independent decoders --

    private class Archive(val cred: String, val dbKeyBlob: String, val recovery: String?)

    private fun archive() = Archive(store.kv.getValue("vlt_a"), store.kv.getValue("vlt_c"), store.kv["vlt_rc"])

    /** The DB key an archived `vlt_a` + `vlt_c` yields for [credential] (null = wrong credential). */
    private fun archivedDbKey(a: Archive, credential: String): ByteArray? {
        val params = assertNotNull(
            VaultKdf.parseCredentialBlob(
                cipher.open(decodeBase64(a.cred), VaultCryptoContexts.CREDENTIAL.encodeToByteArray()),
            ),
        )
        val stretched = VaultKdf.stretch(credential.encodeToByteArray(), params)
        val verifier = sha256WithLabel(stretched, VaultCryptoContexts.LABEL_VERIFIER.encodeToByteArray())
        if (!constantTimeEquals(verifier, params.verifier)) return null
        val kek = sha256WithLabel(stretched, VaultCryptoContexts.LABEL_DBKEY_KEK.encodeToByteArray())
        val inner = hardware.unwrap(a.dbKeyBlob)
        val plain = aesGcmDecrypt(inner, kek, VaultCryptoContexts.DBKEY_INNER.encodeToByteArray())
        return assertNotNull(DbKeyPayloadCodec.decodeDbKeyPayload(plain)).dbKey
    }

    /** The DB key a `vlt_rc` blob yields under the displayed [code]. */
    private fun recoveryKey(blob: String, code: String): ByteArray {
        val secret = assertNotNull(Base32.decode(code))
        val kek = sha256WithLabel(secret, VaultCryptoContexts.LABEL_RECOVERY_KEK.encodeToByteArray())
        val ctx = VaultCryptoContexts.RECOVERY.encodeToByteArray()
        return aesGcmDecrypt(cipher.open(decodeBase64(blob), ctx), kek, ctx)
    }

    private fun opensTheFile(key: ByteArray?) = key != null && fileFactory.probeKey(key)

    private fun enableCode(vs: VaultSelector, credential: String = PIN): String =
        assertIs<VaultSelector.RecoveryEnableResult.Enabled>(vs.enableDbKeyAuthBindingWithRecovery(credential))
            .recoveryCode

    private fun put(k: String) = StoreOp.Put(k)
    private fun rm(k: String) = StoreOp.Remove(k)
    private fun batch(vararg k: String) = StoreOp.Batch(k.toList())

    // ====================================================== Decent → Secure ==

    @Test
    fun decentToSecure_reKeysBeforeTheCodeIsMinted_archivedDecentWrapperIsDead_shownCodeOpensTheFile() {
        val vs = decentVault()
        val decentEra = archive()
        assertTrue(opensTheFile(archivedDbKey(decentEra, PIN)), "control: the archive opens the vault before")

        val code = enableCode(vs)

        assertEquals(
            listOf(batch("vlt_c", "vlt_cn"), put("vlt_c"), rm("vlt_cn"), put("vlt_rp"), put("vlt_rc")),
            store.drain(),
            "union batch → probe-proven promotion → ONLY THEN the recovery code",
        )
        assertNull(store.kv["vlt_cn"], "a completed rotation leaves no record")
        assertFalse(DbKeyScheme.isAuthBound(store.kv.getValue("vlt_c")), "commit-before-display is unchanged")
        assertEquals(0, retired, "a probe-proven commit keeps the session")
        // THE RUN-01 PROPERTY.
        assertFalse(opensTheFile(archivedDbKey(decentEra, PIN)), "the archived Decent-era wrapper must be dead")
        // The code the user is about to be SHOWN opens the file it guards.
        assertTrue(opensTheFile(recoveryKey(store.kv.getValue("vlt_rc"), code)), "the shown code must open the file")

        assertTrue(vs.finalizeDbKeyAuthBinding(ProtectionLevel.PRIVATE))
        assertIs<VaultSelector.UnlockResult.Opened>(selector().unlock(PIN))
        // The hardware key dies: the acknowledged code still recovers the re-keyed vault.
        hardware.invalidateHardwareKey()
        hardware.supportsAuth = false
        val fresh = selector()
        assertIs<VaultSelector.UnlockResult.RecoveryRequired>(fresh.unlock(PIN))
        assertIs<VaultSelector.UnlockResult.Opened>(fresh.recoverWithCode(code, PIN))
    }

    @Test
    fun decentToSecure_fromALegacyV2VaultWithAnUntaggedPayload_rotatesUnderTheLegacyKek_thenMigrates() {
        // Legacy shapes still read and migrate: a v2 (PBKDF2) credential and the
        // pre-adoption 32-byte untagged payload. The `vlt_cn` record is sealed under the
        // CURRENT (v2-derived) KEK, which is what the reconcile would unwrap it with.
        val dbKey = generateSecureRandom(VaultKdf.DBKEY_LENGTH)
        val salt = generateSecureRandom(VaultKdf.SALT_LENGTH)
        val stretched = VaultKdf.stretch(PIN.encodeToByteArray(), VaultKdf.KdfParams(VaultKdf.KDF_VERSION_2, salt, ByteArray(0)))
        val verifier = sha256WithLabel(stretched, VaultCryptoContexts.LABEL_VERIFIER.encodeToByteArray())
        val kek = sha256WithLabel(stretched, VaultCryptoContexts.LABEL_DBKEY_KEK.encodeToByteArray())
        store.kv["vlt_a"] = encodeBase64(
            cipher.seal(VaultKdf.buildCredentialBlob(VaultKdf.KDF_VERSION_2, salt, verifier),
                VaultCryptoContexts.CREDENTIAL.encodeToByteArray()),
        )
        store.kv["vlt_c"] = hardware.wrap(
            aesGcmEncrypt(dbKey, kek, VaultCryptoContexts.DBKEY_INNER.encodeToByteArray()), authBound = false,
        )
        fileFactory.fileKey = dbKey.copyOf()
        val legacy = archive()
        val vs = selector(liveHandle)

        val code = enableCode(vs)
        assertFalse(opensTheFile(archivedDbKey(legacy, PIN)), "the legacy-era wrapper must be dead")
        assertTrue(opensTheFile(recoveryKey(store.kv.getValue("vlt_rc"), code)))
        // Not finalized (abandoned): the vault is plain on the NEW key, the PIN opens it,
        // and that unlock still migrates the v2 credential (and revokes the orphan code).
        store.ops.clear()
        assertIs<VaultSelector.UnlockResult.Opened>(selector().unlock(PIN))
        assertEquals(VaultKdf.CURRENT_KDF_VERSION, assertNotNull(VaultKdf.parseCredentialBlob(
            cipher.open(decodeBase64(store.kv.getValue("vlt_a")), VaultCryptoContexts.CREDENTIAL.encodeToByteArray()),
        )).version)
        assertIs<VaultSelector.UnlockResult.Opened>(selector().unlock(PIN))
    }

    @Test
    fun decentToSecure_fromARawKeyAdoptedHandle_probesTheOldKeyInEveryMode_andRotates() {
        val adopting = FakeVaultFactory(adopts = true)
        val handle = RekeyableVault(adopting)
        val vs = VaultSelector(
            store = store, crypto = cipher, vaultFactory = adopting, dbKeyProtector = protector,
            vaultProvider = { handle }, onRekeyHandleRetired = { retired++ },
        ).also { it.changePinMinDelayMs = 0 }
        assertTrue(vs.setRealCredential(PIN, passphraseMode = false, level = ProtectionLevel.CASUAL))
        val adoptedEra = archive()
        val oldKey = adopting.fileKey!!.copyOf()

        val code = enableCode(vs)
        assertFalse(oldKey.contentEquals(adopting.fileKey!!), "the file moved to a new key")
        assertFalse(archivedDbKey(adoptedEra, PIN)!!.let { adopting.probeKey(it) })
        assertTrue(adopting.probeKey(recoveryKey(store.kv.getValue("vlt_rc"), code)))
        assertEquals(0, retired)
    }

    @Test
    fun decentToSecure_crashAfterTheRotation_beforeTheCode_cancelledBiometric_noCode_pinOpensTheNewKey() {
        // The enable's own failure AFTER the re-key: the biometric round-trip is cancelled.
        // Same disk state as a process death between the promotion and the code.
        val vs = decentVault()
        val decentEra = archive()
        protector.cancelAuthBoundUnwrap = true

        assertIs<VaultSelector.RecoveryEnableResult.Failed>(vs.enableDbKeyAuthBindingWithRecovery(PIN))
        assertEquals(listOf(batch("vlt_c", "vlt_cn"), put("vlt_c"), rm("vlt_cn")), store.drain())
        assertNull(store.kv["vlt_rc"], "no code is minted, so none can be shown")
        assertNull(store.kv["vlt_rp"])
        assertFalse(DbKeyScheme.isAuthBound(store.kv.getValue("vlt_c")))
        assertFalse(opensTheFile(archivedDbKey(decentEra, PIN)), "the rotation that landed still counts")

        protector.cancelAuthBoundUnwrap = false
        assertIs<VaultSelector.UnlockResult.Opened>(selector().unlock(PIN), "PIN opens the rotated vault")
        // The retry mints its code over the (already rotated, and now re-rotated) key.
        val code = enableCode(selector(liveHandle))
        assertTrue(opensTheFile(recoveryKey(store.kv.getValue("vlt_rc"), code)))
    }

    @Test
    fun decentToSecure_reKeyRolledBack_noCodeMinted_handleRetired_unlockDropsTheRecord() {
        // sqlite3_rekey_v2's rollback branch: SQLITE_OK, file NOT moved ⇒ DROP_PENDING.
        val rolledBack = object : InMemoryVault() {
            override fun rekey(newDbKey: ByteArray): Boolean = true
        }
        val vs = decentVault(rolledBack)
        val before = fileFactory.fileKey!!.copyOf()

        assertIs<VaultSelector.RecoveryEnableResult.Failed>(vs.enableDbKeyAuthBindingWithRecovery(PIN))
        assertEquals(listOf(batch("vlt_c", "vlt_cn")), store.drain(), "records kept, nothing promoted, no code")
        assertNotNull(store.kv["vlt_cn"])
        assertNull(store.kv["vlt_rc"])
        assertEquals(1, retired, "the possibly-poisoned handle is retired")
        assertContentEquals(before, fileFactory.fileKey)

        assertIs<VaultSelector.UnlockResult.Opened>(selector().unlock(PIN))
        assertNull(store.kv["vlt_cn"], "vlt_c opened the file ⇒ the record is dropped on positive evidence")
    }

    @Test
    fun decentToSecure_ambiguousProbes_noCode_recordsKept_unlockPromotesTheRotatedKey() {
        val vs = decentVault()
        val decentEra = archive()
        factory.blindProbes = true    // the re-key lands, but neither probe can tell

        assertIs<VaultSelector.RecoveryEnableResult.Failed>(vs.enableDbKeyAuthBindingWithRecovery(PIN))
        assertEquals(listOf(batch("vlt_c", "vlt_cn")), store.drain())
        assertNull(store.kv["vlt_rc"], "no code over an unproven key")
        assertEquals(1, retired)

        factory.blindProbes = false
        assertIs<VaultSelector.UnlockResult.Opened>(selector().unlock(PIN), "never a brick: vlt_cn opens it")
        assertNull(store.kv["vlt_cn"])
        assertFalse(opensTheFile(archivedDbKey(decentEra, PIN)))
        assertTrue(opensTheFile(archivedDbKey(archive(), PIN)), "the promoted vlt_c is the file's key")
    }

    @Test
    fun decentToSecure_pendingRecordWriteDropped_nothingReKeyed_noCode() {
        val vs = decentVault()
        val before = fileFactory.fileKey!!.copyOf()
        store.droppedPuts += "vlt_cn"   // iOS locked-keybag kvPut no-op

        assertIs<VaultSelector.RecoveryEnableResult.Failed>(vs.enableDbKeyAuthBindingWithRecovery(PIN))
        assertEquals(listOf(batch("vlt_c", "vlt_cn"), rm("vlt_cn")), store.drain())
        assertContentEquals(before, fileFactory.fileKey, "no durable record ⇒ the re-key never starts")
        assertNull(store.kv["vlt_rc"])
        assertEquals(0, retired)
        store.droppedPuts.clear()
        assertIs<VaultSelector.UnlockResult.Opened>(selector().unlock(PIN))
    }

    @Test
    fun decentToSecure_promotionWriteDropped_noCode_handleKept_nextUnlockPromotes() {
        val vs = decentVault()
        val decentEra = archive()
        store.droppedPuts += "vlt_c"    // the promotion's copy silently does not land

        assertIs<VaultSelector.RecoveryEnableResult.Failed>(vs.enableDbKeyAuthBindingWithRecovery(PIN))
        assertEquals(listOf(batch("vlt_c", "vlt_cn"), put("vlt_c")), store.drain(), "vlt_cn is NOT removed")
        assertNotNull(store.kv["vlt_cn"], "the only record of the file's new key survives")
        assertNull(store.kv["vlt_rc"])
        assertEquals(0, retired, "PROMOTE: the handle is consistent on the new key")
        assertIs<VaultSelector.RecoveryEnableResult.Failed>(vs.enableDbKeyAuthBindingWithRecovery(PIN),
            "a retry defers while the record is pending")

        store.droppedPuts.clear()
        assertIs<VaultSelector.UnlockResult.Opened>(selector().unlock(PIN))
        assertNull(store.kv["vlt_cn"])
        assertFalse(opensTheFile(archivedDbKey(decentEra, PIN)))
    }

    @Test
    fun decentToSecure_withAProvenRecoveryCodeOnDisk_neverReKeys() {
        // A PROVEN `vlt_rc` over a plain blob (an un-acknowledged earlier enable, or a
        // post-recovery re-arm whose ab: commit failed) is a code the user may hold. A
        // re-key would kill it with no replacement guaranteed, so the enable SKIPS the
        // rotation (the pre-RUN-01 behaviour) — the file never moves under that code.
        val earlier = decentVault(vault = null)
        val heldCode = enableCode(earlier)
        val before = fileFactory.fileKey!!.copyOf()

        val vs = selector(liveHandle)
        store.ops.clear()   // construction's decoy purge
        val code = enableCode(vs)
        assertEquals(listOf(put("vlt_rp"), put("vlt_rc")), store.drain(), "no rotation batch")
        assertContentEquals(before, fileFactory.fileKey)
        assertTrue(opensTheFile(recoveryKey(store.kv.getValue("vlt_rc"), code)))
        assertFalse(code == heldCode)
    }

    @Test
    fun decentToSecure_withoutALiveHandle_isTheUnchangedPreFixFlow() {
        // Onboarding enables before the session owns the handle: nothing to re-key.
        val vs = decentVault(vault = null)
        enableCode(vs)
        assertEquals(listOf(put("vlt_rp"), put("vlt_rc")), store.drain())
    }

    @Test
    fun finalize_refusesWhileARotationRecordIsPending_writesNothing_thenCommits() {
        val vs = decentVault(vault = null)
        enableCode(vs)
        store.kv["vlt_cn"] = "pending"
        store.ops.clear()
        assertFalse(vs.finalizeDbKeyAuthBinding(ProtectionLevel.PRIVATE))
        assertEquals(emptyList(), store.drain())
        assertFalse(DbKeyScheme.isAuthBound(store.kv.getValue("vlt_c")))
        store.kv.remove("vlt_cn")
        assertTrue(vs.finalizeDbKeyAuthBinding(ProtectionLevel.PRIVATE), "the prepared enable was kept")
    }

    // ===================================================== Secure → Maximum ==

    /** Decent → Secure through the real settings sequence; returns the acknowledged code. */
    private fun secureVault(vs: VaultSelector): String {
        val code = enableCode(vs)
        assertTrue(vs.finalizeDbKeyAuthBinding(ProtectionLevel.PRIVATE))
        store.ops.clear()
        return code
    }

    @Test
    fun secureToMaximum_reKeysAfterTheDrop_archivedSecureEraWrapperAndRecoveryBlobAreDead() {
        val vs = decentVault()
        val code = secureVault(vs)
        val secureEra = archive()
        val secureEraRecovery = assertNotNull(secureEra.recovery)

        // 1. The credential change: vetoed (ab: + a live code), exactly as before.
        assertEquals(VaultSelector.ChangePinResult.SUCCESS, vs.changeCredentialAndMode(PIN, PHRASE, newModePassphrase = true))
        assertEquals(listOf(batch("vlt_a", "vlt_c", "vlt_m")), store.drain(), "no rotation while Lever B is live")
        // 2. The Lever B drop: plain blob proven, then `vlt_rc` removed.
        assertTrue(vs.setDbKeyAuthBinding(false))
        store.ops.clear()
        // Control — the RUN-01 hole: right here the Secure-era archive still opens the file.
        assertTrue(opensTheFile(archivedDbKey(secureEra, PIN)))
        assertTrue(opensTheFile(recoveryKey(secureEraRecovery, code)))

        // 3. The new step, gated by the shared rule both platforms call.
        assertTrue(ProtectionUpgradePlan.rotatesDbKeyAfterLeverBDrop(ProtectionLevel.MAXIMUM, true, true))
        assertTrue(vs.rotateDbKeyAfterTierUpgrade(PHRASE))
        assertEquals(listOf(batch("vlt_c", "vlt_cn"), put("vlt_c"), rm("vlt_cn")), store.drain())
        assertEquals(0, retired)

        assertFalse(opensTheFile(archivedDbKey(secureEra, PIN)), "the archived Secure-era ab: wrapper must be dead")
        assertFalse(opensTheFile(recoveryKey(secureEraRecovery, code)), "…and so must an archived recovery blob")
        assertNull(store.kv["vlt_rc"], "Maximum keeps no recovery code — none was live to kill")
        assertIs<VaultSelector.UnlockResult.Opened>(selector().unlock(PHRASE))
        assertIs<VaultSelector.UnlockResult.Denied>(selector().unlock(PIN))
    }

    @Test
    fun secureToMaximum_dropDidNotLand_rotationRefuses_writesNothing_codeStillWorks() {
        val vs = decentVault()
        val code = secureVault(vs)
        assertEquals(VaultSelector.ChangePinResult.SUCCESS, vs.changeCredentialAndMode(PIN, PHRASE, newModePassphrase = true))
        store.ops.clear()
        val before = fileFactory.fileKey!!.copyOf()

        // The drop never happened (cancelled prompt): still ab: with a live code.
        assertFalse(ProtectionUpgradePlan.rotatesDbKeyAfterLeverBDrop(ProtectionLevel.MAXIMUM, false, true))
        assertFalse(vs.rotateDbKeyAfterTierUpgrade(PHRASE), "a direct call is refused by the vault-side gates")
        assertEquals(emptyList(), store.drain())
        assertContentEquals(before, fileFactory.fileKey)
        assertTrue(opensTheFile(recoveryKey(store.kv.getValue("vlt_rc"), code)), "the held code still opens the file")
    }

    @Test
    fun secureToMaximum_crashBetweenTheDropAndTheRotation_passphraseOpens_nothingPending() {
        val vs = decentVault()
        secureVault(vs)
        assertEquals(VaultSelector.ChangePinResult.SUCCESS, vs.changeCredentialAndMode(PIN, PHRASE, newModePassphrase = true))
        assertTrue(vs.setDbKeyAuthBinding(false))
        // Process death here: a fresh selector, no rotation ever ran.
        assertIs<VaultSelector.UnlockResult.Opened>(selector().unlock(PHRASE))
        assertNull(store.kv["vlt_cn"])
    }

    @Test
    fun secureToMaximum_wrongCredential_writesNothing() {
        val vs = decentVault()
        secureVault(vs)
        assertEquals(VaultSelector.ChangePinResult.SUCCESS, vs.changeCredentialAndMode(PIN, PHRASE, newModePassphrase = true))
        assertTrue(vs.setDbKeyAuthBinding(false))
        store.ops.clear()
        assertFalse(vs.rotateDbKeyAfterTierUpgrade(PIN))
        assertEquals(emptyList(), store.drain())
    }

    @Test
    fun secureToMaximum_ambiguousProbes_recordsKept_handleRetired_unlockPromotes() {
        val vs = decentVault()
        secureVault(vs)
        assertEquals(VaultSelector.ChangePinResult.SUCCESS, vs.changeCredentialAndMode(PIN, PHRASE, newModePassphrase = true))
        assertTrue(vs.setDbKeyAuthBinding(false))
        val maxEraBeforeRotation = archive()
        factory.blindProbes = true

        assertFalse(vs.rotateDbKeyAfterTierUpgrade(PHRASE))
        assertNotNull(store.kv["vlt_cn"])
        assertEquals(1, retired)

        factory.blindProbes = false
        assertIs<VaultSelector.UnlockResult.Opened>(selector().unlock(PHRASE))
        assertNull(store.kv["vlt_cn"])
        assertFalse(opensTheFile(archivedDbKey(maxEraBeforeRotation, PHRASE)))
    }

    @Test
    fun secureToMaximum_promotionWriteDropped_unlockPromotes() {
        val vs = decentVault()
        secureVault(vs)
        assertEquals(VaultSelector.ChangePinResult.SUCCESS, vs.changeCredentialAndMode(PIN, PHRASE, newModePassphrase = true))
        assertTrue(vs.setDbKeyAuthBinding(false))
        store.droppedPuts += "vlt_c"
        assertFalse(vs.rotateDbKeyAfterTierUpgrade(PHRASE))
        assertNotNull(store.kv["vlt_cn"])
        store.droppedPuts.clear()
        assertIs<VaultSelector.UnlockResult.Opened>(selector().unlock(PHRASE))
        assertNull(store.kv["vlt_cn"])
    }

    @Test
    fun decentToMaximum_isStillTheCredentialChangeRotation_andThePostDropStepIsNeverAsked() {
        val vs = decentVault()
        val decentEra = archive()
        assertEquals(VaultSelector.ChangePinResult.SUCCESS, vs.changeCredentialAndMode(PIN, PHRASE, newModePassphrase = true))
        assertFalse(opensTheFile(archivedDbKey(decentEra, PIN)))
        assertFalse(ProtectionUpgradePlan.rotatesDbKeyAfterLeverBDrop(ProtectionLevel.MAXIMUM, false, true))
    }

    private companion object {
        const val PIN = "135790"
        // Meets the Lever A floor (pinned by CredentialPolicyTest).
        const val PHRASE = "correct horse battery staple lamp river"
    }
}

/** A [VaultFactory] whose probes can be made BLIND ("could not tell" — false for every key). */
private class SwitchableProbeFactory(private val inner: FakeVaultFactory) : VaultFactory by inner {
    var blindProbes = false
    override fun probeKey(dbKey: ByteArray): Boolean = !blindProbes && inner.probeKey(dbKey)
    override fun probeRawKey(rawKey: ByteArray): Boolean = !blindProbes && inner.probeRawKey(rawKey)
}

/** A [DbKeyProtector] whose auth-bound unwrap (the biometric prompt) can be CANCELLED. */
private class CancellableProtector(private val inner: FakeDbKeyProtector) : DbKeyProtector by inner {
    var cancelAuthBoundUnwrap = false
    override fun unwrap(stored: String): ByteArray {
        if (cancelAuthBoundUnwrap && DbKeyScheme.isAuthBound(stored)) throw KeyUnavailableException("prompt cancelled")
        return inner.unwrap(stored)
    }
}
