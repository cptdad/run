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
 * GOLDEN: the exact store-write sequence and the final key set of every credential-path
 * flow of the REAL [VaultSelector], plus format round-trips through an independent
 * decoder written here from the frozen [VaultCryptoContexts] labels.
 *
 * It CHARACTERISES the code as it is (b7ff07b8 + the SelectorStore seam), written BEFORE
 * the codec / phase extractions. Every later refactor of provision / unlock /
 * changeCredential / recoverWithCode / the Lever-B enable must keep it green UNCHANGED:
 * a diff here is a change to what lands on disk, not a test to update.
 *
 * Writes are recorded as ISSUED (a remove of an absent key still shows up); reads are
 * deliberately not recorded, because extracting a helper may legitimately add or merge
 * a read. Runs on the JVM only (androidUnitTest): testDebugUnitTest ⇒ isDebugBuild ⇒
 * Argon2 1 MiB × 1; the pinned cost is asserted against [VaultKdf.runtimeArgon2MemoryKiB]
 * / [VaultKdf.runtimeArgon2Iterations], so testReleaseUnitTest (64 MiB × 3) is green too,
 * and T13 is the one row whose expectation branches on [isDebugBuild].
 */
class VaultSelectorGoldenTest {

    private val cipher = FakeDeviceKeyCipher()
    private val store = RecordingSelectorStore()
    private var factory = FakeVaultFactory()
    private val protector = FakeDbKeyProtector(cipher)

    private fun selector(vaultProvider: () -> VaultDatabase? = { null }): VaultSelector =
        VaultSelector(
            store = store, crypto = cipher, vaultFactory = factory,
            dbKeyProtector = protector, vaultProvider = vaultProvider,
        ).also { it.changePinMinDelayMs = 0; store.ops.clear() }   // T0 is asserted separately

    // ------------------------------------------------------------ helpers --

    private fun put(k: String) = StoreOp.Put(k)
    private fun rm(k: String) = StoreOp.Remove(k)
    private fun batch(vararg k: String) = StoreOp.Batch(k.toList())

    private val cred = VaultCryptoContexts.CREDENTIAL.encodeToByteArray()
    private val dbCtx = VaultCryptoContexts.DBKEY_INNER.encodeToByteArray()
    private val recCtx = VaultCryptoContexts.RECOVERY.encodeToByteArray()

    /** Independent decoder of `vlt_a` (device layer → layout). */
    private fun credentialParams(): VaultKdf.KdfParams =
        assertNotNull(VaultKdf.parseCredentialBlob(cipher.open(decodeBase64(store.kv.getValue("vlt_a")), cred)))

    /** Independent decoder of `vlt_c` under [pin]: stretch → KEK → outer → inner → payload. */
    private fun openDbKey(pin: String): DbKeyPayload? {
        val params = credentialParams()
        val stretched = VaultKdf.stretch(pin.encodeToByteArray(), params)
        val verifier = sha256WithLabel(stretched, VaultCryptoContexts.LABEL_VERIFIER.encodeToByteArray())
        if (!constantTimeEquals(verifier, params.verifier)) return null
        val kek = sha256WithLabel(stretched, VaultCryptoContexts.LABEL_DBKEY_KEK.encodeToByteArray())
        val inner = protector.unwrap(store.kv.getValue("vlt_c"))
        return DbKeyPayloadCodec.decodeDbKeyPayload(aesGcmDecrypt(inner, kek, dbCtx))
    }

    /** Independent decoder of a selector-meta slot. */
    private fun meta(key: String): String = SelectorMetaPolicy.unpadSelectorMetaPlaintext(
        cipher.open(
            decodeBase64(store.kv.getValue(key)),
            (VaultCryptoContexts.SELECTOR_META_PREFIX + key).encodeToByteArray(),
        ),
    )

    /** Independent decoder of `vlt_rc` under the displayed code. */
    private fun recoveryDbKey(code: String): ByteArray {
        val secret = assertNotNull(Base32.decode(code))
        val kek = sha256WithLabel(secret, VaultCryptoContexts.LABEL_RECOVERY_KEK.encodeToByteArray())
        return aesGcmDecrypt(cipher.open(decodeBase64(store.kv.getValue("vlt_rc")), recCtx), kek, recCtx)
    }

    private fun provisioned(level: ProtectionLevel = ProtectionLevel.CASUAL): VaultSelector =
        selector().also {
            assertTrue(it.setRealCredential(PIN, passphraseMode = false, level = level))
            store.ops.clear()
        }

    private fun leverBOn(vs: VaultSelector): String {
        val code = assertIs<VaultSelector.RecoveryEnableResult.Enabled>(
            vs.enableDbKeyAuthBindingWithRecovery(PIN),
        ).recoveryCode
        assertTrue(vs.finalizeDbKeyAuthBinding(ProtectionLevel.PRIVATE))
        store.ops.clear(); protector.events.clear()
        return code
    }

    private fun intBE(v: Int) =
        byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())

    /** Plant a vault by hand at an arbitrary credential layout (T12/T13). */
    private fun plantVault(
        credPlain: (salt: ByteArray, verifier: ByteArray) -> ByteArray,
        params: VaultKdf.KdfParams,
    ): ByteArray {
        val dbKey = generateSecureRandom(VaultKdf.DBKEY_LENGTH)
        val stretched = VaultKdf.stretch(PIN.encodeToByteArray(), params)
        val verifier = sha256WithLabel(stretched, VaultCryptoContexts.LABEL_VERIFIER.encodeToByteArray())
        val kek = sha256WithLabel(stretched, VaultCryptoContexts.LABEL_DBKEY_KEK.encodeToByteArray())
        store.kv["vlt_a"] = encodeBase64(cipher.seal(credPlain(params.salt, verifier), cred))
        store.kv["vlt_c"] = protector.wrap(
            aesGcmEncrypt(DbKeyPayloadCodec.encodeDbKeyPayload(dbKey, null), kek, dbCtx), authBound = false,
        )
        factory.fileKey = dbKey.copyOf()
        return dbKey
    }

    // ---------------------------------------------------------------- T0 --

    @Test fun t0_construction_writesOnlyTheDecoyPurge() {
        VaultSelector(store = store, crypto = cipher, vaultFactory = factory, dbKeyProtector = protector)
        assertEquals(
            listOf(rm("vlt_b"), rm("vlt_d"), rm("decoy_credential_hash"), rm("decoy_db_wrapped")),
            store.drain(),
        )
        assertTrue(store.kv.isEmpty())
    }

    // ------------------------------------------------------- T1–T3 provision --

    @Test fun t1_provision_oneBatch_thenFormatsDecode() {
        assertTrue(selector().setRealCredential(PIN, passphraseMode = false, level = ProtectionLevel.CASUAL))
        assertEquals(listOf(batch("vlt_a", "vlt_c", "vlt_m", "vlt_lvl")), store.drain())
        assertEquals(setOf("vlt_a", "vlt_c", "vlt_m", "vlt_lvl"), store.kv.keys)
        assertEquals(listOf("create(provision)"), factory.opens)
        val p = credentialParams()
        assertEquals(VaultKdf.CURRENT_KDF_VERSION, p.version)
        assertEquals(VaultKdf.runtimeArgon2MemoryKiB, p.memoryKiB)
        assertEquals(VaultKdf.runtimeArgon2Iterations, p.iterations)
        assertFalse(DbKeyScheme.isAuthBound(store.kv.getValue("vlt_c")))
        assertContentEquals(factory.fileKey, assertNotNull(openDbKey(PIN)).dbKey)
        assertEquals(SelectorMetaPolicy.MODE_PIN, meta("vlt_m"))
        assertEquals(ProtectionLevel.CASUAL.storageValue, meta("vlt_lvl"))
    }

    @Test fun t2_provision_legacyNoLevel_removesTierFirst() {
        selector().setRealCredential(PIN)
        assertEquals(listOf(rm("vlt_lvl"), batch("vlt_a", "vlt_c", "vlt_m")), store.drain())
        assertEquals(setOf("vlt_a", "vlt_c", "vlt_m"), store.kv.keys)
    }

    @Test fun t3_provision_tornWrite_rollsBackInListOrder_thenDeletesFile() {
        store.droppedPuts += "vlt_c"
        val vs = selector()
        assertFalse(vs.setRealCredential(PIN, passphraseMode = false, level = ProtectionLevel.CASUAL))
        assertFalse(vs.lastProvisionWasDeviceKeyUnavailable())
        assertEquals(
            listOf(batch("vlt_a", "vlt_c", "vlt_m", "vlt_lvl")) +
                listOf("vlt_txn_journal", "vlt_a", "vlt_c", "vlt_m", "vlt_lvl").map { rm(it) },
            store.drain(),
        )
        assertTrue(store.kv.isEmpty())
        assertNull(factory.fileKey)
        assertEquals(listOf("create(provision)", "delete-file"), factory.opens)
    }

    // -------------------------------------------------------------- T4 unlock --

    @Test fun t4_unlock_steadyState_writesNothing() {
        val vs = provisioned()
        assertIs<VaultSelector.UnlockResult.Opened>(vs.unlock(PIN))
        assertEquals(emptyList(), store.drain())
        assertIs<VaultSelector.UnlockResult.Denied>(vs.unlock(WRONG))
        assertEquals(emptyList(), store.drain())
        assertEquals(listOf("create(provision)", "create"), factory.opens)
    }

    // ------------------------------------------------------ T5–T6 change cred --

    @Test fun t5_changePin_oneBatch_modeRepersisted_sameDbKey() {
        val vs = provisioned()
        val before = factory.fileKey!!.copyOf()
        assertEquals(VaultSelector.ChangePinResult.SUCCESS, vs.changeCredential(PIN, PIN2))
        assertEquals(listOf(batch("vlt_a", "vlt_c", "vlt_m")), store.drain())
        assertEquals(setOf("vlt_a", "vlt_c", "vlt_m", "vlt_lvl"), store.kv.keys)
        assertNull(openDbKey(PIN))
        assertContentEquals(before, assertNotNull(openDbKey(PIN2)).dbKey)
        assertIs<VaultSelector.UnlockResult.Denied>(vs.unlock(PIN))
        assertIs<VaultSelector.UnlockResult.Opened>(vs.unlock(PIN2))
        assertEquals(emptyList(), store.drain())
    }

    @Test fun t6_tierUpgrade_unionBatch_thenPromote() {
        val handle = RekeyableVault(factory)
        val vs = selector(vaultProvider = { handle })
        assertTrue(vs.setRealCredential(PIN, passphraseMode = false, level = ProtectionLevel.CASUAL))
        store.ops.clear()
        val oldKey = factory.fileKey!!.copyOf()
        assertEquals(
            VaultSelector.ChangePinResult.SUCCESS,
            vs.changeCredentialAndMode(PIN, PHRASE, newModePassphrase = true),
        )
        assertEquals(
            listOf(batch("vlt_a", "vlt_c", "vlt_cn", "vlt_m"), put("vlt_c"), rm("vlt_cn")),
            store.drain(),
        )
        assertEquals(setOf("vlt_a", "vlt_c", "vlt_m", "vlt_lvl"), store.kv.keys)
        assertFalse(oldKey.contentEquals(factory.fileKey!!))
        assertContentEquals(factory.fileKey, assertNotNull(openDbKey(PHRASE)).dbKey)
        assertEquals(SelectorMetaPolicy.MODE_PASSPHRASE, meta("vlt_m"))
    }

    // -------------------------------------------------- T7–T9 Lever B toggles --

    @Test fun t7_leverB_enableThenFinalize() {
        val vs = provisioned()
        val code = assertIs<VaultSelector.RecoveryEnableResult.Enabled>(
            vs.enableDbKeyAuthBindingWithRecovery(PIN),
        ).recoveryCode
        assertEquals(listOf(put("vlt_rp"), put("vlt_rc")), store.drain())
        assertEquals(listOf("delete-key", "mint-key"), protector.events)
        assertEquals(1, protector.prompts)                                // the round-trip verify
        assertFalse(DbKeyScheme.isAuthBound(store.kv.getValue("vlt_c")))  // commit-before-display
        assertTrue(vs.finalizeDbKeyAuthBinding(ProtectionLevel.PRIVATE))
        assertEquals(listOf(batch("vlt_c", "vlt_abk", "vlt_lvl"), rm("vlt_rp")), store.drain())
        assertEquals(setOf("vlt_a", "vlt_c", "vlt_m", "vlt_lvl", "vlt_rc", "vlt_abk"), store.kv.keys)
        assertTrue(DbKeyScheme.isAuthBound(store.kv.getValue("vlt_c")))
        assertEquals(ProtectionLevel.PRIVATE.storageValue, meta("vlt_lvl"))
        assertContentEquals(factory.fileKey, recoveryDbKey(code))
        assertIs<VaultSelector.UnlockResult.Opened>(vs.unlock(PIN))
        assertEquals(emptyList(), store.drain())
        assertEquals(2, protector.prompts)
    }

    @Test fun t8_leverB_disable_plainCommitThenDrop() {
        val vs = provisioned(); leverBOn(vs)
        assertTrue(vs.setDbKeyAuthBinding(false))
        assertEquals(listOf(put("vlt_c"), rm("vlt_rc"), rm("vlt_rp"), rm("vlt_abk")), store.drain())
        assertEquals(setOf("vlt_a", "vlt_c", "vlt_m", "vlt_lvl"), store.kv.keys)
        assertContentEquals(factory.fileKey, assertNotNull(openDbKey(PIN)).dbKey)
    }

    @Test fun t9_leverB_toggleOn_overProvenRecoveryBlob() {
        val vs = provisioned()
        assertIs<VaultSelector.RecoveryEnableResult.Enabled>(vs.enableDbKeyAuthBindingWithRecovery(PIN))
        store.ops.clear(); protector.events.clear()
        assertTrue(vs.setDbKeyAuthBinding(true))
        assertEquals(listOf(put("vlt_c"), put("vlt_abk"), rm("vlt_rp")), store.drain())
        assertEquals(listOf("delete-key", "mint-key"), protector.events)
    }

    // ---------------------------------------------------------- T10–T11 recover --

    @Test fun t10_recover_afterHardwareKeyLoss_staysPlain_keepsTimers() {
        val vs = provisioned(); val code = leverBOn(vs)
        protector.invalidateHardwareKey()
        assertIs<VaultSelector.UnlockResult.RecoveryRequired>(vs.unlock(PIN))
        assertEquals(emptyList(), store.drain())
        protector.supportsAuth = false
        assertIs<VaultSelector.UnlockResult.Opened>(vs.recoverWithCode(code, PIN))
        assertEquals(listOf(put("vlt_c"), rm("vlt_rc"), rm("vlt_rp"), rm("vlt_abk")), store.drain())
        assertEquals(setOf("vlt_a", "vlt_c", "vlt_m", "vlt_lvl"), store.kv.keys)
        assertEquals(ProtectionLevel.PRIVATE.storageValue, meta("vlt_lvl"))  // KEY vs TIMER split
        assertFalse(vs.isDbKeyAuthBound())
        assertIs<VaultSelector.UnlockResult.Opened>(vs.unlock(PIN))
    }

    @Test fun t11_recover_reestablishesLeverB_underTheSameCode() {
        val vs = provisioned(); val code = leverBOn(vs)
        protector.invalidateHardwareKey()
        assertIs<VaultSelector.UnlockResult.Opened>(vs.recoverWithCode(code, PIN))
        assertEquals(
            listOf(
                put("vlt_c"), rm("vlt_rc"), rm("vlt_rp"), rm("vlt_abk"),
                rm("vlt_rp"), put("vlt_rc"), put("vlt_c"), put("vlt_abk"),
            ),
            store.drain(),
        )
        assertEquals(setOf("vlt_a", "vlt_c", "vlt_m", "vlt_lvl", "vlt_rc", "vlt_abk"), store.kv.keys)
        assertTrue(DbKeyScheme.isAuthBound(store.kv.getValue("vlt_c")))
        assertContentEquals(factory.fileKey, recoveryDbKey(code))
    }

    // ------------------------------------------------------------ T12–T13 rewrap --

    @Test fun t12_rewrap_v2Credential_migratesOnceInOneBatch() {
        val salt = generateSecureRandom(VaultKdf.SALT_LENGTH)
        val dbKey = plantVault(
            { s, v -> VaultKdf.buildCredentialBlob(VaultKdf.KDF_VERSION_2, s, v) },
            VaultKdf.KdfParams(VaultKdf.KDF_VERSION_2, salt, ByteArray(0)),
        )
        val vs = selector()
        assertIs<VaultSelector.UnlockResult.Opened>(vs.unlock(PIN))
        assertEquals(listOf(batch("vlt_a", "vlt_c")), store.drain())
        assertEquals(VaultKdf.CURRENT_KDF_VERSION, credentialParams().version)
        assertContentEquals(dbKey, assertNotNull(openDbKey(PIN)).dbKey)
        assertIs<VaultSelector.UnlockResult.Opened>(vs.unlock(PIN))
        assertEquals(emptyList(), store.drain())
    }

    @Test fun t13_rewrap_subFloorV3_repinsOnlyInRelease() {
        val salt = generateSecureRandom(VaultKdf.SALT_LENGTH)
        plantVault(
            { s, v -> byteArrayOf(VaultKdf.KDF_VERSION_3) + s + v + intBE(1_024) + intBE(1) + byteArrayOf(1) },
            VaultKdf.KdfParams(VaultKdf.KDF_VERSION_3, salt, ByteArray(0), 1_024, 1, 1),
        )
        assertIs<VaultSelector.UnlockResult.Opened>(selector().unlock(PIN))
        assertEquals(if (isDebugBuild) emptyList() else listOf(batch("vlt_a", "vlt_c")), store.drain())
    }

    // --------------------------------------------------------------- T14 adoption --

    @Test fun t14_adoption_singleWriteAtFirstUnlock_thenRawOpens() {
        factory = FakeVaultFactory(adopts = true, refuseFirstDerive = true)
        val vs = provisioned()
        assertIs<VaultSelector.UnlockResult.Opened>(vs.unlock(PIN))
        assertEquals(listOf(put("vlt_c")), store.drain())
        assertEquals(DbKeyMode.RAW, assertNotNull(openDbKey(PIN)).mode)
        assertIs<VaultSelector.UnlockResult.Opened>(vs.unlock(PIN))
        assertEquals(emptyList(), store.drain())
        assertEquals(listOf("create(provision)", "create", "raw"), factory.opens)
    }

    private companion object {
        const val PIN = "135790"
        const val PIN2 = "246802"
        const val WRONG = "000000"
        // Meets the Lever A floor (pinned by CredentialPolicyTest).
        const val PHRASE = "correct horse battery staple lamp river"
    }
}
