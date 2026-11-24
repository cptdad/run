package com.vg.run

import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * RÚN-02 on the REAL [VaultSelector] (golden fakes): while a wipe's erase is
 * unresolved the old vault stays closed — every open answers the neutral, never
 * counted [VaultSelector.UnlockResult.Error] (never `Denied`, so no wrong-credential
 * budget is spent and no second wipe can be triggered by it) — and no fresh setup
 * can start. Plus the tri-state reads the two cross-launch rules depend on.
 */
class WipeEraseVaultSelectorGateTest {

    private val cipher = FakeDeviceKeyCipher()
    private val store = RecordingSelectorStore()
    private val factory = FakeVaultFactory()
    private val protector = FakeDbKeyProtector(cipher)

    private fun selector(s: SelectorStore = store): VaultSelector =
        VaultSelector(store = s, crypto = cipher, vaultFactory = factory, dbKeyProtector = protector)
            .also { it.changePinMinDelayMs = 0 }

    @BeforeTest fun reset() = WipeEraseLatch.resetForTest()
    @AfterTest fun tearDown() = WipeEraseLatch.resetForTest()

    private fun latchUnresolved() {
        WipeEraseLatch.finish(
            WipeEraseLatch.begin(),
            WipeEraseReport(mapOf(WipeItem.DEVICE_KEY to EraseResult(EraseOutcome.UNRESOLVED, -25308))),
        )
    }

    @Test
    fun unresolvedErase_everyOpenIsTheNeutralError_neverDenied() {
        val vs = selector()
        assertTrue(vs.setRealCredential(PIN, passphraseMode = false, level = ProtectionLevel.CASUAL))
        latchUnresolved()

        assertEquals(VaultSelector.UnlockResult.Error, vs.unlock(PIN), "the right PIN does not open it")
        assertEquals(VaultSelector.UnlockResult.Error, vs.unlock("999999"), "a wrong PIN is NOT counted")
        assertEquals(
            VaultSelector.UnlockResult.Error,
            vs.recoverWithCode("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", PIN),
            "the recovery path is closed too",
        )

        WipeEraseLatch.recordOutcome(WipeEraseReport(mapOf(WipeItem.DEVICE_KEY to EraseResult(EraseOutcome.DELETED, 0))))
        assertIs<VaultSelector.UnlockResult.Opened>(vs.unlock(PIN), "resolution reopens the gate (fake: key kept)")
    }

    @Test
    fun unresolvedErase_noFreshSetup_thenSetupSucceedsAfterResolution() {
        latchUnresolved()
        val vs = selector()
        assertFalse(vs.setRealCredential(PIN, passphraseMode = false, level = ProtectionLevel.CASUAL))
        assertTrue(store.kv.keys.none { it == "vlt_a" || it == "vlt_c" }, "nothing was written")
        assertNull(factory.fileKey, "no vault file was created")

        WipeEraseLatch.recordOutcome(WipeEraseReport(mapOf(WipeItem.DEVICE_KEY to EraseResult(EraseOutcome.DELETED, 0))))
        assertTrue(vs.setRealCredential(PIN, passphraseMode = false, level = ProtectionLevel.CASUAL))
        assertIs<VaultSelector.UnlockResult.Opened>(vs.unlock(PIN))
    }

    @Test
    fun credentialPairPresence_isTriState_andNeverPurges() {
        val vs = selector()
        assertEquals(false, vs.credentialPairPresence(), "fresh install: both confirmed absent")
        assertTrue(vs.setRealCredential(PIN, passphraseMode = false, level = ProtectionLevel.CASUAL))
        assertEquals(true, vs.credentialPairPresence())

        store.kv.remove("vlt_c")
        assertNull(vs.credentialPairPresence(), "a torn pair proves neither")
        assertTrue("vlt_a" in store.kv, "the probe is read-only (no half-pair purge)")

        val broken = object : SelectorStore {
            override fun getString(key: String): String? = throw KeyUnavailableException("locked")
            override fun contains(key: String): Boolean = throw KeyUnavailableException("locked")
            override fun putStringSync(key: String, value: String) = Unit
            override fun putStringsSync(values: Map<String, String>) = Unit
            override fun remove(key: String): Boolean = false
        }
        val vsBroken = VaultSelector(store = broken, crypto = cipher, vaultFactory = factory, dbKeyProtector = protector)
        assertNull(vsBroken.credentialPairPresence(), "a store error is never 'absent'")
        assertFalse(vsBroken.batchJournalConfirmedAbsent(), "…nor 'no journal'")
    }

    @Test
    fun batchJournalConfirmedAbsent_readsTheJournalKey() {
        val vs = selector()
        assertTrue(vs.batchJournalConfirmedAbsent())
        store.kv[VaultStoreKeys.BATCH_JOURNAL] = "x"
        assertFalse(vs.batchJournalConfirmedAbsent())
    }

    /**
     * RÚN-02 consumer class "vault selector readers": with the device key REFUSED
     * (what a refused mint looks like: KeyUnavailableException on seal and open),
     * every reader the platforms call pre-unlock or across a non-@Throws iOS bridge
     * returns its fail-safe value instead of throwing.
     */
    @Test
    fun vaultSelectorReaders_absorbARefusedDeviceKey() {
        val vs = selector()
        assertTrue(vs.setRealCredential(PIN, passphraseMode = false, level = ProtectionLevel.CASUAL))
        cipher.throwOnOpen = true
        cipher.throwOnSeal = true
        vs.isConfigured()
        assertTrue(vs.credentialsReadable(), "a refused key DEFERS the orphan check — never 'unreadable' (no wipe)")
        assertEquals(true, vs.credentialPairPresence())
        vs.isPassphraseMode()
        vs.credentialKindProven()
        vs.protectionLevelOrNull()
        vs.protectionLevelForFloorCheck()
        vs.protectionLevelForEnforcement()
        vs.maximumShieldLevel()
        vs.maxConsecutiveAttemptsForInterruptedWipe()
        vs.currentProtectionLevel()
        vs.displayProtectionLevel()
        vs.isDbKeyAuthBound()
        vs.hasRecoveryCode()
        vs.needsLeverBReharden()
        assertFalse(vs.verifyCredential(PIN))
        assertFalse(vs.setProtectionLevel(ProtectionLevel.MAXIMUM))
        assertEquals(VaultSelector.UnlockResult.Error, vs.unlock(PIN), "never Denied on a refused key")
    }

    /** R2 against real inputs: the rule fires ONLY for proven credentials over a proven-missing file. */
    @Test
    fun postWipeResidue_realInputs() {
        val vs = selector()
        assertTrue(vs.setRealCredential(PIN, passphraseMode = false, level = ProtectionLevel.CASUAL))
        fun residue(fileAbsent: Boolean) =
            WipeErasePolicy.postWipeResidue(vs.credentialPairPresence(), fileAbsent, vs.batchJournalConfirmedAbsent())

        assertTrue(factory.vaultFileExists())
        assertFalse(residue(fileAbsent = !factory.vaultFileExists()), "credentials + vault file ⇒ NEVER erased")
        assertFalse(residue(fileAbsent = false), "file state unknown (reported as not-absent) ⇒ never erased")

        store.kv[VaultStoreKeys.BATCH_JOURNAL] = "x"
        factory.fileKey = null
        assertFalse(residue(fileAbsent = true), "a pending journal ⇒ never erased")
        store.kv.remove(VaultStoreKeys.BATCH_JOURNAL)

        store.kv.remove("vlt_c")
        assertFalse(residue(fileAbsent = true), "a torn pair (one read fails to prove presence) ⇒ never erased")
        assertTrue(vs.setRealCredential(PIN, passphraseMode = false, level = ProtectionLevel.CASUAL))
        factory.fileKey = null
        assertTrue(residue(fileAbsent = true), "both reads proven + no file + no journal ⇒ the residue rule")
    }

    private companion object {
        const val PIN = "482913"
    }
}
