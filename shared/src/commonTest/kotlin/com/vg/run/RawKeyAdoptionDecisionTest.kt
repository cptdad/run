package com.vg.run

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// Raw-key adoption (2026-10-07) — the PURE units: the DB-key payload codec that
// carries the SQLCipher key mode inside the KEK-AEAD'd inner plaintext of `vlt_c`
// (and of every `ab:` / `vlt_cn` blob), the unlock's mode order, and the promotion
// decision. `VaultSelector`'s store/crypto are expect classes with no common fake
// seam (see DbKeyRotationTest's header), so the end-to-end halves live in
// androidUnitTest `RawKeyAdoptionPayloadSealTest` (real AES-GCM) and androidTest
// `RawKeyAdoptionTest` (real SQLCipher file on a device).
//
// The properties pinned here are the brick-safety ones:
//   • a LEGACY 32-byte payload — every vault provisioned before adoption — still
//     decodes, as PASSPHRASE (establish-on-read), and migrates on write to the
//     explicitly-tagged form with the SAME key;
//   • every decodable payload can ALWAYS be opened in passphrase mode with R
//     (openModeOrder ends in PASSPHRASE), so no adopted vault depends on K' alone;
//   • anything malformed is null (→ the unlock's neutral Error), never a guess;
//   • promotion needs every piece of positive evidence, and any "could not tell"
//     refuses.
// ---------------------------------------------------------------------------

class RawKeyAdoptionDecisionTest {

    private val r = ByteArray(32) { (it * 3 + 1).toByte() }
    private val k = ByteArray(32) { (0xA0 + it).toByte() }

    // -- codec: legacy reads, tagged forms round-trip ---------------------------

    @Test
    fun legacy32BytePayload_decodesAsUntaggedPassphrase_withTheSameKey() {
        val p = assertNotNull(DbKeyPayloadCodec.decodeDbKeyPayload(r.copyOf()))
        assertEquals(DbKeyMode.PASSPHRASE, p.mode, "missing tag = legacy passphrase mode (establish-on-read)")
        assertFalse(p.tagged)
        assertNull(p.rawKey)
        assertContentEquals(r, p.dbKey)
    }

    @Test
    fun legacyPayload_migratesOnWriteToTheTaggedPassphraseForm_keyUnchanged() {
        val legacy = assertNotNull(DbKeyPayloadCodec.decodeDbKeyPayload(r.copyOf()))
        val rewritten = DbKeyPayloadCodec.encodeDbKeyPayload(legacy)
        assertEquals(33, rewritten.size)
        assertEquals(DbKeyPayloadCodec.DBKEY_MODE_TAG_PASSPHRASE, rewritten[32])
        val again = assertNotNull(DbKeyPayloadCodec.decodeDbKeyPayload(rewritten))
        assertEquals(DbKeyMode.PASSPHRASE, again.mode)
        assertTrue(again.tagged)
        assertContentEquals(r, again.dbKey, "a re-wrap must never change the SQLCipher key")
    }

    @Test
    fun taggedPassphrasePayload_roundTrips() {
        val enc = DbKeyPayloadCodec.encodeDbKeyPayload(r, null)
        assertContentEquals(r + byteArrayOf(0x01), enc)
        val p = assertNotNull(DbKeyPayloadCodec.decodeDbKeyPayload(enc))
        assertEquals(DbKeyMode.PASSPHRASE, p.mode)
        assertTrue(p.tagged)
        assertNull(p.rawKey)
        assertContentEquals(r, p.dbKey)
    }

    @Test
    fun rawPayload_roundTrips_andKeepsR() {
        val enc = DbKeyPayloadCodec.encodeDbKeyPayload(r, k)
        assertEquals(65, enc.size)
        assertContentEquals(r + byteArrayOf(0x02) + k, enc)
        val p = assertNotNull(DbKeyPayloadCodec.decodeDbKeyPayload(enc))
        assertEquals(DbKeyMode.RAW, p.mode)
        assertContentEquals(r, p.dbKey, "R must survive adoption: recovery + the fallback open need it")
        assertContentEquals(k, p.rawKey)
        // Canonical re-encode (change-PIN / KDF migration re-seal) is byte-identical.
        assertContentEquals(enc, DbKeyPayloadCodec.encodeDbKeyPayload(p))
    }

    @Test
    fun decode_returnsCopies_soWipingThePayloadNeverAliasesTheInput() {
        val enc = DbKeyPayloadCodec.encodeDbKeyPayload(r, k)
        val p = assertNotNull(DbKeyPayloadCodec.decodeDbKeyPayload(enc))
        enc.fill(0)
        assertContentEquals(r, p.dbKey)
        assertContentEquals(k, p.rawKey)
        val enc2 = DbKeyPayloadCodec.encodeDbKeyPayload(r, k)
        val p2 = assertNotNull(DbKeyPayloadCodec.decodeDbKeyPayload(enc2))
        p2.wipe()
        assertContentEquals(r + byteArrayOf(0x02) + k, enc2, "wiping the payload must not zero the source")
    }

    @Test
    fun malformedPayloads_decodeToNull_neverToAGuess() {
        val cases = listOf(
            ByteArray(0),
            ByteArray(31),
            r + byteArrayOf(0x00),                 // 33 bytes, unknown tag
            r + byteArrayOf(0x02),                 // RAW tag with no K'
            ByteArray(34),
            r + byteArrayOf(0x01) + k,             // 65 bytes with the PASSPHRASE tag
            r + byteArrayOf(0x00) + k,             // 65 bytes, unknown tag
            r + byteArrayOf(0x02) + k + byteArrayOf(0), // 66
            ByteArray(64),
        )
        for (c in cases) assertNull(DbKeyPayloadCodec.decodeDbKeyPayload(c), "size ${c.size} must be malformed")
    }

    @Test
    fun encode_rejectsWrongKeyLengths() {
        assertFailsWith<IllegalArgumentException> { DbKeyPayloadCodec.encodeDbKeyPayload(ByteArray(31), null) }
        assertFailsWith<IllegalArgumentException> { DbKeyPayloadCodec.encodeDbKeyPayload(r, ByteArray(16)) }
    }

    // -- unlock mode order -------------------------------------------------------

    @Test
    fun openModeOrder_tagFirst_andEveryPayloadEndsInPassphraseModeWithR() {
        assertEquals(listOf(DbKeyMode.RAW, DbKeyMode.PASSPHRASE), DbKeyPayloadCodec.openModeOrder(DbKeyMode.RAW))
        assertEquals(listOf(DbKeyMode.PASSPHRASE), DbKeyPayloadCodec.openModeOrder(DbKeyMode.PASSPHRASE))
        for (enc in listOf(r.copyOf(), DbKeyPayloadCodec.encodeDbKeyPayload(r, null), DbKeyPayloadCodec.encodeDbKeyPayload(r, k))) {
            val p = assertNotNull(DbKeyPayloadCodec.decodeDbKeyPayload(enc))
            assertEquals(DbKeyMode.PASSPHRASE, DbKeyPayloadCodec.openModeOrder(p.mode).last(),
                "brick-safety: R in passphrase mode is always the last resort")
        }
    }

    // -- promotion preconditions -------------------------------------------------

    private fun allowed(
        platformAdopts: Boolean = true,
        openedInPassphraseMode: Boolean = true,
        moved: Boolean = false,
        rotationPending: Boolean? = false,
        journalPending: Boolean? = false,
        authBound: Boolean = false,
        recoveryNetProven: Boolean = false,
    ) = RawKeyAdoptionPolicy.rawKeyAdoptionAllowed(
        platformAdopts, openedInPassphraseMode, moved, rotationPending, journalPending, authBound, recoveryNetProven,
    )

    @Test
    fun adoption_allowed_onAPlainVaultThatJustOpenedInPassphraseMode() {
        assertTrue(allowed())
    }

    @Test
    fun adoption_neverOnAPlatformThatDoesNotAdopt() {
        assertFalse(allowed(platformAdopts = false), "iOS keeps its own raw-with-R mode; nothing to adopt")
    }

    @Test
    fun adoption_neverWithoutAPassphraseModeOpenThisUnlock() {
        assertFalse(allowed(openedInPassphraseMode = false),
            "an already-raw open (or a reconcile-opened handle) proves nothing about R")
    }

    @Test
    fun adoption_deferredWhenTheCredentialBlobsMovedThisUnlock() {
        assertFalse(allowed(moved = true), "KDF migration / rotation reconcile rewrote vlt_c: defer one cycle")
    }

    @Test
    fun adoption_refusedWhileAnM1RotationIsPendingOrUnknown() {
        assertFalse(allowed(rotationPending = true), "vlt_cn present: the union invariant still rules")
        assertFalse(allowed(rotationPending = null), "could not tell = refuse")
    }

    @Test
    fun adoption_refusedWhileAWriteAheadJournalIsPendingOrUnknown() {
        assertFalse(allowed(journalPending = true))
        assertFalse(allowed(journalPending = null))
    }

    @Test
    fun adoption_onAnAuthBoundVault_onlyBehindAProvenRecoveryNet() {
        assertFalse(allowed(authBound = true, recoveryNetProven = false))
        assertTrue(allowed(authBound = true, recoveryNetProven = true))
        assertTrue(allowed(authBound = false, recoveryNetProven = false), "a plain vault needs no net")
    }

    // -- commit gate --------------------------------------------------------------

    @Test
    fun commit_requiresTheRawProbeToHaveOpenedTheRealFile() {
        assertFalse(RawKeyAdoptionPolicy.rawKeyAdoptionMayCommit(rawProbeOpened = false, storedBlobUnchanged = true, roundTripOk = true),
            "a derived K' that has not opened the file is a computation, not evidence")
    }

    @Test
    fun commit_requiresTheStoredBlobToBeTheOneThisUnlockUnwrapped() {
        assertFalse(RawKeyAdoptionPolicy.rawKeyAdoptionMayCommit(rawProbeOpened = true, storedBlobUnchanged = false, roundTripOk = true))
    }

    @Test
    fun commit_refusesAFailedRoundTrip_butAllowsTheUncheckableAuthBoundCase() {
        assertFalse(RawKeyAdoptionPolicy.rawKeyAdoptionMayCommit(rawProbeOpened = true, storedBlobUnchanged = true, roundTripOk = false))
        assertTrue(RawKeyAdoptionPolicy.rawKeyAdoptionMayCommit(rawProbeOpened = true, storedBlobUnchanged = true, roundTripOk = true))
        assertTrue(RawKeyAdoptionPolicy.rawKeyAdoptionMayCommit(rawProbeOpened = true, storedBlobUnchanged = true, roundTripOk = null),
            "null = auth-bound (would prompt); allowed only because the precondition demanded a proven recovery net")
    }
}
