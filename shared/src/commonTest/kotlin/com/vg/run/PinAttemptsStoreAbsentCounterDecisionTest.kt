package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// Absent-counter decision (brick-safe).
// The stores are expect classes with no common fake seam, so this pins the two
// extracted pure rules both platforms' readAbsentCounter() consumes; the Android
// wiring (including the establish-on-read WRITE) is covered end-to-end by the
// instrumented PinAttemptsStoreSplitTest, and the iOS wiring passes the DB-key-
// wrap presence probe (IosAppController) into the vaultConfigured leg below.
//
// The rule pair (mutually exclusive; both false when the vault is NOT configured):
//   tamper       = established && configured   (marker survived a deletion)
//   shouldEstablish = !established && configured (legacy / unmigrated / provision)
// ---------------------------------------------------------------------------

class PinAttemptsStoreAbsentCounterDecisionTest {

    @Test
    fun legitFirstRun_notConfigured_neitherTamperNorEstablish() {
        // Fresh install / post-wipe: counter absent, nothing configured (vlt_c
        // gone) — read 0, never wipe AND never establish (establish-on-read must
        // not resurrect state after a wipe).
        assertFalse(PinAttemptsStore.absentCounterIsTamper(established = false, vaultConfigured = false))
        assertFalse(PinAttemptsStore.absentCounterShouldEstablish(established = false, vaultConfigured = false))
    }

    @Test
    fun markerSurvives_counterDeleted_onConfiguredVault_isTamper() {
        // The deletion attack: the fate-shared marker survives a counter-blob
        // deletion while the vault is still configured → tamper (→ wipe), and NOT
        // establish (the counter was demonstrably established before).
        assertTrue(PinAttemptsStore.absentCounterIsTamper(established = true, vaultConfigured = true))
        assertFalse(PinAttemptsStore.absentCounterShouldEstablish(established = true, vaultConfigured = true))
    }

    @Test
    fun markerPresentButNotConfigured_isNotTamper() {
        // A surviving marker with the vault NOT configured (e.g. a torn wipe that
        // cleared vlt_c but left the marker) must NOT wipe — there is no vault to
        // protect. vlt_c-presence is the required AND-gate.
        assertFalse(PinAttemptsStore.absentCounterIsTamper(established = true, vaultConfigured = false))
        assertFalse(PinAttemptsStore.absentCounterShouldEstablish(established = true, vaultConfigured = false))
    }

    @Test
    fun legacyVault_configuredNoMarker_establishes_notTamper() {
        // THE BRICK FIX: a legacy / unmigrated / interrupted-
        // provision vault (vlt_c present, no marker, no counter) must ESTABLISH on
        // read, NEVER wipe (reading this state as tamper would brick a real vault).
        assertFalse(PinAttemptsStore.absentCounterIsTamper(established = false, vaultConfigured = true))
        assertTrue(PinAttemptsStore.absentCounterShouldEstablish(established = false, vaultConfigured = true))
    }

    // -----------------------------------------------------------------------
    // Verified provision-time establishment. The old
    // best-effort reset() (tryWrite swallows a key outage; Unit return) let an
    // iOS provision COMPLETE with the DB-key wrap present but counter+marker
    // absent — the tamper signature above — wiping the honest vault at next
    // launch. runVerifiedEstablishment is the pure loop establishVerified()
    // runs with the real store; provision aborts when it reports false.
    // -----------------------------------------------------------------------

    @Test
    fun establishment_firstAttemptSucceeds_isVerified() {
        var writes = 0
        assertTrue(PinAttemptsStore.runVerifiedEstablishment(
            writeCounter = { writes++; true },
            readBack = { 0 },
        ))
        assertEquals(1, writes)
    }

    @Test
    fun establishment_allWritesFail_reportsFalse_neverSilently() {
        // The device key is down for all attempts: the primitive must SAY so
        // (provision aborts, ok=false) — never complete silently like reset().
        var writes = 0
        assertFalse(PinAttemptsStore.runVerifiedEstablishment(
            writeCounter = { writes++; false },
            readBack = { 0 },
        ))
        assertEquals(4, writes)
    }

    @Test
    fun establishment_writeClaimsSuccess_butReadBackSeesNothing_reportsFalse() {
        // Silent-store case: the write reported success but the read-back finds
        // no decryptable blob (null = absent / outage / tamper read) — the
        // counter is NOT verifiably established, so provision must not proceed.
        // establishVerified()'s readBack returns null for a MISSING blob before
        // ever calling read() — a bare read() would return 0 via
        // readAbsentCounter() in the pre-wrap provision state and falsely
        // verify a silently-rejected iOS kvPut; this test models that wiring.
        assertFalse(PinAttemptsStore.runVerifiedEstablishment(
            writeCounter = { true },
            readBack = { null },
        ))
    }

    @Test
    fun establishment_readBackOfForeignCount_reportsFalse() {
        // Read-back must confirm the FRESH zero blob, not just "something reads".
        assertFalse(PinAttemptsStore.runVerifiedEstablishment(
            writeCounter = { true },
            readBack = { 3 },
        ))
    }

    @Test
    fun establishment_transientOutageThenSuccess_isVerified() {
        // A warm-up glitch on the first attempts heals within the retry budget.
        var attempt = 0
        assertTrue(PinAttemptsStore.runVerifiedEstablishment(
            writeCounter = { ++attempt >= 3 },
            readBack = { 0 },
        ))
        assertEquals(3, attempt)
    }

    /**
     * Interleaving enumeration (mirrors the comment in
     * IosAppController.setRealCredential). With establishment ordered BEFORE the
     * DB-key wrap (and the counter blob written BEFORE the marker inside
     * write()), an interrupted honest provision can only be observed in these
     * states — none of which reads as tamper:
     *  1. died before the counter write → counter/marker/wrap all absent;
     *  2. died between counter and marker → counter PRESENT (decision unused);
     *  3. died after establishment, before the verifier → counter PRESENT;
     *  4. died between verifier and wrap → counter PRESENT (verifier purged);
     *  5. establishment unverifiable → provision ABORTED, no wrap ever written;
     *  6. wrap persisted → counter was verified present first.
     * The tamper rows (marker or wrap present with the counter absent) therefore
     * require a DELETION, never an honest interruption.
     */
    @Test
    fun honestProvisionInterleavings_neverReadAsTamper() {
        // State 1 (and the post-abort state 5): the only counter-ABSENT states an
        // honest provision can leave behind — pre-wrap, so NOT configured → never
        // tamper. (Post-wrap-but-pre-counter is now impossible: establishVerified
        // runs BEFORE the wrap, and establish-on-read backstops it anyway.)
        assertFalse(PinAttemptsStore.absentCounterIsTamper(established = false, vaultConfigured = false))
        // States 2/3/4/6 leave the counter blob PRESENT, so the absent-counter
        // decision is never consulted — read() decrypts the blob and returns the
        // count regardless of marker/wrap presence.
    }
}
