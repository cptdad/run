package com.vg.run

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * The `boot` telemetry field's one rule: FIRST STAMP WINS.
 *
 * `boot` must describe how long THIS session's Tor PROCESS took to reach
 * `Connected`. Two observers can see that transition:
 *
 *  1. `ConnectTelemetryRecorder.armBootStamp` — armed pre-unlock, beside the speculative Tor
 *     start, so it fires when the bootstrap actually finishes;
 *  2. `RunViewModel.startTorMonitor` — attached at UNLOCK, whose `StateFlow`
 *     collector is replayed an already-`Connected` state and would therefore
 *     measure `max(true bootstrap, time-to-unlock)`.
 *
 * Before C6 only (2) existed: the dev-relay device runs reported Android `boot` p50 = 40 s
 * while SOCKS_READY was at 5 s, i.e. an unlock-latency histogram. These pin the
 * arithmetic that makes (2) a no-op once (1) has stamped — the same "one wait"
 * discipline the connect anchor and `tor` already follow, so a self-heal Tor
 * restart, a manual Reconnect, or an activity recreation (the ViewModel owns
 * the value) can never move it.
 *
 * iOS never had the defect: its `TorManager.$state` sink is installed in
 * `AppState.init` (pre-unlock) and latches `torConnectedUptime` on the first
 * `.connected` — this restores parity, it does not change iOS.
 */
class BootStampFirstWinsTest {

    @Test
    fun stampsTheElapsedTimeFromTheProcessAnchor() {
        // Tor started at 1_000, reached Connected at 6_500 → a 5.5 s bootstrap.
        assertEquals(5_500L, firstBootStamp(existingMs = null, anchorMs = 1_000L, nowMs = 6_500L))
    }

    @Test
    fun theFirstStampWins_aLaterUnlockNeverOverwritesIt() {
        // THE regression this exists for: the pre-unlock observer stamped 5 s,
        // then the user finished typing 35 s later and the post-unlock monitor
        // saw the replayed Connected. The answer must still be 5 s.
        assertEquals(
            5_000L,
            firstBootStamp(existingMs = 5_000L, anchorMs = 1_000L, nowMs = 41_000L),
        )
    }

    @Test
    fun aZeroStampIsAValueAndIsKept() {
        // Zero is the interesting value (Tor was already connected when the
        // observer attached), NOT a missing measurement — a `?: ` on the Long
        // rather than on the nullable box would silently re-stamp here.
        assertEquals(0L, firstBootStamp(existingMs = 0L, anchorMs = 1_000L, nowMs = 90_000L))
    }

    @Test
    fun noTorProcessAnchorMeansNoField() {
        // Debug/direct path: no Tor at all, so `boot` is OMITTED from the report
        // rather than sent as a zero.
        assertNull(firstBootStamp(existingMs = null, anchorMs = null, nowMs = 12_345L))
    }

    @Test
    fun aClockThatWentBackwardsClampsToZeroRatherThanReportingNegative() {
        assertEquals(0L, firstBootStamp(existingMs = null, anchorMs = 9_000L, nowMs = 1_000L))
    }

    @Test
    fun repeatedConnectedTransitionsFoldToTheFirstOne() {
        // The real sequence: pre-unlock Connected, unlock replay, a self-heal
        // restart's Connected, a manual Reconnect's Connected.
        var boot: Long? = null
        for (now in listOf(6_000L, 40_000L, 150_000L, 300_000L)) {
            boot = firstBootStamp(existingMs = boot, anchorMs = 1_000L, nowMs = now)
        }
        assertEquals(5_000L, boot)
    }
}
