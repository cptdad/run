package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// BOOTSTRAP-STALL RUNG (2026-10-06). A bootstrap percent that stands still for
// TorBootstrapStall.STALL_MS inside the ladder (5 <= % < 100) earns ONE pipelined
// `SETCONF DisableNetwork=1` / `=0` on the command connection, at most MAX_KICKS
// per Tor process, never within NEWNYM_SPACING_MS of a NEWNYM. Both platforms
// call the predicate, the phrases and (Android) the event parser tested here.
// ---------------------------------------------------------------------------

class TorBootstrapStallTest {

    private val never = TorBootstrapStall.NEVER

    private fun until(
        pct: Int = 55,
        sinceProgress: Long = 20_000L,
        sinceKick: Long = never,
        sinceNewnym: Long = never,
        fired: Int = 0,
    ) = TorBootstrapStall.msUntilKick(pct, sinceProgress, sinceKick, sinceNewnym, fired)

    // --- the predicate -----------------------------------------------------

    @Test
    fun constants_areTheDesignedOnes() {
        assertEquals(20_000L, TorBootstrapStall.STALL_MS)
        assertEquals(2, TorBootstrapStall.MAX_KICKS)
        assertEquals(5, TorBootstrapStall.MIN_PERCENT)
        assertEquals(10_000L, TorBootstrapStall.NEWNYM_SPACING_MS)
    }

    @Test
    fun stalledLongEnough_insideTheLadder_kicksNow() {
        assertEquals(0L, until(sinceProgress = 20_000L))
        assertEquals(0L, until(sinceProgress = 95_000L))
        assertTrue(TorBootstrapStall.shouldKick(55, 20_000L, never, never, 0))
    }

    @Test
    fun notYetStalled_returnsTheRemainingWait() {
        assertEquals(20_000L, until(sinceProgress = 0L))
        assertEquals(1L, until(sinceProgress = 19_999L))
        assertFalse(TorBootstrapStall.shouldKick(55, 19_999L, never, never, 0))
    }

    @Test
    fun ladderBounds_fiveInclusive_hundredExclusive() {
        assertEquals(TorBootstrapStall.NO_KICK, until(pct = 0))
        assertEquals(TorBootstrapStall.NO_KICK, until(pct = 4))
        assertEquals(0L, until(pct = 5))
        assertEquals(0L, until(pct = 99))
        assertEquals(TorBootstrapStall.NO_KICK, until(pct = 100))
        assertEquals(TorBootstrapStall.NO_KICK, until(pct = 101))
        assertEquals(TorBootstrapStall.NO_KICK, until(pct = -1))
    }

    @Test
    fun budget_twoPerProcess_thenNever() {
        assertEquals(0L, until(fired = 1, sinceKick = 20_000L))
        assertEquals(TorBootstrapStall.NO_KICK, until(fired = 2, sinceKick = 60_000L))
        assertEquals(TorBootstrapStall.NO_KICK, until(fired = 7))
    }

    @Test
    fun negativeCounterOrClock_failsClosed() {
        assertEquals(TorBootstrapStall.NO_KICK, until(fired = -1))
        assertEquals(TorBootstrapStall.NO_KICK, until(sinceProgress = -1L))
        assertEquals(TorBootstrapStall.NO_KICK, until(sinceKick = -1L))
    }

    @Test
    fun secondKick_needsAFreshStallAfterTheFirst() {
        // Percent unchanged for 45 s, but the first kick went out 5 s ago.
        assertEquals(15_000L, until(sinceProgress = 45_000L, sinceKick = 5_000L, fired = 1))
        assertEquals(0L, until(sinceProgress = 45_000L, sinceKick = 20_000L, fired = 1))
    }

    @Test
    fun newnymSpacing_defersButNeverCancels() {
        assertEquals(7_000L, until(sinceNewnym = 3_000L))
        assertEquals(0L, until(sinceNewnym = 10_000L))
        // Both clocks pending: the LATER deadline wins.
        assertEquals(12_000L, until(sinceProgress = 8_000L, sinceNewnym = 9_000L))
        assertEquals(9_000L, until(sinceProgress = 18_000L, sinceNewnym = 1_000L))
        // A negative NEWNYM clock means "just now", never "long ago".
        assertEquals(10_000L, until(sinceNewnym = -5L))
    }

    // --- the shared phrases -------------------------------------------------

    @Test
    fun phrases_areFixedWordsAndNumbersOnly() {
        assertEquals(
            "bootstrap stalled 20 s at 55% - network re-kicked (1/2)",
            TorBootstrapStall.kickLine(55, 1),
        )
        assertEquals(
            "bootstrap stalled 20 s at 69% - network re-kick unavailable",
            TorBootstrapStall.skipLine(69),
        )
        // redact() must have nothing to do on either.
        for (line in listOf(TorBootstrapStall.kickLine(99, 2), TorBootstrapStall.skipLine(5))) {
            assertEquals(line, ConnectionLog.redact(line))
            assertTrue(line.all { it == ' ' || it.isLetterOrDigit() || it in "%-()/." }, line)
        }
    }

    @Test
    fun codes_existAndStayWithinTheWireNameLength() {
        val kick = ConnectionLog.Code.TOR_BOOT_KICK
        val skip = ConnectionLog.Code.TOR_BOOT_KICK_SKIP
        for (c in listOf(kick, skip)) {
            // ≤ 20 chars: TOR_BOOTSTRAP_PROBLEM (21) stays the longest name, so
            // the telemetry body ceiling arithmetic is unchanged.
            assertTrue(c.name.length <= 20, c.name)
            assertTrue(c.name.all { it in 'A'..'Z' || it == '_' }, c.name)
        }
    }

    // --- the control-event parser (Android's event socket) -----------------

    private val hostile =
        "WARNING=\"Connection refused\" REASON=CONNECTREFUSED COUNT=3 RECOMMENDATION=warn " +
            "HOSTID=\"\$0123456789ABCDEF0123456789ABCDEF01234567\" HOSTADDR=\"198.51.100.7:9001\""

    @Test
    fun progress_isReadFromAStatusClientBootstrapEvent() {
        assertEquals(
            55,
            TorBootstrapStall.progressFromControlEvent(
                "650 STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=55 TAG=loading_descriptors SUMMARY=\"Loading relay descriptors\"\r\n",
            ),
        )
        assertEquals(
            5,
            TorBootstrapStall.progressFromControlEvent("STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=5 TAG=conn SUMMARY=\"Connecting to a relay\""),
        )
        assertEquals(
            100,
            TorBootstrapStall.progressFromControlEvent("650-STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\""),
        )
        // A WARN problem event re-reports the current percent — harmless (the
        // platforms track the HIGHEST), and nothing else of it is read.
        assertEquals(
            14,
            TorBootstrapStall.progressFromControlEvent("650 STATUS_CLIENT WARN BOOTSTRAP PROGRESS=14 TAG=handshake SUMMARY=\"x\" $hostile"),
        )
    }

    @Test
    fun progress_nothingButTheIntegerLeaves_andGarbageIsNull() {
        // The return type is Int?: no field of the event can leave. These pin
        // that hostile or malformed shapes yield null rather than a misread.
        assertNull(TorBootstrapStall.progressFromControlEvent("650 STATUS_CLIENT NOTICE CIRCUIT_ESTABLISHED"))
        assertNull(TorBootstrapStall.progressFromControlEvent("650 STATUS_GENERAL NOTICE BOOTSTRAP PROGRESS=50"))
        assertNull(TorBootstrapStall.progressFromControlEvent("650 STATUS_CLIENT NOTICE BOOTSTRAP TAG=conn $hostile"))
        assertNull(TorBootstrapStall.progressFromControlEvent("650 STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=1000 TAG=x"))
        assertNull(TorBootstrapStall.progressFromControlEvent("650 STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=101 TAG=x"))
        assertNull(TorBootstrapStall.progressFromControlEvent("650 STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=-5 TAG=x"))
        assertNull(TorBootstrapStall.progressFromControlEvent("650 STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS= TAG=x"))
        assertNull(TorBootstrapStall.progressFromControlEvent("650 STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=5x TAG=x"))
        assertNull(TorBootstrapStall.progressFromControlEvent("650 HS_DESC REQUESTED abc NO_AUTH \$AAAA~nick"))
        assertNull(TorBootstrapStall.progressFromControlEvent(""))
        assertNull(TorBootstrapStall.progressFromControlEvent("250 OK"))
    }
}
