package com.vg.run

import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The debug-log uploader's relative clock (`+SSSSS.mmm` since a per-process
 * origin) must keep counting past the origin's time-of-day. Pinned after the
 * 2026-10-26 production Pixel stream: the process had lived since the previous
 * morning, every line was written at a time-of-day EARLIER than the origin's,
 * and the old time-of-day subtraction rendered all of them as `+00000.000`
 * under a day-old `t0`.
 */
class DebugLogRelativeClockTest {
    // 2026-10-25T06:38:00Z — the real origin of that Pixel's process.
    private val originEpochMs = 1_792_910_280_000L
    private val originMsOfDay = (6 * 3600 + 38 * 60) * 1000

    @BeforeTest fun pin() = DebugLogUploader.setOriginForTest(originMsOfDay, originEpochMs)
    @AfterTest fun clear() = DebugLogUploader.clearOriginForTest()

    private fun rebase(line: String, nowMs: Long) = DebugLogUploader.toRelativeTime(line, originMsOfDay, nowMs)

    @Test
    fun originLineMillisecondsAheadOfNow_isNotTakenForYesterday() {
        // The origin line was stamped 3 ms AFTER the batch's nowMs (two threads, two clock reads).
        // Without the clamp establishOrigin() placed the origin a day in the past and every
        // later line rendered as ~+86400 s.
        DebugLogUploader.clearOriginForTest()
        val now = originEpochMs
        val origin = DebugLogUploader.establishOrigin(listOf("06:38:00.003 D/X: first"), now)
        assertEquals(originMsOfDay + 3, origin)
        assertEquals("+00009.997 D/X: y", DebugLogUploader.toRelativeTime("06:38:10.000 D/X: y", origin, now + 10_000L))
    }

    @Test
    fun sameDay_offsetIsSecondsSinceOrigin() {
        val now = originEpochMs + 3_600_000L
        assertEquals("+01800.500 D/X: y", rebase("07:08:00.500 D/X: y", now))
    }

    @Test
    fun aDayLater_timeOfDayBeforeOrigin_keepsCounting() {
        // 23 h 42 min after the origin: 06:20:00 the next morning, i.e. a time-of-day
        // BELOW the origin's 06:38 — the exact shape that used to collapse to zero.
        val now = originEpochMs + 85_320_000L
        assertEquals("+85320.000 D/X: y", rebase("06:20:00.000 D/X: y", now))
    }

    @Test
    fun severalDaysLater_offsetGrowsPastFiveDigits() {
        val now = originEpochMs + 3 * 86_400_000L + 1_000L
        assertEquals("+259201.000 D/X: y", rebase("06:38:01.000 D/X: y", now))
    }

    @Test
    fun smallInversionBeforeOrigin_clampsToZero() {
        val now = originEpochMs + 5_000L
        assertEquals("+00000.000 D/X: y", rebase("06:37:59.990 D/X: y", now))
    }

    @Test
    fun lineSlightlyAheadOfNow_isAClockInversionNotYesterday() {
        val now = originEpochMs + 10_000L
        assertEquals("+00010.500 D/X: y", rebase("06:38:10.500 D/X: y", now))
    }

    @Test
    fun noOriginPinned_leavesTheLineAlone() {
        DebugLogUploader.clearOriginForTest()
        assertEquals("06:38:10.500 D/X: y", DebugLogUploader.toRelativeTime("06:38:10.500 D/X: y", -1, originEpochMs))
    }

    @Test
    fun lineWithoutClockPrefix_leavesTheLineAlone() {
        assertEquals("no clock here", rebase("no clock here", originEpochMs + 1_000L))
    }
}
