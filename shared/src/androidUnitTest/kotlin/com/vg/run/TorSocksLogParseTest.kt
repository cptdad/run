package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/**
 * The Tor NOTICE-log SOCKS-port parser had ZERO
 * coverage despite a history of trap-class bugs (a partially-flushed line let
 * "…127.0.0.1:44321" be read as port 4432). Getting this wrong points the app's
 * SOCKS traffic at whatever local process holds the mis-parsed port — a
 * deanonymisation and capability-token-leak hazard, not a cosmetic bug.
 */
class TorSocksLogParseTest {

    @Test
    fun parsesTheModernLoopbackForm() {
        assertEquals(
            44321,
            TorNoticeLog.parseSocksListenerPort(
                "Jul 20 12:00:00.000 [notice] Socks listener listening on 127.0.0.1:44321"
            ),
        )
    }

    @Test
    fun parsesTheLegacyPortForm() {
        assertEquals(
            9050,
            TorNoticeLog.parseSocksListenerPort("[notice] Socks listener listening on port 9050"),
        )
    }

    @Test
    fun unrelatedLinesYieldNull() {
        assertNull(TorNoticeLog.parseSocksListenerPort("[notice] Bootstrapped 100% (done): Done"))
        assertNull(TorNoticeLog.parseSocksListenerPort(""))
        assertNull(TorNoticeLog.parseSocksListenerPort("Socks listener listening on 127.0.0.1:"))
        // A control-port line must never be mistaken for the SOCKS one.
        assertNull(TorNoticeLog.parseSocksListenerPort(
            "[notice] Control listener listening on 127.0.0.1:9051"))
    }

    @Test
    fun outOfRangePortIsRejectedRatherThanTruncated() {
        // The failure mode's cousin: a corrupt/hostile line must yield NOTHING
        // rather than a plausible-looking port the app would then dial.
        assertNull(TorNoticeLog.parseSocksListenerPort(
            "[notice] Socks listener listening on 127.0.0.1:99999"))
        assertNull(TorNoticeLog.parseSocksListenerPort(
            "[notice] Socks listener listening on 127.0.0.1:0"))
    }

    @Test
    fun aTruncatedPortParsesToTheTruncatedValue_whichIsWhyOnlyCompleteLinesAreFed() {
        // Documents the REASON TorNoticeLogTail.pollLines exists: a line cut mid-number
        // is indistinguishable from a genuine shorter port at this layer, so the
        // caller must never hand a partial line here. The parser cannot save us —
        // the newline discipline in `TorNoticeLogTail.pollLines` is the actual defense.
        assertEquals(
            4432,
            TorNoticeLog.parseSocksListenerPort(
                "Jul 20 12:00:00.000 [notice] Socks listener listening on 127.0.0.1:4432"
            ),
        )
    }
}
