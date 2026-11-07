package com.vg.run

import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// C4 groundwork (2026-10-09): the guard-channel kick re-binds `SocksPort auto` on
// a NEW port; every Tor-proxied client resolves its port through
// SocksPortRedirect at each connection. Rules: unmoved ports pass through; the
// old port is BLOCKED (→ port 1, nothing can listen) between the kick and the
// readback; a readback re-points it; a failed readback stays blocked (fail
// closed); a new Tor process resets everything; the readback parser accepts a
// 127.0.0.1 listener only.
// ---------------------------------------------------------------------------

class SocksPortRedirectTest {

    @BeforeTest fun clean() = SocksPortRedirect.reset()
    @AfterTest fun cleanAfter() = SocksPortRedirect.reset()

    @Test
    fun anUnmovedPortPassesThrough() {
        assertEquals(41234, SocksPortRedirect.resolve(41234))
    }

    @Test
    fun theGapIsBlocked_thenTheMoveRepointsEveryClient() {
        SocksPortRedirect.beginMove(41234)
        assertEquals(SocksPortRedirect.BLOCKED_PORT, SocksPortRedirect.resolve(41234), "never the closed (squattable) port")
        assertEquals(50000, SocksPortRedirect.resolve(50000), "other ports untouched")
        assertTrue(SocksPortRedirect.completeMove(41234, 45678))
        assertEquals(45678, SocksPortRedirect.resolve(41234))
        assertEquals(45678, SocksPortRedirect.resolve(45678))
    }

    @Test
    fun aFailedReadbackStaysBlocked() {
        SocksPortRedirect.beginMove(41234)
        assertFalse(SocksPortRedirect.completeMove(41234, 0))
        assertFalse(SocksPortRedirect.completeMove(41234, 80), "privileged ports are refused")
        assertFalse(SocksPortRedirect.completeMove(41234, 70000))
        assertEquals(SocksPortRedirect.BLOCKED_PORT, SocksPortRedirect.resolve(41234))
    }

    @Test
    fun theSamePortConfirmedByTor_justUnblocks() {
        SocksPortRedirect.beginMove(41234)
        assertTrue(SocksPortRedirect.completeMove(41234, 41234))
        assertEquals(41234, SocksPortRedirect.resolve(41234))
    }

    @Test
    fun chainedPortMoves_blockEveryOlderClientUntilTheLatestMoveCompletes() {
        SocksPortRedirect.beginMove(41234)
        SocksPortRedirect.completeMove(41234, 45678)
        SocksPortRedirect.beginMove(45678)
        assertEquals(SocksPortRedirect.BLOCKED_PORT, SocksPortRedirect.resolve(41234), "the oldest client is blocked too")
        SocksPortRedirect.completeMove(45678, 47000)
        assertEquals(47000, SocksPortRedirect.resolve(41234))
    }

    @Test
    fun aNewTorProcessResetsEverything() {
        SocksPortRedirect.beginMove(41234)
        SocksPortRedirect.reset()
        assertEquals(41234, SocksPortRedirect.resolve(41234), "a new Tor may legitimately reuse the number")
    }

    @Test
    fun theBlockedPortIsPrivileged() {
        assertTrue(SocksPortRedirect.BLOCKED_PORT in 1 until SocksPortRedirect.MIN_LISTENER_PORT)
    }

    // --- readback parser ------------------------------------------------------

    @Test
    fun parsesTheGetinfoReply() {
        assertEquals(45678, SocksPortRedirect.parseGetinfoSocksPort(listOf("250-net/listeners/socks=\"127.0.0.1:45678\"", "250 OK")))
        assertEquals(45678, SocksPortRedirect.parseGetinfoSocksPort(listOf("250 net/listeners/socks=\"127.0.0.1:45678\"\r\n")))
        assertEquals(45678, SocksPortRedirect.parseGetinfoSocksPort(listOf("250-net/listeners/socks=127.0.0.1:45678", "250 OK")))
    }

    @Test
    fun picksTheLoopbackListenerOnly_andFailsClosed() {
        assertEquals(
            45678,
            SocksPortRedirect.parseGetinfoSocksPort(listOf("250-net/listeners/socks=\"[::1]:41000\" \"127.0.0.1:45678\"", "250 OK")),
        )
        assertNull(SocksPortRedirect.parseGetinfoSocksPort(listOf("250-net/listeners/socks=\"0.0.0.0:45678\"", "250 OK")))
        assertNull(SocksPortRedirect.parseGetinfoSocksPort(listOf("250-net/listeners/socks=", "250 OK")), "no listener")
        assertNull(SocksPortRedirect.parseGetinfoSocksPort(listOf("552 Unrecognized key")))
        assertNull(SocksPortRedirect.parseGetinfoSocksPort(listOf("250-net/listeners/socks=\"127.0.0.1:80\"", "250 OK")), "privileged")
        assertNull(SocksPortRedirect.parseGetinfoSocksPort(listOf("250-net/listeners/socks=\"127.0.0.1:x\"", "250 OK")))
        assertNull(SocksPortRedirect.parseGetinfoSocksPort(emptyList()))
    }
}
