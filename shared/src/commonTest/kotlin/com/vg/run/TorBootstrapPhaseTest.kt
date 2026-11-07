package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * [TorBootstrapPhase] is a PRODUCER-side mapping onto the closed
 * [ConnectionLog.Code] vocabulary, and it is the only place a string that came
 * out of the Tor daemon decides which code reaches the connect timeline. Two
 * axes, same as the control-event parser's tests:
 *
 *  1. Behaviour — Tor's ladder maps onto the nine phase groups, monotonically
 *     and identically on both platforms (this is commonMain precisely so there
 *     is one table).
 *  2. THE LEAK PROPERTY — no input can produce anything except a member of the
 *     enum, and an input that is not a known tag lands on the pre-C2 catch-all
 *     rather than inventing a phase. A code is never derived from the value.
 */
class TorBootstrapPhaseTest {

    private fun code(tag: String) = TorBootstrapPhase.codeFor(tag)

    @Test
    fun theLadderMapsOntoThePhaseGroups() {
        assertEquals(ConnectionLog.Code.TOR_BOOT_STARTING, code("starting"))

        for (tag in listOf("conn", "conn_dir", "conn_pt", "conn_done_pt", "conn_proxy", "conn_done_proxy")) {
            assertEquals(ConnectionLog.Code.TOR_BOOT_CONN, code(tag), tag)
        }
        for (tag in listOf("conn_done", "handshake", "handshake_dir", "handshake_or", "handshake_done")) {
            assertEquals(ConnectionLog.Code.TOR_BOOT_HANDSHAKE, code(tag), tag)
        }
        for (tag in listOf("onehop_create", "requesting_status", "loading_status", "loading_keys")) {
            assertEquals(ConnectionLog.Code.TOR_BOOT_ONEHOP, code(tag), tag)
        }
        for (tag in listOf("requesting_descriptors", "loading_descriptors")) {
            assertEquals(ConnectionLog.Code.TOR_BOOT_DESCRIPTORS, code(tag), tag)
        }
        // The load-bearing boundary: everything before it is the DIRECTORY
        // problem, everything after it is the CIRCUIT problem.
        assertEquals(ConnectionLog.Code.TOR_BOOT_DIRINFO, code("enough_dirinfo"))
        for (tag in listOf(
            "ap_conn", "ap_conn_done", "ap_conn_pt", "ap_conn_done_pt",
            "ap_conn_proxy", "ap_conn_done_proxy", "ap_handshake", "ap_handshake_done",
        )) {
            assertEquals(ConnectionLog.Code.TOR_BOOT_AP_CONN, code(tag), tag)
        }
        assertEquals(ConnectionLog.Code.TOR_BOOT_CIRCUIT, code("circuit_create"))
        assertEquals(ConnectionLog.Code.TOR_BOOT_DONE, code("done"))
    }

    @Test
    fun anUnknownOrAbsentTagKeepsThePreC2CatchAll() {
        // A future Tor's new phase, the Android parser's "no parenthesised tag"
        // case, and a mis-parse must all read as "some bootstrap line" — never
        // as a phase we did not observe.
        for (tag in listOf("", " ", "brand_new_phase_in_tor_0_4_10", "42", "_", "ap")) {
            assertEquals(ConnectionLog.Code.TOR_BOOTSTRAP_TAG, code(tag), "<$tag>")
        }
    }

    @Test
    fun theMappingIsALookupAndNeverEchoesItsInput() {
        // Hostile shapes: an address, an onion, prose with a known tag inside
        // it, punctuation. None of them is a tag, so none of them maps to a
        // phase — and the return type makes it structurally impossible for any
        // fragment of the input to travel.
        for (tag in listOf(
            "conn 10.1.2.3:9001",
            "done; rm -rf /",
            "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv.onion",
            "\$9695DFC35FFEB861329B9F1AB04C46397020CE31~moria1",
            "enough_dirinfo=yes",
            "x".repeat(4096),
        )) {
            assertEquals(ConnectionLog.Code.TOR_BOOTSTRAP_TAG, code(tag), tag.take(24))
        }
        // And every reachable answer is a member of the enum by construction.
        assertTrue(ConnectionLog.Code.entries.contains(code("enough_dirinfo")))
    }

    @Test
    fun tagMatchingIsCaseInsensitive() {
        // Android reads the tag out of a NOTICE log line and iOS out of a
        // control-port argument; neither is guaranteed to keep Tor's casing
        // forever, and a case flip must not silently downgrade every line to
        // the catch-all.
        assertEquals(ConnectionLog.Code.TOR_BOOT_DIRINFO, code("ENOUGH_DIRINFO"))
        assertEquals(ConnectionLog.Code.TOR_BOOT_CONN, code("Conn"))
        assertEquals(ConnectionLog.Code.TOR_BOOT_DONE, code("DONE"))
    }
}
