package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * [parseTorControlEvent] is the ONE place where text produced by the Tor daemon
 * becomes text on a RELEASE-VISIBLE panel, so it is tested on two axes:
 *
 *  1. Behaviour — every event family maps to the right phrase + [ConnectionLog.Code],
 *     and an unknown REASON degrades to `OTHER` instead of being echoed.
 *  2. THE LEAK PROPERTY — a line built from an event carrying an HSAddress, an
 *     HsDir fingerprint, a Path, a Target, a SOURCE/SOURCE_ADDR, a guard nickname
 *     or HOSTID/HOSTADDR contains none of those values. This is the property the
 *     producer rule in ConnectionLog.kt actually rests on; `redact()` is only
 *     defence in depth and would not catch a nickname or an IPv4 literal.
 */
class TorControlEventParseTest {

    // Realistic argument values that must NEVER reach a line.
    private val onion = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv.onion"
    private val hsDir = "\$9695DFC35FFEB861329B9F1AB04C46397020CE31~moria1"
    private val descId = "g5rfxkdcb5wc3lwqxbrnmfphs2j3zfmf"
    private val path = "\$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA~guardnick,\$BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB~middlenick"

    private fun parse(line: String) = parseTorControlEvent(line)

    private fun textOf(line: String): String {
        val ev = parse(line)
        assertNotNull(ev, "expected a line for: $line")
        return ev.text
    }

    // -- HS_DESC -----------------------------------------------------------

    @Test
    fun hsDescRequestedAndReceived() {
        val requested = parse("650 HS_DESC REQUESTED $onion NO_AUTH $hsDir $descId")
        assertEquals(ConnectionLog.Code.HSDESC_REQUESTED, requested?.code)
        assertEquals("descriptor requested", requested?.text)
        assertEquals(ConnectionLog.Kind.TOR, requested?.kind)

        val received = parse("650 HS_DESC RECEIVED $onion NO_AUTH $hsDir $descId")
        assertEquals(ConnectionLog.Code.HSDESC_RECEIVED, received?.code)
        assertEquals("descriptor received", received?.text)
    }

    @Test
    fun hsDescFailedCarriesTheAllowlistedReasonOnly() {
        val ev = parse("650 HS_DESC FAILED $onion NO_AUTH $hsDir $descId REASON=NOT_FOUND")
        assertEquals(ConnectionLog.Code.HSDESC_NOT_FOUND, ev?.code)
        assertEquals("descriptor fetch failed: NOT_FOUND", ev?.text)

        assertEquals(
            "descriptor fetch failed: QUERY_RATE_LIMITED",
            textOf("650 HS_DESC FAILED $onion NO_AUTH $hsDir REASON=QUERY_RATE_LIMITED"),
        )
    }

    @Test
    fun hsDescUnknownReasonFallsBackToOther() {
        assertEquals(
            "descriptor fetch failed: OTHER",
            textOf("650 HS_DESC FAILED $onion NO_AUTH $hsDir REASON=SOMETHING_NEW"),
        )
        // A missing REASON must not produce a dangling phrase either.
        assertEquals(
            "descriptor fetch failed: OTHER",
            textOf("650 HS_DESC FAILED $onion NO_AUTH $hsDir"),
        )
    }

    @Test
    fun hsDescFailedCodeIsSplitByReasonThroughTheFixedMap() {
        // 2026-10-23: the CODE (what reaches the connect timeline) names the
        // reason; the TEXT is unchanged. Every argument is identifying and must
        // stay out of the text whatever the reason.
        val expected = mapOf(
            "NOT_FOUND" to ConnectionLog.Code.HSDESC_NOT_FOUND,
            "QUERY_NO_HSDIR" to ConnectionLog.Code.HSDESC_NO_HSDIR,
            "QUERY_RATE_LIMITED" to ConnectionLog.Code.HSDESC_RATE_LIMITED,
            "BAD_DESC" to ConnectionLog.Code.HSDESC_BAD_DESC,
            "UNEXPECTED" to ConnectionLog.Code.HSDESC_UNEXPECTED,
            // On the panel allowlist but deliberately NOT split: rare (an HTTP
            // 400 from the HSDir), so it keeps the pre-split code.
            "QUERY_REJECTED" to ConnectionLog.Code.HSDESC_FAILED,
        )
        for ((reason, code) in expected) {
            val ev = parse("650 HS_DESC FAILED $onion NO_AUTH $hsDir $descId REASON=$reason")
            assertNotNull(ev, reason)
            assertEquals(code, ev.code, reason)
            assertEquals("descriptor fetch failed: $reason", ev.text)
            for (secret in listOf(onion, hsDir, descId, "9695DFC35FFEB861329B9F1AB04C46397020CE31", "moria1")) {
                assertFalse(ev.text.contains(secret), "$reason line leaked $secret")
            }
        }
    }

    @Test
    fun hsDescFailedUnknownOrMissingReasonKeepsThePreSplitCode() {
        for (line in listOf(
            "650 HS_DESC FAILED $onion NO_AUTH $hsDir REASON=SOMETHING_NEW",
            "650 HS_DESC FAILED $onion NO_AUTH $hsDir",
            // A reason that SMUGGLES a value must never become a code of its own.
            "650 HS_DESC FAILED $onion NO_AUTH $hsDir REASON=NOT_FOUND_$descId",
            "650 HS_DESC FAILED $onion NO_AUTH $hsDir REASON=$onion",
        )) {
            val ev = parse(line)
            assertNotNull(ev, line)
            assertEquals(ConnectionLog.Code.HSDESC_FAILED, ev.code, line)
            assertEquals("descriptor fetch failed: OTHER", ev.text, line)
        }
    }

    @Test
    fun dedupeFoldsTheWholeHsDescFailureFamilyIntoOneWindow() {
        // Before the split all of these were HSDESC_FAILED and shared one 2 s
        // window; the panel must still show ONE line for a mixed-reason burst.
        val dedupe = TorEventDedupe()
        assertTrue(dedupe.allow(ConnectionLog.Code.HSDESC_NOT_FOUND, 1_000))
        assertFalse(dedupe.allow(ConnectionLog.Code.HSDESC_NO_HSDIR, 1_500))
        assertFalse(dedupe.allow(ConnectionLog.Code.HSDESC_FAILED, 2_000))
        assertFalse(dedupe.allow(ConnectionLog.Code.HSDESC_BAD_DESC, 2_999))
        assertTrue(dedupe.allow(ConnectionLog.Code.HSDESC_UNEXPECTED, 3_000))
        // …and the fold does not swallow the unrelated descriptor codes.
        assertTrue(dedupe.allow(ConnectionLog.Code.HSDESC_REQUESTED, 3_100))
        assertTrue(dedupe.allow(ConnectionLog.Code.HSDESC_RECEIVED, 3_200))
    }

    @Test
    fun hsDescServiceSideActionsAreIgnored() {
        assertNull(parse("650 HS_DESC CREATED $onion UNKNOWN $hsDir $descId"))
        assertNull(parse("650 HS_DESC UPLOAD $onion UNKNOWN $hsDir $descId"))
        assertNull(parse("650 HS_DESC UPLOADED $onion UNKNOWN $hsDir"))
        assertNull(parse("650 HS_DESC IGNORE $onion NO_AUTH $hsDir"))
    }

    // -- CIRC --------------------------------------------------------------

    @Test
    fun circBuiltLinesForTheTwoOnionPurposes() {
        assertEquals(
            "introduction circuit built",
            textOf("650 CIRC 7 BUILT $path PURPOSE=HS_CLIENT_INTRO HS_STATE=HSCI_CONNECTING TIME_CREATED=2026-09-14T10:00:00.000000"),
        )
        assertEquals(
            ConnectionLog.Code.INTRO_CIRC_BUILT,
            parse("650 CIRC 7 BUILT $path PURPOSE=HS_CLIENT_INTRO HS_STATE=HSCI_CONNECTING")?.code,
        )
        assertEquals(
            ConnectionLog.Code.REND_CIRC_BUILT,
            parse("650 CIRC 8 BUILT $path PURPOSE=HS_CLIENT_REND HS_STATE=HSCR_CONNECTING")?.code,
        )
    }

    @Test
    fun circLaunchedLinesForTheTwoOnionPurposes() {
        // C2d. A LAUNCHED with no BUILT after it is the stall signature; before
        // this the panel and the timeline saw only the BUILT that never came.
        assertEquals(
            "introduction circuit launched",
            textOf("650 CIRC 7 LAUNCHED PURPOSE=HS_CLIENT_INTRO HS_STATE=HSCI_CONNECTING TIME_CREATED=2026-09-14T10:00:00.000000"),
        )
        assertEquals(
            ConnectionLog.Code.INTRO_CIRC_LAUNCHED,
            parse("650 CIRC 7 LAUNCHED PURPOSE=HS_CLIENT_INTRO HS_STATE=HSCI_CONNECTING")?.code,
        )
        assertEquals(
            "rendezvous circuit launched",
            textOf("650 CIRC 8 LAUNCHED PURPOSE=HS_CLIENT_REND HS_STATE=HSCR_CONNECTING REND_QUERY=$onion"),
        )
        assertEquals(
            ConnectionLog.Code.REND_CIRC_LAUNCHED,
            parse("650 CIRC 8 LAUNCHED PURPOSE=HS_CLIENT_REND")?.code,
        )
        // The onion address rides the SAME event (REND_QUERY=) and must not be
        // in the line it produces.
        assertFalse(
            textOf("650 CIRC 8 LAUNCHED PURPOSE=HS_CLIENT_REND HS_STATE=HSCR_CONNECTING REND_QUERY=$onion")
                .contains("abcdefg"),
        )
        // A LAUNCHED that already carries a narrated HS_STATE still reports the
        // STATE, not the launch — the state switch runs first, as on BUILT.
        assertEquals(
            ConnectionLog.Code.INTRO_SENT,
            parse("650 CIRC 7 LAUNCHED PURPOSE=HS_CLIENT_INTRO HS_STATE=HSCI_INTRO_SENT")?.code,
        )
        // HSDIR stays silent at launch for the same reason it does at BUILT.
        assertNull(parse("650 CIRC 9 LAUNCHED PURPOSE=HS_CLIENT_HSDIR"))
        assertNull(parse("650 CIRC 10 LAUNCHED PURPOSE=GENERAL"))
    }

    @Test
    fun hsDirBuiltAndGeneralCircuitsProduceNoLine() {
        assertNull(parse("650 CIRC 9 BUILT $path PURPOSE=HS_CLIENT_HSDIR"))
        assertNull(parse("650 CIRC 10 BUILT $path PURPOSE=GENERAL"))
        assertNull(parse("650 CIRC 10 EXTENDED $path PURPOSE=GENERAL"))
        // No PURPOSE at all: nothing to attribute the line to.
        assertNull(parse("650 CIRC 10 BUILT $path"))
    }

    @Test
    fun circHsStateTransitions() {
        assertEquals(
            ConnectionLog.Code.INTRO_SENT,
            parse("650 CIRC 7 BUILT $path PURPOSE=HS_CLIENT_INTRO HS_STATE=HSCI_INTRO_SENT")?.code,
        )
        assertEquals("introduction sent", textOf("650 CIRC 7 BUILT $path PURPOSE=HS_CLIENT_INTRO HS_STATE=HSCI_INTRO_SENT"))
        assertEquals(
            ConnectionLog.Code.INTRO_DONE,
            parse("650 CIRC 7 BUILT $path PURPOSE=HS_CLIENT_INTRO HS_STATE=HSCI_DONE")?.code,
        )
        assertEquals(
            ConnectionLog.Code.REND_JOINED,
            parse("650 CIRC 8 BUILT $path PURPOSE=HS_CLIENT_REND HS_STATE=HSCR_JOINED")?.code,
        )
        // An HS state we don't surface is not a "built" line either.
        assertNull(parse("650 CIRC 8 EXTENDED $path PURPOSE=HS_CLIENT_REND HS_STATE=HSCR_ESTABLISHED_IDLE"))
    }

    @Test
    fun circFailuresPerPurposeWithAllowlistedReason() {
        assertEquals(
            ConnectionLog.Code.HSDIR_CIRC_FAILED,
            parse("650 CIRC 9 FAILED $path PURPOSE=HS_CLIENT_HSDIR REASON=TIMEOUT")?.code,
        )
        assertEquals(
            "directory circuit failed: TIMEOUT",
            textOf("650 CIRC 9 FAILED $path PURPOSE=HS_CLIENT_HSDIR REASON=TIMEOUT"),
        )
        assertEquals(
            "introduction circuit failed: DESTROYED",
            textOf("650 CIRC 7 CLOSED $path PURPOSE=HS_CLIENT_INTRO REASON=DESTROYED"),
        )
        assertEquals(
            ConnectionLog.Code.REND_CIRC_FAILED,
            parse("650 CIRC 8 FAILED $path PURPOSE=HS_CLIENT_REND REASON=CHANNEL_CLOSED")?.code,
        )
        assertEquals(
            "rendezvous circuit failed: OTHER",
            textOf("650 CIRC 8 FAILED $path PURPOSE=HS_CLIENT_REND REASON=WEIRD_NEW_REASON"),
        )
    }

    // -- CIRC_MINOR: the onion handshake (2026-10-06) -----------------------
    //
    // Tor reports HS_STATE transitions ONLY as CIRC_MINOR PURPOSE_CHANGED; these
    // lines are shaped exactly as control_event_circuit_status_minor() emits
    // them (path, PURPOSE, HS_STATE, REND_QUERY, TIME_CREATED, OLD_PURPOSE,
    // OLD_HS_STATE).

    private fun circMinor(id: Int, purpose: String, state: String, oldState: String?) =
        "650 CIRC_MINOR $id PURPOSE_CHANGED $path BUILD_FLAGS=IS_INTERNAL,NEED_CAPACITY,NEED_UPTIME " +
            "PURPOSE=$purpose HS_STATE=$state REND_QUERY=${onion.removeSuffix(".onion")} " +
            "TIME_CREATED=2026-10-06T10:00:00.000000 OLD_PURPOSE=$purpose" +
            (if (oldState != null) " OLD_HS_STATE=$oldState" else "")

    @Test
    fun circMinorIntroSent() {
        val raw = circMinor(7, "HS_CLIENT_INTRO", "HSCI_INTRO_SENT", "HSCI_CONNECTING")
        assertEquals(ConnectionLog.Code.INTRO_SENT, parse(raw)?.code)
        assertEquals("introduction sent", textOf(raw))
    }

    @Test
    fun circMinorIntroAcked() {
        val raw = circMinor(7, "HS_CLIENT_INTRO", "HSCI_DONE", "HSCI_INTRO_SENT")
        assertEquals(ConnectionLog.Code.INTRO_DONE, parse(raw)?.code)
        assertEquals("introduction complete", textOf(raw))
    }

    @Test
    fun circMinorRendezvousJoined() {
        val raw = circMinor(8, "HS_CLIENT_REND", "HSCR_JOINED", "HSCR_ESTABLISHED_WAITING")
        assertEquals(ConnectionLog.Code.REND_JOINED, parse(raw)?.code)
        assertEquals("rendezvous joined", textOf(raw))
        // RENDEZVOUS2 can beat the INTRODUCE_ACK: JOINED straight from IDLE.
        assertEquals(
            ConnectionLog.Code.REND_JOINED,
            parse(circMinor(8, "HS_CLIENT_REND", "HSCR_JOINED", "HSCR_ESTABLISHED_IDLE"))?.code,
        )
    }

    @Test
    fun circMinorNackIsAnIntroFailureAndItsGiveUpIsSilent() {
        // handle_introduce_ack_bad: INTRO_SENT → CONNECTING is the intro point's NACK.
        val nack = circMinor(7, "HS_CLIENT_INTRO", "HSCI_CONNECTING", "HSCI_INTRO_SENT")
        assertEquals(ConnectionLog.Code.INTRO_CIRC_FAILED, parse(nack)?.code)
        assertEquals("introduction refused", textOf(nack))
        // close_or_reextend_intro_circ: CONNECTING → DONE is the give-up, NOT an ack.
        assertNull(parse(circMinor(7, "HS_CLIENT_INTRO", "HSCI_DONE", "HSCI_CONNECTING")))
    }

    @Test
    fun circMinorStatesAndEventsWeDoNotNarrate() {
        assertNull(parse(circMinor(8, "HS_CLIENT_REND", "HSCR_ESTABLISHED_IDLE", "HSCR_CONNECTING")))
        assertNull(parse(circMinor(8, "HS_CLIENT_REND", "HSCR_ESTABLISHED_WAITING", "HSCR_ESTABLISHED_IDLE")))
        // A cannibalized general circuit becoming an intro circuit: no handshake yet.
        assertNull(
            parse(
                "650 CIRC_MINOR 7 CANNIBALIZED $path PURPOSE=HS_CLIENT_INTRO HS_STATE=HSCI_CONNECTING " +
                    "OLD_PURPOSE=GENERAL",
            ),
        )
        // A CANNIBALIZED event never narrates a state, whatever it carries.
        assertNull(parse("650 CIRC_MINOR 8 CANNIBALIZED $path PURPOSE=HS_CLIENT_REND HS_STATE=HSCR_JOINED"))
        assertNull(parse("650 CIRC_MINOR 10 PURPOSE_CHANGED $path PURPOSE=CONFLUX_LINKED OLD_PURPOSE=GENERAL"))
        assertNull(parse("650 CIRC_MINOR 9 PURPOSE_CHANGED $path PURPOSE=HS_CLIENT_HSDIR OLD_PURPOSE=GENERAL"))
        assertNull(parse("650 CIRC_MINOR 9 PURPOSE_CHANGED"))
        // OLD_HS_STATE is a different keyword: an intro whose OLD state was
        // INTRO_SENT but whose CURRENT state is unknown must not read as "sent".
        assertNull(parse("650 CIRC_MINOR 7 PURPOSE_CHANGED $path PURPOSE=HS_CLIENT_INTRO OLD_HS_STATE=HSCI_INTRO_SENT"))
    }

    @Test
    fun introClosedFinishedAfterAckIsNotAFailure() {
        // The ordinary end of every successful introduction (hs_client.c
        // handle_introduce_ack_success): purpose → INTRODUCE_ACKED, close FINISHED.
        assertNull(
            parse(
                "650 CIRC 7 CLOSED $path BUILD_FLAGS=IS_INTERNAL,NEED_CAPACITY,NEED_UPTIME " +
                    "PURPOSE=HS_CLIENT_INTRO HS_STATE=HSCI_DONE REND_QUERY=${onion.removeSuffix(".onion")} " +
                    "TIME_CREATED=2026-10-06T10:00:00.000000 REASON=FINISHED",
            ),
        )
        // FINISHED is Tor's own bookkeeping close in any intro state.
        assertNull(parse("650 CIRC 7 CLOSED $path PURPOSE=HS_CLIENT_INTRO HS_STATE=HSCI_CONNECTING REASON=FINISHED"))
        // Past the ack, even an odd reason is not an intro failure.
        assertNull(parse("650 CIRC 7 CLOSED $path PURPOSE=HS_CLIENT_INTRO HS_STATE=HSCI_DONE REASON=DESTROYED"))
    }

    @Test
    fun introClosedTimeoutBeforeAckIsStillAFailure() {
        val raw = "650 CIRC 7 CLOSED $path PURPOSE=HS_CLIENT_INTRO HS_STATE=HSCI_INTRO_SENT " +
            "REND_QUERY=${onion.removeSuffix(".onion")} REASON=TIMEOUT"
        assertEquals(ConnectionLog.Code.INTRO_CIRC_FAILED, parse(raw)?.code)
        assertEquals("introduction circuit failed: TIMEOUT", textOf(raw))
        // FAILED (never built) is a failure whatever the reason says.
        assertEquals(
            ConnectionLog.Code.INTRO_CIRC_FAILED,
            parse("650 CIRC 7 FAILED $path PURPOSE=HS_CLIENT_INTRO HS_STATE=HSCI_CONNECTING REASON=FINISHED")?.code,
        )
        // The FINISHED exemption is intro-only: rendezvous / HSDir closes keep
        // their existing coding.
        assertEquals(
            ConnectionLog.Code.REND_CIRC_FAILED,
            parse("650 CIRC 8 CLOSED $path PURPOSE=HS_CLIENT_REND HS_STATE=HSCR_JOINED REASON=FINISHED")?.code,
        )
    }

    @Test
    fun remoteReasonIsNeverReadAsReason() {
        // REMOTE_REASON is a DIFFERENT keyword whose value is chosen by the far
        // side; a prefix-sloppy lookup would echo it.
        assertEquals(
            "rendezvous circuit failed: OTHER",
            textOf("650 CIRC 8 FAILED $path PURPOSE=HS_CLIENT_REND REMOTE_REASON=TIMEOUT"),
        )
    }

    // -- STREAM ------------------------------------------------------------

    @Test
    fun streamLifecycleLines() {
        assertEquals(
            ConnectionLog.Code.STREAM_SENT,
            parse("650 STREAM 12 SENTCONNECT 7 $onion:80")?.code,
        )
        assertEquals("stream connecting", textOf("650 STREAM 12 SENTCONNECT 7 $onion:80"))
        assertEquals("stream connected", textOf("650 STREAM 12 SUCCEEDED 7 $onion:80"))
        assertEquals(ConnectionLog.Code.STREAM_OK, parse("650 STREAM 12 SUCCEEDED 7 $onion:80")?.code)
    }

    @Test
    fun streamFailuresAndTheNormalCloseSkips() {
        assertEquals(
            "stream failed: RESOLVEFAILED",
            textOf("650 STREAM 12 FAILED 7 $onion:80 REASON=RESOLVEFAILED"),
        )
        assertEquals(
            "stream failed: OTHER",
            textOf("650 STREAM 12 FAILED 7 $onion:80 REASON=NOT_A_REAL_REASON"),
        )
        // A stream closing normally is the end of every single request.
        assertNull(parse("650 STREAM 12 CLOSED 7 $onion:80 REASON=DONE"))
        assertNull(parse("650 STREAM 12 CLOSED 7 $onion:80 REASON=END"))
        // …but a CLOSED with a real fault still reports.
        assertEquals(
            "stream failed: TORPROTOCOL",
            textOf("650 STREAM 12 CLOSED 7 $onion:80 REASON=TORPROTOCOL"),
        )
        // Uninteresting statuses stay silent.
        assertNull(parse("650 STREAM 12 NEW 0 $onion:80 SOURCE_ADDR=127.0.0.1:55555 PURPOSE=USER"))
        assertNull(parse("650 STREAM 12 REMAP 7 $onion:80 SOURCE=CACHE"))
    }

    @Test
    fun streamIdIsCarriedAsAPairingKeyAndNeverAsText() {
        // FIX 2b (2026-09-16): the StreamID is read so ConnectionLog can match a
        // SENT to the SUCCEEDED/FAILED that ends it (an uneventful pair is left
        // out of a debug-mode upload; a slow or failed one ships WITH its start
        // line). The producer rule is unchanged — it must never appear in the
        // TEXT, and it never leaves the process.
        assertEquals(12L, parse("650 STREAM 12 SENTCONNECT 7 $onion:80")?.streamKey)
        assertEquals(12L, parse("650 STREAM 12 SUCCEEDED 7 $onion:80")?.streamKey)
        assertEquals(12L, parse("650 STREAM 12 FAILED 7 $onion:80 REASON=TIMEOUT")?.streamKey)
        for (raw in listOf(
            "650 STREAM 4242 SENTCONNECT 7 $onion:80",
            "650 STREAM 4242 SUCCEEDED 7 $onion:80",
            "650 STREAM 4242 FAILED 7 $onion:80 REASON=TIMEOUT",
        )) {
            assertFalse(textOf(raw).contains("4242"), "the stream id reached the line: ${textOf(raw)}")
            // Nor the circuit id, nor the onion, nor the port — unchanged.
            assertFalse(textOf(raw).contains("7"))
            assertFalse(textOf(raw).contains("onion"))
        }
        // A non-numeric id (Tor never emits one) simply leaves the pair
        // unmatched; the line is still produced, and the uploader then ships it.
        assertNull(parse("650 STREAM notanid SENTCONNECT 7 $onion:80")?.streamKey)
        assertEquals("stream connecting", textOf("650 STREAM notanid SENTCONNECT 7 $onion:80"))
        // Every non-STREAM line carries no key at all.
        assertNull(parse("650 HS_DESC REQUESTED $onion NO_AUTH ABCD1234")?.streamKey)
    }

    // -- STATUS_CLIENT -----------------------------------------------------

    @Test
    fun statusClientDirInfoAndCircuitStatus() {
        assertEquals(ConnectionLog.Code.DIR_ENOUGH, parse("650 STATUS_CLIENT NOTICE ENOUGH_DIR_INFO")?.code)
        assertEquals("enough directory info", textOf("650 STATUS_CLIENT NOTICE ENOUGH_DIR_INFO"))
        assertEquals(ConnectionLog.Code.DIR_NOT_ENOUGH, parse("650 STATUS_CLIENT NOTICE NOT_ENOUGH_DIR_INFO")?.code)
        assertEquals(ConnectionLog.Code.CIRCUIT_OK, parse("650 STATUS_CLIENT NOTICE CIRCUIT_ESTABLISHED")?.code)
        assertEquals("circuit established", textOf("650 STATUS_CLIENT NOTICE CIRCUIT_ESTABLISHED"))
        assertEquals("circuit lost", textOf("650 STATUS_CLIENT NOTICE CIRCUIT_NOT_ESTABLISHED"))
        assertEquals(
            "circuit lost (clock jumped)",
            textOf("650 STATUS_CLIENT NOTICE CIRCUIT_NOT_ESTABLISHED REASON=CLOCK_JUMPED"),
        )
        assertEquals(
            ConnectionLog.Code.CIRCUIT_LOST,
            parse("650 STATUS_CLIENT NOTICE CIRCUIT_NOT_ESTABLISHED REASON=CLOCK_JUMPED")?.code,
        )
    }

    @Test
    fun bootstrapProblemKeepsOnlyTagPercentReasonAndCount() {
        val line = "650 STATUS_CLIENT WARN BOOTSTRAP PROGRESS=80 TAG=conn_or SUMMARY=\"Connecting to the Tor network\" " +
            "WARNING=\"Connection timed out\" REASON=TIMEOUT COUNT=3 RECOMMENDATION=warn " +
            "HOSTID=\"9695DFC35FFEB861329B9F1AB04C46397020CE31\" HOSTADDR=\"128.31.0.39:9101\""
        val ev = parse(line)
        assertEquals(ConnectionLog.Code.TOR_BOOTSTRAP_PROBLEM, ev?.code)
        assertEquals("bootstrap problem at conn_or (80%): TIMEOUT, count 3", ev?.text)
    }

    @Test
    fun bootstrapProblemFallbacks() {
        // Unknown REASON ⇒ OTHER; a tag that is not a bare word (punctuation,
        // i.e. anything that could be an address) ⇒ "unknown".
        assertEquals(
            "bootstrap problem at unknown (80%): OTHER, count 1",
            textOf("650 STATUS_CLIENT WARN BOOTSTRAP PROGRESS=80 TAG=128.31.0.39:9101 REASON=NEW_REASON COUNT=1"),
        )
        // A non-numeric PROGRESS/COUNT is never echoed either.
        assertEquals(
            "bootstrap problem at conn (?%): TIMEOUT, count ?",
            textOf("650 STATUS_CLIENT WARN BOOTSTRAP PROGRESS=eighty TAG=conn REASON=TIMEOUT COUNT=many"),
        )
        // Missing numerics degrade to "?" rather than printing something else.
        assertEquals(
            "bootstrap problem at conn (?%): NOROUTE, count ?",
            textOf("650 STATUS_CLIENT WARN BOOTSTRAP TAG=conn REASON=NOROUTE"),
        )
        // ERR is Tor giving up on the bootstrap — the most diagnostic line there
        // is, so it is surfaced alongside WARN.
        assertEquals(
            "bootstrap problem at conn (10%): NOROUTE, count 10",
            textOf("650 STATUS_CLIENT ERR BOOTSTRAP PROGRESS=10 TAG=conn REASON=NOROUTE COUNT=10"),
        )
        // Plain progress events (NOTICE, no REASON) are already covered by the
        // notice-log tail — no duplicate line.
        assertNull(parse("650 STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=50 TAG=loading_descriptors SUMMARY=\"Loading relay descriptors\""))
        assertNull(parse("650 STATUS_CLIENT WARN BOOTSTRAP PROGRESS=50 TAG=conn"))
    }

    // -- STATUS_GENERAL ----------------------------------------------------

    @Test
    fun clockSkewBuckets() {
        assertEquals("clock skew: under 1 min ahead", textOf("650 STATUS_GENERAL WARN CLOCK_SKEW SKEW=30 SOURCE=DIRSERV:1.2.3.4:443"))
        assertEquals("clock skew: under 10 min behind", textOf("650 STATUS_GENERAL WARN CLOCK_SKEW SKEW=-300 SOURCE=DIRSERV:1.2.3.4:443"))
        assertEquals("clock skew: under 1 h ahead", textOf("650 STATUS_GENERAL WARN CLOCK_SKEW SKEW=3000"))
        assertEquals("clock skew: under 1 d behind", textOf("650 STATUS_GENERAL WARN CLOCK_SKEW SKEW=-40000"))
        assertEquals("clock skew: 1 d or more ahead", textOf("650 STATUS_GENERAL WARN CLOCK_SKEW SKEW=90000"))
        assertEquals(ConnectionLog.Code.CLOCK_SKEW, parse("650 STATUS_GENERAL WARN CLOCK_SKEW SKEW=30")?.code)
        // MIN_SKEW is the fallback form.
        assertEquals("clock skew: under 10 min ahead", textOf("650 STATUS_GENERAL WARN CLOCK_SKEW MIN_SKEW=200"))
        // Boundaries.
        assertEquals("under 1 min ahead", clockOffsetBucket(59))
        assertEquals("under 10 min ahead", clockOffsetBucket(60))
        assertEquals("1 d or more behind", clockOffsetBucket(-86_400))
        assertEquals("1 d or more behind", clockOffsetBucket(Long.MIN_VALUE))
    }

    @Test
    fun clockJumpedWarning_isLoggedWithAnOffsetBucket_otherGeneralStatusesStaySilent() {
        assertEquals(ConnectionLog.Code.CLOCK_JUMPED, parse("650 STATUS_GENERAL WARN CLOCK_JUMPED TIME=100")?.code)
        assertEquals("clock jumped: under 10 min ahead", textOf("650 STATUS_GENERAL WARN CLOCK_JUMPED TIME=100"))
        assertNull(parse("650 STATUS_GENERAL WARN CLOCK_JUMPED"))
        assertNull(parse("650 STATUS_GENERAL NOTICE CONSENSUS_ARRIVED"))
        assertNull(parse("650 STATUS_GENERAL WARN DANGEROUS_VERSION CURRENT=0.4.9.11 REASON=OBSOLETE"))
    }

    // -- NETWORK_LIVENESS / GUARD -----------------------------------------

    @Test
    fun networkLivenessUpDown_areLogged_bareLineIsIgnored() {
        assertEquals(ConnectionLog.Code.NET_UP, parse("650 NETWORK_LIVENESS UP")?.code)
        assertEquals("network up", textOf("650 NETWORK_LIVENESS UP"))
        assertEquals(ConnectionLog.Code.NET_DOWN, parse("650 NETWORK_LIVENESS DOWN")?.code)
        assertEquals("network down", textOf("650 NETWORK_LIVENESS DOWN"))
        assertNull(parse("650 NETWORK_LIVENESS"))
    }

    @Test
    fun guardEntryUpDownDropped_areLogged_bookkeepingStatusesStaySilent() {
        assertEquals("guard up", textOf("650 GUARD ENTRY $hsDir UP"))
        assertEquals(ConnectionLog.Code.GUARD_UP, parse("650 GUARD ENTRY $hsDir UP")?.code)
        assertEquals("guard down", textOf("650 GUARD ENTRY $hsDir DOWN"))
        assertEquals("guard dropped", textOf("650 GUARD ENTRY $hsDir DROPPED"))
        // Bookkeeping statuses and non-ENTRY types stay silent.
        assertNull(parse("650 GUARD ENTRY $hsDir NEW"))
        assertNull(parse("650 GUARD ENTRY $hsDir BAD"))
        assertNull(parse("650 GUARD ENTRY $hsDir GOOD"))
        assertNull(parse("650 GUARD DIRUSE $hsDir UP"))
    }

    // -- ORCONN ------------------------------------------------------------

    @Test
    fun orConnLifecycleLines() {
        assertEquals(
            ConnectionLog.Code.ORCONN_LAUNCHED,
            parse("650 ORCONN $hsDir LAUNCHED")?.code,
        )
        assertEquals("or connection launched", textOf("650 ORCONN $hsDir LAUNCHED"))
        assertEquals(
            ConnectionLog.Code.ORCONN_CONNECTED,
            parse("650 ORCONN $hsDir CONNECTED NCIRCS=4 ID=18")?.code,
        )
        assertEquals("or connection connected", textOf("650 ORCONN 1.2.3.4:9001 CONNECTED NCIRCS=4"))
        assertEquals(ConnectionLog.Kind.TOR, parse("650 ORCONN $hsDir LAUNCHED")?.kind)
    }

    @Test
    fun orConnFailuresAndAllowlist() {
        assertEquals(
            "or connection failed: CONNECTREFUSED",
            textOf("650 ORCONN 1.2.3.4:9001 FAILED REASON=CONNECTREFUSED NCIRCS=0"),
        )
        assertEquals(
            ConnectionLog.Code.ORCONN_FAILED,
            parse("650 ORCONN $hsDir FAILED REASON=TIMEOUT")?.code,
        )
        assertEquals(
            "or connection failed: OTHER",
            textOf("650 ORCONN $hsDir FAILED REASON=SOME_NEW_REASON"),
        )
        assertEquals("or connection failed: OTHER", textOf("650 ORCONN $hsDir FAILED"))
    }

    @Test
    fun orConnCloseIsSilentUnlessItIsAFault() {
        // Ordinary channel churn.
        assertNull(parse("650 ORCONN $hsDir CLOSED REASON=DONE"))
        // …and a close with no reason names nothing we could report honestly.
        assertNull(parse("650 ORCONN $hsDir CLOSED"))
        // A channel that went away under us reads as a failure.
        assertEquals(
            "or connection failed: IOERROR",
            textOf("650 ORCONN $hsDir CLOSED REASON=IOERROR"),
        )
        assertEquals(
            ConnectionLog.Code.ORCONN_FAILED,
            parse("650 ORCONN 1.2.3.4:9001 CLOSED REASON=CONNECTRESET")?.code,
        )
        // Inbound connections cannot happen to a client.
        assertNull(parse("650 ORCONN $hsDir NEW"))
    }

    @Test
    fun orConnTargetNeverReachesTheLine() {
        val targets = listOf(
            "\$9695DFC35FFEB861329B9F1AB04C46397020CE31~moria1",
            "1.2.3.4:9001",
            "[2001:db8::1]:9001",
            "somenickname",
        )
        val statuses = listOf("LAUNCHED", "CONNECTED", "FAILED REASON=TIMEOUT", "CLOSED REASON=IOERROR")
        for (target in targets) {
            for (status in statuses) {
                val ev = parse("650 ORCONN $target $status NCIRCS=2 ID=7") ?: continue
                for (secret in listOf(target, "moria1", "9695DFC35FFEB861329B9F1AB04C46397020CE31", "1.2.3.4", "2001:db8::1", "somenickname", "9001")) {
                    assertFalse(
                        ev.text.contains(secret, ignoreCase = true),
                        "ORCONN target leaked: <$secret> in \"${ev.text}\"",
                    )
                }
                assertEquals(ev.text, ConnectionLog.redact(ev.text))
            }
        }
    }

    // -- Consensus age -----------------------------------------------------

    @Test
    fun consensusValidAfterIsPulledOutOfTheMultiLineReply() {
        val reply = listOf("250-consensus/valid-after=2026-09-14 06:00:00", "250 OK")
        assertEquals("2026-09-14 06:00:00", parseConsensusValidAfter(reply))
        // 552 (no consensus yet) and junk both yield null.
        assertNull(parseConsensusValidAfter(listOf("552 Unrecognized key \"consensus/valid-after\"")))
        assertNull(parseConsensusValidAfter(emptyList()))
        assertNull(parseConsensusValidAfter(listOf("250-consensus/valid-after=", "250 OK")))
    }

    @Test
    fun utcTimestampParsing() {
        assertEquals(0L, parseUtcTimestampSeconds("1970-01-01 00:00:00"))
        assertEquals(1_000_000_000L, parseUtcTimestampSeconds("2001-09-09 01:46:40"))
        // 2026-09-14 06:00:00 UTC (cross-checked against `date -u -j -f`)
        assertEquals(1_789_365_600L, parseUtcTimestampSeconds("2026-09-14 06:00:00"))
        // Leap day, and a date before the epoch (the civil-days algorithm has to
        // handle both signs).
        assertEquals(1_709_208_000L, parseUtcTimestampSeconds("2024-02-29 12:00:00"))
        assertEquals(-86_400L, parseUtcTimestampSeconds("1969-12-31 00:00:00"))
        assertNull(parseUtcTimestampSeconds("2026-09-14T06:00:00"))
        assertNull(parseUtcTimestampSeconds("not a timestamp at all"))
        assertNull(parseUtcTimestampSeconds("2026-13-14 06:00:00"))
        assertNull(parseUtcTimestampSeconds(""))
    }

    @Test
    fun consensusAgeBuckets() {
        val validAfter = "2026-09-14 06:00:00"
        val base = parseUtcTimestampSeconds(validAfter)!!
        val reply = listOf("250-consensus/valid-after=$validAfter", "250 OK")
        fun at(offsetSeconds: Long) = consensusAgeLine(reply, base + offsetSeconds)

        assertEquals("consensus age: under 1 h", at(0).text)
        assertEquals("consensus age: under 1 h", at(3_599).text)
        assertEquals("consensus age: under 3 h", at(3_600).text)
        assertEquals("consensus age: under 24 h", at(3 * 3_600).text)
        assertEquals("consensus age: over 24 h", at(24 * 3_600).text)
        assertEquals("consensus age: over 24 h", at(72 * 3_600).text)
        // A clock behind the consensus is "fresh", never a negative bucket.
        assertEquals("consensus age: under 1 h", at(-5_000).text)
        // C2c: the CODE splits fresh/stale on the same 3 h boundary as the text
        // (the timeline carries the code and nothing else, so the split has to
        // live there too). The bucket TEXT keeps its four steps.
        assertEquals(ConnectionLog.Code.CONSENSUS_FRESH, at(0).code)
        assertEquals(ConnectionLog.Code.CONSENSUS_FRESH, at(-5_000).code)
        assertEquals(ConnectionLog.Code.CONSENSUS_FRESH, at(3 * 3_600 - 1).code)
        assertEquals(ConnectionLog.Code.CONSENSUS_STALE, at(3 * 3_600).code)
        assertEquals(ConnectionLog.Code.CONSENSUS_STALE, at(72 * 3_600).code)
        assertEquals(ConnectionLog.Kind.TOR, at(0).kind)
    }

    @Test
    fun consensusAgeAlwaysProducesALineAndNeverTheTimestamp() {
        val validAfter = "2026-09-14 06:00:00"
        val base = parseUtcTimestampSeconds(validAfter)!!
        val line = consensusAgeLine(listOf("250-consensus/valid-after=$validAfter", "250 OK"), base + 100)
        for (fragment in listOf("2026", "06:00:00", "2026-09-14", validAfter)) {
            assertFalse(line.text.contains(fragment), "consensus timestamp leaked: <$fragment> in \"${line.text}\"")
        }
        // 552 / empty / garbage ⇒ one honest "unknown" line, never silence.
        assertEquals(
            "consensus age: unknown",
            consensusAgeLine(listOf("552 Unrecognized key \"consensus/valid-after\""), base).text,
        )
        assertEquals("consensus age: unknown", consensusAgeLine(emptyList(), base).text)
        assertEquals(
            "consensus age: unknown",
            consensusAgeLine(listOf("250-consensus/valid-after=garbage", "250 OK"), base).text,
        )
        // C2c: "Tor had no consensus to report" is its OWN code — it used to be
        // the same one a fresh directory produced, which made an unanswered
        // question indistinguishable from a healthy answer on the wire.
        assertEquals(
            ConnectionLog.Code.CONSENSUS_UNKNOWN,
            consensusAgeLine(emptyList(), base).code,
        )
        assertEquals(
            ConnectionLog.Code.CONSENSUS_UNKNOWN,
            consensusAgeLine(listOf("552 Unrecognized key \"consensus/valid-after\""), base).code,
        )
        assertEquals(
            ConnectionLog.Code.CONSENSUS_UNKNOWN,
            consensusAgeLine(listOf("250-consensus/valid-after=garbage", "250 OK"), base).code,
        )
    }

    @Test
    fun finalReplyLineDetection() {
        assertTrue(isFinalReplyLine("250 OK"))
        assertTrue(isFinalReplyLine("552 Unrecognized key"))
        assertFalse(isFinalReplyLine("250-consensus/valid-after=2026-09-14 06:00:00"))
        assertFalse(isFinalReplyLine("250+ns/all="))
        assertFalse(isFinalReplyLine("250"))
        assertFalse(isFinalReplyLine(""))
        // An async event is never a reply terminator, even though it is "650 ".
        assertTrue(isFinalReplyLine("650 NETWORK_LIVENESS UP"))  // shape only — the
        // reader checks the 650 prefix FIRST, which is what keeps events out of
        // a pending reply (see consumeReplyLine).
    }

    @Test
    fun setEventsCoversEveryParsedFamily() {
        // A family parsed but not subscribed is dead code; a family subscribed
        // but not parsed is noise. Keep the two lists honest.
        for (family in listOf(
            "HS_DESC", "CIRC", "CIRC_MINOR", "STREAM", "STATUS_CLIENT", "STATUS_GENERAL",
            "NETWORK_LIVENESS", "GUARD", "ORCONN",
        )) {
            assertTrue(
                TOR_SETEVENTS_COMMAND.split(' ').contains(family),
                "$family is parsed but not in SETEVENTS",
            )
        }
        assertTrue(TOR_GETINFO_CONSENSUS_VALID_AFTER.startsWith("GETINFO "))
    }

    // -- Framing -----------------------------------------------------------

    @Test
    fun onlyAsyncEventLinesAreParsed() {
        assertNull(parse("250 OK"))
        assertNull(parse("650"))
        assertNull(parse(""))
        assertNull(parse("515 Authentication failed"))
        assertNull(parse("650 UNKNOWN_EVENT whatever"))
        // Mid-multiline (`650-`) and data-block headers (`650+`) share the parser.
        assertEquals("network up", textOf("650-NETWORK_LIVENESS UP"))
        // …but a descriptor CONTENT header is not an event we surface (and its
        // payload is skipped by the reader, never parsed).
        assertNull(parse("650+HS_DESC_CONTENT $onion $descId $hsDir"))
        // Trailing CRLF is tolerated.
        assertEquals("network down", textOf("650 NETWORK_LIVENESS DOWN\r\n"))
    }

    // -- THE LEAK PROPERTY -------------------------------------------------

    @Test
    fun noEventArgumentEverReachesALine() {
        val guardNick = "someguardnickname"
        val target = "$onion:80"
        val source = "DIRSERV:128.31.0.39:9131"
        val forbidden = listOf(
            onion, hsDir, descId, path, target, source, guardNick,
            "9695DFC35FFEB861329B9F1AB04C46397020CE31", "128.31.0.39", "moria1", "guardnick", "middlenick",
            "Connecting to the Tor network", "Connection timed out",
        )
        val events = listOf(
            "650 HS_DESC REQUESTED $onion NO_AUTH $hsDir $descId",
            "650 HS_DESC RECEIVED $onion NO_AUTH $hsDir $descId",
            "650 HS_DESC FAILED $onion NO_AUTH $hsDir $descId REASON=QUERY_NO_HSDIR",
            "650 CIRC 7 BUILT $path PURPOSE=HS_CLIENT_INTRO HS_STATE=HSCI_CONNECTING REND_QUERY=$onion",
            "650 CIRC 7 BUILT $path PURPOSE=HS_CLIENT_INTRO HS_STATE=HSCI_INTRO_SENT REND_QUERY=$onion",
            "650 CIRC 8 BUILT $path PURPOSE=HS_CLIENT_REND HS_STATE=HSCR_JOINED REND_QUERY=$onion",
            "650 CIRC 9 FAILED $path PURPOSE=HS_CLIENT_HSDIR REASON=TIMEOUT REMOTE_REASON=TORPROTOCOL",
            "650 CIRC 7 CLOSED $path PURPOSE=HS_CLIENT_INTRO HS_STATE=HSCI_INTRO_SENT REND_QUERY=$onion REASON=TIMEOUT",
            "650 CIRC_MINOR 7 PURPOSE_CHANGED $path PURPOSE=HS_CLIENT_INTRO HS_STATE=HSCI_INTRO_SENT " +
                "REND_QUERY=$onion OLD_PURPOSE=HS_CLIENT_INTRO OLD_HS_STATE=HSCI_CONNECTING",
            "650 CIRC_MINOR 7 PURPOSE_CHANGED $path PURPOSE=HS_CLIENT_INTRO HS_STATE=HSCI_DONE " +
                "REND_QUERY=$onion OLD_PURPOSE=HS_CLIENT_INTRO OLD_HS_STATE=HSCI_INTRO_SENT",
            "650 CIRC_MINOR 7 PURPOSE_CHANGED $path PURPOSE=HS_CLIENT_INTRO HS_STATE=HSCI_CONNECTING " +
                "REND_QUERY=$onion OLD_PURPOSE=HS_CLIENT_INTRO OLD_HS_STATE=HSCI_INTRO_SENT",
            "650 CIRC_MINOR 8 PURPOSE_CHANGED $path PURPOSE=HS_CLIENT_REND HS_STATE=HSCR_JOINED " +
                "REND_QUERY=$onion OLD_PURPOSE=HS_CLIENT_REND OLD_HS_STATE=HSCR_ESTABLISHED_WAITING",
            "650 STREAM 12 SENTCONNECT 7 $target",
            "650 STREAM 12 SUCCEEDED 7 $target SOURCE_ADDR=127.0.0.1:55555",
            "650 STREAM 12 FAILED 7 $target REASON=TIMEOUT SOURCE=$source SOURCE_ADDR=127.0.0.1:55555",
            "650 STATUS_CLIENT WARN BOOTSTRAP PROGRESS=80 TAG=conn_or SUMMARY=\"Connecting to the Tor network\" " +
                "WARNING=\"Connection timed out\" REASON=TIMEOUT COUNT=3 " +
                "HOSTID=\"9695DFC35FFEB861329B9F1AB04C46397020CE31\" HOSTADDR=\"128.31.0.39:9101\"",
            "650 STATUS_CLIENT NOTICE CIRCUIT_NOT_ESTABLISHED REASON=CLOCK_JUMPED",
            "650 STATUS_GENERAL WARN CLOCK_SKEW SKEW=-300 SOURCE=$source",
            "650 STATUS_GENERAL WARN CLOCK_JUMPED TIME=4000",
            "650 NETWORK_LIVENESS UP",
            "650 GUARD ENTRY \$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA~$guardNick DOWN",
            "650 ORCONN $hsDir LAUNCHED",
            "650 ORCONN $hsDir CONNECTED NCIRCS=3 ID=11",
            "650 ORCONN 1.2.3.4:9001 FAILED REASON=TIMEOUT NCIRCS=0",
            "650 ORCONN $hsDir CLOSED REASON=IOERROR",
        )
        for (raw in events) {
            val ev = parse(raw) ?: continue
            for (secret in forbidden) {
                assertFalse(
                    ev.text.contains(secret, ignoreCase = true),
                    "event argument leaked into the panel line: <$secret> in \"${ev.text}\" (from: $raw)",
                )
            }
            // Belt and braces: no '=' (a KEY=VALUE argument), no '$' (a
            // fingerprint), no '.' (a host or an address). ':' is NOT in this
            // list — the fixed phrases use it as their own separator
            // ("stream failed: TIMEOUT").
            for (c in listOf('=', '$', '.')) {
                assertFalse(ev.text.contains(c), "raw argument punctuation '$c' in \"${ev.text}\" (from: $raw)")
            }
        }
    }

    @Test
    fun everyProducedLineSurvivesRedactionUnchanged() {
        // If a line ever needed redacting, the producer rule had already been
        // broken — assert the two agree.
        val samples = listOf(
            "650 HS_DESC REQUESTED $onion NO_AUTH $hsDir $descId",
            "650 CIRC 8 FAILED $path PURPOSE=HS_CLIENT_REND REASON=NOPATH",
            "650 STREAM 12 FAILED 7 $onion:80 REASON=TIMEOUT",
            "650 STATUS_GENERAL WARN CLOCK_SKEW SKEW=-300 SOURCE=DIRSERV:1.2.3.4:443",
        )
        for (raw in samples) {
            val ev = parse(raw)
            assertNotNull(ev)
            assertEquals(ev.text, ConnectionLog.redact(ev.text))
        }
    }

    // -- Dedupe ------------------------------------------------------------

    @Test
    fun dedupeAllowsOneLinePerCodePerWindow() {
        val dedupe = TorEventDedupe(TOR_EVENT_DEDUPE_WINDOW_MS)
        assertTrue(dedupe.allow(ConnectionLog.Code.HSDESC_REQUESTED, 1_000))
        // Same code inside the window: suppressed.
        assertFalse(dedupe.allow(ConnectionLog.Code.HSDESC_REQUESTED, 1_500))
        assertFalse(dedupe.allow(ConnectionLog.Code.HSDESC_REQUESTED, 2_999))
        // A different code is never suppressed by another one's burst.
        assertTrue(dedupe.allow(ConnectionLog.Code.HSDESC_RECEIVED, 1_500))
        // Past the window: allowed again.
        assertTrue(dedupe.allow(ConnectionLog.Code.HSDESC_REQUESTED, 3_000))
    }
}

/**
 * The notice-log bootstrap line feeding the same panel. Split out of
 * [TorSocksLogParseTest] because the property under test is the NEW one: only
 * the percent and the closed-vocabulary phase TAG may reach a release-visible
 * line — Tor's human summary prose (which on the problem paths carries a relay
 * address) must be dropped at the producer.
 */
class TorControlBootstrapLineTest {

    @Test
    fun keepsPercentAndTagOnly() {
        val p = TorNoticeLog.parseBootstrapProgress(
            "Sep 14 10:00:00.000 [notice] Bootstrapped 5% (conn): Connecting to a relay"
        )
        assertNotNull(p)
        assertEquals(5, p.percent)
        assertEquals("conn", p.tag)
        assertEquals("bootstrap 5% conn", TorNoticeLog.bootstrapLogLine(p))
    }

    @Test
    fun summaryProseNeverSurvives() {
        val line = "[notice] Bootstrapped 10% (conn_done): Connected to a relay at 128.31.0.39:9101"
        val text = TorNoticeLog.bootstrapLogLine(TorNoticeLog.parseBootstrapProgress(line)!!)
        assertEquals("bootstrap 10% conn_done", text)
        assertFalse(text.contains("128.31.0.39"))
        assertFalse(text.contains("Connected to a relay"))
    }

    @Test
    fun handlesTheTaglessAndHundredPercentForms() {
        assertEquals("bootstrap 100% done", TorNoticeLog.bootstrapLogLine(TorNoticeLog.parseBootstrapProgress("Bootstrapped 100% (done): Done")!!))
        assertEquals("bootstrap 42%", TorNoticeLog.bootstrapLogLine(TorNoticeLog.parseBootstrapProgress("Bootstrapped 42%")!!))
        assertEquals("bootstrap 42%", TorNoticeLog.bootstrapLogLine(TorNoticeLog.parseBootstrapProgress("Bootstrapped 42%: Loading")!!))
    }

    @Test
    fun nonBootstrapLinesYieldNull() {
        assertNull(TorNoticeLog.parseBootstrapProgress("[notice] Socks listener listening on 127.0.0.1:44321"))
        assertNull(TorNoticeLog.parseBootstrapProgress(""))
        assertNull(TorNoticeLog.parseBootstrapProgress("Bootstrapped x%"))
    }
}
