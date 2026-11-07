package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

private const val NUDGE_RELAY = "http://relay.test"
private const val LOCAL_VERSION = "0.8.184"

/** A relay reply carrying the platform-normalised version header. */
private fun okWithVersion(v: String) =
    HttpResult(code = 200, body = "{}", isSuccess = true, headers = mapOf(UPDATE_NUDGE_HEADER_KEY to v))

/** A relay reply with no headers at all (an old relay, or one that suppresses it). */
private fun okBare(code: Int = 200) = HttpResult(code = code, body = "{}", isSuccess = code in 200..299)

/** A transport failure — both actuals map every network error to this shape. */
private fun transportFailure() = HttpResult(code = -1, body = "boom", isSuccess = false)

/**
 * The MessageManager side of the update nudge: one endpoint-agnostic observer
 * wrapped around the injected transport, latched on the FIRST relay response
 * with `code > 0`, monotonic for the lifetime of the instance, and fail-closed
 * on every ambiguity.
 */
class UpdateNudgeLatchTest {

    private fun mgr(http: RelayHttp, local: String = LOCAL_VERSION) =
        MessageManager(InMemoryVault(), NUDGE_RELAY, http, local)

    @Test
    fun firstResponseWithANewerVersion_armsTheNudge() {
        val http = RecordingRelayHttp()
        http.script(okWithVersion("9.9.9"))
        val m = mgr(http)
        assertNull(m.newerRelayVersion(), "nothing may be latched before the first response")

        assertTrue(m.isRelayReachable())

        assertEquals("9.9.9", m.newerRelayVersion())
    }

    @Test
    fun aLaterResponseCanNotChangeTheLatchedValue() {
        // Bound: the check runs ONCE per instance. A relay that escalates its
        // advertised version mid-session must not be able to re-decide.
        val http = RecordingRelayHttp()
        http.script(okWithVersion("9.9.9"))
        val m = mgr(http)
        assertTrue(m.isRelayReachable())
        assertEquals("9.9.9", m.newerRelayVersion())

        http.script(okWithVersion("10.0.0"))
        assertTrue(m.isRelayReachable())

        assertEquals("9.9.9", m.newerRelayVersion(), "the latch is monotonic per instance")
    }

    @Test
    fun aFailedFirstResponseDoesNotConsumeTheLatch() {
        // code = -1 is a transport failure, not a relay answer: nothing was
        // advertised, so the check must stay armed for the next real response.
        val http = RecordingRelayHttp()
        http.script(transportFailure(), okWithVersion("9.9.9"))
        val m = mgr(http)

        assertTrue(m.isRelayReachable(), "the second attempt answers 200")

        assertEquals("9.9.9", m.newerRelayVersion())
    }

    @Test
    fun aFailureOnlySessionLatchesNothing() {
        val http = RecordingRelayHttp()
        http.script(transportFailure(), transportFailure())
        val m = mgr(http)

        assertFalse(m.isRelayReachable())

        assertNull(m.newerRelayVersion())
        // …and a later good response still arms it.
        http.script(okWithVersion("9.9.9"))
        assertTrue(m.isRelayReachable())
        assertEquals("9.9.9", m.newerRelayVersion())
    }

    @Test
    fun anAbsentHeaderYieldsNull_andStillConsumesTheLatch() {
        // a relay that suppresses the header means "no nudge" — and it does
        // NOT get a second bite at the same session.
        val http = RecordingRelayHttp()
        http.script(okBare())
        val m = mgr(http)
        assertTrue(m.isRelayReachable())
        assertNull(m.newerRelayVersion())

        http.script(okWithVersion("9.9.9"))
        assertTrue(m.isRelayReachable())
        assertNull(m.newerRelayVersion(), "the check was already spent on the first response")
    }

    @Test
    fun aMalformedHeaderYieldsNull_andStillConsumesTheLatch() {
        for (bad in listOf("v9.9.9", "9.9", "9.9.9.9", " 9.9.9", "99999.0.0", "", "not-a-version")) {
            val http = RecordingRelayHttp()
            http.script(HttpResult(200, "{}", true, mapOf(UPDATE_NUDGE_HEADER_KEY to bad)))
            val m = mgr(http)
            assertTrue(m.isRelayReachable())
            assertNull(m.newerRelayVersion(), "\"$bad\" must not nudge")

            http.script(okWithVersion("9.9.9"))
            assertTrue(m.isRelayReachable())
            assertNull(m.newerRelayVersion(), "the latch is spent even when the header was junk")
        }
    }

    @Test
    fun anEqualOrLowerAdvertisedVersionYieldsNull() {
        for (v in listOf(LOCAL_VERSION, "0.8.183", "0.0.0")) {
            val http = RecordingRelayHttp()
            http.script(okWithVersion(v))
            val m = mgr(http)
            assertTrue(m.isRelayReachable())
            assertNull(m.newerRelayVersion(), "$v is not newer than $LOCAL_VERSION")
        }
    }

    @Test
    fun anUnparseableLocalVersionNeverNudges() {
        // The default: no ctor arg at all (every pre-existing construction site).
        val http = RecordingRelayHttp()
        http.script(okWithVersion("9.9.9"))
        val m = MessageManager(InMemoryVault(), NUDGE_RELAY, http)
        assertTrue(m.isRelayReachable())
        assertNull(m.newerRelayVersion(), "an empty local version is ambiguous — never nudge")

        val http2 = RecordingRelayHttp()
        http2.script(okWithVersion("9.9.9"))
        val m2 = mgr(http2, local = "0.8.184-dev")
        assertTrue(m2.isRelayReachable())
        assertNull(m2.newerRelayVersion())
    }

    @Test
    fun theWrapperIsAPureObserver_theTransportSeesEveryCallVerbatim() {
        // The delegate must not change what the relay layer does: same method,
        // same URL, same headers — and the result object is returned unchanged.
        val http = RecordingRelayHttp()
        val expected = okWithVersion("9.9.9")
        http.script(expected)
        val m = mgr(http)

        assertTrue(m.isRelayReachable())

        assertEquals(1, http.calls.size)
        assertEquals("GET", http.calls[0].method)
        assertEquals(NUDGE_RELAY, http.calls[0].url)
        assertTrue(http.calls[0].headers.isEmpty())
    }

    @Test
    fun aNon2xxRelayAnswerStillCountsAsTheFirstResponse() {
        // The relay's `GET /` is a 404 BY DESIGN and still carries the header —
        // the hook keys on `code > 0` (a real HTTP answer), not on success.
        val http = RecordingRelayHttp()
        http.script(HttpResult(404, "{\"error\":\"request rejected\"}", false,
            mapOf(UPDATE_NUDGE_HEADER_KEY to "9.9.9")))
        val m = mgr(http)

        assertTrue(m.isRelayReachable(), "any real HTTP answer means the relay is up")

        assertEquals("9.9.9", m.newerRelayVersion())
    }
}
