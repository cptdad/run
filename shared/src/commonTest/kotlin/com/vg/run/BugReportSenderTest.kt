package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// BugReportSenderTest — anonymous "Report bug" body building + wire limits.
// No network: RecordingBugReportRelay is an in-memory RelayHttp fake, same
// shape as PushRegistrationTest's RecordingPushRelay.
// ---------------------------------------------------------------------------

private const val BASE = "http://relay.test"

/** POST-only recorder answering `204`; a test re-scripts it through `onPost`. */
private fun RecordingBugReportRelay() = FakeRelayHttp.postOnly("bug report") { HttpResult(204, null, true) }

class BugReportSenderTest {

    // -------------------------------------------------------------------
    // buildBody — pure, no network
    // -------------------------------------------------------------------

    @Test
    fun buildBody_wellFormedFields() {
        val body = BugReportSender.buildBody("it crashed on send", "1.6.8", "android")
        assertEquals(
            """{"v":1,"text":"it crashed on send","app":"1.6.8","platform":"android"}""",
            body,
        )
    }

    @Test
    fun buildBody_escapesQuotes() {
        val body = BugReportSender.buildBody("she said \"hi\"", "1.0.0", "android")
        assertEquals(
            """{"v":1,"text":"she said \"hi\"","app":"1.0.0","platform":"android"}""",
            body,
        )
    }

    @Test
    fun buildBody_escapesNewlines() {
        val body = BugReportSender.buildBody("line1\nline2", "1.0.0", "ios")
        assertEquals(
            """{"v":1,"text":"line1\nline2","app":"1.0.0","platform":"ios"}""",
            body,
        )
    }

    @Test
    fun buildBody_escapesBackslashes() {
        val body = BugReportSender.buildBody("path\\to\\file", "1.0.0", "android")
        assertEquals(
            """{"v":1,"text":"path\\to\\file","app":"1.0.0","platform":"android"}""",
            body,
        )
    }

    @Test
    fun buildBody_trimsSurroundingWhitespace() {
        val body = BugReportSender.buildBody("   hello world   \n", "1.6.8", "ios")
        assertEquals(
            """{"v":1,"text":"hello world","app":"1.6.8","platform":"ios"}""",
            body,
        )
    }

    @Test
    fun buildBody_clipsOverLongTextAtMaxChars() {
        val long = "a".repeat(5000)
        val body = BugReportSender.buildBody(long, "1.6.8", "android")
        val expectedText = "a".repeat(BugReportSender.MAX_TEXT_CHARS)
        assertEquals(
            """{"v":1,"text":"$expectedText","app":"1.6.8","platform":"android"}""",
            body,
        )
    }

    @Test
    fun buildBody_exactlyMaxChars_notClipped() {
        val exact = "b".repeat(BugReportSender.MAX_TEXT_CHARS)
        val body = BugReportSender.buildBody(exact, "1.0.0", "ios")
        assertEquals(
            """{"v":1,"text":"$exact","app":"1.0.0","platform":"ios"}""",
            body,
        )
    }

    @Test
    fun buildBody_appAndPlatformFieldsAreAlsoEscaped() {
        // Defense-in-depth: the same escaper applies to every field, so a
        // stray quote anywhere can never break the JSON.
        val body = BugReportSender.buildBody("hi", "1.\"6\".8", "android")
        assertEquals(
            """{"v":1,"text":"hi","app":"1.\"6\".8","platform":"android"}""",
            body,
        )
    }

    // -------------------------------------------------------------------
    // send — transport behavior
    // -------------------------------------------------------------------

    @Test
    fun send_204_postsExpectedUrlAndContentType_returnsTrue() {
        val http = RecordingBugReportRelay()
        http.onPost = { HttpResult(204, null, true) }

        val ok = BugReportSender.send(http, BASE, "it crashed", "1.6.8", "android")

        assertTrue(ok)
        val call = http.requests.single()
        assertEquals("POST", call.method)
        assertEquals("$BASE/bugreport", call.url)
        assertEquals("application/json; charset=utf-8", call.contentType)
        assertEquals(
            """{"v":1,"text":"it crashed","app":"1.6.8","platform":"android"}""",
            call.bodyText,
        )
    }

    @Test
    fun send_200IsNotAccepted_returnsFalse() {
        // Only 204 counts per the wire contract — a 200 from a misbehaving
        // relay must not be treated as success.
        val http = RecordingBugReportRelay()
        http.onPost = { HttpResult(200, null, true) }

        assertFalse(BugReportSender.send(http, BASE, "it crashed", "1.6.8", "android"))
    }

    @Test
    fun send_413TooLarge_returnsFalse() {
        val http = RecordingBugReportRelay()
        http.onPost = { HttpResult(413, "too large", false) }

        assertFalse(BugReportSender.send(http, BASE, "it crashed", "1.6.8", "android"))
    }

    @Test
    fun send_429RateLimited_returnsFalse() {
        val http = RecordingBugReportRelay()
        http.onPost = { HttpResult(429, "slow down", false) }

        assertFalse(BugReportSender.send(http, BASE, "it crashed", "1.6.8", "android"))
    }

    @Test
    fun send_transportThrows_returnsFalseNeverThrows() {
        val http = RecordingBugReportRelay()
        http.onPost = { throw RuntimeException("no route to host") }

        assertFalse(BugReportSender.send(http, BASE, "it crashed", "1.6.8", "ios"))
    }

    @Test
    fun send_blankText_refusedBeforeAnyCall() {
        val http = RecordingBugReportRelay()

        assertFalse(BugReportSender.send(http, BASE, "   \n\t  ", "1.6.8", "android"))
        assertTrue(http.requests.isEmpty())
    }

    @Test
    fun send_emptyRelayBaseUrl_refusedBeforeAnyCall() {
        val http = RecordingBugReportRelay()

        assertFalse(BugReportSender.send(http, "", "it crashed", "1.6.8", "android"))
        assertTrue(http.requests.isEmpty())
    }

    @Test
    fun send_singleCallOnly_noRetries() {
        // "Send exactly once per tap" — a failure must not trigger a retry
        // loop inside the sender itself.
        val http = RecordingBugReportRelay()
        http.onPost = { HttpResult(500, "err", false) }

        BugReportSender.send(http, BASE, "it crashed", "1.6.8", "android")

        assertEquals(1, http.requests.size)
    }
}
