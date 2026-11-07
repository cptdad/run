package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// MoveHandleCodec — the QR / paste text of a move.
//
// The handle IS the transfer secret (inbox read capability + the 160-bit
// one-time code), so this codec is a trust boundary in exactly the way
// PairingPayload is: anything malformed must be REJECTED rather than stored,
// and one shape must be produced/accepted by both platforms.
// ---------------------------------------------------------------------------
class MigrationHandleTest {

    private val inbox = migTestInboxId(31)
    private val rcap = migTestCap(31)
    private val bid = migTestBundleId(31)
    private val code = MigrationSeal.encodeCode(ByteArray(MoveConstants.CODE_BYTES) { (it * 9 + 3).toByte() })

    private fun handle() = MoveHandle(inboxId = inbox, readCap = rcap, code = code, bundleId = bid)

    @Test
    fun aMoveHandle_survivesQrTextEncodeAndParse() {
        val h = handle()
        val text = MoveHandleCodec.toQrText(h)
        assertEquals(h, MoveHandleCodec.parse(text))
    }

    @Test
    fun qrTextIsDepth1AllStringJson() {
        val text = MoveHandleCodec.toQrText(handle())
        assertTrue(text.startsWith("{") && text.endsWith("}"))
        assertTrue(text.contains("\"v\":\"1\""), "version travels as a STRING, like PairingPayload")
        assertTrue(text.contains("\"inbox\":\"$inbox\""))
        assertTrue(text.contains("\"rcap\":\"$rcap\""))
        assertTrue(text.contains("\"code\":\"$code\""))
        assertTrue(text.contains("\"bid\":\"$bid\""))
    }

    @Test
    fun toleratesSurroundingWhitespace() {
        val text = MoveHandleCodec.toQrText(handle())
        assertEquals(handle(), MoveHandleCodec.parse("\n\t  $text  \n"))
    }

    @Test
    fun normalisesTheCodeOnParse() {
        // A user retyping the code from A's "show as text" screen will group it and
        // may use lower case; downstream must only ever see the canonical form.
        val grouped = Base32.formatGrouped(code.lowercase(), 4, "-")
        val text = "{\"v\":\"1\",\"inbox\":\"$inbox\",\"rcap\":\"$rcap\",\"code\":\"$grouped\",\"bid\":\"$bid\"}"
        val parsed = assertNotNull(MoveHandleCodec.parse(text), "grouped lower-case code must parse")
        assertEquals(code, parsed.code, "parse must return the canonical 32-symbol code")
    }

    @Test
    fun rejectsEveryMalformedField() {
        val good = MoveHandleCodec.toQrText(handle())
        val bad = listOf(
            "" to "empty",
            "   " to "blank",
            "not json" to "not json",
            "[]" to "array",
            good.dropLast(1) to "truncated",
            "junk$good" to "leading junk",
            "${good}junk" to "trailing junk",
            good.replace("\"v\":\"1\"", "\"v\":\"2\"") to "future version",
            good.replace("\"v\":\"1\"", "\"v\":1") to "version as a number",
            good.replace("\"v\":\"1\",", "") to "missing version",
            good.replace("\"inbox\":\"$inbox\",", "") to "missing inbox",
            good.replace("\"rcap\":\"$rcap\",", "") to "missing rcap",
            good.replace("\"code\":\"$code\",", "") to "missing code",
            good.replace(",\"bid\":\"$bid\"", "") to "missing bid",
            good.replace(inbox, inbox.dropLast(1)) to "31-char inbox id",
            good.replace(inbox, inbox.dropLast(1) + "!") to "bad inbox alphabet",
            good.replace(rcap, rcap.dropLast(1)) to "42-char cap",
            good.replace(rcap, rcap.dropLast(1) + "+") to "bad cap alphabet",
            good.replace(bid, bid.dropLast(1)) to "15-char bundle id",
            good.replace(code, code.dropLast(1)) to "31-symbol code",
            good.replace(code, code + "Z") to "33-symbol code",
            good.replace("\"code\":\"$code\"", "\"code\":123") to "code as a number",
            good.replace("\"rcap\":\"$rcap\"", "\"rcap\":{\"a\":\"b\"}") to "cap as an object",
            "{\"v\":\"1\"}" to "version only",
        )
        for ((text, why) in bad) {
            assertNull(MoveHandleCodec.parse(text), "must reject: $why")
        }
    }

    @Test
    fun rejectsAnOverLongPayload() {
        val good = MoveHandleCodec.toQrText(handle())
        val padded = good.dropLast(1) + ",\"junk\":\"" + "A".repeat(2000) + "\"}"
        assertNull(MoveHandleCodec.parse(padded))
    }

    @Test
    fun unknownExtraFieldsAreIgnored() {
        val good = MoveHandleCodec.toQrText(handle())
        val extended = good.dropLast(1) + ",\"future\":\"x\"}"
        assertEquals(handle(), MoveHandleCodec.parse(extended))
    }

    @Test
    fun toQrTextOfAnInvalidHandleIsRejectedByParse() {
        // toQrText never throws (it is on both platforms' UI paths); the guarantee is
        // that a malformed handle simply does not survive a parse.
        val junk = MoveHandle(inboxId = "nope", readCap = "nope", code = "nope", bundleId = "nope")
        assertNull(MoveHandleCodec.parse(MoveHandleCodec.toQrText(junk)))
    }

    @Test
    fun quotesInAFieldCannotBreakOutOfTheJson() {
        val evil = MoveHandle(
            inboxId = "\",\"rcap\":\"$rcap",
            readCap = rcap,
            code = code,
            bundleId = bid,
        )
        // Escaped on build, and the resulting inbox id fails validation on parse.
        assertNull(MoveHandleCodec.parse(MoveHandleCodec.toQrText(evil)))
    }

    @Test
    fun newBundleId_isSixteenBase64UrlCharsAndFresh() {
        val a = MoveHandleCodec.newBundleId()
        val b = MoveHandleCodec.newBundleId()
        assertEquals(MoveHandleCodec.BUNDLE_ID_LENGTH, a.length)
        assertTrue(MoveHandleCodec.isValidBundleId(a))
        assertNotEquals(a, b)
    }

    @Test
    fun isValidBundleId_isStrict() {
        assertTrue(MoveHandleCodec.isValidBundleId("aA0_-bcdefghijkl"))   // 16 base64url chars
        assertTrue(!MoveHandleCodec.isValidBundleId(""))
        assertTrue(!MoveHandleCodec.isValidBundleId("0123456789abcde"))     // 15
        assertTrue(!MoveHandleCodec.isValidBundleId("0123456789abcdefg"))   // 17
        assertTrue(!MoveHandleCodec.isValidBundleId("0123456789abcde+"))    // wrong alphabet
        assertTrue(!MoveHandleCodec.isValidBundleId("0123456789abcde "))
    }

    @Test
    fun redactedRenderingLeaksNeitherCapNorCode() {
        val r = MoveHandleCodec.redact(handle())
        assertTrue(!r.contains(rcap), "read capability must never be rendered")
        assertTrue(!r.contains(code), "one-time code must never be rendered")
        assertTrue(!r.contains(inbox), "full inbox id must not be rendered")
        assertTrue(r.contains("[redacted]"))
        // No id FRAGMENT either — log lines carry class names and counts only.
        assertTrue(!r.contains(inbox.take(4)), "no inbox id prefix may be rendered")
        assertTrue(!r.contains(handle().bundleId.take(4)), "no bundle id prefix may be rendered")
        val s = handle().toString()
        for (secret in listOf(inbox.take(4), handle().bundleId.take(4), rcap, code)) {
            assertTrue(!s.contains(secret), "MoveHandle.toString must render no id fragment")
        }
    }
}
