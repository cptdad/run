package com.vg.run

// ---------------------------------------------------------------------------
// BugReportSender — anonymous "Report bug" wire client.
//
// Deliberately standalone (NOT part of MessageManager): this path shares
// nothing with the message protocol — no vault, no contact, no capability
// token, no PoW, no anti-replay counter. It is a single bare JSON POST to a
// relay endpoint that requires no auth at all, by design (the user stays
// anonymous), so keeping it out of MessageManager means this feature never
// touches message-protocol code.
//
// Wire contract (agreed with the relay side — do not change without also
// updating the relay):
//   POST <relayBaseUrl>/bugreport
//   Content-Type: application/json; charset=utf-8
//   {"v":1,"text":"<user text>","app":"<versionName e.g. 1.6.8>","platform":"android"|"ios"}
//   204 = accepted; 413 = too large; 429 = rate-limited; anything else /
//   transport failure = error. No retries — callers send exactly once per tap.
//
// Transport: callers pass in the SAME [RelayHttp] MessageManager is already
// using for this session (see MessageManager.relayTransport()) — Tor SOCKS in
// production, direct HTTP only where the app already uses it in debug/
// emulator. No new clearnet path is introduced here. "Connection: close" is
// already what that shared transport sends on every request (SwiftTorHttp's
// raw HTTP/1.1 request line; OkHttp's zero-keepalive SOCKS ConnectionPool),
// so nothing extra is needed here for that either.
// ---------------------------------------------------------------------------

object BugReportSender {
    /**
     * Client-side text ceiling. Both platform text fields clip user input to
     * this as it's typed (and show a counter) — see
     * `report_bug_text_field`/`ReportBugDialog`. A plain `val` member (not a
     * top-level `const val`) so Swift can read the SAME number via
     * `BugReportSender.shared.MAX_TEXT_CHARS`, the identical pattern
     * `CredentialPolicy.MAX_PASSPHRASE_LENGTH` already uses, rather than
     * hand-duplicating the literal on both platforms.
     */
    val MAX_TEXT_CHARS: Int = 4000

    /**
     * Hard body-size ceiling (bytes) per the wire contract. [MAX_TEXT_CHARS]'s
     * worst-case JSON-escaped size (~3 bytes/UTF-16 unit for an unescaped
     * multi-byte char, ~2 for an escaped ASCII one) plus the small
     * app/platform/json overhead never approaches this — kept as an explicit
     * belt-and-braces cap rather than an assumption.
     */
    internal const val MAX_BODY_BYTES: Int = 16 * 1024

    private const val CONTENT_TYPE = "application/json; charset=utf-8"
    private const val PATH = "/bugreport"

    /**
     * Builds the wire body: [rawText] trimmed, then clipped to
     * [MAX_TEXT_CHARS] UTF-16 code units (matching the field's own clip, so
     * what the on-screen counter shows is what is sent), with every field
     * JSON-escaped via the same [jsonEscapeString] the message envelope uses.
     * Pure and non-throwing — unit-tested (BugReportSenderTest) without a
     * network dependency.
     */
    internal fun buildBody(rawText: String, appVersion: String, platform: String): String {
        val trimmed = rawText.trim()
        val clipped = if (trimmed.length > MAX_TEXT_CHARS) trimmed.substring(0, MAX_TEXT_CHARS) else trimmed
        return "{\"v\":1,\"text\":${jsonEscapeString(clipped)}," +
            "\"app\":${jsonEscapeString(appVersion)}," +
            "\"platform\":${jsonEscapeString(platform)}}"
    }

    /**
     * Sends [rawText] exactly once — no retry loop (the spec: "send exactly
     * once per tap"). Returns true ONLY on the relay's 204; every other
     * status (413 too large, 429 rate-limited, anything else) and every
     * transport failure/exception returns false. Callers show one generic
     * error copy for all of those — an anonymous, unauthenticated endpoint
     * has no finer-grained state worth surfacing to the user.
     *
     * A blank [rawText] (after trim) is refused before any network I/O — the
     * UI already disables Send while blank, but this keeps the guarantee
     * true for any future caller that forgets the UI-level check.
     */
    fun send(http: RelayHttp, relayBaseUrl: String, rawText: String, appVersion: String, platform: String): Boolean {
        if (relayBaseUrl.isEmpty() || rawText.isBlank()) return false
        val body = buildBody(rawText, appVersion, platform).encodeToByteArray()
        if (body.size > MAX_BODY_BYTES) return false
        val result = try {
            http.post("$relayBaseUrl$PATH", body, CONTENT_TYPE)
        } catch (e: Exception) {
            platformLogWarn("BugReportSender", "send threw: ${e::class.simpleName}")
            return false
        }
        return result.code == 204
    }
}
