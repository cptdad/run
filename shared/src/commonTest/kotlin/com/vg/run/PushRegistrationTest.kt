package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// PushRegistrationTest — Phase-3 opt-in contentless-push client plumbing
// (docs/RELAY_SPEC.md (push)): PUT/DELETE /inbox/{id}/push.
// ---------------------------------------------------------------------------

private const val BASE = "http://relay.test"

// Valid 32-char inbox id (isValidInboxId) / 43-char capability (isValidCapability).
private const val INBOX_ID = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
private const val READ_CAP = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
private const val TOKEN = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd"

private class RecordingPushRelay : FakeRelayHttp(
    onPost = { throw AssertionError("push registration must never POST") },
    onGet = { throw AssertionError("push registration must never GET") },
) {
    data class Call(val method: String, val url: String, val body: String, val headers: Map<String, String>)
    val calls: List<Call>
        get() = requests.filter { it.method == "PUT" || it.method == "DELETE" }
            .map { Call(it.method, it.url, it.body.decodeToString(), it.headers) }
    var scripted: HttpResult = HttpResult(200, null, true)
    init { onPut = { scripted }; onDelete = { scripted } }
}

class PushRegistrationTest {

    @Test
    fun register_putsExpectedUrlBodyAndReadCapHeader() {
        val http = RecordingPushRelay()

        val ok = PushRegistration.register(http, BASE, INBOX_ID, READ_CAP, TOKEN, "sandbox")

        assertTrue(ok)
        val call = http.calls.single()
        assertEquals("PUT", call.method)
        assertEquals("$BASE/inbox/$INBOX_ID/push", call.url)
        assertEquals(READ_CAP, call.headers["X-Read-Capability"])
        // Write cap must NEVER appear on this path — registration is
        // recipient-only (docs/RELAY_SPEC.md (push)).
        assertEquals(null, call.headers["X-Write-Capability"])
        assertEquals("""{"platform":"apns","token":"$TOKEN","env":"sandbox"}""", call.body)
    }

    @Test
    fun register_badgeDefaultFalse_bodyByteIdenticalToPreExistingLiteral() {
        // badge defaults to false for every pre-existing caller (Android's FCM/
        // UnifiedPush registrations included) — the body must stay exactly what
        // the relay has always parsed, with no trailing "badge" field at all.
        val http = RecordingPushRelay()

        val ok = PushRegistration.register(http, BASE, INBOX_ID, READ_CAP, TOKEN, "sandbox")

        assertTrue(ok)
        assertEquals("""{"platform":"apns","token":"$TOKEN","env":"sandbox"}""", http.calls.single().body)
    }

    @Test
    fun register_badgeTrue_apns_appendsBadgeFieldAfterEnv() {
        // 2026-08-20: the APNs-only badge opt-in. Position is right after
        // "env":..., before any (absent, here) p256dh/auth key fields.
        val http = RecordingPushRelay()

        val ok = PushRegistration.register(http, BASE, INBOX_ID, READ_CAP, TOKEN, "sandbox", badge = true)

        assertTrue(ok)
        assertEquals(
            """{"platform":"apns","token":"$TOKEN","env":"sandbox","badge":true}""",
            http.calls.single().body,
        )
    }

    @Test
    fun register_badgeTrue_nonApnsPlatform_fieldOmitted() {
        // aps.badge has no fcm/unifiedpush analogue: badge=true on a non-apns
        // platform is a silent no-op, not a validation failure and not a body
        // change — so an accidental true never leaks the field onto a
        // registration the relay wouldn't know what to do with.
        val http = RecordingPushRelay()
        val fcmToken = "f".repeat(140)

        val ok = PushRegistration.register(http, BASE, INBOX_ID, READ_CAP, fcmToken, "production", platform = "fcm", badge = true)

        assertTrue(ok)
        assertEquals("""{"platform":"fcm","token":"$fcmToken","env":"production"}""", http.calls.single().body)
    }

    @Test
    fun register_relayFailure_returnsFalse() {
        val http = RecordingPushRelay()
        http.scripted = HttpResult(500, "err", false)

        assertFalse(PushRegistration.register(http, BASE, INBOX_ID, READ_CAP, TOKEN, "production"))
    }

    @Test
    fun register_malformedInboxId_refusedBeforeAnyCall() {
        val http = RecordingPushRelay()

        assertFalse(PushRegistration.register(http, BASE, "not-a-valid-inbox-id", READ_CAP, TOKEN, "sandbox"))
        assertTrue(http.calls.isEmpty(), "a malformed inbox id must never reach the transport")
    }

    @Test
    fun register_malformedCapability_refusedBeforeAnyCall() {
        val http = RecordingPushRelay()

        assertFalse(PushRegistration.register(http, BASE, INBOX_ID, "short", TOKEN, "sandbox"))
        assertTrue(http.calls.isEmpty())
    }

    @Test
    fun register_nonHexToken_refused() {
        val http = RecordingPushRelay()

        assertFalse(PushRegistration.register(http, BASE, INBOX_ID, READ_CAP, "not-hex-at-all!!", "sandbox"))
        assertTrue(http.calls.isEmpty(), "a malformed token must never reach the JSON body")
    }

    @Test
    fun register_badEnv_refused() {
        val http = RecordingPushRelay()

        assertFalse(PushRegistration.register(http, BASE, INBOX_ID, READ_CAP, TOKEN, "production\r\nX-Evil: 1"))
        assertTrue(http.calls.isEmpty())
    }

    @Test
    fun register_emptyRelayBaseUrl_noOp() {
        val http = RecordingPushRelay()

        assertFalse(PushRegistration.register(http, "", INBOX_ID, READ_CAP, TOKEN, "sandbox"))
        assertTrue(http.calls.isEmpty())
    }

    @Test
    fun unregister_deletesExpectedUrlWithReadCapHeader() {
        val http = RecordingPushRelay()

        val ok = PushRegistration.unregister(http, BASE, INBOX_ID, READ_CAP)

        assertTrue(ok)
        val call = http.calls.single()
        assertEquals("DELETE", call.method)
        assertEquals("$BASE/inbox/$INBOX_ID/push", call.url)
        assertEquals(READ_CAP, call.headers["X-Read-Capability"])
    }

    @Test
    fun unregister_200EvenWithNoPriorToken_stillReportsSuccess() {
        // docs/RELAY_SPEC.md (push): DELETE returns 200 even if no token was registered
        // (opt-out / wipe must not fail just because push was never enabled).
        val http = RecordingPushRelay()
        http.scripted = HttpResult(200, null, true)

        assertTrue(PushRegistration.unregister(http, BASE, INBOX_ID, READ_CAP))
    }

    @Test
    fun unregister_malformedInboxId_refusedBeforeAnyCall() {
        val http = RecordingPushRelay()

        assertFalse(PushRegistration.unregister(http, BASE, "bad", READ_CAP))
        assertTrue(http.calls.isEmpty())
    }
}

// ---------------------------------------------------------------------------
// unregisterAllReturningFailures — the shared per-ref DELETE pass behind the
// 2026-08-11 opt-out fix (in-session retry with backoff + the persisted
// pending-flag sweep). Both platforms' opt-out paths route through it, so the
// per-ref semantics are pinned here once, in commonTest.
// ---------------------------------------------------------------------------

/** DELETE-only fake whose outcome is scripted PER INBOX ID, so a pass over a
 *  mixed set can be asserted ref by ref (RecordingPushRelay scripts one result
 *  for every call, which cannot express a partial failure). */
private class PerInboxDeleteRelay(var failingInboxIds: Set<String>) : FakeRelayHttp(
    onPost = { throw AssertionError("push unregister must never POST") },
    onPut = { throw AssertionError("push unregister must never PUT") },
    onGet = { throw AssertionError("push unregister must never GET") },
) {
    val deletedUrls: List<String> get() = requestsOf("DELETE").map { it.url }
    init {
        onDelete = { r -> if (failingInboxIds.any { r.url.contains(it) }) HttpResult(500, "err", false) else HttpResult(200, null, true) }
    }
}

class UnregisterAllReturningFailuresTest {

    private val a = InboundInboxRef("A".repeat(32), "A".repeat(43))
    private val b = InboundInboxRef("B".repeat(32), "B".repeat(43))
    private val c = InboundInboxRef("C".repeat(32), "C".repeat(43))

    @Test
    fun allSucceed_returnsEmpty_afterDeletingEveryRef() {
        val http = PerInboxDeleteRelay(emptySet())

        val failures = PushRegistration.unregisterAllReturningFailures(http, BASE, listOf(a, b, c))

        assertTrue(failures.isEmpty())
        assertEquals(
            listOf(a, b, c).map { "$BASE/inbox/${it.inboxId}/push" },
            http.deletedUrls,
        )
    }

    @Test
    fun partialFailure_returnsExactlyTheFailedRefs_inOrder() {
        val http = PerInboxDeleteRelay(setOf(a.inboxId, c.inboxId))

        val failures = PushRegistration.unregisterAllReturningFailures(http, BASE, listOf(a, b, c))

        // Only the failed refs, original order preserved — the caller's retry
        // loop feeds this list straight back in.
        assertEquals(listOf(a, c), failures)
        // One failed DELETE must not abort the rest of the pass.
        assertEquals(3, http.deletedUrls.size)
    }

    @Test
    fun retryPass_touchesOnlyThePreviousFailures() {
        // The in-session retry shape: pass 1 over everything, pass 2 over pass
        // 1's failures only — an inbox already 200'd must not be re-DELETEd.
        val http = PerInboxDeleteRelay(setOf(b.inboxId))
        val firstFailures = PushRegistration.unregisterAllReturningFailures(http, BASE, listOf(a, b, c))
        assertEquals(listOf(b), firstFailures)

        http.clearRequests()
        http.failingInboxIds = emptySet()   // circuit recovered
        val secondFailures = PushRegistration.unregisterAllReturningFailures(http, BASE, firstFailures)

        assertTrue(secondFailures.isEmpty())
        assertEquals(listOf("$BASE/inbox/${b.inboxId}/push"), http.deletedUrls)
    }

    @Test
    fun malformedRef_countsAsFailure_withoutReachingTheTransport() {
        // unregister() refuses a malformed inbox id before any HTTP — the pass
        // must report it as a failure (fail-closed) rather than skip it silently.
        val bad = InboundInboxRef("bad", "B".repeat(43))
        val http = PerInboxDeleteRelay(emptySet())

        val failures = PushRegistration.unregisterAllReturningFailures(http, BASE, listOf(a, bad))

        assertEquals(listOf(bad), failures)
        assertEquals(listOf("$BASE/inbox/${a.inboxId}/push"), http.deletedUrls)
    }

    @Test
    fun emptyRefs_isANoOp() {
        val http = PerInboxDeleteRelay(emptySet())

        assertTrue(PushRegistration.unregisterAllReturningFailures(http, BASE, emptyList()).isEmpty())
        assertTrue(http.deletedUrls.isEmpty())
    }
}

// ---------------------------------------------------------------------------
// UnifiedPush (`platform = "unifiedpush"`) — the Google-free Android wake
// transport. [token] carries the distributor's RFC 8030 WebPush endpoint URL,
// and the RFC 8291 subscription keys ride along as a mandatory matched pair.
// ---------------------------------------------------------------------------

private const val UP_ENDPOINT = "https://ntfy.example/UP?up=1&i=abcdef0123456789"
// 87-char base64url (65-byte uncompressed P-256 point) and 22-char auth secret
// (16 bytes) — the shapes a real distributor hands back.
private val UP_P256DH = "B" + "A".repeat(86)
private val UP_AUTH = "C".repeat(22)

class PushRegistrationUnifiedPushTest {

    @Test
    fun register_unifiedPush_bodyCarriesEndpointAndBothKeys() {
        val http = RecordingPushRelay()

        val ok = PushRegistration.register(
            http, BASE, INBOX_ID, READ_CAP, UP_ENDPOINT, "production",
            platform = "unifiedpush", p256dh = UP_P256DH, auth = UP_AUTH,
        )

        assertTrue(ok)
        val call = http.calls.single()
        assertEquals("PUT", call.method)
        assertEquals("$BASE/inbox/$INBOX_ID/push", call.url)
        assertEquals(READ_CAP, call.headers["X-Read-Capability"])
        assertEquals(null, call.headers["X-Write-Capability"])
        assertEquals(
            """{"platform":"unifiedpush","token":"$UP_ENDPOINT","env":"production","p256dh":"$UP_P256DH","auth":"$UP_AUTH"}""",
            call.body,
        )
    }

    @Test
    fun register_unifiedPush_badgeTrue_fieldOmitted_keysStillPresent() {
        // badge is APNs-only: true on a unifiedpush registration must not add
        // a "badge" field, and must not disturb the p256dh/auth key fields.
        val http = RecordingPushRelay()

        val ok = PushRegistration.register(
            http, BASE, INBOX_ID, READ_CAP, UP_ENDPOINT, "production",
            platform = "unifiedpush", p256dh = UP_P256DH, auth = UP_AUTH, badge = true,
        )

        assertTrue(ok)
        assertEquals(
            """{"platform":"unifiedpush","token":"$UP_ENDPOINT","env":"production","p256dh":"$UP_P256DH","auth":"$UP_AUTH"}""",
            http.calls.single().body,
        )
    }

    @Test
    fun register_apns_bodyStillHasExactlyThreeFields_whenNoKeysPassed() {
        // The whole point of making p256dh/auth trailing + nullable: an
        // apns/fcm body must remain byte-identical to what the relay has
        // always parsed. (register_putsExpectedUrlBodyAndReadCapHeader pins
        // apns; this pins the fcm sibling, which has no exact-body test of
        // its own.)
        val http = RecordingPushRelay()
        val fcmToken = "f".repeat(140)

        assertTrue(PushRegistration.register(http, BASE, INBOX_ID, READ_CAP, fcmToken, "production", platform = "fcm"))

        assertEquals("""{"platform":"fcm","token":"$fcmToken","env":"production"}""", http.calls.single().body)
    }

    @Test
    fun register_unifiedPush_missingEitherKey_refusedBeforeAnyCall() {
        // A one-sided pair is undeliverable — the relay cannot RFC-8291-encrypt
        // a wake without both halves — so it must never become a subscription.
        val http = RecordingPushRelay()

        assertFalse(PushRegistration.register(
            http, BASE, INBOX_ID, READ_CAP, UP_ENDPOINT, "production",
            platform = "unifiedpush", p256dh = UP_P256DH, auth = null,
        ))
        assertFalse(PushRegistration.register(
            http, BASE, INBOX_ID, READ_CAP, UP_ENDPOINT, "production",
            platform = "unifiedpush", p256dh = null, auth = UP_AUTH,
        ))
        assertFalse(PushRegistration.register(
            http, BASE, INBOX_ID, READ_CAP, UP_ENDPOINT, "production",
            platform = "unifiedpush",
        ))
        assertTrue(http.calls.isEmpty(), "a mismatched key pair must never reach the transport")
    }

    @Test
    fun register_unifiedPush_malformedEndpoint_refusedBeforeAnyCall() {
        val http = RecordingPushRelay()

        for (bad in listOf(
            "http://ntfy.example/UP?up=1&i=abcdef",          // http, not https
            "ntfy.example/UP?up=1&i=abcdef0123456789",       // no scheme
            "https://short",                                  // under the 16-char floor
            "https://ntfy.example/UP?i=a b",                  // whitespace
            "https://ntfy.example/UP\r\nX-Evil: 1",           // CRLF injection
            "https://ntfy.example/\"quoted\"",                // JSON-breaking quote
            "https://ntfy.example/back\\slash",               // JSON-breaking backslash
            "https://ntfy.example/" + "x".repeat(1100),       // over the 1024 ceiling
        )) {
            assertFalse(
                PushRegistration.register(
                    http, BASE, INBOX_ID, READ_CAP, bad, "production",
                    platform = "unifiedpush", p256dh = UP_P256DH, auth = UP_AUTH,
                ),
                "endpoint must be refused: $bad",
            )
        }
        assertTrue(http.calls.isEmpty(), "a malformed endpoint must never reach the JSON body")
    }

    @Test
    fun register_unifiedPush_malformedKeys_refusedBeforeAnyCall() {
        val http = RecordingPushRelay()

        // Non-base64url characters (quote / backslash / whitespace / CRLF) and
        // out-of-band lengths must all be refused before the body is built.
        assertFalse(PushRegistration.register(
            http, BASE, INBOX_ID, READ_CAP, UP_ENDPOINT, "production",
            platform = "unifiedpush", p256dh = "\"" + "A".repeat(86), auth = UP_AUTH,
        ))
        assertFalse(PushRegistration.register(
            http, BASE, INBOX_ID, READ_CAP, UP_ENDPOINT, "production",
            platform = "unifiedpush", p256dh = UP_P256DH, auth = "C\r\nX-Evil: 1",
        ))
        assertFalse(PushRegistration.register(
            http, BASE, INBOX_ID, READ_CAP, UP_ENDPOINT, "production",
            platform = "unifiedpush", p256dh = "short", auth = UP_AUTH,
        ))
        assertFalse(PushRegistration.register(
            http, BASE, INBOX_ID, READ_CAP, UP_ENDPOINT, "production",
            platform = "unifiedpush", p256dh = UP_P256DH, auth = "C".repeat(200),
        ))
        assertTrue(http.calls.isEmpty())
    }

    @Test
    fun register_unifiedPush_badEnv_refusedBeforeAnyCall() {
        val http = RecordingPushRelay()

        assertFalse(PushRegistration.register(
            http, BASE, INBOX_ID, READ_CAP, UP_ENDPOINT, "production\r\nX-Evil: 1",
            platform = "unifiedpush", p256dh = UP_P256DH, auth = UP_AUTH,
        ))
        assertFalse(PushRegistration.register(
            http, BASE, INBOX_ID, READ_CAP, UP_ENDPOINT, "",
            platform = "unifiedpush", p256dh = UP_P256DH, auth = UP_AUTH,
        ))
        assertFalse(PushRegistration.register(
            http, BASE, INBOX_ID, READ_CAP, UP_ENDPOINT, "e".repeat(33),
            platform = "unifiedpush", p256dh = UP_P256DH, auth = UP_AUTH,
        ))
        assertTrue(http.calls.isEmpty())
    }

    @Test
    fun register_vendorPlatformsWithWebPushKeys_refused() {
        // Platform-exclusive keys, mirroring the relay's own validator: an
        // apns/fcm row must never carry WebPush key material, so a caller
        // cannot smuggle it onto one.
        val http = RecordingPushRelay()

        assertFalse(PushRegistration.register(
            http, BASE, INBOX_ID, READ_CAP, TOKEN, "sandbox",
            platform = "apns", p256dh = UP_P256DH, auth = UP_AUTH,
        ))
        assertFalse(PushRegistration.register(
            http, BASE, INBOX_ID, READ_CAP, "f".repeat(140), "production",
            platform = "fcm", p256dh = UP_P256DH, auth = UP_AUTH,
        ))
        assertTrue(http.calls.isEmpty())
    }

    @Test
    fun register_unknownPlatform_refused() {
        val http = RecordingPushRelay()

        assertFalse(PushRegistration.register(
            http, BASE, INBOX_ID, READ_CAP, UP_ENDPOINT, "production", platform = "webpush",
        ))
        assertTrue(http.calls.isEmpty())
    }
}

class IsPlausibleUnifiedPushEndpointTest {

    @Test
    fun httpsOnly_httpRefusedEvenForOnion() {
        // Decision locked by the plan: the relay reaches the endpoint through a
        // Tor HTTP-CONNECT tunnel, which is CONNECT-only — an http:// target
        // (onion included) 405s, so accepting one here would only produce a
        // subscription that silently never delivers.
        assertTrue(isPlausibleUnifiedPushEndpoint("https://ntfy.example/UP?up=1&i=abc"))
        assertTrue(isPlausibleUnifiedPushEndpoint("https://abcdefghijklmnopqrstuvwxyz234567.onion/UP?i=abc"))
        assertFalse(isPlausibleUnifiedPushEndpoint("http://ntfy.example/UP?up=1&i=abc"))
        assertFalse(isPlausibleUnifiedPushEndpoint("http://abcdefghijklmnopqrstuvwxyz234567.onion/UP?i=abc"))
        assertFalse(isPlausibleUnifiedPushEndpoint("HTTPS://ntfy.example/UP?up=1&i=abc"))
    }

    @Test
    fun lengthBounds_16to1024() {
        assertFalse(isPlausibleUnifiedPushEndpoint(""))
        assertFalse(isPlausibleUnifiedPushEndpoint("https://"))
        assertTrue(isPlausibleUnifiedPushEndpoint("https://a.example"))            // exactly 17
        assertTrue(isPlausibleUnifiedPushEndpoint("https://" + "a".repeat(1016)))  // exactly 1024
        assertFalse(isPlausibleUnifiedPushEndpoint("https://" + "a".repeat(1017))) // 1025
    }

    @Test
    fun rejectsWhitespaceQuoteAndBackslash() {
        assertFalse(isPlausibleUnifiedPushEndpoint("https://ntfy.example/UP i=abc"))
        assertFalse(isPlausibleUnifiedPushEndpoint("https://ntfy.example/UP\r\nX-Evil: 1"))
        assertFalse(isPlausibleUnifiedPushEndpoint("https://ntfy.example/UP\ti=abc"))
        assertFalse(isPlausibleUnifiedPushEndpoint("https://ntfy.example/\"i\"=abc"))
        assertFalse(isPlausibleUnifiedPushEndpoint("https://ntfy.example/\\i=abc"))
    }

    @Test
    fun neverThrows_onPathologicalInput() {
        // No URL parser behind this predicate on purpose — it must be total.
        for (s in listOf("h", "https:/", "https://\u0000abcdefghij", "https://ñ.example/abcdefgh", "://")) {
            isPlausibleUnifiedPushEndpoint(s)
        }
    }
}

class AllInboundInboxesTest {

    @Test
    fun collectsBothMainAndControlInboundInboxesAcrossContacts() {
        val vault = InMemoryVault()
        vault.insertContact(ContactRecord("c1", generateSecureRandom(32), 1, "A", 0L))
        vault.insertContact(ContactRecord("c2", generateSecureRandom(32), 1, "B", 0L))
        vault.insertInboxId(InboxIdRecord(
            inboxId = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", contactId = "c1",
            createdAt = 1L, expiresAt = Long.MAX_VALUE, direction = "inbound", cap = "A".repeat(43),
        ))
        vault.insertInboxId(InboxIdRecord(
            inboxId = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", contactId = "c1",
            createdAt = 1L, expiresAt = Long.MAX_VALUE, direction = MessageManager.DIR_INBOUND_CTL, cap = "B".repeat(43),
        ))
        vault.insertInboxId(InboxIdRecord(
            inboxId = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", contactId = "c2",
            createdAt = 1L, expiresAt = Long.MAX_VALUE, direction = "inbound", cap = "C".repeat(43),
        ))
        // c2 has no control channel (pre-v7 pairing) — must simply be skipped, not error.

        val refs = allInboundInboxes(vault)

        assertEquals(setOf("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"),
            refs.map { it.inboxId }.toSet())
    }

    @Test
    fun skipsRowsWithNoCapability() {
        val vault = InMemoryVault()
        vault.insertContact(ContactRecord("c1", generateSecureRandom(32), 1, "A", 0L))
        vault.insertInboxId(InboxIdRecord(
            inboxId = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", contactId = "c1",
            createdAt = 1L, expiresAt = Long.MAX_VALUE, direction = "inbound", cap = null,
        ))

        assertTrue(allInboundInboxes(vault).isEmpty())
    }
}

class AllInboundTextInboxesTest {

    @Test
    fun excludesControlInboxes_includesOnlyText() {
        // Regression for the on-device bug (2026-07-27): a push-opted device
        // registered a CONTROL inbox (spurious "New message" alert on every
        // pairing/ratchet-repair control blob) and missed a live TEXT inbox.
        // Push registration must draw from this function, never allInboundInboxes.
        val vault = InMemoryVault()
        vault.insertContact(ContactRecord("c1", generateSecureRandom(32), 1, "A", 0L))
        vault.insertContact(ContactRecord("c2", generateSecureRandom(32), 1, "B", 0L))
        vault.insertInboxId(InboxIdRecord(
            inboxId = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", contactId = "c1",
            createdAt = 1L, expiresAt = Long.MAX_VALUE, direction = "inbound", cap = "A".repeat(43),
        ))
        vault.insertInboxId(InboxIdRecord(
            inboxId = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", contactId = "c1",
            createdAt = 1L, expiresAt = Long.MAX_VALUE, direction = MessageManager.DIR_INBOUND_CTL, cap = "B".repeat(43),
        ))
        vault.insertInboxId(InboxIdRecord(
            inboxId = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", contactId = "c2",
            createdAt = 1L, expiresAt = Long.MAX_VALUE, direction = "inbound", cap = "C".repeat(43),
        ))

        val refs = allInboundTextInboxes(vault)

        assertEquals(setOf("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"),
            refs.map { it.inboxId }.toSet())
    }

    @Test
    fun skipsRowsWithNoCapability() {
        val vault = InMemoryVault()
        vault.insertContact(ContactRecord("c1", generateSecureRandom(32), 1, "A", 0L))
        vault.insertInboxId(InboxIdRecord(
            inboxId = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", contactId = "c1",
            createdAt = 1L, expiresAt = Long.MAX_VALUE, direction = "inbound", cap = null,
        ))

        assertTrue(allInboundTextInboxes(vault).isEmpty())
    }

    @Test
    fun contactWithOnlyControlInbox_yieldsNothing() {
        val vault = InMemoryVault()
        vault.insertContact(ContactRecord("c1", generateSecureRandom(32), 1, "A", 0L))
        vault.insertInboxId(InboxIdRecord(
            inboxId = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", contactId = "c1",
            createdAt = 1L, expiresAt = Long.MAX_VALUE, direction = MessageManager.DIR_INBOUND_CTL, cap = "B".repeat(43),
        ))

        assertTrue(allInboundTextInboxes(vault).isEmpty())
    }
}

class InboxesNeedingRegistrationTest {

    private val a = InboundInboxRef("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "A".repeat(43))
    private val b = InboundInboxRef("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", "B".repeat(43))
    private val c = InboundInboxRef("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", "C".repeat(43))

    @Test
    fun emptyAlreadyRegistered_returnsEverything() {
        assertEquals(listOf(a, b), inboxesNeedingRegistration(listOf(a, b), emptySet()))
    }

    @Test
    fun fullyCoveredSet_returnsEmpty() {
        assertTrue(inboxesNeedingRegistration(listOf(a, b), setOf(a.inboxId, b.inboxId)).isEmpty())
    }

    @Test
    fun onlyNewlyMintedInboxSurfaces() {
        // Simulates the coverage-gap scenario: a and b were registered at
        // app-launch time; c is a brand-new contact's inbox minted afterward
        // (pairing/referral) and must be the only one the diff surfaces.
        val result = inboxesNeedingRegistration(listOf(a, b, c), setOf(a.inboxId, b.inboxId))
        assertEquals(listOf(c), result)
    }

    @Test
    fun desiredSetShrank_noStaleEntriesResurface() {
        // A contact deleted since the last sync simply drops out of `desired`
        // — the diff must not error or invent anything for an id that's no
        // longer present.
        assertTrue(inboxesNeedingRegistration(listOf(a), setOf(a.inboxId, b.inboxId, c.inboxId)).isEmpty())
    }
}
