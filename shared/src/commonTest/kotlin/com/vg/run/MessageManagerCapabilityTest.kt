package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

// ---------------------------------------------------------------------------
// Test fixtures shared across the MessageManager auth-matrix tests below.
// ---------------------------------------------------------------------------

private const val FIXTURE_INBOX_ID      = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX"  // 32 chars
private const val FIXTURE_PEER_INBOX_ID = "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"  // 32 chars
private const val FIXTURE_READ_CAP      = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  // 43 chars
private const val FIXTURE_WRITE_CAP     = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"  // 43 chars

// InMemoryVault, RecordingRelayHttp, PairMintRelayHttp and powChallengeBody live in support/.

// ---------------------------------------------------------------------------
// Auth-matrix tests for the capability-based MessageManager.
// ---------------------------------------------------------------------------

class MessageManagerCapabilityTest {

    private fun seedContact(vault: InMemoryVault, contactId: String, withCaps: Boolean) {
        vault.insertContact(
            ContactRecord(
                contactId = contactId,
                sharedSecret = generateSecureRandom(32),
                trustLevel = 1,
                alias = "T",
                aliasLastRotated = 0L,
            )
        )
        vault.insertInboxId(
            InboxIdRecord(
                inboxId = FIXTURE_INBOX_ID,
                contactId = contactId,
                createdAt = 1L,
                expiresAt = Long.MAX_VALUE,
                direction = "inbound",
                cap = if (withCaps) FIXTURE_READ_CAP else null,
            )
        )
        vault.insertInboxId(
            InboxIdRecord(
                inboxId = FIXTURE_PEER_INBOX_ID,
                contactId = contactId,
                createdAt = 1L,
                expiresAt = Long.MAX_VALUE,
                direction = "outbound",
                cap = if (withCaps) FIXTURE_WRITE_CAP else null,
            )
        )
    }

    // A relay PoW-challenge body — single-sourced; see [powChallengeBody].
    private fun challengeBody(nonce: String = "AAECAwQFBgcICQoLDA0ODw", difficulty: Int = 8) =
        powChallengeBody(nonce, difficulty)

    private val mintSuccessBody =
        """{"inboxId":"$FIXTURE_INBOX_ID","readCapability":"$FIXTURE_READ_CAP","writeCapability":"$FIXTURE_WRITE_CAP","expiresAt":12345}"""

    @Test
    fun mintInbox_twoPhase_success_parsesRelayBody() {
        val vault = InMemoryVault()
        val http = RecordingRelayHttp()
        // Phase 1: 400 challenge. Phase 2: 201 mint after a valid solve.
        http.script(
            HttpResult(code = 400, body = challengeBody(), isSuccess = false),
            HttpResult(code = 201, body = mintSuccessBody, isSuccess = true),
        )
        val mgr = MessageManager(
            databaseManager = vault, relayBaseUrl = "http://relay.test", transport = http,
        )
        val minted = mgr.mintInbox()
        assertNotNull(minted)
        assertEquals(FIXTURE_INBOX_ID, minted.inboxId)
        assertEquals(FIXTURE_READ_CAP, minted.readCapability)
        assertEquals(FIXTURE_WRITE_CAP, minted.writeCapability)
        assertEquals(12345L, minted.expiresAt)

        assertEquals(2, http.calls.size)
        // First call: challenge request — empty body, NO PoW headers.
        val fetch = http.calls[0]
        assertEquals("POST", fetch.method)
        assertEquals("http://relay.test/inbox", fetch.url)
        assertEquals(0, fetch.body.size)
        assertTrue(!fetch.headers.containsKey("X-PoW-Token"))
        assertTrue(!fetch.headers.containsKey("X-PoW-Counter"))
        // The old precomputable window header must be gone entirely.
        assertTrue(!fetch.headers.containsKey("X-PoW-Window"))
        // Second call: solution submit — token echoed + winning counter.
        val submit = http.calls[1]
        assertEquals("POST", submit.method)
        assertEquals("http://relay.test/inbox", submit.url)
        assertEquals("opaque-token-xyz", submit.headers["X-PoW-Token"])
        assertNotNull(submit.headers["X-PoW-Counter"])
        assertTrue(!submit.headers.containsKey("X-PoW-Window"))
    }

    @Test
    fun mintInbox_retriesOn400_thenSucceeds() {
        val vault = InMemoryVault()
        val http = RecordingRelayHttp()
        // Challenge → solve → relay rejects with a FRESH challenge (expired/
        // spent/skew) → re-solve → 201. Bounded retry must re-fetch and re-solve.
        http.script(
            HttpResult(code = 400, body = challengeBody(nonce = "AAAAAAAAAAAAAAAAAAAAAA"), isSuccess = false),
            HttpResult(code = 400, body = challengeBody(nonce = "_-A_----ABEiM6q7zN3u_w"), isSuccess = false),
            HttpResult(code = 201, body = mintSuccessBody, isSuccess = true),
        )
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)
        val minted = mgr.mintInbox()
        assertNotNull(minted)
        assertEquals(FIXTURE_INBOX_ID, minted.inboxId)
        assertEquals(3, http.calls.size)
    }

    @Test
    fun mintInbox_relayKeepsRejecting_returnsNullAfterBoundedRetries() {
        val vault = InMemoryVault()
        val http = RecordingRelayHttp()
        // 1 challenge fetch + 3 solve attempts that each get a fresh 400 back.
        // The 4th 400 wouldn't be requested — the loop is bounded at 3 solves.
        http.script(
            HttpResult(code = 400, body = challengeBody(), isSuccess = false),
            HttpResult(code = 400, body = challengeBody(), isSuccess = false),
            HttpResult(code = 400, body = challengeBody(), isSuccess = false),
            HttpResult(code = 400, body = challengeBody(), isSuccess = false),
        )
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)
        assertNull(mgr.mintInbox())
        // 1 fetch + 3 bounded submit attempts = 4 POSTs, then give up.
        assertEquals(4, http.calls.size)
    }

    @Test
    fun mintInbox_difficultyAboveCeiling_refusesWithoutSubmitting() {
        val vault = InMemoryVault()
        val http = RecordingRelayHttp()
        // A hostile relay asks for more than the client ceiling. The client
        // must refuse to grind and never submit a solution.
        http.script(
            HttpResult(code = 400, body = challengeBody(difficulty = MAX_POW_DIFFICULTY_BITS + 1), isSuccess = false),
        )
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)
        assertNull(mgr.mintInbox())
        // Only the challenge fetch happened — no solution was submitted.
        assertEquals(1, http.calls.size)
    }

    @Test
    fun mintInbox_429OnSubmit_backsOffAndRetriesThenSucceeds() {
        val vault = InMemoryVault()
        val http = RecordingRelayHttp()
        // A 429 means "slow down", not "give up": the client backs off and
        // retries the whole handshake, and the relay accepts the next attempt.
        // (Re-grind across the retry stays bounded by MINT_TOTAL_POW_BUDGET_MS,
        // which is the actual anti-DoS guarantee — not a terminal 429.)
        http.script(
            HttpResult(code = 400, body = challengeBody(), isSuccess = false),
            HttpResult(code = 429, body = """{"error":"rate limited"}""", isSuccess = false),
            HttpResult(code = 400, body = challengeBody(), isSuccess = false),
            HttpResult(code = 201, body = mintSuccessBody, isSuccess = true),
        )
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)
        assertNotNull(mgr.mintInbox())
        // fetch, rate-limited submit, fetch (retry), accepted submit = 4 POSTs.
        assertEquals(4, http.calls.size)
    }

    @Test
    fun mintInbox_malformedCapInResponse_returnsNull() {
        val vault = InMemoryVault()
        val http = RecordingRelayHttp()
        // 201 but with a truncated readCapability (shape must be checked).
        http.script(
            HttpResult(code = 400, body = challengeBody(), isSuccess = false),
            HttpResult(
                code = 201,
                body = """{"inboxId":"$FIXTURE_INBOX_ID","readCapability":"too-short","writeCapability":"$FIXTURE_WRITE_CAP","expiresAt":12345}""",
                isSuccess = true,
            ),
        )
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)
        assertNull(mgr.mintInbox())
    }

    // sendMessage_withWriteCap_attachesHeader lives in androidUnitTest —
    // it goes through aesGcmEncrypt, which on iOS routes via the Swift bridge
    // that isn't installed in KMP unit tests. The JVM/Android path uses Tink
    // directly so it works there. Headers + URL are protocol-layer assertions
    // not crypto-dependent; the rest of this class covers both targets.

    @Test
    fun sendMessage_nullWriteCap_refusesWithoutNetworkCall() {
        val vault = InMemoryVault()
        val contactId = "stale"
        seedContact(vault, contactId, withCaps = false)
        val http = RecordingRelayHttp()  // no scripted replies — any call would fail
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)

        val ok = mgr.sendMessage(contactId, "hello")

        assertEquals(false, ok)
        assertEquals(0, http.calls.size, "send must not touch the network for stale contacts")
    }

    @Test
    fun sendMessage_outboundPersistThrows_failsClosedNoCrash() {
        // Regression guard: iOS insertContact now throws on a vault
        // write failure (execChecked). The outbound counter persist in
        // sendMessage must fail CLOSED (return false) — never propagate the throw
        // (an uncaught Kotlin->Swift exception SIGABRTs the app) or post without a
        // persisted counter (which a later crash could reuse = replay).
        val inner = InMemoryVault()
        val contactId = "c-throw"
        seedContact(inner, contactId, withCaps = true)
        var failInsert = false
        val vault = object : VaultDatabase by inner {
            override fun insertContact(contact: ContactRecord): Long {
                if (failInsert) throw RuntimeException("simulated vault write failure")
                return inner.insertContact(contact)
            }
        }
        failInsert = true
        val http = RecordingRelayHttp()  // any network call would fail — must not happen
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)

        val ok = mgr.sendMessage(contactId, "hello")

        assertEquals(false, ok, "send must fail closed when the outbound counter persist throws")
        assertEquals(0, http.calls.size, "no network call when the counter persist fails")
    }

    @Test
    fun sendMessage_escapedEnvelopeOversize_refusesWithoutBumpingCounter() {
        // a payload whose RAW byte size passes the ceiling but
        // whose JSON-ESCAPED envelope overflows the pad cap must be rejected BEFORE the
        // anti-replay counter is bumped+persisted. Here 100k of `"` (each escaping to
        // `\"`, 2×) stays under the old `raw + 128 <= cap` check yet doubles past the
        // cap once escaped. Pre-fix the counter was bumped and the send then threw in
        // padMessage → spurious failure + a permanently burned counter. The pre-check
        // now probes the serialized envelope, so the send fails closed and the counter
        // never moves.
        val vault = InMemoryVault()
        val contactId = "c-oversize"
        seedContact(vault, contactId, withCaps = true)
        val http = RecordingRelayHttp()  // any network call would fail — must not happen
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)

        val payload = "\"".repeat(100_000)
        // Sanity: the payload's RAW size passes the OLD raw-bytes ceiling, so this
        // test genuinely exercises the escaped-vs-raw gap and not a trivial rejection.
        assertTrue(payload.encodeToByteArray().size <= MAX_PADDED_PAYLOAD_BYTES - 128)

        val ok = mgr.sendMessage(contactId, payload)

        assertEquals(false, ok, "escaped-oversize send must fail closed")
        assertEquals(0, http.calls.size, "no network call for an oversize message")
        assertEquals(
            0L,
            vault.getContact(contactId)?.outboundCounter,
            "counter must NOT advance when the send is rejected pre-flight (L9)",
        )
    }

    @Test
    fun sendMessage_contactDeletedMidSend_abortsWithoutResurrecting() {
        // If the contact is deleted between the snapshot at the top
        // of the send and the counter-persist re-read under the lock, the send must ABORT
        // — never fall back to the stale snapshot and insertContact it (which would
        // resurrect the deleted contact and re-persist its sharedSecret + alias). The
        // poll path shares the same guard (the actual ~60s window).
        val inner = InMemoryVault()
        val contactId = "c-del"
        seedContact(inner, contactId, withCaps = true)
        var getCount = 0
        var resurrected = false
        val vault = object : VaultDatabase by inner {
            override fun getContact(id: String): ContactRecord? {
                getCount++
                // Call 1 = the top-of-send snapshot (present); the locked re-read (call
                // 2) sees the row GONE, as if a concurrent delete landed in between.
                return if (getCount >= 2) null else inner.getContact(id)
            }
            override fun insertContact(contact: ContactRecord): Long {
                if (getCount >= 2) resurrected = true   // any write after the "delete" = resurrection
                return inner.insertContact(contact)
            }
        }
        val http = RecordingRelayHttp()  // any network call would fail — must not happen
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)

        val ok = mgr.sendMessage(contactId, "hi")

        assertEquals(false, ok, "send must abort when the contact is gone")
        assertEquals(0, http.calls.size, "no network for an aborted send")
        assertTrue(!resurrected, "a contact deleted mid-send must NOT be re-persisted (T2)")
    }

    @Test
    fun rotateCapability_rejectsControlChars_withoutNetworkCall() {
        // A new capability containing CRLF must be refused before
        // it is placed into an HTTP header (header injection) and without any
        // network call.
        val vault = InMemoryVault()
        val contactId = "c1"
        seedContact(vault, contactId, withCaps = true)
        val http = RecordingRelayHttp()  // any call would fail (no scripted reply)
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)

        @Suppress("DEPRECATION")
        assertEquals(false, mgr.rotateWriteCapabilityNonDurable(contactId, "newcap\r\nX-Inject: 1"))
        assertEquals(0, http.calls.size, "invalid cap must not touch the network")
    }

    @Test
    fun pollMessages_withReadCap_attachesHeader_andBackoffOn404() {
        val vault = InMemoryVault()
        val contactId = "c1"
        seedContact(vault, contactId, withCaps = true)
        val http = RecordingRelayHttp()
        // Auth-failure path: relay collapses NOT_FOUND/UNAUTHORIZED/LOCKED
        // into a single 404 "request rejected". Client backs off silently —
        // no retry, no self-heal (no signal to base one on under the new spec).
        http.script(HttpResult(code = 404, body = """{"error":"request rejected"}""", isSuccess = false))
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)

        val messages = mgr.pollMessages(contactId)

        assertEquals(0, messages.size)
        val call = http.calls.single()
        assertEquals("GET", call.method)
        // Retrieve-ack: every drain is the LEASING retrieve.
        assertEquals("http://relay.test/inbox/$FIXTURE_INBOX_ID?lease=1", call.url)
        assertEquals(FIXTURE_READ_CAP, call.headers["X-Read-Capability"])
        // Generic 404 must NOT trigger a register/retry — that pattern was
        // for the old X-Read-Secret protocol and no longer exists.
        assertEquals(1, http.calls.size, "no retry after 404 under capability protocol")
    }

    @Test
    fun pollMessages_nullReadCap_refusesWithoutNetworkCall() {
        val vault = InMemoryVault()
        val contactId = "stale"
        seedContact(vault, contactId, withCaps = false)
        val http = RecordingRelayHttp()
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)

        val messages = mgr.pollMessages(contactId)

        assertEquals(0, messages.size)
        assertEquals(0, http.calls.size, "poll must not touch the network for stale contacts")
    }

    @Test
    fun pollMessages_429_backsOffSilently() {
        val vault = InMemoryVault()
        val contactId = "c1"
        seedContact(vault, contactId, withCaps = true)
        val http = RecordingRelayHttp()
        http.script(HttpResult(code = 429, body = """{"error":"rate limited"}""", isSuccess = false))
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)

        val messages = mgr.pollMessages(contactId)

        assertEquals(0, messages.size)
        assertEquals(1, http.calls.size)
    }

    @Test
    fun contactNeedsRepair_flagsNullCaps() {
        val vault = InMemoryVault()
        seedContact(vault, "needs", withCaps = false)
        seedContact(vault, "ok",    withCaps = true)
        // Re-seed "ok" with a unique inbox so the inboxId PRIMARY-KEY-style
        // dedupe in the in-memory stub doesn't blow them away.
        vault.inboxes.removeAll { it.inboxId == FIXTURE_INBOX_ID || it.inboxId == FIXTURE_PEER_INBOX_ID }
        vault.insertInboxId(InboxIdRecord(
            inboxId = FIXTURE_INBOX_ID, contactId = "ok",
            createdAt = 1L, expiresAt = Long.MAX_VALUE,
            direction = "inbound", cap = FIXTURE_READ_CAP,
        ))
        vault.insertInboxId(InboxIdRecord(
            inboxId = FIXTURE_PEER_INBOX_ID, contactId = "ok",
            createdAt = 1L, expiresAt = Long.MAX_VALUE,
            direction = "outbound", cap = FIXTURE_WRITE_CAP,
        ))
        // "needs" has no rows now (we wiped them above). A contact with no
        // rows at all is also stale.
        assertTrue(contactNeedsRepair(vault, "needs"))
        assertEquals(false, contactNeedsRepair(vault, "ok"))
    }

    @Test
    fun contactNeedsRepair_flagsLegacyUuidInboxId() {
        val vault = InMemoryVault()
        vault.insertContact(ContactRecord(
            contactId = "legacy",
            sharedSecret = generateSecureRandom(32),
            trustLevel = 0, alias = "L", aliasLastRotated = 0L,
        ))
        vault.insertInboxId(InboxIdRecord(
            // UUID format — pre-migration row.
            inboxId = "550e8400-e29b-41d4-a716-446655440000",
            contactId = "legacy",
            createdAt = 1L, expiresAt = Long.MAX_VALUE,
            direction = "inbound",
            // Even WITH a cap, legacy ID alone makes the contact unusable.
            cap = FIXTURE_READ_CAP,
        ))
        vault.insertInboxId(InboxIdRecord(
            inboxId = "550e8400-e29b-41d4-a716-446655440001",
            contactId = "legacy",
            createdAt = 1L, expiresAt = Long.MAX_VALUE,
            direction = "outbound",
            cap = FIXTURE_WRITE_CAP,
        ))
        assertTrue(contactNeedsRepair(vault, "legacy"))
    }
}

// ---------------------------------------------------------------------------
// mintInboxPair — the shared sequential two-inbox mint (Android + iOS call the
// SAME function, so it is tested once here in commonMain).
// ---------------------------------------------------------------------------

private val PAIR_CHALLENGE_BODY = POW_CHALLENGE_BODY
private const val PAIR_MINT_SUCCESS_BODY =
    """{"inboxId":"$FIXTURE_INBOX_ID","readCapability":"$FIXTURE_READ_CAP","writeCapability":"$FIXTURE_WRITE_CAP","expiresAt":12345}"""

class MintInboxPairTest {

    @Test
    fun mintInboxPair_bothInboxesMintSequentially_returnsPair() = runTest {
        val http = PairMintRelayHttp()
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", http as RelayHttp)

        val pair = mgr.mintInboxPair()

        assertNotNull(pair)
        // Both inboxes minted successfully and parsed.
        assertEquals(FIXTURE_INBOX_ID, pair.main.inboxId)
        assertEquals(FIXTURE_READ_CAP, pair.main.readCapability)
        assertEquals(FIXTURE_WRITE_CAP, pair.main.writeCapability)
        assertEquals(FIXTURE_INBOX_ID, pair.ctl.inboxId)
        assertEquals(FIXTURE_WRITE_CAP, pair.ctl.writeCapability)
        // …and the GROUP inbox, minted the same way.
        assertNotNull(pair.grp)
        assertEquals(FIXTURE_INBOX_ID, pair.grp.inboxId)
        assertEquals(FIXTURE_WRITE_CAP, pair.grp.writeCapability)
        // Three inboxes, each a challenge fetch + a solution submit = 6 POSTs.
        assertEquals(6, http.postCount)
    }

    @Test
    fun mintInboxPair_whenAMintFails_returnsNull() = runTest {
        // The relay hands out challenges but rejects every submit with 507 (a
        // TERMINAL code — inbox limit reached), so each mintInbox returns null
        // and the pair collapses to null — the caller surfaces "Could not reach
        // the relay" identically on both platforms.
        val http = PairMintRelayHttp(
            submitReply = HttpResult(code = 507, body = """{"error":"inbox limit"}""", isSuccess = false),
        )
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", http as RelayHttp)

        assertNull(mgr.mintInboxPair())
    }

    @Test
    fun mintInbox_retriesTransientTransportDropThenSucceeds() = runTest {
        // The first submit is a dropped Tor round-trip (code <= 0); mintInbox
        // must retry the whole handshake and succeed on the next attempt rather
        // than failing pairing on one lost request.
        val http = MintingRelay(
            mintReply = { submit ->
                if (submit == 1) HttpResult(code = -1, body = null, isSuccess = false)
                else HttpResult(code = 201, body = PAIR_MINT_SUCCESS_BODY, isSuccess = true)
            },
            challengeBody = PAIR_CHALLENGE_BODY,
            onGet = { HttpResult(code = -1, body = "unused", isSuccess = false) },
        )
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", http as RelayHttp)

        val minted = mgr.mintInbox()
        assertNotNull(minted)
        assertEquals(FIXTURE_INBOX_ID, minted.inboxId)
    }
}
