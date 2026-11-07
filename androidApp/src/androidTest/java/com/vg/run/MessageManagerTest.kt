package com.vg.run

import android.content.Context
import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented tests for [MessageManager].
 *
 * A [MockWebServer] acts as the relay server — it starts before each test and
 * shuts down after, giving every test a clean, isolated in-process HTTP server
 * with no external dependencies.
 *
 * The [InMemoryRelayDispatcher] implements the same POST/GET/DELETE semantics
 * as the real RelayServer (fetch-and-delete on GET, in-memory blob store) so
 * these tests exercise the full encrypt → relay → decrypt pipeline.
 *
 * Run with: ./gradlew connectedAndroidTest
 */
@RunWith(AndroidJUnit4::class)
class MessageManagerTest {

    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------

    companion object {
        private const val CONTACT_A_ID      = "contact-alice"
        private const val CONTACT_B_ID      = "contact-bob"
        // Capability protocol: inbox IDs are base64url-no-pad of 24 bytes (32
        // chars) and caps are base64url-no-pad of 32 bytes (43 chars). Built via
        // encodeBase64Url so they always satisfy isValidInboxId/isValidCapability
        // — the old canonical-UUID constants are rejected post-migration, and a
        // cap is now required on every inbox row (sendMessage/pollMessages
        // refuse rows with no cap).
        private val OUTBOX_A_ID  = encodeBase64Url(ByteArray(24) { 0x1A.toByte() })
        private val INBOX_A_ID   = encodeBase64Url(ByteArray(24) { 0x1B.toByte() })
        private val OUTBOX_B_ID  = encodeBase64Url(ByteArray(24) { 0x2A.toByte() })
        private val INBOX_B_ID   = encodeBase64Url(ByteArray(24) { 0x2B.toByte() })
        // Caps: the peer's write-cap on our outbound row; our own read-cap on inbound.
        private val WRITE_CAP_A  = encodeBase64Url(ByteArray(32) { 0x3A.toByte() })
        private val READ_CAP_A   = encodeBase64Url(ByteArray(32) { 0x3B.toByte() })
        private val WRITE_CAP_B  = encodeBase64Url(ByteArray(32) { 0x4A.toByte() })
        private val READ_CAP_B   = encodeBase64Url(ByteArray(32) { 0x4B.toByte() })

        private const val DB_NAME       = "run.db"
        private const val DB_KEY_PREFS  = "db_key_prefs"

        // Shared secrets — must be 32 bytes for AES-256 key derivation.
        // Different secrets per contact so AEAD contexts differ.
        private val SECRET_A = "alice-secret-32-bytes-padding!!".toByteArray(Charsets.UTF_8)  // 32 bytes
        private val SECRET_B = "bob---secret-32-bytes-padding!!".toByteArray(Charsets.UTF_8)  // 32 bytes
    }

    // -----------------------------------------------------------------------
    // Fields
    // -----------------------------------------------------------------------

    private lateinit var context: Context
    private lateinit var databaseManager: DatabaseManager
    private lateinit var messageManager: MessageManager
    private lateinit var mockServer: MockWebServer
    private lateinit var relayDispatcher: InMemoryRelayDispatcher

    // -----------------------------------------------------------------------
    // Setup / teardown
    // -----------------------------------------------------------------------

    @Before
    fun setUp() {
        context = InstrumentationRegistry.getInstrumentation().targetContext

        context.deleteDatabase(DB_NAME)
        context.deleteSharedPreferences(DB_KEY_PREFS)

        // CR-1: DatabaseManager takes the SQLCipher passphrase directly.
        // isProvision=true: setUp creates a fresh vault DB, so this is the provision
        // open, exempt from the unlock-path empty-vault guard (restart reopen stays false).
        databaseManager = DatabaseManager(context, ByteArray(32) { (it + 1).toByte() }, isProvision = true)

        val now    = System.currentTimeMillis()
        val expiry = now + 86_400_000L

        // Contacts with real 32-byte shared secrets — required for
        // AES-256-GCM key derivation in MessageManager.
        databaseManager.insertContact(ContactRecord(
            contactId        = CONTACT_A_ID,
            sharedSecret     = SECRET_A,
            trustLevel       = 1,
            alias            = "Alice",
            aliasLastRotated = now
        ))
        databaseManager.insertContact(ContactRecord(
            contactId        = CONTACT_B_ID,
            sharedSecret     = SECRET_B,
            trustLevel       = 1,
            alias            = "Bob",
            aliasLastRotated = now
        ))

        databaseManager.insertInboxId(InboxIdRecord(OUTBOX_A_ID, CONTACT_A_ID, now, expiry, "outbound", WRITE_CAP_A))
        databaseManager.insertInboxId(InboxIdRecord(INBOX_A_ID,  CONTACT_A_ID, now, expiry, "inbound",  READ_CAP_A))
        databaseManager.insertInboxId(InboxIdRecord(OUTBOX_B_ID, CONTACT_B_ID, now, expiry, "outbound", WRITE_CAP_B))
        databaseManager.insertInboxId(InboxIdRecord(INBOX_B_ID,  CONTACT_B_ID, now, expiry, "inbound",  READ_CAP_B))

        relayDispatcher = InMemoryRelayDispatcher()
        mockServer      = MockWebServer()
        mockServer.dispatcher = relayDispatcher
        mockServer.start()

        // MessageManager now takes (databaseManager, relayBaseUrl, httpClient).
        // Using PlatformHttpClient.direct() for tests (no Tor).
        messageManager = MessageManager(
            databaseManager = databaseManager,
            relayBaseUrl    = "http://${mockServer.hostName}:${mockServer.port}",
            httpClient      = PlatformHttpClient.direct()
        )
    }

    @After
    fun tearDown() {
        mockServer.shutdown()
        context.deleteDatabase(DB_NAME)
        context.deleteSharedPreferences(DB_KEY_PREFS)
    }

    // -----------------------------------------------------------------------
    // Test 1 — Full round-trip
    // -----------------------------------------------------------------------

    @Test
    fun sendAndPoll_roundTrip_returnsOriginalPlaintext() {
        val original = "Hello Bob, this is a secret message!"

        // A real peer posts to the inbox we poll, binding "di" to it; sendBlobs does a
        // genuine send and retargets "di" from our outbound row to our inbound row so the
        // blob is exactly what a real peer would deliver (see the sendBlobs note).
        val blobs = sendBlobs(original)
        assertEquals("exactly one blob must have been produced", 1, blobs.size)
        relayDispatcher.setInbox(INBOX_B_ID, blobs)

        val received = messageManager.pollMessages(CONTACT_B_ID)

        assertEquals("pollMessages must return exactly one message", 1, received.size)
        assertEquals("Decrypted text must exactly match the original plaintext", original, received[0].text)
    }

    // -----------------------------------------------------------------------
    // Test 2 — Wrong-contact AEAD context
    // -----------------------------------------------------------------------

    @Test
    fun pollMessages_withWrongContactContext_returnsEmpty() {
        // Encrypt for Alice (uses SHA-256(SECRET_A) as key).
        val sent = messageManager.sendMessage(CONTACT_A_ID, "secret only for Alice")
        assertTrue("sendMessage to Alice must succeed", sent)

        // Copy Alice's blob into Bob's inbound inbox.
        // Bob's pollMessages uses SHA-256(SECRET_B) as key — different key, decryption fails.
        relayDispatcher.copyInbox(OUTBOX_A_ID, INBOX_B_ID)

        val received = messageManager.pollMessages(CONTACT_B_ID)

        assertTrue(
            "A blob encrypted with Alice's secret must not decrypt with Bob's secret",
            received.isEmpty()
        )
    }

    // -----------------------------------------------------------------------
    // Test 3 — Empty inbox
    // -----------------------------------------------------------------------

    @Test
    fun pollMessages_withEmptyInbox_returnsEmptyListWithoutCrashing() {
        val received = messageManager.pollMessages(CONTACT_B_ID)

        assertNotNull("pollMessages must never return null", received)
        assertTrue("pollMessages must return an empty list for an empty inbox", received.isEmpty())
    }

    // -----------------------------------------------------------------------
    // Replay / reorder / drop protection
    // -----------------------------------------------------------------------

    // A real peer's OUTBOUND inbox for us IS our INBOUND inbox, so it seals every blob's
    // AEAD-bound "di" (destination-inbox) to that shared id and we accept it. A single
    // DatabaseManager can't reproduce that: inbox_ids.inboxId is a GLOBAL PRIMARY KEY (our
    // outbound and inbound rows must therefore have DISTINCT ids) and DatabaseManager's db
    // file name is a fixed const (no second "peer" DB is possible on one device). So the
    // old copyInbox(OUTBOX→INBOX) loopback is exactly the outbound→inbound reflection the
    // "di" defense (MessageManager.kt:1785-1795) now rejects — every receive dropped.
    //
    // We SYNTHESISE the peer's blob instead: do a GENUINE send (real shared-secret epoch,
    // real monotonic counter, ch="m", di=OUTBOX_B_ID), then retarget ONLY "di" from our
    // outbound id to the inbound id we actually poll. Everything the receive path
    // authenticates (AEAD key, epoch, counter, channel) stays genuine — this is byte-for-
    // byte the blob a real peer would have posted to our inbox. The di value and the id we
    // retarget to are both encodeBase64Url(24 bytes) = 32 chars, so the rewritten envelope
    // is length-identical and re-pads to the same bucket.

    /** Genuine sends of [texts] to CONTACT_B, captured and di-retargeted to our inbound
     *  inbox — i.e. the blobs a real peer would have delivered, in send order. [secret]
     *  must be the contact's CURRENT shared secret (it changes across a re-pair). */
    private fun sendBlobs(vararg texts: String, secret: ByteArray = SECRET_B): List<String> {
        texts.forEach {
            assertTrue("real send must be accepted by the relay",
                messageManager.sendMessage(CONTACT_B_ID, it))
        }
        val captured = relayDispatcher.snapshot(OUTBOX_B_ID)
        relayDispatcher.setInbox(OUTBOX_B_ID, emptyList())  // don't let these bleed into a later capture
        return captured.map { rebindDi(it, from = OUTBOX_B_ID, to = INBOX_B_ID, secret = secret) }
    }

    /** Decrypt [base64Blob] under CONTACT_B's message key, rewrite the AEAD-sealed "di"
     *  from [from] to [to], and re-seal. Uses only the public crypto the app itself uses;
     *  no envelope field other than "di" is touched. */
    private fun rebindDi(base64Blob: String, from: String, to: String, secret: ByteArray): String {
        val key  = sha256(secret)
        val aead = sha256(key + "message-aead".encodeToByteArray())
        val json = unpadMessage(aesGcmDecrypt(decodeBase64(base64Blob), key, aead)).decodeToString()
        val rebound = json.replace("\"di\":\"$from\"", "\"di\":\"$to\"")
        assertTrue("captured envelope must carry the outbound di to rebind", rebound != json)
        return encodeBase64(aesGcmEncrypt(padMessage(rebound.encodeToByteArray()), key, aead))
    }

    @Test
    fun replayedBlob_isDropped() {
        val blobs = sendBlobs("m1")
        relayDispatcher.setInbox(INBOX_B_ID, blobs)

        val first = messageManager.pollMessages(CONTACT_B_ID)
        assertEquals(1, first.size)
        assertEquals("m1", first[0].text)
        assertEquals(1L, first[0].counter)

        // Hostile relay re-serves the identical blob.
        relayDispatcher.setInbox(INBOX_B_ID, blobs)
        assertTrue("a replayed blob must be dropped",
            messageManager.pollMessages(CONTACT_B_ID).isEmpty())
    }

    @Test
    fun reorderedOlderBlob_isDropped() {
        val blobs = sendBlobs("m1", "m2")            // [b1, b2], counters 1,2
        relayDispatcher.setInbox(INBOX_B_ID, blobs)
        assertEquals(2, messageManager.pollMessages(CONTACT_B_ID).size)  // lastSeen = 2

        // Relay re-serves only the older message (counter 1 <= 2).
        relayDispatcher.setInbox(INBOX_B_ID, listOf(blobs[0]))
        assertTrue("a reordered-older blob must be dropped",
            messageManager.pollMessages(CONTACT_B_ID).isEmpty())
    }

    @Test
    fun reorderedWithinSingleDrain_bothDelivered() {
        // A hostile relay can serve blobs OUT OF ORDER within one drain. The
        // client must sort by counter before the strict-monotonic check, or the
        // lower-counter message looks like a replay of the higher one and is
        // permanently suppressed (in-drain reorder).
        val blobs = sendBlobs("m1", "m2")                       // counters 1, 2
        relayDispatcher.setInbox(INBOX_B_ID, listOf(blobs[1], blobs[0]))  // served 2,1
        val got = messageManager.pollMessages(CONTACT_B_ID)
        assertEquals("both messages delivered despite in-drain reorder", 2, got.size)
        assertEquals("m1", got[0].text); assertEquals(1L, got[0].counter)
        assertEquals("m2", got[1].text); assertEquals(2L, got[1].counter)
    }

    @Test
    fun droppedMessage_flagsSequenceGap() {
        val blobs = sendBlobs("m1", "m2", "m3")      // counters 1,2,3
        // Relay drops m2; delivers m1 then m3.
        relayDispatcher.setInbox(INBOX_B_ID, listOf(blobs[0], blobs[2]))

        val got = messageManager.pollMessages(CONTACT_B_ID)
        assertEquals(2, got.size)
        assertEquals("m1", got[0].text)
        assertTrue("first accepted message has no gap", !got[0].sequenceGap)
        assertEquals("m3", got[1].text)
        assertTrue("a counter jump must flag a dropped-message gap", got[1].sequenceGap)
    }

    @Test
    fun legacyEnvelopeWithoutCounter_isDropped() {
        // A blob a hostile relay could craft/replay in the pre-#2 format
        // (no "c"/"e"). Encrypted exactly as the app would have, so AEAD
        // succeeds — only the missing counter must cause the drop.
        val key  = sha256(SECRET_B)
        val aead = sha256(key + "message-aead".encodeToByteArray())
        val legacy = """{"t":1700000000000,"m":"legacy replay"}"""
        val blob = aesGcmEncrypt(padMessage(legacy.encodeToByteArray()), key, aead)
        relayDispatcher.setInbox(INBOX_B_ID,
            listOf(Base64.encodeToString(blob, Base64.NO_WRAP)))

        assertTrue("a legacy no-counter envelope must be dropped (no downgrade)",
            messageManager.pollMessages(CONTACT_B_ID).isEmpty())
    }

    @Test
    fun replayState_persistsAcrossRestart() {
        val blobs = sendBlobs("m1")
        relayDispatcher.setInbox(INBOX_B_ID, blobs)
        assertEquals(1, messageManager.pollMessages(CONTACT_B_ID).size)

        // Simulate an app restart: fresh DatabaseManager + MessageManager
        // over the same persisted vault file.
        val restartedDb = DatabaseManager(context, ByteArray(32) { (it + 1).toByte() })
        val restartedMgr = MessageManager(
            databaseManager = restartedDb,
            relayBaseUrl    = "http://${mockServer.hostName}:${mockServer.port}",
            httpClient      = PlatformHttpClient.direct()
        )
        relayDispatcher.setInbox(INBOX_B_ID, blobs)   // relay replays after restart
        assertTrue("persisted replay state must survive a restart",
            restartedMgr.pollMessages(CONTACT_B_ID).isEmpty())
        restartedDb.close()
    }

    @Test
    fun epochChange_resetsCounterSpace() {
        val blobs = sendBlobs("m1", "m2")             // counters 1,2 under epoch E1
        relayDispatcher.setInbox(INBOX_B_ID, blobs)
        assertEquals(2, messageManager.pollMessages(CONTACT_B_ID).size)  // inboundCounter=2 @E1

        // Re-pair: new shared secret (new epoch), counter space reset.
        val now = System.currentTimeMillis()
        val newSecret = "bob---NEW-secret-32bytes-pad!!!".toByteArray(Charsets.UTF_8)
        databaseManager.insertContact(ContactRecord(
            contactId = CONTACT_B_ID,
            sharedSecret = newSecret,
            trustLevel = 1, alias = "Bob", aliasLastRotated = now,
            outboundCounter = 0, inboundCounter = 0, inboundEpoch = ""
        ))
        // Send under the NEW secret so the genuine blob carries the new epoch E2 (its di is
        // then retargeted to our inbound inbox exactly as for E1).
        val freshBlobs = sendBlobs("m1-new", secret = newSecret)   // counter 1 under epoch E2
        relayDispatcher.setInbox(INBOX_B_ID, freshBlobs)

        val got = messageManager.pollMessages(CONTACT_B_ID)
        assertEquals("a fresh low counter under a new epoch must be accepted", 1, got.size)
        assertEquals("m1-new", got[0].text)
    }
}

// ---------------------------------------------------------------------------
// InMemoryRelayDispatcher
// ---------------------------------------------------------------------------

private class InMemoryRelayDispatcher : Dispatcher() {

    private val store = mutableMapOf<String, MutableList<String>>()

    // Hostile-relay simulation: when true, GET serves blobs but
    // does NOT delete them, so the next poll re-serves the same blobs —
    // exactly the replay a compromised relay can mount.
    var hostileRetainOnRead = false

    /** Snapshot of an inbox's current blobs (capture for replay/reorder). */
    fun snapshot(inboxId: String): List<String> = store[inboxId]?.toList() ?: emptyList()

    /** Overwrite an inbox's blobs (inject replay / reordered / dropped set). */
    fun setInbox(inboxId: String, blobs: List<String>) {
        store[inboxId] = blobs.toMutableList()
    }

    override fun dispatch(request: RecordedRequest): MockResponse {
        val inboxId = request.path
            ?.substringAfterLast("/")
            ?.takeIf { it.isNotEmpty() }
            ?: return MockResponse().setResponseCode(400)

        return when (request.method) {
            "POST" -> {
                val bytes  = request.body.readByteArray()
                val base64 = Base64.encodeToString(bytes, Base64.NO_WRAP)
                store.getOrPut(inboxId) { mutableListOf() }.add(base64)

                MockResponse()
                    .setResponseCode(202)
                    .addHeader("Content-Type", "application/json")
                    .setBody("""{"stored":true}""")
            }

            "GET" -> {
                val blobs = if (hostileRetainOnRead) {
                    store[inboxId]?.toMutableList() ?: mutableListOf()
                } else {
                    store.remove(inboxId) ?: mutableListOf()
                }
                val json  = blobs.joinToString(
                    prefix    = """{"blobs":[""",
                    separator = ",",
                    postfix   = "]}"
                ) { "\"$it\"" }

                MockResponse()
                    .setResponseCode(200)
                    .addHeader("Content-Type", "application/json")
                    .setBody(json)
            }

            "DELETE" -> {
                store.remove(inboxId)
                MockResponse().setResponseCode(204)
            }

            else -> MockResponse().setResponseCode(405)
        }
    }

    fun copyInbox(fromInboxId: String, toInboxId: String) {
        val blobs = store[fromInboxId]?.toList() ?: return
        store.getOrPut(toInboxId) { mutableListOf() }.addAll(blobs)
    }
}
