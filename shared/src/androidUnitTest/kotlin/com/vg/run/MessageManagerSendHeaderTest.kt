package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Two concurrent sends to the SAME contact must be serialized so
 * POST order == counter order — otherwise the receiver's strict-monotonic rule drops the
 * lower-counter blob as a replay (permanent message loss). Uses real threads + Tink AES,
 * so it lives here, not in commonTest.
 */
class ConcurrentSendSerializationTest {

    @Test
    fun concurrentSameContactSends_neverOverlapPost() {
        val vault = InMemoryVault()
        val contactId = "c-serial"
        vault.insertContact(ContactRecord(contactId, generateSecureRandom(32), 1, "T", 0L))
        vault.insertInboxId(InboxIdRecord(
            inboxId = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX", contactId = contactId,
            createdAt = 1L, expiresAt = Long.MAX_VALUE, direction = "inbound", cap = "A".repeat(43),
        ))
        vault.insertInboxId(InboxIdRecord(
            inboxId = "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", contactId = contactId,
            createdAt = 1L, expiresAt = Long.MAX_VALUE, direction = "outbound", cap = "B".repeat(43),
        ))

        val gate = java.util.concurrent.CountDownLatch(1)          // released to let the 1st POST finish
        val firstEntered = java.util.concurrent.CountDownLatch(1)  // signals the 1st POST is in-flight
        val inPost = java.util.concurrent.atomic.AtomicInteger(0)
        val maxConcurrent = java.util.concurrent.atomic.AtomicInteger(0)
        val firstFlag = java.util.concurrent.atomic.AtomicBoolean(false)

        val http = object : RelayHttp {
            override fun post(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult {
                val cur = inPost.incrementAndGet()
                maxConcurrent.updateAndGet { if (cur > it) cur else it }
                // The first POST to enter holds the sendOrderLock (it's called from
                // inside sendEnvelope's critical section) until the gate is released,
                // giving the second thread every chance to overlap if the lock is absent.
                if (firstFlag.compareAndSet(false, true)) {
                    firstEntered.countDown()
                    gate.await(3, java.util.concurrent.TimeUnit.SECONDS)
                }
                inPost.decrementAndGet()
                return HttpResult(code = 200, body = null, isSuccess = true)
            }
            override fun put(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int) =
                HttpResult(code = -1, body = "x", isSuccess = false)
            override fun get(url: String, headers: Map<String, String>, timeoutSeconds: Int) =
                HttpResult(code = -1, body = "x", isSuccess = false)
        }
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)

        val okA = java.util.concurrent.atomic.AtomicBoolean(false)
        val okB = java.util.concurrent.atomic.AtomicBoolean(false)
        val tA = Thread { okA.set(mgr.sendMessage(contactId, "A")) }
        val tB = Thread { okB.set(mgr.sendMessage(contactId, "B")) }

        tA.start()
        firstEntered.await(3, java.util.concurrent.TimeUnit.SECONDS)  // A is in POST, holding the lock
        tB.start()
        Thread.sleep(400)          // B, if unlocked, would enter POST here → overlap
        gate.countDown()           // release A; B may now proceed
        tA.join(5_000); tB.join(5_000)

        assertEquals(1, maxConcurrent.get(),
            "sends to the same contact must serialize — never two POSTs in flight")
        assertTrue(okA.get() && okB.get(), "both sends must succeed")
    }
}

// ---------------------------------------------------------------------------
// Channel-tag drain ordering. These go through
// aesGcmEncrypt (Tink on the JVM/Android target) to build authentic legacy
// blobs, so they live here, not in commonTest — same reason as the send test
// above.
// ---------------------------------------------------------------------------
class ChannelTagDrainOrderingTest {
    private val readCap = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    private val inboundInboxId = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX"

    /** Deterministic contact so the derived epoch/key/AAD are reproducible here. */
    private fun seed(vault: InMemoryVault, contactId: String): ByteArray {
        val sharedSecret = ByteArray(32) { it.toByte() }
        vault.insertContact(ContactRecord(contactId, sharedSecret, 1, "T", 0L))
        vault.insertInboxId(InboxIdRecord(
            inboxId = inboundInboxId, contactId = contactId,
            createdAt = 1L, expiresAt = Long.MAX_VALUE,
            direction = "inbound", cap = readCap,
        ))
        return sharedSecret
    }

    /** Reproduces the wire format MessageManager seals on send + the relay base64s. */
    private fun sealBlob(sharedSecret: ByteArray, envelope: String): String {
        val key = sha256(sharedSecret)
        val aad = sha256(key + "message-aead".encodeToByteArray())
        return encodeBase64(aesGcmEncrypt(padMessage(envelope.encodeToByteArray()), key, aad))
    }

    private fun epochOf(sharedSecret: ByteArray): String =
        bytesToHex(sha256(sharedSecret + "msg-epoch".encodeToByteArray()).copyOfRange(0, 6))

    @Test
    fun upgradeDrain_taggedBeforeLegacy_keepsBothMessages() {
        // The one-time upgrade drain: this peer sends an OLD untagged blob (counter 1,
        // before channel tagging) and a NEW tagged blob (counter 2, after it). A hostile — or unlucky —
        // relay serves the TAGGED one FIRST. Pre-fix, seeing the tag flipped the
        // "peer tags channels" flag mid-drain, so the genuinely-legacy untagged blob
        // that arrived second was dropped as "missing tag from channel-tagging peer" — a
        // real message silently lost. The fix decides the flag for the whole drain
        // from persisted state up front, so BOTH are delivered.
        val vault = InMemoryVault()
        val contactId = "c-upgrade"
        val ss = seed(vault, contactId)
        val epoch = epochOf(ss)

        val untagged = sealBlob(ss, """{"e":"$epoch","c":1,"t":0,"m":"older"}""")
        val tagged   = sealBlob(ss, """{"e":"$epoch","c":2,"t":0,"ch":"m","m":"newer"}""")

        val http = RecordingRelayHttp()
        // Adversarial arrival order: tagged (newer) first, legacy (older) second.
        http.script(HttpResult(code = 200, body = """{"blobs":["$tagged","$untagged"]}""", isSuccess = true))
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)

        val msgs = mgr.pollMessages(contactId)

        assertEquals(2, msgs.size, "both the tagged and the genuinely-legacy untagged blob must be delivered")
        assertEquals(setOf("older", "newer"), msgs.map { it.text }.toSet())
        // The upgrade flag is persisted AFTER the drain, so the NEXT drain enforces it.
        assertEquals("1", vault.getMeta(MessageManager.channelTagSeenKey(contactId)))
    }

    @Test
    fun steadyState_untaggedFromKnownTaggingPeer_isDropped() {
        // SIBLING PATH (fix-sibling-path coverage): once the peer is KNOWN to tag
        // (flag already persisted from a prior drain), an untagged blob is a
        // downgrade / cross-channel splice and MUST still be dropped. The fix
        // relaxes only the ONE-TIME upgrade drain, never the enforced steady state.
        val vault = InMemoryVault()
        val contactId = "c-steady"
        val ss = seed(vault, contactId)
        vault.putMeta(MessageManager.channelTagSeenKey(contactId), "1")  // already upgraded
        val epoch = epochOf(ss)

        val untagged = sealBlob(ss, """{"e":"$epoch","c":1,"t":0,"m":"spliced"}""")
        val tagged   = sealBlob(ss, """{"e":"$epoch","c":2,"t":0,"ch":"m","m":"legit"}""")

        val http = RecordingRelayHttp()
        http.script(HttpResult(code = 200, body = """{"blobs":["$tagged","$untagged"]}""", isSuccess = true))
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)

        val msgs = mgr.pollMessages(contactId)

        assertEquals(1, msgs.size, "the untagged blob from an M2-capable peer must be dropped")
        assertEquals("legit", msgs.single().text)
    }
}

/**
 * Android-only piece of the MessageManager auth-matrix tests.
 *
 * This single case goes through `aesGcmEncrypt`, which on iOS is implemented
 * via the Swift bridge — that bridge isn't installed when running KMP unit
 * tests, so the test would always return false there. The JVM/Android target
 * uses Tink directly and works under unit tests.
 *
 * The rest of the auth-matrix lives in commonTest (`MessageManagerTest`) and
 * exercises both targets without touching crypto.
 */
class MessageManagerSendHeaderTest {

    @Test
    fun sendMessage_withWriteCap_attachesHeader() {
        val vault = InMemoryVault()
        val contactId = "c1"
        vault.insertContact(
            ContactRecord(
                contactId = contactId,
                sharedSecret = generateSecureRandom(32),
                trustLevel = 1,
                alias = "T",
                aliasLastRotated = 0L,
            )
        )
        val inboundInboxId = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX"
        val outboundInboxId = "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
        val readCap  = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        val writeCap = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        vault.insertInboxId(InboxIdRecord(
            inboxId = inboundInboxId, contactId = contactId,
            createdAt = 1L, expiresAt = Long.MAX_VALUE,
            direction = "inbound", cap = readCap,
        ))
        vault.insertInboxId(InboxIdRecord(
            inboxId = outboundInboxId, contactId = contactId,
            createdAt = 1L, expiresAt = Long.MAX_VALUE,
            direction = "outbound", cap = writeCap,
        ))

        val http = RecordingRelayHttp()
        http.script(HttpResult(code = 200, body = null, isSuccess = true))
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)

        val ok = mgr.sendMessage(contactId, "hello")

        assertTrue(ok, "sendMessage must succeed when the outbound writeCap is set")
        val call = http.calls.single()
        assertEquals("POST", call.method)
        assertEquals("http://relay.test/inbox/$outboundInboxId", call.url)
        assertEquals(writeCap, call.headers["X-Write-Capability"])
        // Read cap must NEVER be sent on a write path.
        assertNull(call.headers["X-Read-Capability"])
    }

    /**
     * docs/RELAY_SPEC.md (push): default sends (no [noPush] arg) must carry NO
     * `X-No-Push` header at all — byte-identical to pre-Phase-3 clients, not
     * merely "0" (a relay may only check header PRESENCE).
     */
    @Test
    fun sendMessage_defaultNoPush_omitsHeader() {
        val vault = InMemoryVault()
        val contactId = "c-nopush-default"
        vault.insertContact(
            ContactRecord(contactId, generateSecureRandom(32), 1, "T", 0L)
        )
        val outboundInboxId = "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
        val writeCap = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        vault.insertInboxId(InboxIdRecord(
            inboxId = outboundInboxId, contactId = contactId,
            createdAt = 1L, expiresAt = Long.MAX_VALUE,
            direction = "outbound", cap = writeCap,
        ))

        val http = RecordingRelayHttp()
        http.script(HttpResult(code = 200, body = null, isSuccess = true))
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)

        val ok = mgr.sendMessage(contactId, "hello")

        assertTrue(ok)
        val call = http.calls.single()
        assertEquals(writeCap, call.headers["X-Write-Capability"])
        assertNull(call.headers["X-No-Push"], "default send must not carry X-No-Push at all")
    }

    /**
     * docs/RELAY_SPEC.md (push) D.4: `noPush = true` must attach `X-No-Push: 1` on the
     * outbound POST /inbox append so the relay suppresses the contentless
     * wake-push it would otherwise enqueue for a registered destination inbox.
     */
    @Test
    fun sendMessage_noPushTrue_attachesSuppressionHeader() {
        val vault = InMemoryVault()
        val contactId = "c-nopush-true"
        vault.insertContact(
            ContactRecord(contactId, generateSecureRandom(32), 1, "T", 0L)
        )
        val outboundInboxId = "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
        val writeCap = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        vault.insertInboxId(InboxIdRecord(
            inboxId = outboundInboxId, contactId = contactId,
            createdAt = 1L, expiresAt = Long.MAX_VALUE,
            direction = "outbound", cap = writeCap,
        ))

        val http = RecordingRelayHttp()
        http.script(HttpResult(code = 200, body = null, isSuccess = true))
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)

        val ok = mgr.sendMessage(contactId, "hello", noPush = true)

        assertTrue(ok)
        val call = http.calls.single()
        assertEquals(writeCap, call.headers["X-Write-Capability"])
        assertEquals("1", call.headers["X-No-Push"])
    }

    /**
     * Regression: the outbound counter is derived+persisted from a FRESH
     * read INSIDE the per-contact lock, not from the snapshot taken at the top of
     * sendMessage. If a concurrent send advances the counter between that snapshot
     * and this send's persist, the whole-row upsert must NOT roll it back —
     * otherwise the two sends reuse a counter and the receiver drops the second as
     * a replay (silent message loss).
     *
     * We simulate the concurrent advance with a vault whose getContact returns the
     * seeded record on the first (snapshot) call and an advanced outboundCounter on
     * the locked re-read. Pre-fix, sendMessage computed counter = snapshot+1 and
     * wrote the snapshot back (clobbering the advance); post-fix it re-reads fresh,
     * so the persisted counter builds on the advanced value.
     */
    @Test
    fun sendMessage_outboundCounter_readFreshUnderLock_noClobber() {
        val inner = InMemoryVault()
        val contactId = "c-race"
        val outboundInboxId = "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
        val writeCap = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        inner.insertContact(
            ContactRecord(
                contactId = contactId,
                sharedSecret = generateSecureRandom(32),
                trustLevel = 1,
                alias = "T",
                aliasLastRotated = 0L,
                outboundCounter = 0L,
            )
        )
        inner.insertInboxId(InboxIdRecord(
            inboxId = outboundInboxId, contactId = contactId,
            createdAt = 1L, expiresAt = Long.MAX_VALUE,
            direction = "outbound", cap = writeCap,
        ))

        // A concurrent send is modelled as: the outbound counter has already been
        // advanced to 5 in the vault by the time this send re-reads under the lock.
        // getContact call #1 = sendMessage's initial snapshot (sees 0);
        // call #2 = the locked re-read (sees the advanced 5).
        val advancedTo = 5L
        val vault = object : VaultDatabase by inner {
            var getCount = 0
            override fun getContact(id: String): ContactRecord? {
                val c = inner.getContact(id) ?: return null
                getCount++
                return if (getCount >= 2) c.copy(outboundCounter = advancedTo) else c
            }
        }

        val http = RecordingRelayHttp()
        http.script(HttpResult(code = 200, body = null, isSuccess = true))
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)

        val ok = mgr.sendMessage(contactId, "hello")

        assertTrue(ok, "send must succeed")
        // Post-fix: persisted counter = advanced(5) + 1 = 6 (built on the fresh
        // value). Pre-fix it would have been snapshot(0) + 1 = 1, clobbering the
        // concurrent advance.
        assertEquals(
            6L,
            inner.getContact(contactId)!!.outboundCounter,
            "outbound counter must build on the fresh (advanced) value, not the stale snapshot",
        )
    }
}

// ---------------------------------------------------------------------------
// SR Finding 1: destination-inbox binding ("di"). A malicious/compromised relay
// can copy a blob the victim POSTed to its OUTBOUND inbox into the victim's
// INBOUND inbox; the separate inbound/outbound counter baselines let it pass the
// replay check, so the victim's own ciphertext is accepted (attribution spoof /
// self-echo DoS). The sender now seals the destination inbox id inside the AEAD;
// on receive it must equal the inbox we polled. Real Tink AES → androidUnitTest.
// ---------------------------------------------------------------------------
class InboxBindingDrainTest {
    private val readCap = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    private val inboundInboxId  = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX"   // the inbox we poll (our inbound)
    private val outboundInboxId = "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"    // our send-to inbox (a reflected blob's di)

    private fun seed(vault: InMemoryVault, contactId: String): ByteArray {
        val sharedSecret = ByteArray(32) { it.toByte() }
        vault.insertContact(ContactRecord(contactId, sharedSecret, 1, "T", 0L))
        vault.insertInboxId(InboxIdRecord(
            inboxId = inboundInboxId, contactId = contactId,
            createdAt = 1L, expiresAt = Long.MAX_VALUE, direction = "inbound", cap = readCap,
        ))
        return sharedSecret
    }

    /** Seals a blob with the SAME static key + AAD the receiver derives — the "di"
     *  binding lives INSIDE the envelope plaintext, so the AAD is unchanged (a legacy
     *  peer's blobs still decrypt). */
    private fun sealBlob(sharedSecret: ByteArray, envelope: String): String {
        val key = sha256(sharedSecret)
        val aad = sha256(key + "message-aead".encodeToByteArray())
        return encodeBase64(aesGcmEncrypt(padMessage(envelope.encodeToByteArray()), key, aad))
    }
    private fun epochOf(ss: ByteArray) = bytesToHex(sha256(ss + "msg-epoch".encodeToByteArray()).copyOfRange(0, 6))

    @Test
    fun boundBlobMatchingPolledInbox_isAccepted_andMarksPeerCapable() {
        val vault = InMemoryVault()
        val contactId = "c-di-ok"
        val ss = seed(vault, contactId)
        val epoch = epochOf(ss)
        val bound = sealBlob(ss, """{"e":"$epoch","c":1,"t":0,"ch":"m","di":"$inboundInboxId","m":"hi"}""")
        val http = RecordingRelayHttp()
        http.script(HttpResult(code = 200, body = """{"blobs":["$bound"]}""", isSuccess = true))
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)

        val msgs = mgr.pollMessages(contactId)

        assertEquals(1, msgs.size)
        assertEquals("hi", msgs.single().text)
        // A matching di marks the peer inbox-binding-capable → future drains ENFORCE it.
        assertEquals("1", vault.getMeta(MessageManager.inboxBoundSeenKey(contactId)))
    }

    @Test
    fun reflectedBlob_diNamesADifferentInbox_isDropped() {
        // The relay reflects our OWN outbound blob (di = our OUTBOUND inbox) onto our
        // INBOUND inbox. It decrypts (same key) and its counter passes the inbound
        // baseline, but the sealed di names a DIFFERENT inbox than the one we polled → drop.
        val vault = InMemoryVault()
        val contactId = "c-di-reflect"
        val ss = seed(vault, contactId)
        val epoch = epochOf(ss)
        val reflected = sealBlob(ss, """{"e":"$epoch","c":1,"t":0,"ch":"m","di":"$outboundInboxId","m":"reflected"}""")
        val http = RecordingRelayHttp()
        http.script(HttpResult(code = 200, body = """{"blobs":["$reflected"]}""", isSuccess = true))
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)

        val msgs = mgr.pollMessages(contactId)

        assertEquals(0, msgs.size, "a blob whose sealed di != the polled inbox is a cross-inbox reflection — dropped")
        // A reflected blob teaches us nothing: the capability marker stays unset.
        assertNull(vault.getMeta(MessageManager.inboxBoundSeenKey(contactId)))
    }

    @Test
    fun steadyState_diLessBlobFromBindingPeer_isDropped() {
        // Once the peer is KNOWN to bind (marker persisted from a prior drain), a di-less
        // blob is a downgrade / a reflected pre-binding blob and must still be dropped —
        // the enforced steady state, relaxed only during the one-time upgrade drain.
        val vault = InMemoryVault()
        val contactId = "c-di-steady"
        val ss = seed(vault, contactId)
        vault.putMeta(MessageManager.inboxBoundSeenKey(contactId), "1")
        val epoch = epochOf(ss)
        val bound  = sealBlob(ss, """{"e":"$epoch","c":2,"t":0,"ch":"m","di":"$inboundInboxId","m":"legit"}""")
        val diLess = sealBlob(ss, """{"e":"$epoch","c":1,"t":0,"ch":"m","m":"spliced"}""")
        val http = RecordingRelayHttp()
        http.script(HttpResult(code = 200, body = """{"blobs":["$bound","$diLess"]}""", isSuccess = true))
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)

        val msgs = mgr.pollMessages(contactId)

        assertEquals(1, msgs.size, "the di-less blob from a binding-capable peer must be dropped")
        assertEquals("legit", msgs.single().text)
    }

    @Test
    fun inboxAnnounce_namingOurOwnInboundInbox_isRejected() {
        // Defense-in-depth (control-channel half): the relay reflects our own inbox
        // announce back onto our inbound inbox. Absent the guard, applyInboxAnnounce would
        // repoint our OUTBOUND record at our OWN inbound inbox (self-echo DoS). The
        // reflected announce is sealed di-less (a pre-binding reflection) so it reaches
        // applyInboxAnnounce, where the self-inbox reject fires and the outbound is untouched.
        val vault = InMemoryVault()
        val contactId = "peer-b"
        val ss = seed(vault, contactId)   // gives us inbound = inboundInboxId
        // We already know the peer's real outbound inbox.
        vault.insertInboxId(InboxIdRecord(
            inboxId = outboundInboxId, contactId = contactId,
            createdAt = 1L, expiresAt = Long.MAX_VALUE, direction = "outbound", cap = "B".repeat(43),
        ))
        val epoch = epochOf(ss)
        // The reflected announce declares OUR OWN inbound inbox as the peer's inbox.
        val announceBody = """{"ib":"$inboundInboxId","wc":"${"G".repeat(43)}"}"""
        val env = """{"e":"$epoch","c":1,"t":0,"ch":"m","k":"inbox","b":${jsonEscapeString(announceBody)},"m":""}"""
        val blob = sealBlob(ss, env)
        val http = RecordingRelayHttp()
        http.script(HttpResult(code = 200, body = """{"blobs":["$blob"]}""", isSuccess = true))
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)

        mgr.pollMessages(contactId)

        // The outbound record must still point at the peer's REAL inbox, not our own.
        assertEquals(outboundInboxId, vault.getInboxIdForContact(contactId, "outbound")?.inboxId,
            "an announce naming our own inbound inbox is a reflection — the outbound target must be unchanged")
    }
}
