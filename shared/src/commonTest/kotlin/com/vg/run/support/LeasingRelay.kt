package com.vg.run

import kotlin.test.assertEquals
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// The retrieve-ack relay double and the two-device harness built on it (moved
// out of RetrieveAckTest so the drain / send characterisation suites share one
// copy).
//
// Models: the relay's LEASING drain (`GET /inbox/{id}?lease=1` →
// {"blobs":[…],"ids":[…],"token":"…"}, nothing deleted, the returned blobs hidden
// until `POST /ack` deletes the listed ids and releases the rest of that token),
// the pre-lease relay (`leasing = false`: the GET deletes at fetch and answers
// {"blobs":[…]} only), `GET /inbox/{id}/peek` ({"pending":<visible>}), appends
// (`POST /inbox/{id}` stores the body), a lost ack (`failAcks`: 500, nothing
// changes), lease expiry ([LeasingRelay.expireLeases]) and the relay's ack limits
// (≤ 64 items, ≤ 256 ids per item — asserted).
//
// Does NOT model: capabilities (any cap is accepted), TTLs, the PoW mint (use
// [MintingRelay]), the batch `POST /peek`, or rotation PUTs (always `200 {}`).
// ---------------------------------------------------------------------------

internal class LeasingRelay : RelayHttp {
    private class Entry(val id: String, val data: ByteArray) { var token: String? = null }
    class Ack(val inboxId: String, val token: String, val delete: List<String>)

    private val lock = SyncLock()
    private val store = mutableMapOf<String, MutableList<Entry>>()
    private var seq = 0
    val getUrls = mutableListOf<String>()
    val ackPosts = mutableListOf<List<Ack>>()
    // A lost ack: the POST is answered 500 and changes nothing.
    var failAcks = false
    // false = a relay that predates the lease: `?lease=1` is ignored, the GET deletes.
    var leasing = true
    // Runs at the start of every GET, before the answer is built (a test's
    // "something happens during the round trip" hook). Gets the url.
    var beforeGet: ((String) -> Unit)? = null

    private fun ref(): String { seq++; return ("z" + seq.toString()).padEnd(22, 'q') }
    private fun idOf(url: String) = url.substringAfter("/inbox/").substringBefore("/").substringBefore("?")

    fun deliver(inboxId: String, data: ByteArray): String = lock.withLock {
        val e = Entry(ref(), data.copyOf())
        store.getOrPut(inboxId) { mutableListOf() }.add(e)
        e.id
    }
    fun total(inboxId: String): Int = lock.withLock { store[inboxId]?.size ?: 0 }
    fun visible(inboxId: String): Int = lock.withLock { store[inboxId]?.count { it.token == null } ?: 0 }
    fun idsOf(inboxId: String): List<String> = lock.withLock { store[inboxId]?.map { it.id } ?: emptyList() }
    // The stored bytes of every blob of [inboxId], in arrival order.
    fun blobsOf(inboxId: String): List<ByteArray> = lock.withLock { store[inboxId]?.map { it.data.copyOf() } ?: emptyList() }
    // The lease ran out without an ack.
    fun expireLeases() = lock.withLock { store.values.forEach { l -> l.forEach { it.token = null } } }
    // The relay LOSES blob [id] of [inboxId] (a Tor-dropped send, a text that expired
    // on the relay): gone without an ack, never served again.
    fun withhold(inboxId: String, id: String) { lock.withLock { store[inboxId]?.removeAll { it.id == id } } }
    fun acksFor(inboxId: String): List<Ack> = lock.withLock { ackPosts.flatten().filter { it.inboxId == inboxId } }
    // Every id any ack so far asked the relay to delete for [inboxId], in order.
    fun ackedIds(inboxId: String): List<String> = acksFor(inboxId).flatMap { it.delete }

    override fun post(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult {
        if (url.endsWith("/ack")) return ack(body.decodeToString())
        if (!url.contains("/inbox/")) return HttpResult(404, """{"error":"no"}""", false)
        deliver(idOf(url), body)
        return HttpResult(200, "{}", true)
    }

    private fun ack(body: String): HttpResult {
        val items = parseObjectArrayField(body, "items", 64)!!.map { el ->
            Ack(firstStringFieldAnywhere(el, "id")!!, firstStringFieldAnywhere(el, "token")!!, parseStringArrayField(el, "delete")!!)
        }
        assertTrue(items.size <= 64, "the relay refuses more than 64 items")
        assertTrue(items.all { it.delete.size <= 256 }, "the relay refuses more than 256 ids per item")
        lock.withLock { ackPosts.add(items) }
        if (failAcks) return HttpResult(500, "", false)
        lock.withLock {
            for (it0 in items) {
                val q = store[it0.inboxId] ?: continue
                q.removeAll { it.id in it0.delete }
                q.forEach { if (it.token == it0.token) it.token = null }
            }
        }
        return HttpResult(200, """{"v":1,"results":[]}""", true)
    }

    override fun get(url: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult {
        beforeGet?.invoke(url)
        lock.withLock { getUrls.add(url) }
        val id = idOf(url)
        if (url.substringBefore("?").endsWith("/peek")) return HttpResult(200, """{"pending":${visible(id)}}""", true)
        return lock.withLock {
            val q = store.getOrPut(id) { mutableListOf() }
            val vis = q.filter { it.token == null }
            val blobs = vis.joinToString(",") { "\"${encodeBase64(it.data)}\"" }
            if (leasing && url.endsWith("?lease=1")) {
                val token = if (vis.isEmpty()) "" else ref()
                vis.forEach { it.token = token }
                HttpResult(200, """{"blobs":[$blobs],"ids":[${vis.joinToString(",") { "\"${it.id}\"" }}],"token":"$token"}""", true)
            } else {
                q.removeAll { it.token == null }
                HttpResult(200, """{"blobs":[$blobs]}""", true)
            }
        }
    }

    override fun put(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int) =
        HttpResult(200, "{}", true)
}

// Acks run synchronously on the calling thread (the production launcher is an IO
// coroutine), so a test can assert on them right after the drain returns.
internal fun MessageManager.syncAcks(): MessageManager = also { it.ackLauncher = { work -> work() } }

internal const val LA = "c1"
internal val LA_IN_A = "A".repeat(32)    // Alice inbound  / Bob outbound   (text)
internal val LA_IN_B = "B".repeat(32)    // Bob inbound    / Alice outbound (text)
internal val LA_CTL_A = "a".repeat(32)   // Alice inbound-ctl / Bob outbound-ctl
internal val LA_CTL_B = "b".repeat(32)   // Bob inbound-ctl   / Alice outbound-ctl
internal val LA_RCAP = "R".repeat(43)
internal val LA_WCAP_A = "W".repeat(43)
internal val LA_WCAP_B = "X".repeat(43)
internal val LA_GID = "G".repeat(32)
internal const val LA_HASH = "hash-1"
internal val LA_ROSTER = """{"n":"crew","ep":2,"adm":"m1","mem":[]}"""

// Alice and Bob paired over one [LeasingRelay] (text + control inbox pair each, no
// group inbox). [ratchet] = true engages and MATURES the text ratchet (4 round
// trips; Alice's `dr-rxlock` armed). [alice] can be a decorated vault (a failing
// insert, a counting wrapper). Every manager acks synchronously.
internal class LaHarness(ratchet: Boolean, val alice: InMemoryVault = InMemoryVault()) {
    val relay = LeasingRelay()
    val secret = generateSecureRandom(32)
    val bob = InMemoryVault()
    var aliceMgr = MessageManager(alice, "http://relay.test", relay).syncAcks()
    val bobMgr = MessageManager(bob, "http://relay.test", relay).syncAcks()

    init {
        provision(alice, LA_IN_A, LA_IN_B, LA_CTL_A, LA_CTL_B, LA_WCAP_B)
        provision(bob, LA_IN_B, LA_IN_A, LA_CTL_B, LA_CTL_A, LA_WCAP_A)
        if (ratchet) {
            MessageManager.markRatchetCapable(alice, LA)
            MessageManager.markRatchetCapable(bob, LA)
            repeat(4) { i ->
                assertTrue(aliceMgr.sendMessage(LA, "a$i"))
                assertEquals(listOf("a$i"), bobMgr.pollMessages(LA).map { it.text })
                assertTrue(bobMgr.sendMessage(LA, "b$i"))
                assertEquals(listOf("b$i"), aliceMgr.pollMessages(LA).map { it.text })
            }
            assertEquals("1", alice.getMeta(MessageManager.drRecvLockKey(LA)), "precondition: the ratchet is mature")
        }
        relay.ackPosts.clear()
    }

    private fun provision(v: InMemoryVault, inText: String, outText: String, inCtl: String, outCtl: String, peerWcap: String) {
        v.insertContact(ContactRecord(contactId = LA, sharedSecret = secret, trustLevel = 0, alias = "p", aliasLastRotated = 0))
        v.insertInboxId(InboxIdRecord(inText, LA, 0L, Long.MAX_VALUE, "inbound", LA_RCAP))
        v.insertInboxId(InboxIdRecord(outText, LA, 0L, Long.MAX_VALUE, "outbound", peerWcap))
        v.insertInboxId(InboxIdRecord(inCtl, LA, 0L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_CTL, LA_RCAP))
        v.insertInboxId(InboxIdRecord(outCtl, LA, 0L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, peerWcap))
    }

    fun ratchetState(): String? = alice.getMeta("dr/$LA/text")
    fun textBaseline(): Long = alice.getContact(LA)!!.inboundCounter
    fun ctlBaseline(): Long = alice.getContact(LA)!!.inboundCtlCounter

    // A session teardown + the next session on the same vault.
    fun newSession() {
        aliceMgr.scrubInMemory()
        aliceMgr = MessageManager(alice, "http://relay.test", relay).syncAcks()
    }
}
