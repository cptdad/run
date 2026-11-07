package com.vg.run

/**
 * The in-memory relay: per-inbox blob queues with the real relay's append /
 * peek / drain semantics, for tests where two managers (or one manager and a
 * hostile relay) exchange real envelopes.
 *
 * Models:
 *  - `POST /inbox/{id}` appends the body and answers [postReply];
 *  - `GET /inbox/{id}[?…]` DRAINS the queue into `{"blobs":["<b64>",…]}`;
 *  - `GET /inbox/{id}/peek` (only when [peek] is true) answers `{"pending":n}`
 *    and drains nothing; with [peek] false a peek url drains like a retrieve,
 *    which is what the older hand-written doubles did;
 *  - [strict] = an inbox it was never told about ([declare]) answers
 *    `404 {"error":"request rejected"}` on every route, which is exactly how a
 *    reaped inbox behaves; non-strict inboxes spring into being on first use;
 *  - [storePosts] false = every append is accepted and discarded (a recorder);
 *  - the hostile-relay primitives: [dropRatchetTo] (accept a ratchet append with
 *    2xx, then discard it — ratchet blobs are self-identifying on the wire),
 *    [withholdLast] / [inject] (serve a blob late, alone), [injectJunk],
 *    [throwOnGet] (a transport error on that inbox), [getDelayMs];
 *  - PUT answers [putReply], DELETE [deleteReply] (null = the interface default);
 *  - [nonInboxRoute]: a subclass hook for urls with no `/inbox/` segment (the
 *    `GET /` probe, `POST /inbox` mint, batch `POST /peek`); null = treat the
 *    url like any other, as the older doubles did.
 * Every POST is counted ([posts]) and logged ([posted]); [sawRatchetWire] is set
 * when any POST body carried the ratchet magic, dropped or not. State is
 * lock-guarded (the prime and the sweeps call in from several workers).
 *
 * Does NOT model: capabilities (any header is accepted), leases / retrieve-ack
 * (see [LeasingRelay]), the batch `/peek` route, the PoW mint
 * ([MintingRelay]), TTLs, or the relay's size and count limits.
 */
internal open class InboxQueueRelay(
    private val strict: Boolean = false,
    private val peek: Boolean = false,
    private val storePosts: Boolean = true,
    var postReply: HttpResult = HttpResult(200, "{}", true),
    var putReply: HttpResult = HttpResult(200, "{}", true),
    var deleteReply: HttpResult? = null,
) : RelayHttp {
    private val lock = SyncLock()
    private val queues = mutableMapOf<String, MutableList<String>>()   // inboxId -> base64 blobs
    private val postLog = mutableListOf<ByteArray>()
    private var ratchetSeen = false

    /** Inbox ids whose RATCHET appends are answered 2xx and then discarded. */
    val dropRatchetTo = mutableSetOf<String>()
    /** Inbox ids whose GET (peek or drain) throws, like a circuit dying mid-request. */
    val throwOnGet = mutableSetOf<String>()
    /** Per-inbox delay before a GET is served. */
    val getDelayMs = mutableMapOf<String, Long>()

    /** Every POST body so far, in order (copies), whatever its route. */
    val posted: List<ByteArray> get() = lock.withLock { postLog.toList() }
    val posts: Int get() = lock.withLock { postLog.size }
    val sawRatchetWire: Boolean get() = lock.withLock { ratchetSeen }

    /** A url with no `/inbox/{id}` segment: answer it here, or null to treat it as an inbox url. */
    protected open fun nonInboxRoute(method: String, url: String, body: ByteArray, headers: Map<String, String>): HttpResult? = null

    /** Tell a [strict] relay these inboxes exist (empty). */
    fun declare(vararg inboxIds: String) = lock.withLock {
        for (id in inboxIds) queues.getOrPut(id) { mutableListOf() }
        Unit
    }
    /** Queue an already-base64 blob. */
    fun queue(inboxId: String, blobB64: String) = lock.withLock {
        queues.getOrPut(inboxId) { mutableListOf() }.add(blobB64); Unit
    }
    /** Queue a raw blob (a withheld one served late, a hand-built envelope). */
    fun inject(inboxId: String, blob: ByteArray) = queue(inboxId, encodeBase64(blob))
    /** Queue a blob that is neither a valid ratchet wire nor a decryptable legacy envelope. */
    fun injectJunk(inboxId: String) = inject(inboxId, ByteArray(48) { (it * 3 + 11).toByte() })
    fun pending(inboxId: String): Int = pendingOrNull(inboxId) ?: 0
    /** The queue depth, or null for an inbox this relay does not know (never declared, or [forget]-reaped). */
    fun pendingOrNull(inboxId: String): Int? = lock.withLock { queues[inboxId]?.size }
    fun blobsIn(inboxId: String): List<ByteArray> = lock.withLock { queues[inboxId]?.map { decodeBase64(it) } ?: emptyList() }
    /** A hostile relay WITHHOLDS the newest blob on [inboxId] (to serve it later via [inject]). */
    fun withholdLast(inboxId: String): ByteArray = lock.withLock {
        val q = queues[inboxId]!!
        decodeBase64(q.removeAt(q.size - 1))
    }
    /** The relay REAPS an inbox: a [strict] relay answers 404 for it from now on. */
    fun forget(inboxId: String) = lock.withLock { queues.remove(inboxId); Unit }

    override fun post(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult {
        val ratchet = MessageManager.isRatchetWire(body)
        lock.withLock {
            postLog.add(body.copyOf())
            if (ratchet) ratchetSeen = true
            Unit
        }
        if (!url.contains("/inbox/")) nonInboxRoute("POST", url, body, headers)?.let { return it }
        val id = relayInboxIdOf(url)
        if (ratchet && id in dropRatchetTo) return postReply   // accepted, then discarded
        if (!storePosts) return postReply
        val known = lock.withLock {
            val q = if (strict) queues[id] else queues.getOrPut(id) { mutableListOf() }
            q?.add(encodeBase64(body)) != null
        }
        return if (known) postReply else REJECTED
    }

    override fun get(url: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult {
        if (!url.contains("/inbox/")) nonInboxRoute("GET", url, ByteArray(0), headers)?.let { return it }
        val id = relayInboxIdOf(url)
        lock.withLock { getDelayMs[id] }?.let { sleepMillis(it) }
        if (lock.withLock { id in throwOnGet }) throw IllegalStateException("circuit died")
        if (peek && url.substringBefore("?").endsWith("/peek")) {
            val n = lock.withLock { queues[id]?.size ?: if (strict) null else 0 } ?: return REJECTED
            return HttpResult(200, """{"pending":$n}""", true)
        }
        val blobs = lock.withLock {
            if (strict) queues[id]?.let { q -> q.toList().also { q.clear() } }
            else queues.remove(id) ?: emptyList()
        } ?: return REJECTED
        return HttpResult(200, blobs.joinToString(",", "{\"blobs\":[", "]}") { "\"$it\"" }, true)
    }

    override fun put(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult =
        putReply

    override fun delete(url: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult =
        deleteReply ?: super.delete(url, headers, timeoutSeconds)

    private companion object {
        val REJECTED = HttpResult(404, """{"error":"request rejected"}""", false)
    }
}
