package com.vg.run

/**
 * The `/peek`-count [RelayHttp] double: `GET …/inbox/{id}/peek` answers
 * `200 {"pending":N}`, a bare `GET …/inbox/{id}` is the DESTRUCTIVE drain, and
 * every request is recorded by [FakeRelayHttp] (so `requests` / `requestsOf` work).
 *
 * Peek count, in this order: [reject] → `404 {"error":"request rejected"}`; a
 * declared control queue → its size; [textPending] → that count;
 * otherwise [unknownPending], or `404` with [notFoundBody] when that is null.
 *
 * Drain: runs [onControlDrain] once, then empties the control queue into
 * `200 {"blobs":[…]}`; an inbox with no queue answers [drainUnknown], or `404`
 * with [notFoundBody] when that is null. [reject] does not apply to a drain.
 *
 * [peekOnly] = every GET is a peek (the drain is not modelled), keyed by the
 * whole path segment after `/inbox/` — the shape of the peek-only doubles.
 * Otherwise the key is [relayInboxIdOf] (a drain's `?lease=1` is stripped).
 *
 * In-flight peeks are counted ([peakConcurrentPeeks]); [whilePeekInFlight] runs
 * while one is in flight (default: sleep [holdMs]). Subclasses override it,
 * [peekReply] or [drainReply] for an exotic shape. POST answers `202 ""`, PUT
 * [putReply], DELETE [deleteReply] (null = the interface default, `-1`).
 * Thread-safe: the maps are read and written under one lock (a test that
 * pre-fills [textPending] directly does so before the code under test runs).
 */
internal open class PeekCountRelay(
    protected val textPending: MutableMap<String, Int> = mutableMapOf(),
    reject: Set<String> = emptySet(),
    private val unknownPending: Int? = null,
    private val notFoundBody: String = RELAY_REJECTED_BODY,
    private val drainUnknown: HttpResult? = null,
    private val peekOnly: Boolean = false,
    private val holdMs: Long = 0L,
    putReply: HttpResult = RELAY_OK_202,
    deleteReply: HttpResult? = null,
) : FakeRelayHttp(onPut = { putReply }, onDelete = deleteReply?.let { r -> { _: FakeRelayHttp.Request -> r } }) {

    protected val lock = SyncLock()
    private val rejected = reject.toMutableSet()
    private val controlQueues = mutableMapOf<String, MutableList<String>>()
    private var inFlight = 0
    private var maxInFlight = 0

    /** Runs INSIDE the next control drain, once — models a concurrent sweep. */
    var onControlDrain: (() -> Unit)? = null

    init {
        onGet = { onGetRequest(it) }
    }

    fun queueControl(inboxId: String, blobB64: String) = lock.withLock {
        controlQueues.getOrPut(inboxId) { mutableListOf() }.add(blobB64); Unit
    }
    fun declareControlInbox(inboxId: String) = lock.withLock { controlQueues.getOrPut(inboxId) { mutableListOf() }; Unit }
    fun setTextPending(inboxId: String, n: Int) = lock.withLock { textPending[inboxId] = n; Unit }
    fun reject(inboxId: String) = lock.withLock { rejected.add(inboxId); Unit }

    /** The recorded GETs that were peeks / drains, in order. */
    fun peekRequests(): List<FakeRelayHttp.Request> = requestsOf("GET").filter { peekOnly || it.url.endsWith("/peek") }
    fun drainRequests(): List<FakeRelayHttp.Request> = requestsOf("GET").filter { !peekOnly && !it.url.endsWith("/peek") }
    val peakConcurrentPeeks: Int get() = lock.withLock { maxInFlight }
    protected val peeksInFlight: Int get() = lock.withLock { inFlight }

    /** Control-queue size, else the text count; null when neither is declared. */
    protected fun pendingOf(inboxId: String): Int? = lock.withLock { controlQueues[inboxId]?.size ?: textPending[inboxId] }

    protected open fun onGetRequest(r: FakeRelayHttp.Request): HttpResult {
        val id = if (peekOnly) r.url.substringAfter("/inbox/").substringBefore("/") else relayInboxIdOf(r.url)
        if (!peekOnly && !r.url.endsWith("/peek")) return drainReply(id)
        lock.withLock { inFlight++; if (inFlight > maxInFlight) maxInFlight = inFlight }
        try {
            whilePeekInFlight()
        } finally {
            lock.withLock { inFlight-- }
        }
        return peekReply(id)
    }

    protected open fun whilePeekInFlight() {
        if (holdMs > 0) sleepMillis(holdMs)
    }

    protected open fun peekReply(inboxId: String): HttpResult {
        if (lock.withLock { inboxId in rejected }) return HttpResult(code = 404, body = RELAY_REJECTED_BODY, isSuccess = false)
        val n = pendingOf(inboxId) ?: unknownPending
            ?: return HttpResult(code = 404, body = notFoundBody, isSuccess = false)
        return HttpResult(code = 200, body = """{"pending":$n}""", isSuccess = true)
    }

    protected open fun drainReply(inboxId: String): HttpResult {
        val hook = lock.withLock { onControlDrain.also { onControlDrain = null } }
        hook?.invoke()
        val blobs = lock.withLock {
            val q = controlQueues[inboxId] ?: return@withLock null
            val out = q.toList(); q.clear(); out
        } ?: return drainUnknown ?: HttpResult(code = 404, body = notFoundBody, isSuccess = false)
        return HttpResult(code = 200, body = """{"blobs":[${blobs.joinToString(",") { "\"$it\"" }}]}""", isSuccess = true)
    }
}

/** The relay's refusal body (bad capability, unknown inbox). */
internal const val RELAY_REJECTED_BODY = """{"error":"request rejected"}"""
