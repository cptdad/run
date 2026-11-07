package com.vg.run

/**
 * The fixed-reply [RelayHttp] double: each verb answers through one lambda, and
 * every request is recorded in [requests] (always, before the lambda runs, so a
 * lambda that throws is still recorded).
 *
 * Defaults are the "warm relay" a real onion relay looks like with nothing to
 * say: POST / PUT `202 ""`, `GET` the by-design `404 "not found"` (a completed
 * round-trip), and DELETE the interface default (`-1`, fails closed). Use the
 * factories ([warm], [dead], [allVerbs], [throwing], and the
 * single-verb recorders [postOnly] / [getOnly] / [deleteOnly]) for the common shapes, or
 * pass lambdas; the lambdas are `var`, so a subclass can install stateful ones in
 * `init` (a flag that flips the relay from dead to warm, say).
 *
 * Models: the four verbs plus the defaulted overloads below the SOCKS-isolation
 * form — the suppressLog / cancelOnNewCircuit POSTs and the cancelOnNewCircuit /
 * first-byte GETs all land on [onPost] / [onGet] with their flags in the
 * [Request] — and [RelayHttp.cancelNewCircuitSensitive] via [onCancelNewCircuit].
 * The overrides are final, so a subclass cannot silently re-route one overload.
 *
 * Does NOT model: inbox state (use [InboxQueueRelay]), the PoW mint (use
 * [MintingRelay]), a per-call FIFO script (use [RecordingRelayHttp]), or SOCKS
 * isolation ([supportsSocksIsolation] stays false; the isolated GET reaches
 * [onGet] through the interface default). Thread-safe for recording only: the
 * lambdas run unlocked, exactly like a hand-written fake would.
 */
internal open class FakeRelayHttp(
    var onPost: (Request) -> HttpResult = { RELAY_OK_202 },
    var onPut: (Request) -> HttpResult = { RELAY_OK_202 },
    var onGet: (Request) -> HttpResult = { RELAY_WARM_404 },
    /** null = the [RelayHttp.delete] interface default (`-1`, fails closed). */
    var onDelete: ((Request) -> HttpResult)? = null,
    var onCancelNewCircuit: () -> Int = { 0 },
) : RelayHttp {

    /**
     * One recorded request. [body] is empty for GET / DELETE; [contentType] null there.
     * [firstByteTimeoutSeconds] is null unless the first-byte GET overload was used.
     */
    class Request(
        val method: String,
        val url: String,
        val body: ByteArray,
        val contentType: String?,
        val headers: Map<String, String>,
        val timeoutSeconds: Int,
        val suppressLog: Boolean = false,
        val cancelOnNewCircuit: Boolean = false,
        val firstByteTimeoutSeconds: Int? = null,
    ) {
        /** [body] as UTF-8 text (what a JSON-posting caller sent). */
        val bodyText: String get() = body.decodeToString()
    }

    private val lock = SyncLock()
    private val log = mutableListOf<Request>()

    /** Every request so far, in order (a snapshot). */
    val requests: List<Request> get() = lock.withLock { log.toList() }

    /** The requests of one verb ("POST", "PUT", "GET", "DELETE"), in order. */
    fun requestsOf(method: String): List<Request> = requests.filter { it.method == method }

    /** POST, PUT and GET all answer [result] (DELETE untouched). */
    fun answerPostPutGet(result: HttpResult) {
        onPost = { result }; onPut = { result }; onGet = { result }
    }

    /** Forget every request recorded so far (a test's "from here on" marker). */
    fun clearRequests() = lock.withLock { log.clear() }

    private fun record(r: Request): Request = r.also { lock.withLock { log.add(it) } }

    final override fun post(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult =
        onPost(record(Request("POST", url, body, contentType, headers, timeoutSeconds)))
    final override fun post(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int, suppressLog: Boolean): HttpResult =
        onPost(record(Request("POST", url, body, contentType, headers, timeoutSeconds, suppressLog = suppressLog)))
    final override fun post(
        url: String, body: ByteArray, contentType: String, headers: Map<String, String>,
        timeoutSeconds: Int, suppressLog: Boolean, cancelOnNewCircuit: Boolean,
    ): HttpResult =
        onPost(record(Request("POST", url, body, contentType, headers, timeoutSeconds, suppressLog, cancelOnNewCircuit)))
    final override fun put(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult =
        onPut(record(Request("PUT", url, body, contentType, headers, timeoutSeconds)))
    final override fun get(url: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult =
        onGet(record(Request("GET", url, ByteArray(0), null, headers, timeoutSeconds)))
    final override fun get(url: String, headers: Map<String, String>, timeoutSeconds: Int, cancelOnNewCircuit: Boolean): HttpResult =
        onGet(record(Request("GET", url, ByteArray(0), null, headers, timeoutSeconds, cancelOnNewCircuit = cancelOnNewCircuit)))
    final override fun get(url: String, headers: Map<String, String>, timeoutSeconds: Int, cancelOnNewCircuit: Boolean, firstByteTimeoutSeconds: Int): HttpResult =
        onGet(record(Request("GET", url, ByteArray(0), null, headers, timeoutSeconds, cancelOnNewCircuit = cancelOnNewCircuit, firstByteTimeoutSeconds = firstByteTimeoutSeconds)))
    final override fun delete(url: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult {
        val r = record(Request("DELETE", url, ByteArray(0), null, headers, timeoutSeconds))
        return onDelete?.invoke(r) ?: super.delete(url, headers, timeoutSeconds)
    }
    final override fun cancelNewCircuitSensitive(): Int = onCancelNewCircuit()

    companion object {
        /** POST / PUT `202`, GET the relay's by-design `404 "not found"` — a live relay. */
        fun warm() = FakeRelayHttp()

        /** POST / PUT / GET fail with [code] and [body] (no throw); DELETE stays the interface default. */
        fun dead(code: Int = -1, body: String? = "") =
            FakeRelayHttp().apply { answerPostPutGet(HttpResult(code = code, body = body, isSuccess = false)) }

        /** Every verb, DELETE included, answers [result]. */
        fun allVerbs(result: HttpResult) =
            FakeRelayHttp(onPost = { result }, onPut = { result }, onGet = { result }, onDelete = { result })

        /**
         * A relay the code under test ([label], e.g. "the debug log") may only POST to:
         * every POST is recorded and answered by [reply] (which may throw); PUT, GET and
         * DELETE throw `AssertionError("<label> must never <VERB>")`.
         */
        fun postOnly(label: String, reply: (Request) -> HttpResult) = FakeRelayHttp(
            onPost = reply, onPut = forbidden(label, "PUT"), onGet = forbidden(label, "GET"), onDelete = forbidden(label, "DELETE"),
        )

        /** [postOnly] for a GET-only caller (the rendezvous warm-up, say). */
        fun getOnly(label: String, reply: (Request) -> HttpResult) = FakeRelayHttp(
            onPost = forbidden(label, "POST"), onPut = forbidden(label, "PUT"), onGet = reply, onDelete = forbidden(label, "DELETE"),
        )

        /** [postOnly] for a DELETE-only caller (push deregistration, say). */
        fun deleteOnly(label: String, reply: (Request) -> HttpResult) = FakeRelayHttp(
            onPost = forbidden(label, "POST"), onPut = forbidden(label, "PUT"), onGet = forbidden(label, "GET"), onDelete = reply,
        )

        private fun forbidden(label: String, verb: String): (Request) -> HttpResult =
            { throw AssertionError("$label must never $verb") }

        /** POST / PUT / GET throw `IllegalStateException(message)`; DELETE stays the interface default. */
        fun throwing(message: String) = FakeRelayHttp(
            onPost = { throw IllegalStateException(message) },
            onPut = { throw IllegalStateException(message) },
            onGet = { throw IllegalStateException(message) },
        )
    }
}

/** `202 ""` — an accepted append / registration. */
internal val RELAY_OK_202 = HttpResult(code = 202, body = "", isSuccess = true)

/** `404 "not found"` — the relay's by-design answer to `GET /`, which proves it is up. */
internal val RELAY_WARM_404 = HttpResult(code = 404, body = "not found", isSuccess = false)

/** `-1 ""` — a transport failure (refused / broken stream), no throw. */
internal val RELAY_DEAD = HttpResult(code = -1, body = "", isSuccess = false)

/** `200 {"blobs":[]}` — an empty inbox drain. */
internal val RELAY_EMPTY_DRAIN = HttpResult(code = 200, body = """{"blobs":[]}""", isSuccess = true)

/** The inbox id in a relay url: `…/inbox/{id}[/route][?query]`. */
internal fun relayInboxIdOf(url: String): String =
    url.substringAfter("/inbox/").substringBefore("/").substringBefore("?")
