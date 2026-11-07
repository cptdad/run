package com.vg.run

/**
 * THE relay PoW-challenge body, single-sourced for every test that drives a mint
 * ([MessageManager.mintInbox] / [MessageManager.mintInboxPair] / the referral
 * accept / the §1.6 group-inbox backfill). It was copy-pasted verbatim into five
 * files, so a relay-side change to the challenge shape would have had to be found
 * five times — and a test still passing against a stale shape is worse than one
 * that fails.
 *
 * `difficulty = 8` keeps every solve sub-millisecond; the nonce is a fixed,
 * valid base64url value.
 */
internal fun powChallengeBody(
    nonce: String = "AAECAwQFBgcICQoLDA0ODw",
    difficulty: Int = 8,
) = """{"error":"proof required","nonce":"$nonce","token":"opaque-token-xyz","difficulty":$difficulty,"ttlSeconds":120,"algorithm":"sha256","preimage":"nonce:counter"}"""

/** @see powChallengeBody — the default-parameter form, for the many call sites
 *  that need a constant rather than a call. */
internal val POW_CHALLENGE_BODY: String = powChallengeBody()

/** The bundle a successful mint returns in the shared fixtures (32-char id, 43-char caps). */
internal const val MINT_FIXTURE_SUCCESS_BODY =
    """{"inboxId":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYX","readCapability":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","writeCapability":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","expiresAt":12345}"""

/**
 * The PoW-mint [RelayHttp] double: replies by REQUEST SHAPE, never from a FIFO
 * script, so a dispatcher or ordering change cannot silently mis-script a case.
 *
 * Models the two-request mint handshake ([MessageManager.mintInbox] /
 * [MessageManager.mintInboxPair]): a POST without `X-PoW-Token` gets `400` with
 * [challengeBody]; a POST with it is the n-th SUBMIT (1-based) and gets
 * `mintReply(n)`, so "the second mint fails 507" is `mintReply = { n -> … }`.
 * When [onSend] is set, a POST whose url does not end in `/inbox` is an inbox
 * append and goes there instead (recorded in [sendUrls]); when it is null EVERY
 * POST is part of the mint handshake. GET answers [onGet] (default `404 "up"`,
 * so the mint warm gate passes at once), PUT [putReply], DELETE [deleteReply]
 * (null = the interface default, `-1`). Counters and logs are lock-guarded; the
 * reply lambdas run under the same lock, so they must not call back into it.
 *
 * Does NOT model: inbox queues or drains ([InboxQueueRelay]), the batch `/peek`,
 * PoW verification (any token is accepted), or the defaulted abort / first-byte
 * overloads beyond the interface's forwarding.
 */
internal open class MintingRelay(
    var mintReply: (submit: Int) -> HttpResult = { HttpResult(code = 201, body = MINT_FIXTURE_SUCCESS_BODY, isSuccess = true) },
    var challengeBody: String = POW_CHALLENGE_BODY,
    var onGet: (url: String) -> HttpResult = { HttpResult(code = 404, body = "up", isSuccess = false) },
    var putReply: HttpResult = HttpResult(code = -1, body = "unused", isSuccess = false),
    var deleteReply: HttpResult? = null,
    var onSend: ((url: String) -> HttpResult)? = null,
) : RelayHttp {
    private val lock = SyncLock()
    private var postN = 0
    private var mintPostN = 0
    private var submitN = 0
    private var getN = 0
    private val deleteLog = mutableListOf<Pair<String, Map<String, String>>>()
    private val sendLog = mutableListOf<String>()

    /** Every POST, mint or send. */
    val posts: Int get() = lock.withLock { postN }
    /** POSTs on the mint route (challenge + submit). */
    val mintPosts: Int get() = lock.withLock { mintPostN }
    /** Token-bearing mint POSTs, whatever [mintReply] answered. */
    val submits: Int get() = lock.withLock { submitN }
    val gets: Int get() = lock.withLock { getN }
    /** Each DELETE's url and headers, in order. */
    val deleteCalls: List<Pair<String, Map<String, String>>> get() = lock.withLock { deleteLog.toList() }
    /** Urls of the POSTs routed to [onSend]. */
    val sendUrls: List<String> get() = lock.withLock { sendLog.toList() }

    override fun post(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult =
        lock.withLock {
            postN++
            val send = onSend
            if (send != null && !url.endsWith("/inbox")) {
                sendLog.add(url)
                return@withLock send(url)
            }
            mintPostN++
            if (!headers.containsKey("X-PoW-Token")) return@withLock HttpResult(code = 400, body = challengeBody, isSuccess = false)
            submitN++
            mintReply(submitN)
        }

    override fun put(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult = putReply

    override fun get(url: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult {
        lock.withLock { getN++ }
        return onGet(url)
    }

    override fun delete(url: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult {
        lock.withLock { deleteLog.add(url to headers) }
        return deleteReply ?: super.delete(url, headers, timeoutSeconds)
    }
}

/**
 * Relay double for [MessageManager.mintInboxPair]: a token-less POST gets the
 * PoW challenge, a token-bearing POST gets [submitReply]; PUT `-1 "unused"`,
 * GET `404 "up"` (the mint warm gate passes at once), DELETE the interface
 * default. A named [MintingRelay] kept for its many call sites.
 */
internal class PairMintRelayHttp(
    submitReply: HttpResult = HttpResult(code = 201, body = MINT_FIXTURE_SUCCESS_BODY, isSuccess = true),
) : MintingRelay(mintReply = { submitReply }) {
    val postCount: Int get() = posts
}
