package com.vg.run

import kotlinx.coroutines.withContext

// ---------------------------------------------------------------------------
// RelayWarmup — the PRE-UNLOCK rendezvous warm-up (lever 1, 2026-09-11).
//
// Cold connect time is Tor bootstrap + onion RENDEZVOUS + one HTTP round trip,
// and the rendezvous is the dominant, most variable phase: a v3 hidden-service
// descriptor is NEVER cached on disk by Tor, so every process re-fetches one
// (HSDir fetch -> intro circuit || rendezvous circuit -> first stream). Tor's
// "Bootstrapped 100%" says nothing about it.
//
// Android already bootstraps Tor speculatively while the user types their
// credential (RunViewModel.startSpeculativeTor), but the rendezvous only began
// after unlock, because the only thing that talks to the relay is the health
// probe on MessageManager — and a MessageManager needs an OPEN VAULT. Nothing
// about a bare `GET /` does: it carries no capability, no auth header and names
// no inbox. So the object graph, not the crypto, was holding the rendezvous
// behind the PIN screen.
//
// This is that one request, issued the moment the speculative Tor reports
// Connected and while no vault is open. Tor keeps the resulting rendezvous
// circuit reusable for MaxCircuitDirtiness (10 min), so the session's real
// probe — built at unlock, unchanged — rides an already-established circuit and
// answers in ~1 RTT.
//
// Rules, and none of them may be relaxed:
//  - NO capability, NO auth, NO custom headers, NO body. The exact same bare
//    `GET /` the health probe already issues (MessageManager.probeRelayReachable),
//    which is also the first request of every session today. The relay learns
//    nothing it does not already learn seconds later.
//  - NEVER through a MessageManager: it must be impossible for this path to
//    touch a vault, a counter, a ratchet or an inbox.
//  - [HTTP_TIMEOUT_SECONDS] per attempt, fire-and-forget, nothing persisted,
//    and AT MOST ONE retry — see [shouldRotateAndRetry] (2026-09-15). The
//    post-unlock probe is still the real signal and is untouched by this file.
//  - It does NOT latch MessageManager.hasCompletedRelayRoundTrip and therefore
//    does NOT reveal the contact list: the reveal gate stays tied to the
//    SESSION's own transport answering (contact_list_hidden_until_connected).
//  - Two ConnectionLog lines, fixed phrases plus one number, per that surface's
//    producer rule. The relay host/onion is NEVER logged (see [ConnectionLog]).
//
// Threat delta: zero new observables. The network already sees Tor bootstrap at
// launch on Android, and the relay already sees exactly one anonymous `GET /`
// per session; this moves that request a few seconds earlier in the same
// session. It does NOT run pre-unlock on a device whose launch-time wipe is
// pending — every wipe trigger runs strictly before the ViewModel that arms
// this exists (see RunViewModel.init).
// ---------------------------------------------------------------------------

object RelayWarmup {

    /**
     * Per-attempt transport budget. 25 s since 2026-09-15, down from the
     * original 60 s.
     *
     * 60 s was "generous because nobody is waiting on it", and the measurement
     * refuted the premise: in all three slow Android timelines of the
     * connect-time study the warm-up sat on a WEDGED rendezvous for its whole
     * 60 s budget and only then reported `WARMUP_FAILED` — by which time the
     * user had unlocked and was paying for the same wedge through the health
     * probe. The budget is the only thing that decides when the cheap self-heal
     * (one `SIGNAL NEWNYM` + one more attempt, see [shouldRotateAndRetry]) can
     * run, so a long budget was actively buying the slow path.
     *
     * 25 s and NOT lower: a genuinely cold first descriptor fetch + rendezvous
     * routinely needs longer than 10 s (the empirical floor
     * `MessageManager.SEND_COLD_TIMEOUT_SECONDS` is pinned against, and above
     * the cold health probe's own `HEALTH_HTTP_TIMEOUT_SECONDS`), and an
     * attempt that cannot finish a cold rendezvous would make every launch pay
     * a NEWNYM for work that was about to succeed. Two 25 s attempts also
     * fit inside the 60 s the single attempt used to occupy, so a slow unlock
     * still meets at most the same amount of warm-up in flight.
     */
    const val HTTP_TIMEOUT_SECONDS: Int = 25

    /**
     * At most ONE retry per Tor instance. The retry exists to use a FRESH
     * set of HS circuits after a `SIGNAL NEWNYM`, not to hammer: a second
     * rotation would be introduction-point hammering, and the post-unlock rungs
     * (the cold NEWNYM rung, then the stall ladder) own everything after that.
     */
    const val MAX_RETRIES: Int = 1

    /**
     * Slack when deciding whether a failed attempt burned its whole budget.
     * Two seconds, an order of magnitude below [HTTP_TIMEOUT_SECONDS]: the only
     * job of this number is to separate "sat on a wedged rendezvous until the
     * deadline" from "failed fast" (SOCKS refused, no route, the relay's own
     * socket error), and the two transports enforce their deadline with
     * different precision, so a tight 250 ms slack would misclassify a
     * legitimate timeout as a fast failure.
     */
    internal const val FULL_BUDGET_SLACK_MS: Long = 2_000L

    /**
     * Floor on the warm-up GET's own timeout after waiting for the descriptor race
     * ([RelayAddressRace.WARMUP_WAIT_MAX_MS] = 15 s at most, so 25 − 15 = 10 s is
     * also the common worst case): enough for intro + rendezvous on a cached
     * descriptor, which measured ~1 s once the descriptor was in.
     */
    const val RACE_MIN_GET_SECONDS: Int = 10

    /** Length of a v3 onion address (base32), without the `.onion` suffix. */
    internal const val V3_ONION_ADDRESS_LEN: Int = 56

    internal const val LINE_STARTED = "rendezvous warm-up started"
    internal const val LINE_FAILED = "rendezvous warm-up failed"

    /**
     * One warm-up attempt's outcome: whether the relay answered, and how long
     * the attempt took. The duration is what [shouldRotateAndRetry] classifies —
     * it is never logged as a number by itself beyond the existing
     * one-decimal-seconds panel line, and it names nothing.
     */
    data class Attempt(val answered: Boolean, val elapsedMs: Long)

    /**
     * Issues the one bare `GET {relayBaseUrl}/` and returns whether the relay
     * answered at all (any HTTP code, 404 included — the relay has no root
     * handler by design).
     *
     * Skips silently when there is no transport or no relay configured; callers
     * pass a nullable [http] precisely so "Tor is not up" needs no branch of
     * their own. Never throws.
     *
     * The GET is blocking, so it runs on [ioDispatcher]; the caller's scope
     * (lock / wipe / teardown) cancels the suspension. Note that cancelling
     * cannot abort a socket read already in flight — the bounded timeout is what
     * makes that residual finite, and the request carries nothing to leak.
     */
    suspend fun warm(http: RelayHttp?, relayBaseUrl: String): Boolean =
        warmAttempt(http, relayBaseUrl).answered

    /**
     * [warm] with the timing the rotate-and-retry ladder needs. Kept as the primitive (and
     * [warm] as the boolean wrapper) so no existing call site changes shape and
     * so the "did it burn its budget" classification has a real number to work
     * from instead of a second clock read at the call site.
     *
     * A skipped attempt — no transport, no relay — reports `elapsedMs = 0`,
     * which [shouldRotateAndRetry] rejects: nothing was tried, so there is
     * nothing to rotate away from.
     */
    suspend fun warmAttempt(http: RelayHttp?, relayBaseUrl: String): Attempt =
        warmAttempt(http, relayBaseUrl, RelayEndpoints.racingOrNull())

    /**
     * [warmAttempt] against an explicit descriptor [race] (null = none — the
     * single-address flow, unchanged). SEVERAL ONION ADDRESSES (2026-10-23): when
     * [relayBaseUrl] is one of [race]'s addresses and its race is still undecided,
     * the attempt first waits — at most [RelayAddressRace.WARMUP_WAIT_MAX_MS],
     * inside its own [HTTP_TIMEOUT_SECONDS] budget — for the first descriptor to
     * arrive, then sends its one GET to the WINNER, whose descriptor Tor already
     * holds. Without the wait the GET would queue on whichever address happened to
     * be slot 1, i.e. on exactly the stalled HSDir fetch the race exists to dodge.
     * The GET's own timeout is what is left of the budget, floored at
     * [RACE_MIN_GET_SECONDS]; [Attempt.elapsedMs] covers wait + GET, so the
     * full-budget classification is unchanged.
     */
    internal suspend fun warmAttempt(http: RelayHttp?, relayBaseUrl: String, race: RelayAddressRace?): Attempt {
        if (http == null || relayBaseUrl.isEmpty()) return Attempt(answered = false, elapsedMs = 0L)
        ConnectionLog.append(ConnectionLog.Kind.RELAY, LINE_STARTED, ConnectionLog.Code.WARMUP_STARTED)
        val startedAtMs = currentTimeMillis()
        var timeoutSeconds = HTTP_TIMEOUT_SECONDS
        var target = relayBaseUrl
        if (race != null) {
            val waitedMs = race.awaitWinner(relayBaseUrl, RelayAddressRace.WARMUP_WAIT_MAX_MS)
            if (waitedMs > 0) {
                timeoutSeconds = maxOf(RACE_MIN_GET_SECONDS, HTTP_TIMEOUT_SECONDS - ((waitedMs + 999) / 1000).toInt())
            }
            target = race.resolve(relayBaseUrl)
        }
        val answered = withContext(ioDispatcher) {
            try {
                // `code > 0` == "a real HTTP response", the same reachability
                // test probeRelayReachable uses. Both actuals map a transport
                // failure to code = -1 rather than throwing; the catch is
                // defence in depth (an iOS bridge-holder misregistration).
                http.get(warmUpUrl(target), timeoutSeconds = timeoutSeconds).code > 0
            } catch (_: Exception) {
                false
            }
        }
        val elapsedMs = currentTimeMillis() - startedAtMs
        ConnectionLog.append(
            ConnectionLog.Kind.RELAY,
            if (answered) "rendezvous warm-up done in ${formatSeconds(elapsedMs)} s" else LINE_FAILED,
            if (answered) ConnectionLog.Code.WARMUP_DONE else ConnectionLog.Code.WARMUP_FAILED,
        )
        return Attempt(answered = answered, elapsedMs = elapsedMs)
    }

    /**
     * THE ROTATE-AND-RETRY DECISION, shared by both platforms: should the caller spend one
     * cold-rung `SIGNAL NEWNYM` and run the warm-up once more?
     *
     * Three gates, and all three are about not wasting the rung:
     *  - the attempt must have FAILED (an answered warm-up is the whole point);
     *  - it must have burned (almost) its whole budget — a failure that came
     *    back fast is a broken transport, not a wedged introduction point, and
     *    NEWNYM cannot fix a broken transport (same reasoning as
     *    `MessageManager.isFullBudgetProbeTimeout`, which gates the post-unlock
     *    sibling of this rung);
     *  - at most [MAX_RETRIES] retries.
     *
     * The PER-SESSION NEWNYM BUDGET is deliberately NOT checked here: it lives
     * on the platform session ([EarlyNewnymLedger]: `RunViewModel.earlyNewnymLedger` /
     * `IosAppController.earlyNewnymLedger`, capped at
     * `MessageManager.EARLY_NEWNYM_MAX_FIRES`) because it is shared with the
     * post-unlock cold rung and must survive a transport re-wire. A caller that
     * gets `true` here still fires nothing if that budget is spent — and then
     * does not retry either, because a retry onto the SAME circuits would just
     * re-pay the budget for the identical wedge.
     *
     * Pure; unit-tested without a clock or a transport.
     */
    fun shouldRotateAndRetry(answered: Boolean, elapsedMs: Long, retriesUsed: Int): Boolean {
        if (answered) return false
        if (retriesUsed < 0 || retriesUsed >= MAX_RETRIES) return false
        return elapsedMs >= HTTP_TIMEOUT_SECONDS * 1_000L - FULL_BUDGET_SLACK_MS
    }

    /**
     * `{base}/` — the relay root. [RelayConfig.BASE_URL] is documented as
     * carrying no trailing slash; the trim keeps a misconfigured value from
     * producing a `//` request line.
     */
    internal fun warmUpUrl(relayBaseUrl: String): String = relayBaseUrl.trimEnd('/') + "/"

    /**
     * The v3 onion address inside [url] — 56 base32 chars, WITHOUT the `.onion`
     * suffix, which is the exact form Tor's control-port `HSFETCH` accepts
     * (`hs_address_is_valid`). Null for anything else.
     *
     * Host-level parsing, mirroring [hostIsOnion]: scheme, userinfo, port and
     * path/query/fragment are stripped, so a path containing ".onion" cannot
     * reach the control channel. The charset + length check is STRICT because
     * the result is written into a command on an AUTHENTICATED Tor control
     * socket — a value carrying CR/LF (or spaces) would be command injection
     * into that channel, not merely a failed fetch. The address is compiled in,
     * not attacker-supplied, so this is defence in depth.
     */
    internal fun v3OnionAddress(url: String): String? {
        val afterScheme = if (url.contains("://")) url.substringAfter("://") else url
        val authority = afterScheme
            .substringBefore("/").substringBefore("?").substringBefore("#")
        val host = authority.substringAfterLast("@").substringBefore(":").trimEnd('.').lowercase()
        if (!host.endsWith(".onion")) return null
        val address = host.removeSuffix(".onion")
        if (address.length != V3_ONION_ADDRESS_LEN) return null
        for (c in address) {
            val ok = (c in 'a'..'z') || (c in '2'..'7')
            if (!ok) return null
        }
        return address
    }
}
