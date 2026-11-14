package com.vg.run

import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.sync.withPermit

// ---------------------------------------------------------------------------
// PushRegistration — opt-in contentless-push client plumbing
// (contract: docs/RELAY_SPEC.md). Registers/unregisters an inbox's APNs device token with
// the relay over an already-established [RelayHttp] transport (the iOS
// caller hands in a Tor-proxied client — see AppState.registerPushToken /
// unregisterPushToken).
//
// Lives in commonMain for the reason most of this file's siblings do: pure
// logic with no platform bridge needed, so it is commonTest-covered with a
// fake RelayHttp rather than only exercised on-device. Used by BOTH platforms
// in practice: iOS registers APNs tokens (`platform = "apns"`, the default —
// see AppState.registerPushToken/unregisterPushToken); Android registers FCM tokens
// (where Play Services is present) (`platform = "fcm"` — RunViewModel's
// refreshVendorPushRegistration, androidApp), and Android can also
// register a UnifiedPush WebPush endpoint (`platform = "unifiedpush"` —
// RunViewModel's refreshUnifiedPushRegistration). Nothing here is
// platform-specific; `"unifiedpush"` is simply never sent from iOS, where
// [NotificationLevel.UNIFIED_PUSH] stays a dead value.
//
// EVERY caller must source `readCap` from the OPEN VAULT. The read capability is
// the relay inbox OWNER capability (drain / delete-inbox / rotate both caps), so
// a copy kept anywhere a locked device can reach hands an AFU forensic image
// that authority — see NotificationPollStore (androidMain), which purges the legacy
// Android cap mirror that was deleted for this reason. iOS never had one: it sources
// refs from the open vault via IosAppController.currentInboundInboxRefs.
//
// Privacy (non-negotiable): CONTENTLESS. No message content,
// plaintext, or per-message metadata ever crosses this path. What the relay
// DOES learn (Trade-off, disclosed in the opt-in copy
// `notif_edu_vendor_deep`): the SET of inboxes registered under one vendor
// token — i.e. which inboxes belong to one device — keyed by an identifier
// Google/Apple can resolve. It is the transitive closure of "inboxId -> token"
// over every inbound + inbound-ctl inbox, not a single linkage.
// ---------------------------------------------------------------------------

object PushRegistration {
    private const val READ_CAP_HEADER = "X-Read-Capability"
    private const val CONTENT_TYPE = "application/json"

    // -----------------------------------------------------------------------
    // SEVERAL ONION ADDRESSES (follow-up to RelayAddressRace).
    //
    // Every push PUT/DELETE resolves its base URL AT REQUEST TIME through the
    // descriptor race ([RelayAddressRace.resolve]) — the same idiom
    // MessageManager uses — so a caller that captured `RelayConfig.BASE_URL`
    // once (a per-inbox loop, the opt-out's minutes-long backoff) follows the
    // session's current winner instead of dialing a slot whose descriptor fetch
    // may sit 50–120 s at a bad HSDir set. A URL that is not one of the relay's
    // configured addresses (every unit test) is used verbatim.
    //
    // A batch additionally waits — bounded by [RACE_WAIT_MAX_MS] — while a race
    // begun in the current Tor HS state is undecided
    // ([awaitRelayAddressDecided]): sending the first PUT to slot 1 before the
    // race decides would queue it on exactly the stalled fetch the race exists
    // to dodge, and the PUT is not one of the NEWNYM-sensitive requests a winner
    // switch aborts. One address: never waits, URL unchanged.
    // -----------------------------------------------------------------------

    /** Upper bound on [awaitRelayAddressDecided] — same as the warm-up's
     *  ([RelayAddressRace.WARMUP_WAIT_MAX_MS]); a healthy race decides in 0.5–2 s. */
    const val RACE_WAIT_MAX_MS: Long = RelayAddressRace.WARMUP_WAIT_MAX_MS
    private const val RACE_WAIT_STEP_MS: Long = 100L

    /**
     * The opt-out DELETE ladder's transport re-acquire: polls [get]
     * every [stepMs] for at most [maxMs] and returns the first non-null value, or
     * null when the bound runs out. A retry that finds NO transport is usually
     * Tor re-establishing after a network restore (chain:push Case A, a device
     * run: the ladder broke 6 s after the restore, leaving the
     * opt-out to the ~5 min sweep) — waiting a bounded moment keeps the ladder
     * alive across that gap. Suspends ([kotlinx.coroutines.delay]); never logs.
     */
    suspend fun <T : Any> awaitTransport(maxMs: Long, stepMs: Long = 1_000L, get: () -> T?): T? {
        get()?.let { return it }
        var waited = 0L
        while (waited < maxMs) {
            val step = minOf(stepMs, maxMs - waited)
            kotlinx.coroutines.delay(step)
            waited += step
            get()?.let { return it }
        }
        return null
    }

    /**
     * The opt-out ladder's BACKOFF (network-restore kick): sleeps
     * [backoffMs] unless [wakeEpoch] moves off [sinceEpoch] first — the platform
     * owner bumps it right after a network-restore kick reached Tor, so a ladder
     * parked in its 45 s backoff retries as soon as Tor has been told the network
     * is back instead of sitting out the rest of the wait. Capture [sinceEpoch]
     * BEFORE the pass that failed: a restore that landed during that pass wakes
     * the backoff at once. Returns true iff woken early. Never logs.
     */
    suspend fun awaitBackoffOrWake(
        backoffMs: Long,
        sinceEpoch: Long,
        wakeEpoch: kotlinx.coroutines.flow.StateFlow<Long>,
    ): Boolean {
        if (wakeEpoch.value != sinceEpoch) return true
        return kotlinx.coroutines.withTimeoutOrNull(backoffMs) {
            wakeEpoch.first { it != sinceEpoch }
            true
        } ?: false
    }

    /**
     * The opt-out ladder's AFTER-RESTORE extension: once a
     * network-restore kick has been seen, the ladder keeps retrying past its
     * normal passes until Tor has had this long to recover. Pixel 7, Case A:
     * the kick went out 8 s after the restore, the relay answered ~2m20s after
     * it, and the 4-pass ladder had already given up 2 min after it, leaving
     * the opt-out to the sweep.
     */
    const val DEREG_RESTORE_GRACE_MS: Long = 240_000L

    /** Backoff between the after-restore extension passes. */
    const val DEREG_RESTORE_BACKOFF_MS: Long = 15_000L

    /** Hard cap on the ladder's passes, extension included. */
    const val DEREG_MAX_PASSES: Int = 12

    /**
     * Whether the opt-out ladder runs another pass after [passesDone] passes:
     * always below [normalPasses]; past them only while [restoreSeenAtMs] (the
     * monotonic time the ladder last saw the restore epoch move, null = never)
     * is within [DEREG_RESTORE_GRACE_MS] of [nowMs], and never past
     * [DEREG_MAX_PASSES]. Both platforms' ladders call this.
     */
    fun continueDeregLadder(passesDone: Int, normalPasses: Int, nowMs: Long, restoreSeenAtMs: Long?): Boolean {
        if (passesDone < normalPasses) return true
        if (restoreSeenAtMs == null || passesDone >= DEREG_MAX_PASSES) return false
        return nowMs - restoreSeenAtMs < DEREG_RESTORE_GRACE_MS
    }

    /** Per-request budget of a push DEREGISTRATION. The relay
     *  answers a healthy DELETE in 1–3 s over Tor; a request still silent after
     *  this is on a dead circuit and is better failed and retried by the ladder
     *  than left to the transport's 60 s default (Case A: three sequential 60 s
     *  waits made one ladder pass take ~192 s). */
    const val DEREG_TIMEOUT_SECONDS: Int = 25

    /** DELETEs in flight at once — the registration fan-out's bound
     *  (RunViewModel.registerInboxesForCurrentSession uses the same 4). */
    const val DEREG_PARALLELISM: Int = 4

    /** The base URL a push request made NOW must use: [race]'s current winner
     *  when [relayBaseUrl] is one of its addresses, else [relayBaseUrl]. */
    internal fun requestBaseUrl(relayBaseUrl: String, race: RelayAddressRace?): String =
        race?.resolve(relayBaseUrl) ?: relayBaseUrl

    /**
     * BLOCKS (bounded by [maxMs]) while [race] is undecided for [relayBaseUrl]
     * ([RelayAddressRace.needsWait]); returns the milliseconds waited (0 without
     * sleeping when nothing is racing / the race is decided / [relayBaseUrl] is
     * not one of its addresses). Call ONCE at the start of a batch, off the main
     * thread (every caller runs on a detached Task / Dispatchers.IO and is about
     * to do blocking HTTP anyway). Logs a fixed phrase + a number only.
     */
    fun awaitRelayAddressDecided(
        relayBaseUrl: String,
        maxMs: Long = RACE_WAIT_MAX_MS,
        race: RelayAddressRace? = RelayEndpoints.racingOrNull(),
        sleep: (Long) -> Unit = ::sleepMillis,
    ): Long {
        if (race == null || maxMs <= 0) return 0L
        var waited = 0L
        while (waited < maxMs && race.needsWait(relayBaseUrl)) {
            val step = minOf(RACE_WAIT_STEP_MS, maxMs - waited)
            sleep(step)
            waited += step
        }
        if (waited > 0) platformLog("PushRegistration", "push request waited $waited ms for the relay address race")
        return waited
    }

    /**
     * `PUT /inbox/{id}/push` — registers [token] (hex APNs device token) as
     * the wake-push target for [inboxId], authenticated with THAT inbox's own
     * read capability (only the recipient — the read-cap holder — may
     * register). [env] is `"sandbox"` or `"production"`.
     * Idempotent upsert on the relay. Returns true on a 2xx; false on any
     * validation failure or transport error (fail-closed — a caller that
     * can't confirm registration should not claim push is active).
     *
     * [platform] defaults to `"apns"` (the only value ever sent before the
     * FCM tier existed) so every pre-existing caller — iOS's
     * `IosAppController.registerPushToken`/`registerRefs` included — is
     * byte-for-byte unchanged; a future Android/FCM caller passes
     * `"fcm"` explicitly.
     *
     * [p256dh]/[auth] are the RFC 8291 WebPush subscription keys, used ONLY by
     * `platform = "unifiedpush"` (where [token] carries the distributor's
     * endpoint URL rather than a device token). They are TRAILING and default
     * to null so every pre-existing apns/fcm call site is byte-identical, and
     * they are appended to the JSON body only when present — a 3-field apns
     * body stays exactly the 3 fields the relay has always parsed. Both keys
     * are required as a MATCHED PAIR: the relay cannot encrypt a wake with one
     * half, so a registration carrying only one is refused here rather than
     * accepted into a subscription that can never deliver.
     *
     * [badge] is an APNs-ONLY opt-in: when `true` AND
     * `platform == "apns"`, the body gains a trailing `"badge":true` field and
     * the relay pins a constant `aps.badge = 1` onto every contentless wake it
     * sends this registration — the client (AppState.swift) clears the badge
     * itself on unlock, so the relay's `1` is just "something is unread,"
     * never a real count. Defaults to `false` so every pre-existing call site
     * — Android's FCM/UnifiedPush registrations included — emits a
     * byte-identical body; a relay that predates this field ignores it, but
     * an OLD (pre-opt-in) relay is exactly why the default must stay `false`
     * rather than opportunistically true. Silently a no-op (no field emitted)
     * for `fcm`/`unifiedpush` — `aps.badge` is an APNs payload concept with no
     * FCM/WebPush analogue, so a caller passing `badge = true` on a non-apns
     * platform is treated the same as not passing it, rather than surfaced as
     * a validation failure.
     */
    fun register(
        http: RelayHttp,
        relayBaseUrl: String,
        inboxId: String,
        readCap: String,
        token: String,
        env: String,
        platform: String = "apns",
        p256dh: String? = null,
        auth: String? = null,
        badge: Boolean = false,
        race: RelayAddressRace? = RelayEndpoints.racingOrNull(),
    ): Boolean {
        if (relayBaseUrl.isEmpty()) return false
        // Defense-in-depth (mirrors every other relay-call site in this
        // codebase): reject a malformed inbox id / cap / token / env BEFORE
        // any of it reaches a header or a JSON body — never let a corrupt or
        // adversarial value get as far as raw HTTP construction.
        if (!isValidInboxId(inboxId) || !isValidCapability(readCap)) {
            platformLogWarn("PushRegistration", "register refused: malformed inbox/cap")
            return false
        }
        val tokenEnvOk = when (platform) {
            "apns" -> isPlausibleApnsToken(token) && (env == "sandbox" || env == "production") &&
                p256dh == null && auth == null
            // FCM tokens are NOT APNs-shaped (not 64-hex) and carry no
            // sandbox/production env — validate shape only; env is ignored.
            "fcm" -> isPlausibleFcmToken(token) && p256dh == null && auth == null
            // UnifiedPush: [token] is the distributor's WebPush endpoint URL and
            // BOTH RFC 8291 subscription keys are mandatory (the relay encrypts
            // the wake to them — a subscription missing either is undeliverable).
            // The keys are platform-EXCLUSIVE: an apns/fcm registration carrying
            // them is refused above, mirroring the relay's own validator, so a
            // caller can never smuggle key material onto a vendor-push row.
            "unifiedpush" -> isPlausibleUnifiedPushEndpoint(token) &&
                isPlausibleWebPushEnv(env) &&
                p256dh != null && auth != null &&
                isPlausibleWebPushKey(p256dh, P256DH_MIN_CHARS, P256DH_MAX_CHARS) &&
                isPlausibleWebPushKey(auth, AUTH_SECRET_MIN_CHARS, AUTH_SECRET_MAX_CHARS)
            else -> false
        }
        if (!tokenEnvOk) {
            // NEVER interpolate [token] here: on the unifiedpush path it is the
            // endpoint URL, which names the user's distributor/push server.
            platformLogWarn("PushRegistration", "register refused: malformed token/env/keys (platform=$platform)")
            return false
        }
        val url = "${requestBaseUrl(relayBaseUrl, race)}/inbox/$inboxId/push"
        // Emitted ONLY when the caller opted in AND the platform is apns —
        // aps.badge has no fcm/unifiedpush analogue, so badge=true on those
        // platforms is a silent no-op rather than a body change. `false` (the
        // default for every pre-existing caller) never emits the field, so
        // the body stays byte-identical to what it has always been.
        val badgeField = if (badge && platform == "apns") ""","badge":true""" else ""
        // The two WebPush key fields are appended ONLY when present, so the
        // apns/fcm body stays byte-for-byte what it has always been (pinned by
        // PushRegistrationTest.register_putsExpectedUrlBodyAndReadCapHeader).
        val keyFields =
            if (p256dh != null && auth != null) {
                ""","p256dh":${jsonEscapeString(p256dh)},"auth":${jsonEscapeString(auth)}"""
            } else ""
        val body = """{"platform":${jsonEscapeString(platform)},"token":${jsonEscapeString(token)},"env":${jsonEscapeString(env)}$badgeField$keyFields}"""
        val result = try {
            http.put(url, body.encodeToByteArray(), CONTENT_TYPE, mapOf(READ_CAP_HEADER to readCap))
        } catch (e: Exception) {
            platformLogError("PushRegistration", "register failed: ${e::class.simpleName}")
            return false
        }
        if (!result.isSuccess) {
            platformLogWarn("PushRegistration", "register → ${result.code}")
        }
        return result.isSuccess
    }

    /**
     * A plausible FCM registration token: non-blank, within the relay's length
     * budget (MAX_PUSH_TOKEN_CHARS = 256), and free of whitespace / JSON-breaking
     * chars. FCM tokens are URL-safe-ish (alphanumerics + `:` / `-` / `_`), NOT
     * the 64-hex form [isPlausibleApnsToken] expects.
     */
    private fun isPlausibleFcmToken(token: String): Boolean =
        token.length in 20..256 &&
            token.none { it.isWhitespace() || it == '"' || it == '\\' }

    /**
     * `DELETE /inbox/{id}/push` — opt-out / vault-wipe path. The relay
     * returns 200 even when no token was registered, so
     * this simply reports transport success; there is no "already gone"
     * failure mode to special-case.
     */
    fun unregister(
        http: RelayHttp,
        relayBaseUrl: String,
        inboxId: String,
        readCap: String,
        race: RelayAddressRace? = RelayEndpoints.racingOrNull(),
        timeoutSeconds: Int = DEFAULT_RELAY_HTTP_TIMEOUT_SECONDS,
    ): Boolean {
        if (relayBaseUrl.isEmpty()) return false
        if (!isValidInboxId(inboxId) || !isValidCapability(readCap)) {
            platformLogWarn("PushRegistration", "unregister refused: malformed inbox/cap")
            return false
        }
        val url = "${requestBaseUrl(relayBaseUrl, race)}/inbox/$inboxId/push"
        val result = try {
            http.delete(url, mapOf(READ_CAP_HEADER to readCap), timeoutSeconds)
        } catch (e: Exception) {
            platformLogError("PushRegistration", "unregister failed: ${e::class.simpleName}")
            return false
        }
        if (!result.isSuccess) {
            platformLogWarn("PushRegistration", "unregister → ${result.code}")
        }
        return result.isSuccess
    }

    /**
     * One best-effort [unregister] pass over [refs], reporting the refs whose
     * DELETE did NOT succeed — so a caller can retry exactly those (the
     * in-session backoff loop) or persist a bare "still owed" boolean and
     * re-enumerate the open vault on a later session (the opt-out sweep).
     * Order-preserving; safe to repeat (the relay answers 200 even when no
     * push row exists — see [unregister]'s kdoc). Never throws: [unregister]
     * already folds transport exceptions and non-2xx into `false`, and a
     * malformed ref counts as a failure rather than surfacing — the same
     * fail-closed posture as every other relay-call site in this file.
     *
     * The shared core of the opt-out ladder (a slow-Tor DELETE once died
     * after one attempt, the result was swallowed, and the relay kept
     * dispatching contentless wakes for an opted-out device forever): BOTH
     * platforms' opt-out paths route through this
     * (`RunViewModel.unregisterPushInBackground` /
     * `sweepPendingPushDeregistration` on Android;
     * `IosAppController.unregisterPushInboxesReturningFailures` on iOS), so
     * the per-ref retry semantics cannot drift.
     */
    fun unregisterAllReturningFailures(
        http: RelayHttp,
        relayBaseUrl: String,
        refs: List<InboundInboxRef>,
        race: RelayAddressRace? = RelayEndpoints.racingOrNull(),
        sleep: (Long) -> Unit = ::sleepMillis,
        raceWaitMaxMs: Long = RACE_WAIT_MAX_MS,
    ): List<InboundInboxRef> {
        if (refs.isEmpty()) return emptyList()
        // Once per pass: never send the first DELETE into an undecided race. A
        // caller that already waited (a per-ref loop) passes raceWaitMaxMs = 0.
        if (relayBaseUrl.isNotEmpty()) awaitRelayAddressDecided(relayBaseUrl, raceWaitMaxMs, race, sleep)
        return refs.filter { ref ->
            val ok = try {
                unregister(http, relayBaseUrl, ref.inboxId, ref.readCap, race)
            } catch (_: Exception) {
                false
            }
            !ok
        }
    }

    /**
     * [unregisterAllReturningFailures], FAIL-FAST: every DELETE on
     * its own [timeoutSeconds] budget ([DEREG_TIMEOUT_SECONDS]), up to
     * [DEREG_PARALLELISM] in flight at once, so a pass over three inboxes on a
     * dead circuit costs ~25 s instead of the ~192 s three sequential 60 s
     * waits cost (chain:push Case A, measured on a device). Same contract:
     * order-preserving list of the refs that did NOT succeed; never throws.
     *
     * NON-CANCELLABLE, like the registration fan-out (dd1123a5): the children
     * must not observe the CALLER's cancellation — a settings modal closing or a
     * teardown would otherwise cancel DELETEs before they were sent and the
     * caller would read them as failures it never attempted. A pass is bounded
     * by its own timeouts, so it always ends; a cancelled caller resumes its own
     * cancellation at its next suspension point.
     */
    suspend fun unregisterAllParallelReturningFailures(
        http: RelayHttp,
        relayBaseUrl: String,
        refs: List<InboundInboxRef>,
        timeoutSeconds: Int = DEREG_TIMEOUT_SECONDS,
        race: RelayAddressRace? = RelayEndpoints.racingOrNull(),
        dispatcher: kotlinx.coroutines.CoroutineDispatcher = ioDispatcher,
        sleep: (Long) -> Unit = ::sleepMillis,
        raceWaitMaxMs: Long = RACE_WAIT_MAX_MS,
    ): List<InboundInboxRef> {
        if (refs.isEmpty()) return emptyList()
        return kotlinx.coroutines.withContext(kotlinx.coroutines.NonCancellable + dispatcher) {
            // Once per pass, as in the sequential form.
            if (relayBaseUrl.isNotEmpty()) awaitRelayAddressDecided(relayBaseUrl, raceWaitMaxMs, race, sleep)
            val gate = kotlinx.coroutines.sync.Semaphore(DEREG_PARALLELISM)
            val ok = refs.map { ref ->
                async {
                    gate.withPermit {
                        try {
                            unregister(http, relayBaseUrl, ref.inboxId, ref.readCap, race, timeoutSeconds)
                        } catch (_: Exception) {
                            false
                        }
                    }
                }
            }.awaitAll()
            refs.filterIndexed { i, _ -> !ok[i] }
        }
    }

    /**
     * [unregisterAllParallelReturningFailures] for a BLOCKING caller — iOS's
     * `IosAppController.unregisterPushInboxesReturningFailures`, called from a
     * detached Swift Task. Blocks the calling thread ([runBlockingIo]); never
     * from the main thread, never from inside another [runBlockingIo].
     */
    fun unregisterAllParallelReturningFailuresBlocking(
        http: RelayHttp,
        relayBaseUrl: String,
        refs: List<InboundInboxRef>,
        timeoutSeconds: Int = DEREG_TIMEOUT_SECONDS,
    ): List<InboundInboxRef> {
        if (refs.isEmpty()) return emptyList()
        return runBlockingIo { unregisterAllParallelReturningFailures(http, relayBaseUrl, refs, timeoutSeconds) }
    }

    /**
     * Bounds an APNs device token before it reaches a JSON body / log: hex
     * only. A real token is 64 hex chars (32-byte device token); the range
     * leaves slack for Apple lengthening the token format without this
     * becoming unbounded (an attacker-shaped "token" from a compromised
     * NotificationCenter delegate must still be rejected, not forwarded raw).
     */
    private fun isPlausibleApnsToken(token: String): Boolean =
        token.length in 16..256 && token.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }

    // -----------------------------------------------------------------------
    // UnifiedPush / RFC 8291 WebPush subscription-key bounds.
    //
    // Deliberately LOOSER than the relay's own validator (which pins p256dh to
    // an 87-88-char base64url encoding of a 65-byte uncompressed P-256 point
    // and the auth secret to 16 bytes). This side's job is the one every other
    // relay-call site in this file does: stop corrupt or adversarial material
    // before it reaches a JSON body or a log — NOT to be a second authority on
    // the exact encoding. Pinning the exact lengths here would mean a relay
    // that ever widened them could not be talked to by an already-shipped
    // client, and the failure mode would be a silent "push never registers".
    // The relay stays authoritative; a wrong-but-well-formed key just 400s.
    // -----------------------------------------------------------------------
    private const val P256DH_MIN_CHARS = 80
    private const val P256DH_MAX_CHARS = 128
    private const val AUTH_SECRET_MIN_CHARS = 16
    private const val AUTH_SECRET_MAX_CHARS = 64

    /** Base64url (RFC 4648 §5) with optional padding, length-bounded. */
    private fun isPlausibleWebPushKey(key: String, minChars: Int, maxChars: Int): Boolean =
        key.length in minChars..maxChars &&
            key.all { it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_' || it == '=' }

    /**
     * The relay bounds the unifiedpush `env` field at MAX_PUSH_ENV_CHARS = 32.
     * Unlike apns there is no fixed sandbox/production vocabulary, so validate
     * shape only — non-blank, bounded, and free of the whitespace / quote /
     * backslash that would break the JSON body or inject into a relay log line
     * (the same CRLF class `register_badEnv_refused` locks down for apns).
     */
    private fun isPlausibleWebPushEnv(env: String): Boolean =
        env.length in 1..32 && env.none { it.isWhitespace() || it == '"' || it == '\\' }
}

/**
 * Bounds a UnifiedPush distributor endpoint URL before it reaches a JSON body,
 * a log line, or the relay's own validator.
 *
 * **`https://` only** — matched to the relay side deliberately, and NOT
 * loosened for `.onion`. The relay reaches a push endpoint through a Tor
 * HTTP-CONNECT tunnel, which is CONNECT-only: a plain `http://` target (onion
 * or not) gets a 405 from the tunnel, so accepting one here would only manifest
 * as a subscription that silently never delivers. An `https://` onion address
 * passes this predicate and works.
 *
 * Length 16..1024 (the relay's `MAX_PUSH_ENDPOINT_CHARS`; 16 is below any real
 * endpoint but above the bare scheme, so an empty/stub value can't slip
 * through), and no whitespace / `"` / `\` — the same JSON-and-log-injection
 * bound [PushRegistration]'s token predicates apply, which additionally kills
 * the CRLF header-injection class.
 *
 * Public and pure so the Android UI/ViewModel layer can pre-screen an endpoint
 * the moment the distributor hands it over — before it is persisted — and so
 * this is commonTest-covered without a transport.
 */
fun isPlausibleUnifiedPushEndpoint(endpoint: String): Boolean =
    endpoint.length in 16..1024 &&
        endpoint.startsWith("https://") &&
        endpoint.none { it.isWhitespace() || it == '"' || it == '\\' }

/** One inbound inbox this device receives on, with the read capability
 *  needed to register/unregister it for push. */
data class InboundInboxRef(val inboxId: String, val readCap: String) {
    // Never let a stray log/interpolation print a live capability.
    override fun toString() = "InboundInboxRef(inboxId=${inboxId.take(8)}…, readCap=[redacted])"
}

/**
 * Shared enumeration core for [allInboundInboxes] / [allInboundTextInboxes]:
 * walks every contact and, for each requested [directions], pulls the
 * matching inbound [InboxIdRecord] and shapes it into an [InboundInboxRef].
 * Skips incomplete/malformed records (a pre-v7 peer with no control channel,
 * a stale row with an empty cap, or anything failing the same shape checks
 * every relay call site enforces) rather than surfacing a ref that would
 * fail [PushRegistration.register]/[unregister] anyway.
 */
private fun collectInboundInboxes(vault: VaultDatabase, directions: Array<String>): List<InboundInboxRef> {
    val out = mutableListOf<InboundInboxRef>()
    for (contact in vault.getAllContacts()) {
        for (direction in directions) {
            val rec = vault.getInboxIdForContact(contact.contactId, direction) ?: continue
            val cap = rec.cap
            if (!cap.isNullOrEmpty() && isValidInboxId(rec.inboxId) && isValidCapability(cap)) {
                out.add(InboundInboxRef(rec.inboxId, cap))
            }
        }
    }
    return out
}

/**
 * Enumerates every inbound inbox — main text (`"inbound"`) AND control
 * (`MessageManager.DIR_INBOUND_CTL`) — across every contact. This is the full
 * "receive" surface: the complete set of inbox rows whose READ (owner)
 * capability this device holds.
 *
 * Kept distinct from [allPushableInboxes] even though the two currently
 * enumerate the SAME two directions: this one answers "what do I own", that one
 * answers "what may the relay wake me for". A future receive-only direction
 * must not silently become push-registered by landing in one list.
 *
 * (The old kdoc cited an `AllInboundInboxesTest` that has never existed. The
 * both-main-and-control contract is actually pinned by
 * `ReferralEdgeCaseTest.ReferralPushSurfaceTest`.)
 */
fun allInboundInboxes(vault: VaultDatabase): List<InboundInboxRef> =
    collectInboundInboxes(
        vault,
        arrayOf("inbound", MessageManager.DIR_INBOUND_CTL, MessageManager.DIR_INBOUND_GRP),
    )

/**
 * Enumerates ONLY inbound TEXT inboxes (`"inbound"` direction) across every
 * contact — EXCLUDES control inboxes (`MessageManager.DIR_INBOUND_CTL`).
 *
 * **This is no longer the push-registration surface — [allPushableInboxes] is.**
 * The old exclusion rationale ("control traffic was never meant to wake the
 * user") was right about the TRAFFIC and wrong about the INBOX: it left every
 * control kind unwakeable, including the referral offer/accept legs and group
 * invites, which is exactly a user-visible event stuck behind "next time you
 * happen to open the app". Wake selection is now per-KIND, sender-side, via the
 * `X-No-Push` header (see the table below), which is strictly finer-grained than
 * refusing to register the inbox at all.
 *
 * Still exported, and still the right answer for anything that means literally
 * "the inboxes user-visible MESSAGES arrive on" (e.g. an unread-count prime).
 */
fun allInboundTextInboxes(vault: VaultDatabase): List<InboundInboxRef> =
    collectInboundInboxes(vault, arrayOf("inbound"))

/**
 * The PUSH-REGISTRATION surface: every inbound inbox the relay may fire a
 * contentless wake for — the text surface ([allInboundTextInboxes]) PLUS every
 * inbound CONTROL row (`MessageManager.DIR_INBOUND_CTL`) and every inbound GROUP
 * row (`MessageManager.DIR_INBOUND_GRP`).
 *
 * `inbox_ids` only ever holds six directions, all PER CONTACT — `"inbound"`,
 * `"outbound"`, `inbound-ctl`, `outbound-ctl`, `inbound-grp`, `outbound-grp`
 * (written by `PairingVault`,
 * `MessageManager.applyInboxAnnounce` and `ReferralManager`'s finalize). GROUPS
 * still mint no inbox rows of their own: group control fans out over the members'
 * per-contact control inboxes and group TEXT over their per-contact GROUP
 * inboxes, so the three inbound directions below really are the complete inbound
 * set, direct and group alike.
 *
 * WHY CONTROL INBOXES ARE NOW REGISTERED. A referral offer, a relayed
 * referral accept and a group invite all ride the CONTROL channel, and with the
 * control inbox unregistered none of them could wake a sleeping device: an
 * introduction stalled until BOTH introducees happened to foreground the app
 * inside the record's TTL — the same half-pair failure the 7-day TTL and the
 * durable offer/accept redrives attack from the other side. Registering the
 * inbox is only half the change: the relay wakes on ANY append unless the SENDER
 * set `X-No-Push`, so every control kind now states its choice explicitly, and
 * the ones that must stay silent are suppressed sender-side:
 *
 * | control kind | sender | wakes? | relay ttl |
 * | --- | --- | --- | --- |
 * | `ref-offer` | `ReferralManager.startReferral` / offer redrive | YES | 7 d |
 * | `ref-accept` | `ReferralManager` accept + relay-forward + both redrives | YES | 7 d |
 * | `invite` | `GroupManager.createGroup` / `addMember` | YES | 7 d |
 * | `inbox` (announce) | `MessageManager.sendInboxAnnounce` | no (forced) | 7 d |
 * | `screenshot` (1:1) | `MessageManager.sendScreenshotNotice` | no | 7 d |
 * | `screenshot` (group) | `GroupManager.sendGroupScreenshotNotice` | no | 7 d |
 * | `plvl` (1:1) | `MessageManager.sendMaximumAnnouncement` | no | 7 d |
 * | `act` (activity) | `GroupManager.sendGroupMessage` | no (the text already woke) | 7 d |
 * | `join` | `GroupManager.acceptInvite` / `sendSelfJoinToNewAdmin` | no | 7 d |
 * | `roster` | `GroupManager.broadcastRoster` + the ack-gated re-roster | no | 7 d |
 * | `leave` | `GroupManager.leaveGroup` | no | 7 d |
 *
 * `GroupManager.fanOutControl` defaults to `noPush = true` so a control kind
 * added later is SILENT until someone deliberately makes it wake.
 *
 * **The ttl column is deliberately CONSTANT.** It used to
 * vary by kind, and `?ttl` rides the request line in the CLEAR, so `?ttl=604800`
 * together with `X-No-Push: 1` was a plaintext "this append is a group ROSTER or
 * LEAVE to this recipient" label for a relay that decrypts nothing — the selector
 * that made a relay's 201-and-discard suppression surgical instead of blunt. Every
 * control append now passes `MessageManager.CONTROL_APPEND_TTL_SECONDS`; do not
 * reintroduce a per-kind value. What CANNOT be removed is the `X-No-Push` column
 * itself — the relay has to be told not to wake the device — so a kind's WAKE
 * choice stays relay-visible (Known limitation, stated in
 * `docs/vault-relay-internals.md`). TEXT appends still carry
 * no ttl at all, which is why they are not in this table.
 *
 * Same rules, same [InboundInboxRef] shape and the same skip-the-malformed
 * behaviour as its siblings — and the same non-negotiable: `readCap` is sourced
 * from an OPEN VAULT and nowhere else (see this file's header).
 *
 * **"Move to new device" FREEZE GATE (docs/device-move.md D2).** Empty while
 * `mig_frozen` is set. This is the one place BOTH platforms resolve the push
 * surface from — `RunViewModel.refreshVendorPushRegistration` and
 * `IosAppController.currentInboundInboxRefs` — so gating it here is what stops a
 * frozen phone from (re)registering its token on inboxes the NEW phone is about
 * to own. That matters concretely: `PUT /inbox/{id}/push` is an UPSERT keyed by
 * inbox, so an old phone re-registering would silently replace the new phone's
 * token and steal its wakes.
 *
 * It gates DE-registration too, and that is deliberate rather than accidental:
 * `MoveManager.beginExport` unregisters push BEFORE it writes `mig_frozen`
 * (`UNREGISTER_PUSH` then `FREEZE` — keep that order), so the move's own dereg
 * always runs un-gated. Known limitation: a dereg that failed or timed out there cannot
 * be re-tried later from the frozen phone. It is closed on the other side — the
 * new phone's post-import read-cap rotation issues `DELETE /inbox/{id}/push` with
 * the freshly proven cap (`MessageManager.onRotationCommitted`), evicting whatever
 * token the old phone left behind.
 *
 * Fails toward FROZEN on an unreadable vault ([isMoveFrozen]): the worst case is
 * one skipped registration pass, which the next sweep repeats.
 */
fun allPushableInboxes(db: VaultDatabase): List<InboundInboxRef> {
    if (isMoveFrozen(db)) {
        platformLog(
            "PushRegistration",
            "push surface empty — this device is the old phone of a move",
        )
        return emptyList()
    }
    return collectInboundInboxes(
        db,
        // The GROUP inbox is on the wake surface for the same reason the text inbox
        // is: a group TEXT used to arrive on the sender's 1:1 text inbox and fire
        // that inbox's wake, and it now arrives here instead. Leaving it out would
        // silently make every group message unable to wake a sleeping device —
        // the wake semantics must be preserved EXACTLY, not merely not-regressed.
        arrayOf("inbound", MessageManager.DIR_INBOUND_CTL, MessageManager.DIR_INBOUND_GRP),
    )
}

/**
 * Diff step behind the periodic push-registration re-sync: filters [desired]
 * (typically [allInboundTextInboxes]'s current snapshot) down to the entries
 * whose inboxId is NOT already in [alreadyRegisteredIds] — the caller's
 * session-scoped "already told the relay about this one" set.
 *
 * Coverage gap this exists to close: the one-time device-token callback
 * (iOS `didRegisterForRemoteNotificationsWithDeviceToken`) only registers
 * whatever inboxes exist AT THAT MOMENT. A contact paired, referred, or
 * re-paired afterward mints a brand-new inbound-text inbox that nothing
 * else ever revisits. Re-running this diff on the same cadence as the
 * background control-poll loop — which already sits downstream of every
 * cap-mutation site (PairingVault, ReferralManager, rotateReadCap) —
 * covers all of them without a hook at each insertInboxId call site. Android
 * runs the identical diff on the identical cadence
 * (RunViewModel.refreshVendorPushRegistration).
 *
 * Order-preserving, pure (no I/O) — so this is commonTest-covered without a
 * live vault or transport, unlike the platform orchestration that calls it.
 */
fun inboxesNeedingRegistration(
    desired: List<InboundInboxRef>,
    alreadyRegisteredIds: Set<String>,
): List<InboundInboxRef> = desired.filter { it.inboxId !in alreadyRegisteredIds }
