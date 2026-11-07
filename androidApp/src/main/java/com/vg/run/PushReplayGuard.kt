package com.vg.run

/**
 * Bounds the UnifiedPush replay/behaviour
 * oracle: [RunPushService.onMessage]'s only authenticity check
 * (`REQUIRE_ENCRYPTED_PUSH`) is freshness-blind, so any party that has ever
 * seen a delivered ciphertext for this device's subscription (the push
 * server itself, by construction of RFC 8030/8291) can re-deliver it at any
 * later time and re-fire the "Notification" banner on demand.
 *
 * WHY THIS IS A RATE LIMIT, NOT A CONTENT-HASH DEDUPE
 * -------------------------------------------------------------------------
 * The obvious fix is a ring of `sha256(ciphertext)` that drops an exact
 * repeat. That is not realizable through the
 * `org.unifiedpush.android.connector` 3.3.3 public API this service is
 * written against, and implementing it literally would be actively harmful:
 * bytecode-verified (`MessagingReceiverImpl`/`MessagingReceiver.onReceive`),
 * the connector decrypts the wire ciphertext internally and hands
 * [org.unifiedpush.android.connector.data.PushMessage] to [RunPushService]
 * with only the DECRYPTED bytes (`content`) and a `decrypted` Boolean — never
 * the pre-decrypt ciphertext, and never the connector's own `id` extra (that
 * is read only to ACK the distributor; it is never forwarded to `onMessage`).
 * This app's relay mints a single FIXED plaintext, `{"type":"wake"}`, for
 * every wake, genuine or replayed (`WebPushSender.kt`, relay repo) — so
 * `message.content` is byte-identical across ALL of them. A ring keyed on
 * that hash cannot distinguish "this exact message was seen before" from
 * "a brand new message happens to say the same fixed thing", which is true
 * of every legitimate wake after the first: it would dedupe the SECOND EVER
 * genuine new-message notification and every one after it, silently
 * disabling UnifiedPush banners for the rest of the install's life. That is
 * a worse outcome than the replay it would "fix", so it is not shipped.
 *
 * Instead this bounds the same oracle by rate: at most one banner per
 * [rateLimitMs] regardless of content, which bounds the oracle just as well.
 * The small ring is kept anyway
 * (structurally, not just as a rate limiter) so that if a future connector
 * version exposes a genuinely per-message-unique input (raw ciphertext or
 * the `id` extra), plugging it into [shouldShowBanner] immediately upgrades
 * this from "one banner per window" to a real exact-duplicate dedupe with no
 * further call-site changes.
 *
 * RAM-ONLY, DELIBERATELY. State resets on process death, which means a
 * replay delivered to a fresh process after this one was torn down (this
 * app is foreground-only — MainActivity.onStop tears the whole session down)
 * is not caught by either the ring or the rate limit. That is a known
 * limitation, not an oversight: persisting the ring buys nothing
 * given the fixed-plaintext constraint above (a persisted hash of a constant
 * value is exactly as uninformative as a RAM one), and persisting *only* a
 * rate-limit timestamp would re-arm on every backgrounding of an app that is
 * ALREADY torn down and rebuilt on every foreground return by design — so it
 * would not meaningfully narrow the window either. [UnifiedPushStateStore]
 * was checked for a suitable slot and has none that would change this
 * analysis.
 *
 * Pure and Android-free on purpose — no Context, no clock read internally —
 * so the policy is unit-testable without Robolectric. [RunPushService] is the
 * sole caller.
 */
class PushReplayGuard(
    private val ringCapacity: Int = RING_CAPACITY,
    private val dedupeWindowMs: Long = DEDUPE_WINDOW_MS,
    private val rateLimitMs: Long = RATE_LIMIT_MS,
) {

    private data class Seen(val hash: String, val atMs: Long)

    private val ring = ArrayDeque<Seen>(ringCapacity)

    /** Null (never shown) rather than a sentinel Long — `nowMs - Long.MIN_VALUE`
     *  overflows a Long and would otherwise make the very first wake read as
     *  "just shown". */
    private var lastBannerAtMs: Long? = null

    /**
     * @param contentHash a hex/base64/any-stable digest of the wake's
     *   identifying bytes (today: `sha256(message.content)` — see the class
     *   kdoc for why that is a rate limiter in practice, not an exact dedupe).
     * @param nowMs caller-supplied clock reading (testability; production
     *   caller passes `System.currentTimeMillis()`).
     * @return `true` if the caller should show the banner for this wake,
     *   `false` if it must be dropped (exact repeat inside the dedupe window,
     *   or the rate limit has not elapsed since the last shown banner).
     */
    @Synchronized
    fun shouldShowBanner(contentHash: String, nowMs: Long): Boolean {
        val isExactRepeat = ring.any { it.hash == contentHash && nowMs - it.atMs < dedupeWindowMs }
        recordSeen(contentHash, nowMs)
        if (isExactRepeat) return false
        val lastShown = lastBannerAtMs
        if (lastShown != null && nowMs - lastShown < rateLimitMs) return false
        lastBannerAtMs = nowMs
        return true
    }

    private fun recordSeen(hash: String, nowMs: Long) {
        if (ring.size >= ringCapacity) ring.removeFirst()
        ring.addLast(Seen(hash, nowMs))
    }

    companion object {
        /**
         * THE process-wide guard both wake transports share (RunPushService for
         * UnifiedPush, RunFcmService for FCM). Process-wide, not per Service
         * instance: the framework may construct a new Service object per
         * dispatch. Only one transport is active at a time, so sharing one
         * rate limit never starves the other. Routing FCM through it closes
         * review 2026-11-06 S4: the relay (the sole FCM sender) could stream
         * high-priority wakes and make the phone sound at the OS ceiling,
         * while UnifiedPush was already capped at one banner per 10 s.
         */
        val processWide: PushReplayGuard = PushReplayGuard()

        const val RING_CAPACITY = 64
        const val DEDUPE_WINDOW_MS = 10_000L
        const val RATE_LIMIT_MS = 10_000L
    }
}
