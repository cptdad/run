package com.vg.run

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-policy tests for [PushReplayGuard],
 * the UnifiedPush replay/rate-limit bound wired into
 * [RunPushService.onMessage]. See that class's kdoc for why this is a rate
 * limiter rather than a literal content-hash dedupe (the connector never
 * exposes a genuinely per-message-unique input to `onMessage`).
 */
class PushReplayGuardTest {

    @Test
    fun firstWake_isAlwaysShown() {
        val guard = PushReplayGuard()
        assertTrue(
            "the very first wake, on a fresh guard, must show the banner",
            guard.shouldShowBanner("hash-a", nowMs = 0L),
        )
    }

    @Test
    fun exactRepeatWithinTheDedupeWindow_isDropped() {
        val guard = PushReplayGuard(dedupeWindowMs = 10_000L, rateLimitMs = 0L)
        assertTrue(guard.shouldShowBanner("hash-a", nowMs = 0L))
        assertFalse(
            "an exact repeat of the same hash inside the dedupe window must be dropped, even " +
                "with the rate limit disabled",
            guard.shouldShowBanner("hash-a", nowMs = 1_000L),
        )
    }

    @Test
    fun exactRepeatAfterTheDedupeWindowExpires_isAllowedByDedupe() {
        // rateLimitMs = 0 isolates the dedupe-window behaviour from the rate
        // limiter, which would otherwise also gate this case.
        val guard = PushReplayGuard(dedupeWindowMs = 1_000L, rateLimitMs = 0L)
        assertTrue(guard.shouldShowBanner("hash-a", nowMs = 0L))
        assertTrue(
            "once the dedupe window has elapsed, the SAME hash must be treated as a new " +
                "event by the dedupe check — this is the fixed-plaintext constraint " +
                "documented on the class: this guard cannot tell a genuine repeat wake from " +
                "an old one being replayed, so it must not gate forever",
            guard.shouldShowBanner("hash-a", nowMs = 1_500L),
        )
    }

    @Test
    fun differentHashesWithinTheWindow_areNotTreatedAsDuplicates() {
        val guard = PushReplayGuard(dedupeWindowMs = 10_000L, rateLimitMs = 0L)
        assertTrue(guard.shouldShowBanner("hash-a", nowMs = 0L))
        assertTrue(
            "a DIFFERENT hash must never be suppressed by the dedupe ring, regardless of " +
                "timing",
            guard.shouldShowBanner("hash-b", nowMs = 1L),
        )
    }

    @Test
    fun rateLimit_boundsTheBannerFrequencyRegardlessOfHash() {
        val guard = PushReplayGuard(dedupeWindowMs = 0L, rateLimitMs = 10_000L)
        assertTrue(guard.shouldShowBanner("hash-a", nowMs = 0L))
        assertFalse(
            "a DIFFERENT hash arriving inside the rate-limit window must still be dropped — " +
                "this is the mechanism that actually bounds the replay oracle, since the " +
                "connector's fixed-plaintext wake means every replay AND every genuine new " +
                "message hash identically",
            guard.shouldShowBanner("hash-b", nowMs = 5_000L),
        )
        assertTrue(
            "once the rate-limit window has fully elapsed, a new wake must be shown again",
            guard.shouldShowBanner("hash-c", nowMs = 10_000L),
        )
    }

    @Test
    fun ringCapacity_evictsOldestEntryFirst() {
        val guard = PushReplayGuard(ringCapacity = 2, dedupeWindowMs = 1_000_000L, rateLimitMs = 0L)
        assertTrue(guard.shouldShowBanner("hash-a", nowMs = 0L))
        assertTrue(guard.shouldShowBanner("hash-b", nowMs = 1L))
        // Capacity 2: this THIRD distinct hash must evict "hash-a" from the ring.
        assertTrue(guard.shouldShowBanner("hash-c", nowMs = 2L))
        assertTrue(
            "hash-a must have been evicted once the ring exceeded capacity, so it now reads " +
                "as a fresh event rather than a duplicate",
            guard.shouldShowBanner("hash-a", nowMs = 3L),
        )
    }

    @Test
    fun defaultConstants_matchTheAuditedFixShape() {
        // Intended shape: "a small RAM ring (e.g. 64
        // entries)" and "a rate limit of at most one banner per 10 s".
        // Non-vacuousness: this pins the shipped defaults so a future change
        // must be a deliberate edit here too, not a silent drift.
        val guard = PushReplayGuard()
        assertTrue(PushReplayGuard.RING_CAPACITY == 64)
        assertTrue(PushReplayGuard.RATE_LIMIT_MS == 10_000L)
        // Exercise the default-constructed instance too, so the constants above
        // cannot silently diverge from what `PushReplayGuard()` actually wires.
        assertTrue(guard.shouldShowBanner("hash-a", nowMs = 0L))
        assertFalse(guard.shouldShowBanner("hash-b", nowMs = 1L))
    }

    /**
     * Review 2026-11-06 S4: both wake transports share ONE process-wide guard, and
     * the FCM path consults it before posting the banner (after the level and
     * freshness gates), so a relay streaming FCM wakes gets one banner per 10 s.
     */
    @Test
    fun bothTransports_shareTheProcessWideGuard_beforeTheBanner() {
        val up = stripComments(SourcePins.text("androidApp/src/main/java/com/vg/run/RunPushService.kt"))
        assertTrue(up.contains("private val replayGuard = PushReplayGuard.processWide"))
        val fcm = stripComments(SourcePins.text(SourcePins.RUN_FCM_SERVICE))
        val start = fcm.indexOf("override fun onMessageReceived(message: RemoteMessage) {")
        assertTrue(start >= 0)
        val body = fcm.substring(start, fcm.indexOf("\n    }", start))
        val freshAt = body.indexOf("PushWakeFreshness.isStaleWake(")
        val guardAt = body.indexOf("PushReplayGuard.processWide.shouldShowBanner(")
        val showAt = body.indexOf("NotificationHelper.showNewMessages(")
        assertTrue("the FCM path must consult the shared guard. Body:\n$body", guardAt >= 0)
        assertTrue("guard after the freshness gate, before the banner", freshAt in 0 until guardAt && guardAt < showAt)
        assertFalse("no second, private guard instance anywhere", Regex("""=\s*PushReplayGuard\(\)""").containsMatchIn(up + fcm))
    }
}
