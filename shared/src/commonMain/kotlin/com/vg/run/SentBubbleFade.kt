package com.vg.run

/**
 * The look of a SENT bubble (owner directive 2026-11-12): instead of a small check mark,
 * a bubble the relay has not accepted yet is drawn GREY and TRANSLUCENT, creeps slowly up
 * toward a cap that is deliberately well below opaque, and only the relay's acceptance
 * animates it to full opacity AND its real sent-bubble colour. Full opacity + real colour
 * is the one and only "it got through" signal.
 *
 * Shared by ConversationScreen / GroupConversationScreen (Android) and ConversationView /
 * GroupViews (iOS) so the two renderers cannot drift. Pure: the platforms supply the
 * elapsed time since the message was sent and the delivered flag; nothing here keeps time.
 *
 * "Delivered" = 1:1: the relay accepted the message; group: EVERY member copy was accepted.
 * A failed / partially delivered bubble is simply "not delivered": it never exceeds
 * [PENDING_CAP] and never takes its real colour.
 */
object SentBubbleFade {
    /** Opacity of a pending bubble the moment it appears. */
    const val START_ALPHA = 0.25f
    /** A pending (or failed / partial) bubble never rises above this, however long it waits. */
    const val PENDING_CAP = 0.5f
    /** Ease-out creep from [START_ALPHA] to [PENDING_CAP] over this long, then hold. */
    const val CREEP_MS = 10_000L
    /** Pending -> delivered: grey -> real colour and translucent -> opaque over this long. */
    const val DELIVERED_MS = 500L
    /** RGB of the pending grey the bubble background starts from (0xRRGGBB). */
    const val PENDING_GREY_RGB = 0x9E9E9E

    /** Opacity of a still-pending bubble [elapsedMs] after it was sent: monotone, in [START_ALPHA, PENDING_CAP]. */
    fun pendingAlpha(elapsedMs: Long): Float {
        val t = (elapsedMs.coerceAtLeast(0L).toFloat() / CREEP_MS.toFloat()).coerceIn(0f, 1f)
        val eased = 1f - (1f - t) * (1f - t)
        return START_ALPHA + (PENDING_CAP - START_ALPHA) * eased
    }

    /** Settled opacity: exactly 1.0 when [delivered], otherwise the pending curve (never above the cap). */
    fun alpha(elapsedMs: Long, delivered: Boolean): Float =
        if (delivered) 1f else pendingAlpha(elapsedMs)

    /** Opacity for no-animation mode (Reduce Motion / animator scale 0): the translucent state, at the cap. */
    fun reducedMotionPendingAlpha(): Float = PENDING_CAP

    /**
     * Opacity while the delivered transition is [progress] (0 = still pending look, 1 = delivered)
     * through, from the pending opacity [pendingAlpha] it started at. Monotone in [progress].
     */
    fun transitionAlpha(pendingAlpha: Float, progress: Float): Float {
        val p = progress.coerceIn(0f, 1f)
        return pendingAlpha + (1f - pendingAlpha) * p
    }

    /** True while the creep still has distance to cover (the platforms stop their frame clock after this). */
    fun isCreeping(elapsedMs: Long): Boolean = elapsedMs < CREEP_MS
}
