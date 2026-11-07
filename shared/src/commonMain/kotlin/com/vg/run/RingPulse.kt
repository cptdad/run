package com.vg.run

import kotlin.math.PI
import kotlin.math.cos

/**
 * The runestone's red ring while connecting (2026-09-11): it
 * pulses harder and harder as the paced connect percent climbs, goes SOLID red
 * the instant the relay answers, holds for [SOLID_HOLD_MS], and only then does
 * the white R light (the platforms' existing lit fade). Shared by
 * ContactListScreen (Android, the `runestone_bright` layer's alpha) and
 * ContactListView (iOS, the same layer's opacity) so both phones breathe alike.
 *
 * Pure: the platforms supply the progress (BootstrapProgressPacer.displayed()
 * / 100) and a wall-clock phase; nothing here keeps time.
 */
object RingPulse {
    /** One breath, trough → peak → trough. Constant, so the phase is just wall-clock modulo. */
    const val PERIOD_MS = 1100L
    /** Solid-red beat between the relay's first answer and the R lighting. */
    const val SOLID_HOLD_MS = 600L

    fun solidHoldMs(): Long = SOLID_HOLD_MS

    /** Lowest opacity of a breath at connect progress [p] (0..1): 0.20 → 0.45 (brighter, user 2026-09-11). */
    fun trough(p: Float): Float = 0.20f + 0.25f * p.coerceIn(0f, 1f)

    /** Highest opacity of a breath at connect progress [p]: 0.65 → 1.0 (full red only at 100 — the relay answer). */
    fun peak(p: Float): Float = 0.65f + 0.35f * p.coerceIn(0f, 1f)

    /**
     * Opacity of the bright (red-ring) layer at connect progress [p] and breath
     * [phase] in 0..1 (0 = trough, 0.5 = peak, cosine-eased). Monotone in [p] at
     * every phase, so the pulse only ever gets stronger while connecting.
     */
    fun opacity(p: Float, phase: Float): Float {
        val ph = ((phase % 1f) + 1f) % 1f
        val s = ((1.0 - cos(2.0 * PI * ph)) / 2.0).toFloat()
        val lo = trough(p)
        return lo + (peak(p) - lo) * s
    }

    /** Wall-clock → breath phase. */
    fun phaseAt(nowMs: Long): Float = ((nowMs % PERIOD_MS + PERIOD_MS) % PERIOD_MS).toFloat() / PERIOD_MS
}
