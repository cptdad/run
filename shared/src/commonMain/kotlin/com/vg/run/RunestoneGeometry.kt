package com.vg.run

/**
 * Where the runestone sits inside the full-bleed art, so the platforms can
 * anchor UI *below the stone* instead of guessing with weighted spacers
 * (the "Connecting to Tor…" caption always sits
 * below the runestone — both platforms).
 *
 * The nine art variants share one canvas ([ART_WIDTH] × [ART_HEIGHT]); the
 * stone's foot ends at [STONE_BOTTOM_FRACTION] of the canvas height and the
 * blue forcefield's base (the widest/lowest tier, the ring's bottom edge)
 * at [RING_BOTTOM_FRACTION]. The connect caption sits well BELOW the ring,
 * never over it — [captionTopY]. Android draws
 * the art width-filled from the top; iOS aspect-fills the screen
 * (vertically centred). [stoneBottomY] / [ringBottomY] handle both.
 */
object RunestoneGeometry {
    const val ART_WIDTH = 624f
    const val ART_HEIGHT = 1254f
    const val STONE_BOTTOM_FRACTION = 0.68f

    /**
     * Lowest bright-blue row of the forcefield art (measured on
     * runestone_dim_forcefield.png: row 984 of 1254). Same canvas for the
     * dim/ring tiers, whose art ends higher, so one anchor serves all nine.
     */
    const val RING_BOTTOM_FRACTION = 0.785f

    /** Gap between the stone's foot and the first line of UI below it, in dp/pt. */
    const val BELOW_STONE_GAP = 12f

    /** Gap between the ring's bottom edge and the connect caption, in dp/pt. */
    const val BELOW_RING_GAP = 28f

    /**
     * Swift-friendly accessor for [BELOW_STONE_GAP] — avoids guessing how a
     * `const val` on a Kotlin `object` surfaces in the generated Obj-C/Swift
     * header (function export spelling is unambiguous: `RunestoneGeometry.shared.belowStoneGap()`).
     */
    fun belowStoneGap(): Float = BELOW_STONE_GAP

    /** Swift-friendly accessor for [BELOW_RING_GAP]. */
    fun belowRingGap(): Float = BELOW_RING_GAP

    /**
     * Y (same unit as the inputs, from the top of the drawn area) of the stone's
     * foot when the art is drawn [fillWidth]-style (Android: width-filled, top
     * aligned) or aspect-filled into [viewportW] × [viewportH] (iOS: centred).
     */
    fun stoneBottomY(viewportW: Float, viewportH: Float, fillWidth: Boolean): Float =
        canvasY(STONE_BOTTOM_FRACTION, viewportW, viewportH, fillWidth)

    /** Y of the ring's (forcefield's) bottom edge, same conventions as [stoneBottomY]. */
    fun ringBottomY(viewportW: Float, viewportH: Float, fillWidth: Boolean): Float =
        canvasY(RING_BOTTOM_FRACTION, viewportW, viewportH, fillWidth)

    /**
     * Y where the first line of the connect caption ("Connecting to Tor…",
     * the stall hints, the Reconnect button) starts: [BELOW_RING_GAP] under
     * the ring's bottom edge, so the text never overlaps the blue ring.
     */
    fun captionTopY(viewportW: Float, viewportH: Float, fillWidth: Boolean): Float =
        ringBottomY(viewportW, viewportH, fillWidth) + BELOW_RING_GAP

    private fun canvasY(fraction: Float, viewportW: Float, viewportH: Float, fillWidth: Boolean): Float {
        val byWidth = viewportW * ART_HEIGHT / ART_WIDTH
        if (fillWidth) return byWidth * fraction
        val drawnH = maxOf(viewportH, byWidth)
        val offset = (drawnH - viewportH) / 2f
        return drawnH * fraction - offset
    }
}
