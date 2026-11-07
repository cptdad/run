package com.vg.run

import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.unit.LayoutDirection

// ---------------------------------------------------------------------------
// RTL parity (ar/fa) — this app draws all "icons" as hand-drawn Unicode
// glyphs in Text() (no Material Icons anywhere), so unlike iOS's
// auto-mirroring SF Symbols, a fixed "←" has to be flipped by hand.
// ---------------------------------------------------------------------------

/**
 * The reading-direction-aware back-arrow glyph: "←" under LTR, "→" under
 * RTL. The header Row that hosts this glyph already relocates correctly
 * under RTL (Compose mirrors Row/Arrangement automatically) — only the
 * glyph itself needs to point the other way. Mirrors iOS's swap of
 * `chevron.left` for the auto-mirroring `chevron.backward`.
 */
@Composable
fun backArrowGlyph(): String =
    if (LocalLayoutDirection.current == LayoutDirection.Rtl) "→" else "←"
