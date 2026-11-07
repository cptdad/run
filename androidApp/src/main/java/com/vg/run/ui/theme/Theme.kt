package com.vg.run.ui.theme

import android.app.Activity
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat

// ---------------------------------------------------------------------------
// RunTheme — dark-only Material 3 theme for Rún.
//
// A single dark colour scheme: no dynamic colour, no light mode. System bars
// are transparent (edge-to-edge, see MainActivity's enableEdgeToEdge()) and
// the near-black background shows through, so the app blends seamlessly
// with the system chrome without painting the bars directly.
// ---------------------------------------------------------------------------

private val RunColorScheme = darkColorScheme(
    background       = RunBlack,
    surface          = RunSurface,
    surfaceVariant   = RunSurfaceAlt,
    onBackground     = RunWhite,
    onSurface        = RunWhite,
    onSurfaceVariant = RunGrey,
    primary          = RunAccent,
    onPrimary        = RunBlack,
    error            = RunError,
    onError          = RunBlack
)

@Composable
fun RunTheme(content: @Composable () -> Unit) {
    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as Activity).window
            // Bars are transparent under enableEdgeToEdge() (MainActivity) and
            // the near-black background shows through, so the app still reads
            // as edge-to-edge with no visual seam — no need to paint the bars
            // via the deprecated Window.setStatusBarColor/setNavigationBarColor.
            WindowCompat.getInsetsController(window, view).apply {
                isAppearanceLightStatusBars = false
                isAppearanceLightNavigationBars = false
            }
        }
    }

    MaterialTheme(
        colorScheme = RunColorScheme,
        typography = Typography,
        content = content
    )
}
