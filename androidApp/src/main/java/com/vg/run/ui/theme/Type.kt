package com.vg.run.ui.theme

import androidx.compose.material3.Typography
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import com.vg.run.R

// ---------------------------------------------------------------------------
// Typography — all app text uses Metamorphous (bundled, OFL — assets/fonts/),
// the carved-stone face matching the runestone art. Single Regular weight;
// heavier/lighter weights render as Regular. The serif family ([SerifFamily])
// stays for the runic "ᚱ" / "Rún" wordmark in the About/Donate surfaces, and
// code/diagnostic surfaces keep FontFamily.Monospace at their call sites.
// ---------------------------------------------------------------------------

/** Bundled Metamorphous — the app-wide default face. */
val MetamorphousFamily = FontFamily(Font(R.font.metamorphous))

/** Platform serif family, used for the runic mark / "Rún" wordmark. */
val SerifFamily = FontFamily.Serif

private val Base = Typography()
private fun TextStyle.rune() = copy(fontFamily = MetamorphousFamily)

val Typography = Typography(
    displayLarge = Base.displayLarge.rune(),
    displayMedium = Base.displayMedium.rune(),
    displaySmall = Base.displaySmall.rune(),
    headlineLarge = Base.headlineLarge.rune(),
    // Keypad digits
    headlineMedium = TextStyle(
        fontFamily = MetamorphousFamily,
        fontWeight = FontWeight.Light,
        fontSize = 28.sp,
        lineHeight = 36.sp,
        letterSpacing = 0.sp
    ),
    headlineSmall = Base.headlineSmall.rune(),
    titleLarge = Base.titleLarge.rune(),
    // Contact list items
    titleMedium = TextStyle(
        fontFamily = MetamorphousFamily,
        fontWeight = FontWeight.Normal,
        fontSize = 18.sp,
        lineHeight = 24.sp,
        letterSpacing = 0.15.sp
    ),
    titleSmall = Base.titleSmall.rune(),
    // General body
    bodyLarge = TextStyle(
        fontFamily = MetamorphousFamily,
        fontWeight = FontWeight.Normal,
        fontSize = 16.sp,
        lineHeight = 24.sp,
        letterSpacing = 0.5.sp
    ),
    bodyMedium = Base.bodyMedium.rune(),
    bodySmall = Base.bodySmall.rune(),
    labelLarge = Base.labelLarge.rune(),
    labelMedium = Base.labelMedium.rune(),
    labelSmall = Base.labelSmall.rune(),
)
