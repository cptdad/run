package com.vg.run

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import com.vg.run.ui.theme.RuneCardFill
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.vg.run.ui.theme.RunAccent
import com.vg.run.ui.theme.RunGrey
import com.vg.run.ui.theme.RunSurface
import com.vg.run.ui.theme.RunWhite
import com.vg.run.ui.theme.SerifFamily

// ---------------------------------------------------------------------------
// AboutModal — a swipeable carousel that introduces Rún's privacy features.
//
// All copy is rendered from AboutContent (commonMain) so Android and iOS show
// identical text and the page set stays unit-testable. This modal is static
// content.
//
// Two of the pages animate the runestone, reusing the same layered drawables
// (runestone_dim / runestone_bright / runestone_bright_and_lit) that the
// contact list and conversation screens crossfade:
//   • RUNESTONE_TOR   plays "dark → red" when its page is current.
//   • RUNESTONE_RELAY plays the white centre ᚱ fading in when its page is current.
// ---------------------------------------------------------------------------

@Composable
fun AboutModal(onClose: () -> Unit) {
    Dialog(
        onDismissRequest = onClose,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        // Separate window — reading the carousel must not read as idle to the
        // Lever-C auto-lock (60 s on MAXIMUM).
        Box(Modifier.keepUnlockedOnInteraction()) {
            AboutModalContent(onClose = onClose)
        }
    }
}

/**
 * The About carousel body, without the [Dialog] window wrapper. Extracted so it
 * can be hosted directly in Compose UI tests — a Dialog renders in a separate
 * window that `createComposeRule` does not see ("No compose hierarchies found").
 * At runtime [AboutModal] wraps this in a full-screen Dialog.
 */
@OptIn(androidx.compose.ui.ExperimentalComposeUiApi::class)
@Composable
fun AboutModalContent(onClose: () -> Unit) {
    val pagerState = rememberPagerState(pageCount = { AboutContent.pages.size })

    Box(
            modifier = Modifier
                .fillMaxSize()
                .semantics { testTagsAsResourceId = BuildConfig.DEBUG }
                .testTag("about_modal")
                .padding(16.dp)
        ) {
            RuneCard(modifier = Modifier.fillMaxSize(), fill = RuneCardFill.copy(alpha = 0.8f)) {
                // Close button — top-right.
                Box(modifier = Modifier.fillMaxWidth()) {
                    Box(
                        modifier = Modifier
                            .align(Alignment.TopEnd)
                            .padding(8.dp)
                            .size(40.dp)
                            .clip(CircleShape)
                            .clickable(onClick = onClose)
                            .testTag("about_close"),
                        contentAlignment = Alignment.Center
                    ) {
                        Text("✕", color = RunGrey, fontSize = 20.sp)
                    }
                }

                HorizontalPager(
                    state = pagerState,
                    modifier = Modifier
                        .weight(1f)
                        .fillMaxWidth()
                        .testTag("about_pager")
                ) { index ->
                    AboutPageContent(
                        page = AboutContent.pages[index],
                        isCurrent = pagerState.currentPage == index
                    )
                }

                // Page-indicator dots.
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 20.dp),
                    horizontalArrangement = Arrangement.Center
                ) {
                    AboutContent.pages.indices.forEach { i ->
                        val selected = pagerState.currentPage == i
                        Box(
                            modifier = Modifier
                                .padding(horizontal = 4.dp)
                                .size(if (selected) 8.dp else 6.dp)
                                .clip(CircleShape)
                                .background(if (selected) RunAccent else RunGrey)
                        )
                    }
                }
            }
        }
    }

@Composable
private fun AboutPageContent(page: AboutPage, isCurrent: Boolean) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            // Scrollable so a long page body doesn't clip; Arrangement.Center
            // still centers a short page within the viewport.
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 28.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        when (page.kind) {
            AboutPageKind.TEXT -> {
                Text(
                    text = page.glyph,
                    fontSize = 72.sp,
                    textAlign = TextAlign.Center,
                    color = RunWhite
                )
                Spacer(Modifier.height(24.dp))
            }
            AboutPageKind.RUNESTONE_TOR -> {
                // Dark → red: crossfade dim → bright when this page is current.
                val redAlpha by animateFloatAsState(
                    targetValue = if (isCurrent) 1f else 0f,
                    animationSpec = tween(
                        durationMillis = if (isCurrent) 1500 else 0,
                        easing = LinearEasing
                    ),
                    label = "aboutTorRed"
                )
                RunestonePages(brightAlpha = redAlpha, litAlpha = 0f)
                Spacer(Modifier.height(24.dp))
            }
            AboutPageKind.RUNESTONE_RELAY -> {
                // Red stays solid; white centre ᚱ fades in when current.
                val litAlpha by animateFloatAsState(
                    targetValue = if (isCurrent) 1f else 0f,
                    animationSpec = tween(
                        durationMillis = if (isCurrent) 2000 else 0,
                        easing = LinearEasing
                    ),
                    label = "aboutRelayLit"
                )
                RunestonePages(brightAlpha = 1f, litAlpha = litAlpha)
                Spacer(Modifier.height(24.dp))
            }
            AboutPageKind.FORCEFIELD -> {
                // The full blue forcefield around the lit runestone — the visual
                // for the Forensic-safe page (static image, sized like the runestone pages).
                Box(
                    modifier = Modifier.fillMaxWidth().aspectRatio(1.4f),
                    contentAlignment = Alignment.Center
                ) {
                    Image(
                        painter = painterResource(id = R.drawable.runestone_bright_and_lit_forcefield),
                        contentDescription = null,
                        contentScale = ContentScale.Fit,
                        modifier = Modifier.fillMaxSize()
                    )
                }
                Spacer(Modifier.height(24.dp))
            }
        }

        Text(
            text = page.title,
            fontFamily = SerifFamily,
            fontWeight = FontWeight.Bold,
            fontSize = 26.sp,
            textAlign = TextAlign.Center,
            color = RunWhite
        )
        Spacer(Modifier.height(16.dp))
        Text(
            text = page.body,
            fontSize = 16.sp,
            lineHeight = 24.sp,
            textAlign = TextAlign.Center,
            color = RunGrey
        )
    }
}

/**
 * Renders the layered runestone drawables for the About carousel, reusing the
 * same dim → bright → bright_and_lit stack the live screens crossfade.
 *
 * @param brightAlpha alpha of the red ("bright") layer; the dim base is always shown.
 * @param litAlpha    alpha of the white-centre-ᚱ ("bright_and_lit") layer.
 */
@Composable
private fun RunestonePages(brightAlpha: Float, litAlpha: Float) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .aspectRatio(1.4f),
        contentAlignment = Alignment.Center
    ) {
        // Dim runestone — always visible base layer.
        Image(
            painter = painterResource(id = R.drawable.runestone_dim),
            contentDescription = null,
            contentScale = ContentScale.Fit,
            modifier = Modifier.fillMaxSize()
        )
        // Bright (red) runestone — fades in.
        Image(
            painter = painterResource(id = R.drawable.runestone_bright),
            contentDescription = null,
            contentScale = ContentScale.Fit,
            modifier = Modifier
                .fillMaxSize()
                .alpha(brightAlpha * (1f - litAlpha))
        )
        // Lit runestone (white centre ᚱ) — fades in.
        Image(
            painter = painterResource(id = R.drawable.runestone_bright_and_lit),
            contentDescription = null,
            contentScale = ContentScale.Fit,
            modifier = Modifier
                .fillMaxSize()
                .alpha(litAlpha)
        )
    }
}
