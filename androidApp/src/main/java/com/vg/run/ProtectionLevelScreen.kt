package com.vg.run

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.Animatable
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.TextAutoSize
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vg.run.ui.theme.RunBlack
import com.vg.run.ui.theme.RunGrey
import com.vg.run.ui.theme.RunWhite
import kotlin.math.ceil
import kotlin.math.floor
import kotlin.math.roundToInt
import kotlinx.coroutines.launch

// ---------------------------------------------------------------------------
// ProtectionLevelScreen — the "Choose protection level" chooser
// (docs/threat-level-slider-spec.md). A dynamic, draggable three-stop slider
// (Decent · Secure · Maximum — the storageValue enum stays casual/private/maximum)
// whose runestone hero cross-fade-MORPHS between the three tier images as the
// thumb slides. Bare-forced at onboarding (no stop pre-selected, Continue disabled
// until one is picked); in Settings the current tier is pre-selected. Secure
// needs a hardware secure element AND enrolled biometrics; a phone without a lock
// screen forces Maximum — those stops grey out with a reason (DeviceLockPolicy)
// and the thumb turns grey + Apply disables when it rests on one.
//
// All copy (title / tier names / taglines / forced-notice) is single-sourced in
// shared/commonMain ProtectionLevelContent so Android and iOS can't drift; only
// the slider mechanics + hero morph are platform-specific.
// ---------------------------------------------------------------------------

private data class LevelCard(
    val level: ProtectionLevel,
    val accent: Color,
    val runestone: Int,      // per-level runestone art (plain → base ring → full forcefield)
)

private val LEVEL_CARDS = listOf(
    LevelCard(ProtectionLevel.CASUAL, Color(0xFF7B8590), R.drawable.runestone_dim),
    LevelCard(ProtectionLevel.PRIVATE, Color(0xFFD4463A), R.drawable.runestone_dim_ring),
    LevelCard(ProtectionLevel.MAXIMUM, Color(0xFFF1EADC), R.drawable.runestone_dim_forcefield),
)

// Device base security panel — temporarily disabled at the product's
// request. The panel code (DevicePanel + DeviceBaseline detection below) is kept
// intact; flip this to true to bring it back in the chooser.
private const val SHOW_DEVICE_BASELINE_PANEL = false

// Continuous slider geometry: for N equal-weight stops the dot centres sit at
// (i + 0.5) / N of the track width, so a position p in [0, N-1] maps to a centre
// x-fraction of (p + 0.5) / N (and back). Kept here so the thumb, the drag maths,
// and the hero blend all agree.
private fun posToCentreX(pos: Float, widthPx: Int): Float =
    (pos + 0.5f) / LEVEL_CARDS.size * widthPx

private fun centreXToPos(x: Float, widthPx: Int): Float =
    (x / widthPx * LEVEL_CARDS.size - 0.5f).coerceIn(0f, (LEVEL_CARDS.size - 1).toFloat())

@OptIn(androidx.compose.ui.ExperimentalComposeUiApi::class)
@Composable
fun ProtectionLevelScreen(
    viewModel: RunViewModel,
    currentLevel: ProtectionLevel?,      // null = onboarding (bare-forced); non-null = Settings
    confirmLabel: String,
    onConfirm: (ProtectionLevel) -> Unit,
    onBack: (() -> Unit)? = null,
) {
    val hwSupported = remember { viewModel.vaultSelector.supportsDbKeyAuthBinding() }
    // This actual device's identity + its own forensic baseline (real detection).
    val context = LocalContext.current
    val deviceModel = remember { "${android.os.Build.MANUFACTURER} ${android.os.Build.MODEL}".trim().replaceFirstChar { it.uppercase() } }
    val osLabel = remember { "Android ${android.os.Build.VERSION.RELEASE}" }
    val lockState = remember { deviceLockState(context) }
    val lockSet = lockState == DeviceLockState.Present
    // Splits Secure's two greyed sub-reasons: a real chip that just needs a
    // fingerprint/face enrolled ("Biometrics is missing") vs no secure hardware at
    // all ("This phone has no security chip"). iOS is always chip-present on real
    // devices; on Android we probe. (DeviceLockPolicy.stopReason 4th arg.)
    val secureElementPresent = remember { AuthBoundKeyStore.isSecureElementPresent(context) }
    // Non-null when this phone has NO lock screen: the device-key factor of CR-1
    // is then free to anyone holding it, so the passphrase tier is the only one
    // whose promise still holds (DeviceLockPolicy). Everything below it is a
    // greyed stop with its own reason, and the tier is pre-selected.
    val forcedLevel = remember { DeviceLockPolicy.forcedLevel(lockState) }
    val baseline = remember { DeviceBaseline.assess(lockSet = lockSet, secureElement = hwSupported, patchesCurrent = securityPatchIsCurrent()) }
    var selected by remember { mutableStateOf(forcedLevel ?: currentLevel) }
    // The forced tier's cost has to be ACKNOWLEDGED before it is applied — it
    // carries a 7-day inactivity self-wipe this user never opted into.
    var showForcedNotice by remember { mutableStateOf(false) }
    val selectedIndex = LEVEL_CARDS.indexOfFirst { it.level == selected }  // -1 when none

    // Continuous slider position (the draggable thumb), lifted here so the hero
    // morph can blend between adjacent runestones as it moves. Starts on the
    // pre-selected stop (or the first stone when nothing is picked yet, so the
    // chooser is never blank).
    var pos by remember { mutableFloatStateOf((if (selectedIndex >= 0) selectedIndex else 0).toFloat()) }
    var dragging by remember { mutableStateOf(false) }

    fun selectable(level: ProtectionLevel): Boolean =
        DeviceLockPolicy.isSelectable(level, lockState, hwSupported)

    // While the thumb is in motion the detail panel + label highlight follow it
    // live (round(pos)); at rest they follow the committed selection.
    val displayIndex = if (dragging) pos.roundToInt().coerceIn(0, LEVEL_CARDS.lastIndex) else selectedIndex
    val selectedSelectable = selected?.let { selectable(it) } ?: false

    // The reason a greyed tier can't be picked — shown ONLY when the CHOSEN /
    // displayed tier (the thumb's current stop) is itself unavailable, prefixed with
    // "Not possible to select level." A stop the user can act on ("set a lock screen",
    // "enroll biometrics") must name the fix; single-sourced in DeviceLockPolicy so
    // both platforms say the same thing.
    val stopReason = displayIndex.takeIf { it in LEVEL_CARDS.indices }
        ?.let { DeviceLockPolicy.stopReason(LEVEL_CARDS[it].level, lockState, hwSupported, secureElementPresent) }
        ?.let { "${ProtectionLevelContent.stopReasonPrefix} $it" }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .semantics { testTagsAsResourceId = BuildConfig.DEBUG }
            .background(RunBlack)
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .statusBarsPadding()
                .padding(horizontal = 24.dp)
                .verticalScroll(rememberScrollState()),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Spacer(Modifier.height(22.dp))
            Text(
                ProtectionLevelContent.title,
                style = MaterialTheme.typography.headlineSmall,
                color = RunWhite,
                textAlign = TextAlign.Center,
                modifier = Modifier.testTag("protection_level_title"),
            )
            Spacer(Modifier.height(16.dp))

            // Hero: the selected level's runestone — bare (Decent) → shielded (Secure)
            // → chained + locked (Maximum). MORPHS by cross-fading between the two
            // runestones the thumb currently straddles as it slides.
            LevelRunestone(pos = pos)

            Spacer(Modifier.height(18.dp))

            LevelSlider(
                pos = pos,
                onPosChange = { pos = it },
                dragging = dragging,
                onDraggingChange = { dragging = it },
                displayIndex = displayIndex,
                disabled = { i -> !selectable(LEVEL_CARDS[i].level) },
                onSelect = { i -> selected = LEVEL_CARDS[i].level },
            )

            if (stopReason != null) {
                Spacer(Modifier.height(12.dp))
                Text(
                    stopReason,
                    style = MaterialTheme.typography.bodySmall.copy(fontSize = 11.sp),
                    color = Color(0xFFD4463A),
                    textAlign = TextAlign.Center,
                    modifier = Modifier.testTag("protection_level_stop_reason"),
                )
            }

            Spacer(Modifier.height(22.dp))
            // Detail panel for the stop the thumb is on (or the empty state before
            // any pick).
            Box(
                Modifier
                    .fillMaxWidth()
                    .background(Color(0xFF14181F), RoundedCornerShape(14.dp))
                    .padding(18.dp),
            ) {
                if (displayIndex < 0) {
                    Text(
                        ProtectionLevelContent.emptyState,
                        color = RunGrey,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.fillMaxWidth(),
                    )
                } else {
                    // Name is already on the slider label above — show just the tagline.
                    Text(
                        ProtectionLevelContent.tagline(LEVEL_CARDS[displayIndex].level),
                        style = MaterialTheme.typography.bodySmall.copy(fontSize = 13.sp),
                        color = RunGrey,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
            }

            if (SHOW_DEVICE_BASELINE_PANEL) {
                Spacer(Modifier.height(18.dp))
                DevicePanel(model = deviceModel, os = osLabel, baseline = baseline)
            }

            Spacer(Modifier.height(20.dp))
            Button(
                onClick = {
                    // A tier the user did not choose has to be acknowledged first —
                    // it brings a 7-day inactivity self-wipe with it.
                    if (forcedLevel != null) showForcedNotice = true else selected?.let(onConfirm)
                },
                // Enabled only when a tier is picked AND it is actually selectable on
                // this device (the thumb can now rest on a greyed stop; Apply must not
                // commit one).
                enabled = selected != null && selectedSelectable,
                modifier = Modifier.fillMaxWidth().testTag("protection_level_confirm"),
                colors = ButtonDefaults.buttonColors(
                    containerColor = RunWhite,
                    contentColor = RunBlack,
                    disabledContainerColor = Color(0xFF20262F),
                    disabledContentColor = RunGrey,
                ),
            ) {
                // ONE line, never a mid-word break.
                // iOS sibling: ProtectionLevelView.swift's protection_level_confirm.
                Text(
                    if (selected == null) stringResource(R.string.protection_pick_a_level) else confirmLabel,
                    maxLines = 1,
                    softWrap = false,
                    autoSize = TextAutoSize.StepBased(minFontSize = 10.sp, maxFontSize = 16.sp, stepSize = 0.5.sp),
                )
            }
            if (onBack != null) {
                TextButton(onClick = onBack, modifier = Modifier.testTag("protection_level_back")) {
                    Text(stringResource(R.string.common_cancel), color = RunGrey)
                }
            }
            Spacer(Modifier.height(24.dp))
        }

        // Forced-tier notice. The security half is one sentence; the rest is the
        // COST, stated as what happens to the user rather than as a mechanism —
        // and the 7-day erase is body text with its own acknowledgment, not a
        // footnote, because it is the one irreversible consequence of a tier
        // they did not pick. The way out (set a passcode) is named in the same
        // breath, and sits in the reflex-safe left slot. Title + body single-sourced.
        if (showForcedNotice) {
            RuneDialog(
                // Consent gate (onDismissRequest = null): no back-press or
                // tap-outside dismissal — a forced tier must be answered.
                onDismissRequest = null,
                title = ProtectionLevelContent.forcedNoticeTitle,
                message = ProtectionLevelContent.forcedNoticeBody,
                testTag = "protection_forced_notice",
                actions = listOf(
                    runeSecondary(stringResource(R.string.common_not_now), testTag = "protection_forced_cancel") { showForcedNotice = false },
                    RuneDialogAction(
                        label = stringResource(R.string.common_understood),
                        testTag = "protection_forced_ack",
                        onClick = {
                            showForcedNotice = false
                            // Confirm the FORCED tier (same value by construction —
                            // the notice only opens when one exists), so this never
                            // depends on the selection surviving a recomposition.
                            (forcedLevel ?: selected)?.let(onConfirm)
                        },
                    ),
                ),
            )
        }
    }
}

@OptIn(androidx.compose.ui.ExperimentalComposeUiApi::class)
@Composable
private fun LevelRunestone(pos: Float) {
    val last = LEVEL_CARDS.lastIndex
    val p = pos.coerceIn(0f, last.toFloat())
    val lo = floor(p).toInt().coerceIn(0, last)
    val hi = ceil(p).toInt().coerceIn(0, last)
    val frac = (p - lo).coerceIn(0f, 1f)
    val nearest = p.roundToInt().coerceIn(0, last)
    // Two stacked runestones: the lower one full, the upper one at alpha=frac.
    // The PNGs are opaque + frame-aligned, so a whole-frame dissolve reads as the
    // ring/forcefield morphing in as you slide.
    Box(
        Modifier
            .height(250.dp)
            .clip(RoundedCornerShape(18.dp))
            .semantics { testTagsAsResourceId = BuildConfig.DEBUG }
            .testTag("protection_level_runestone"),
        contentAlignment = Alignment.Center,
    ) {
        Image(
            painter = painterResource(id = LEVEL_CARDS[lo].runestone),
            contentDescription = stringResource(
                R.string.protection_level_accessibility_label,
                ProtectionLevelContent.displayName(LEVEL_CARDS[nearest].level),
            ),
            contentScale = ContentScale.Fit,
            modifier = Modifier.height(250.dp),
        )
        if (hi != lo) {
            Image(
                painter = painterResource(id = LEVEL_CARDS[hi].runestone),
                contentDescription = null,
                contentScale = ContentScale.Fit,
                modifier = Modifier.height(250.dp).alpha(frac),
            )
        }
    }
}

@Composable
private fun LevelSlider(
    pos: Float,
    onPosChange: (Float) -> Unit,
    dragging: Boolean,
    onDraggingChange: (Boolean) -> Unit,
    displayIndex: Int,
    disabled: (Int) -> Boolean,
    onSelect: (Int) -> Unit,
) {
    val scope = rememberCoroutineScope()
    val density = LocalDensity.current
    val n = LEVEL_CARDS.size
    val last = LEVEL_CARDS.lastIndex
    var trackWidthPx by remember { mutableIntStateOf(0) }
    // Latest pos for the incremental drag callback (rememberDraggableState's lambda
    // would otherwise capture a stale value from first composition).
    val currentPos = rememberUpdatedState(pos)
    val thumbSize = 22.dp
    val thumbHalfPx = with(density) { (thumbSize / 2).toPx() }

    // Animate the thumb to a stop (tap or release-snap) while streaming each frame
    // back to the shared pos.
    fun animateTo(target: Int) {
        scope.launch {
            val anim = Animatable(currentPos.value)
            anim.animateTo(target.toFloat()) { onPosChange(value) }
        }
    }

    // Force LTR on the whole control (track, stops, thumb, AND labels together):
    // posToCentreX/centreXToPos and the drag maths operate on raw physical
    // pixels, so under an auto-mirrored RTL Row the visual stops and the math
    // would disagree (thumb tracks the wrong stop; drag runs backwards). A
    // numeric-style continuous position is direction-agnostic the same way the
    // PIN keypad is — forcing LTR here keeps thumb, stops, drag, and the labels
    // underneath all consistent, rather than making three separate call sites
    // (track math, thumb offset, drag callback) individually RTL-aware.
    CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
    Column(Modifier.fillMaxWidth()) {
        Box(
            Modifier
                .fillMaxWidth()
                .height(34.dp)
                .onSizeChanged { trackWidthPx = it.width }
                // Drag lives on the TRACK, not on the thumb: a thumb with its own
                // pointer handler draws on top of the stop cells and shadows a
                // coordinate tap on the stop it rests on (UiAutomator2 taps the
                // bounds-centre) — which broke onboarding tier selection at the Decent
                // rest position. detectDragGestures here coexists with the child stop
                // .clickable (a tap has no slop → only the click fires; a real drag
                // moves the thumb).
                .pointerInput(trackWidthPx) {
                    if (trackWidthPx <= 0) return@pointerInput
                    detectDragGestures(
                        onDragStart = { onDraggingChange(true) },
                        onDragEnd = {
                            onDraggingChange(false)
                            val target = currentPos.value.roundToInt().coerceIn(0, last)
                            animateTo(target)
                            onSelect(target)
                        },
                        onDragCancel = {
                            onDraggingChange(false)
                            val target = currentPos.value.roundToInt().coerceIn(0, last)
                            animateTo(target)
                            onSelect(target)
                        },
                        onDrag = { change, _ ->
                            change.consume()
                            onPosChange(centreXToPos(change.position.x, trackWidthPx))
                        },
                    )
                },
        ) {
            // Track line — spans the outer dot centres ((N-1)/N of the width).
            Box(
                Modifier
                    .align(Alignment.Center)
                    .fillMaxWidth((n - 1f) / n)
                    .height(2.dp)
                    .background(Color(0xFF2A313C)),
            )
            // Fixed anchor stops: each a full-height tap target keeping its
            // level_${storageValue} a11y id (the cross suites tap these to pick a
            // tier). Tap animates the thumb over and commits the tier.
            Row(Modifier.fillMaxWidth().fillMaxHeight()) {
                LEVEL_CARDS.forEachIndexed { i, c ->
                    val off = disabled(i)
                    Box(
                        Modifier
                            .weight(1f)
                            .fillMaxHeight()
                            .clickable {
                                animateTo(i)
                                onSelect(i)
                            }
                            .testTag("level_${c.level.storageValue}"),
                        contentAlignment = Alignment.Center,
                    ) {
                        Box(
                            Modifier
                                .size(8.dp)
                                .clip(CircleShape)
                                .background(if (off) Color(0xFF20262F) else Color(0xFF3A424E)),
                        )
                    }
                }
            }
            // Thumb — VISUAL ONLY (no pointer handler), so it never shadows a stop's
            // coordinate tap; the drag is handled by the track's detectDragGestures
            // above. White while dragging and when it rests on a selectable tier; grey
            // when it rests on an unavailable one (Apply is disabled then).
            if (trackWidthPx > 0) {
                val landed = pos.roundToInt().coerceIn(0, last)
                val thumbWhite = dragging || !disabled(landed)
                val centreX = posToCentreX(pos, trackWidthPx)
                Box(
                    Modifier
                        .align(Alignment.CenterStart)
                        .offset { IntOffset((centreX - thumbHalfPx).roundToInt(), 0) }
                        .size(thumbSize)
                        .clip(CircleShape)
                        .background(if (thumbWhite) RunWhite else Color(0xFF606A76))
                        .border(2.dp, if (thumbWhite) RunWhite else Color(0xFF2A313C), CircleShape),
                )
            }
        }
        Spacer(Modifier.height(6.dp))
        // Labels, centred under each stop (Decent / Secure / Maximum).
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            LEVEL_CARDS.forEachIndexed { i, c ->
                val off = disabled(i)
                val isSel = i == displayIndex
                Box(Modifier.weight(1f), contentAlignment = Alignment.Center) {
                    Text(
                        ProtectionLevelContent.displayName(c.level),
                        fontSize = 10.sp,
                        color = when { off -> Color(0xFF606A76); isSel -> RunWhite; else -> RunGrey },
                        textAlign = TextAlign.Center,
                    )
                }
            }
        }
    }
    }
}

@Composable
private fun DevicePanel(model: String, os: String, baseline: DeviceBaselineTier) {
    val sevColor = if (DeviceBaseline.severity(baseline) == "bad") Color(0xFFE0524A) else Color(0xFFD9A441)
    var expanded by remember { mutableStateOf(false) }
    Box(
        Modifier.fillMaxWidth().background(Color(0xFF14181F), RoundedCornerShape(10.dp)).padding(12.dp)
            .testTag("device_baseline_panel"),
    ) {
        Column {
            // Header — always visible; tap to expand. The tier label gives an at-a-glance
            // status without opening, keeping the chooser short by default.
            Row(
                Modifier.fillMaxWidth().clickable { expanded = !expanded }.testTag("device_baseline_toggle"),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    stringResource(R.string.protection_device_panel_title),
                    fontSize = 12.sp, fontWeight = FontWeight.Medium, color = RunWhite,
                    modifier = Modifier.weight(1f),
                )
                Text(
                    DeviceBaseline.label(baseline),
                    fontFamily = FontFamily.Monospace, fontSize = 11.sp,
                    fontWeight = FontWeight.SemiBold, color = sevColor,
                )
                Spacer(Modifier.size(8.dp))
                // Collapsed glyph points toward reading-start: "▸" under LTR,
                // "◂" under RTL (mirrors iOS's chevron.forward). Expanded stays "▾".
                val collapsedGlyph = if (LocalLayoutDirection.current == LayoutDirection.Rtl) "◂" else "▸"
                Text(if (expanded) "▾" else collapsedGlyph, fontSize = 12.sp, color = Color(0xFF808A96))
            }
            AnimatedVisibility(visible = expanded) {
                Column {
                    Spacer(Modifier.height(11.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(stringResource(R.string.protection_device_panel_detected_label), fontFamily = FontFamily.Monospace, fontSize = 8.5.sp, color = Color(0xFF606A76))
                        Spacer(Modifier.size(8.dp))
                        Text(stringResource(R.string.protection_device_panel_detected_value, model, os), fontFamily = FontFamily.Monospace, fontSize = 10.5.sp, color = RunGrey)
                    }
                    Spacer(Modifier.height(9.dp))
                    Box(Modifier.fillMaxWidth().height(1.dp).background(Color(0xFF20262F)))
                    Spacer(Modifier.height(9.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(stringResource(R.string.protection_device_panel_baseline_label), fontFamily = FontFamily.Monospace, fontSize = 8.5.sp, color = Color(0xFF606A76))
                        Spacer(Modifier.size(8.dp))
                        repeat(4) { i ->
                            Box(
                                Modifier.size(width = 15.dp, height = 5.dp).clip(RoundedCornerShape(2.dp))
                                    .background(if (i < DeviceBaseline.fill(baseline)) sevColor else Color(0xFF2A313C)),
                            )
                            Spacer(Modifier.size(3.dp))
                        }
                    }
                    Spacer(Modifier.height(8.dp))
                    Text(DeviceBaseline.note(baseline), fontSize = 11.sp, color = RunGrey)
                    Spacer(Modifier.height(8.dp))
                    Text(DeviceBaseline.CAVEAT, fontSize = 9.5.sp, color = Color(0xFF606A76))
                }
            }
        }
    }
}

// Security-patch currency: current if the platform SECURITY_PATCH date is within
// ~6 months. Unknown/unparseable → don't penalize.
private fun securityPatchIsCurrent(): Boolean = try {
    val p = android.os.Build.VERSION.SECURITY_PATCH.split("-")   // "yyyy-MM-dd"
    val cal = java.util.Calendar.getInstance()
    val monthsBehind = (cal.get(java.util.Calendar.YEAR) - p[0].toInt()) * 12 +
        (cal.get(java.util.Calendar.MONTH) + 1 - p[1].toInt())
    monthsBehind <= 6
} catch (_: Exception) { true }
