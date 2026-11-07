package com.vg.run

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.LocalTextStyle
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.foundation.text.TextAutoSize
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.rememberTextMeasurer
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.vg.run.ui.theme.RunBlack
import com.vg.run.ui.theme.RuneAsh
import com.vg.run.ui.theme.RuneBorderBright
import com.vg.run.ui.theme.RuneBorderDim
import com.vg.run.ui.theme.RuneCardFill
import com.vg.run.ui.theme.RuneDanger
import com.vg.run.ui.theme.RuneGold
import com.vg.run.ui.theme.RuneHairline
import com.vg.run.ui.theme.RuneParchment

// ---------------------------------------------------------------------------
// RuneDialog — the single modal chrome for every popup (artist mock
// 2026-07-20): a dark stone card with a worn light border, centered uppercase
// Metamorphous text in parchment, a full-width hairline, and a divider-split
// action row. iOS mirrors this in UIComponents.swift; keep the two in visual
// lockstep.
//
// ACTION ORDER IS A SAFETY RULE, not a style choice. Actions render left→right
// in list order, and:
//
//   * A DESTRUCTIVE action (delete / leave / block / reduce-protection) must
//     ALWAYS be LAST — never the leftmost cell. Muscle memory from every other
//     app puts Cancel on the left, so a destructive action there gets tapped by
//     reflex. In this app the leftmost cell is NEVER destructive.
//   * When a dialog HAS a destructive action, the dismissive one ("Cancel",
//     "Keep current") goes FIRST, so the reflex tap lands on the safe choice.
//   * Otherwise follow the mock: the affirmative action first (left), the
//     dismissive one second (e.g. APPROVE | DECLINE).
//   * STACKED fallback (2026-09-29, see RuneActionRow below): when the row
//     can't fit side by side, actions render top→bottom in the SAME list
//     order instead of left→right. The safe slot is still index 0 — it just
//     moves from "leftmost" to "topmost", because a reflex tap on a vertical
//     list lands on the first row exactly like it lands on the first column.
// ---------------------------------------------------------------------------

/** One action cell in the divider-split row. [testTag] lands as a resource-id. */
data class RuneDialogAction(
    val label: String,
    val onClick: () -> Unit,
    val color: Color = RuneGold,
    val enabled: Boolean = true,
    val testTag: String? = null,
)

/**
 * The bare bordered stone card, for the in-screen scrim overlays (contact
 * menu, confirms, pickers) so they share the dialog chrome exactly.
 */
@Composable
fun RuneCard(
    modifier: Modifier = Modifier,
    horizontalAlignment: Alignment.Horizontal = Alignment.Start,
    contentPadding: PaddingValues = PaddingValues(0.dp),
    fill: Color = RuneCardFill,
    content: @Composable ColumnScope.() -> Unit,
) {
    val shape = RoundedCornerShape(22.dp)
    Column(
        modifier = modifier
            .clip(shape)
            .background(fill)
            .border(
                width = 2.dp,
                brush = Brush.verticalGradient(listOf(RuneBorderBright, RuneBorderDim)),
                shape = shape,
            )
            .padding(contentPadding),
        horizontalAlignment = horizontalAlignment,
        content = content,
    )
}

/** Scrim opacity of the in-screen overlays ([RuneScrimOverlay]). */
private const val SCRIM_ALPHA = 0.8f

/**
 * In-window (NOT a Dialog window) full-screen scrim + centred [RuneCard]. Kept
 * in-tree on purpose: the lock idle clock sees taps on it, and it sits under the
 * screen's testTagsAsResourceId root. Tapping the scrim, or card area no child
 * consumes, calls [onDismiss].
 *
 * [testTag] goes on the SCRIM node, before `.background` (the e2e ids such as
 * `delete_alert` / `mnemonic_alert` name the scrim). [imePadding] is applied LAST,
 * for overlays holding a text field. The modifier chain is node-for-node the one
 * the call sites used to spell out by hand (`Modifier.then(Modifier)` is a no-op).
 */
@Composable
internal fun RuneScrimOverlay(
    onDismiss: () -> Unit,
    testTag: String? = null,
    imePadding: Boolean = false,
    cardModifier: Modifier = Modifier.padding(32.dp),
    content: @Composable ColumnScope.() -> Unit,
) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .then(if (testTag != null) Modifier.testTag(testTag) else Modifier)
            .background(RunBlack.copy(alpha = SCRIM_ALPHA))
            .clickable(onClick = onDismiss)
            .then(if (imePadding) Modifier.imePadding() else Modifier),
        contentAlignment = Alignment.Center,
    ) {
        RuneCard(modifier = cardModifier, content = content)
    }
}

/** Centered uppercase dialog title in parchment. */
@Composable
fun RuneDialogTitle(text: String, modifier: Modifier = Modifier, maxLines: Int = Int.MAX_VALUE) {
    Text(
        text.uppercase(),
        color = RuneParchment,
        fontSize = 19.sp,
        letterSpacing = 1.5.sp,
        textAlign = TextAlign.Center,
        maxLines = maxLines,
        overflow = TextOverflow.Ellipsis,
        modifier = modifier,
    )
}

/** Centered uppercase dialog body text in parchment, mock line spacing. */
@Composable
fun RuneDialogMessage(text: String, modifier: Modifier = Modifier) {
    Text(
        text.uppercase(),
        color = RuneParchment,
        fontSize = 13.sp,
        lineHeight = 24.sp,
        letterSpacing = 0.4.sp,
        textAlign = TextAlign.Center,
        modifier = modifier,
    )
}

/**
 * The card's padded content column — shared spacing for dialogs + overlays.
 *
 * Bounded + scrollable. A dialog message can embed a peer-supplied
 * string (e.g. a group's eclipse-warning message interpolates the inviter's
 * claimed group name) that is capped in CHARACTERS but not in rendered
 * height — a name with no spaces, or one long enough after wrapping, could
 * otherwise push a trailing safety clause (or the action row below this
 * Column) out of the visible dialog. The height cap only engages once
 * content actually exceeds it, so an ordinary short dialog renders exactly
 * as before. iOS mirrors this in UIComponents.swift's ScrollView + maxHeight
 * — keep the two in step.
 */
@Composable
fun RuneCardBody(modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
    val maxHeight = (LocalConfiguration.current.screenHeightDp * 0.55f).dp
    Column(
        modifier = modifier
            .fillMaxWidth()
            .heightIn(max = maxHeight)
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 24.dp, vertical = 26.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(14.dp),
        content = content,
    )
}

/** The floor autosize may shrink a label to — see RuneActionRow below. */
private val RuneActionLabelFloor = 14.sp
private val RuneActionLabelCeiling = 19.sp

/**
 * Hairline + action cells, side by side (equal-width columns) when every
 * label fits at the readable floor, else STACKED (full-width rows) when one
 * doesn't.
 *
 * 2026-09-29: the update nudge's store label ("Öppna Google Play" / "Открыть
 * Google Play" / … — the string is long in every locale, see
 * ContactListScreen.kt's nudge call site) no longer fits a half-width cell
 * even at the old 10sp autosize floor, so it clipped ("ÖPPNA GOOGLE PLA").
 * Shrinking further isn't the fix — 10sp is already below comfortable
 * reading size, and the mid-word-break alternative was already rejected
 * (2026-09-11, see the ordering-rule comment above). Instead we MEASURE each
 * label (uppercased, actual letterSpacing, at the READABLE FLOOR of 14sp)
 * against its real equal-width cell before committing to the side-by-side
 * row; if any label wouldn't fit there, the whole row falls back to a
 * STACKED layout — one full-width cell per action, hairlines between rows
 * instead of columns — where the same floor always fits. Labels are NEVER
 * broken mid-word in either layout; autosize still ranges up to 19sp when
 * there's room. iOS sibling: UIComponents.swift's RuneActionRow.
 */
@OptIn(androidx.compose.ui.ExperimentalComposeUiApi::class)
@Composable
fun RuneActionRow(actions: List<RuneDialogAction>, topHairline: Boolean = true) {
    if (actions.isEmpty()) return
    if (topHairline) Box(Modifier.fillMaxWidth().height(1.dp).background(RuneHairline))
    val density = LocalDensity.current
    val textMeasurer = rememberTextMeasurer()
    val floorStyle = LocalTextStyle.current.merge(
        TextStyle(fontSize = RuneActionLabelFloor, letterSpacing = 1.5.sp),
    )
    BoxWithConstraints(Modifier.fillMaxWidth()) {
        val n = actions.size
        val totalWidthPx = with(density) { maxWidth.toPx() }
        val hairlinesPx = with(density) { 1.dp.toPx() } * (n - 1)
        val cellWidthPx = (totalWidthPx - hairlinesPx) / n
        val cellHorizontalPaddingPx = with(density) { (8.dp * 2).toPx() }
        val availableTextWidthPx = (cellWidthPx - cellHorizontalPaddingPx).coerceAtLeast(0f)
        val fitsSideBySide = actions.all { action ->
            textMeasurer.measure(
                text = AnnotatedString(action.label.uppercase()),
                style = floorStyle,
                softWrap = false,
                maxLines = 1,
            ).size.width <= availableTextWidthPx
        }
        if (fitsSideBySide) {
            Row(Modifier.fillMaxWidth().height(IntrinsicSize.Min)) {
                actions.forEachIndexed { i, action ->
                    if (i > 0) Box(Modifier.width(1.dp).fillMaxHeight().background(RuneHairline))
                    RuneActionCell(action, Modifier.weight(1f).fillMaxHeight())
                }
            }
        } else {
            Column(Modifier.fillMaxWidth()) {
                actions.forEachIndexed { i, action ->
                    if (i > 0) Box(Modifier.fillMaxWidth().height(1.dp).background(RuneHairline))
                    RuneActionCell(action, Modifier.fillMaxWidth())
                }
            }
        }
    }
}

/** One action cell — shared by the side-by-side and stacked layouts above. */
@Composable
private fun RuneActionCell(action: RuneDialogAction, modifier: Modifier) {
    val tag = action.testTag?.let { Modifier.testTag(it) } ?: Modifier
    // A SEPARATE testTag on the label itself (not just the clickable cell), so
    // e2e geometry checks (update-nudge-layout.spec.ts) can measure the
    // rendered label's own bounds independently of the button's — e.g. "is
    // the label fully inside its button, and not shrunk relative to its
    // sibling's label". A bare Text testTag survives Compose's clickable
    // merge as its own queryable node — same precedent as ContactListScreen.kt's
    // contact_name_${id} nested inside its clickable row.
    val labelTag = action.testTag?.let { Modifier.testTag("${it}_label") } ?: Modifier
    Box(
        modifier = modifier
            .clickable(enabled = action.enabled, onClick = action.onClick)
            .then(tag)
            .padding(vertical = 18.dp, horizontal = 8.dp),
        contentAlignment = Alignment.Center,
    ) {
        // ONE line, never a mid-word break ("Understood" rendered as "UNDERSTO / OD" on a half-width
        // button): the label shrinks to fit instead of wrapping.
        // iOS sibling: UIComponents.swift runeDialog's action Text
        // (lineLimit(1) + minimumScaleFactor).
        Text(
            action.label.uppercase(),
            color = if (action.enabled) action.color else action.color.copy(alpha = 0.4f),
            letterSpacing = 1.5.sp,
            textAlign = TextAlign.Center,
            maxLines = 1,
            softWrap = false,
            autoSize = TextAutoSize.StepBased(
                minFontSize = RuneActionLabelFloor,
                maxFontSize = RuneActionLabelCeiling,
                stepSize = 0.5.sp,
            ),
            modifier = labelTag,
        )
    }
}

/**
 * The modal itself — a [Dialog] window (inherits FLAG_SECURE, handles back)
 * holding a [RuneCard]. `onDismissRequest = null` makes it a consent gate:
 * no back-press or tap-outside dismissal. [content] slots custom UI (chip
 * lists, text fields) between the message and the action row.
 *
 * [actions] render left→right in list order — see the ordering SAFETY RULE at
 * the top of this file before adding a destructive one.
 */
@OptIn(androidx.compose.ui.ExperimentalComposeUiApi::class)
@Composable
fun RuneDialog(
    onDismissRequest: (() -> Unit)?,
    modifier: Modifier = Modifier,
    title: String? = null,
    message: String? = null,
    actions: List<RuneDialogAction> = emptyList(),
    testTag: String? = null,
    // Optional a11y hooks for the title/message text nodes, threaded straight
    // to RuneDialogTitle/RuneDialogMessage's own `modifier` param — null at
    // every existing call site (unchanged behavior); the update nudge
    // (ContactListScreen.kt) is the first caller to need one, so e2e geometry
    // checks can measure the message's own rendered bounds (there is no
    // separate title on that dialog). iOS sibling: UIComponents.swift's
    // `.runeDialog(messageA11yId:)`.
    titleTestTag: String? = null,
    messageTestTag: String? = null,
    content: (@Composable ColumnScope.() -> Unit)? = null,
) {
    Dialog(
        onDismissRequest = onDismissRequest ?: {},
        properties = DialogProperties(
            dismissOnBackPress = onDismissRequest != null,
            dismissOnClickOutside = onDismissRequest != null,
        ),
    ) {
        val tag = testTag?.let { Modifier.testTag(it) } ?: Modifier
        RuneCard(
            modifier = modifier
                .fillMaxWidth()
                // A Dialog is its own window, so taps in here never reach
                // Activity.onUserInteraction — without this, interacting with any
                // modal reads as idle and the Lever-C auto-lock closes the app
                // mid-use. Hooked at the shared chrome so every RuneDialog gets it.
                .keepUnlockedOnInteraction()
                .semantics { testTagsAsResourceId = BuildConfig.DEBUG }
                .then(tag),
        ) {
            RuneCardBody {
                title?.let {
                    RuneDialogTitle(it, modifier = titleTestTag?.let { t -> Modifier.testTag(t) } ?: Modifier)
                }
                message?.let {
                    RuneDialogMessage(it, modifier = messageTestTag?.let { t -> Modifier.testTag(t) } ?: Modifier)
                }
                content?.invoke(this)
            }
            RuneActionRow(actions)
        }
    }
}

/** Convenience secondary ("cancel"-flavoured) action in ash grey. */
fun runeSecondary(label: String, testTag: String? = null, onClick: () -> Unit) =
    RuneDialogAction(label = label, onClick = onClick, color = RuneAsh, testTag = testTag)

/**
 * Convenience DESTRUCTIVE action in ember red. Per the ordering safety rule at
 * the top of this file, one of these must always be LAST in the actions list.
 */
fun runeDestructive(label: String, testTag: String? = null, onClick: () -> Unit) =
    RuneDialogAction(label = label, onClick = onClick, color = RuneDanger, testTag = testTag)
