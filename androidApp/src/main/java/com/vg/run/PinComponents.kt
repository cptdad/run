package com.vg.run

import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.keyframes
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTag
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import com.vg.run.ui.theme.RunError
import com.vg.run.ui.theme.RunGrey
import com.vg.run.ui.theme.RunSurface
import com.vg.run.ui.theme.RunWhite
import kotlin.math.roundToInt
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation

// ---------------------------------------------------------------------------
// Shared PIN UI components used by both PinEntryScreen and PinSetupScreen.
//
// Security purpose: sharing the exact same visual components ensures that
// an observer watching the screen during setup cannot distinguish the setup
// flow from the unlock flow based on keypad appearance, dot size, or layout.
// ---------------------------------------------------------------------------

/** Number of PIN digits required. */
// B6a: single-sourced from commonMain CredentialPolicy so Android + iOS agree.
val PIN_LENGTH: Int = CredentialPolicy.PIN_LENGTH

// ---------------------------------------------------------------------------
// Dot indicators
// ---------------------------------------------------------------------------

/**
 * A row of [PIN_LENGTH] circular dot indicators.
 *
 * Security purpose: dots are used instead of digit echo so that entered
 * digits are never visible on screen, defeating shoulder-surfing attacks.
 *
 * @param filledCount  How many dots to show as filled (left to right).
 * @param errorFlash   When true, all dots turn red (error feedback).
 * @param shakeOffset  Animatable driving horizontal shake displacement.
 */
@Composable
fun PinDotRow(
    filledCount: Int,
    errorFlash: Boolean,
    shakeOffset: Animatable<Float, *>
) {
    Box {
        Row(
            modifier = Modifier
                .semantics { testTag = "pin_dots" }
                .offset { IntOffset(shakeOffset.value.roundToInt(), 0) },
            horizontalArrangement = Arrangement.spacedBy(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            repeat(PIN_LENGTH) { index ->
                val filled = index < filledCount
                val color = when {
                    errorFlash -> RunError
                    filled     -> RunWhite
                    else       -> RunGrey.copy(alpha = 0.3f)
                }
                Box(
                    modifier = Modifier
                        .size(14.dp)
                        .clip(CircleShape)
                        .background(color)
                )
            }
        }
        // Invisible entered-digit count, exposed as the Text's TEXT (which
        // uiautomator2/XCUITest read reliably — unlike a Compose
        // contentDescription) so e2e can verify each keypad tap registered:
        // deterministic PIN entry. The dots already show this visually; this
        // reveals the count, never the digits.
        // DEBUG-only: in release this node would still publish the
        // digit-COUNT into the accessibility tree (readable by a malicious a11y
        // service), so gate it out of production — e2e runs on debug builds.
        if (BuildConfig.DEBUG) {
            Text(
                text = filledCount.toString(),
                color = Color.Transparent,
                modifier = Modifier.semantics { testTag = "pin_count" }
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Numeric keypad
// ---------------------------------------------------------------------------

/**
 * A 4x3 custom numeric keypad (1-9, blank, 0, delete).
 *
 * Security purpose: using a Composable keypad instead of the system keyboard
 * prevents third-party IMEs, clipboard managers, and accessibility loggers
 * from intercepting entered digits. No InputMethodService is ever invoked.
 *
 * @param onDigit  Called with the digit character ('0'-'9') when a number is pressed.
 * @param onDelete Called when the delete key is pressed.
 * @param enabled  When false, all key presses are ignored (used while auto-submit is pending).
 */
@Composable
fun PinKeypad(
    onDigit: (Char) -> Unit,
    onDelete: () -> Unit,
    enabled: Boolean = true
) {
    val haptic = LocalHapticFeedback.current

    val rows = listOf(
        listOf("1", "2", "3"),
        listOf("4", "5", "6"),
        listOf("7", "8", "9"),
        listOf("", "0", "DEL")
    )

    // Force LTR on just the grid: a numeric keypad is direction-agnostic (like
    // the system dialer), and Compose auto-mirroring the Row/Column under an
    // RTL locale (ar/fa) would scramble the 1-2-3 / 4-5-6 / 7-8-9 layout.
    // Scoped to this Composable only — the rest of the screen (labels, etc.)
    // stays reading-direction-aware.
    CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
        Column(
            verticalArrangement = Arrangement.spacedBy(12.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            rows.forEach { row ->
                Row(
                    horizontalArrangement = Arrangement.spacedBy(24.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    row.forEach { key ->
                        KeypadButton(
                            label = key,
                            onClick = {
                                if (!enabled) return@KeypadButton
                                haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                when (key) {
                                    "DEL" -> onDelete()
                                    ""    -> { /* blank spacer */ }
                                    else  -> onDigit(key[0])
                                }
                            }
                        )
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Single keypad button
// ---------------------------------------------------------------------------

@Composable
internal fun KeypadButton(
    label: String,
    onClick: () -> Unit
) {
    // Empty label = invisible spacer (bottom-left cell in the 4x3 grid).
    if (label.isEmpty()) {
        Spacer(Modifier.size(72.dp))
        return
    }

    val displayText = if (label == "DEL") "\u232B" else label
    val tag = if (label == "DEL") "key_delete" else "key_$label"

    Box(
        modifier = Modifier
            .semantics { testTag = tag }
            .size(72.dp)
            .clip(RoundedCornerShape(36.dp))
            .background(RunSurface.copy(alpha = 0.4f))
            .clickable(
                interactionSource = remember { MutableInteractionSource() },
                indication = null,
                onClick = onClick
            ),
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = displayText,
            style = MaterialTheme.typography.headlineMedium,
            color = if (label == "DEL") RunGrey else Color.White.copy(alpha = 0.9f)
        )
    }
}

// ---------------------------------------------------------------------------
// Passphrase input (high-risk mode — hardening plan Lever A)
// ---------------------------------------------------------------------------

/**
 * Secure free-text credential field for passphrase mode.
 *
 * Security: `KeyboardType.Password` + autoCorrect=false keep the passphrase
 * out of IME learning/prediction dictionaries (the same no-IME-learning
 * discipline used for contact mnemonics), and `PasswordVisualTransformation`
 * masks it on screen. Unlike the PIN keypad this necessarily uses the system
 * keyboard — a hostile third-party IME could observe input, which is already
 * true for every other text the user types into the app and is out of scope
 * (the threat here is the SEIZED device, not a live keylogger).
 */
@Composable
fun PassphraseInputField(
    value: String,
    onValueChange: (String) -> Unit,
    placeholder: String,
    fieldTag: String,
    enabled: Boolean = true,
    isError: Boolean = false,
    onDone: (() -> Unit)? = null,
) {
    OutlinedTextField(
        value = value,
        onValueChange = { if (it.length <= CredentialPolicy.MAX_PASSPHRASE_LENGTH) onValueChange(it) },
        enabled = enabled,
        isError = isError,
        singleLine = true,
        placeholder = { Text(placeholder, color = RunGrey) },
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(
            keyboardType = KeyboardType.Password,
            autoCorrectEnabled = false,
            imeAction = if (onDone != null) ImeAction.Done
                        else ImeAction.Default,
        ),
        keyboardActions = KeyboardActions(
            onDone = { onDone?.invoke() }
        ),
        colors = OutlinedTextFieldDefaults.colors(
            focusedTextColor = RunWhite,
            unfocusedTextColor = RunWhite,
            focusedContainerColor = RunSurface.copy(alpha = 0.4f),
            unfocusedContainerColor = RunSurface.copy(alpha = 0.4f),
            cursorColor = RunWhite,
            focusedBorderColor = RunGrey,
            unfocusedBorderColor = RunGrey.copy(alpha = 0.5f),
            errorBorderColor = RunError,
        ),
        modifier = Modifier
            .fillMaxWidth()
            .semantics { testTag = fieldTag },
    )
}

/**
 * Strength meter for a candidate passphrase: four segments driven by
 * [CredentialPolicy.strengthBucket], with the enforced floor sitting on
 * the fair→strong boundary so "the bar turns green enough" and "the continue
 * button enables" always agree.
 */
@Composable
fun PassphraseStrengthMeter(passphrase: String) {
    val bits = CredentialPolicy.estimateBits(passphrase)
    val bucket = CredentialPolicy.strengthBucket(bits)
    val meetsFloor = CredentialPolicy.meetsFloor(passphrase)
    val (label, color) = when {
        passphrase.isEmpty() -> "" to RunGrey
        bucket <= 0 -> stringResource(R.string.pin_strength_too_weak) to RunError
        bucket == 1 -> stringResource(R.string.pin_strength_still_weak) to RunError
        bucket == 2 -> stringResource(R.string.pin_strength_strong) to Color(0xFF66BB6A)
        else -> stringResource(R.string.pin_strength_excellent) to Color(0xFF66BB6A)
    }
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
            repeat(4) { i ->
                val filled = passphrase.isNotEmpty() && i <= bucket && (i < 2 || meetsFloor)
                Box(
                    modifier = Modifier
                        .size(width = 40.dp, height = 4.dp)
                        .clip(RoundedCornerShape(2.dp))
                        .background(
                            when {
                                !filled -> RunGrey.copy(alpha = 0.3f)
                                meetsFloor -> Color(0xFF66BB6A)
                                else -> RunError
                            }
                        )
                )
            }
        }
        if (label.isNotEmpty()) {
            Spacer(Modifier.size(6.dp))
            Text(
                text = label,
                style = MaterialTheme.typography.bodySmall,
                color = color,
                modifier = Modifier.semantics { testTag = "passphrase_strength" }
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Shake animation helper
// ---------------------------------------------------------------------------

/**
 * Plays the standard horizontal shake animation on the given [Animatable].
 * Used for wrong-PIN feedback on both the entry and setup screens.
 */
suspend fun playShakeAnimation(shakeOffset: Animatable<Float, *>) {
    shakeOffset.animateTo(
        targetValue = 0f,
        animationSpec = keyframes {
            durationMillis = 400
            0f at 0
            -18f at 50
            18f at 100
            -14f at 150
            14f at 200
            -8f at 250
            8f at 300
            -4f at 350
            0f at 400
        }
    )
}
