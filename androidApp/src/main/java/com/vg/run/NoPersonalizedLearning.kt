package com.vg.run

import android.text.InputType
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputConnection
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.InterceptPlatformTextInput
import androidx.compose.ui.platform.PlatformTextInputInterceptor
import androidx.compose.ui.platform.PlatformTextInputMethodRequest
import androidx.compose.ui.platform.PlatformTextInputSession

/**
 * Wraps a text field so the keyboard is asked not to learn what is typed into it.
 *
 * WHY: `KeyboardOptions` has no way to set `EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING`
 * (the IME must not add the typed words to its learned dictionary or sync them) or
 * `InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS`. That dictionary lives in the keyboard
 * app, outside Rún's sandbox, and survives a wipe. So the flags are added here, at the
 * one point Compose exposes: the `EditorInfo` passed to `createInputConnection`.
 *
 * These are HINTS. Gboard and Samsung Keyboard honour them, but a third-party IME is
 * free to ignore them, and Android has no way for an app to refuse a given keyboard
 * (iOS can, through `shouldAllowExtensionPointIdentifier`). Fields that already use
 * `KeyboardType.Password` keep it; this adds the learning flag on top and does not
 * add NO_SUGGESTIONS to a password variation, which already has no suggestions.
 *
 * Two strengths, chosen per field by [keepSuggestions]:
 *  - secret fields (contact memory, group name, recovery code, bug report, move
 *    paste, debug code, proxy host/port) use the default: no learning AND no
 *    suggestion strip, so nothing typed there is even offered back as a suggestion;
 *  - the message composers pass `keepSuggestions = true`: no learning, but the
 *    suggestion strip and glide typing stay (Gboard turns glide typing off on a
 *    NO_SUGGESTIONS field), which is what everyday typing at the lower tiers needs.
 *
 * A composable wrapper and not a `Modifier`: [InterceptPlatformTextInput] (stable in
 * compose-ui 1.12, BOM 2026.09.00) intercepts every text input session started inside
 * its content, and Compose offers no modifier-level hook into another node's session.
 * It adds no layout node, so wrapping a field changes nothing on screen or in the
 * accessibility tree.
 */
@Composable
fun NoPersonalizedLearning(keepSuggestions: Boolean = false, content: @Composable () -> Unit) {
    val interceptor = remember(keepSuggestions) { NoPersonalizedLearningInterceptor(keepSuggestions) }
    InterceptPlatformTextInput(interceptor, content)
}

private class NoPersonalizedLearningInterceptor(
    private val keepSuggestions: Boolean,
) : PlatformTextInputInterceptor {
    override suspend fun interceptStartInputMethod(
        request: PlatformTextInputMethodRequest,
        nextHandler: PlatformTextInputSession,
    ): Nothing {
        val withFlags = object : PlatformTextInputMethodRequest {
            override fun createInputConnection(outAttributes: EditorInfo): InputConnection {
                // Let the field fill in its own attributes first, then add ours.
                val connection = request.createInputConnection(outAttributes)
                outAttributes.imeOptions = noLearningImeOptions(outAttributes.imeOptions)
                if (!keepSuggestions) {
                    outAttributes.inputType = noSuggestionsInputType(outAttributes.inputType)
                }
                return connection
            }
        }
        nextHandler.startInputMethod(withFlags)
    }
}

/** [imeOptions] plus `IME_FLAG_NO_PERSONALIZED_LEARNING`. */
internal fun noLearningImeOptions(imeOptions: Int): Int =
    imeOptions or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING

/**
 * [inputType] plus `TYPE_TEXT_FLAG_NO_SUGGESTIONS` when it is a non-password TEXT
 * input; unchanged otherwise (the flag is a text-class flag, and a password
 * variation already has no suggestions).
 */
internal fun noSuggestionsInputType(inputType: Int): Int {
    if (inputType and InputType.TYPE_MASK_CLASS != InputType.TYPE_CLASS_TEXT) return inputType
    val variation = inputType and InputType.TYPE_MASK_VARIATION
    val isPassword = variation == InputType.TYPE_TEXT_VARIATION_PASSWORD ||
        variation == InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD ||
        variation == InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD
    return if (isPassword) inputType else inputType or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
}
