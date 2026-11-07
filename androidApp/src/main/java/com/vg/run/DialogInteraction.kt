package com.vg.run

import androidx.compose.runtime.Composable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.pointer.PointerEventPass
import androidx.compose.ui.input.pointer.pointerInput

// ---------------------------------------------------------------------------
// Feeding the Lever-C idle clock from dialogs.
//
// The foreground auto-lock measures idle time via Activity.onUserInteraction.
// A Compose Dialog (and Popup) renders in its OWN WINDOW, so touches inside it
// are dispatched to that window and NEVER reach the Activity callback. A user
// actively reading and tapping the About carousel, the Donate / Play tip flow,
// a referral picker or a group-invite dialog therefore looked completely idle:
// after AUTO_LOCK_TIMEOUT_MS (as little as 60 s on MAXIMUM) the app hard-closed
// mid-interaction, and because the countdown warning rendered in a Popup UNDER
// the open dialog, there was not even a visible warning first.
//
// Every dialog surface funnels its pointer events through the modifier below,
// which resets the same idle clock a direct screen touch would. It observes on
// the INITIAL pass and consumes nothing, so dialog buttons, scrolling and text
// fields behave exactly as before.
// ---------------------------------------------------------------------------

/**
 * Resets the foreground inactivity clock, as a real screen touch does. Provided
 * by MainActivity; the no-op default keeps previews, tests and any non-Activity
 * host working without wiring.
 */
val LocalKeepUnlocked = staticCompositionLocalOf<() -> Unit> { {} }

/**
 * Treat any pointer activity in this subtree as user interaction for the
 * Lever-C idle clock. Apply to the ROOT of every separate-window surface
 * (Dialog / Popup content) — in-activity content already reports through
 * `Activity.onUserInteraction` and does not need it.
 */
@Composable
fun Modifier.keepUnlockedOnInteraction(): Modifier {
    val keepUnlocked = LocalKeepUnlocked.current
    return this.pointerInput(keepUnlocked) {
        awaitPointerEventScope {
            while (true) {
                // Initial pass = observe before children; nothing is consumed, so
                // this is purely a tap on the shoulder for the idle clock.
                awaitPointerEvent(PointerEventPass.Initial)
                keepUnlocked()
            }
        }
    }
}
