package com.vg.run

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp

/**
 * Invisible test marker tracking whether the `runestone_bright_and_lit`
 * background is allowed to show. Emits a 24×24 dp Box whose test tag is
 * `runestone_lit_active` when the relay is reachable, `runestone_lit_inactive`
 * otherwise. Covered by the unit test in
 * androidTest/java/com/vg/run/RunestoneLitMarkerTest.kt.
 *
 * NOTE: This marker does NOT reliably surface to UiAutomator2 in e2e tests
 * because Compose's accessibility delegate filters out small bare Boxes
 * with no a11y-meaningful content. The screen-level visual verification
 * lives in the iOS counterpart via the cross:multi spec; the Android
 * lit-runestone gate is asserted at the unit level only.
 */
@Composable
fun RunestoneLitMarker(active: Boolean) {
    if (active) {
        Box(modifier = Modifier.size(24.dp).testTag("runestone_lit_active"))
    } else {
        Box(modifier = Modifier.size(24.dp).testTag("runestone_lit_inactive"))
    }
}
