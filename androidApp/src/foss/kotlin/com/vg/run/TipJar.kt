package com.vg.run

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag

// ---------------------------------------------------------------------------
// TipJar — the `foss` flavour's stub of the tip-jar seam. Google Play Billing is
// not linked in this build, so the real TipJarBody (src/google/.../TipJar.kt,
// Play Billing) is replaced by an empty body. DonateModal never composes it
// here — VendorBilling.isSupported is false, which hides the Tip tab — so this
// exists only so the shared DonateModal compiles for the `foss` variant.
// ---------------------------------------------------------------------------

@Composable
fun TipJarBody() {
    Box(modifier = Modifier.fillMaxWidth().testTag("tip_jar_body"))
}
