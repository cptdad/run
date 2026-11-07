package com.vg.run

import android.app.Activity
import android.content.Context

// ---------------------------------------------------------------------------
// VendorReview — the store-review seam, `foss` flavour: a no-op. There is no
// Play Services and no store review sheet on an F-Droid install. ReviewPromptPolicy
// still latches "shown" before the call, so the nudge fires once and is never
// asked again; the `google` source set declares the real Play In-App Review half.
// ---------------------------------------------------------------------------

object VendorReview {
    fun requestReview(context: Context, activity: Activity) {}
}
