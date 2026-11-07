package com.vg.run

import android.app.Activity
import android.content.Context
import com.google.android.play.core.review.ReviewManagerFactory

// ---------------------------------------------------------------------------
// VendorReview — the store-review seam, `google` flavour: Play In-App Review.
// ReviewPromptPolicy (commonMain) decides WHEN; ContactListScreen calls this
// once the policy fires and has already latched "shown", so the OS alone decides
// whether its sheet actually renders (Play throttles internally). Any failure —
// no Play Services, a non-Play install — leaves the Task unsuccessful and
// nothing happens: never a custom dialog, never a browser fallback. The `foss`
// source set declares the same object as a no-op (no store to review on).
// ---------------------------------------------------------------------------

object VendorReview {
    fun requestReview(context: Context, activity: Activity) {
        val manager = ReviewManagerFactory.create(context)
        manager.requestReviewFlow().addOnCompleteListener { task ->
            if (task.isSuccessful) manager.launchReviewFlow(activity, task.result)
        }
    }
}
