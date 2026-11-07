package com.vg.run

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper

/**
 * Resolve the hosting [Activity] from a (possibly wrapped) [Context]. Compose's
 * Dialog surfaces a ContextThemeWrapper via LocalContext, so a direct
 * `as? Activity` is null; Play Billing / Play In-App Review / the locale and
 * UnifiedPush distributor pickers all need the real Activity. Returns null
 * rather than throwing so callers can no-op when none is found.
 */
internal fun Context.findActivity(): Activity? {
    var ctx: Context? = this
    while (ctx is ContextWrapper) {
        if (ctx is Activity) return ctx
        ctx = ctx.baseContext
    }
    return null
}
