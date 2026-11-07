package com.vg.run

import android.content.Context

// ---------------------------------------------------------------------------
// VendorPush — the `foss` flavour's half of the vendor-push seam. The `google`
// source set declares an object with the SAME fully-qualified name and API (the
// FCM implementation); exactly one of the two is compiled per variant. This
// build carries ZERO Firebase / Play Services code: isAvailable() is always
// false and currentToken() always null, so the main code that gates FCM on them
// (PushRegistrationCoordinator, RunApplication, WipeRoutine) falls through to
// UnifiedPush unconditionally. F-Droid builds this flavour.
// ---------------------------------------------------------------------------

object VendorPush {

    /** Always false: no Play Services client is linked, so FCM can never be the transport. */
    fun isAvailable(context: Context): Boolean = false

    /** No Firebase SDK, hence no notification delegate to revoke. */
    fun disableNotificationDelegation(context: Context) {}

    /** Always null: no token was ever requested. */
    suspend fun currentToken(context: Context): String? = null

    /**
     * Nothing to destroy: this build never created a push identity. [onSettled] is deliberately
     * NEVER invoked — it exists so the `google` half can sweep the artefacts its async Firebase
     * Tasks rewrite, and this build starts no Tasks. Every caller also runs its own synchronous
     * [sweepLocalArtifacts] pass right after, so no path waits on the callback.
     */
    fun destroyLocalPushIdentity(context: Context, onSettled: () -> Unit) {}

    /** Nothing on disk to sweep: no Firebase state is ever written by this build. */
    fun sweepLocalArtifacts(context: Context) {}
}
