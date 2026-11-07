package com.vg.run

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Firebase notification DELEGATION left enabled.
 *
 * Bytecode-verified against firebase-messaging 25.1.2:
 * `ProxyNotificationInitializer`'s enabling lambda runs from an UNGATED eager
 * component at process start (unlike its two siblings, it is NOT gated on
 * `isAutoInitEnabled`), and when the manifest key
 * `firebase_messaging_notification_delegation_enabled` is ABSENT it defaults
 * to calling `NotificationManager.setNotificationDelegate("com.google.android
 * .gms")` — authorising Play Services to render an FCM display payload as a
 * Rún notification WITHOUT this app's process ever starting, bypassing
 * `RunFcmService.handleIntent`'s strip and the `NotificationLevel` wake
 * gate entirely. The fix has two independent halves, and BOTH are required:
 * the manifest key only steers a FRESH grant, while the SDK persists whichever
 * delegate it last set, once-ever, in its own prefs — so an install that
 * already granted the delegate needs the RUNTIME call
 * ([VendorPush.disableNotificationDelegation]) to revoke it.
 *
 * SOURCE-LEVEL, same technique and same reason as
 * [VendorPushOptOutTeardownSourceTest] / [ForwardSecrecyStalledNoticeSourceTest]:
 * `RunApplication`/`VendorPush` need a real `Context`/Play-Services classpath
 * to exercise `FirebaseMessaging.getInstance()` behaviourally, and this
 * module's unit-test tier has no Robolectric. The DECISION under test — that
 * the manifest key exists with the right value, and that the runtime call is
 * wired at process start, on every wipe, and on every push opt-out — is
 * checked structurally. Bodies are scanned with comments STRIPPED so prose
 * that merely names a call can neither satisfy nor trip a guard.
 *
 * The push-opt-out half is pinned separately, and NOT duplicated here: the
 * opt-out branch of `PushRegistrationCoordinator.setBackgroundNotificationsEnabledAwaiting`
 * already calls `VendorPush.destroyLocalPushIdentity` end-to-end
 * (`VendorPushOptOutTeardownSourceTest.optOutBranch_callsDestroyLocalPushIdentity`),
 * and [destroyLocalPushIdentity_disablesNotificationDelegation] below pins
 * that THAT function itself revokes the delegate — so the opt-out path is
 * covered transitively without a second copy of the branch-extraction logic.
 */
class FcmNotificationDelegationSourceTest {

    // -----------------------------------------------------------------------
    // 1. The manifest half — a fresh install must never grant the delegate.
    // -----------------------------------------------------------------------

    @Test
    fun manifest_declaresNotificationDelegationDisabled() {
        val manifest = File(repoRoot(), "androidApp/src/main/AndroidManifest.xml").readText()

        val nameAt = manifest.indexOf("firebase_messaging_notification_delegation_enabled")
        assertTrue(
            "AndroidManifest.xml must declare the " +
                "firebase_messaging_notification_delegation_enabled meta-data — its absence " +
                "makes ProxyNotificationInitializer default to GRANTING Play Services the " +
                "notification delegate (bytecode-verified, firebase-messaging 25.1.2).",
            nameAt >= 0,
        )

        // The <meta-data> element order is name-then-value in this file (matching
        // its siblings), so the nearest value attribute AFTER the name is this
        // element's own — a window bounds the scan to the one element rather than
        // wandering into an unrelated meta-data block.
        val window = manifest.substring(nameAt, minOf(manifest.length, nameAt + 200))
        assertTrue(
            "the firebase_messaging_notification_delegation_enabled meta-data must be " +
                "android:value=\"false\" — any other value (or the key's mere presence with a " +
                "true/missing value) leaves the delegation bypass open. Window was:\n$window",
            window.contains("android:value=\"false\""),
        )
    }

    // -----------------------------------------------------------------------
    // 2. The runtime half at process start.
    // -----------------------------------------------------------------------

    @Test
    fun runApplication_disablesNotificationDelegationAtProcessStart() {
        val body = fileFunctionBody(
            "androidApp/src/main/java/com/vg/run/RunApplication.kt",
            "override fun onCreate() {",
        )
        assertTrue(
            "RunApplication.onCreate must call VendorPush.disableNotificationDelegation so " +
                "an install that already granted Play Services the notification delegate " +
                "(before this fix, or via an app-data restore) has it revoked as early as " +
                "this app's own code can run — this runs in EVERY process, including a " +
                "background push wake that never reaches MainActivity. Body was:\n$body",
            stripComments(body).contains("VendorPush.disableNotificationDelegation("),
        )
    }

    // -----------------------------------------------------------------------
    // 3. The runtime half on every wipe AND every opt-out, via the ONE shared
    //    function both teardown paths call.
    // -----------------------------------------------------------------------

    @Test
    fun disableNotificationDelegation_isGuardedForFossDevices() {
        val body = stripComments(vendorPushFunctionBody("fun disableNotificationDelegation("))

        assertTrue(
            "disableNotificationDelegation must bail out via isAvailable(context) before " +
                "touching FirebaseMessaging — a FOSS device with no Play Services must never " +
                "crash on this call. Body was:\n$body",
            body.contains("isAvailable(context)"),
        )
        assertTrue(
            "disableNotificationDelegation must call setNotificationDelegationEnabled(false). " +
                "Body was:\n$body",
            body.contains("setNotificationDelegationEnabled(false)"),
        )
        assertTrue(
            "disableNotificationDelegation must try/catch the SDK call — it can throw when " +
                "Play Services / FirebaseApp is unavailable. Body was:\n$body",
            body.contains("try {") && body.contains("catch"),
        )
    }

    @Test
    fun destroyLocalPushIdentity_disablesNotificationDelegation() {
        val body = stripComments(vendorPushFunctionBody("fun destroyLocalPushIdentity("))

        val disableAt = body.indexOf("disableNotificationDelegation(")
        assertTrue(
            "destroyLocalPushIdentity must call disableNotificationDelegation — this is the " +
                "ONE function both WipeRoutine's full-wipe path and RunViewModel's push " +
                "opt-out path call, and the notification delegate is SYSTEM-side per-package " +
                "state that nothing else on either teardown path clears. Body was:\n$body",
            disableAt >= 0,
        )

        val tryAt = body.indexOf("try {")
        assertTrue("destroyLocalPushIdentity must have a try block", tryAt >= 0)
        assertTrue(
            "the delegation revocation must run synchronously, before the async " +
                "deleteToken()/FirebaseInstallations chain starts — mirroring " +
                "markIdentityDestroyed()'s own first-statement placement, so an interrupted " +
                "teardown still revokes the delegate. Body was:\n$body",
            disableAt < tryAt,
        )
    }

    @Test
    fun wipeRoutine_routesThroughDestroyLocalPushIdentity() {
        val src = SourcePins.text(SourcePins.WIPE_ROUTINE)
        assertTrue(
            "WipeRoutine's wipe path must call VendorPush.destroyLocalPushIdentity so the " +
                "wipe path picks up the delegation revocation wired inside it.",
            src.contains("VendorPush.destroyLocalPushIdentity("),
        )
    }

    // -----------------------------------------------------------------------
    // 4. The kdoc — the "sole entry point" claim must not be stated
    //    unconditionally.
    // -----------------------------------------------------------------------

    @Test
    fun handleIntentKdoc_documentsTheDelegationPrecondition() {
        val src = SourcePins.text(SourcePins.RUN_FCM_SERVICE)
        val kdocStart = src.indexOf("ENFORCE the contentless invariant")
        assertTrue("RunFcmService.kt must still carry the handleIntent kdoc", kdocStart >= 0)
        val kdocEnd = src.indexOf("override fun handleIntent", kdocStart)
        assertTrue("the handleIntent kdoc must precede handleIntent's declaration", kdocEnd >= 0)
        val kdoc = src.substring(kdocStart, kdocEnd)

        assertTrue(
            "the handleIntent kdoc must document that 'sole entry point' depends on " +
                "notification delegation being disabled — without this, the kdoc claims a " +
                "guarantee the FCM delegation bypass disproved. kdoc was:\n$kdoc",
            kdoc.contains("sole entry point only while") && kdoc.contains("disableNotificationDelegation"),
        )
    }

    // -----------------------------------------------------------------------

    /** Brace-matched body of a `VendorPush.kt` function. */
    private fun vendorPushFunctionBody(signature: String): String =
        fileFunctionBody(SourcePins.VENDOR_PUSH, signature)
}
