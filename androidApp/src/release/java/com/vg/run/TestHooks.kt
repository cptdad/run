package com.vg.run

import android.app.Activity
import android.content.Intent

// ---------------------------------------------------------------------------
// TestHooks (RELEASE variant) — no-op stub.
//
// The e2e test-wipe hook MUST NOT exist in shipped builds. This release-only
// stub has the same signature as the src/debug TestHooks so MainActivity calls
// it unconditionally, but the wipe-via-intent path is compiled out of release
// entirely (not merely dead-stripped). A co-located app or adb firing
// `--ez TEST_WIPE true` therefore has no code path to trigger in release.
// ---------------------------------------------------------------------------

object TestHooks {
    @Suppress("UNUSED_PARAMETER")
    fun handleTestWipe(activity: Activity, intent: Intent?) { /* no-op in release */ }

    // e2e app-language pin (`--es test_language <tag>`, the sibling of iOS's
    // --test-language=): the release stub — a shipped APK has no intent-driven
    // language override at all. See the debug variant's kdoc.
    @Suppress("UNUSED_PARAMETER")
    fun handleTestLanguage(activity: Activity, intent: Intent?) { /* no-op in release */ }

    // Periodic random re-auth at MAXIMUM (docs/periodic-reauth-design.md):
    // the release stub — no override path exists in a shipped APK. See the
    // debug variant's kdoc.
    @Suppress("UNUSED_PARAMETER")
    fun handleTestReauth(intent: Intent?) { /* no-op in release */ }

    // e2e store-variant force for the update nudge (`--ez TEST_FORCE_STORE_INSTALL
    // true`): release stub — no override path exists in a shipped APK, and
    // isPlayInstall never reads this outside the debug source set anyway. See
    // the debug variant's kdoc.
    val forceStoreInstall: Boolean = false

    @Suppress("UNUSED_PARAMETER")
    fun handleTestForceStoreInstall(intent: Intent?) { /* no-op in release: forceStoreInstall stays false */ }

    // Physical-phone A/B no-hedge control arms for the descriptor hedge (`--ez
    // TEST_DESCRIPTOR_HEDGE_OFF true`) and the rendezvous hedge (`--ez
    // TEST_REND_HEDGE_OFF true`): release stub — a shipped APK always hedges
    // (both setNoHedgeControl calls also refuse outside a debug build).
    @Suppress("UNUSED_PARAMETER")
    fun handleTestDescriptorHedge(activity: Activity, intent: Intent?) { /* no-op in release */ }
}
