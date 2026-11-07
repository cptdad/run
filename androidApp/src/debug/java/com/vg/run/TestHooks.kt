package com.vg.run

import android.app.Activity
import android.content.Intent

// ---------------------------------------------------------------------------
// TestHooks (DEBUG variant) — e2e support invoked by MainActivity.
//
// Lives ONLY in src/debug. The release source set provides a no-op TestHooks
// with the identical signature, so MainActivity can call handleTestWipe()
// unconditionally while the wipe-via-intent path (and its symbol) is physically
// absent from the shipped APK — stronger than the old src/main TestSupport,
// which relied on R8 dead-code elimination to keep the wipe out of release.
//
// The e2e suite passes `--ez TEST_WIPE true` as an Activity intent extra to get
// a clean first-run state without uninstalling the APK (uninstalling on iOS
// would revoke the Local Network privacy grant; the Android path mirrors it).
// Delegates to WipeRoutine so the clean-state path stays byte-identical to the
// real emergency/inactivity wipes (incl. crypto erasure).
//
// ProcessWipeLatch.resetForTest() runs immediately after (2026-08-14,
// FOSS/UnifiedPush registration-convergence investigation). WipeRoutine's
// FIRST statement is ProcessWipeLatch.latch() (armed so nothing racing the
// wipe itself can resurrect what it just erased), and that latch is normally
// only ever cleared by a fresh process — the ordinary case, since
// MainActivity.onStop -> finishAndRemoveTask() kills the process on every
// background. An e2e SESSION never backgrounds between TEST_WIPE and the rest
// of the spec, though: the same process that ran the wipe goes on to
// onboard, pair, and toggle background notifications, all live. Any later
// legitimate write this session gated on ProcessWipeLatch — concretely,
// UnifiedPushStateStore.saveSubscription refusing every distributor-delivered
// endpoint for the rest of the process — was permanently, silently refused,
// which is indistinguishable on-device from the connector never delivering at
// all (root-caused via temporary debug-only diagnostic logging, since removed:
// saveSubscription refusing on ProcessWipeLatch.wipedThisProcess on every
// attempt, seq never advancing).
// resetForTest() is exactly the primitive built for this ("a wipe test would
// otherwise latch every later test class out of whatever gates on it" — see
// its kdoc) and is a hard no-op outside a DEBUG build, so this changes nothing
// about the one-way latch a real user's wipe (Erase and start over, the
// launch-time inactivity/orphaned-credential wipes) arms — those still stay
// latched for the rest of that process, exactly as documented. This whole
// file is compiled OUT of release (see the release TestHooks stub), so the
// production security invariant is untouched either way.
// ---------------------------------------------------------------------------

object TestHooks {
    fun handleTestWipe(activity: Activity, intent: Intent?) {
        if (intent?.getBooleanExtra("TEST_WIPE", false) == true) {
            WipeRoutine.wipePersistentState(activity)
            ProcessWipeLatch.resetForTest()
            wipedThisLaunch = true
            LogBuffer.append("W", "MainActivity", "TEST_WIPE — persistent state cleared")
            // Consume the extra: a LATER recreate()/config-change relaunch of
            // this same Activity instance — concretely, AppLocale.apply's
            // API 29-32 language-switch recreate() — re-delivers this SAME
            // Intent object (recreate() does not clear extras), which would
            // otherwise re-run the wipe on every language change for the rest
            // of the e2e session. One-shot by construction, mirroring how a
            // real TEST_WIPE launch is one-shot per process.
            intent.removeExtra("TEST_WIPE")
        }
    }

    /**
     * App-language pin for the e2e harness — the Android sibling of iOS's
     * `--test-language=<tag>` (RunApp.swift), and the ONLY lever that works
     * below API 33: `cmd locale set-app-locales` does not exist there, so on
     * the API-30 bench phones (Samsung A20e) the harness had no way to pin the
     * app language at all and a Swedish device silently ran the whole suite in
     * Swedish — which makes every text-ABSENCE assertion pass falsely.
     *
     * `--es test_language <BCP-47 tag>` on the launch intent, applied through
     * [AppLocale.apply] so it takes the SAME path as the in-app language
     * switcher (LocaleManager on 33+, the app_locale_prefs + recreate() path on
     * 29-32). Must run AFTER [handleTestWipe]: a wipe resets the override to
     * follow-system (WipeRoutine), so re-pinning here is what keeps the
     * post-wipe first frame in the pinned language.
     *
     * One-shot, exactly like TEST_WIPE above and for the same reason: BOTH
     * arms of [AppLocale.apply] relaunch this Activity (the API 29-32 arm calls
     * recreate() itself; 33+ has LocaleManager do it), and a relaunch
     * re-delivers this SAME Intent object — so leaving the extra in place would
     * re-apply, re-relaunch, forever. The extra is consumed BEFORE apply() for
     * that reason.
     *
     * The tag is applied verbatim (no SUPPORTED-list filtering), mirroring
     * iOS, which writes whatever `--test-language=` carried into AppleLanguages:
     * an unknown tag then resolves to the app's default resources rather than
     * leaving the device's own language in place. The release stub is a hard
     * no-op, so no shipped APK has an intent-driven language override at all.
     */
    fun handleTestLanguage(activity: Activity, intent: Intent?) {
        val tag = intent?.getStringExtra("test_language")?.trim().orEmpty()
        if (tag.isEmpty()) return
        intent?.removeExtra("test_language")
        val current = AppLocale.current(activity)
        if (current == tag) {
            LogBuffer.append("I", "MainActivity", "test_language=$tag — already pinned, no relaunch")
            return
        }
        LogBuffer.append("W", "MainActivity", "test_language=$tag (was ${current ?: "system"}) — applying")
        AppLocale.apply(activity, tag)
    }

    /**
     * Periodic random re-auth at MAXIMUM (docs/periodic-reauth-design.md):
     * `--el TEST_REAUTH_INTERVAL_MS <n>` arms a FIXED interval for e2e
     * determinism via [ReauthPolicy.setTestIntervalOverrideMs] — the only way
     * to turn the touch-independent timer on in a debuggable build (it is OFF
     * by default there; see [ReauthPolicy.isEnabled]). No-op when the extra is
     * absent. The release stub below is a hard no-op, so no override path
     * exists in a shipped APK regardless of what an intent extra carries.
     */
    fun handleTestReauth(intent: Intent?) {
        val ms = intent?.getLongExtra("TEST_REAUTH_INTERVAL_MS", -1L) ?: -1L
        if (ms >= 0L) {
            ReauthPolicy.setTestIntervalOverrideMs(ms)
            LogBuffer.append("W", "MainActivity", "TEST_REAUTH_INTERVAL_MS=$ms — periodic re-auth armed")
        }
    }

    /**
     * e2e-only override for the update nudge's store-variant gate
     * ([RunViewModel.isPlayInstall]). A sideloaded/emulator debug build has no
     * real Play Store installer of record, so the two-button ("Open Google
     * Play") variant can otherwise never render there — this lets the harness
     * force it on to verify its LAYOUT (RuneActionRow's stacked-fallback fix,
     * ContactListScreen.kt's nudge call site) without touching the real
     * installer-of-record check at all. `--ez TEST_FORCE_STORE_INSTALL true`
     * on the launch intent. No one-shot consumption needed (idempotent, same
     * shape as [handleTestReauth]): re-applying `true` on a later relaunch
     * changes nothing, and there is no legitimate reason to turn it back off
     * mid-process. iOS sibling: RunApp.swift's `--test-force-store-install` /
     * StoreInstall.debugForceStoreInstall. The release stub below never reads
     * the extra at all — no override path exists in a shipped APK regardless
     * of what an intent extra carries.
     */
    var forceStoreInstall: Boolean = false
        private set

    fun handleTestForceStoreInstall(intent: Intent?) {
        if (intent?.getBooleanExtra("TEST_FORCE_STORE_INSTALL", false) == true) {
            forceStoreInstall = true
            LogBuffer.append("W", "MainActivity", "TEST_FORCE_STORE_INSTALL — update-nudge store variant forced")
        }
    }

    /**
     * Physical-phone A/B NO-HEDGE CONTROL ARM for the descriptor hedge ([DescriptorHedge],
     * 2026-10-12). `--ez TEST_DESCRIPTOR_HEDGE_OFF true` (or `false`) on a launch
     * intent sets it; the value is PERSISTED in a debug-only prefs file because
     * the connect:cycle suite relaunches with a plain activateApp (no extras) and
     * every relaunch is a fresh process here (MainActivity.onStop →
     * finishAndRemoveTask). A launch carrying `TEST_WIPE` without the extra
     * resets it to the default (hedge ON), so a later suite never inherits a
     * previous run's control arm. Applied on EVERY onCreate (process-wide flag
     * [DescriptorHedge.setNoHedgeControl], itself refused outside a debug build).
     * iOS sibling: RunApp.swift's `--test-descriptor-hedge-off`.
     */
    fun handleTestDescriptorHedge(activity: Activity, intent: Intent?) {
        val prefs = activity.applicationContext.getSharedPreferences(E2E_PREFS, Activity.MODE_PRIVATE)
        when {
            intent?.hasExtra("TEST_DESCRIPTOR_HEDGE_OFF") == true ->
                prefs.edit().putBoolean(KEY_HEDGE_OFF, intent.getBooleanExtra("TEST_DESCRIPTOR_HEDGE_OFF", false)).commit()
            intent?.getBooleanExtra("TEST_WIPE", false) == true || wipedThisLaunch ->
                prefs.edit().remove(KEY_HEDGE_OFF).commit()
        }
        // Same lifecycle for the RENDEZVOUS hedge's control arm (RendezvousHedge,
        // 2026-10-25): `--ez TEST_REND_HEDGE_OFF true`, persisted until the next
        // TEST_WIPE launch without it. Handled HERE, before wipedThisLaunch is
        // consumed. iOS sibling: RunApp.swift's `--test-rend-hedge-off`.
        when {
            intent?.hasExtra("TEST_REND_HEDGE_OFF") == true ->
                prefs.edit().putBoolean(KEY_REND_HEDGE_OFF, intent.getBooleanExtra("TEST_REND_HEDGE_OFF", false)).commit()
            intent?.getBooleanExtra("TEST_WIPE", false) == true || wipedThisLaunch ->
                prefs.edit().remove(KEY_REND_HEDGE_OFF).commit()
        }
        wipedThisLaunch = false
        val off = prefs.getBoolean(KEY_HEDGE_OFF, false)
        DescriptorHedge.setNoHedgeControl(off)
        if (off) LogBuffer.append("W", "MainActivity", "TEST_DESCRIPTOR_HEDGE_OFF — descriptor hedge control arm (no hedge)")
        val rendOff = prefs.getBoolean(KEY_REND_HEDGE_OFF, false)
        RendezvousHedge.setNoHedgeControl(rendOff)
        if (rendOff) LogBuffer.append("W", "MainActivity", "TEST_REND_HEDGE_OFF — rendezvous hedge control arm (no hedge)")
    }

    /** handleTestWipe consumes the TEST_WIPE extra, so it leaves this mark for
     *  [handleTestDescriptorHedge] (same onCreate, later). */
    private var wipedThisLaunch = false
    private const val E2E_PREFS = "e2e_test_hooks"
    private const val KEY_HEDGE_OFF = "descriptor_hedge_off"
    private const val KEY_REND_HEDGE_OFF = "rend_hedge_off"
}
