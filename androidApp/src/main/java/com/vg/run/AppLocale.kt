package com.vg.run

import android.app.Activity
import android.app.LocaleManager
import android.content.Context
import android.content.res.Configuration
import android.content.res.Resources
import android.os.Build
import android.os.LocaleList
import java.util.Locale

// ---------------------------------------------------------------------------
// AppLocale — per-app language override, split across the two API-level
// mechanisms Android has ever offered:
//
//  - API 33+ (Tiramisu): the OS owns it end-to-end via
//    `LocaleManager.applicationLocales`. Every `Context` (including a freshly
//    attached base context) is kept in sync by the platform itself, so [wrap]
//    re-applies that same locale explicitly (see [wrap] — push-started
//    processes don't reliably get the override) and [current]/[apply] just
//    read/write that one API.
//  - API 30-32 (minSdk is 30, so this is NOT dead code):
//    LocaleManager does not exist, so this object hand-rolls the same
//    behaviour with a PLAIN (non-vault) SharedPreferences flag plus
//    `Context.createConfigurationContext` in [wrap], invoked from
//    `MainActivity.attachBaseContext`.
//
// NOT SENSITIVE, NOT VAULT MATERIAL: the chosen language is visible from the
// system locale anyway (and from the app's own on-screen text), so it carries
// nothing a PIN-gated vault is protecting. It must still never be WRITTEN
// through any vault-derived key/path — this is deliberately a bare prefs file,
// parallel to (not part of) WipeRoutine's vault-derived PREFS_FILES list.
//
// WIPE: [WipeRoutine] deletes [PREFS_NAME] (see WipeRoutine.kt's PREFS_FILES),
// so on API 29-32 a wipe resets the language override back to "follow system"
// along with everything else. On API 33+ the override lives in the OS's own
// LocaleManager store; that is a system-owned, user-attributable record, so
// WipeRoutine resets it to "follow system" explicitly via
// `LocaleManager.applicationLocales = LocaleList.getEmptyLocaleList()` — the
// same call [apply] below uses — rather than letting it outlive the crypto-erase
// (the notification channel gets the same treatment).
// ---------------------------------------------------------------------------

object AppLocale {

    /** API 29-32 ONLY. On 33+ this file is never created — LocaleManager owns
     *  the override and this constant is unused there except as the name
     *  WipeRoutine deletes defensively (a no-op if it was never written). */
    const val PREFS_NAME = "app_locale_prefs"

    private const val KEY_LOCALE_TAG = "locale_tag"

    /** BCP-47 tags. "en" is the app's built-in default, listed for
     *  completeness/UI parity with the other six — selecting it is
     *  equivalent to "System default" only when the device is already
     *  English, so it still gets its own explicit row. */
    val SUPPORTED = listOf("en", "sv", "de", "fr", "es", "nb", "da", "fi", "ar", "fa", "so", "ru", "mk")

    /** The current override tag, or null when following the system locale
     *  (the default, and the only state possible before any selection). */
    fun current(context: Context): String? {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val locales = context.getSystemService(LocaleManager::class.java)?.applicationLocales
            return if (locales == null || locales.isEmpty) null else locales[0]?.toLanguageTag()
        }
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return prefs.getString(KEY_LOCALE_TAG, null)
    }

    /**
     * Apply [tag] (null = follow system) and take effect immediately.
     *
     * API 33+: hands off to `LocaleManager`, which relaunches [activity] as a
     * configuration change itself — no explicit `recreate()` here, and adding
     * one would just be a redundant second relaunch.
     *
     * API 29-32: writes the plain SharedPreferences flag [wrap] reads, using
     * `commit()` — never `apply()` (`PrefsApplySourceGuardTest` bans it
     * app-wide: a queued `apply()` flush can land AFTER a later WipeRoutine
     * deletion and silently re-create the file). Then updates the JVM-global
     * `Locale.setDefault` and calls `activity.recreate()` itself, since
     * nothing else will on this API range.
     */
    fun apply(activity: Activity, tag: String?) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            activity.getSystemService(LocaleManager::class.java)?.applicationLocales =
                if (tag == null) LocaleList.getEmptyLocaleList() else LocaleList.forLanguageTags(tag)
            return
        }
        val prefs = activity.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val editor = prefs.edit()
        if (tag == null) editor.remove(KEY_LOCALE_TAG) else editor.putString(KEY_LOCALE_TAG, tag)
        editor.commit()
        Locale.setDefault(resolveLocale(tag))
        activity.recreate()
    }

    /**
     * `MainActivity.attachBaseContext` + push-service hook. API 33+: LocaleManager
     * already keeps every context in sync. API 29-32: when a tag is stored,
     * re-configures [base] (and the JVM default Locale, so date/number
     * formatting elsewhere in the process agrees) to it; otherwise returns
     * [base] unchanged.
     */
    fun wrap(base: Context): Context {
        // API 33+ is NOT identity: LocaleManager keeps ACTIVITY processes in
        // sync, but a process cold-started for a push (RunFcmService /
        // RunPushService → NotificationHelper) has no window/activity yet and
        // does not reliably receive the per-app override — observed on a
        // Pixel 7 (sv-SE system, app pinned en-US) whose FCM banner title
        // resolved to the Swedish resource. Applying the app locale explicitly
        // to the context is idempotent for activities and fixes the push path.
        val tag = current(base) ?: return base
        val locale = Locale.forLanguageTag(tag)
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) Locale.setDefault(locale)
        val cfg = Configuration(base.resources.configuration).apply {
            setLocales(LocaleList(locale))
        }
        return base.createConfigurationContext(cfg)
    }

    /** [tag] resolved to a Locale, or the device's TRUE system locale (via
     *  `Resources.getSystem()`, which is never affected by this app's own
     *  per-app override) when [tag] is null — i.e. what "follow system"
     *  actually means, resolved once at apply-time so `Locale.setDefault`
     *  is never left pointing at a just-cleared override. */
    private fun resolveLocale(tag: String?): Locale =
        tag?.let(Locale::forLanguageTag) ?: Resources.getSystem().configuration.locales[0]
}
