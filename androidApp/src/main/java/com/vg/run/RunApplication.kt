package com.vg.run

import android.app.Application
import android.util.Log

class RunApplication : Application() {

    override fun onCreate() {
        super.onCreate()
        // Flip the master logging kill switch BEFORE any log call. In DEBUG
        // builds this lets LogBuffer capture lines for the in-app log viewer;
        // it stays on-device only (the off-device Loki telemetry sink was
        // removed). Release builds leave it false, so LogBuffer.append is a
        // no-op: nothing is held in memory at all.
        LoggingState.enabled = BuildConfig.DEBUG
        // Debug mode (Settings → Debug mode, DebugMode.kt commonMain): a
        // RELEASE build with the user's opt-in flag already on must re-enable
        // LogBuffer capture right here, immediately after the line above sets
        // it false for Release — otherwise a release install with Debug mode
        // enabled from a previous session would silently capture nothing to
        // upload. Runs in EVERY process this Application attaches to (see the
        // legacy-mirror purge below), with its own tiny prefs file — no ViewModel/vault
        // needed to read it, same as RunFcmService/RunPushService's own
        // KeyValueStore(ctx, RunViewModel.NOTIFICATION_LEVEL_PREFS_NAME) reads.
        // The flag is a DEVICE-KEY AEAD blob now, so this
        // startup read needs the device key — which the Android master key binds to
        // `setUnlockedDeviceRequired(true)`. A process the system started for a push
        // wake on a LOCKED screen therefore reads it as unreadable and logs nothing;
        // `RunViewModel`'s vault-open `DebugMode.reapplyPersisted` is what turns
        // consent back on in that session (the same shape iOS has needed since the
        // 2026-09-20 locked-keybag fix). Constructing CryptoProvider is lazy — it
        // touches the Keystore only if there is a value to open.
        DebugMode.applyAtStartup(
            KeyValueStore(this, RunViewModel.DEBUG_MODE_PREFS_NAME),
            CryptoProvider(this),
        )
        // Guard the launch marker so it never reaches logcat in a Release build
        // (every other log site is already DEBUG-gated via Platform.android.kt).
        if (BuildConfig.DEBUG) Log.d("RunApplication", "onCreate()")

        // Revoke Google Play Services'
        // FCM notification-DELEGATION grant, which the SDK persists once-ever
        // and which the manifest meta-data (AndroidManifest.xml) alone cannot
        // undo for an install that already granted it. Runs in EVERY process
        // this Application attaches to — including a background FCM/UnifiedPush
        // wake — same reasoning as the L10n install below: the SDK's proxy-
        // notification init already ran from FirebaseInitProvider's eager
        // component before this line, so calling it here races the standing
        // grant closed as early as this app's own code can run. Guarded
        // exactly like every other VendorPush.isAvailable call site so a
        // Play-Services-less (FOSS) device never crashes on it; try/caught
        // inside VendorPush.disableNotificationDelegation as well.
        VendorPush.disableNotificationDelegation(this)

        // Localization: install the commonMain L10n resolver's Android backend.
        // Runs in EVERY process this Application attaches to — including a
        // background FCM/UnifiedPush wake that never reaches MainActivity — so
        // shared-content strings (About/Donate/NotificationEducation/etc.,
        // commonMain's platformString) resolve correctly no matter which
        // process first touches them. contextWrapper plugs AppLocale.wrap in as
        // the per-app-language hook Android's resolver (L10n.android.kt) calls
        // before every getString — identity on API 33+ (LocaleManager already
        // keeps every context in sync), the API 29-32 override on the rest.
        AndroidStrings.install(this, com.vg.run.l10n.L10nKeys.strings)
        AndroidStrings.contextWrapper = AppLocale::wrap

        // One-time destruction of the REMOVED
        // background-poll capability mirror — the (inboxId, relay READ capability)
        // blob plus the deliberately weak-gated Keystore key that sealed it.
        // Deleting the code does not delete the data: without this, every device
        // that already shipped the feature keeps an AFU-readable relay-OWNER
        // capability per inbound inbox forever. See
        // NotificationPollStore.purgeLegacyCapabilityMirror for what it removes.
        //
        // HERE, and synchronously, on purpose:
        //  - Application.onCreate runs in EVERY process — including the one a
        //    background FCM wake starts, which may never reach MainActivity — and
        //    before any app code that could read or rewrite the store.
        //  - it strictly precedes every wipe trigger in the process
        //    (MainActivity.onCreate's inactivity + orphaned-credential checks, the
        //    ViewModel's panic wipe), so the purge's one write can never land
        //    after a wipe and re-create the file it just deleted. Moving this to a
        //    background thread would re-open exactly that race.
        //  - it runs regardless of whether push was ever opted into: the mirror
        //    could have been written by any earlier build, and the opt-in flag
        //    (which is NOT capability material) survives untouched.
        // The call is total by contract — it never throws — so it cannot fail the
        // app; a failed pass simply retries on the next launch.
        NotificationPollStore.purgeLegacyCapabilityMirror(this)

        // Retired warm-Tor-cache (2026-07-31, ): same "deleting the code
        // is not deleting the data" problem. Its last production caller went with
        // the poll-manifest removal, so nothing creates these any more — but an
        // install that DID use it keeps a weak-gated (locked-device-usable) AES key
        // in the Keystore plus a dated tor_warm_cache.enc in filesDir, and that
        // blob is the one Tor artifact deliberately placed OUTSIDE the tree
        // TorManager.stop()/purgeStaleTorDirs() sweep — so nothing else would ever
        // remove it short of a wipe or uninstall.
        // Unlike the legacy-mirror purge above this one only DELETES (deleteEntry /
        // deleteSharedPreferences / File.delete), so it can mint no file and needs
        // no ProcessWipeLatch gate — a deletion landing after a wipe is a no-op.
        LegacyTorWarmCache.purgeLegacyWarmCache(this)
    }
}
