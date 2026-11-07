package com.vg.run

import android.content.Context

// ---------------------------------------------------------------------------
// WipeRoutine — the single source of truth for destroying all persisted
// vault material on Android.
//
// Previously this deletion list was triplicated across
// RunViewModel.performEmergencyWipe(), InactivityWipe.wipeAllData() and the
// debug test-wipe hook (now TestHooks), and the copies had already drifted
// (only performEmergencyWipe deleted pin_attempts_prefs; none
// performed cryptographic erasure). Centralising removes the
// drift class entirely: a new prefs file is wiped everywhere by adding one
// line here.
// ---------------------------------------------------------------------------

object WipeRoutine {

    // Every SharedPreferences file that holds vault-derived material.
    // Mirrored on iOS: IosAppController wipes the whole Keychain KV service with
    // kvDeleteAll(); a file added here needs its iOS key family covered there.
    private val PREFS_FILES = listOf(
        "db_key_prefs",        // legacy pre-CR-1 wrapped DB password (may still exist)
        "decoy_key_prefs",     // legacy decoy-feature artifact (removed); wiped for old installs
        VAULT_SELECTOR_PREFS_NAME, // credential verifiers + PIN-wrapped DB keys (CR-1)
        "pin_attempts_prefs",  // wrong-PIN counter
        "inactivity_prefs",    // InactivityWipe last-opened timestamp (CryptoProvider-encrypted)
        "auto_wipe_prefs",     // legacy/orphaned name — kept for old installs
        "pin_entry_prefs",     // misc PIN-entry UI state
        // Language-override flag, API 29-32 ONLY (AppLocale.kt). Not vault
        // material (the language is visible from the system locale anyway),
        // but it must not survive a wipe on this API range either. On API 33+
        // the override lives in the OS's LocaleManager store instead and is
        // reset explicitly further down.
        AppLocale.PREFS_NAME,
        NotificationPollStore.PREFS_NAME,   // vendor-push opt-in flag (+ the REMOVED cap mirror on legacy installs)
        // The wrapped Tink master keyset. Its
        // deletion was single-sourced in CryptoManager.eraseMasterKey (which now
        // also overwrites it); listing it here is the second, independent delete.
        CryptoManager.PREF_FILE_NAME,
        // The (inboxId, readCap) mirror and its
        // ManifestCrypto AEAD are DELETED, but installs provisioned before that
        // still carry the wrapped keyset. Keep deleting it BY NAME — the class
        // that owned the name is gone, so nothing else would.
        NotificationPollStore.LEGACY_KEYSET_PREFS_NAME,
        // Same story, same shape: the warm-Tor-cache AEAD and its
        // weak-gated Keystore key are DELETED with the feature, but the wrapped
        // keyset survives on installs that ran it. Deleted by name here and, in
        // the crypto-erase-first position below, by LegacyTorWarmCache.
        LegacyTorWarmCache.LEGACY_KEYSET_PREFS_NAME,
        // The NotificationLevel selector: since 2026-09-22 BOTH
        // the plaintext wake-gate slot and the device-key AEAD consent proof
        // that authorises minting a push identity. One file, so one entry.
        // Also carries PushWakeFreshness's last-sweep stamp, which
        // this whole-file deletion destroys with it.
        RunViewModel.NOTIFICATION_LEVEL_PREFS_NAME,
        // The Debug-mode opt-in flag, a device-key AEAD blob since
        // 2026-09-22 — it was the plaintext "1" a planted file could set.
        RunViewModel.DEBUG_MODE_PREFS_NAME,
        // External SOCKS proxy setting (ExternalTorProxy.kt): the "ip:port",
        // device-key sealed, read pre-unlock. Not vault material, but its
        // presence proves the app
        // was configured (and a LAN address says where) — it must not survive a
        // wipe, and a wiped install must come back on the embedded Tor.
        RunViewModel.EXT_TOR_PROXY_PREFS_NAME,
        // UnifiedPush tier: our own plaintext endpoint + the SEALED RFC 8291
        // (p256dh, auth) pair. `auth` is a shared secret, not a public half —
        // see UnifiedPushStateStore's kdoc — so its key surface is crypto-erased
        // above, in the key-material-first position, and this deletes the
        // ciphertext half.
        // Also deleted by UnifiedPushSupport.sweepLocalArtifacts (which the
        // settings OPT-OUT path calls, where no full wipe runs); listed here
        // too so the wipe does not depend on that call having happened. The
        // CONNECTOR's own artifacts are not SharedPreferences and are handled
        // in wipePersistentState below.
        UnifiedPushStateStore.PREFS_NAME,
    )

    /**
     * Destroy all persisted vault material.
     *
     * Order matters: [CryptoManager.eraseMasterKey] is the FIRST destructive
     * step, so that even if the process is killed mid-wipe, the Keystore master
     * key is already gone and every CryptoProvider-encrypted blob (and therefore
     * the PIN-wrapped SQLCipher key, and therefore the DB files themselves) is
     * cryptographically unrecoverable. Database and prefs deletion is the
     * follow-up hygiene pass, not the security boundary.
     *
     * Exactly one thing runs before it — `ProcessWipeLatch.latch()`, which
     * performs NO I/O at all (it flips one in-RAM flag) and so cannot delay or
     * interrupt the crypto-erasure; it has to precede it so a concurrent write
     * racing the erasure is refused too. See the call site.
     */
    fun wipePersistentState(context: Context) {
        // FIRST of all — before any erasure, deletion or I/O. [ProcessWipeLatch]
        // is the process-lifetime "a wipe has happened" flag honoured by anything
        // that could otherwise RE-CREATE an artifact this routine is about to
        // destroy. Deleting a key and its keyset is not enough on its own when
        // the owning code recreates both whenever they are absent: that is how
        // the 2026-07-30 regression produced a Keystore key, a Tink keyset and an
        // encrypted blob all dated AFTER the wipe, on the one path (inactivity)
        // that fires while the user is absent and cannot re-wipe. Latching BEFORE
        // the erasures means a write that RACES an erasure is refused too, not
        // only one that follows it.
        //
        // RAM only — persisting the latch would itself be a post-wipe artifact.
        // It never blocks Tor, the vault or the relay: Tor still starts and
        // bootstraps, and a vault re-provisioned in this same process (the
        // orphaned-credential path routes straight to setup) works normally. See
        // the ProcessWipeLatch kdoc for what a NEW consumer must gate.
        ProcessWipeLatch.latch()
        CryptoManager.eraseMasterKey(context)
        // Lever B: crypto-erase the auth-bound DB-key (RSA) Keystore key too, so
        // a wipe leaves no key that could unwrap a surviving DB-key blob. Erased
        // alongside the Tink master key, before the file deletions.
        AuthBoundKeyStore.deleteKey(context)
        // LEGACY background-notification manifest key (the WEAKER, AfterFirstUnlock-
        // class key). The mirror it protected is REMOVED
        // and no code creates this alias any more, but an install
        // provisioned before that still has the alias + wrapped keyset on disk. This
        // is a pure crypto-erasure by name — key first, then keyset, no write — so
        // the stale read-cap mirror is unrecoverable even if the prefs deletion
        // below is interrupted. (The normal cleanup happens once at launch:
        // NotificationPollStore.purgeLegacyCapabilityMirror from RunApplication.)
        NotificationPollStore.eraseLegacyManifestKeySurface(context)
        // LEGACY warm-Tor-cache key (the OTHER weak, AfterFirstUnlock-class key).
        // The feature is RETIRED (2026-07-31: its only production
        // caller, the FCM-woken poll runner, went with the poll manifest), so
        // nothing creates this alias any more — but an install that ran it still
        // has the alias + wrapped keyset on disk. Crypto-erased HERE, before the
        // file deletions, so the persisted consensus/guard-state blob is
        // unrecoverable even if the blob deletion further down is interrupted.
        LegacyTorWarmCache.eraseLegacyKeySurface(context)
        // The UnifiedPush tier's BOTH Keystore aliases — the connector's
        // `UnifiedPush` (which wraps the stored WebPush PRIVATE keys) and our
        // own `run_up_state_key` (which seals the RFC 8291 p256dh+auth pair in
        // unifiedpush_state_prefs). Crypto-erased HERE, in the
        // key-material-first position alongside the two legacy surfaces above,
        // so an interrupted wipe leaves both unrecoverable even if the database
        // and prefs deletions below never run. Pure destruction: creates
        // nothing, writes nothing, never throws.
        UnifiedPushSupport.eraseKeySurface(context)
        // …then the connector-side teardown (tell the distributor to stop, drop
        // the distributor choice, clear our own store), and only THEN the
        // artifact sweep. This ORDER is load-bearing twice over:
        //  - teardown BEFORE the sweep, because it constructs the connector's
        //    DBStore and re-creates `databases/unifiedpush-connector` if absent
        //    — the write-after-delete race the Firebase sweep hit, avoidable here
        //    purely by ordering (nothing is async in this half);
        //  - both BEFORE the wholesale `databases/` deleteRecursively below, so
        //    that delete stays the last word on that directory. Sweeping after
        //    it would re-create an empty `databases/` (Context.deleteDatabase
        //    resolves through getDatabasesDir(), which mkdirs), and a bare,
        //    freshly dated databases/ is itself the "this app ran" evidence the
        //    wholesale delete exists to remove.
        //
        // THIS IS THE ONLY LEGITIMATE CALLER of the FULL sweep — the variant
        // that CLOSES the connector's cached SQLite handle and then unlinks
        // `databases/unifiedpush-connector`. The close-before-unlink is
        // load-bearing, because "a wipe is terminal" is FALSE for this routine
        // (that claim shipped the 2026-08-11 defect): four of its five entry
        // points — the orphaned-vault "Erase and start over", the launch-time
        // inactivity wipe, the orphaned-credential self-heal, and the debug
        // TEST_WIPE hook — deliberately fall through to setup in the SAME
        // process, which also survives finishAndRemoveTask() as a cached
        // process. Unlinking under the open handle pinned it in
        // SQLITE_READONLY_DBMOVED and wedged every later saveDistributor until
        // real process death, so a re-onboarded user could never re-enable
        // UnifiedPush (see UnifiedPushSupport.sweepLocalArtifacts for the full
        // history — that kdoc's safety invariant has now been wrong twice).
        // The two in-session teardowns still must NOT use the full sweep (they
        // need the live handle for an immediate retry, and their file unlink
        // adds nothing eraseKeySurface + the row deletes don't already cover)
        // and call sweepInSessionArtifacts instead;
        // VendorPushOptOutTeardownSourceTest pins that split at source level.
        UnifiedPushSupport.destroyLocalPushIdentity(context)
        UnifiedPushSupport.sweepLocalArtifacts(context)

        try {
            context.deleteDatabase("run.db")
            context.deleteDatabase("run_b.db")
            // Belt-and-braces: deleteDatabase() already unlinks
            // -wal/-shm/-journal, but a wipe is forensic-critical, so explicitly
            // remove any sidecar a partial/aborted delete or an unexpected journal
            // mode could strand — even encrypted sidecars leak metadata (existence,
            // size, last-write time).
            listOf("run.db", "run_b.db").forEach { name ->
                val base = context.getDatabasePath(name).path
                listOf("", "-wal", "-shm", "-journal").forEach { sfx ->
                    java.io.File(base + sfx).delete()
                }
            }
            // …then remove databases/ WHOLESALE. The two names above are the only
            // databases this app opens, but a DEPENDENCY can create one without a
            // single line of our code running — androidx.work did exactly that via
            // its merged androidx.startup provider, leaving androidx.work.workdb
            // behind after every wipe. A named list cannot
            // defend against a file we never knew was created.
            //
            // ONE operation, deliberately: an earlier revision did two passes —
            // databaseList()+deleteDatabase() and then listFiles()+File.delete()
            // over the same directory — which READ as exhaustive but was not.
            // databaseList() only reports what the framework recognises as a
            // database (so a stray journal/temp file it doesn't name is invisible
            // to it), and File.delete() FAILS on a non-empty directory, so any
            // nested artifact silently survived a sweep that looked total.
            // deleteRecursively() on the directory is the single operation that
            // actually means "nothing survives in databases/": files, -wal/-shm/
            // -journal and -mj* master journals, subdirectories, and the
            // directory's own mtime (which is itself evidence — an app that never
            // opened a database has no databases/ dir at all). Android recreates
            // it on demand (ContextImpl.getDatabasePath / openOrCreateDatabase
            // mkdirs it), so removing it cannot break a later open — including
            // the getDatabasePath() call on the very next line, which mkdirs it
            // if missing and is then itself undone by the delete.
            // Safe by construction: runs only in the wipe, after the crypto-erase,
            // when nothing in databases/ may survive.
            //
            // The RESULT is checked, and a partial sweep is retried ONCE.
            // deleteRecursively() walks top-down and then removes the directory
            // itself, so a single file created by another thread between the walk
            // and that final rmdir makes the whole call answer false and leaves a
            // dated, app-attributable databases/ behind — silently, since the
            // Boolean used to be discarded inside this best-effort catch. (The
            // same class of race is REAL one directory over: Firebase's heartbeat
            // datastore is re-created ~140 ms after its sweep, which is why
            // VendorPush schedules bounded late passes for it.) One retry, still
            // delete-only, still after the crypto-erase — never a write.
            val databasesDir = context.getDatabasePath("run.db").parentFile
            if (databasesDir != null && !databasesDir.deleteRecursively() && databasesDir.exists()) {
                databasesDir.deleteRecursively()
            }
        } catch (_: Exception) { /* best-effort */ }

        PREFS_FILES.forEach { context.deleteSharedPreferences(it) }
        // Also disarms the push-dereg pending flag (secure_prefs /
        // push_dereg_pending, 2026-08-11): a wipe destroys the vault, so a flag
        // surviving it could never be cleared (no vault → no caps → the opt-out
        // sweep can never run) — and the wipe path deliberately never arms it
        // (RunViewModel.unregisterPushBestEffort stays one-shot). Mirrors iOS
        // clearWipeResidue() removing PushDeregPending.storageKey.
        SecurePrefs.clear(context)

        // Local FCM/Firebase push identity.
        // VendorPush.destroyLocalPushIdentity fires the SDK's own async deleteToken() /
        // FirebaseInstallations.delete() calls. Those are network-dependent and
        // this routine must NEVER block on the network, so the artifacts they
        // touch are deleted here synchronously and unconditionally.
        //
        // …but the synchronous delete alone was a write-after-delete race
        // (regression 2026-07-30). Both SDK calls WRITE on their way through:
        // deleteToken() needs a Firebase Installation ID to authenticate the RPC
        // (generating and persisting a FRESH one into PersistedInstallation.*.json
        // if we just deleted it) and then commits the token removal back into
        // com.google.android.gms.appid; FirebaseInstallations.delete() rewrites
        // that same json with a NOT_GENERATED entry. Every one of those writes
        // lands AFTER this function's synchronous deletion — recreating exactly
        // the push residue this sweep exists to remove. deleteSharedPreferences() evicts
        // the ContextImpl cache entry but does NOT neuter the SharedPreferences
        // instance the SDK already holds, so its next commit() recreates the file.
        //
        // So: delete synchronously (process dies mid-wipe ⇒ nothing readable is
        // left, and the Tasks that would have rewritten never complete either),
        // AND re-delete once both Tasks settle (process survives ⇒ whatever they
        // rewrote is swept). Both SDK writes happen strictly before their Task
        // completes, so ONE post-settle sweep is sufficient — it is not a poll.
        // The callback never blocks anything here; if it never fires (no network,
        // process killed) the synchronous pass already stands alone.
        //
        // applicationContext, not `context`: MainActivity passes `this`, and the
        // callback can outlive it by a network round trip.
        //
        // 2026-09-17: the synchronous pass below is UNCHANGED and still removes
        // the FCM token store, the auto-init prefs, the heartbeat datastore, the
        // cross-process lock and the no-backup marker. ONE artifact is now
        // deferred inside it — `PersistedInstallation.<key>.json`, and only until
        // this teardown's own revocation chain settles — because deleting it
        // while `deleteToken()` is re-reading it makes the Installations SDK ask
        // FIS for an auth token under a NULL fid, and that 400 locks the SDK out
        // of every registration for 24 hours. See [FisTeardownGate].
        val app = context.applicationContext
        VendorPush.destroyLocalPushIdentity(app) { VendorPush.sweepLocalArtifacts(app) }
        VendorPush.sweepLocalArtifacts(app)

        // Bounded Tor keep-alive (TorKeepAlive.kt): a Tor child KEPT from an
        // earlier session (the app was backgrounded < 2 min ago) dies here through
        // the DISCARD path, never the preserving one, before the dirs it lives in
        // are deleted below — and its foreground service goes with it. Covers
        // every wipe entry point (launch-time inactivity / orphan self-heal / test
        // hook run BEFORE any ViewModel exists, so nothing else would reach it).
        // No-op when nothing is kept.
        TorKeepAliveHolder.discardForWipe()

        // Delete the Tor working dirs so a wipe leaves no forensic proof Tor was
        // ever used (guard state, consensus, descriptors, onion-client-auth keys,
        // control socket, lock files). THIS IS NOW THE ONLY ROUTINE DELETION OF
        // THEM: since 2026-08-01 the dirs are deliberately PRESERVED across an
        // ordinary stop/start so Tor reuses its entry guards and cached consensus
        // (TorManager.dataDir), so `TorManager.stop()` no longer removes anything
        // and this call is load-bearing rather than belt-and-braces. It covers
        // EVERY wipe entry point (emergency, inactivity, launch-time self-heal,
        // debug test hook), mirroring iOS deleteTorData(); the in-session panic
        // wipe additionally calls TorManager.stopAndDiscardState() afterwards, so
        // a Tor child still alive during THIS deletion cannot leave residue.
        // deleteRecursively also removes the empty parent dir.
        try {
            java.io.File(context.filesDir, "tor_direct").deleteRecursively()
            java.io.File(context.cacheDir, "tor_direct").deleteRecursively()
            // The LEGACY warm-Tor-cache blob lives at a TOP-LEVEL sibling of
            // tor_direct/, OUTSIDE the tree the two lines above sweep — so a wipe
            // would otherwise leave an AEAD-encrypted-but-undeleted artifact
            // behind. Delete it (and any stranded .tmp) explicitly. The key that
            // could unwrap it was already crypto-erased above, in the
            // key-material-first position; this is the ciphertext half.
            LegacyTorWarmCache.deleteLegacyBlob(context)
        } catch (_: Exception) { /* best-effort */ }

        // Background-notification hygiene: remove any delivered
        // "Notification" notification — a post-wipe device must not display
        // evidence that messages had arrived. (The WorkManager background poll
        // this used to also cancel has been removed entirely — every remaining
        // transport is server-pushed, FCM and UnifiedPush alike, so there is no
        // local schedule left to cancel.)
        NotificationHelper.cancelAll(context)
        // Delete the CHANNEL too, not just the notifications shown on it. This
        // does NOT remove the proof that the app posted notifications: Android
        // keeps deleted channels on record (restorable if re-created), and the
        // app's notification settings page shows "N categories deleted". No app
        // API purges that record; it is listed in SECURITY_OVERVIEW's "Traces
        // left on the device" (review 2026-11-06, S1 F2). Deleting still removes
        // the live channel's name, importance and lock-screen setting.
        NotificationHelper.deleteChannel(context)
        // Same rule for the keep-alive's own standby channel. Best-effort: the
        // OS refuses to delete a channel while its foreground service is still up,
        // so TorKeepAliveService.onDestroy repeats this once the latch is set.
        TorKeepAliveService.deleteChannel(context)
        // The per-app language override on API 33+
        // lives in the OS's LocaleManager store — a system-owned, user-attributable
        // record (visible in Settings › Apps › Rún › Language) that no file delete
        // reaches and that only the in-app picker ever sets, so its survival proved
        // both "this app was used" and which language its user chose. Same class as
        // the channel record above; reset it to "follow system". Runs AFTER the
        // crypto-erase + file deletes (it triggers an async config change), wrapped
        // so a throw cannot abort the wipe. API 29-32 is covered by PREFS_FILES.
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
            try {
                context.getSystemService(android.app.LocaleManager::class.java)
                    ?.applicationLocales = android.os.LocaleList.getEmptyLocaleList()
            } catch (_: Exception) { /* best-effort residue removal, never gates the wipe */ }
        }

        // Clear the in-memory log buffer so a RAM capture taken
        // after a panic wipe can't recover buffered id prefixes / lengths /
        // unlock events. Empty in production (LoggingState is DEBUG-only) but
        // non-empty in beta/DEBUG builds.
        LogBuffer.clear()
        // Debug mode: a wipe REVOKES the diagnostic-upload
        // consent in THIS process too, on every wipe path — the ViewModel-less
        // launch-time wipes (InactivityWipe / orphaned-credential self-heal in
        // MainActivity) never reach RunViewModel.performEmergencyWipe, and the
        // wiped process routes on to setup without a relaunch. BuildConfig.DEBUG,
        // not `false`: a debug build enables logging for its own reasons.
        LoggingState.enabled = BuildConfig.DEBUG
        DebugLogUploader.resetCursor()
        // Same reasoning, and NOT debug-gated: the connection-log panel's ring
        // buffer is live in RELEASE builds too (ConnectionLog.kt). No marker
        // line is appended here — a wipe leaves nothing, deniably.
        ConnectionLog.clear()

        // LAST, after the crypto-erase and every file delete: give the CAMERA and
        // POST_NOTIFICATIONS grants back (review 2026-11-06, S1 F1). Each is asked
        // for by exactly one feature (QR pairing, push opt-in), so a grant that
        // survives the wipe proves the feature was used. The revocation takes
        // effect when the OS kills the process, which it does once the app leaves
        // the foreground: that also ends the deniable black-screen cover's
        // process, which is acceptable (backgrounding tears the session down
        // anyway, and the cover's point is that nothing shows). Best-effort; a
        // throw never gates the wipe. Below API 33 there is no such API and the
        // grants stay, a known trace (SECURITY_OVERVIEW "Traces left on the
        // device"). Release only: the debug test-wipe hook runs this routine
        // between e2e specs, and the push suites rely on the install-time grants.
        if (!BuildConfig.DEBUG && android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
            try {
                context.applicationContext.revokeSelfPermissionsOnKill(
                    listOf(android.Manifest.permission.CAMERA, android.Manifest.permission.POST_NOTIFICATIONS)
                )
            } catch (_: Exception) { /* best-effort residue removal, never gates the wipe */ }
        }
    }

    // The UnifiedPush tier's on-disk artifacts follow the SAME single-owner
    // rule: UnifiedPushSupport owns the list (the connector's
    // `unifiedpush-connector` database, its legacy `unifiedpush.connector`
    // prefs, our `unifiedpush_state_prefs`) and both the wipe path above and
    // RunViewModel's opt-out branch call it. Its key surface — the
    // AndroidKeyStore alias the connector seals WebPush private keys under — is
    // erased separately and FIRST, mirroring how the two legacy AEAD key
    // surfaces are handled.
    //
    // The on-disk Firebase/FCM push artifacts are swept by
    // VendorPush.sweepLocalArtifacts — deliberately ONE implementation, owned by
    // VendorPush, because this list is now
    // called from two places: here on the wipe path, and from RunViewModel when
    // the user opts OUT of push. A duplicated deletion list is exactly the
    // drift class hand-maintained purge lists have shown before, so
    // do not re-inline it. It is not part of [PREFS_FILES] because two of the
    // four artifacts (PersistedInstallation*.json, the no-backup marker) are not
    // SharedPreferences files at all.
}
