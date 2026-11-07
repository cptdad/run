package com.vg.run

import android.content.Context
import com.google.android.gms.common.ConnectionResult
import com.google.android.gms.common.GoogleApiAvailability
import com.google.firebase.messaging.FirebaseMessaging
import kotlinx.coroutines.suspendCancellableCoroutine
import java.util.concurrent.Executor
import java.util.concurrent.atomic.AtomicBoolean

// ---------------------------------------------------------------------------
// VendorPush — the FCM side of the vendor-push seam, `google` flavour. The seam
// has two halves: this file (Play Services present ⇒ FCM; isAvailable() is the
// first branch everywhere, devices without Play Services route to UnifiedPush)
// and src/foss/.../VendorPush.kt, a stub with the same API whose isAvailable()
// is always false, so the `foss` build (F-Droid) carries no Firebase or Play
// Services code at all. Main code reads the seam flavour-blind. The RAM-only
// state both halves share (FisTeardownGate, VendorPushIdentityEpoch) lives in
// src/main/.../VendorPushState.kt.
// ---------------------------------------------------------------------------

object VendorPush {

    /**
     * Diagnostics tag. Everything logged under it is BOOLEANS, exception class
     * names and SDK messages only — never a token, never an inbox id, never
     * message bytes (content-discipline invariant I4).
     */
    private const val LOG_TAG = "VendorPush"

    /**
     * The SDK's own SharedPreferences file, where `setAutoInitEnabled` persists.
     * MUST stay in sync with WipeRoutine's Firebase-artifact deletion list —
     * that is the code that removes this file on every wipe; the name here only
     * exists so [destroyLocalPushIdentity] can flush a pending write to it
     * before that deletion runs.
     */
    private const val FCM_PREFS_FILE = "com.google.firebase.messaging"

    /**
     * True iff Google Play Services is present AND usable on this device.
     * Checked both at opt-in and at every re-sync — Play Services can be
     * uninstalled/disabled between the two — so callers must
     * re-probe rather than cache this across a session.
     */
    fun isAvailable(context: Context): Boolean =
        GoogleApiAvailability.getInstance().isGooglePlayServicesAvailable(context) ==
            ConnectionResult.SUCCESS

    /**
     * Refuses Google Play Services' standing
     * offer to render FCM notifications ON THIS APP'S BEHALF via
     * `NotificationManager.setNotificationDelegate` — the "notification
     * delegation" capability `ProxyNotificationInitializer` grants
     * UNCONDITIONALLY at first launch (bytecode-verified against
     * firebase-messaging 25.1.2: its enabling lambda, unlike its two siblings,
     * is NOT gated on `isAutoInitEnabled`, so
     * `firebase_messaging_auto_init_enabled=false` does not stop it). Left
     * enabled, a hostile relay can send a display-type (not data-only) FCM
     * payload and have `com.google.android.gms` post it as a Rún notification
     * with attacker-chosen title/body — WITHOUT this app's process ever
     * starting, so `RunFcmService.handleIntent`'s D-1 strip and the
     * `NotificationLevelStore` wake gate are both bypassed entirely.
     *
     * The manifest meta-data (`firebase_messaging_notification_delegation_enabled
     * =false`, `AndroidManifest.xml`) is the other half of this fix and is
     * NOT sufficient alone: it only steers a FRESH grant. The SDK persists
     * whichever delegate it last set, once-ever, in its own prefs — so an
     * install that already granted the delegate before this fix shipped needs
     * this RUNTIME call to revoke it. Called from:
     *  - [RunApplication.onCreate], every process, so the revocation applies
     *    even to an install that never explicitly opts into push (the SDK's
     *    proxy-notification init runs from `FirebaseInitProvider`'s eager
     *    component regardless of opt-in);
     *  - [destroyLocalPushIdentity], which is itself called from both
     *    `WipeRoutine`'s full-wipe path and every push opt-out
     *    (`RunViewModel.setBackgroundNotificationsEnabledAwaiting`'s disable
     *    branch) — the delegate is SYSTEM-side per-package state
     *    (`NotificationManagerService`), so nothing else on either of those
     *    paths would ever clear it.
     *
     * `setNotificationDelegationEnabled` is documented to require a live
     * `FirebaseApp`/Play-Services context, so this mirrors [isAvailable]'s
     * guard and is additionally try/caught: a FOSS device with no Play
     * Services must never crash on this call, at startup or during a wipe.
     */
    fun disableNotificationDelegation(context: Context) {
        if (!isAvailable(context)) return
        try {
            FirebaseMessaging.getInstance().setNotificationDelegationEnabled(false)
        } catch (e: Exception) {
            platformLogWarn(
                LOG_TAG,
                "disableNotificationDelegation: threw ${e.javaClass.simpleName}",
            )
        }
    }

    /**
     * The current FCM registration token, or null on ANY failure (Play
     * Services unavailable, no network, token-fetch error) — fail-soft,
     * mirroring every other relay-call site in this codebase. Firebase caches
     * the token locally, so this is cheap to call repeatedly.
     *
     * That cache self-corrects for SDK-INITIATED rotations only (the SDK
     * refreshes and fires
     * [onNewToken][com.google.firebase.messaging.FirebaseMessagingService.onNewToken]).
     * It does NOT self-correct after we destroy the identity out of band — the
     * earlier claim that this "always returns the CURRENT token even after a
     * rotation" was false in exactly the case that matters, and the bug it hid
     * is the one [VendorPushIdentityEpoch] documents. So when that latch is
     * armed, this awaits a `deleteToken()` that must report SUCCESS —
     * `addOnSuccessListener`/`addOnFailureListener`, never `addOnComplete`,
     * because the SDK evicts its local `Store` entry only on the branch where
     * the revocation RPC actually succeeded. A delete that fails or throws
     * returns null with the latch STILL ARMED: this pass registers nothing and
     * the next cycle retries, which is recoverable, whereas re-asserting a
     * token that is probably already dead is not.
     *
     * Explicitly re-enables SDK auto-init
     * immediately before requesting the token. The manifest now ships
     * `firebase_messaging_auto_init_enabled=false`, so with no call site ever
     * flipping it back on the SDK would never register at all; this is the
     * ONE call site that does, and it is reached only from the app's own
     * genuine opt-in flow ([RunViewModel.refreshVendorPushRegistration]) —
     * never from process start. The flag PERSISTS in the SDK's own
     * SharedPreferences across app restarts, so it must be (and is) flipped
     * back off on every wipe by [destroyLocalPushIdentity].
     */
    suspend fun currentToken(context: Context): String? {
        if (!isAvailable(context)) {
            platformLog(LOG_TAG, "currentToken: no vendor transport available")
            return null
        }
        return try {
            val fcm = FirebaseMessaging.getInstance()
            fcm.isAutoInitEnabled = true
            if (VendorPushIdentityEpoch.refreshRequired()) {
                // Shape is load-bearing and pinned by
                // VendorPushOptOutTeardownSourceTest: the delete's Boolean MUST
                // be consumed inline as `if (!awaitProvenTokenDelete(…)) return
                // null`, because merely calling it and clearing the latch
                // afterwards re-creates the dead-token bug. The diagnostic
                // logging therefore lives INSIDE awaitProvenTokenDelete rather
                // than around this call.
                if (!awaitProvenTokenDelete(fcm)) return null
                VendorPushIdentityEpoch.markRefreshProven()
            }
            suspendCancellableCoroutine { cont ->
                fcm.token
                    .addOnSuccessListener { token -> cont.resumeWith(Result.success(token)) }
                    .addOnFailureListener { e ->
                        // e.g. FIS_AUTH_ERROR after the Firebase Installation was
                        // destroyed by a wipe/opt-out. The SDK will NOT retry it.
                        platformLogWarn(LOG_TAG, "currentToken: token fetch failed: ${e.javaClass.simpleName}")
                        cont.resumeWith(Result.success(null))
                    }
            }
        } catch (e: Exception) {
            platformLogWarn(LOG_TAG, "currentToken: threw ${e.javaClass.simpleName}")
            null
        }
    }

    /**
     * Awaits `deleteToken()` and answers whether it SUCCEEDED — the distinction
     * the whole fix turns on, since `addOnCompleteListener` would answer merely
     * "it finished" and the local token cache is evicted only on the success
     * branch (see [VendorPushIdentityEpoch]).
     *
     * Resumes on [DIRECT_EXECUTOR] so the answer does not depend on the main
     * looper being free; the caller is already on a background dispatcher.
     */
    private suspend fun awaitProvenTokenDelete(fcm: FirebaseMessaging): Boolean =
        suspendCancellableCoroutine { cont ->
            fcm.deleteToken()
                .addOnSuccessListener(DIRECT_EXECUTOR) {
                    // The single most useful diagnostic in this file. Every
                    // failure mode of [currentToken] used to collapse into an
                    // identical silent `null`, so from outside the process "the
                    // latch gated us" and "FCM refused to mint a token" were
                    // indistinguishable — three consecutive on-device failures
                    // (2026-08-09/10) could not be attributed to either, and two
                    // independent reviews reached OPPOSITE conclusions from the
                    // same evidence.
                    platformLog(LOG_TAG, "provenTokenDelete: SUCCEEDED — latch will be cleared")
                    cont.resumeWith(Result.success(true))
                }
                .addOnFailureListener(DIRECT_EXECUTOR) { e ->
                    platformLogWarn(
                        LOG_TAG,
                        "provenTokenDelete: FAILED (${e.javaClass.simpleName}) — " +
                            "latch stays armed, this pass registers nothing",
                    )
                    cont.resumeWith(Result.success(false))
                }
        }

    /**
     * Destroys this device's LOCAL Firebase
     * push identity — called from [WipeRoutine.wipePersistentState] on EVERY
     * wipe path (settings opt-out, emergency wipe, and the absent-user
     * inactivity wipe). `deleteToken()` revokes the FCM registration at
     * Google — which is also what makes the relay's stored `inboxId -> token`
     * row a dead reference without any relay-side call; `FirebaseInstallations
     * .delete()` additionally rotates the Firebase Installation ID (FID) the
     * token is derived from. `firebase-installations` is a TRANSITIVE
     * dependency of `firebase-messaging-ktx` (confirmed on the resolved
     * app classpath; nothing new added to build.gradle.kts for
     * this), so calling it directly is safe.
     *
     * Both are async, network-dependent Play-Services `Task`s that this wipe
     * path — deliberately synchronous, and required to NEVER block on the
     * network — cannot await. [onSettled] fires when they have, on the
     * completing background thread, so the caller can sweep the on-disk
     * artifacts the SDK REWRITES on its way through (a fresh FID persisted to
     * authenticate the delete RPC, the token removal committed back into
     * `com.google.android.gms.appid`). It is a cleanup hook, never a gate:
     * the caller deletes those artifacts synchronously too, so a process death
     * before the Tasks complete — which also means the SDK never got to
     * rewrite anything — still leaves nothing readable. Not a `suspend` fun
     * and nothing here joins/awaits.
     *
     * The two Tasks are CHAINED, not fired in parallel: `deleteToken()`
     * requires a live FID to authenticate its RPC, so deleting the
     * installation concurrently would race the token revocation it is supposed
     * to follow.
     *
     * Also flips auto-init back off (undoing [currentToken]'s just-in-time
     * enable) so the still-alive process — the panic wipe deliberately keeps it
     * running behind a black screen — cannot re-register through the SDK after
     * the wipe. Two details there, both about not leaving a file behind:
     *  - written ONLY when it is actually ON. The setter persists into the SDK's
     *    own prefs file, so writing it unconditionally would CREATE that file on
     *    installs that never opted into push. Reading `false` needs no write:
     *    the manifest's `firebase_messaging_auto_init_enabled=false` is what the
     *    SDK falls back to once the caller deletes the prefs entry.
     *  - the setter persists via `apply()`, an ASYNC flush that would otherwise
     *    land AFTER the caller's synchronous deletion and recreate the file.
     *    The `commit()` below drains SharedPreferences' serialized write queue
     *    (a sync commit is queued behind, and awaits, every pending write to the
     *    same file), so the flush is on disk before this returns and the
     *    caller's delete is the last word. It writes nothing itself — the value
     *    is already in the in-memory map, so `changesMade` is false.
     *
     * Leaves a lasting mark on [currentToken] for the rest of the process: it
     * arms [VendorPushIdentityEpoch], so the next token fetch must first PROVE a
     * `deleteToken()`. Without that, an install that opts back in during the
     * same process re-registers the pre-teardown token out of the SDK's
     * in-memory `Store` — a token whose installation this function just
     * destroyed, which FCM accepts and never delivers.
     */
    @android.annotation.SuppressLint("ApplySharedPref")
    fun destroyLocalPushIdentity(context: Context, onSettled: () -> Unit) {
        // FIRST statement, before any async work and before the caller's own
        // synchronous sweep: from this instruction on, every token the SDK can
        // hand out is suspect, and nothing below may leave the latch disarmed —
        // not the catch fallback, not a delete that fails. See
        // [VendorPushIdentityEpoch].
        VendorPushIdentityEpoch.markIdentityDestroyed()
        // Armed BEFORE the chain below can start, and before the caller's own
        // synchronous sweep runs: from here until the chain settles, the sweep
        // must leave the Installations SDK's state file alone. See
        // [FisTeardownGate] — deleting it mid-chain is what makes the SDK POST
        // `authTokens:generate` for a null fid and take a 24-hour FIS lockout.
        FisTeardownGate.arm()
        val settledLatch = java.util.concurrent.CountDownLatch(1)
        val deferReleased = AtomicBoolean(false)
        // Idempotent: whichever of the settle and the cap gets there first.
        val releaseDefer: () -> Unit = {
            if (deferReleased.compareAndSet(false, true)) FisTeardownGate.release()
        }
        // The late half. It now WAITS for the chain to settle before its first
        // pass — the out-of-band writes this teardown provokes were measured
        // relative to the settle ("gone at settle+11 ms, BACK at settle+25 ms"),
        // and a pass that lands mid-chain is the very race above. Delete-only,
        // bounded, and it never blocks anything in this function.
        scheduleLateArtifactSweeps(context, settledLatch, releaseDefer)
        // Both callers of this function (WipeRoutine's full wipe and
        // RunViewModel's push opt-out) must also revoke the SYSTEM-side
        // notification-delegation grant — see [disableNotificationDelegation].
        // Synchronous and before the async chain, same reasoning as the
        // auto-init flip below: best-effort, never blocks the teardown.
        disableNotificationDelegation(context)
        val settled = AtomicBoolean(false)
        // Runs the caller's sweep at most once, whichever link of the chain
        // reaches it (normal completion, or the catch fallbacks below).
        val finish: () -> Unit = {
            if (settled.compareAndSet(false, true)) {
                // Re-armed at SETTLE, not only at entry, because the chain is
                // async and its last link is the installation delete. A user who
                // re-enables push seconds after a failed enable can complete a
                // proven refresh (latch cleared, fresh token fetched and
                // registered) BEFORE that delete lands — which then destroys the
                // FID the brand-new token is bound to and recreates the exact
                // dead-token state. Arming again costs one extra
                // delete-and-refetch on the next registration pass (≤45 s away,
                // on the control-poll cycle) and can never suppress one.
                VendorPushIdentityEpoch.markIdentityDestroyed()
                // Released BEFORE onSettled(), so the settle sweep is the pass
                // that finally removes PersistedInstallation.*.json — the chain
                // has read everything it needed by now.
                releaseDefer()
                settledLatch.countDown()
                try { onSettled() } catch (_: Exception) { /* best-effort */ }
            }
        }
        try {
            val fcm = FirebaseMessaging.getInstance()
            if (fcm.isAutoInitEnabled) {
                fcm.isAutoInitEnabled = false
                context.getSharedPreferences(FCM_PREFS_FILE, Context.MODE_PRIVATE).edit().commit()
            }
            fcm.deleteToken().addOnCompleteListener(DIRECT_EXECUTOR) { deleteInstallation(finish) }
        } catch (_: Exception) {
            // FirebaseApp not initialized / Play Services missing: nothing local
            // to revoke through FCM, but still rotate the installation below.
            deleteInstallation(finish)
        }
    }

    /**
     * Opt-out identity teardown: sweeps the SAME
     * on-disk Firebase/FCM artifacts `WipeRoutine`'s private
     * `deleteVendorPushArtifacts` removes on a full wipe. Duplicated here
     * rather than exposed from `WipeRoutine` — that file's deletion list stays
     * the single source of truth for the FULL wipe (it also tears down the
     * vault DB, Tor dirs, and every other prefs file, none of which belong in
     * a lightweight opt-out), but the settings opt-out toggle
     * ([RunViewModel.setBackgroundNotificationsEnabledAwaiting]'s disable
     * branch) needs exactly this narrower sweep so a live, Google-side-
     * correlatable install identity doesn't survive turning push OFF — until
     * this fix the only caller of the identity teardown was `WipeRoutine`
     * (wipe-only), so opt-out left `currentToken`'s auto-init-enabled FCM
     * token and Firebase Installation ID on disk untouched.
     *
     * MUST stay in sync with `WipeRoutine`'s list — the same coupling
     * [FCM_PREFS_FILE]'s kdoc already documents for the token-flush file.
     * Meant to be passed as [destroyLocalPushIdentity]'s `onSettled` callback,
     * mirroring the wipe call site's `{ deleteVendorPushArtifacts(app) }`.
     *
     * Idempotent and best-effort: never throws, safe to call on an install
     * that never opted into push (the named files simply don't exist).
     */
    fun sweepLocalArtifacts(context: Context) {
        try {
            context.deleteSharedPreferences("com.google.android.gms.appid")
            context.deleteSharedPreferences(FCM_PREFS_FILE)
            // firebase-installations 19.1.2 (pinned by this app's firebase-bom
            // 34.18.0, 2026-08-21 bump) moved PersistedInstallation's data file:
            // `PersistedInstallation.getDataFile()` now tries
            // `Context.getNoBackupFilesDir()` FIRST and only migrates a legacy
            // `filesDir` copy into it via `File.renameTo` — it does not delete
            // the old location outright, and a failed renameTo leaves the old
            // copy in place too. Sweep BOTH directories so a fresh 19.1.2 file,
            // a migrated-but-stale legacy copy, and a pre-19.1.2 install that
            // never upgraded are all covered. The file's fields are
            // Fid/Status/AuthToken/RefreshToken/... — a live bearer credential.
            val persistedInstallationFilter = java.io.FileFilter { f ->
                f.name.startsWith("PersistedInstallation.") && f.name.endsWith(".json")
            }
            // …but NOT while this process's own revocation chain is still reading
            // it. Deleting it mid-chain makes the Installations SDK re-read the
            // ABSENT-file default (ATTEMPT_MIGRATION / no fid) and POST
            // `installations/<null fid>/authTokens:generate`, whose 400
            // INVALID_ARGUMENT locks every later FIS request out for 24 HOURS —
            // see [FisTeardownGate] for the measured proof. The deferral is
            // bounded by the settle (or SETTLE_WAIT_CAP_MS), and the settle sweep
            // plus the late passes are what then remove it, so the file's life is
            // bounded either way. Every OTHER artifact below is still swept
            // synchronously, unconditionally.
            if (!FisTeardownGate.isPending()) {
                context.filesDir?.listFiles(persistedInstallationFilter)?.forEach { it.delete() }
                context.noBackupFilesDir?.listFiles(persistedInstallationFilter)?.forEach { it.delete() }
            }
            // Not just residue — this marker is the SDK's own token-cache
            // invalidator, and deleting it is the only lever we have over a
            // FUTURE process. `Store.<init>` calls `checkForRestore`, which on a
            // MISSING marker recreates it and calls `deleteAll()` on the token
            // prefs ("App restored, clearing state"). So an install whose
            // identity was destroyed while the delete RPC failed still cannot
            // serve the dead token to the next process. Do not "optimise" this
            // line away as a duplicate of the deleteSharedPreferences above:
            // that one only removes the file, this one removes the SDK's reason
            // to trust whatever the file says.
            java.io.File(context.noBackupFilesDir, "com.google.android.gms.appid-no-backup").delete()
            // 2C-2 sibling: FirebaseInstallations' multi-process-safe prefs
            // helper (`getMultiProcessSafePrefs()`, invoked from both
            // `deleteFirebaseInstallationId()` above and the SDK's own
            // create/refresh path) takes `CrossProcessLock.acquire(ctx,
            // "generatefid.lock")` — a `FileLock` on a plain `filesDir` file the
            // SDK creates but never deletes. Zero-byte and content-free, but a
            // dated, app-attributable artifact a "never configured push"
            // account should not carry.
            java.io.File(context.filesDir, "generatefid.lock").delete()
            // 2C-1 sibling: the Firebase heartbeat store
            // (`files/datastore/FirebaseHeartBeat<persistenceKey>.preferences_pb`,
            // androidx.datastore-backed) is written after the first push
            // opt-in and is never named by any wipe path. `datastore/` is a
            // directory dedicated to this one store in this app (nothing else
            // uses androidx.datastore), so removing it wholesale is safe and
            // covers any file inside regardless of name.
            deleteHeartbeatStore(context)
        } catch (_: Exception) { /* best-effort */ }
    }

    /**
     * The 2C-1 artifact on its own, so the reasoning about it can live in one
     * place. Never throws.
     *
     * The file name is `FirebaseHeartBeat<persistenceKey>[.preferences_pb]`, and
     * `persistenceKey` has MOVED between firebase-common releases (it is
     * `base64(appName)` on old ones and `base64(appName)+base64(appId)` on
     * firebase-common 22.2.x — both shapes were observed on one Pixel 7), which
     * is exactly why this deletes the DIRECTORY rather than any name.
     */
    private fun deleteHeartbeatStore(context: Context) {
        try {
            java.io.File(context.filesDir, HEARTBEAT_DATASTORE_DIR).deleteRecursively()
        } catch (_: Exception) { /* best-effort */ }
    }

    /** See [deleteHeartbeatStore] — dedicated to Firebase's heartbeat store in this app. */
    private const val HEARTBEAT_DATASTORE_DIR = "datastore"

    /**
     * Delays of the delete-only passes [scheduleLateArtifactSweeps] runs after a
     * teardown, measured from the moment that teardown's revocation chain
     * SETTLES (2026-09-17; they used to be measured from the teardown call, which
     * put the first pass inside the window the chain is still reading its state
     * in — see [FisTeardownGate]).
     *
     * Measured on a Pixel 7 (firebase-bom 34.19.0: firebase-common 22.2.1,
     * firebase-installations 19.1.2, androidx.datastore 1.1.7). The heartbeat
     * write our own teardown provokes lands ~140 ms after
     * [destroyLocalPushIdentity] is entered — after the caller's synchronous
     * sweep and, because the two FCM Tasks complete in ~10 ms when there is no
     * token to revoke, after the post-settle sweep as well. `generatefid.lock`
     * is re-created on the same kind of schedule by the installation delete. The
     * later passes cover a slow device and a `deleteToken()` RPC that only
     * settles seconds later (its request registers another heartbeat on the way
     * out).
     */
    private val LATE_SWEEP_DELAYS_MS = longArrayOf(1_000L, 4_000L, 10_000L)

    /**
     * How long the late-sweep thread waits for the teardown chain to settle
     * before sweeping anyway. Sized so the whole thread (wait + the last delay
     * above) stays inside the 20 s budget the instrumented residue tests give
     * [awaitLateSweepsForTest], and comfortably past the Installations SDK's own
     * 10 s connect / 10 s read timeouts, so a chain still unsettled at this point
     * is wedged rather than slow.
     */
    private const val SETTLE_WAIT_CAP_MS = 8_000L

    /** The most recently scheduled late-sweep thread; see [awaitLateSweepsForTest]. */
    @Volatile
    private var lateSweepThread: Thread? = null

    /**
     * The missing half of the identity teardown: re-run the artifact sweep a few times after
     * a teardown, because the SDK re-creates some of these files MILLISECONDS
     * after the sweep — dated AFTER the wipe, and then never touched again.
     *
     * Why the existing two passes cannot catch it. `destroyLocalPushIdentity`'s
     * synchronous sweep and its post-settle sweep are sufficient for exactly the
     * writes that happen strictly before one of the two FCM `Task`s completes.
     * They are NOT ordered against work the SDK performs out of band: the
     * heartbeat record is written by androidx.datastore on its own coroutine
     * scope, and `CrossProcessLock.acquire(ctx, "generatefid.lock")` re-creates
     * the lock file whenever the installations SDK next takes it. Observed on a
     * Pixel 7: `files/datastore` gone at settle+11 ms, BACK at settle+25 ms, and
     * still there 10 s later — i.e. every wipe left it behind, permanently.
     *
     * [VendorPushIdentityEpoch.markIdentityDestroyed] is re-armed before each
     * pass, for the same reason `finish` re-arms it at settle: a pass that
     * deletes an installation a re-onboarding user created seconds earlier must
     * leave this process distrusting the token bound to it. Arming again costs
     * at most one extra delete-and-refetch on the next registration pass and can
     * never suppress a registration.
     *
     * Delete-only (it creates nothing and writes nothing), so it is safe after
     * the crypto-erase and needs no [ProcessWipeLatch] gate. One daemon thread,
     * bounded by the last delay above, that never blocks its caller, never
     * throws and dies with the process.
     *
     * Known limitation: a process killed inside that window leaves
     * whatever the SDK last re-created on disk (dates, a zero-byte lock file —
     * no token, no installation id, since those are destroyed server-side by the
     * teardown itself). Bounding the window is what this can do; closing it
     * would mean either blocking the wipe on a network-dependent SDK or not
     * revoking the push identity at all.
     */
    private fun scheduleLateArtifactSweeps(
        context: Context,
        settledLatch: java.util.concurrent.CountDownLatch,
        releaseDefer: () -> Unit,
    ) {
        val app = context.applicationContext
        try {
            val t = Thread({
                // Phase 1 — wait for OUR OWN revocation chain. Every delay below
                // is measured from the settle, not from the poke, because that is
                // where the out-of-band rewrites were measured and because a pass
                // that lands while the chain is mid-read is the 24-hour-lockout
                // race [FisTeardownGate] documents.
                val settled = try {
                    settledLatch.await(SETTLE_WAIT_CAP_MS, java.util.concurrent.TimeUnit.MILLISECONDS)
                } catch (_: InterruptedException) {
                    // Interrupted before the chain settled: the deferral would
                    // otherwise outlive the only thread that can lift it, so the
                    // state file would survive every later sweep in this process.
                    releaseDefer()
                    return@Thread
                }
                // Cap reached: the chain is wedged (no network, Play Services
                // down). Stop deferring — a live Fid/AuthToken/RefreshToken left
                // on disk is worse than poisoning an SDK whose own 10 s request
                // timeouts have already expired twice over.
                if (!settled) releaseDefer()
                var waited = 0L
                for (at in LATE_SWEEP_DELAYS_MS) {
                    try { Thread.sleep(at - waited) } catch (_: InterruptedException) { return@Thread }
                    waited = at
                    VendorPushIdentityEpoch.markIdentityDestroyed()
                    sweepLocalArtifacts(app)
                }
            }, "push-artifact-sweep")
            t.isDaemon = true
            lateSweepThread = t
            t.start()
        } catch (_: Throwable) {
            // The thread is the ONLY thing that can lift the deferral when the
            // chain never settles, so a thread that never started must not leave
            // the Installations state file deferred forever. The settle path
            // (which is idempotent with this one) still runs normally.
            releaseDefer()
            // Best-effort otherwise; the synchronous sweeps already ran.
        }
    }

    /**
     * Test-only: block until the scheduled late passes have finished, so an
     * instrumented test that seeds these artifacts cannot have them deleted by a
     * PREVIOUS test's teardown mid-seed. Production never calls it.
     */
    @androidx.annotation.VisibleForTesting
    fun awaitLateSweepsForTest(timeoutMs: Long) {
        // Note for callers: since 2026-09-17 that thread first waits for the
        // teardown chain to settle (bounded by SETTLE_WAIT_CAP_MS), so the budget
        // has to cover the settle plus the last delay above.
        try { lateSweepThread?.join(timeoutMs) } catch (_: InterruptedException) { }
    }

    /** Second link of [destroyLocalPushIdentity]'s chain; always settles. */
    private fun deleteInstallation(onSettled: () -> Unit) {
        try {
            com.google.firebase.installations.FirebaseInstallations.getInstance()
                .delete()
                .addOnCompleteListener(DIRECT_EXECUTOR) { onSettled() }
        } catch (_: Exception) {
            onSettled()
        }
    }

    /**
     * Runs the completion listener on whatever thread completed the Task (the
     * SDK's own background executor) instead of the main looper — the listener
     * deletes files, which must not land on the UI thread, and no new thread
     * needs to exist for a wipe. When the Task is ALREADY complete (e.g.
     * `deleteToken()` short-circuits to a resolved Task when no token was ever
     * issued) the listener runs inline on the caller, which is exactly right:
     * nothing was written, so the sweep is a no-op.
     */
    private val DIRECT_EXECUTOR = Executor { it.run() }
}
