package com.vg.run

import android.app.Activity
import android.content.Context
import org.unifiedpush.android.connector.UnifiedPush

// ---------------------------------------------------------------------------
// UnifiedPushSupport — the app-side wrapper around the connector library,
// shaped like the `VendorPush` runtime seam so RunViewModel/WipeRoutine can call
// the two transports through the same verbs (isAvailable / register /
// unregister / destroyLocalPushIdentity / sweepLocalArtifacts).
//
// ONE DELIBERATE ASYMMETRY vs. VendorPush: the sweep is SPLIT in two.
// sweepLocalArtifacts (wipe path) CLOSES the connector's cached SQLite handle
// and then unlinks its database file; sweepInSessionArtifacts (opt-out /
// failed enable) touches neither, because the in-session teardowns must leave
// the connector's live handle working for an immediate retry. The close is
// load-bearing: unlinking under the open handle the connector caches in a
// static singleton wedges every later write for the life of the process, and
// most WIPE paths keep running in that process too (they fall through to
// setup). Read both kdocs before touching either call site.
//
// Unlike VendorPush this is NOT a runtime-selected seam — there is one implementation,
// compiled into every build, because the connector carries no Google code.
//
// EVERYTHING HERE IS LOCAL. Nothing in this file performs network I/O: the
// connector talks to the distributor APP over intents, and the relay-side
// registration (which needs an open vault for the read capability) lives in
// RunViewModel. Do not add a relay call here.
// ---------------------------------------------------------------------------

object UnifiedPushSupport {

    /**
     * The AndroidKeyStore alias the connector wraps its WebPush PRIVATE keys
     * under (`WebPushKeysEntries23.ALIAS`, verified by disassembling
     * connector-3.3.5.aar — the library exposes no constant for it).
     *
     * Named here so [eraseKeySurface] can crypto-erase it. Same pattern, same
     * reason, as [NotificationPollStore.eraseLegacyManifestKeySurface]: the
     * class that owns the name lives in a third-party AAR, so nothing else in
     * this app would ever destroy it.
     *
     * If a future connector version renames this, the erase becomes a silent
     * no-op — [UnifiedPushArtifactSweepTest] seeds and asserts on the alias so
     * the rename surfaces as a test failure rather than as surviving key
     * material.
     */
    private const val CONNECTOR_KEYSTORE_ALIAS = "UnifiedPush"

    /**
     * The connector's own SQLite database (`DBStore.DB_NAME`): distributor
     * choice, per-instance registrations, connector tokens, and the `keys`
     * table — which holds the WebPush private key AES-GCM-sealed under the
     * `UnifiedPush` alias, and, in the CLEAR beside it, the RFC 8291 `auth`
     * shared secret (verified in the disassembly; the library encrypts only
     * `privKey`). See [sweepInSessionArtifacts] for what covers which.
     *
     * This is the artifact that would be easiest to miss — "the code
     * is deleted but the data survives". It is covered TWICE on the wipe path:
     * by name here, and by `WipeRoutine`'s wholesale `databases/`
     * deleteRecursively.
     *
     * It is deliberately NOT deleted on the in-session paths — see
     * [sweepInSessionArtifacts] for why unlinking it there wedges the connector
     * and why [eraseKeySurface] is what actually protects its contents.
     */
    private const val CONNECTOR_DB_NAME = "unifiedpush-connector"

    /**
     * The connector's LEGACY (pre-3.x) SharedPreferences file
     * (`LegacyStore.PREF_MASTER`). Connector 3.x migrates out of it into
     * [CONNECTOR_DB_NAME] but — verified in the disassembly — never calls
     * `deleteSharedPreferences`, so a migrated install keeps the old file with
     * the old endpoint/keys in it forever. Deleted by name; a no-op on installs
     * that never ran a 2.x connector (which is all of ours today, but "all of
     * ours today" is not a property a wipe list may depend on).
     */
    private const val CONNECTOR_LEGACY_PREFS = "unifiedpush.connector"

    /**
     * True iff at least one UnifiedPush distributor app is installed.
     *
     * Re-probe, never cache across a session: a distributor is an ordinary app
     * the user can install or uninstall at any moment — the same reasoning
     * [VendorPush.isAvailable]'s kdoc gives for Play Services.
     *
     * Discovery works because the connector AAR ships its own `<queries>` block
     * (LINK / REGISTER / UNREGISTER intent actions), which merges into our
     * manifest — verified by reading connector-3.3.5.aar's AndroidManifest.xml.
     * Without it this would silently return an empty list on API 30+ package
     * visibility. Do NOT duplicate those `<queries>` app-side; if a future
     * connector version drops them, add them then.
     */
    fun isAvailable(context: Context): Boolean =
        try { UnifiedPush.getDistributors(context).isNotEmpty() } catch (_: Exception) { false }

    /** How many distributors are installed — the UI needs this to decide
     *  between "use the only/saved one" and "show the system picker". */
    fun distributorCount(context: Context): Int =
        try { UnifiedPush.getDistributors(context).size } catch (_: Exception) { 0 }

    /**
     * True once a distributor has ACKNOWLEDGED us (`getAckDistributor`), i.e.
     * a registration is genuinely live — as opposed to merely saved-but-never
     * answered. Used to decide whether the toggle can go straight to
     * registration or has to run the selection dance first.
     */
    fun hasAcknowledgedDistributor(context: Context): Boolean =
        try { UnifiedPush.getAckDistributor(context) != null } catch (_: Exception) { false }

    /**
     * Selects a distributor without a UI: the already-saved one if it is still
     * installed, else the single installed one, else nothing (the caller must
     * fall back to [pickDistributor]). Asynchronous — the connector may have to
     * round-trip through its LinkActivity — so the result arrives on [onResult].
     *
     * Never throws: any failure reports `false`, which the caller treats as
     * "couldn't select", never as an error to surface raw.
     */
    fun useCurrentOrDefaultDistributor(context: Context, onResult: (Boolean) -> Unit) {
        try {
            UnifiedPush.tryUseCurrentOrDefaultDistributor(context) { onResult(it) }
        } catch (_: Exception) {
            onResult(false)
        }
    }

    /**
     * Shows the system distributor picker. Needs an [Activity] (it starts one),
     * so the UI layer supplies it; a null/finishing host reports false rather
     * than crashing a settings modal.
     */
    fun pickDistributor(activity: Activity?, onResult: (Boolean) -> Unit) {
        if (activity == null || activity.isFinishing) {
            onResult(false)
            return
        }
        try {
            UnifiedPush.tryPickDistributor(activity) { onResult(it) }
        } catch (_: Exception) {
            onResult(false)
        }
    }

    /**
     * Asks the distributor for an endpoint. Fire-and-forget by construction:
     * the answer comes back out-of-process as
     * [RunPushService.onNewEndpoint]/[RunPushService.onRegistrationFailed],
     * which the caller awaits through [UnifiedPushEndpointSignal].
     *
     * Uses the connector's default instance (`"default"`) and passes NO VAPID
     * key — v1 does not mint one (the relay's WebPush sender is unauthenticated
     * to the push server). A distributor whose push server REQUIRES VAPID
     * answers `FailedReason.VAPID_REQUIRED`, which the toggle surfaces as its
     * own specific error.
     *
     * [resetConnectorBindState] runs FIRST, unconditionally — see its kdoc.
     * Without it, a `connected` flag left stuck `true` by an earlier bind
     * cycle in this process makes the distributor's answer to THIS register()
     * call short-circuit straight to a stale `mService` reference instead of
     * a fresh bind, and [RunPushService.onNewEndpoint] never runs at all
     * (regression, hardware, 2026-08-14: ntfy answered in ~8ms and the
     * endpoint was still never persisted).
     */
    fun register(context: Context) {
        resetConnectorBindState()
        try {
            UnifiedPush.register(context)
        } catch (e: Exception) {
            // Includes the connector's own VapidNotValidException. No material
            // in the message path — just the class name.
            LogBuffer.append("W", "UnifiedPush", "register failed: ${e::class.simpleName}")
            UnifiedPushEndpointSignal.emit(PushEndpointEvent.Failed("INTERNAL_ERROR"))
        }
    }

    /**
     * Forces the connector's OWN `InternalPushServiceConnection` bind-state
     * (`connected`/`binding`) back to "not connected" — the private state
     * machine that decides whether a distributor's answer to [register] is
     * delivered through a fresh `bindService()` → `onServiceConnected()` →
     * `handlePendingEvents()` cycle, or short-circuited straight to a cached
     * `mService` reference.
     *
     * WHY THIS EXISTS (regression, hardware, 2026-08-14 — ntfy 1.25.2
     * F-Droid, a Pixel with GMS off and no Orbot). Disassembling
     * connector-3.3.5 shows `InternalPushServiceConnection.bind` scheduling
     * an UNCONDITIONAL 5-second `Timer` whose task calls
     * `context.unbindService(connection)` no matter what
     * (`InternalPushServiceConnection$bind$$inlined$schedule$1.run`). A
     * client-initiated `unbindService()` on an IN-PROCESS binding does NOT
     * invoke `onServiceConnected`/`onServiceDisconnected` — that callback
     * pair is for the framework tearing the *service's* process down, not a
     * deliberate unbind by the client that made it — so the `connected`/
     * `binding` static flags this object gates `sendEvent` on are NEVER reset
     * once that timer has fired once in this process.
     *
     * The observed effect matches exactly: `NEW_ENDPOINT` delivered by the
     * distributor in ~8ms, "Binding to PushService" → "Service is connected"
     * → (+5s) "Unbinding" in logcat, and the endpoint still never reaches
     * [RunPushService.onNewEndpoint] — because that delivery, or the ONE
     * after it, took the "`connected == true`" fast path in `sendEvent`
     * straight into a stale/torn-down `mService`, and a subsequent register()
     * attempt then never calls `bind()` (never logs "Binding to PushService")
     * at all, since `binding` reads stuck `true` too.
     *
     * THE FIX: force both flags back to `false` immediately before every
     * [register] call, so the event that call is about to provoke is
     * GUARANTEED a fresh bind/connect/handle cycle. Unconditional and safe
     * even when a bind is genuinely still live: `bindService()` on an
     * already-bound-in-process target is idempotent from the caller's side
     * (it just re-delivers `onServiceConnected`), which is the same
     * concurrent-event coalescing this class already performs internally via
     * `binding`.
     *
     * REFLECTION, same reasoning and same disclaimers as
     * [closeConnectorDbHandle]: the library exposes no reset for this state.
     * Field names verified against connector-3.3.5's bytecode
     * (`org.unifiedpush.android.connector.internal.InternalPushServiceConnection`,
     * private static `connected` / `binding`). Best-effort and silent on any
     * failure — a connector upgrade that renames either field degrades back
     * to the pre-fix (rare, timing-dependent) drop instead of crashing the
     * toggle.
     */
    private fun resetConnectorBindState() {
        try {
            val cls = Class.forName(
                "org.unifiedpush.android.connector.internal.InternalPushServiceConnection"
            )
            for (name in listOf("connected", "binding")) {
                val field = cls.getDeclaredField(name)
                field.isAccessible = true
                field.setBoolean(null, false)
            }
        } catch (_: Throwable) { /* best-effort — see kdoc */ }
    }

    /**
     * LOCAL push-identity teardown: tells the distributor to forget us, forgets
     * the distributor, and drops our own endpoint copy.
     *
     * Counterpart of [VendorPush.destroyLocalPushIdentity] — but SYNCHRONOUS
     * and network-free, so it needs no `onSettled` callback and cannot leave a
     * write racing a deletion the way the Firebase Tasks could.
     *
     * ORDER IS LOAD-BEARING, top to bottom:
     *  1. The persisted [NotificationLevel] first — but only when it currently
     *     reads UNIFIED_PUSH, so tearing this transport down can never clear
     *     someone else's VENDOR_PUSH opt-in. Removing it first is what makes
     *     the local wake gate ([RunPushService.onMessage]) read "off"
     *     immediately, independent of whether anything below succeeds; and it
     *     is ALSO what suppresses the spurious "your distributor dropped you"
     *     notice, because the connector broadcasts UNREGISTERED back into our
     *     own [RunPushService.onUnregistered] for a deliberate local
     *     unregister, and that callback only records the notice when the level
     *     still reads UNIFIED_PUSH.
     *  2. `unregister` — asks the distributor to stop delivering.
     *  3. `removeDistributor` — forgets the distributor choice and deletes the
     *     connector's own key material for our instance.
     *  4. our own store.
     *
     * MUST run BEFORE [sweepLocalArtifacts] (and, on the wipe path, before
     * `WipeRoutine`'s wholesale `databases/` deletion): steps 2-3 construct the
     * connector's `DBStore`, which CREATES `databases/unifiedpush-connector` if
     * it is absent. Calling it after the sweep would resurrect exactly the file
     * the sweep just removed — the write-after-delete race the Firebase teardown also has to avoid,
     * in a form that here is trivially avoidable by ordering.
     *
     * WHAT STEPS 2-3 ACTUALLY DELETE — verified against connector-3.3.5's own
     * sources, because this is what makes the IN-SESSION paths able to skip the
     * file unlink entirely (see [sweepInSessionArtifacts]):
     *  - `unregister` → `registrations.remove(instance, keyManager)` deletes the
     *    `registrations` row, which FK-cascades the `tokens` and `keys` rows,
     *    and `DefaultKeyManager.delete` removes the `keys` row directly too;
     *    when that leaves no instances it also runs `distributor.remove()`
     *    (`DELETE FROM distributors`). It then broadcasts ACTION_UNREGISTER to
     *    every token's distributor — the distributor-side subscription teardown.
     *  - `removeDistributor` → unregisters any remaining instance,
     *    `registrations.removeAll` and `distributor.remove()` again.
     * Every one of those is a row-level DELETE issued through the connector's
     * OWN live handle, so it both succeeds and leaves the handle usable.
     *
     * Best-effort and never throws: a distributor that was uninstalled between
     * the check and the call simply isn't there.
     */
    fun destroyLocalPushIdentity(context: Context) {
        val app = context.applicationContext
        try {
            val levelStore = KeyValueStore(app, RunViewModel.NOTIFICATION_LEVEL_PREFS_NAME)
            if (NotificationLevelStore.getLevel(levelStore) == NotificationLevel.UNIFIED_PUSH) {
                // No vault on this teardown path — see RunPushService.
                NotificationLevelStore.clearLevel(levelStore, CryptoProvider(app), vault = null)
            }
        } catch (_: Exception) { /* best-effort */ }
        try { UnifiedPush.unregister(app) } catch (_: Exception) { /* best-effort */ }
        try { UnifiedPush.removeDistributor(app) } catch (_: Exception) { /* best-effort */ }
        try { UnifiedPushStateStore(app).clear() } catch (_: Exception) { /* best-effort */ }
    }

    /**
     * Crypto-erasure of this tier's WHOLE key surface — BOTH AndroidKeyStore
     * aliases:
     *  - [CONNECTOR_KEYSTORE_ALIAS] (`UnifiedPush`), which wraps every stored
     *    WebPush PRIVATE key in the connector's own database;
     *  - [UnifiedPushStateStore.KEYSTORE_ALIAS] (`run_up_state_key`), which
     *    seals the RFC 8291 `p256dh`+`auth` pair in our own prefs.
     *
     * Both, in one function, because this is the single crypto-erase-FIRST slot
     * every teardown path already calls (`WipeRoutine`, the settings opt-out
     * branch and the enable-FAILURE branch of
     * `RunViewModel.setBackgroundNotificationsEnabledAwaiting`, all pinned by
     * `VendorPushOptOutTeardownSourceTest`). A second erase entry point would be
     * a second list to forget — the drift class the shared purge lists exist to
     * close.
     *
     * Purely destructive — creates nothing, writes nothing, never throws — so it
     * is safe in `WipeRoutine`'s key-material-FIRST position, alongside
     * [NotificationPollStore.eraseLegacyManifestKeySurface] and
     * [LegacyTorWarmCache.eraseLegacyKeySurface]. Erasing the keys before the DB
     * and the prefs means an interrupted wipe still leaves the sealed private
     * keys AND the sealed `auth` secret unrecoverable.
     *
     * Idempotent, and safe to run in-session: [UnifiedPushStateStore] mints its
     * alias again on the next successful save, so a user who re-enables after an
     * opt-out is unaffected.
     */
    fun eraseKeySurface(@Suppress("UNUSED_PARAMETER") context: Context) {
        for (alias in listOf(CONNECTOR_KEYSTORE_ALIAS, UnifiedPushStateStore.KEYSTORE_ALIAS)) {
            try {
                val ks = java.security.KeyStore.getInstance("AndroidKeyStore")
                ks.load(null)
                ks.deleteEntry(alias)
            } catch (_: Exception) { /* alias absent or Keystore unavailable */ }
        }
    }

    /**
     * WIPE PATH ONLY. Deletes every on-disk artifact of this tier, ours AND the
     * connector's, INCLUDING unlinking the connector's SQLite file.
     *
     * **Do not call this from an in-session path — use
     * [sweepInSessionArtifacts].** `WipeRoutine` is the only legitimate caller;
     * `VendorPushOptOutTeardownSourceTest` pins that at source level.
     *
     * WHY THE RESTRICTION (regression 2026-08-03, root-caused from a Pixel
     * logcat). The connector keeps its `SQLiteOpenHelper` in a private static
     * singleton (`DBStore.instance`) and exposes no `close()`. Unlinking the
     * file out from under that still-open connection puts SQLite into
     * `SQLITE_READONLY_DBMOVED` (extended result 1032) — and
     * `SQLiteOpenHelper.getWritableDatabase()` hands the SAME dead handle back
     * forever, because the connection object is still `isOpen()` and its
     * open-flags still say read-write. Every later write on it fails:
     *
     *     E/SQLiteLog (1032) statement aborts at 76: attempt to write a
     *     readonly database; [INSERT OR REPLACE INTO distributors(...)]
     *
     * so `saveDistributor` throws, `getAckDistributor()` stays null, and the
     * toggle reports "No notification distributor was selected" for the rest of
     * the process — which, given Android keeps the process cached after
     * `finishAndRemoveTask()`, can outlive several apparent app restarts.
     *
     * THIS KDOC'S SAFETY INVARIANT HAS NOW BEEN WRONG TWICE, in opposite
     * directions, and each version put a live defect on a device. Keep both
     * corrections:
     *  - The pre-2026-08-03 version called the delete-under-open-handle "inert
     *    in practice because … no code path calls into the connector after
     *    this point", and named the panic wipe as "the one place this could
     *    matter". Wrong: the two IN-SESSION teardowns — the OPT-OUT branch and
     *    the enable-FAILURE branch of
     *    `RunViewModel.setBackgroundNotificationsEnabledAwaiting` — retry in
     *    the same process ("toggle ON → Tor still bootstrapping → toggle ON
     *    again" is the ordinary first-run sequence). Both now call
     *    [sweepInSessionArtifacts].
     *  - The 2026-08-03 fix then justified keeping the bare unlink HERE with
     *    "`WipeRoutine` is a terminal path — nothing may survive it, and no
     *    retry follows it in this process". ALSO wrong (reproduced on a Pixel,
     *    2026-08-11): of `WipeRoutine`'s five entry points, only the DENIABLE
     *    panic wipe never reaches the connector again — and even there the
     *    process survives; what actually protects it is [ProcessWipeCover]
     *    blocking every UI route for the process lifetime, not process death.
     *    The other four — the orphaned-vault "Erase and start over"
     *    (`performEmergencyWipe(deniable = false)`), the launch-time
     *    inactivity wipe, the launch-time orphaned-credential self-heal, and
     *    the debug TEST_WIPE hook — all deliberately FALL THROUGH TO SETUP in
     *    the same process. Wipe → re-onboard → enable notifications then hit
     *    the wedged handle, and on a device without Play Services UnifiedPush
     *    is the ONLY transport: notifications silently dead until real process
     *    death, behind an error telling the user to install a distributor they
     *    already have.
     *
     * THE FIX: [closeConnectorDbHandle] runs FIRST, so the unlink never happens
     * under an open handle — the connector's next call constructs a fresh
     * helper over a fresh, empty database and works. The unlink itself is
     * unchanged, and the wipe's destructive guarantee never depends on the
     * close succeeding: a failed close costs only the un-wedge (surfaced
     * honestly by the settings modal's distributor-selection error copy, which
     * no longer claims "no distributor" while one is installed — see
     * [PushEnableFailure.forFailedDistributorSelection]).
     *
     * The list (enumerated by disassembling connector-3.3.5.aar, since the
     * library documents none of it):
     *  - `databases/unifiedpush-connector` (+ its -wal/-shm/-journal sidecars,
     *    belt-and-braces exactly as `WipeRoutine` does for `run.db`),
     *  - `unifiedpush.connector` SharedPreferences (the connector's LEGACY
     *    pre-3.x store, which it migrates out of but never deletes),
     *  - `unifiedpush_state_prefs` (ours).
     *
     * Purely destructive, idempotent, never throws. Safe on an install that
     * never enabled the tier — the named files simply don't exist.
     *
     * ORDERING NOTE for the wipe path: run this BEFORE `WipeRoutine`'s
     * wholesale `databases/` deleteRecursively, not after. `Context
     * .deleteDatabase` resolves the databases dir through `getDatabasesDir()`,
     * which re-creates that directory if it is missing — and a bare, freshly
     * dated `databases/` is itself the kind of "this app ran" evidence the
     * wholesale delete exists to remove.
     */
    fun sweepLocalArtifacts(context: Context) {
        // BEFORE the unlink — see the kdoc. Every wipe reaches here with the
        // handle provably open (WipeRoutine's destroyLocalPushIdentity, one
        // line earlier, constructed the connector's DBStore to delete its
        // rows), so an unclosed unlink is the wedge, deterministically.
        closeConnectorDbHandle()
        try {
            context.deleteDatabase(CONNECTOR_DB_NAME)
            val base = context.getDatabasePath(CONNECTOR_DB_NAME).path
            listOf("", "-wal", "-shm", "-journal").forEach { sfx ->
                java.io.File(base + sfx).delete()
            }
        } catch (_: Exception) { /* best-effort */ }
        sweepInSessionArtifacts(context)
    }

    /**
     * Closes and drops the connector's cached database handle — the private
     * static `DBStore.instance` singleton (an `SQLiteOpenHelper` the library
     * never closes) — so [sweepLocalArtifacts]'s unlink never happens under an
     * open handle and the connector stays usable for the wipe paths that fall
     * through to setup in the same process.
     *
     * REFLECTION, because the library offers nothing else (no `close()`, no
     * reset). The class/field names are verified against connector-3.3.5's
     * bytecode (`public final class org.unifiedpush.android.connector.internal
     * .DBStore extends SQLiteOpenHelper` with `private static DBStore
     * instance`) and are the same surface `UnifiedPushArtifactSweepTest
     * .resetConnectorStore` drives LOUDLY in CI — a connector upgrade that
     * renames either fails that instrumented suite instead of silently
     * degrading this into a no-op. Release builds keep both NAMES through the
     * `-keepnames` pair in `androidApp/proguard-rules.pro`;
     * `UnifiedPushWipeWedgeSourceTest` pins this function and those rules
     * together so neither can drift alone.
     *
     * FAIL DIRECTION: best-effort, never throws. On any failure the wipe still
     * unlinks — the destructive guarantee never depends on this call — and the
     * only cost is the wedge this exists to prevent, which the modal now
     * reports honestly ([PushEnableFailure.DISTRIBUTOR_SELECTION]: restart the
     * app, i.e. real process death, always clears it).
     *
     * RESIDUE — why closing is safe in the wipe's destructive sequence: the
     * close itself creates nothing and writes nothing new (at most SQLite's
     * own checkpoint into the file the very next statement unlinks). It does
     * mean a LATER in-process connector call re-creates a fresh EMPTY database
     * where the wedged handle used to fail: on the four fall-through wipe
     * paths that is the point (the re-onboarded user's enable must work), and
     * on the deniable panic path the only remaining in-process caller is the
     * connector's own manifest-registered receiver reacting to a late
     * distributor broadcast — which could ALWAYS re-create the file in a fresh
     * process post-wipe, and whose re-created file holds no rows and no key
     * material (the key surface is erased first, in WipeRoutine's
     * crypto-erase-first slot). Same accepted residue class, not a new one.
     */
    private fun closeConnectorDbHandle() {
        try {
            val field = Class.forName("org.unifiedpush.android.connector.internal.DBStore")
                .getDeclaredField("instance")
            field.isAccessible = true
            (field.get(null) as? android.database.sqlite.SQLiteOpenHelper)?.close()
            field.set(null, null)
        } catch (_: Throwable) { /* best-effort — see kdoc */ }
    }

    /**
     * The IN-SESSION sweep: everything [sweepLocalArtifacts] removes EXCEPT the
     * connector's SQLite file, which is deliberately left in place.
     *
     * Called by the two paths that tear the tier down and then keep running —
     * the settings OPT-OUT branch and the enable-FAILURE branch of
     * `RunViewModel.setBackgroundNotificationsEnabledAwaiting`. Both must leave
     * a retry working ("toggle on → Tor still bootstrapping → toggle on again"
     * is the ordinary case), and unlinking the file wedges the connector for
     * the life of the process — see [sweepLocalArtifacts]'s kdoc for the exact
     * SQLite mechanism.
     *
     * WHY DROPPING THE UNLINK COSTS LITTLE SECURITY-WISE. It is not the file
     * deletion that protects the key material; it is [eraseKeySurface] plus the
     * ROW deletion [destroyLocalPushIdentity] performs through the connector's
     * live handle.
     *
     * The connector's `keys` table holds TWO sensitive fields, and — verified by
     * disassembling connector-3.3.5 — it encrypts only ONE of them:
     *  - `privkey`, the WebPush PRIVATE key, stored as AES-GCM ciphertext under
     *    the AndroidKeyStore alias `UnifiedPush` (`WebPushKeysEntries23`).
     *    Deleting that alias renders it unrecoverable whether or not its bytes
     *    survive in a freed SQLite page.
     *  - `auth`, the RFC 8291 §3.2 16-octet SHARED SECRET, which the library
     *    reads back IN THE CLEAR. It is NOT covered by the alias deletion. An
     *    earlier version of this kdoc called the private key "the only secret
     *    the connector's database holds", and called the rest "the subscription's
     *    PUBLIC half" — that was wrong: `auth` plus `p256dh` is exactly what an
     *    RFC 8291 sender needs to forge a wake that passes
     *    `RunPushService.REQUIRE_ENCRYPTED_PUSH`.
     * What protects `auth` here is therefore the ROW deletion, not the alias:
     * by the time this runs, [destroyLocalPushIdentity] has already DELETED the
     * `keys`/`registrations`/`tokens`/`distributors` rows through the
     * connector's own live handle (see its kdoc for the row-by-row account).
     * Known limitation: freed SQLite pages remain in a file we deliberately do not
     * unlink in-session, the cost of keeping the connector usable for a retry; the
     * WIPE path unlinks the file, so it does not carry that limitation.
     * Our OWN copy of the same pair is sealed at rest under
     * [UnifiedPushStateStore.KEYSTORE_ALIAS] and is erased by [eraseKeySurface]
     * above.
     *
     * Everything else in that database is a distributor package name and a
     * random connector-token UUID. The endpoint URL — the one value that names
     * the user's push server — is never in the connector's database at all; it
     * lives in [UnifiedPushStateStore.PREFS_NAME], which this DOES delete.
     *
     * So the in-session end state is: no rows, neither alias, no endpoint prefs,
     * no distributor selected, distributor-side subscription unregistered — and
     * a connector that still works. The remaining trace is an SQLite file whose mere
     * existence says "this app links the UnifiedPush connector", which the APK
     * says anyway, plus whatever the deleted rows left in its free pages.
     *
     * Purely destructive, idempotent, never throws.
     */
    fun sweepInSessionArtifacts(context: Context) {
        try {
            context.deleteSharedPreferences(CONNECTOR_LEGACY_PREFS)
            context.deleteSharedPreferences(UnifiedPushStateStore.PREFS_NAME)
        } catch (_: Exception) { /* best-effort */ }
    }

    /**
     * True iff the Tink primitives the connector needs for RFC 8291 decryption
     * are actually on the runtime classpath.
     *
     * This exists because of a dependency decision in `androidApp/build.gradle
     * .kts`: the connector declares `com.google.crypto.tink:tink` (the JVM
     * artifact), which overlaps `:shared`'s `tink-android` on 1357 of its 1366
     * classes, so it is EXCLUDED and tink-android satisfies it instead. If
     * tink-android is ever dropped from `:shared`, the connector's bundled
     * `com.google.crypto.tink.apps.fixed_webpush` decryptor loses its
     * dependencies and every wake arrives with `decrypted == false` — which
     * [RunPushService] drops by design. That failure is SILENT: no crash, just
     * notifications that stop.
     *
     * `UnifiedPushTinkRuntimeTest` asserts this, turning a silent runtime
     * regression into a red test.
     */
    fun isWebPushCryptoLinked(): Boolean =
        try {
            Class.forName("com.google.crypto.tink.subtle.EllipticCurves")
            Class.forName("com.google.crypto.tink.subtle.Hkdf")
            Class.forName("com.google.crypto.tink.subtle.EngineFactory")
            Class.forName("com.google.crypto.tink.apps.fixed_webpush.WebPushHybridDecrypt")
            true
        } catch (_: Throwable) {
            false
        }
}
