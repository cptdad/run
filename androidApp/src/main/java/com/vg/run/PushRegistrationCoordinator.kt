package com.vg.run

import android.app.Application
import android.os.SystemClock
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.onSubscription
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Push registration for one RunViewModel: the opt-in/opt-out toggle, the per-
 * session "already registered" bookkeeping for both transports (FCM and
 * UnifiedPush), the registration passes, the opt-out DELETE ladder and the
 * pending-deregistration sweep. It owns all of that state (the session sets and
 * fields, the mutex, both epochs, the ladder counter); its dependencies are
 * handed in:
 *
 *  - [scope] is the ViewModel's `viewModelScope`, so the unregister and the
 *    opt-out ladder keep the scope (and the cancellation) they always had.
 *  - [vaultProvider] / [messageManagerProvider] / [relayHttp] are read at use
 *    time, never cached: the vault, the manager and the transport all change
 *    across a session (lock, Tor self-heal, external proxy mode).
 *  - [notificationLevelStore] is the ViewModel's own store (it keeps the
 *    declaration; the control poll and the wake-freshness stamp use it too).
 *
 * [unregisterPushBestEffort] MUST STAY NON-SUSPEND: the emergency wipe calls it
 * synchronously (PushSessionBookkeepingRaceSourceTest).
 */
internal class PushRegistrationCoordinator(
    private val app: Application,
    private val scope: CoroutineScope,
    private val notificationLevelStore: KeyValueStore,
    private val cryptoProvider: CryptoProvider,
    private val vaultProvider: () -> VaultDatabase?,
    private val messageManagerProvider: () -> MessageManager?,
    private val relayHttp: () -> RelayHttp?,
    /** The opt-out ladder's wake: bumped on every network restore. */
    private val networkRestoreEpoch: StateFlow<Long>,
) {
    /** The ViewModel's CURRENT vault, read at every use (null while locked). */
    private val vault: VaultDatabase? get() = vaultProvider()

    /** The ViewModel's CURRENT session MessageManager, read at every use. */
    private val messageManager: MessageManager? get() = messageManagerProvider()

    /** The persisted transport, or [NotificationLevel.OFF] when unset. The
     *  modal needs the LEVEL (not just a boolean) so it can tell "on via FCM"
     *  from "on via UnifiedPush" when both are theoretically installable.
     *
     *  Reads the PROVEN level
     *  ([NotificationLevelStore.provenLevel]) — the device-key-authenticated
     *  consent proof, not the plaintext selector. Every caller of this function
     *  either MINTS a push identity ([refreshPushRegistration] and, through
     *  [isBackgroundNotificationsEnabled], the vault-open and control-poll
     *  re-registrations) or renders the Settings switch, and all of them run
     *  post-unlock with a usable device key. The plaintext selector stays where
     *  it is for the locked-screen wake gates the push SERVICES read — see
     *  [NotificationLevelStore.getLevel].
     *
     *  The legacy plaintext is handed in explicitly (it is the ViewModel store's own
     *  SharedPreferences slot) so the one-time migration has a source without
     *  routing the read through a `KeyValueStore` whose iOS actual would move
     *  the value out from under the other platform's reader. */
    fun currentNotificationLevel(): NotificationLevel =
        NotificationLevelStore.provenLevel(
            notificationLevelStore,
            cryptoProvider,
            // The one-time legacy migration is latched INSIDE the vault
            // (`notif_consent_v1`), because the sealed slot itself lives in the
            // very store an attacker can write. No open vault ⇒ the
            // latch cannot be consulted ⇒ no migration, answer OFF. Every minting
            // caller of this function runs with the vault open.
            vault,
            notificationLevelStore.getString(NotificationLevelStore.KEY),
        )

    /**
     * "Is some background-notification transport opted into." Both live tiers
     * count: `google` devices persist [NotificationLevel.VENDOR_PUSH] (FCM),
     * Google-free devices persist [NotificationLevel.UNIFIED_PUSH]. POLL is
     * dead (removed with the poll manifest) and never written, so it can only appear on a store written by
     * a build that predates its removal — treated as OFF, which is the correct
     * fail-closed reading since nothing can deliver it.
     */
    fun isBackgroundNotificationsEnabled(): Boolean =
        when (currentNotificationLevel()) {
            NotificationLevel.VENDOR_PUSH, NotificationLevel.UNIFIED_PUSH -> true
            NotificationLevel.OFF, NotificationLevel.POLL -> false
        }

    /**
     * Why the last [setBackgroundNotificationsEnabledAwaiting] enable attempt
     * failed, so the modal can pick error copy instead of showing one generic
     * line for every cause. Reset at the start of every attempt; meaningless
     * (and null) after a success or a disable.
     *
     * A plain property rather than a StateFlow deliberately: the sole consumer
     * reads it exactly once, immediately after awaiting the call it describes.
     */
    var lastPushEnableFailure: PushEnableFailure? = null
        private set

    /**
     * Awaitable variant of [RunViewModel.setBackgroundNotificationsEnabled] — lets the
     * caller (NotificationSettingsModal's SwitchPage) show a spinner while
     * the FCM token registers with the relay, and revert the switch to OFF
     * if registration fails rather than leaving it stuck on a state nothing
     * is actually backing.
     *
     * TAKES A [NotificationLevel], not a boolean (changed when the UnifiedPush
     * tier landed): "on" is no longer a single transport, and the caller — the
     * modal, the sole call site — is the layer that knows which one this
     * device can deliver on. [NotificationLevel.OFF] is the disable request.
     *
     * Enable: writes the requested level into [NotificationLevelStore]
     * IMMEDIATELY — at TOGGLE time, before registration even starts — then
     * AWAITS that transport's registration ([refreshVendorPushRegistration] for
     * FCM; register-then-await-the-distributor for UnifiedPush) and returns
     * whether it succeeded (at least one inbound-text inbox got a 2xx from
     * PushRegistration.register — or there was nothing to register in the
     * first place, e.g. no contacts yet, which is not a failure). The level
     * MUST be written before awaiting registration, not after: registration
     * itself no longer writes it (see [refreshVendorPushRegistration]'s note),
     * and a device with zero contacts at toggle time returns from that
     * function having registered nothing — writing the level only on success
     * would silently leave a user who enables push with no contacts yet (a
     * very common first-run state) with nothing persisted at all. On
     * end-to-end registration failure, the persisted level is REMOVED (not
     * written to OFF — see [NotificationLevelStore.clearLevel]) so
     * [isBackgroundNotificationsEnabled] never claims "enabled" when nothing
     * is actually registered (the silent-registration-failure class of bug
     * this guards against).
     *
     * Disable: REMOVES the persisted level (not written to OFF — same
     * [NotificationLevelStore.clearLevel] reasoning) and unregisters;
     * always returns true (there is nothing that can fail from the caller's
     * perspective — the relay unregister never blocks the toggle; since
     * 2026-08-11 it retries with backoff in the background and, failing
     * that, arms a persisted flag a later session's sweep finishes — see
     * [unregisterPushInBackground]).
     *
     * Switches to [Dispatchers.IO] internally for the
     * DB reads + network round-trip (mirrors the IO dispatcher the old
     * fire-and-forget path used) — safe to call from ANY coroutine
     * (including one on the Main dispatcher, e.g. Compose's
     * `rememberCoroutineScope`) without blocking it.
     */
    suspend fun setBackgroundNotificationsEnabledAwaiting(level: NotificationLevel): Boolean =
        withContext(Dispatchers.IO) {
            lastPushEnableFailure = null
            val enabled = level != NotificationLevel.OFF
            if (!enabled) {
                // REMOVE first, before anything best-effort/async below — the
                // local wake gate (isBackgroundNotificationsEnabled /
                // RunFcmService.onMessageReceived) must read OFF the instant
                // the user disables, independent of whether cancelAll or the
                // relay unregister ever complete. removeObject-equivalent
                // semantics, not write-false: see NotificationLevelStore.clearLevel.
                // The vault handle is what lets the
                // opt-out ADVANCE the consent epoch, so a pre-opt-out proof
                // restored from a filesystem image cannot revert it.
                NotificationLevelStore.clearLevel(notificationLevelStore, cryptoProvider, vault)
                // The late-wake sweep stamp lives beside the level and dies with it.
                PushWakeFreshness.clear(notificationLevelStore)
                NotificationHelper.cancelAll(app)
                // ONE relay DELETE per inbox covers BOTH transports:
                // `DELETE /inbox/{id}/push` is platform-agnostic — it drops
                // whatever push row that inbox holds, apns/fcm/unifiedpush
                // alike — so there is deliberately no second loop here.
                unregisterPushInBackground()
                // Opt-out must also retire the LOCAL Firebase push
                // identity, not just this session's relay registration. Before
                // this fix, VendorPush.currentToken's just-in-time auto-init-
                // enable was never undone by opt-out (only WipeRoutine, on a
                // full wipe, called destroyLocalPushIdentity), so a user who
                // enabled push and later turned it back off kept a live,
                // Google-side-correlatable FCM token + Firebase Installation ID
                // on disk indefinitely. Mirrors iOS, whose opt-out calls
                // unregisterForRemoteNotifications() directly.
                // Fire-and-forget: the async Firebase
                // Tasks this kicks off must never block the toggle from
                // completing. But the async half alone leaves a process-death
                // gap: this app's whole-session-teardown-on-background design
                // (MainActivity.onStop -> finishAndRemoveTask()) can kill the
                // process before deleteToken()/FirebaseInstallations.delete()
                // ever settle, so the residue the onSettled callback below
                // sweeps never gets swept. Mirror WipeRoutine.wipePersistentState's
                // ordering exactly (async call, then an unconditional
                // synchronous sweep right after): fire the async half for its
                // best-effort server-side token revocation, then ALSO sweep the
                // on-disk artifacts synchronously so they're gone even if the
                // process dies before the Tasks ever settle.
                // The synchronous sweep still runs, and still removes everything
                // except one file: `PersistedInstallation.<key>.json` is deferred
                // until this teardown's revocation chain settles, because
                // deleting it mid-chain costs a 24-hour FIS lockout that makes
                // re-enabling notifications fail for the rest of the process
                // (measured on a Samsung A20e, 2026-09-17 — see [FisTeardownGate]).
                VendorPush.destroyLocalPushIdentity(app) { VendorPush.sweepLocalArtifacts(app) }
                VendorPush.sweepLocalArtifacts(app)
                // BOTH transports tear down UNCONDITIONALLY, never "the one the
                // level said was active". The level is the thing that can be
                // wrong: a reverted enable, a restored data dir from a different
                // build, or a distributor uninstalled while the app
                // was closed all leave state behind that no level names. Every
                // call below is a documented no-op on an install that never
                // enabled the tier, so running both costs nothing and closes the
                // "opted out of A, kept B's state" gap by construction.
                //
                // Ordering inside the UnifiedPush half is load-bearing, and is
                // now IDENTICAL on all three paths (here, the enable-failure
                // branch below, and WipeRoutine): crypto-erase FIRST, then the
                // connector-side teardown, then the artifact sweep.
                //  - eraseKeySurface first because it is what actually protects
                //    the sealed WebPush private keys: an opt-out interrupted
                //    anywhere after this line leaves them unrecoverable
                //    regardless of which rows or files survive.
                //  - destroyLocalPushIdentity before the sweep because it
                //    constructs the connector's DBStore and would otherwise
                //    re-create artifacts a sweep placed first had just removed
                //    (see its kdoc).
                //
                // sweepInSessionArtifacts, NOT sweepLocalArtifacts: this branch
                // returns into a live process where the user can immediately
                // toggle back ON. sweepLocalArtifacts unlinks the connector's
                // SQLite file out from under the open handle its static DBStore
                // singleton caches, which pins that handle in
                // SQLITE_READONLY_DBMOVED and makes every later saveDistributor
                // throw — "disable → re-enable in the same session" wedged the
                // connector permanently (regression 2026-08-03). The in-session
                // sweep drops our endpoint prefs and the connector's legacy
                // prefs; the connector's own rows were already deleted through
                // its live handle a line above.
                UnifiedPushSupport.eraseKeySurface(app)
                UnifiedPushSupport.destroyLocalPushIdentity(app)
                UnifiedPushSupport.sweepInSessionArtifacts(app)
                // Both transports' session bookkeeping, through the shared
                // teardown helper. The vendor half was already emptied by
                // unregisterPushInBackground above; running it again here is what
                // bumps the teardown epoch AFTER the local identities are gone, so
                // a registration pass still in flight on the control-poll
                // coroutine cannot re-populate the sets behind us
                // (see [clearPushSessionBookkeeping]).
                clearPushSessionBookkeeping()
                LogBuffer.append("D", "NotifPoll", "background notifications enabled=false")
                return@withContext true
            }

            // Written HERE, at toggle time — not inside the registration
            // functions (which no longer persist the level at all) and not gated
            // on the registration result below. See the kdoc above for why.
            // Writes the plaintext wake gate AND the sealed consent proof
            // in ONE commit. A device key that cannot seal persists NEITHER — and
            // an unproven write must abort the enable BEFORE any registration
            // leg runs, or this device ends up registered on the relay behind a
            // consent no later provenLevel() acknowledges and no opt-out sweep
            // can find. Same revert the end-to-end failure below takes.
            if (!NotificationLevelStore.setLevel(notificationLevelStore, cryptoProvider, vault, level)) {
                revertFailedPushEnable(app)
                LogBuffer.append("W", "NotifPoll", "background-notification enable aborted — consent proof did not persist")
                return@withContext false
            }
            // Registration leg per transport. POLL is dead (removed) and OFF was
            // handled above, so the `else` is unreachable in practice — it fails
            // CLOSED (false ⇒ the level written a line ago is removed again)
            // rather than silently persisting an opt-in nothing can deliver.
            //
            // The level is already persisted, so between here and the success
            // decision below every exit must either CONFIRM or REVERT it —
            // including CANCELLATION. The registration legs suspend for up to
            // tens of seconds (the UnifiedPush distributor handshake, a Tor
            // round-trip), and the caller's scope is the settings modal's
            // rememberCoroutineScope: closing the modal mid-spinner (or the
            // whole-session teardown on background) cancels this coroutine at
            // the next suspension point. Skipping the revert there would leave
            // the persisted level claiming "on" with nothing registered behind
            // it and no error ever shown — the switch would read ON forever on
            // the next modal open, which is exactly the
            // silent-registration-failure class the kdoc above promises this
            // function guards against. Revert on the way out, then rethrow
            // (cancellation must stay cancellation).
            val success = try {
                when (level) {
                    NotificationLevel.VENDOR_PUSH ->
                        // On a device without Play Services there is no delivery
                        // mechanism at all — NotificationSettingsModal never offers
                        // this level in that case, so it is reachable only when
                        // VendorPush IS available in practice. Stay defensive rather
                        // than assume: treat the absence of a registration leg as
                        // trivially successful (there is nothing to fail).
                        // awaitTurn: this Boolean decides whether the enable is
                        // reported as FAILED, so it must never be a lock skip.
                        if (VendorPush.isAvailable(app)) refreshVendorPushRegistration(awaitTurn = true) else true
                    NotificationLevel.UNIFIED_PUSH -> enableUnifiedPushAwaiting()
                    else -> false
                }
            } catch (e: CancellationException) {
                revertFailedPushEnable(app)
                LogBuffer.append("W", "NotifPoll", "background-notification enable cancelled mid-flight — opt-in reverted")
                throw e
            }
            if (!success) {
                revertFailedPushEnable(app)
            }
            LogBuffer.append("D", "NotifPoll", "background notifications enabled=$success (requested=true)")
            success
        }

    /**
     * The enable-FAILURE revert: everything an enable attempt that did not end
     * in a confirmed registration must undo. Reached from BOTH non-success
     * exits of [setBackgroundNotificationsEnabledAwaiting]'s enable leg — the
     * ordinary `success == false` return AND a mid-flight CANCELLATION (modal
     * closed during the spinner, whole-session teardown on background) — which
     * is why it is a named function rather than the inline block it used to
     * be: the cancellation exit did not exist before 2026-08-11, and inlining
     * the revert in one exit is how the other got missed.
     *
     * Registration failed end-to-end (bad token, unreachable relay, every
     * PushRegistration.register call non-2xx, …) — revert by REMOVING the
     * level (not writing OFF) so isBackgroundNotificationsEnabled() reflects
     * reality rather than claiming "on" for a registration that never landed.
     *
     * Level FIRST, exactly as in the opt-out branch, and for the same two
     * reasons: it is the gate every local wake path reads
     * (RunPushService.onMessage), and a level that no longer says UNIFIED_PUSH
     * is the "the user did not ask for this" signal that BOTH writing
     * callbacks key on:
     *  - onUnregistered — so the UNREGISTERED broadcast the teardown below
     *    provokes neither arms the "your distributor dropped you" notice nor
     *    re-creates the prefs file;
     *  - onNewEndpoint — the sharper one HERE: this path is reached by giving up on the distributor handshake after
     *    a TIMEOUT, so the distributor's NEW_ENDPOINT answer is very often
     *    still in flight and lands AFTER the sweep. An ungated write would
     *    MINT unifiedpush_state_prefs.xml again, carrying the endpoint URL
     *    that names the user's push server, with nothing left to ever remove
     *    it.
     * Both are the write-after-delete race the Firebase sweep hit.
     * ProcessWipeLatch does NOT cover either of them: it is armed only by
     * WipeRoutine, and this path arms nothing.
     *
     * Then the RELAY's push row ([unregisterPushInBackground]), which the
     * opt-out branch has always dropped and this one never did. "Failed" means
     * no inbox got a 2xx on THIS pass — not that no row exists: a partially
     * successful earlier pass, or any earlier session that did register,
     * leaves rows behind, and the local teardown below then destroys the
     * address they point at. The relay would keep pushing to an identity
     * nothing can receive on, with the level cleared first so nothing ever
     * revisits it. This is `DELETE /inbox/{id}/push` only — platform-agnostic
     * (it drops whatever push row the inbox holds, fcm or unifiedpush alike,
     * which is why there is no second loop) and NOT the irreversible
     * `DELETE /inbox/{id}`, so the "never from a block or wipe path" rule that
     * guards inbox destruction does not apply here. Ordering mirrors the
     * opt-out branch exactly: level, then the relay unregister (it needs the
     * vault and the transport, both still live at this point), then the local
     * teardowns.
     *
     * Then the LOCAL push identity, because by the time an enable can fail the
     * artifacts already exist:
     *  - `unifiedpush_state_prefs` is written by RunPushService.onNewEndpoint
     *    BEFORE the relay leg runs, so a RELAY failure leaves the endpoint +
     *    subscription public keys on disk;
     *  - the connector's `databases/unifiedpush-connector` (its distributor
     *    choice, connector token and the AES-GCM-sealed WebPush PRIVATE key)
     *    and the AndroidKeyStore alias `UnifiedPush` are created during
     *    DISTRIBUTOR SELECTION, in NotificationSettingsModal.setEnabled —
     *    i.e. EARLIER than the enable is even dispatched. They therefore exist
     *    in the sub-cases where NO endpoint ever arrived (handshake timeout,
     *    DISTRIBUTOR_REFUSED, VAPID_UNSUPPORTED, NO_DISTRIBUTOR) just as much
     *    as in the RELAY one;
     *  - and a distributor-side subscription (an ntfy topic, say) is LIVE at
     *    the push server with nobody left to unregister it.
     * Nothing rediscovers those orphans afterwards: the modal's applyLevel
     * sets its local `enabled=false` without dispatching a disable, and the
     * control-poll dispatcher keys off the level this path just removed.
     *
     * UNCONDITIONAL for both transports and in the opt-out branch's exact
     * order — see that branch for the full reasoning; the short version is
     * that the level is the thing that can be wrong, and here it is
     * *guaranteed* absent by the first line, so nothing this removes is state
     * the user still holds. Ordering inside the UnifiedPush half stays
     * load-bearing and matches the opt-out branch exactly — crypto-erase
     * first, then the connector-side teardown, then the sweep; see that
     * branch.
     *
     * And, as there, the IN-SESSION sweep ([UnifiedPushSupport
     * .sweepInSessionArtifacts], never sweepLocalArtifacts): this is the path
     * the 2026-08-03 regression was reported on. A first enable that fails
     * (Tor still bootstrapping, distributor slow to answer) is the normal
     * prelude to the user immediately tapping the toggle again, so this
     * teardown of all places must not unlink the connector's database and
     * leave its cached handle write-dead for the rest of the process.
     *
     * Contains no suspension point, deliberately: it must run to completion
     * even on an already-CANCELLED coroutine (the cancellation exit), where
     * the first suspension would throw. [unregisterPushInBackground] launches
     * its retry ladder on [scope] (viewModelScope) — a different, live scope — so the
     * relay DELETEs still happen; if even that scope is dead (whole-session
     * teardown), the persisted `push_dereg_pending` flag it arms FIRST hands
     * the job to a later session's sweep.
     */
    private fun revertFailedPushEnable(app: Application) {
        NotificationLevelStore.clearLevel(notificationLevelStore, cryptoProvider, vault)
        PushWakeFreshness.clear(notificationLevelStore)
        unregisterPushInBackground()
        VendorPush.destroyLocalPushIdentity(app) { VendorPush.sweepLocalArtifacts(app) }
        VendorPush.sweepLocalArtifacts(app)
        UnifiedPushSupport.eraseKeySurface(app)
        UnifiedPushSupport.destroyLocalPushIdentity(app)
        UnifiedPushSupport.sweepInSessionArtifacts(app)
        // Session bookkeeping follows the artifacts: both addresses are gone
        // now, so any "already registered under it" entry describes a
        // registration nothing can deliver to. Through the shared teardown
        // helper, which additionally bumps the epoch AFTER the local
        // identities were destroyed and so invalidates a control-poll
        // registration pass still in flight (see [clearPushSessionBookkeeping]).
        clearPushSessionBookkeeping()
    }

    // -----------------------------------------------------------------------
    // Vendor push (FCM)
    // -----------------------------------------------------------------------
    //
    // VendorPush is the vendor-push seam; since the 2026-08-04 flavor collapse
    // the gate is purely runtime: on devices without Play Services,
    // isAvailable() is false and every call below is a fall-through no-op
    // (UnifiedPush is that path's transport).

    /** Session-scoped "already registered under the CURRENT token" set —
     *  mirrors iOS AppState.pushRegisteredInboxIds. Cleared whenever the
     *  token itself changes (rotation, or the first-ever fetch), so a stale
     *  mapping under an OLD token can never silently linger unregistered.
     *
     *  CONCURRENT rather than `mutableSetOf()`: [pushRefreshMutex] serialises the
     *  registration PASSES against one another, but the teardown that empties
     *  these four fields ([clearPushSessionBookkeeping]) cannot hold that mutex —
     *  it is reached from the non-suspend wipe path — so a `clear()` really can
     *  land while a pass is inside `registeredIds.add(...)` seconds deep in a Tor
     *  PUT loop. A plain HashSet under concurrent add/clear is undefined; this is
     *  not. */
    private val vendorPushRegisteredIds: MutableSet<String> =
        Collections.newSetFromMap(ConcurrentHashMap<String, Boolean>())

    /** `@Volatile` for the same reason as the set above: written by a teardown on
     *  a different thread from the refresh pass that reads it. */
    @Volatile
    private var vendorPushToken: String? = null

    /**
     * The UnifiedPush siblings of the two fields above, kept SEPARATE rather
     * than shared. A device can carry stale registrations for both transports
     * at once (a `google` device whose Play Services was disabled after opting
     * in, say), and merging the sets would let a successful registration under
     * one transport suppress the other's — the silent-skip shape the vendor
     * fields' own kdoc warns about. Session-scoped RAM for the same reason:
     * nothing persisted can go stale and quietly suppress a re-registration.
     *
     * [unifiedPushLastEndpoint] plays [vendorPushToken]'s role — the endpoint is
     * the receiving address, so a rotated endpoint invalidates every existing
     * relay row exactly as a rotated FCM token does.
     *
     * Concurrent set + `@Volatile` for the same reason as the vendor pair above.
     */
    private val unifiedPushRegisteredIds: MutableSet<String> =
        Collections.newSetFromMap(ConcurrentHashMap<String, Boolean>())

    @Volatile
    private var unifiedPushLastEndpoint: String? = null

    /**
     * Serialises the registration refresh over the four session fields above.
     * They are ViewModel state mutated from THREE concurrent coroutines on
     * Dispatchers.IO — the unlock kick, every control-poll cycle, and the
     * settings toggle — and each refresh is a
     * read-decide-write straddling a network round trip. Interleaved, one pass
     * can clear the "already registered" set for a rotated address while the
     * other is still adding ids under the old one, leaving the set claiming
     * registrations the relay does not have: a silent skip that lasts the whole
     * session, which is the exact failure shape these fields' own kdocs warn
     * about.
     *
     * TRY-lock, not lock, for the background callers: a registration pass can
     * sit on a 60 s Tor PUT, and queueing would pile every control-poll cycle up
     * behind it and then run them back to back against state the first pass
     * already fixed. A skipped cycle self-corrects on the next one (~25-45 s),
     * because the diff it would have run is recomputed from scratch every time.
     *
     * The TOGGLE path is the one exception and waits its turn (`awaitTurn`): it
     * is user-initiated, singular (the modal blocks on it behind a spinner) and
     * its Boolean answer decides whether the enable is reported as FAILED — so
     * a skip there would be read as "registration did not land", clearing the
     * level and tearing the identity down while a concurrent pass was in fact
     * registering it. Waiting is bounded by that one in-flight pass; a toggle
     * cannot queue behind itself.
     *
     * IT DOES NOT COVER THE FOURTH MUTATOR. The push-identity TEARDOWN
     * ([clearPushSessionBookkeeping], reached from the opt-out branch, the
     * enable-failure branch and the emergency wipe) empties the same four fields
     * WITHOUT this mutex, because it must stay callable from a non-suspend wipe
     * path. [pushTeardownEpoch] is what makes that safe; read it next.
     */
    private val pushRefreshMutex = Mutex()

    /**
     * Bumped by every push-identity teardown BEFORE it empties the four session
     * fields, so a registration pass that STRADDLES one can notice and throw its
     * own bookkeeping away (see [withPushRefreshTurn]).
     *
     * WHY A COUNTER AND NOT JUST THE MUTEX. The clearing site that forces the
     * design, [unregisterPushBestEffort], is a NON-suspend function called from
     * [RunViewModel.performEmergencyWipe] — itself non-suspend, running crypto-erase-first on
     * the caller's thread. It can neither `lock()` (that suspends) nor block on
     * one, and reshaping the wipe path into a coroutine just to borrow this mutex
     * is exactly the restructuring a wipe path must not get: the erase must not
     * become contingent on some unrelated 60 s Tor PUT releasing a lock. So the
     * fields themselves were made thread-safe (concurrent set + `@Volatile`),
     * which closes the data race, and this counter supplies the ordering the lock
     * would otherwise have given: bump-then-clear means any teardown a pass could
     * outlive is preceded by an epoch change that pass is guaranteed to observe,
     * so the TEARDOWN ALWAYS WINS. The direction is the safe one — an over-cleared
     * set merely re-registers (PushRegistration.register is an idempotent relay
     * upsert), it can never suppress a registration.
     */
    private val pushTeardownEpoch = AtomicInteger(0)

    /**
     * Bumped every time a Settings opt-out ARMS the persisted pending flag
     * ([unregisterPushInBackground]); captured by each retry ladder and each
     * sweep pass at start and re-checked before the ONE mutation that matters
     * — DISARMING the flag. Two opt-out ladders CAN overlap: opt-out (ladder
     * A starts, arms) → re-enable → opt-out again (ladder B, re-arms), all
     * inside A's ~65 s backoff window — nothing cancels A (no Job is held).
     * A fully-successful pass by A over its OWN older, narrower ref snapshot
     * would then clear the flag B armed, orphaning B's wider set — which can
     * include an inbox minted during the brief re-enable — with the sweep
     * permanently disarmed: a push row left on the relay for an opted-out
     * device, the exact leak the flag exists to catch.
     *
     * The guard sits on the DISARM, deliberately NOT on the DELETEs: a stale
     * ladder's DELETEs are harmless and idempotent (rows a newer opt-out
     * wants gone anyway), so cancelling them buys nothing — only clearing a
     * flag a newer opt-out armed is dangerous, so only the disarm is gated;
     * a stale ladder just stops.
     *
     * Same stale-async-completion pattern as [pushTeardownEpoch], including
     * the ordering discipline: bump-and-capture BEFORE the arm, as that
     * epoch bumps before its clears — the newer opt-out must always win.
     * In-memory ONLY, never persisted — the bare boolean stays the entire
     * persisted surface; a process restart resetting this to zero is
     * safe, the armed flag survives and the sweep simply re-runs. Mirrors
     * iOS `pushDeregGeneration` (AppState.swift).
     */
    private val pushDeregGeneration = AtomicInteger(0)

    /**
     * The ONE place the four session fields are emptied. Everything that tears a
     * push identity down goes through here — the opt-out branch, the
     * enable-failure branch and [unregisterPushBestEffort] (hence the wipe) —
     * so the epoch bump can never be forgotten at one of them.
     *
     * The bump comes FIRST, and that ordering is the invariant: a clear-then-bump
     * would leave a window in which a pass reads the epoch, this function empties
     * the fields, the pass re-populates them and its own exit check still sees the
     * pre-bump value — precisely the interleaving the epoch exists to catch.
     */
    fun clearPushSessionBookkeeping() {
        pushTeardownEpoch.incrementAndGet()
        vendorPushRegisteredIds.clear()
        vendorPushToken = null
        unifiedPushRegisteredIds.clear()
        unifiedPushLastEndpoint = null
    }

    private suspend fun withPushRefreshTurn(awaitTurn: Boolean, block: suspend () -> Boolean): Boolean {
        if (awaitTurn) {
            pushRefreshMutex.lock()
        } else if (!pushRefreshMutex.tryLock()) {
            LogBuffer.append("D", "NotifPoll", "push registration refresh already in flight — cycle skipped")
            return false
        }
        // Snapshot inside the lock, before the pass reads or writes anything.
        val epochAtEntry = pushTeardownEpoch.get()
        return try {
            block()
        } finally {
            // A teardown ran while this pass was in flight, so anything the pass
            // recorded describes an address that has since been destroyed and a
            // relay row the teardown's own DELETE is on its way to removing.
            // Discard it: the next pass re-derives the whole diff from scratch and
            // re-registers (idempotent upsert). Never the other direction — see
            // [pushTeardownEpoch].
            //
            // The pass's Boolean is deliberately left alone. Only the toggle reads
            // it, and turning a registration that may well have landed into a
            // reported FAILURE would clear the level and tear down further state,
            // which is worse than one redundant re-registration.
            if (pushTeardownEpoch.get() != epochAtEntry) {
                LogBuffer.append("D", "NotifPoll", "push identity torn down mid-refresh — discarding this pass's bookkeeping")
                clearPushSessionBookkeeping()
            }
            pushRefreshMutex.unlock()
        }
    }

    /**
     * Registers this device's current FCM token for every inbound-TEXT inbox
     * not already registered THIS session (mirrors iOS
     * refreshPushRegistrationIfNeeded / registerNewPushInboxes — the same
     * [inboxesNeedingRegistration] diff). Run on unlock, on toggle-ON, and
     * once per control-poll cycle — that cycle sits downstream of every
     * cap-mutation site, so a contact paired/re-paired after the first
     * registration still gets covered without a hook at every call site.
     *
     * A token change (rotation, or the first-ever fetch) clears the
     * session's "already registered" set so every inbox gets RE-registered
     * under the new token — a stale mapping under the OLD token would
     * otherwise silently stop delivering. Fail-soft throughout: any failure
     * just means the next cycle/session retries.
     *
     * Since the AFU-class (inboxId, readCap) manifest was
     * removed, this is the ONLY path that re-registers a rotated FCM token —
     * `RunFcmService.onNewToken` is now a no-op because it has no vault and no
     * mirror to read refs from. That is safe precisely because BOTH
     * [vendorPushToken] and [vendorPushRegisteredIds] are session-scoped RAM,
     * not persisted: a fresh session starts with token == null and an empty set,
     * so the first run of this function always re-registers EVERY inbound text
     * inbox under whatever token FCM currently holds. There is no stored value
     * that could go stale and silently suppress the re-registration.
     *
     * Returns whether registration succeeded — at least one inbound-text
     * inbox got a 2xx from [PushRegistration.register], OR there was
     * nothing that needed registering in the first place (already
     * registered this session, or no inboxes yet — not a failure). Callers
     * that fire this off in the background (unlock, control-poll cycle) are
     * free to ignore the result — it stays fail-soft there; only the
     * toggle-ON path ([setBackgroundNotificationsEnabledAwaiting]) acts on it,
     * which is why that path alone passes [awaitTurn] — see [pushRefreshMutex].
     */
    private suspend fun refreshVendorPushRegistration(awaitTurn: Boolean = false): Boolean =
        withPushRefreshTurn(awaitTurn) { refreshVendorPushRegistrationLocked() }

    private suspend fun refreshVendorPushRegistrationLocked(): Boolean {
        if (!VendorPush.isAvailable(app)) return false
        val db = vault ?: return false
        val token = try {
            VendorPush.currentToken(app)
        } catch (e: Exception) {
            LogBuffer.append("W", "NotifPoll", "vendor push token fetch failed: ${e::class.simpleName}")
            null
        } ?: return false
        // Invariant these two fields must keep: [vendorPushToken] names the token
        // that [vendorPushRegisteredIds] describes registrations under. So a
        // changed token invalidates the SET here…
        if (token != vendorPushToken) vendorPushRegisteredIds.clear()
        // Rotated read-caps evict the relay's push row — see the helper.
        drainRotatedPushInboxIdsIntoSessionSets()
        val http = relayHttp() ?: return false
        // …but the token is adopted only once a transport exists, i.e. only for a
        // pass that can actually register. The unlock-time call almost always
        // takes the early return above (Tor is still bootstrapping), and recording
        // the token for a pass that registered NOTHING is the shape of a silent
        // skip: it is benign only while the set was emptied in the same breath.
        // Since the manifest removal this is the ONLY path that recovers a rotated token, so the
        // trap is removed rather than documented. Clearing an already-empty set on
        // the next pass is free and self-correcting.
        vendorPushToken = token
        return registerInboxesForCurrentSession(
            db = db, http = http, token = token, platform = "fcm",
            registeredIds = vendorPushRegisteredIds,
        )
    }

    /**
     * Registers this device's stored UnifiedPush WebPush subscription for every
     * inbound-TEXT inbox not already registered THIS session — the exact
     * sibling of [refreshVendorPushRegistration], differing ONLY in how the
     * receiving address is acquired: read out of [UnifiedPushStateStore]
     * (written by [RunPushService.onNewEndpoint], the only thing the distributor
     * can reach) instead of asked of the FCM SDK.
     *
     * That difference is the whole reason the acquisition step is NOT shared:
     * FCM's token is fetched on demand and can be re-fetched at will, whereas a
     * UnifiedPush endpoint only ever ARRIVES, asynchronously, from another app.
     * Everything downstream of acquisition is [registerInboxesForCurrentSession].
     *
     * Returns false with no side effects when there is no stored subscription —
     * the normal state before the distributor has answered, and NOT an error:
     * the next control-poll cycle retries, and the toggle-ON path awaits the
     * distributor explicitly rather than relying on this.
     *
     * [awaitTurn] as in [refreshVendorPushRegistration] — see [pushRefreshMutex].
     */
    private suspend fun refreshUnifiedPushRegistration(awaitTurn: Boolean = false): Boolean =
        withPushRefreshTurn(awaitTurn) { refreshUnifiedPushRegistrationLocked() }

    private suspend fun refreshUnifiedPushRegistrationLocked(): Boolean {
        val db = vault ?: return false
        val sub = UnifiedPushStateStore(app).readSubscription() ?: return false
        // Same invariant as the vendor pair: [unifiedPushLastEndpoint] names the
        // address [unifiedPushRegisteredIds] describes registrations under, so a
        // rotated endpoint (distributor reinstalled, push server changed)
        // invalidates the set.
        if (sub.endpoint != unifiedPushLastEndpoint) unifiedPushRegisteredIds.clear()
        drainRotatedPushInboxIdsIntoSessionSets()
        val http = relayHttp() ?: return false
        unifiedPushLastEndpoint = sub.endpoint
        return registerInboxesForCurrentSession(
            db = db, http = http, token = sub.endpoint, platform = "unifiedpush",
            p256dh = sub.p256dh, auth = sub.auth,
            registeredIds = unifiedPushRegisteredIds,
        )
    }

    /**
     * A COMMITTED read-cap rotation evicts the relay's push registration
     * for that inbox (under ANY token — ours, or one an attacker registered
     * while they held the device). Drop those ids from the session sets so the
     * next diff re-registers under the new cap; no new registration call site.
     * Mirrors iOS AppState.refreshPushRegistrationIfNeeded.
     *
     * Drains into **both** transports' sets. `drainRotatedPushInboxIds` is
     * DESTRUCTIVE — it empties MessageManager's pending list — so whichever
     * transport called it first would otherwise consume the eviction and leave
     * the other holding a stale "already registered" entry for an inbox whose
     * relay row is gone. Applying it to both sets is free (a set that never had
     * the id is unchanged) and removes the ordering dependency entirely.
     */
    private fun drainRotatedPushInboxIdsIntoSessionSets() {
        val mm = messageManager ?: return
        val evicted = mm.drainRotatedPushInboxIds()
        if (evicted.isEmpty()) return
        vendorPushRegisteredIds.removeAll(evicted)
        unifiedPushRegisteredIds.removeAll(evicted)
    }

    /**
     * The transport-agnostic half of push registration: diff the vault's
     * inbound-TEXT inboxes against [registeredIds] and PUT the ones that are
     * missing. Extracted so the FCM and UnifiedPush paths cannot drift — the
     * diff, the fail-soft error handling, the "nothing to do is success"
     * semantics and the never-persist-the-level rule are identical for both,
     * and only the address acquisition differs (see the two callers).
     *
     * [token] is whatever the platform's address is: an FCM registration token,
     * or a UnifiedPush endpoint URL. [p256dh]/[auth] are the RFC 8291 keys,
     * non-null for `"unifiedpush"` only; [PushRegistration.register] refuses a
     * mismatch, so a wiring error fails closed before any HTTP.
     *
     * Returns true when at least one inbox got a 2xx, OR when there was nothing
     * that needed registering (already covered this session, or no contacts yet
     * — not a failure). Never throws.
     *
     * NOTE: the persisted NotificationLevel is written at TOGGLE time
     * ([setBackgroundNotificationsEnabledAwaiting]), NOT here. Every caller
     * reaches this only with the level already set, so there is nothing to
     * (re)persist on a successful pass — see that function's kdoc for why
     * writing it only here was the original bug.
     */
    private suspend fun registerInboxesForCurrentSession(
        db: VaultDatabase,
        http: RelayHttp,
        token: String,
        platform: String,
        registeredIds: MutableSet<String>,
        p256dh: String? = null,
        auth: String? = null,
    ): Boolean {
        val env = if (BuildConfig.DEBUG) "sandbox" else "production"
        return try {
            // The push-registration surface is text AND inbound-control
            // inboxes (allPushableInboxes) — a referral offer/accept or a group
            // invite rides control and must be able to wake this device too. See
            // the per-kind noPush table in PushRegistration.kt for which control
            // kinds actually fire the relay's wake.
            val desired = allPushableInboxes(db)
            val newRefs = inboxesNeedingRegistration(desired, registeredIds)
            if (newRefs.isEmpty()) {
                // "Nothing needed registering" IS a success (a device with no
                // contacts yet is the ordinary first-run state, and the first
                // pairing's control-poll cycle registers it) — but it must not
                // be a SILENT one (hardware, Pixel): with no log
                // line and no relay PUT, a toggle that reported success here
                // was indistinguishable from a registration that silently
                // never happened. Counts only — never a token/endpoint, never
                // an inbox id.
                LogBuffer.append(
                    "D", "NotifPoll",
                    "$platform push: nothing to register " +
                        "(${desired.size} pushable inbox(es), all already covered this session)",
                )
                return true
            }
            // Several onion addresses: never send the first PUT into an
            // undecided descriptor race (bounded); register() resolves the address
            // per PUT. iOS sibling: IosAppController.registerRefs.
            PushRegistration.awaitRelayAddressDecided(RelayConfig.BASE_URL)
            // Bounded fan-out: 32 sequential ~1-2 s Tor PUTs outlasted
            // short sessions. 4 in flight; each success lands in [registeredIds]
            // (a concurrent set) as it completes, so a pass cut short by a
            // teardown keeps what it got. Failures stay fail-soft per inbox.
            // NonCancellable: the toggle-ON caller runs in the settings modal's scope,
            // which closing the modal (or backgrounding) cancels. The old blocking loop
            // ran to completion regardless; child launches would instead be cancelled
            // before their PUT started, and the caller would revert a consent it had
            // just asked for. A teardown still wins through [pushTeardownEpoch].
            val okCount = AtomicInteger(0)
            val gate = Semaphore(4)
            withContext(NonCancellable) {
                for (ref in newRefs) {
                    launch(Dispatchers.IO) {
                        gate.withPermit {
                            val registered = PushRegistration.register(
                                http, RelayConfig.BASE_URL, ref.inboxId, ref.readCap, token, env,
                                platform = platform, p256dh = p256dh, auth = auth,
                            )
                            if (registered) {
                                registeredIds.add(ref.inboxId)
                                okCount.incrementAndGet()
                            }
                        }
                    }
                }
            }
            val ok = okCount.get()
            if (ok > 0) {
                // Counts only — never the token/endpoint, never an inbox id.
                LogBuffer.append("D", "NotifPoll", "$platform push: $ok/${newRefs.size} inbox(es) registered")
            }
            ok > 0
        } catch (e: Exception) {
            LogBuffer.append("W", "NotifPoll", "$platform push registration failed: ${e::class.simpleName}")
            false
        }
    }

    /**
     * The single, level-aware entry point for "(re)register this device's push
     * address with the relay". Replaces the three hand-rolled
     * `isBackgroundNotificationsEnabled() && VendorPush.isAvailable()` branches
     * that used to sit at the choke points (vault-open, control-poll cycle,
     * toggle-ON) — each of which would have needed its own UnifiedPush arm, and
     * one of which would eventually have been forgotten.
     *
     * Dispatches purely on the PERSISTED level, so the transport that runs is
     * always the one the user actually opted into: a `google` device that opted
     * into UnifiedPush (Play Services disabled after the fact) does not get
     * quietly switched back to FCM, and vice versa.
     */
    suspend fun refreshPushRegistration(): Boolean =
        when (currentNotificationLevel()) {
            NotificationLevel.VENDOR_PUSH -> refreshVendorPushRegistration()
            NotificationLevel.UNIFIED_PUSH -> refreshUnifiedPushRegistration()
            // OFF: nothing opted in. POLL: dead since the manifest removal and never written by
            // any current build — a store carrying it can only come from an
            // older binary, and there is nothing left that could deliver it.
            // Both run the INVERSE branch of this re-sync: if a
            // Settings opt-out's relay DELETE never landed, its persisted flag
            // is still armed and the sweep finishes the job on this cadence.
            NotificationLevel.OFF, NotificationLevel.POLL -> {
                sweepPendingPushDeregistration()
                false
            }
        }

    /**
     * The toggle-ON handshake for UnifiedPush, and the one place in this file
     * that waits on another app.
     *
     * FCM can be registered synchronously (the SDK hands over a token on
     * demand), but a UnifiedPush endpoint only arrives as an out-of-process
     * broadcast into [RunPushService], which cannot do the relay PUT itself (no
     * vault). So: subscribe, register, await the distributor's answer,
     * then run the ordinary registration pass.
     *
     * `onSubscription` — not a bare `launch` + `first()` — is what closes the
     * lost-wakeup race WITHIN an attempt: it starts the distributor request
     * only AFTER this collector is attached to the shared flow, so a
     * distributor that answers instantly cannot emit into a void and leave
     * this waiting the full timeout.
     *
     * BETWEEN attempts the flow's replay(1) + the sequence baseline do the
     * same job: an answer that lands after this attempt has begun
     * but before the collector attaches is REPLAYED into it instead of being
     * dropped, while [answersHandshakeAttempt]'s baseline filter guarantees a
     * replayed event from BEFORE this attempt can never resolve this attempt's
     * await — see [UnifiedPushEndpointSignal]'s replay note.
     *
     * [PushEndpointEvent.TempUnavailable] is filtered out rather than treated
     * as an answer — it explicitly means "ask again later", so consuming it
     * would end the wait on a non-event.
     *
     * A TIMEOUT IS NOT AUTOMATICALLY A FAILURE. If a subscription is stored by
     * the time the wait ends (the answer landed just past the deadline, or one
     * the baseline filter deliberately refused stored it), the registration
     * pass below can proceed on it. Only "no answer AND nothing stored" fails.
     * The resolution truth table is the pure [decideUnifiedPushHandshake],
     * pinned by `UnifiedPushHandshakeDecisionTest`.
     */
    private suspend fun enableUnifiedPushAwaiting(): Boolean {
        if (!UnifiedPushSupport.isAvailable(app)) {
            lastPushEnableFailure = PushEnableFailure.NO_DISTRIBUTOR
            return false
        }
        // Baseline BEFORE the collector attaches (and therefore before
        // register() is broadcast): only events stamped after this may resolve
        // this attempt.
        val baselineSeq = UnifiedPushEndpointSignal.latestSeq
        val answer = withTimeoutOrNull(UNIFIED_PUSH_HANDSHAKE_TIMEOUT_MS) {
            UnifiedPushEndpointSignal.events
                .onSubscription { UnifiedPushSupport.register(app) }
                .first { answersHandshakeAttempt(it, baselineSeq) }
        }?.event
        if (answer is PushEndpointEvent.Failed) {
            LogBuffer.append("W", "NotifPoll", "unifiedpush enable refused: ${answer.reason}")
        }
        val hasStoredSubscription = UnifiedPushStateStore(app).readSubscription() != null
        val outcome = decideUnifiedPushHandshake(
            answer = answer,
            hasStoredSubscription = hasStoredSubscription,
        )
        when (outcome) {
            is UnifiedPushHandshakeOutcome.Fail -> {
                if (outcome.failure == PushEnableFailure.NO_ENDPOINT) {
                    LogBuffer.append(
                        "W", "NotifPoll",
                        "unifiedpush enable: no endpoint after handshake " +
                            "(waited ${UNIFIED_PUSH_HANDSHAKE_TIMEOUT_MS} ms)",
                    )
                }
                lastPushEnableFailure = outcome.failure
                return false
            }
            UnifiedPushHandshakeOutcome.Proceed -> Unit
        }
        // awaitTurn, same reason as the vendor leg: a lock skip here would be
        // reported to the user as a failed enable.
        val ok = refreshUnifiedPushRegistration(awaitTurn = true)
        if (!ok) lastPushEnableFailure = PushEnableFailure.RELAY
        return ok
    }

    /**
     * Step (a) of the export: drop every relay push registration this device
     * holds, over the SAME surface registration uses ([allPushableInboxes]) — an
     * inbox left registered keeps the relay dispatching contentless wakes to
     * Google/Apple for an identity that now lives on another phone.
     *
     * Best-effort and bounded BY THE CALLER: `MoveManager` wraps this in a 30 s
     * `withTimeoutOrNull`, which can only cut at a suspension point. The single
     * suspension point is the `join()` below, and the work it waits on runs in
     * [scope] (the ViewModel's `viewModelScope`) — NOT as a child of the caller — so a timeout abandons the
     * WAIT and lets the DELETEs finish in the background (Tor and the vault both
     * outlive the freeze). A blocking loop inline here would have run past the
     * budget instead of yielding it.
     *
     * No `push_dereg_pending` flag (unlike the settings opt-out): a frozen phone
     * either gets wiped — where the flag could never be cleared, exactly the
     * reasoning in [PushRegistrationCoordinator.unregisterPushBestEffort] — or gets cancelled back to life, in
     * which case `RunViewModel.moveResumeSession`'s control poll re-registers from scratch.
     */
    suspend fun unregisterForMoveAwaiting() {
        val db = vault ?: return
        val refs = try {
            allPushableInboxes(db)
        } catch (_: Exception) {
            null
        } ?: emptyList()
        val http = relayHttp()
        // Through the shared helper so the teardown epoch is bumped first — a
        // registration pass straddling this discards its own bookkeeping instead
        // of re-planting inbox ids behind us.
        clearPushSessionBookkeeping()
        if (refs.isEmpty() || http == null) {
            LogBuffer.append("D", "Move", "push unregister skipped (refs=${refs.size}, transport=${http != null})")
            return
        }
        val relayBaseUrl = RelayConfig.BASE_URL
        val job = scope.launch(Dispatchers.IO) {
            val failures = PushRegistration.unregisterAllParallelReturningFailures(http, relayBaseUrl, refs)
            // Counts only — never a capability, never a raw inbox id.
            LogBuffer.append("D", "Move", "move push dereg: ${refs.size - failures.size}/${refs.size} inboxes cleared")
        }
        job.join()
    }

    /**
     * ONE-SHOT best-effort DELETE for every inbound-TEXT inbox in
     * [snapshotRefs], fired off WITHOUT blocking the caller over [http] —
     * mirrors iOS AppState.unregisterCurrentInboxesBestEffort's wipe leg /
     * unregisterPushTokenForInboxes. [snapshotRefs] and [http] are captured by
     * the CALLER (performEmergencyWipe needs them from the still-open vault /
     * still-live transport, a moment before both get torn down — see its own
     * comment).
     *
     * The wipe CALLER gates [snapshotRefs] on "push was ever opted into" (an
     * empty list sends nothing and only clears the bookkeeping), so a never-push
     * device emits no DELETE burst at wipe time — see performEmergencyWipe.
     *
     * THE WIPE PATH'S variant, deliberately one-shot with no retry and no
     * persisted flag: a wipe destroys the vault, so a
     * "dereg still owed" flag armed here could never be cleared afterwards
     * (no vault → no caps → the sweep can never run) — and a miss is harmless
     * on this path anyway, since the relay inbox itself stops mattering to a
     * wiped device. The SETTINGS paths use the retrying sibling,
     * [unregisterPushInBackground].
     *
     * TRANSPORT-AGNOSTIC, by the wire contract: `DELETE /inbox/{id}/push` drops
     * whatever push row an inbox holds regardless of platform, so ONE pass
     * covers FCM and UnifiedPush together and there is deliberately no second
     * loop. What IS per-transport is the session bookkeeping, so both sets are
     * cleared here — clearing only the "active" one would leave the other
     * claiming registrations the relay no longer has.
     *
     * MUST STAY NON-SUSPEND: [RunViewModel.performEmergencyWipe] calls it, and that path is
     * synchronous by design. That constraint is why the bookkeeping goes through
     * [clearPushSessionBookkeeping] instead of taking [pushRefreshMutex] — the
     * four fields were mutated here with no synchronisation at all until
     * 2026-08-09, racing a concurrent control-poll pass's `registeredIds.add(…)`.
     */
    fun unregisterPushBestEffort(snapshotRefs: List<InboundInboxRef>, http: RelayHttp?) {
        clearPushSessionBookkeeping()
        if (snapshotRefs.isEmpty() || http == null) return
        val relayBaseUrl = RelayConfig.BASE_URL
        scope.launch(Dispatchers.IO) {
            PushRegistration.unregisterAllParallelReturningFailures(http, relayBaseUrl, snapshotRefs)
        }
    }

    /**
     * Settings opt-out (bg_notifications_toggle → off) AND the enable-failure
     * revert: relay unregister using the CURRENT session's vault + transport.
     * The persisted level itself is cleared by the CALLER
     * ([setBackgroundNotificationsEnabledAwaiting]) BEFORE this runs, so the
     * local wake gate (isBackgroundNotificationsEnabled / RunFcmService /
     * RunPushService) already reads OFF the instant the user disables —
     * independent of whether the relay DELETEs below ever complete or succeed.
     * Covers both transports in one pass; see [unregisterPushBestEffort].
     *
     * NO LONGER fire-and-forget-once (2026-08-11 — proven on hardware: one
     * DELETE per inbox died with a 74 s Tor timeout, `unregister → -1`, the
     * relay never saw it, and nothing ever retried, so the relay kept
     * dispatching contentless wakes for an opted-out device forever — a
     * metadata leak and a straight violation of the opt-out contract):
     *
     *  1. The persisted [SecurePrefs] `push_dereg_pending` flag is armed
     *     BEFORE the first DELETE attempt (before the enumeration, even), so a
     *     process death anywhere past that line leaves the sweep armed. It is
     *     a BARE BOOLEAN (never inbox ids or read caps outside the vault
     *     — the sweep re-enumerates [allPushableInboxes] instead), and it
     *     is cleared only when EVERY ref's DELETE succeeded in a pass that is
     *     still the NEWEST opt-out ([pushDeregGeneration] — two ladders can
     *     overlap, and an older one must never disarm what a newer one armed).
     *  2. Each still-failing ref is retried in-session with backoff
     *     ([PUSH_DEREG_MAX_ATTEMPTS] / [PUSH_DEREG_BACKOFF_MS]), off the
     *     caller's thread as before.
     *  3. Whatever still failed — or a session killed mid-backoff — is
     *     finished by [sweepPendingPushDeregistration] on a later session's
     *     control-poll cadence.
     *
     * Stays NON-SUSPEND (the retry loop lives inside the launched coroutine)
     * and mirrors iOS `unregisterCurrentInboxesBestEffort(retryingForOptOut:
     * true)` exactly.
     */
    private fun unregisterPushInBackground() {
        // Bump-and-capture, then arm ([pushDeregGeneration]'s ordering — the
        // newer opt-out must always win); armed FIRST relative to everything
        // else — see the kdoc. The wipe path must never reach this function
        // (it calls unregisterPushBestEffort directly).
        val generationAtArm = pushDeregGeneration.incrementAndGet()
        SecurePrefs.setPushDeregPending(app, true)
        clearPushSessionBookkeeping()
        val refs = try {
            // Dereg surface MUST match the register surface (allPushableInboxes)
            // — an inbox registered but never swept on opt-out is exactly the
            // silent-leak class the 2026-08-11 dereg fix exists to prevent.
            vault?.let { allPushableInboxes(it) }
        } catch (_: Exception) { null }
        if (refs == null) {
            // No open vault / enumeration failed: nothing can be sent now. The
            // armed flag hands the job to the sweep.
            return
        }
        val http = relayHttp()
        if (http == null) {
            LogBuffer.append("D", "NotifPoll", "push dereg: no transport — deferred to sweep")
            return
        }
        if (refs.isEmpty()) {
            // Enumerated an OPEN vault and found nothing to unregister — the
            // opt-out is trivially complete; disarm the flag armed above.
            // Generation-gated like every disarm ([pushDeregGeneration]):
            // unlike the iOS sibling (main-actor-synchronous with its bump,
            // so provably never stale), nothing here excludes a concurrent
            // second opt-out having re-armed since the bump above.
            if (pushDeregGeneration.get() == generationAtArm) SecurePrefs.setPushDeregPending(app, false)
            LogBuffer.append("D", "NotifPoll", "push dereg: 0/0 inboxes cleared")
            return
        }
        // Captured once, but PushRegistration resolves it PER DELETE through the
        // relay address race, so the minutes-long backoff below still
        // follows the session's current winner.
        val relayBaseUrl = RelayConfig.BASE_URL
        // Counted BEFORE the launch so a sweep evaluating right now already sees
        // the ladder; released in the finally below.
        pushDeregLaddersActive.incrementAndGet()
        scope.launch(Dispatchers.IO) {
          try {
            // FAIL-FAST passes: every DELETE on its own 25 s budget,
            // in parallel — a dead-circuit pass costs ~25 s, not 3 × 60 s.
            var restoreEpoch = networkRestoreEpoch.value
            // After-restore extension: the monotonic time the ladder last saw the
            // restore epoch move ([PushRegistration.continueDeregLadder]).
            var seenEpoch = restoreEpoch
            var restoreSeenAtMs: Long? = null
            var failures = PushRegistration.unregisterAllParallelReturningFailures(http, relayBaseUrl, refs)
            var attempt = 1
            // LADDER-ONLY phrases: the ladder's final tally and the
            // sweep's share one wording, so a stalled ladder was indistinguishable
            // from a sweep pass (chain:push Case A). Fixed text + numbers; none of
            // them matches the e2e RETRY / COUNT / DEFERRED patterns.
            LogBuffer.append("D", "NotifPoll", "push dereg ladder: pass $attempt done, ${failures.size} of ${refs.size} failed")
            while (failures.isNotEmpty()) {
                if (networkRestoreEpoch.value != seenEpoch) {
                    seenEpoch = networkRestoreEpoch.value
                    restoreSeenAtMs = SystemClock.elapsedRealtime()
                }
                if (!PushRegistration.continueDeregLadder(attempt, PUSH_DEREG_MAX_ATTEMPTS, SystemClock.elapsedRealtime(), restoreSeenAtMs)) break
                // Past the normal passes = the after-restore extension: Tor was told
                // the network is back but may need minutes to build working circuits.
                val afterRestore = attempt >= PUSH_DEREG_MAX_ATTEMPTS
                val backoffMs = if (afterRestore) PushRegistration.DEREG_RESTORE_BACKOFF_MS else PUSH_DEREG_BACKOFF_MS[attempt - 1]
                // The backoff ends early on a network-restore kick (the epoch was
                // captured before the pass that just failed, so a restore during
                // that pass counts too).
                if (PushRegistration.awaitBackoffOrWake(backoffMs, restoreEpoch, networkRestoreEpoch)) {
                    LogBuffer.append("D", "NotifPoll", "push dereg ladder: backoff ended early (network restored)")
                }
                // Toggled straight back ON during the backoff — stop deleting
                // rows a fresh enable is (re)registering. The flag stays armed;
                // that is inert while notifications are ON (the sweep is gated
                // on OFF) and the next opt-out re-arms it anyway.
                if (isBackgroundNotificationsEnabled()) {
                    LogBuffer.append("D", "NotifPoll", "push dereg ladder: re-enabled during backoff - stopped")
                    break
                }
                // Re-acquire the transport each retry: a Tor self-heal during
                // the backoff replaces the SOCKS port, and the captured client
                // would keep dialing the dead one. None right now → wait a
                // BOUNDED moment for Tor to come back (2026-10-24: right after a
                // network restore Tor is briefly not Connected, and breaking here
                // handed the opt-out to the ~5 min sweep — chain:push Case A).
                // Still none → the sweep finishes the job.
                val waitStartNs = System.nanoTime()
                val transportAbsent = relayHttp() == null
                if (transportAbsent) LogBuffer.append("D", "NotifPoll", "push dereg ladder: no transport - waiting up to ${PUSH_DEREG_TRANSPORT_WAIT_MS / 1000} s")
                val freshHttp = PushRegistration.awaitTransport(PUSH_DEREG_TRANSPORT_WAIT_MS) {
                    relayHttp()
                }
                val waitedS = (System.nanoTime() - waitStartNs) / 1_000_000_000L
                if (freshHttp == null) {
                    LogBuffer.append("D", "NotifPoll", "push dereg ladder: still no transport after $waitedS s - stopped")
                    break
                }
                if (transportAbsent) LogBuffer.append("D", "NotifPoll", "push dereg ladder: transport back after $waitedS s")
                if (isBackgroundNotificationsEnabled()) {
                    LogBuffer.append("D", "NotifPoll", "push dereg ladder: re-enabled during backoff - stopped")
                    break
                }
                attempt++
                LogBuffer.append("D", "NotifPoll", if (afterRestore) "push dereg retry $attempt (after network restore)" else "push dereg retry $attempt/$PUSH_DEREG_MAX_ATTEMPTS")
                restoreEpoch = networkRestoreEpoch.value
                failures = PushRegistration.unregisterAllParallelReturningFailures(freshHttp, relayBaseUrl, failures)
                LogBuffer.append("D", "NotifPoll", "push dereg ladder: pass $attempt done, ${failures.size} of ${refs.size} failed")
            }
            // Counts only — never a capability, never a raw inbox id. The e2e
            // suite asserts on this exact line (identical wording on iOS).
            LogBuffer.append("D", "NotifPoll", "push dereg: ${refs.size - failures.size}/${refs.size} inboxes cleared")
            // The guard is on the DISARM, not the DELETEs ([pushDeregGeneration]):
            // this pass's DELETEs were harmless and idempotent even if a newer
            // opt-out overlapped, but clearing a flag that newer opt-out armed
            // — over a wider inbox set this pass never enumerated — would
            // retire the sweep with a relay push row still standing.
            if (failures.isEmpty()) {
                if (pushDeregGeneration.get() == generationAtArm) {
                    SecurePrefs.setPushDeregPending(app, false)
                } else {
                    LogBuffer.append("D", "NotifPoll", "push dereg: superseded by a newer opt-out — flag left armed")
                }
            }
          } catch (e: CancellationException) {
            // Session teardown mid-ladder: the armed flag hands the job to a later
            // sweep. Said out loud so a vanished ladder is never a mystery again.
            LogBuffer.append("D", "NotifPoll", "push dereg ladder: cancelled (session teardown)")
            throw e
          } finally {
            pushDeregLaddersActive.decrementAndGet()
          }
        }
    }

    /**
     * Opt-out ladders in flight. The sweep stands down while any is:
     * both used to send the same DELETEs over the same dead circuits at once
     * (Case A: a sweep pass started 04:59:58 beside the ladder's pass 1), and the
     * ladder — now woken by a network restore — is the faster of the two.
     */
    private val pushDeregLaddersActive = AtomicInteger(0)

    /**
     * The INVERSE branch of the periodic push re-sync: finishes a
     * Settings opt-out whose relay-side `DELETE /inbox/{id}/push` never landed
     * (Tor down, all in-session retries dead, or the whole-session teardown
     * killed the process mid-backoff). Without this there was NO reconciliation
     * pass anywhere: the local wake gate read OFF while the relay kept the
     * FCM/APNs/WebPush registration — and kept dispatching contentless wakes —
     * forever.
     *
     * Runs on the EXISTING control-poll cadence, via [refreshPushRegistration]'s
     * OFF/POLL arm (the scheduler is `RunViewModel.startControlPoll`'s loop — deliberately no
     * new timer), and only while (a) the vault is open, (b) background
     * notifications are OFF, and (c) the persisted flag is armed. Re-enumerates
     * [allPushableInboxes] from the OPEN vault — the flag is a bare boolean,
     * so read caps are sourced exclusively from the vault at sweep time.
     *
     * Anti-hammer guards: [withPushRefreshTurn] with `awaitTurn = false`
     * try-locks [pushRefreshMutex], so at most one sweep (or registration pass)
     * is ever in flight and a sweep can never interleave with a toggle-ON
     * registration; a fully successful sweep disarms the flag — generation-
     * gated ([pushDeregGeneration]), so a pass a newer opt-out superseded
     * mid-flight leaves it armed — and once disarmed it cannot re-run
     * (nothing re-arms it but a new opt-out). A partial failure keeps
     * the flag and retries on a later cycle — single pass per cycle, the
     * jittered 25–45 s cadence IS the backoff here. Mirrors iOS
     * `sweepPendingPushDeregistrationIfNeeded` (AppState.swift).
     */
    private suspend fun sweepPendingPushDeregistration() {
        if (!SecurePrefs.isPushDeregPending(app)) return
        // Defensive re-check — the dispatcher only routes here on OFF/POLL,
        // but a sweep must never fight a concurrent enable's fresh PUTs.
        if (isBackgroundNotificationsEnabled()) return
        val db = vault ?: return
        // An opt-out ladder is retrying these DELETEs right now: no overlap
        // ([pushDeregLaddersActive]). The flag stays armed; the next cycle after
        // the ladder ends sweeps whatever it left.
        if (pushDeregLaddersActive.get() > 0) {
            LogBuffer.append("D", "NotifPoll", "push dereg sweep: skipped (opt-out ladder active)")
            return
        }
        withPushRefreshTurn(awaitTurn = false) {
            if (pushDeregLaddersActive.get() > 0) return@withPushRefreshTurn false
            // Snapshot inside the lock, before the pass reads anything — a
            // newer opt-out arming mid-sweep must leave the flag armed, so
            // every disarm below is gated on it ([pushDeregGeneration]; the
            // guard is on the disarm, never the DELETEs).
            val generationAtEntry = pushDeregGeneration.get()
            val refs = try {
                // Same surface as registration — see registerInboxesForCurrentSession.
                allPushableInboxes(db)
            } catch (_: Exception) { null } ?: return@withPushRefreshTurn false
            val http = relayHttp() ?: return@withPushRefreshTurn false
            if (refs.isEmpty()) {
                // Open vault, nothing left that could hold a push row.
                if (pushDeregGeneration.get() == generationAtEntry) SecurePrefs.setPushDeregPending(app, false)
                LogBuffer.append("D", "NotifPoll", "push dereg: 0/0 inboxes cleared")
                return@withPushRefreshTurn true
            }
            LogBuffer.append("D", "NotifPoll", "push dereg sweep: pass started (${refs.size} inboxes)")
            val failures = PushRegistration.unregisterAllParallelReturningFailures(http, RelayConfig.BASE_URL, refs)
            LogBuffer.append("D", "NotifPoll", "push dereg: ${refs.size - failures.size}/${refs.size} inboxes cleared")
            if (failures.isEmpty()) {
                if (pushDeregGeneration.get() == generationAtEntry) {
                    SecurePrefs.setPushDeregPending(app, false)
                    true
                } else {
                    LogBuffer.append("D", "NotifPoll", "push dereg: superseded by a newer opt-out — flag left armed")
                    false
                }
            } else {
                false
            }
        }
    }

    private companion object {
        /**
         * How long the UnifiedPush toggle-ON handshake waits for the
         * distributor app to answer with an endpoint before giving up.
         *
         * A compromise between two real constraints. Too short and a
         * distributor on a cold start loses the race on every first enable.
         * Too long and the user is stuck on a spinner they cannot cancel —
         * and, worse, this app tears the whole session down when it goes to
         * the background (`MainActivity.onStop` → `finishAndRemoveTask`), so a
         * long wait is a long window in which backgrounding the app kills the
         * handshake mid-flight (which is why a mid-flight cancellation now
         * REVERTS the level — see [setBackgroundNotificationsEnabledAwaiting]).
         * A timeout is NOT fatal anyway: if a subscription is already stored,
         * the registration pass proceeds on it — see
         * [enableUnifiedPushAwaiting].
         *
         * 30 s, raised from 15 s (hardware, Pixel): a healthy,
         * connected ntfy answering its FIRST register on a fresh connector DB
         * — link round-trip, subscription mint, connection reconciliation —
         * took longer than 15 s, and the timeout's failure branch then
         * UNREGISTERED the in-flight registration (its topic was observably
         * torn down as obsolete at the distributor), so every cold first
         * enable both failed loudly and destroyed the work it was waiting on.
         * The retry then started from zero. Only the distributor round-trip
         * runs inside this budget — the relay PUT (which needs Tor) happens
         * after, outside it — so this number covers distributor latency alone.
         */
        private const val UNIFIED_PUSH_HANDSHAKE_TIMEOUT_MS = 30_000L

        /**
         * Settings-opt-out relay `DELETE /inbox/{id}/push` retry schedule
         * (2026-08-11: on hardware, a single best-effort DELETE died with a
         * 74 s Tor timeout, the result was swallowed, and the relay kept the
         * push registration — and kept dispatching contentless wakes to
         * Google/Apple — forever). 4 total attempts, ~5/15/45 s between them,
         * per still-failing inbox; anything that survives all four is handed
         * to the persisted-flag sweep ([sweepPendingPushDeregistration]) — unless
         * a network restore was seen, which extends the ladder by up to
         * [PushRegistration.DEREG_RESTORE_GRACE_MS].
         * Mirror of iOS `pushDeregMaxAttempts`/`pushDeregBackoffSeconds`
         * (AppState.swift) — keep the two schedules identical.
         */
        private const val PUSH_DEREG_MAX_ATTEMPTS = 4
        private val PUSH_DEREG_BACKOFF_MS = longArrayOf(5_000L, 15_000L, 45_000L)
        /** Per retry: how long the opt-out ladder waits for a transport that is
         *  momentarily absent (Tor re-establishing) before deferring to the sweep. */
        private const val PUSH_DEREG_TRANSPORT_WAIT_MS = 60_000L
    }
}
