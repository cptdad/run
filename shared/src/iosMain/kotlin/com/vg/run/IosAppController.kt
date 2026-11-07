@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package com.vg.run

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

// ---------------------------------------------------------------------------
// IosAppController — single entry point for the Swift layer.
//
// The Swift UI layer (AppState) creates one instance and holds it in an
// ObservableObject; the Kotlin object manages all business-logic state. It owns:
//  - the Keychain-backed [KeyValueStore] and its [CryptoProvider] (device key);
//  - the [VaultSelector], the open [VaultDatabase] and the PIN/change-PIN
//    attempt counters;
//  - the session managers ([MessageManager], [GroupManager], [ReferralManager]),
//    the [MoveManager] and the Tor-side session helpers (descriptor hedge,
//    warm-NEWNYM ledger);
//  - two coroutine scopes ([sessionWorkScope], [moveScope]) whose children
//    [lock] and [emergencyWipe] cancel.
// Every Swift-facing wrapper is non-throwing: the bridge is not @Throws, so a
// Kotlin exception crossing it is a SIGABRT. Each wrapper catches and returns its
// documented failure value instead.
//
// BRIDGE ORDER (document only — never reorder): several property initialisers
// below run INSIDE `IosAppController()` and call the Swift bridge holders
// synchronously:
//  - `KeyValueStore()` runs `recoverPendingBatch` through [KeychainBridgeHolder];
//  - `CryptoProvider()` reaches Keychain + AesGcm via `getOrCreateKey`
//    (`error("KeychainBridge not registered")` otherwise);
//  - `iosVaultFactory()` / `IosDbKeyProtector` read the Database and
//    SecureEnclave holders (lazily, but on the first vault call);
//  - the `init` block binds `RelayEndpoints.race` at construction;
//  - `MoveManager(...)`'s init runs `refreshFrozenState()` through the vault lambda.
// So `AppState.registerBridges()` (AppState.swift — called from `RunApp.init()`
// and again at the top of `AppState.init()`) MUST have registered all seven
// `*BridgeHolder`s before this class is instantiated.
//
// THREADING: Swift calls the heavy entry points ([unlock], [recoverWithCode],
// [setRealCredential*], [changeCredential*], Lever B enable/finalize/binding,
// blocking vault reads such as [shouldShowUpdateNudge]) from a background
// DispatchQueue, and the cheap reads ([newerRelayVersionForNudge],
// [isPassphraseMode], …) plus [lock] / [emergencyWipe] from the main thread.
// Callbacks handed in by Swift (unread prime, move progress, push registration)
// are invoked on Kotlin background threads, never on main — Swift hops to main
// itself.
// ---------------------------------------------------------------------------

class IosAppController {

    private val store  = KeyValueStore()
    private val crypto = CryptoProvider()

    /**
     * Retired clean-leave rows ("Conversation interrupted" warning, removed
     * 2026-11). The Keychain-backed store SURVIVES an app uninstall/upgrade, so
     * a stale row can linger; fresh provision and the wipe remove them so no
     * residue outlives the feature.
     */
    private fun removeRetiredCleanLeaveKeys() {
        try {
            store.remove("clean_leave")
            store.remove("clean_leave_muted")
        } catch (_: Exception) { /* best-effort hygiene */ }
    }

    /**
     * Debug-mode settings toggle (DebugMode.kt, commonMain) — lets the app
     * upload its rolling log buffer to the relay (DebugLogUploader.kt) for
     * support triage, on the user's own opt-in. Keychain-backed via the SAME
     * [store] instance vault credentials/counters use — never a fresh
     * `KeyValueStore()`, which would re-run its init-time write-ahead-journal
     * recovery for no reason. Never throws.
     *
     * [RunApp.swift]'s startup re-apply (`DebugMode.applyAtStartup`) calls the
     * shared object directly with its OWN throwaway `KeyValueStore()` instead
     * of going through this controller: it runs in `RunApp.init()`, before
     * this controller exists (reading `AppState`'s `@StateObject` there
     * returns a throwaway instance — see the comment in `RunApp.init()`).
     */
    fun isDebugModeEnabled(): Boolean = DebugMode.isEnabled(store, crypto)

    /**
     * See [DebugMode.reapplyPersisted]: called by AppState once the vault is open
     * (keybag provably unlocked) because the launch-time read can fail on a
     * cold start and is otherwise never repeated. Never throws; only enables.
     */
    fun reapplyDebugModeAfterUnlock(): Boolean = try { DebugMode.reapplyPersisted(store, crypto) } catch (_: Exception) { false }

    /** Tri-state sibling for a retrying caller: 1 = on (applied), 0 = off, -1 = unreadable. Never throws. */
    fun reapplyDebugModeTriState(): Int = try { DebugMode.reapplyPersistedTriState(store, crypto) } catch (_: Exception) { DebugMode.PERSISTED_UNREADABLE }

    /**
     * See [isDebugModeEnabled]. Never throws.
     *
     * Returns the flag AS PERSISTED (see [DebugMode.setEnabled]) — NOT the
     * requested value. Turning Debug mode off can fail to stick (a Keychain
     * that refuses the delete on a locked keybag), and `AppState.setDebugMode`
     * binds the Settings toggle to this return value so the UI can never claim
     * a revocation the next launch will undo.
     */
    fun setDebugModeEnabled(on: Boolean): Boolean = DebugMode.setEnabled(store, crypto, on)

    /**
     * First-open push-notification prompt latch — unlock-time read against the
     * CURRENTLY OPEN [vault] (VAULT META, not [store]; see PushPromptOnboarding.kt
     * in commonMain, the single shared implementation Android's RunViewModel also
     * calls into). Never throws; false if no vault is open (unreachable in
     * practice — only called right after a successful unlock/provision/recovery).
     */
    fun consumePushPromptOnce(): Boolean = vault?.let { consumePushPromptOnce(it) } ?: false

    // In-app update nudge — Swift-facing wrappers ([newerRelayVersionForNudge],
    // [shouldShowUpdateNudge], [markUpdateNudgeShown]) over UpdateNudge.kt /
    // UpdateCheck.kt in commonMain, the single shared implementation Android's
    // RunViewModel also calls into. Swift never touches [AppVersion], epoch days,
    // or [vault] directly: it holds the plain rendered version string
    // [MessageManager.newerRelayVersion] latched and passes it back verbatim to
    // these three. Same never-throws, vault-handle shape as [consumePushPromptOnce].

    /**
     * RAM-latch read — see [MessageManager.newerRelayVersion]. Cheap and
     * non-blocking (a `@Volatile` field read), safe to call on the main thread
     * from Swift's health loop.
     */
    fun newerRelayVersionForNudge(): String? = messageManager?.newerRelayVersion()

    /**
     * Throttled read against the CURRENTLY OPEN [vault] (VAULT META `_meta`, not
     * [store]). BLOCKING vault I/O — call off the main thread, exactly like
     * [consumePushPromptOnce]. False if the vault is closed or [version] fails to
     * parse; never throws (see [shouldShowUpdateNudge] in commonMain).
     */
    fun shouldShowUpdateNudge(version: String): Boolean {
        val v = vault ?: return false
        val advertised = parseAppVersion(version) ?: return false
        return shouldShowUpdateNudge(v, advertised)
    }

    /**
     * Records that [version] was shown today. WRITE ON SHOW — call this at the
     * moment the modal is displayed, never on dismiss/tap (see the kdoc on
     * [markUpdateNudgeShown] in commonMain for why). BLOCKING vault I/O — call off
     * the main thread. No-op if the vault is closed or [version] fails to parse;
     * never throws.
     */
    fun markUpdateNudgeShown(version: String) {
        val v = vault ?: return
        val advertised = parseAppVersion(version) ?: return
        markUpdateNudgeShown(v, advertised)
    }

    // -----------------------------------------------------------------------
    // Tor-rung seams — shared decisions in commonMain; Swift owns the control
    // channel.
    // -----------------------------------------------------------------------

    /**
     * COLD-TRANSPORT NEWNYM RUNG — Swift's seam onto the SHARED decision
     * ([MessageManager.shouldFireEarlyNewnym], commonMain), so `AppState`'s
     * ladder and `RunViewModel`'s ladder fire at exactly the same wall-clock on
     * exactly the same evidence. Cheap RAM reads only; safe on the main actor.
     *
     * False when no transport is wired — there is nothing cold to unstick, and
     * the health loop re-wires before it probes.
     *
     * @param msSinceConnectAnchor ms since `AppState.connectStartUptime`. This
     *   rung never moves that anchor: the connect report must keep measuring
     *   launch → first answer.
     */
    fun earlyNewnymDue(msSinceConnectAnchor: Long, newnymsFiredThisSession: Int): Boolean =
        messageManager?.earlyNewnymDue(msSinceConnectAnchor, newnymsFiredThisSession) ?: false

    /** Floor fix (2026-10-09): the floor follows the cold rung's OWN fires,
     *  the cap the shared count — see [MessageManager.shouldFireEarlyNewnym].
     *  Android sibling: `RunViewModel.maybeFireEarlyNewnym`. */
    fun earlyNewnymDueWithColdFires(msSinceConnectAnchor: Long, newnymsFiredThisSession: Int, coldRungFiresThisSession: Int): Boolean =
        messageManager?.earlyNewnymDue(msSinceConnectAnchor, newnymsFiredThisSession, coldRungFiresThisSession) ?: false

    /** @see earlyNewnymDue — called right after Swift actually fired the rung's
     *  `SIGNAL NEWNYM`, so the next fire needs fresh evidence. */
    fun noteEarlyNewnymFired() {
        messageManager?.noteEarlyNewnymFired()
    }

    /** The cold rung's per-session cap, rendered in the shared connection-log
     *  phrase `(NEWNYM n/max)` on both platforms. Kept while a Swift caller
     *  remains; [earlyNewnymPhrase] renders the phrase itself. */
    fun earlyNewnymMaxFires(): Int = MessageManager.EARLY_NEWNYM_MAX_FIRES

    // The EARLY rungs' per-session NEWNYM budget ([EarlyNewnymLedger], commonMain):
    // the cold rung, the warm-up rotation and the descriptor-stage stall spend one
    // cap. Held here (controller lifetime = the process), so a new session in a
    // surviving process starts it over with [resetEarlyNewnyms]
    // (AppState.beginWarmTorSession). Main actor only, like [warmNewnymLedger].
    // Android sibling: `RunViewModel.earlyNewnymsFired` (plain counters today; moving it onto EarlyNewnymLedger is the remaining half of parity item D8).
    private val earlyNewnymLedger = EarlyNewnymLedger()

    // NEWNYMs fired this session by any early rung (the cap's count).
    fun earlyNewnymFiredThisSession(): Int = earlyNewnymLedger.firedThisSession

    // How many of those were the COLD rung's own (its 35 s / 80 s floor's count).
    fun earlyNewnymColdFires(): Int = earlyNewnymLedger.coldFiresThisSession

    // Is any of the shared early-NEWNYM budget left this session?
    fun earlyNewnymHasBudget(): Boolean = earlyNewnymLedger.hasBudget

    // Books one fired early NEWNYM ([cold] = the cold rung's); returns the new
    // count. NOT [noteEarlyNewnymFired], which resets the cold rung's EVIDENCE.
    fun noteEarlyNewnymSpent(cold: Boolean): Int = earlyNewnymLedger.noteFired(cold)

    // The control channel is down: spend the rest of the budget for this session.
    fun exhaustEarlyNewnyms() {
        earlyNewnymLedger.exhaust()
    }

    // A new session in this process (AppState.beginWarmTorSession).
    fun resetEarlyNewnyms() {
        earlyNewnymLedger.reset()
    }

    // The shared `NEWNYM n/max` phrase of the panel / LogBuffer lines.
    fun earlyNewnymPhrase(): String = earlyNewnymLedger.phrase()

    /**
     * Budgets of the WARM-TRANSPORT NEWNYM rung — the shared commonMain ledger,
     * held here (controller lifetime = the process) so Swift never owns Kotlin
     * accounting. Android sibling: `RunViewModel.warmNewnymLedger`.
     */
    private val warmNewnymLedger = WarmNewnymLedger()

    /**
     * WARM-TRANSPORT NEWNYM RUNG (2026-10-07) — Swift's seam onto the SHARED
     * decision ([MessageManager.warmNewnymDue] → [MessageManager.shouldFireWarmNewnym]),
     * so `AppState.maybeFireWarmNewnym` and Android's
     * `RunViewModel.maybeFireWarmNewnym` fire on identical evidence. Cheap RAM
     * reads only; safe on the main actor. False when no transport is wired.
     */
    fun warmNewnymDue(): Boolean = messageManager?.warmNewnymDue(warmNewnymLedger) ?: false

    /** @see warmNewnymDue — called right after Swift actually fired the rung's
     *  `SIGNAL NEWNYM`: spends the budgets, clears the timeout run. */
    fun noteWarmNewnymFired() {
        messageManager?.noteWarmNewnymFired(warmNewnymLedger)
    }

    /** NEWNYM refused (control channel down): retire the rung for this dark run. */
    fun retireWarmNewnymRun() {
        warmNewnymLedger.retireRun()
    }

    /** The `n` of the shared phrase `(NEWNYM n/max, warm)`. */
    fun warmNewnymFiresThisRun(): Int = warmNewnymLedger.firesThisRun

    /** The `max` of the shared phrase `(NEWNYM n/max, warm)`. */
    fun warmNewnymMaxPerRun(): Int = MessageManager.WARM_NEWNYM_MAX_PER_RUN

    /** Whole seconds the relay has been dark on this transport — LogBuffer only. */
    fun warmDarkForSeconds(): Long = messageManager?.warmDarkForSeconds() ?: 0L

    /**
     * WARM-UP ROTATION GATE — Swift's seam onto the SHARED decision
     * ([MessageManager.shouldFireWarmupNewnym], commonMain), so
     * `AppState.rotateAndRetryWarmup` and Android's
     * `RunViewModel.fireWarmupNewnym` refuse/allow on identical evidence: no
     * relay round trip yet this session (whether or not the user has unlocked),
     * and the shared per-session NEWNYM budget not spent. The transport input is
     * false while no transport is wired (pre-unlock). Cheap RAM reads only.
     */
    fun warmupNewnymAllowed(relayAnsweredThisSession: Boolean, newnymsFiredThisSession: Int): Boolean =
        MessageManager.shouldFireWarmupNewnym(
            transportRoundTripCompleted = messageManager?.hasCompletedRelayRoundTrip() == true,
            relayAnsweredThisSession = relayAnsweredThisSession,
            newnymsFiredThisSession = newnymsFiredThisSession,
        )

    /**
     * The SESSION's descriptor hedge ([DescriptorHedge], 2026-10-12), installed by
     * `AppState.installDescriptorHedge` into `TorManager.descriptorHedge`. One per
     * controller = one per PROCESS: a warm-Tor session in a surviving process
     * keeps its spent budget (AppState.beginWarmTorSession), and its budget of
     * [DescriptorHedge.HSDESC_FETCH_BUDGET] hedge HSFETCHes is never replenished by
     * a NEWNYM. Android differs: one per ViewModel = one per session
     * (`RunViewModel.descriptorHedge`; review P7 — which rule is intended is open).
     */
    val descriptorHedge: DescriptorHedge = DescriptorHedge()

    init {
        // Several onion addresses (2026-10-23, RelayAddressRace): when the
        // descriptor race moves the session to a different address, the probe /
        // batch peek in flight is queued on the loser's descriptor — abort it and
        // re-probe on the winner. Called on Tor's control queue; non-blocking.
        // Android sibling: RunViewModel's init. Inert with one address.
        RelayEndpoints.race.bindSwitchListener(this) { messageManager?.noteRelayAddressSwitched() }
    }

    /**
     * Swift's seam onto [MessageManager.noteNewCircuitRequested], installed by
     * `AppState.installNewCircuitHook` as `TorManager.onNewCircuitAccepted`: an
     * app-fired `SIGNAL NEWNYM` was accepted, so the current transport aborts its
     * in-flight probe / batch peek and re-probes at once. Android sibling:
     * `RunViewModel.onNewCircuitAccepted`. No transport (pre-unlock) = no-op.
     */
    fun noteNewCircuitRequested() {
        messageManager?.noteNewCircuitRequested()
    }

    /**
     * HUNG ONION-CIRCUIT RUNG gate ([HsCircuitWatchdog]), installed by
     * `AppState.installHsCircuitGate` as `TorManager.hsCircuitAnsweredGate`: has
     * the session had a relay answer (set-once latch OR the current transport's
     * round-trip latch)? The rung acts only before it. Android sibling:
     * `RunViewModel.relayAnsweredForCircuitWatchdog`.
     */
    fun relayAnsweredForCircuitWatchdog(relayAnsweredThisSession: Boolean): Boolean =
        relayAnsweredThisSession || messageManager?.hasCompletedRelayRoundTrip() == true

    val vaultSelector = VaultSelector(
        store        = store,
        crypto       = crypto,
        vaultFactory = iosVaultFactory(),
        // Lever B: the DB-key OUTER layer can be Secure-Enclave auth-bound (opt-in
        // via Settings). Credential verifier + pre-PIN counters stay on `crypto`
        // (Keychain) directly, so a counter read never prompts (the key split).
        dbKeyProtector = IosDbKeyProtector(crypto),
        // The live vault handle, for the SQLCipher key
        // rotation a credential TIER UPGRADE (PIN → passphrase) performs. Read
        // through a lambda, not captured: [vault] is nulled on lock/wipe and
        // re-assigned on every unlock, and the rotation must see the CURRENT one (or
        // none, in which case it skips silently). Android wires the identical lambda.
        vaultProvider = { vault },
        // Review 2026-08-03: VaultSelector has CLOSED that handle because a re-key
        // did not verifiably commit (its codec write context can no longer be
        // trusted — see VaultSelector.retireRekeyedVaultHandle). Forward to Swift
        // (AppState wires [onVaultSessionRetired] in init), which hops to main and
        // runs its existing lock() teardown — parity with Android, where
        // MainActivity tears the session down via the auto-lock path. If Swift has
        // not wired the closure the handle is STILL closed (the close is
        // synchronous in commonMain), so no poisoned write can land either way.
        onRekeyHandleRetired = { onVaultSessionRetired?.invoke() },
    )

    /**
     * Review 2026-08-03: assigned by AppState.init. Invoked on the calling
     * (background, change-credential) thread AFTER VaultSelector closed the live
     * vault handle because a DB-key re-key did not verifiably commit. AppState
     * must dispatch to main and run its lock() teardown; the next unlock's
     * rotation reconcile recovers the vault under whichever key holds the file.
     */
    var onVaultSessionRetired: (() -> Unit)? = null

    // Since 2026-07-23 every kv key is its own Keychain item here, so the
    // "established" marker is per-item deletable alongside the counters. The DB-key
    // wrap item (vlt_c) is the "vault configured" signal — pass its presence probe.
    // The wipe fires only on POSITIVE deletion evidence (marker survives + wrap
    // present); an absent counter with NO marker on a configured vault
    // establishes-on-read instead of wiping (brick fix — an earlier version wiped legacy /
    // interrupted-provision vaults on first launch). Deleting BOTH counter and
    // marker is a known trade-off (→ reset), bounded by the Argon2id KDF cost.
    // Un-rollable monotonic sample so a FORWARD wall-clock jump can't reset
    // the rolling windows. systemUptime is a boot-relative clock the user cannot
    // wind; bootId is fixed to 0 — a real reboot resets systemUptime, which
    // windowRolled() detects as "uptime went backwards" and safely falls back to
    // the wall clock (a reboot forces the harder BFU extraction state anyway), so
    // no shell-writable reboot id is trusted.
    private val monotonicSampler: () -> MonotonicSample? = {
        MonotonicSample(
            (platform.Foundation.NSProcessInfo.processInfo.systemUptime * 1000.0).toLong(),
            0L,
        )
    }

    val pinAttempts = PinAttemptsStore(
        store, crypto,
        dbKeyWrapPresent = { store.contains(VaultStoreKeys.WRAPPED_DBKEY) },
        monotonicNow = monotonicSampler,
    )

    // Daily change-PIN abuse counter — see ChangePinAttemptStore. Its key is in
    // IosUserDefaultsKeys.all so emergencyWipe() clears it. anchorStore == store
    // (the same Keychain KV store holding `VaultStoreKeys.WRAPPED_DBKEY`), so the wrap anchor and
    // the fate-shared "established" marker both live there. A
    // pre-existing / pre-anchor vault's FIRST-ever change-PIN establishes-on-read
    // (marker absent → record + arm, never wipe), so iOS no longer emergency-wipes
    // on the first change-PIN even though unlock()/recoverWithCode() don't
    // re-establish. establish() below stays as a provision-time
    // optimisation; correctness no longer depends on it.
    val changePinAttempts = ChangePinAttemptStore(
        store, crypto,
        vaultWrapKeyInAnchorStore = VaultStoreKeys.WRAPPED_DBKEY,
        monotonicNow = monotonicSampler,
    )

    var vault: VaultDatabase? = null
        private set

    var messageManager: MessageManager? = null
        private set

    /** Group chat orchestration. Lives exactly as long as the unlocked vault;
     *  reads the CURRENT messageManager via the provider lambda, so Tor
     *  reconnects (which recreate the manager) need no re-wiring. */
    var groupManager: GroupManager? = null
        private set

    /**
     * `GroupConversationView` onAppear / onDisappear — the fourth FAST control-cadence
     * condition (2026-10-01; see `GroupManager.setGroupConversationForeground`). Read
     * by `AppState.startControlPoll` per cycle and per idle-sleep slice. Android
     * sibling: `RunViewModel.setGroupConversationForeground`. RAM-only; cleared with
     * the GroupManager on [lock] / emergency wipe.
     */
    fun setGroupConversationForeground(screenKey: String, open: Boolean) {
        groupManager?.setGroupConversationForeground(screenKey, open)
    }

    /** Referral/vouching (referral.md). Created on unlock alongside groupManager;
     *  the group control poll feeds it referral controls via onReferralControl. */
    var referralManager: ReferralManager? = null
        private set

    // -----------------------------------------------------------------------
    // Setup
    // -----------------------------------------------------------------------

    fun isConfigured(): Boolean {
        val configured = vaultSelector.isConfigured()
        platformLog("App", "isConfigured=$configured")
        return configured
    }

    /**
     * True when a vault file exists but no credential is stored for it — the
     * unopenable dead end the provision guard deliberately leaves rather than
     * resolving by destroying the file. Drives the unlock screen's explicit erase
     * offer. Never throws across the bridge; on a probe failure reports `false`
     * (no offer), because a bad read must never be able to surface an erase
     * button for a healthy vault.
     */
    fun orphanedVaultFile(): Boolean = try {
        vaultSelector.orphanedVaultFile()
    } catch (e: Exception) {
        platformLogError("App", "orphanedVaultFile probe failed: ${e::class.simpleName}")
        false
    }

    /**
     * True when the vault database FILE exists, independent of the credential
     * store. AppState ORs this into the flag that routes the UI, so a UserDefaults
     * plist that reads empty on a locked launch (documented in AppState.init —
     * NSFileProtectionComplete makes the plist itself lock-gated) can never send a
     * provisioned install to first-run setup, whose provision would delete the
     * vault. Never throws: a probe failure must not cross the non-@Throws bridge.
     */
    fun vaultFileExists(): Boolean = try {
        vaultSelector.vaultFileExists()
    } catch (e: Exception) {
        // Unresolvable path is not evidence of absence. Report "present" so the
        // caller routes to unlock rather than to the destructive setup flow.
        platformLogError("App", "vaultFileExists probe failed: ${e::class.simpleName}")
        true
    }

    fun setRealCredential(credential: String) {
        platformLog("App", "setting credential")
        try {
            // VERIFIED counter establishment FIRST — before
            // ANY provision state, and in particular before
            // provisionCredentialAndVault persists the DB-key wrap (its last
            // write) — so "wrap present, counter absent" (the iOS deletion
            // signature) can never describe a freshly-provisioned vault. The old
            // order (provision, then best-effort reset(): tryWrite swallows
            // KeyUnavailableException and reset returns Unit) let the provision
            // complete with the wrap present but counter+marker absent — and the
            // next launch's readOrNullOnTamper() emergency-wiped the honest vault.
            // A process kill between the wrap write and reset() produced the same
            // fatal state. Kill/outage interleavings under the NEW order
            // (establish = counter blob, then marker — write()'s order; provision
            // = mode/level, DB file, verifier, wrap LAST):
            //   1. die before the counter write     → nothing stored; fresh setup.
            //   2. die between counter and marker   → counter PRESENT → read()
            //      returns the count; unconfigured, setup re-runs + re-establishes.
            //   3. die after establish, before the verifier → counter+marker only;
            //      same as 2 (marker is only consulted when the counter is absent).
            //   4. die between verifier and wrap    → purgeHalfCredentialPairIfNeeded clears
            //      the lone verifier; counter+marker persist → read() fine.
            //   5. establishment unverifiable       → provision ABORTED below —
            //      no wrap is ever written, so no tamper state can form. (A
            //      flapping outage can in theory strand marker-without-counter
            //      here, but only on an UNCONFIGURED install: no counter read
            //      happens before setup, and re-provisioning overwrites it.)
            //   6. wrap persisted                   → the counter was already
            //      VERIFIED present before the wrap write began.
            // No interleaving leaves marker-or-wrap present with the counter
            // absent, so the tamper signature stays attacker-only.
            if (!pinAttempts.establishVerified()) {
                platformLogError("App", "setRealCredential aborted — counter establishment unverified (retryable)")
                return
            }
            // Establish the change-PIN counter alongside the wrong-PIN one so
            // the wrap anchor never mistakes a first legitimate change-PIN for a
            // deletion. Idempotent; safe to run before the wrap write below.
            changePinAttempts.establish()
            // Fresh provision: drop any retired clean-leave rows a deleted
            // install left in the (uninstall-surviving) Keychain store.
            removeRetiredCleanLeaveKeys()
            vaultSelector.setRealCredential(credential)
        } catch (e: Exception) {
            // Non-@Throws bridge method — a provisioning failure (transient
            // Keychain outage, SQLCipher I/O) must never cross into Swift
            // (SIGABRT). Partial state self-heals: a lone credential blob without
            // its DB-key blob is cleared by purgeHalfCredentialPairIfNeeded, and the next
            // launch recomputes isConfigured=false → setup re-runs.
            platformLogError("App", "setRealCredential failed (transient): ${e::class.simpleName}")
        }
    }

    // -----------------------------------------------------------------------
    // PIN change (rotation of the vault credential)
    // -----------------------------------------------------------------------

    /** Side-effect-free check that [credential] unlocks the vault. */
    fun verifyCredential(credential: String): Boolean =
        vaultSelector.verifyCredential(credential)

    /**
     * Rotate the vault PIN. Returns a stable string code so Swift never has to
     * bridge the Kotlin enum: "success", "wrong_current", "weak_credential", or
     * "failed" when the rotation threw. Heavy — Swift runs it off the main thread.
     */
    fun changeCredential(currentCredential: String, newCredential: String): String {
        platformLog("App", "changing credential")
        return try {
            vaultSelector.changeCredential(currentCredential, newCredential).toBridgeCode()
        } catch (e: Exception) {
            // Non-@Throws bridge method: a throw must become a failure code, never
            // a SIGABRT. Swift maps every non-"success" code to .wrongCurrent (the
            // change-PIN UI restarts; nothing is counted), so no Swift change.
            platformLogError("App", "changeCredential failed: ${e::class.simpleName}")
            "failed"
        }
    }

    /** Bridge string code for a [VaultSelector.ChangePinResult]; shared by
     *  [changeCredential] and [changeCredentialAndMode]. */
    private fun VaultSelector.ChangePinResult.toBridgeCode(): String = when (this) {
        VaultSelector.ChangePinResult.SUCCESS         -> "success"
        VaultSelector.ChangePinResult.WRONG_CURRENT   -> "wrong_current"
        // Swift maps any non-"success" code to .wrongCurrent (shouldn't happen —
        // the UI gates the floor; defense-in-depth).
        VaultSelector.ChangePinResult.WEAK_CREDENTIAL -> "weak_credential"
    }

    /** True when the credential is a passphrase (Lever A / Maximum). Drives the
     *  passphrase-vs-PIN entry UI. Fails OPEN to the free-text field for anything
     *  it cannot authenticate — so it must NEVER decide a tier upgrade; use
     *  [credentialKindProven] for that. */
    fun isPassphraseMode(): Boolean = vaultSelector.isPassphraseMode()

    /**
     * TRI-STATE proof of the credential's kind
     * for the TIER-UPGRADE decision — `true` provably a passphrase, `false`
     * provably a PIN, `null` unproven (unauthenticated/plant, damaged blob, or a
     * device-key outage). Swift sees `KotlinBoolean?`; feed it straight into
     * [ProtectionUpgradePlan.needsCredentialChangeForStorage] rather than
     * comparing by hand, so both platforms run the identical rule.
     */
    fun credentialKindProven(): Boolean? = vaultSelector.credentialKindProven()

    // --- Lever B — Secure-Enclave auth-bound DB-key unwrap (opt-in) ---

    /** True when this device can Secure-Enclave auth-bind the DB-key unwrap. */
    fun supportsDbKeyAuthBinding(): Boolean = vaultSelector.supportsDbKeyAuthBinding()

    /** True when the stored DB key is currently SE auth-bound (Lever B active). */
    fun isDbKeyAuthBound(): Boolean = vaultSelector.isDbKeyAuthBound()

    /**
     * Enable/disable the SE auth-bound DB-key layer. Disable prompts once
     * (biometry/passcode) to unwrap the current auth-bound blob; enable does
     * not. Heavy + may prompt — Swift runs it off the main thread. Returns
     * true on success; false on failure, including a throw (non-@Throws bridge).
     */
    fun setDbKeyAuthBinding(enabled: Boolean): Boolean = try {
        vaultSelector.setDbKeyAuthBinding(enabled)
    } catch (e: Exception) {
        platformLogError("App", "setDbKeyAuthBinding failed: ${e::class.simpleName}")
        false
    }

    /**
     * [changeCredential] that also switches PIN ↔ passphrase mode atomically
     * (high-risk mode enable/disable). Same string codes; heavy — off-main.
     */
    fun changeCredentialAndMode(
        currentCredential: String,
        newCredential: String,
        passphraseMode: Boolean,
    ): String {
        platformLog("App", "changing credential + mode (passphrase=$passphraseMode)")
        return try {
            vaultSelector.changeCredentialAndMode(currentCredential, newCredential, passphraseMode)
                .toBridgeCode()
        } catch (e: Exception) {
            // Same rule as [changeCredential]: a throw becomes "failed" (Swift: .wrongCurrent).
            platformLogError("App", "changeCredentialAndMode failed: ${e::class.simpleName}")
            "failed"
        }
    }

    // -----------------------------------------------------------------------
    // Protection level (threat-level slider) + Lever B recovery code
    // -----------------------------------------------------------------------

    /**
     * True when the most recent [setRealCredentialWithLevel] returned `false`
     * because the device key (Keychain) was transiently unavailable — e.g. a
     * locked keybag — rather than a real provisioning failure. Two upstream
     * sources feed this, mirroring the two places a device-key outage can land
     * given THIS platform's establish-before-persist ordering (see the counter-
     * establishment comment on [setRealCredentialWithLevel]):
     *  - `pinAttempts.establishVerified()` returning false. At a FIRST-RUN
     *    provision nothing was ever previously stored, so its write+read-back
     *    round-trip ([PinAttemptsStore.tryWrite] / `.read`, both gated on the
     *    same device-key-dependent AEAD step) has no realistic failure mode
     *    besides a transient `KeyUnavailableException`: a same-attempt
     *    `TamperException` on a blob this very call just wrote would require an
     *    adversary racing the write, which does not exist at first run.
     *  - [VaultSelector.lastProvisionWasDeviceKeyUnavailable] — the confirmed
     *    Android trigger (Keystore super-key eviction) landing on iOS's
     *    Keychain equivalent instead, inside `provisionCredentialAndVault`.
     *
     * RAM-only, reset at the top of every [setRealCredentialWithLevel] call so a
     * stale `true` can never explain a different attempt's failure. Read-after-
     * write only (same discipline as the Kotlin field it mirrors).
     */
    private var lastProvisionDeviceKeyUnavailable = false

    /** See [lastProvisionDeviceKeyUnavailable]. Call immediately after
     *  [setRealCredentialWithLevel] returns `false`. */
    fun lastProvisionWasDeviceKeyUnavailable(): Boolean = lastProvisionDeviceKeyUnavailable

    /** Provision with a chosen level + credential mode (onboarding slider).
     *  False = entropy floor / transient provision failure (never throws across
     *  the bridge — PinSetupView already treats false as a retryable failure). */
    fun setRealCredentialWithLevel(credential: String, passphraseMode: Boolean, level: String): Boolean = try {
        lastProvisionDeviceKeyUnavailable = false
        // VERIFIED counter establishment BEFORE the DB-key wrap can be
        // persisted — see setRealCredential above for the full kill/outage
        // interleaving enumeration. The old best-effort `if (ok) reset()` could
        // return ok=true with the wrap present but counter+marker absent (the
        // iOS tamper signature) and the next launch emergency-wiped the
        // honest vault. Establishment failure = provision failure (false),
        // consistent with the retryable failure paths PinSetupView already
        // handles; nothing is persisted, so partial state self-heals as before.
        if (!pinAttempts.establishVerified()) {
            platformLogError("App", "provision aborted — counter establishment unverified (retryable)")
            // See lastProvisionDeviceKeyUnavailable's kdoc — at a first-run
            // provision this has no realistic cause besides the device key.
            lastProvisionDeviceKeyUnavailable = true
            false
        } else {
            // Establish the change-PIN counter alongside the wrong-PIN one.
            changePinAttempts.establish()
            val ok = vaultSelector.setRealCredential(
                credential, passphraseMode,
                ProtectionLevel.fromStorageOrNull(level) ?: ProtectionLevel.CASUAL,
            )
            if (!ok) lastProvisionDeviceKeyUnavailable = vaultSelector.lastProvisionWasDeviceKeyUnavailable()
            // Fresh provision: drop retired clean-leave rows — see the sibling
            // in setRealCredential above.
            if (ok) removeRetiredCleanLeaveKeys()
            ok
        }
    } catch (e: Exception) {
        platformLogError("App", "provision failed (transient): ${e::class.simpleName}")
        false
    }

    /** The level to display in Settings (stored, or derived for a legacy vault). */
    fun currentProtectionLevel(): String = vaultSelector.currentProtectionLevel().storageValue

    /** Display level for the runestone art tiers — never throws (CASUAL/plain
     *  art on a transient store outage). */
    fun displayProtectionLevel(): String = vaultSelector.displayProtectionLevel().storageValue

    /** False for a legacy vault that has never had a level set — drives the one-time
     *  post-unlock chooser (first-run sets it before the PIN instead). */
    fun protectionLevelConfigured(): Boolean = vaultSelector.protectionLevelOrNull() != null

    /** Persist a level change (Settings). False = unknown level or a transient
     *  device-key outage (nothing written; VaultSelector logs + defers — never
     *  throws across this non-@Throws bridge). The chooser re-appears on the
     *  next launch until a write lands, so ignoring the result is safe. */
    fun setProtectionLevel(level: String): Boolean =
        ProtectionLevel.fromStorageOrNull(level)?.let { vaultSelector.setProtectionLevel(it) } ?: false

    // ---- Device-lock floor (DeviceLockPolicy) --------------------------------
    //
    // Swift passes a single Bool, not the tri-state: ContentView /
    // ProtectionLevelView derive it from LAError.passcodeNotSet, which is true
    // ONLY on a DEFINITE no-passcode answer and treats every ambiguous
    // LAContext error as "a passcode IS set" — exactly the collapse
    // DeviceLockState.Unknown → Present that these wrappers perform. Keep those
    // probes fail-closed or this bridge silently starts forcing on noise.

    private fun lockState(passcodeAbsent: Boolean): DeviceLockState =
        if (passcodeAbsent) DeviceLockState.Absent else DeviceLockState.Present

    /** The tier this device must run at, or null when the user chooses freely. */
    fun forcedProtectionLevel(passcodeAbsent: Boolean): String? =
        DeviceLockPolicy.forcedLevel(lockState(passcodeAbsent))?.storageValue

    /** Whether [level] may be picked here (device-lock floor + Lever-B hardware). */
    fun isProtectionLevelSelectable(level: String, passcodeAbsent: Boolean, leverBSupported: Boolean): Boolean =
        ProtectionLevel.fromStorageOrNull(level)?.let {
            DeviceLockPolicy.isSelectable(it, lockState(passcodeAbsent), leverBSupported)
        } ?: false

    /** Why [level] is greyed out, or null when it is selectable. */
    fun protectionLevelStopReason(level: String, passcodeAbsent: Boolean, leverBSupported: Boolean): String? =
        ProtectionLevel.fromStorageOrNull(level)?.let {
            DeviceLockPolicy.stopReason(it, lockState(passcodeAbsent), leverBSupported)
        }

    /** True when the STORED level is below the floor this device requires, so the
     *  app must run the forced tier change before it can be used. Checked on
     *  every unlock — on iOS a passcode removal usually crypto-erases the vault
     *  outright, but the path where it doesn't must not stay at a PIN.
     *
     *  Reads [VaultSelector.protectionLevelForFloorCheck],
     *  NOT the lenient `protectionLevelOrNull` — the latter honours a LEGACY
     *  CLEARTEXT `vlt_lvl`, so planting the seven bytes `maximum` in the
     *  NSUserDefaults slot `KeyValueStore` falls back to (`vlt_lvl` IS in
     *  `IosUserDefaultsKeys.all`, so the fallback serves it once the Keychain item
     *  is confirmed-absent) suppressed this gate forever. Android's
     *  `postUnlockRoute` reads the same accessor — keep the two in step. */
    fun needsForcedProtectionMigration(passcodeAbsent: Boolean): Boolean =
        DeviceLockPolicy.needsForcedMigration(
            vaultSelector.protectionLevelForFloorCheck(), lockState(passcodeAbsent))

    /** Per-level enforcement values (or the current defaults for a legacy vault).
     *  All three route through the shared four-state decisions so an UNREADABLE
     *  stored level (transient key outage) fails safe — shortest lock, skip wipe,
     *  most lenient budget — while a DAMAGED one fails SECURE (shortest lock,
     *  MAXIMUM's wipe window, MAXIMUM's budget). */
    fun autoLockTimeoutMs(): Long =
        CredentialPolicy.autoLockTimeoutMs(vaultSelector.protectionLevelForEnforcement())

    /**
     * Bounded Tor keep-alive after backgrounding ([BackgroundTorKeepAlive]): the
     * TIER half of the gate, read LIVE at `.background` — before AppState locks,
     * because the lock wipes the device key this read needs. MAXIMUM / Damaged
     * refuse; an Unreadable read falls back to [sessionTierAllowed] (this
     * session's [torKeepAliveTierAllowsAuthenticated] from unlock, false when
     * there was none). Never throws (protectionLevelForEnforcement never does).
     */
    fun torKeepAliveTierAllows(sessionTierAllowed: Boolean): Boolean =
        BackgroundTorKeepAlive.tierAllows(vaultSelector.protectionLevelForEnforcement(), sessionTierAllowed)

    /** The same tier decision from the AUTHENTICATED read at unlock — AppState's
     *  fallback for a live read that races the device key at backgrounding. */
    fun torKeepAliveTierAllowsAuthenticated(): Boolean =
        BackgroundTorKeepAlive.tierAllowsAuthenticated(vaultSelector.protectionLevelForEnforcement())

    /**
     * Periodic random re-auth at MAXIMUM (docs/periodic-reauth-design.md): the
     * SAME tier gate + debug/e2e escape hatch Android reads via
     * `RunViewModel.onVaultOpened`; see [ReauthPolicy.isEnabled]. Re-read on
     * every unlock (ContentView's `isUnlocked` onChange), not cached, so a
     * mid-session tier change takes effect on the next unlock.
     */
    fun reauthEnabled(): Boolean =
        ReauthPolicy.isEnabled(vaultSelector.protectionLevelForEnforcement())

    /** Fresh random interval (ms) for the NEXT re-auth deadline, drawn at
     *  every unlock — see [ReauthPolicy.nextIntervalMs]. */
    fun nextReauthIntervalMs(): Long = ReauthPolicy.nextIntervalMs()

    /** Threshold for the launch inactivity check, or -1 ONLY when a stored level
     *  is UNREADABLE — the device key is transiently unavailable, so a healthy
     *  blob can't be told from a damaged one and the caller must SKIP the check
     *  this launch (the 7-day default applied to an unreadable CASUAL (180-day)
     *  level would crypto-erase the vault ~173 days early).
     *
     *  A DAMAGED blob is NOT in that bucket since 2026-07-30: the
     *  device key WORKS and the value failed AEAD, which is positive tamper
     *  evidence, so it yields MAXIMUM's 7-day window rather than -1 — one
     *  flipped byte inside the base64 must not disarm the dead-man's switch on
     *  every launch. Selecting that window is not itself a wipe: the caller
     *  still has to find a genuinely expired timestamp.
     *  Decision shared with Android via InactivityPolicy.thresholdMsOrNull. */
    fun inactivityThresholdMs(): Long =
        InactivityPolicy.thresholdMsOrNull(vaultSelector.protectionLevelForEnforcement()) ?: -1L

    /** Wrong-credential wipe budget; an UNREADABLE stored level (transient key
     *  outage) yields the most LENIENT tier's budget (shared decision — never
     *  smaller than chosen), a DAMAGED one MAXIMUM's smallest budget. */
    fun maxConsecutiveAttempts(): Int =
        CredentialPolicy.maxConsecutiveAttempts(vaultSelector.protectionLevelForEnforcement())

    /** True when a Lever B recovery code is provisioned. */
    fun hasRecoveryCode(): Boolean = vaultSelector.hasRecoveryCode()

    /**
     * PHASE ONE of the two-phase Lever B enable: mint a recovery code and PREPARE
     * the strict auth-bound key WITHOUT committing it — the vault stays PLAIN until the
     * code is acknowledged. Returns a stable string so Swift never bridges the Kotlin
     * sealed class: "code:<recoveryCode>" on success, else "unsupported" /
     * "wrong_credential" / "failed". Heavy + prompts — off-main. The UI MUST call
     * [finalizeLeverB] once the user acknowledges the code, or the enable never commits
     * (the vault stays plain — safe, but Lever B is not armed).
     */
    fun enableLeverBWithRecovery(credential: String): String = try {
        when (val r = vaultSelector.enableDbKeyAuthBindingWithRecovery(credential)) {
            is VaultSelector.RecoveryEnableResult.Enabled -> "code:" + r.recoveryCode
            VaultSelector.RecoveryEnableResult.Unsupported -> "unsupported"
            VaultSelector.RecoveryEnableResult.WrongCredential -> "wrong_credential"
            VaultSelector.RecoveryEnableResult.Failed -> "failed"
        }
    } catch (e: Exception) {
        // Non-@Throws bridge method: a throw is reported as the existing "failed".
        platformLogError("App", "enableLeverBWithRecovery failed: ${e::class.simpleName}")
        "failed"
    }

    /**
     * PHASE TWO of the two-phase Lever B enable: commit the prepared strict
     * auth-bound blob AND promote the protection [level] (pass "private") in ONE atomic
     * write, AFTER the user has acknowledged their recovery code. Call this from the code
     * screen's "I've saved it" action. Returns false if nothing was prepared or the batch
     * did not persist — vault stays PLAIN at the honest base tier (never over-claims,
     * never bricks). The enable phase must NOT persist PRIVATE before this. Off-main.
     */
    fun finalizeLeverB(level: String): Boolean = try {
        vaultSelector.finalizeDbKeyAuthBinding(
            ProtectionLevel.fromStorageOrNull(level) ?: ProtectionLevel.PRIVATE
        )
    } catch (e: Exception) {
        // Non-@Throws bridge method: a throw is reported as the existing `false`.
        platformLogError("App", "finalizeLeverB failed: ${e::class.simpleName}")
        false
    }

    /**
     * True when this vault is PRIVATE-armed with a LEGACY WEAK auth-bound key that the
     * unlock-time reconcile could not auto-upgrade (biometrics unavailable, or no
     * recovery code). The UI can offer re-harden (Settings disable→enable) or step-down.
     * Post-unlock; never throws.
     */
    fun needsLeverBReharden(): Boolean = vaultSelector.needsLeverBReharden()

    /**
     * Recover a Lever-B-bricked vault with the recovery code + credential, then
     * open it — mirrors [unlock]'s success wiring. Same tri-state codes
     * ([UNLOCK_OPENED]/[UNLOCK_DENIED]/[UNLOCK_ERROR]). Heavy — off-main.
     */
    fun recoverWithCode(recoveryCode: String, credential: String): Int {
        return try {
            if (crypto.isWiped()) crypto.reloadKey()
            when (val result = vaultSelector.recoverWithCode(recoveryCode, credential)) {
                is VaultSelector.UnlockResult.Opened -> {
                    adoptOpenedVault(result.vault)
                    // Arm the push-consent latch (see provenNotificationLevel).
                    provenNotificationLevel()
                    platformLog("App", "vault recovered + opened via recovery code")
                    UNLOCK_OPENED
                }
                VaultSelector.UnlockResult.Denied -> UNLOCK_DENIED
                VaultSelector.UnlockResult.Error -> UNLOCK_ERROR
                // Recovery is already the escape hatch — if it too reports a dead
                // hardware key there is nowhere further to route, so keep it a
                // retryable error rather than looping the user back to this screen.
                VaultSelector.UnlockResult.RecoveryRequired -> UNLOCK_ERROR
            }
        } catch (e: Exception) {
            platformLogError("App", "recoverWithCode exception (transient): ${e::class.simpleName}")
            UNLOCK_ERROR
        }
    }

    /**
     * The session wiring of a vault that just OPENED — shared by [unlock] and
     * [recoverWithCode], so the two opens cannot drift. Android sibling:
     * `RunViewModel.onVaultOpened`.
     *
     * The frozen-move refresh runs in its own try: by then the vault is open and
     * published, so a throw there must not turn a successful open into
     * [UNLOCK_ERROR] (on recovery, after the recovery blob is already gone).
     */
    private fun adoptOpenedVault(opened: VaultDatabase) {
        // A new session epoch FIRST, before anything can record into the
        // parked-send ledger: a send still in flight from the previous session
        // carries the old epoch and is refused (TransportFailedSends).
        TransportFailedSends.shared.beginSession()
        vault = opened
        // Build + cross-wire both session managers in one shared
        // place so the referral-control bridge can't be forgotten.
        val managers = createSessionManagers(opened) { messageManager }
        groupManager = managers.groupManager
        referralManager = managers.referralManager
        // "Move to new device": the manager is built with the controller
        // (long before any vault), so a FROZEN vault only announces itself
        // once it is open. Idempotent, and it never downgrades a live
        // export state — see MoveManager.refreshFrozenState. On EVERY open
        // (unlock and recovery), in its own try: the vault is already open.
        try {
            moveManager.refreshFrozenState()
        } catch (e: Exception) {
            platformLogWarn("Move", "frozen-state refresh failed after open: ${e::class.simpleName}")
        }
    }

    // -----------------------------------------------------------------------
    // Unlock — returns a tri-state UNLOCK_* code.
    // -----------------------------------------------------------------------

    /**
     * Attempt to unlock the vault. Returns a TRI-STATE code (not a Boolean) so
     * the Swift PIN UI can distinguish a wrong credential from a transient open
     * failure. This distinction is load-bearing: only [UNLOCK_DENIED] is a guess
     * that must count toward the brute-force budget / emergency wipe.
     * [UNLOCK_ERROR] means the credential was CORRECT (or the attempt could not
     * be evaluated at all) — it must be retried, never counted, never wiped.
     * Collapsing the two (the old Boolean contract) let transient SQLCipher open
     * failures on the right PIN burn the budget and wipe real data, which the
     * Android path already avoids.
     *
     *  - [UNLOCK_OPENED] (0): vault opened.
     *  - [UNLOCK_DENIED] (1): wrong credential — counts toward the budget.
     *  - [UNLOCK_ERROR]  (2): transient open failure / unevaluable — retry only.
     */
    fun unlock(credential: String): Int {
        return try {
            val wasWiped = crypto.isWiped()
            platformLog("App", "unlock attempt (cryptoWiped=$wasWiped)")
            if (wasWiped) {
                platformLog("App", "reloading crypto key from Keychain")
                crypto.reloadKey()
            }
            when (val result = vaultSelector.unlock(credential)) {
                is VaultSelector.UnlockResult.Opened -> {
                    adoptOpenedVault(result.vault)
                    // Arm the push-consent latch on EVERY unlock, not
                    // only when something is about to register — an install that
                    // never enabled push would otherwise keep an empty proof slot
                    // forever, and an empty slot is what the one-time legacy
                    // trust reads. See [provenNotificationLevel].
                    provenNotificationLevel()
                    platformLog("App", "vault unlocked")
                    UNLOCK_OPENED
                }
                VaultSelector.UnlockResult.Denied -> {
                    platformLogWarn("App", "unlock denied (wrong credential)")
                    UNLOCK_DENIED
                }
                VaultSelector.UnlockResult.Error -> {
                    // Credential MATCHED but the vault failed to open transiently
                    // (corrupt/locked SQLCipher file or sidecar, I/O). Not a wrong
                    // PIN — the caller retries and must NOT count or wipe.
                    platformLogWarn("App", "vault open failed (transient) — retry")
                    UNLOCK_ERROR
                }
                VaultSelector.UnlockResult.RecoveryRequired -> {
                    // Credential correct, Secure Enclave key permanently gone.
                    platformLogWarn("App", "unlock needs the recovery code — SE key invalidated")
                    UNLOCK_RECOVERY_REQUIRED
                }
            }
        } catch (e: Exception) {
            // Fail CLOSED, never rethrow: an uncaught Kotlin exception crossing
            // into Swift SIGABRTs the process. A wrong PIN never throws here (it
            // returns Denied), so any exception — e.g. a transient
            // KeyUnavailableException from reloadKey() — is a non-guess we report
            // as a transient ERROR the user can retry, never a counted denial.
            platformLogError("App", "unlock exception (transient, retry): ${e::class.simpleName}")
            UNLOCK_ERROR
        }
    }

    // -----------------------------------------------------------------------
    // Tor integration — called from Swift when Tor SOCKS5 proxy is ready.
    // -----------------------------------------------------------------------

    /**
     * The app's own version, for [MessageManager]'s update-nudge compare
     * (`localAppVersion` ctor param — see UpdateCheck.kt in commonMain). Read from
     * `CFBundleShortVersionString`, which the pre-push hook keeps hook-synced to
     * repo-root `version.properties`. `objectForInfoDictionaryKey` never throws;
     * an absent/non-string value (unreachable in a real bundle, but not worth a
     * crash) falls back to `""`, which [parseAppVersion] rejects — the nudge
     * simply never fires rather than comparing against garbage.
     */
    private fun localAppVersionFromBundle(): String =
        platform.Foundation.NSBundle.mainBundle
            .objectForInfoDictionaryKey("CFBundleShortVersionString") as? String ?: ""

    /**
     * Creates the MessageManager with a SOCKS5-proxied HTTP client.
     * Called from Swift's AppState when TorManager reports connected.
     */
    fun connectTor(socksPort: Int) {
        // Remembered for the move's push unregistration, which builds its OWN
        // proxied client (see IosMoveSessionControl.unregisterPushBestEffort).
        lastSocksPort = socksPort
        // SOCKS isolation (RendezvousHedge) only through the EMBEDDED Tor: the
        // user's external proxy gets exactly today's no-auth handshake and no hedge.
        val httpClient = PlatformHttpClient(socksPort, socksIsolationCapable = !externalProxyMode)
        messageManager = vault?.let { v ->
            MessageManager(
                databaseManager = v,
                httpClient      = httpClient,
                localAppVersion = localAppVersionFromBundle()
            )
        }
        // Never the port: in external mode it is the user's proxy port (LogBuffer -> Debug-mode upload).
        platformLog("IosAppController", "MessageManager created (transport=${if (externalProxyMode) "external" else "tor"})")
    }

    /**
     * Creates the MessageManager with a direct (no-proxy) HTTP client.
     * Used when RelayConfig.isTorRequired is false (development mode).
     */
    fun connectDirect() {
        // External SOCKS proxy mode forbids direct HTTP outright — fail closed
        // (AppState never calls this in that mode; Kotlin-side belt).
        if (externalProxyMode) {
            platformLogWarn("IosAppController", "direct HTTP refused — external proxy mode")
            return
        }
        // No SOCKS proxy on this path — the move's push unregistration is skipped
        // (`port > 0`), exactly like every other push path in dev/simulator builds.
        lastSocksPort = 0
        messageManager = vault?.let { v ->
            MessageManager(
                databaseManager = v,
                httpClient      = PlatformHttpClient(),
                localAppVersion = localAppVersionFromBundle()
            )
        }
        platformLog("IosAppController", "MessageManager created with direct HTTP")
    }

    // -----------------------------------------------------------------------
    // Connect-time unread prime — the Swift-facing wrapper around
    // [GroupManager.primeUnreadCounts]. Android calls that suspend function
    // directly from viewModelScope; a suspend function does not cross the Swift
    // bridge cleanly, so iOS gets this callback shape instead. Same shared
    // implementation underneath, so the two platforms prime identically.
    // -----------------------------------------------------------------------

    /**
     * Scope for the per-session background work this controller owns: the unread
     * prime, the rendezvous warm-up ([warmRelayRendezvous]) and the one-shot
     * connect-time report ([reportConnectTime]); the move quiesce cancels it too.
     * [SupervisorJob] so a failed pass can never cancel the scope for the next one;
     * [Dispatchers.Default] only LAUNCHES (each blocking `/peek` hops to
     * `Dispatchers.IO` inside [GroupManager.primeUnreadCounts]).
     *
     * Its children are cancelled by [lock] and [emergencyWipe] so a pass still in
     * flight cannot keep issuing relay requests — nor call back into a torn-down
     * Swift AppState — with capabilities snapshotted before the session ended. The
     * scope itself survives, so the next unlock can prime again.
     */
    private val sessionWorkScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    /**
     * Fires the one-shot parallel unread prime; see [GroupManager.primeUnreadCounts]
     * for the semantics that matter (bounded concurrency, snapshot-then-fan-out, no
     * jitter, MERGE-ONLY emission — a contact whose peek fails produces NO callback,
     * never a 0).
     *
     * Contract for the Swift caller:
     *  - [onContactUnread] is invoked STRICTLY SERIALLY (never from two workers at
     *    once), so a naive merge into `@Published` state needs no lock of its own —
     *    but it arrives on a BACKGROUND thread, so hop to main before touching UI
     *    state, and keep it cheap (it is called while the emission mutex is held).
     *  - [onComplete] fires EXACTLY ONCE on every path — success, failure, no
     *    contacts, no transport, and cancellation by [lock] / [emergencyWipe] — also
     *    on a background thread. It means "this pass is over", NOT "counts arrived".
     *  - Nothing throws across the bridge (this is not `@Throws`; an uncaught Kotlin
     *    exception reaching Swift is a SIGABRT), including a throw from either
     *    closure.
     *
     * With no unlocked session (vault or GroupManager null — locked, wiped, or
     * called before unlock) it emits nothing and completes immediately.
     */
    fun primeUnreadCounts(
        blockedContactIds: List<String>,
        onContactUnread: (contactId: String, count: Int) -> Unit,
        onComplete: () -> Unit,
    ) {
        val gm = groupManager
        if (gm == null || vault == null) {
            platformLog("IosAppController", "unread prime skipped — no unlocked session")
            try { onComplete() } catch (e: Throwable) {
                platformLogWarn("IosAppController", "unread prime onComplete threw: ${e::class.simpleName}")
            }
            return
        }
        sessionWorkScope.launch {
            try {
                gm.primeUnreadCounts(blockedContactIds.toSet(), onContactUnread = onContactUnread)
            } catch (e: Throwable) {
                // Includes the CancellationException from lock()/emergencyWipe(): a
                // cancelled pass is a normal outcome here, not an error to surface.
                platformLogWarn("IosAppController", "unread prime ended early: ${e::class.simpleName}")
            } finally {
                try { onComplete() } catch (e: Throwable) {
                    platformLogWarn("IosAppController", "unread prime onComplete threw: ${e::class.simpleName}")
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Contact teardown / relay re-keying. Both mirror Android's
    // RunViewModel.deleteContactInBackground / resetRelayAccessInBackground and
    // route through the SHARED commonMain implementations, so the two platforms
    // purge and rotate the identical set. Neither throws (they cross the Swift
    // bridge); Swift runs them off the main thread.
    // -----------------------------------------------------------------------

    /**
     * Deletes [contactId] locally and best-effort DELETEs its two inbound inboxes
     * on the relay (caps snapshotted BEFORE the rows go). Returns whether the LOCAL
     * delete succeeded — the relay cleanup never gates it, so a user's delete is
     * never held hostage to Tor. See [deleteContactAndPurgeRelay].
     */
    fun deleteContactAndPurgeRelay(contactId: String): Boolean = try {
        val v = vault
        // Fully qualified: the 3-arg commonMain top-level, not this 1-arg member.
        if (v == null) false else com.vg.run.deleteContactAndPurgeRelay(v, messageManager, contactId)
    } catch (e: Throwable) {
        platformLogError("IosAppController", "deleteContactAndPurgeRelay failed: ${e::class.simpleName}")
        false
    }

    /**
     * "Reset relay access": rotates the READ capability on both of [contactId]'s
     * inbound inboxes. Non-destructive — see [MessageManager.resetRelayAccess]. A
     * false result is "not proven done", never data loss: the durable pending
     * marker survives and the control poll reconciles it.
     */
    fun resetRelayAccess(contactId: String): Boolean = try {
        messageManager?.resetRelayAccess(contactId) ?: false
    } catch (e: Throwable) {
        platformLogError("IosAppController", "resetRelayAccess failed: ${e::class.simpleName}")
        false
    }

    /**
     * Anonymous "Report bug" — sends [text] once over the SAME live relay
     * transport [messageManager] is currently using (Tor SOCKS in
     * production, direct HTTP only in dev/simulator — see [connectTor] /
     * [connectDirect]). No vault access, no capability, no auth; nothing
     * about the report is persisted on this device. See
     * [BugReportSender] (commonMain, standalone — not message-protocol
     * code). Returns false with no relay connected yet (Tor still
     * bootstrapping) exactly like any other transport failure — the caller
     * shows one generic error copy either way. Never throws (crosses the
     * Swift bridge); blocking, mirroring [resetRelayAccess] — call off the
     * main thread.
     */
    fun sendBugReport(text: String): Boolean {
        val mm = messageManager ?: return false
        return try {
            BugReportSender.send(mm.relayTransport(), RelayConfig.BASE_URL, text, localAppVersionFromBundle(), "ios")
        } catch (e: Throwable) {
            platformLogError("IosAppController", "sendBugReport failed: ${e::class.simpleName}")
            false
        }
    }

    // -----------------------------------------------------------------------
    // Opt-in push (docs/RELAY_SPEC.md) — CONTENTLESS. Swift owns the
    // UNUserNotificationCenter/APNs plumbing (auth prompt, token delivery,
    // remote-notification wake); this surface only ever sees an already-hex
    // device token and talks to the relay's PUT/DELETE /inbox/{id}/push.
    //
    // The OPT-IN itself is now two slots, and iOS
    // genuinely stores them in two places — Swift keeps the plaintext selector
    // in NSUserDefaults (`AppState.pushEnabled`, the locked-screen wake/badge
    // gate and the Settings switch), while the DEVICE-KEY AEAD consent proof
    // lives in the Keychain KV service beside the vault's own selector values.
    // Only the proof authorises minting a push identity. The functions below
    // are that seam; everything else about the Swift push plumbing is
    // unchanged.
    // -----------------------------------------------------------------------

    /**
     * The legacy PLAINTEXT selector, read straight from NSUserDefaults rather
     * than through [store].
     *
     * Deliberately not `store.getString(NotificationLevelStore.KEY)`: that key
     * is on [IosUserDefaultsKeys.all], so `KeyValueStore.getString` would
     * MIGRATE it into the Keychain and DELETE the NSUserDefaults copy — after
     * which Swift's `pushEnabled` getter reads nil, the Settings switch flips
     * itself off and every wake gate drops. This read is the migration SOURCE
     * for [NotificationLevelStore.provenLevel] and nothing else.
     */
    private fun legacyNotifLevelPlaintext(): String? = try {
        readFoldedNotifLevel(seed = false)
    } catch (_: Throwable) {
        null
    }

    /**
     * The plaintext selector with the LEGACY FOLD applied — the ONE copy of that
     * rule. Pre-2026-07-28 installs stored the opt-in as the BOOLEAN
     * `push_tier2_enabled`; `notif_level` absent + that bool on means
     * VENDOR_PUSH. `false`/absent needs no fold: that is already OFF.
     *
     * [seed] = true also writes the folded value into `notif_level` (straight to
     * NSUserDefaults, never through [store] — see [legacyNotifLevelPlaintext]),
     * so every later read takes the stored value. The unlock-time establish reads
     * with [seed] = false: the fold is not guaranteed to have been seeded before
     * it runs, and an establish that missed it would seal `off` and latch a
     * legacy push user silent for good.
     */
    private fun readFoldedNotifLevel(seed: Boolean): String? {
        val defaults = platform.Foundation.NSUserDefaults.standardUserDefaults
        defaults.stringForKey(NotificationLevelStore.KEY)?.let { return it }
        if (!defaults.boolForKey(IosUserDefaultsKeys.PUSH_TIER2_LEGACY)) return null
        val folded = NotificationLevel.VENDOR_PUSH.storageValue
        if (seed) defaults.setObject(folded, forKey = NotificationLevelStore.KEY)
        return folded
    }

    /**
     * Swift's plaintext push selector (`AppState.pushEnabled`'s getter, the
     * locked-screen wake/badge gate and the Settings switch): is `notif_level`
     * VENDOR_PUSH, after the legacy fold (seeding `notif_level` when the legacy
     * bool is what said so)? Plaintext — NOT consent; registration requires
     * [provenNotificationLevel]. Never throws (Swift-reachable); unreadable = off.
     */
    fun foldLegacyPushPreference(): Boolean = try {
        readFoldedNotifLevel(seed = true) == NotificationLevel.VENDOR_PUSH.storageValue
    } catch (_: Throwable) {
        false
    }

    /**
     * The authenticated push consent. Never throws (Swift-reachable and
     * on the registration hot path); anything unauthenticated answers OFF.
     *
     * Also performs the one-time establish-on-read described on
     * [NotificationLevelStore.provenLevel] — which is why [unlock] and
     * [recoverWithCode] call it on success even when nothing is about to be
     * registered: that call is what arms the latch on an install that never
     * enabled push, so a plaintext plant made later is never trusted. Both call
     * sites run strictly AFTER [adoptOpenedVault] published the vault, which is required: the
     * latch is a `_meta` row inside the vault, and with no vault open the
     * migration is skipped entirely (answering OFF) rather than run unlatched.
     */
    fun provenNotificationLevel(): NotificationLevel = try {
        NotificationLevelStore.provenLevel(store, crypto, vault, legacyNotifLevelPlaintext())
    } catch (_: Throwable) {
        NotificationLevel.OFF
    }

    /**
     * Swift-facing Boolean form of [provenNotificationLevel] — the gate on
     * asking APPLE for a device token.
     *
     * The APNs request used to ride Swift's plaintext `pushEnabled` and fire from
     * `RunApp`'s `.onAppear`, i.e. BEFORE unlock, so a planted `notif_level`
     * still got a live device token minted: no relay row, but half a vendor
     * identity created from an unauthenticated value. It now fires only from the
     * post-unlock paths, behind this — the same proof `registerRefs` requires, so
     * the two halves of "this device has a push identity" are gated on one fact.
     */
    fun pushConsentProven(): Boolean = provenNotificationLevel() == NotificationLevel.VENDOR_PUSH

    /**
     * Records the user's own push choice as an authenticated consent proof.
     * Called by `AppState.persistNotifLevel` — the single Swift write choke
     * point for the plaintext selector — immediately AFTER it writes
     * NSUserDefaults, so a failure here leaves plaintext-without-proof, the
     * half that self-heals on the next [provenNotificationLevel] rather than
     * the half that registers a silent device.
     *
     * @return true when the proof read back. Never throws.
     */
    fun setPushConsent(on: Boolean): Boolean = try {
        NotificationLevelStore.setConsentProof(
            store,
            crypto,
            vault,
            if (on) NotificationLevel.VENDOR_PUSH else NotificationLevel.OFF,
        )
    } catch (_: Throwable) {
        false
    }

    /**
     * Drops the consent proof — the wipe-residue counterpart to
     * [setPushConsent], called from `AppState.clearWipeResidue()` beside its
     * existing `removeObject(forKey: notif_level)`. Never throws.
     *
     * A wipe also takes the whole Keychain KV service with it (`kvDeleteAll()`),
     * so this is belt-and-braces for the paths that clear residue without a
     * full erase — the same posture the surrounding removals already have.
     */
    fun clearPushConsent() {
        try {
            NotificationLevelStore.clearLevel(store, crypto, vault)
        } catch (_: Throwable) {
            // Best effort; a surviving proof over a removed plaintext selector
            // registers nothing on its own (Swift's own gate reads the
            // plaintext) and the next wipe sweeps the service wholesale.
        }
    }

    /**
     * The current PUSH-REGISTRATION snapshot (across every contact) — see
     * [allPushableInboxes]. Swift calls this to know WHAT to register on
     * opt-in, AND (same function — this is also the sole DEREGISTRATION
     * source, both the settings opt-out and the pending-dereg sweep) what to
     * DELETE on opt-out, so the register and dereg surfaces can never drift
     * apart on this platform. Also used to capture a snapshot BEFORE a wipe
     * destroys the vault (a wipe's DELETE cleanup needs the refs that
     * existed a moment earlier).
     *
     * Was TEXT-only ([allInboundTextInboxes]); now text AND inbound-
     * CONTROL, because a referral offer/accept and a group invite ride the
     * control channel and must be able to wake a sleeping device too — see
     * the per-kind noPush table in PushRegistration.kt for which control
     * kinds actually fire the relay's wake versus stay silent (still every
     * other kind, so the 2026-07-27 "registered control inbox spuriously
     * fired for pairing/ratchet-repair traffic" evidence does not recur:
     * those kinds default `noPush = true` sender-side).
     */
    fun currentInboundInboxRefs(): List<InboundInboxRef> =
        vault?.let { allPushableInboxes(it) } ?: emptyList()

    /**
     * Bridge for [MessageManager.peekControlPending], which is `internal`
     * (module-scoped) and therefore invisible to the generated Swift header —
     * this wrapper is what lets Swift's push-wake handler
     * (`AppState.handleRemotePushWake`) consult it.
     *
     * Since inbound CONTROL inboxes joined the push-registration surface
     * ([allPushableInboxes]), a contentless relay wake — which names no inbox —
     * may be entirely a control-channel event (a referral offer/accept, a group
     * invite). A wake handler that only peeks TEXT inboxes would silently drop
     * the banner for one of those. Peek-only: NEVER drains — same
     * non-destructive contract as [MessageManager.peekInbox].
     */
    fun peekControlPending(contactId: String): Int? = messageManager?.peekControlPending(contactId)

    /**
     * Bridge for [MessageManager.peekGroupInboxPending], which is `internal`
     * (module-scoped) and therefore invisible to the generated Swift header —
     * mirrors [peekControlPending] exactly, for the same reason: the iOS
     * background wake must peek the third inbox. A group-only
     * push wake (a group text on a contact whose text/control inboxes are both
     * empty) would otherwise produce NO banner. Peek-only: NEVER drains, `null`
     * means UNKNOWN — same non-destructive contract as [peekControlPending] and
     * [MessageManager.peekInbox]. Returns `null` instantly (no network call) for
     * a contact with no `inbound-grp` row, so calling this for every contact on
     * a wake is cheap for the 1:1-only majority.
     */
    fun peekGroupInboxPending(contactId: String): Int? = messageManager?.peekGroupInboxPending(contactId)

    /**
     * True once [MessageManager.forwardSecrecyStalled] reports
     * this contact's consecutive legacy-envelope fallback count has crossed
     * RATCHET_FALLBACK_STALL_THRESHOLD — the responder's ratchet still has no sending
     * chain. Backs the 1:1 conversation notice row (`AppState.refreshForwardSecrecyStalled`);
     * a SIGNAL, never a send gate. `false` whenever there is no [messageManager] yet,
     * mirroring [peekControlPending]'s null-safe shape.
     */
    fun forwardSecrecyStalled(contactId: String): Boolean =
        messageManager?.forwardSecrecyStalled(contactId) ?: false

    /**
     * True once [MessageManager.ratchetRefused] reports the secure
     * channel with this contact has provably failed to establish and sends are being
     * refused. Backs the `ratchet_refused_notice` conversation row, which takes
     * precedence over the `fs_stalled_notice` row above when both would show. `false`
     * whenever there is no [messageManager] yet, mirroring [forwardSecrecyStalled].
     */
    fun ratchetRefused(contactId: String): Boolean =
        messageManager?.ratchetRefused(contactId) ?: false

    /**
     * Inbox ids whose READ capability was just rotated. The rotation evicts
     * the relay's push registration for that inbox (any token — ours, or one an
     * attacker registered while they held the device), so Swift must drop them from
     * its session-scoped `pushRegisteredInboxIds` and let
     * [registerNewPushInboxes] re-register OUR token on the next control-poll
     * cycle. Drains the set (each id is reported once). Parity with Android's
     * `PushRegistrationCoordinator.refreshVendorPushRegistration`.
     */
    fun drainRotatedPushInboxIds(): List<String> =
        try { messageManager?.drainRotatedPushInboxIds()?.toList() ?: emptyList() }
        catch (_: Throwable) { emptyList() }

    /**
     * Best-effort PUT of [deviceTokenHex] onto every ref in [refs] over a
     * fresh SOCKS5-proxied client on [socksPort] (never reuses
     * [messageManager]'s — it may be null or mid-reconnect at the moment
     * APNs delivers the token — mirrors [connectTor]'s client construction).
     * One failed registration does not abort the rest. Returns the inboxIds
     * that actually succeeded, so a caller doing incremental re-sync can
     * fold them into its "already registered" set.
     *
     * `badge = true` (2026-08-20): this is the ONLY apns-registration call
     * site in the app — both [registerPushToken] (initial) and
     * [registerNewPushInboxes] (periodic re-sync) route through it — so
     * every iOS PUT opts into the relay's constant `aps.badge = 1` on
     * contentless wakes. Android never passes it (its badge is the local
     * notification, not a push payload field); see
     * [PushRegistration.register]'s kdoc.
     */
    private fun registerRefs(
        refs: List<InboundInboxRef>,
        deviceTokenHex: String,
        env: String,
        socksPort: Int,
        onRegistered: ((String) -> Unit)? = null,
    ): List<String> {
        // The ONE Kotlin choke point every iOS push
        // registration passes through, so the provenance gate sits here rather
        // than on each caller. Swift's `pushEnabled` — plain NSUserDefaults —
        // used to be the only thing between a planted preference and this
        // device handing the relay a wake address at every launch. A plant now
        // reaches, at most, the local banner path.
        if (provenNotificationLevel() != NotificationLevel.VENDOR_PUSH) {
            platformLogWarn("IosAppController",
                "push registration refused — no authenticated push consent on file")
            return emptyList()
        }
        if (refs.isEmpty()) return emptyList()
        val http = proxiedRelayHttp(socksPort)
        // Several onion addresses (2026-10-24): never send the first PUT into an
        // undecided descriptor race (bounded), and resolve the address PER PUT —
        // PushRegistration.register follows the race winner, so a switch mid-loop
        // moves the remaining PUTs with it. Android sibling:
        // PushRegistrationCoordinator.registerInboxesForCurrentSession.
        PushRegistration.awaitRelayAddressDecided(RelayConfig.BASE_URL)
        // Bounded fan-out (2026-10-24): 32 sequential ~1-2 s Tor PUTs outlasted short
        // sessions. 4 in flight via [boundedParallelBlocking] (each PUT blocks its thread; the
        // SwiftTorHttp request state is per-call and its one shared map is lock-
        // guarded, so parallel requests are safe). [onRegistered] fires per success
        // as it lands (on an IO thread) so Swift merges ids incrementally. Android
        // sibling: PushRegistrationCoordinator.registerInboxesForCurrentSession.
        val registered = boundedParallelBlocking(refs, cap = 4) { ref ->
            val ok = PushRegistration.register(http, RelayConfig.BASE_URL, ref.inboxId, ref.readCap, deviceTokenHex, env, badge = true)
            if (ok) onRegistered?.invoke(ref.inboxId)
            if (ok) ref.inboxId else null
        }.filterNotNull()
        return registered
    }

    /**
     * Registers [deviceTokenHex] as the wake-push target for every pushable
     * inbox (text AND inbound-control) this device currently has (see
     * [currentInboundInboxRefs]). The one-time entry point Swift calls the
     * moment APNs hands it a device token. Returns the count that succeeded,
     * so the caller can decide whether to log/retry.
     */
    fun registerPushToken(
        deviceTokenHex: String,
        env: String,
        socksPort: Int,
        onRegistered: (String) -> Unit,
    ): Int {
        val refs = currentInboundInboxRefs()
        // [onRegistered] per landed PUT (2026-10-26), exactly as
        // [registerNewPushInboxes] reports: Swift folds the ids into its session
        // "seen" set so the first resync does not re-register the same inboxes.
        val ok = registerRefs(refs, deviceTokenHex, env, socksPort, onRegistered).size
        platformLog("IosAppController", "registerPushToken: $ok/${refs.size} inboxes registered")
        return ok
    }

    /**
     * Periodic re-sync counterpart to [registerPushToken]: registers ONLY
     * the current pushable inboxes NOT already in [alreadyRegisteredIds]
     * (Swift's session-scoped "seen" set) — see
     * [inboxesNeedingRegistration]. Meant to be called on the SAME cadence
     * as the background control-poll loop, so a contact paired/referred/
     * re-paired AFTER the one-time [registerPushToken] call still gets
     * covered without Swift needing to hook every cap-mutation call site.
     * Returns the inboxIds that succeeded this call — the caller folds them
     * into its "seen" set; anything that failed is simply retried next
     * cycle (fail-open, same posture as [registerPushToken]).
     * [onRegistered] is called with each inboxId as its PUT lands (from a
     * worker thread), so a pass cut short by a teardown still hands back what
     * it got; the returned list is the same set, for the log line.
     */
    fun registerNewPushInboxes(
        deviceTokenHex: String,
        env: String,
        socksPort: Int,
        alreadyRegisteredIds: List<String>,
        onRegistered: (String) -> Unit,
    ): List<String> {
        val newRefs = inboxesNeedingRegistration(currentInboundInboxRefs(), alreadyRegisteredIds.toSet())
        if (newRefs.isEmpty()) return emptyList()
        val registered = registerRefs(newRefs, deviceTokenHex, env, socksPort, onRegistered)
        if (registered.isNotEmpty()) {
            platformLog("IosAppController", "registerNewPushInboxes: ${registered.size}/${newRefs.size} new inboxes registered")
        }
        return registered
    }

    /**
     * Opt-out / vault-wipe cleanup: best-effort DELETE for every ref in
     * [refs] (a caller-supplied snapshot — see [currentInboundInboxRefs] —
     * so this works even after [vault] has already gone null). Returns the
     * count that succeeded. Delegates to
     * [unregisterPushInboxesReturningFailures] so the per-ref DELETE
     * semantics exist exactly once.
     */
    fun unregisterPushTokenForInboxes(refs: List<InboundInboxRef>, socksPort: Int): Int {
        if (refs.isEmpty()) return 0
        // The "unregisterPushToken: N/M inboxes cleared" diagnostic is emitted
        // by the delegate below (once per pass), so it keeps appearing for
        // BOTH callers — this one-shot wipe leg and the retrying opt-out.
        return refs.size - unregisterPushInboxesReturningFailures(refs, socksPort).size
    }

    /**
     * Single best-effort DELETE pass over [refs] that reports WHICH refs
     * failed (2026-08-11 opt-out fix), so Swift's Settings-opt-out retry loop
     * and the pending-dereg sweep (AppState.unregisterCurrentInboxesBestEffort
     * / sweepPendingPushDeregistrationIfNeeded) can retry exactly the failed
     * ones instead of swallowing the result. Same wire call as
     * [unregisterPushTokenForInboxes] — which delegates here — and safe to
     * repeat: the relay answers 200 even when no push row exists
     * (docs/RELAY_SPEC.md (push)). Fresh SOCKS5-proxied client per call, mirroring
     * [registerRefs]'s never-reuse-messageManager's-client reasoning. The
     * shared pass itself lives in commonMain
     * ([PushRegistration.unregisterAllReturningFailures]) so Android and iOS
     * cannot drift on per-ref semantics.
     */
    fun unregisterPushInboxesReturningFailures(refs: List<InboundInboxRef>, socksPort: Int): List<InboundInboxRef> {
        if (refs.isEmpty()) return emptyList()
        val http = proxiedRelayHttp(socksPort)
        // FAIL-FAST (2026-10-25, Android parity): each DELETE on its own 25 s
        // budget, in parallel, the caller's cancellation never observed. Blocks
        // this (detached-Task) thread for one pass.
        val failed = PushRegistration.unregisterAllParallelReturningFailuresBlocking(http, RelayConfig.BASE_URL, refs)
        // Legacy diagnostic wording kept alive (e2e helpers may still read it
        // from push_debug_log against pre-deploy binaries — widen, never
        // narrow); Swift additionally appends the cross-platform
        // "push dereg: N/M inboxes cleared" line. Counts only, never an id/cap.
        platformLog("IosAppController", "unregisterPushToken: ${refs.size - failed.size}/${refs.size} inboxes cleared")
        return failed
    }

    // -----------------------------------------------------------------------
    // Pre-unlock rendezvous warm-up (RelayWarmup.kt, commonMain) — lever 1
    // -----------------------------------------------------------------------

    /**
     * Swift-facing, coroutine-free, fire-and-forget entry point for the ONE
     * pre-unlock rendezvous warm-up. Every rule that makes it safe lives in
     * [RelayWarmup]: no capability, no auth header, no custom header, no body,
     * NEVER a [MessageManager] (so it cannot touch a vault, counter, ratchet or
     * inbox), at most two attempts on a [RelayWarmup.HTTP_TIMEOUT_SECONDS]
     * budget each, nothing persisted, and it does NOT
     * latch the round-trip flag — the contact list stays hidden until the
     * SESSION's own transport answers. Swift decides WHEN (Tor reported
     * Connected while the vault is still locked) and enforces
     * once-per-Tor-instance; this only decides HOW, identically to Android.
     *
     * [socksPort] is passed IN rather than read from [lastSocksPort]: this runs
     * BEFORE any unlock, so nothing has wired a transport yet and that field is
     * still 0. A non-positive port, a relay that needs no Tor, or an unconfigured
     * relay all mean "nothing to warm".
     *
     * [retriesUsed] and [onRotateDue] are the warm-up rotation ladder (2026-09-15). When an
     * attempt FAILS having burned (almost) its whole budget — the signature of a
     * wedged introduction point, and the one failure a `SIGNAL NEWNYM` fixes —
     * and a retry is still allowed, [onRotateDue] is invoked so Swift can fire
     * that NEWNYM out of [earlyNewnymLedger] (the SAME per-session
     * budget the post-unlock cold rung spends) and call back in with
     * `retriesUsed = 1` for the one permitted second attempt. The DECISION is
     * [RelayWarmup.shouldRotateAndRetry], i.e. the identical shared predicate
     * Android's `RunViewModel.armPreUnlockRelayWarmup` evaluates; Swift owns only
     * the budget and the control channel (`TorManager` is main-actor isolated
     * there, which is why this is a callback rather than a Kotlin-side loop).
     *
     * [onRotateDue] arrives on a BACKGROUND thread (like [primeUnreadCounts]'s
     * callbacks) and is invoked at most once per call. It is never called for an
     * answered warm-up, for a fast failure, or when [retriesUsed] has reached
     * [RelayWarmup.MAX_RETRIES].
     *
     * Rides [sessionWorkScope], so [lock] / [emergencyWipe] cancel an in-flight warm-up
     * along with the rest of this controller's background work. Never throws
     * across the Swift bridge (an uncaught Kotlin exception reaching Swift is a
     * SIGABRT).
     */
    fun warmRelayRendezvous(socksPort: Int, retriesUsed: Int = 0, onRotateDue: (() -> Unit)? = null) {
        if (socksPort <= 0) return
        // The SOCKS client is the only transport this may use — the direct
        // Foundation URL-loading branch cannot reach an .onion (local DNS), and a clearnet
        // relay has nothing to warm: no descriptor, no rendezvous.
        if (!relayRoutesViaTor()) return
        sessionWorkScope.launch {
            try {
                val attempt = RelayWarmup.warmAttempt(
                    http = proxiedRelayHttp(socksPort),
                    relayBaseUrl = RelayConfig.BASE_URL,
                )
                if (onRotateDue != null &&
                    RelayWarmup.shouldRotateAndRetry(attempt.answered, attempt.elapsedMs, retriesUsed)
                ) {
                    onRotateDue()
                }
            } catch (e: Throwable) {
                // Includes the CancellationException from lock()/emergencyWipe().
                // A failed warm-up is a normal outcome — the post-unlock probe is
                // the real signal and is untouched by this path. A throw from the
                // Swift callback lands here too, and is equally non-fatal.
                platformLogWarn("IosAppController", "rendezvous warm-up ended early: ${e::class.simpleName}")
            }
        }
    }

    // -----------------------------------------------------------------------
    // Anonymous connect-time report (ConnectTelemetry.kt, commonMain)
    // -----------------------------------------------------------------------

    /**
     * The relay transport CURRENT to this session, built exactly the way
     * [registerRefs] / [unregisterPushInboxesReturningFailures] build theirs
     * (never reusing [messageManager]'s private client, which may be null or
     * mid-reconnect). Null means "no live transport right now", which the
     * caller treats as "drop the report" — there is no retry.
     *
     * The direct branch is DEBUG-only, mirroring Android's
     * `RunViewModel.currentRelayHttpForPush`: a release build with a non-onion
     * relay refuses to route traffic at all (`AppState.startTorOrDirect`), so it
     * must not get a transport here either.
     */
    private fun currentRelayHttpForTelemetry(): RelayHttp? = when {
        RelayConfig.BASE_URL.isEmpty() -> null
        RelayConfig.isTorRequired -> lastSocksPort.takeIf { it > 0 }?.let(::proxiedRelayHttp)
        isDebugBuild -> PlatformHttpClient().asRelayHttp()
        else -> null
    }

    /**
     * Swift-facing, coroutine-free entry point for the one anonymous
     * connect-time report per session (since 2026-09-11). [elapsedMs]
     * is the monotonic time from this session's `startTorOrDirect()` to the
     * first relay answer, measured Swift-side with `ProcessInfo.systemUptime`.
     *
     * [torElapsedMs] is the PHASE SPLIT: milliseconds from that same anchor to
     * the moment Tor reported Connected, so the relay can derive the
     * rendezvous+relay phase as the difference without a second clock. `0` when
     * Tor was already connected at the anchor — the COMMON case since Tor
     * started speculatively at launch (`AppState.startSpeculativeTor`) — and
     * `null` when unknown, which on iOS means the DEBUG/simulator direct branch
     * where no Tor ever connected. [ConnectTelemetry] buckets it to 5 s and caps
     * it at the total, so it can never widen the report beyond one extra coarse
     * number.
     *
     * [bootElapsedMs] is the `boot` field (2026-09-11): milliseconds from this
     * session's Tor PROCESS start — `TorManager.shared.startedAtUptime`, set
     * once per iOS process since `tor_main` can run at most once per process
     * (see that property's kdoc) — to the same first-Connected moment as
     * [torElapsedMs], measured Swift-side off a DIFFERENT anchor than
     * [elapsedMs]. `null` when Tor never started this process or never
     * connected. Unlike [torElapsedMs], [ConnectTelemetry] never caps it
     * against the total — the two share no anchor, so `boot` can legitimately
     * exceed [elapsedMs] (a bootstrap that ran mostly before unlock).
     *
     * Everything that makes this safe lives in [ConnectTelemetry]: no
     * capability, no auth header, no identifier, 5-second buckets, a 2-8 s
     * jitter, one attempt, 20 s budget, nothing persisted. Swift decides WHEN
     * (first `isRelayReachable` true) and enforces once-per-session; this only
     * decides HOW.
     *
     * Runs on [sessionWorkScope], so the children the session teardown already cancels
     * ([lock] / [emergencyWipe]) take an in-flight report with them — a lock
     * during the jitter window silently drops it. Never throws across the Swift
     * bridge. Android sibling: `ConnectTelemetryRecorder.armConnectTelemetry`.
     *
     * DEBUG MODE ONLY (2026-11-03): AppState calls this only while its
     * `debugMode` is on, and [ConnectTelemetry.send] re-reads the persisted
     * consent ([isDebugModeEnabled]) before and after its jitter as the
     * Kotlin-side belt — a consent revoked mid-window drops the report. The
     * Keychain read fails toward OFF (see [DebugMode.isEnabled]).
     */
    fun reportConnectTime(elapsedMs: Long, torElapsedMs: Long?, bootElapsedMs: Long? = null) {
        // External SOCKS proxy mode: no connect-time report (AppState skips the
        // call too — this is the Kotlin-side belt).
        if (externalProxyMode) return
        sessionWorkScope.launch {
            try {
                // Built INSIDE the coroutine: Swift calls this from the main
                // actor, and the direct/simulator branch allocates a URL
                // session. Null (no live transport) simply drops the report —
                // there is no retry and nothing to report.
                ConnectTelemetry.send(
                    http = currentRelayHttpForTelemetry(),
                    relayBaseUrl = RelayConfig.BASE_URL,
                    platform = ConnectTelemetry.PLATFORM_IOS,
                    appVersion = localAppVersionFromBundle(),
                    elapsedMs = elapsedMs,
                    debugModeEnabled = { isDebugModeEnabled() },
                    torElapsedMs = torElapsedMs,
                    bootElapsedMs = bootElapsedMs,
                )
            } catch (e: Throwable) {
                // Includes the CancellationException from lock()/emergencyWipe().
                // Never surfaced: a dropped report is a normal outcome.
                platformLogWarn("IosAppController", "connect-time report ended early: ${e::class.simpleName}")
            }
        }
    }

    // -----------------------------------------------------------------------
    // "Move to new device" (docs/device-move.md)
    //
    // Two things live here: the iOS half of the [MoveSessionControl] seam, and a
    // COROUTINE-FREE Swift surface over [MoveManagerApi] (callback shape, same
    // reasoning as [primeUnreadCounts] — no StateFlow, no suspend function and no
    // Kotlin sealed class crosses into Swift). Android's sibling is RunViewModel's
    // MoveManager wiring; keep the two behaviourally identical.
    // -----------------------------------------------------------------------

    /**
     * SOCKS port of the live Tor session, remembered by [connectTor] so the move's
     * best-effort push unregistration can build its own proxied client exactly the
     * way [registerRefs] / [unregisterPushInboxesReturningFailures] do (never
     * reusing [messageManager]'s). 0 whenever there is no proxied transport
     * (direct/dev HTTP, or nothing connected yet) — the unregistration is then
     * skipped, the same `port > 0` gate every other push path uses.
     */
    private var lastSocksPort: Int = 0

    /**
     * EXTERNAL SOCKS PROXY MODE latch, set by AppState's external-proxy
     * resolution (the `.external` / `.invalid` branches, AppState.swift
     * `controller.externalProxyMode = true`), whose source of truth is
     * `ExternalProxyMode.shared` (iosApp ExternalProxyMode.swift), when the
     * embedded Tor is NOT this process's transport. One-way: never cleared in-process (the mode
     * applies per launch) — the Kotlin-side belt. Gates [reportConnectTime] (no
     * telemetry), [connectDirect] (no direct HTTP fallback) and SOCKS isolation on
     * every proxied relay client ([connectTor], [proxiedRelayHttp]). The transport
     * target itself is enforced in SwiftTorHttp.
     */
    var externalProxyMode: Boolean = false
        set(value) { if (value) field = true }

    /**
     * Every relay client this controller builds on a SOCKS port, apart from
     * [connectTor]'s MessageManager transport (which spells the same flag inline).
     * SOCKS isolation (RendezvousHedge) only through the EMBEDDED Tor: in
     * external-proxy mode the user's proxy gets the plain no-auth handshake.
     * SwiftTorHttp also ignores any credential in that mode; this is the
     * Kotlin-side belt (see [externalProxyMode]).
     */
    private fun proxiedRelayHttp(socksPort: Int): RelayHttp =
        PlatformHttpClient(socksPort, socksIsolationCapable = !externalProxyMode).asRelayHttp()

    /**
     * Swift hooks for [MoveSessionControl.quiesce] / [resume] — AppState sets both
     * in its `init`. Invoked from a BACKGROUND coroutine, so the Swift side hops to
     * the main actor itself (same contract as [onVaultSessionRetired]).
     *
     * quiesce = cancel the CONTACT-FACING loops (control poll + unread prime).
     * NOT the relay-reachability loop and NOT Tor: the frozen phone still has to
     * `peek` its own transfer inbox every 10 s to notice the new phone draining it,
     * and to prove "undrained" for a cancel.
     */
    var onMoveQuiesce: (() -> Unit)? = null
    var onMoveResume: (() -> Unit)? = null

    /**
     * The platform seam MoveManager runs on.
     *
     * Deliberate reading of "[quiesce] must … drop the MessageManager": on iOS the
     * manager reference is KEPT and the contact-facing USE of it is what stops. Two
     * reasons, both load-bearing:
     *  - the durable half of the gate is already in commonMain —
     *    `createSessionManagers` wraps the transport provider in [isMoveFrozen], so
     *    GroupManager/ReferralManager (every poll, every send, the control sweep) go
     *    inert the instant `mig_frozen` lands, whatever the platform does, and that
     *    survives a relaunch;
     *  - `refreshTransferState` / `cancelExport` call `session.transport()` AFTER the
     *    quiesce. Nulling the manager here would make the Ready → Moved detection
     *    impossible and turn every cancel into "no transport to prove the bundle is
     *    undrained" — i.e. a phone that can only ever be wiped.
     * The transfer inbox belongs to no contact and touches no ratchet, so keeping the
     * client alive for it cannot advance a chain (see [MoveManager]'s takeTransport
     * kdoc, which explicitly allows this reading).
     */
    private inner class IosMoveSessionControl : MoveSessionControl {

        /**
         * The EXISTING opt-out/wipe unregistration path over [allPushableInboxes]
         * (via [currentInboundInboxRefs]), so the move cannot drift from it.
         *
         * Per-ref rather than one batch call purely so the caller's 30 s
         * `withTimeoutOrNull` has suspension points to cut at: the underlying DELETE
         * is blocking, and a slow Tor circuit times out per request, so a batch over
         * a dozen contacts could sit far past the documented budget with the export
         * stuck on "Preparing". Failures are ignored by contract — an un-evicted
         * token is closed by the new phone's read-cap rotation and by the wipe.
         */
        override suspend fun unregisterPushBestEffort() {
            val refs = currentInboundInboxRefs()
            val port = lastSocksPort
            if (refs.isEmpty() || port <= 0) {
                platformLog("Move", "push unregistration skipped (refs=${refs.size}, transport=${port > 0})")
                return
            }
            withContext(ioDispatcher) {
                val http = proxiedRelayHttp(port)
                // One bounded race wait for the whole pass (not one per ref).
                PushRegistration.awaitRelayAddressDecided(RelayConfig.BASE_URL)
                var failed = 0
                for (ref in refs) {
                    ensureActive()
                    failed += try {
                        PushRegistration.unregisterAllReturningFailures(
                            http, RelayConfig.BASE_URL, listOf(ref), raceWaitMaxMs = 0,
                        ).size
                    } catch (e: Throwable) {
                        platformLogWarn("Move", "push unregistration failed for one inbox: ${e::class.simpleName}")
                        1
                    }
                }
                // Counts only, never an id or a capability — same wording discipline
                // as the opt-out ladder's diagnostic.
                platformLog("Move", "push dereg: ${refs.size - failed}/${refs.size} inboxes cleared")
            }
        }

        override suspend fun quiesce() {
            platformLog("Move", "quiesce — stopping the contact-facing session (Tor stays up)")
            // The unread prime holds read capabilities snapshotted from the open
            // vault and would keep hitting the relay; same cancellation lock() does.
            sessionWorkScope.coroutineContext.cancelChildren()
            try { onMoveQuiesce?.invoke() } catch (e: Throwable) {
                platformLogWarn("Move", "quiesce hook threw: ${e::class.simpleName}")
            }
        }

        override suspend fun resume() {
            platformLog("Move", "resume — restarting the contact-facing session")
            try { onMoveResume?.invoke() } catch (e: Throwable) {
                platformLogWarn("Move", "resume hook threw: ${e::class.simpleName}")
            }
        }

        /** Null unless the vault is unlocked AND a transport exists (Tor up / dev-direct). */
        override fun transport(): MoveTransport? {
            if (vault == null) return null
            return messageManager?.let { RelayMoveTransport(it) }
        }
    }

    /**
     * Declared LATE on purpose: [MoveManager]'s init calls `refreshFrozenState()`,
     * which reads the `vault` property through the lambda below — that property must
     * already be initialised (it is, being declared far above).
     */
    val moveManager: MoveManager = MoveManager(
        vault = { vault },
        session = IosMoveSessionControl(),
        platformTag = MigrationBundle.FROM_IOS,
        exportAuthGate = MoveExportAuthGate(),
    )

    /**
     * Scope for the move's long operations. [SupervisorJob] so one failed export
     * cannot kill the scope for the retry; children are cancelled by [lock] and
     * [emergencyWipe] like [sessionWorkScope]'s.
     */
    private val moveScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    /**
     * Runs [body] on [moveScope] and calls [onDone] exactly once, on a BACKGROUND
     * thread, on every path (success, failure, cancellation). Nothing throws across
     * the bridge — an uncaught Kotlin exception reaching Swift is a SIGABRT.
     */
    private fun moveOp(what: String, body: suspend () -> Unit, onDone: () -> Unit) {
        moveScope.launch {
            try {
                body()
            } catch (e: Throwable) {
                platformLogWarn("Move", "$what ended early: ${e::class.simpleName}")
            } finally {
                try { onDone() } catch (e: Throwable) {
                    platformLogWarn("Move", "$what onDone threw: ${e::class.simpleName}")
                }
            }
        }
    }

    /**
     * Bounded, CANCELLABLE wait for a live transport, on [moveScope].
     *
     * This wait used to live in an unowned Swift
     * `Task` inside `MoveImportView.startImport()`, which meant it — and the
     * transfer handle it had captured (read capability + one-time code) — outlived
     * a lock by up to the whole budget, because the only loop condition was
     * `messageManager == nil`, and a lock is precisely what makes that nil. Here
     * the wait is a child of [moveScope], which both [lock] and [emergencyWipe]
     * cancel, so a locked or wiped session cuts it at the next [delay]. Android
     * sibling: `RunViewModel.awaitMoveTransport` inside `moveOpJob`.
     *
     * Iteration-counted rather than clock-based on purpose: no monotonic clock is
     * needed, and a wall-clock step (NTP, timezone) cannot shorten or extend it.
     * The budget stays at the iOS value it has always had — a cold Tor bootstrap
     * on a real iPhone has been measured well past Android's 150 s (the vault is
     * freshly provisioned when this runs, so the unlock landed before Tor did),
     * and this change is about the handle's LIFETIME, not about the budget.
     * Returning empty-handed is not an error: `importFromHandle` answers
     * `RELAY_UNREACHABLE` on a null transport, which the UI offers a retry for.
     */
    private suspend fun awaitMoveTransport() {
        var waitedMs = 0L
        while (waitedMs < MOVE_IMPORT_TRANSPORT_WAIT_MS) {
            if (vault != null && messageManager != null) return
            delay(MOVE_TRANSPORT_POLL_MS)
            waitedMs += MOVE_TRANSPORT_POLL_MS
        }
    }

    /**
     * Fresh-credential gate in front of the export (2026-10-21). Blocking and
     * heavy (KDF + the Lever B Secure-Enclave prompt) — call from a BACKGROUND
     * queue. Mirrors the change-PIN gate ([ChangePinAttemptStore] budget, recorded
     * before the check). Returns a [MoveExportAuth.Outcome] name lowercased
     * ("ok" / "wrong" / "wipe" / "deferred"); on "ok" the single-use token
     * [moveBeginExport] consumes is granted. "wipe" = the caller runs the
     * emergency wipe. Never throws across the bridge.
     */
    fun moveVerifyExportAuth(credential: String): String = try {
        MoveExportAuth.verifyAndGrant(
            credential, vaultSelector, changePinAttempts, moveManager.exportAuthGate,
        ).name.lowercase()
    } catch (e: Throwable) {
        platformLogWarn("Move", "export auth ended early: ${e::class.simpleName}")
        "deferred"
    }

    /** Old phone, step 2 of the protocol. [onDone] fires when the state settles. */
    fun moveBeginExport(onDone: () -> Unit) =
        moveOp("beginExport", { moveManager.beginExport() }, onDone)

    /** Old phone, frozen: fresh bundle under a fresh code ("Show again"). */
    fun moveReissueExport(onDone: () -> Unit) =
        moveOp("reissueExport", { moveManager.reissueExport() }, onDone)

    /** Old phone: one `peek` of the transfer inbox (the 10 s waiting poll). */
    fun moveRefreshTransferState(onDone: () -> Unit) =
        moveOp("refreshTransferState", { moveManager.refreshTransferState() }, onDone)

    /**
     * Old phone: cancel + unfreeze. [onDone] reports the manager's Boolean —
     * `false` means REFUSED (the bundle is already drained, or it could not be
     * proven undrained), never "an error happened".
     */
    fun moveCancelExport(onDone: (Boolean) -> Unit) {
        moveScope.launch {
            val ok = try {
                moveManager.cancelExport()
            } catch (e: Throwable) {
                platformLogWarn("Move", "cancelExport ended early: ${e::class.simpleName}")
                false
            }
            try { onDone(ok) } catch (e: Throwable) {
                platformLogWarn("Move", "cancelExport onDone threw: ${e::class.simpleName}")
            }
        }
    }

    /**
     * New phone: drain → import → secure, on the freshly provisioned + unlocked
     * vault. [onProgress] receives [MoveImportStep] as a lowercase string
     * ("fetching"/"importing"/"securing"); [onDone] receives `(ok, errorName)`
     * where `errorName` is a [MoveError] name (or "" on success). Both fire on a
     * BACKGROUND thread — hop to main before touching SwiftUI state.
     */
    fun moveImportFromHandle(
        handle: MoveHandle,
        onProgress: (String) -> Unit,
        onDone: (Boolean, String) -> Unit,
    ) {
        moveScope.launch {
            val result = try {
                awaitMoveTransport()
                moveManager.importFromHandle(handle) { step ->
                    try { onProgress(step.name.lowercase()) } catch (e: Throwable) {
                        platformLogWarn("Move", "import onProgress threw: ${e::class.simpleName}")
                    }
                }
            } catch (e: kotlin.coroutines.cancellation.CancellationException) {
                // A lock/wipe cancelled the run before the import committed
                // (MoveManager never rethrows after its commit): nothing changed on
                // this phone, so report what a cancelled drain always reported —
                // the retryable RELAY_UNREACHABLE, not IMPORT_FAILED. Not rethrown:
                // Swift only ever sees onDone (Android rethrows inside its job).
                platformLogWarn("Move", "import cancelled (lock/wipe)")
                MoveImportResult.Failure(MoveError.RELAY_UNREACHABLE)
            } catch (e: Throwable) {
                platformLogWarn("Move", "import ended early: ${e::class.simpleName}")
                MoveImportResult.Failure(MoveError.IMPORT_FAILED)
            }
            val ok = result is MoveImportResult.Success
            val error = (result as? MoveImportResult.Failure)?.error?.name ?: ""
            try { onDone(ok, error) } catch (e: Throwable) {
                platformLogWarn("Move", "import onDone threw: ${e::class.simpleName}")
            }
        }
    }

    // --- Swift-readable projection of MoveExportState (no sealed class crosses) ---

    /** "idle" | "preparing" | "ready" | "moved" | "frozen_no_code" | "failed". */
    fun moveExportStateKind(): String = when (moveManager.exportStateNow()) {
        is MoveExportState.Idle -> "idle"
        is MoveExportState.Preparing -> "preparing"
        is MoveExportState.Ready -> "ready"
        is MoveExportState.Moved -> "moved"
        is MoveExportState.FrozenNoCode -> "frozen_no_code"
        is MoveExportState.Failed -> "failed"
    }

    /** "unregister_push" | "freeze" | "mint" | "upload"; "" outside `Preparing`. */
    fun moveExportStep(): String =
        (moveManager.exportStateNow() as? MoveExportState.Preparing)?.step?.name?.lowercase() ?: ""

    /**
     * The QR / "Show as text" payload for the `Ready` handle, "" otherwise. This
     * string CONTAINS the one-time code — never log it, never persist it, and drop
     * it from view state on `.background` (the manager's own [MoveManager.scrubInMemory]
     * does the Kotlin half).
     */
    fun moveExportHandleText(): String =
        (moveManager.exportStateNow() as? MoveExportState.Ready)
            ?.let { MoveHandleCodec.toQrText(it.handle) } ?: ""

    /** Chunk count of the `Ready` bundle, 0 otherwise (diagnostics only). */
    fun moveExportChunkCount(): Int =
        (moveManager.exportStateNow() as? MoveExportState.Ready)?.chunkCount ?: 0

    /** [MoveError] name while `Failed`, "" otherwise. */
    fun moveExportErrorName(): String =
        (moveManager.exportStateNow() as? MoveExportState.Failed)?.error?.name ?: ""

    /** Whether the current `Failed` state is worth a retry (false outside `Failed`). */
    fun moveExportRetryable(): Boolean =
        (moveManager.exportStateNow() as? MoveExportState.Failed)?.retryable ?: false

    /** True when THIS vault carries `mig_frozen` — the unlock-time routing probe. */
    fun moveIsFrozen(): Boolean = try {
        moveManager.isFrozen()
    } catch (e: Throwable) {
        // Fails toward FROZEN for the same reason isMoveFrozen does: a false
        // "not frozen" resumes a phone whose identity may already live elsewhere.
        platformLogWarn("Move", "frozen probe failed — treating as frozen: ${e::class.simpleName}")
        true
    }

    /**
     * Re-reads `mig_frozen` into the manager's state. The Kotlin side already
     * refreshes it on every vault open (unlock AND recovery — see
     * [adoptOpenedVault]). Swift calls it from AppState.refreshMoveFrozen: on
     * every open (redundant with [adoptOpenedVault], harmless) and from
     * MoveToNewDeviceView.closeScreen mid-session (an Idle-but-frozen vault after
     * a half-run export; keep it).
     */
    fun moveRefreshFrozenState() = moveManager.refreshFrozenState()

    /** Drops the RAM-only one-time code (lock / `.background` teardown). */
    fun moveScrubExportCode() = moveManager.scrubInMemory()

    // -----------------------------------------------------------------------
    // Lock — clears session state without wiping vault data.
    // -----------------------------------------------------------------------

    /**
     * Kotlin half of the lock: cancels the session/move scopes, scrubs the move
     * code, fences the MessageManager's acks, closes the vault, scrubs manager RAM
     * (again) and ends the parked-send session
     * ([endSessionRam]), wipes the device key. The Swift half (`AppState.lock`)
     * stops pollers, flushes debug logs, stops Tor and clears the RAM logs.
     * Called on the main actor, after AppState cancelled its pollers.
     */
    fun lock() {
        platformLog("App", "locking vault — wiping key material from memory")
        // Stop the connect-time unread prime before the session is torn down: its
        // workers hold inbox READ CAPABILITIES snapshotted while the vault was open,
        // and a still-running pass would keep issuing relay requests (and calling
        // back into a locked UI) after this returns. Cancellation cannot interrupt a
        // blocking HTTP call already in flight, but the next suspension point — the
        // emission mutex — is reached before any callback, so nothing is emitted
        // after this line. Children only: the scope stays usable for the next unlock.
        sessionWorkScope.coroutineContext.cancelChildren()
        // Same reasoning for the move's own scope: an export/import in flight holds
        // the transfer inbox's capabilities and would keep talking to the relay
        // after the session is gone. Children only — the scope survives for the
        // next unlock (which is where a frozen phone resumes the flow).
        moveScope.coroutineContext.cancelChildren()
        // Drop the RAM-only one-time move code with the rest of the session's key
        // material (collapses Ready → FrozenNoCode; the vault stays frozen and the
        // user re-issues on the next unlock).
        moveManager.scrubInMemory()
        // Close the SQLCipher connection so its derived page key leaves the
        // process RAM while locked — parity with Android RunViewModel.onCleared
        // (Lever C: a locked-but-alive process should
        // hold no vault key material). AppState.lock() cancels the pollers
        // before calling this, and IosVaultDatabase.close() is lock-serialized.
        //
        // ACK FENCE before the close: a closed iOS vault reads as "no rows", which a drain
        // finishing right now would take for "contact deleted" and ACK (relay DELETE = lost
        // mail). scrubInMemory() closes the acks first; endSessionRam() below scrubs again
        // AFTER the close, so nothing an in-flight reader refills in between survives.
        messageManager?.scrubInMemory()
        try { vault?.close() } catch (_: Exception) { /* best-effort */ }
        vault = null
        endSessionRam()
        crypto.wipeKey()
        platformLog("App", "vault locked, crypto key wiped")
    }

    /**
     * Reloads the CryptoProvider key from Keychain if it was wiped on lock.
     * Called by the lock screen before any decrypt operation that runs
     * outside the unlock() path — e.g. PinAttemptsStore.read() in
     * PinEntryView.onAppear, which fires after the app returns from
     * background and the key has been wiped, but before the user has
     * actually entered their PIN. Without this hook, the PinEntryView's
     * generic exception catch would treat the wiped-key IllegalStateException
     * as AEAD tampering and trigger an unwanted emergencyWipe.
     */
    fun reloadCryptoIfWiped() {
        if (!crypto.isWiped()) return
        try {
            crypto.reloadKey()
        } catch (_: KeyUnavailableException) {
            // reloadKey() -> getOrCreateKey() throws KeyUnavailableException when
            // the device key is transiently unresolvable (locked keybag /
            // errSecAuthFailed). This function is NOT @Throws, so letting the
            // Kotlin exception cross into Swift would terminate the process
            // (SIGABRT). Swallow and defer: the caller's
            // subsequent decrypt (PinAttemptsStore.read) re-hits the same
            // unavailability and surfaces it as the catchable
            // KeyUnavailableException, which the caller defers on rather than wiping.
            platformLogWarn("App", "reloadCryptoIfWiped deferred — device key unavailable")
        }
    }

    // -----------------------------------------------------------------------
    // Emergency wipe — destroys all vault data and resets credentials.
    // -----------------------------------------------------------------------

    // Kotlin half of a wipe: crypto-erase first, KV + defaults sweep, table wipe,
    // DB files, Tor dir, RAM logs, key + vault close, scopes, move code, session
    // RAM ([endSessionRam]). Callers: AppState.emergencyWipe (after it erased the
    // keys and stopped Tor) and the launch-time wipes (which call only this).
    fun emergencyWipe() {
        platformLogWarn("App", "emergency wipe triggered")

        // Erase-first (mirrors Android WipeRoutine): destroy the
        // Keychain device key BEFORE anything else. It is instantaneous and
        // irreversible, so even if the process dies mid-wipe every
        // CryptoProvider-encrypted blob — credential hashes, the PIN-wrapped
        // SQLCipher keys, counters — is already undecryptable. The in-memory
        // SQLCipher handle stays valid for the best-effort table wipe further
        // down (corrected 2026-07-30: it must run BEFORE the DB file is
        // unlinked — see that call site for why).
        // AppState.emergencyWipe already ran both deleteKey()s before calling this
        // (idempotent); they are repeated here for the launch-time wipes that call
        // ONLY this method.
        KeychainBridgeHolder.bridge?.deleteKey()
        // Lever B: also destroy the Secure-Enclave auth-bound key so no key
        // survives that could unwrap a leftover auth-bound DB-key blob.
        SecureEnclaveBridgeHolder.bridge?.deleteKey()

        // Delete all sensitive UserDefaults entries. IosUserDefaultsKeys.all
        // includes the wrapped DB-key blob (and any leftover decoy blobs from
        // pre-removal installs), which previously survived a panic wipe.
        // The vault verifier / wrapped DB key / wrong-PIN counters now live in
        // the Keychain (KeyValueStore → KeychainBridge); kvDeleteAll() clears
        // them there, and the UserDefaults sweep still removes any legacy copies
        // not yet migrated plus the non-KV keys (inactivity ts, legacy device key).
        KeychainBridgeHolder.bridge?.kvDeleteAll()
        val defaults = platform.Foundation.NSUserDefaults.standardUserDefaults
        IosUserDefaultsKeys.all.forEach { defaults.removeObjectForKey(it) }
        defaults.synchronize()
        // REMOVE (never write) any retired
        // clean-leave row. kvDeleteAll() above already swept them; this keeps the
        // removal explicit and leaves no breadcrumb row after the sweep.
        removeRetiredCleanLeaveKeys()

        // Row-level table
        // wipe — hygiene on top of the crypto-erase above, never a gate on it.
        // wipeAllTables() runs DELETEs inside withTransaction, which RETHROWS
        // after rollback on any failure; execChecked throws a plain
        // RuntimeException("vault write failed") whenever the Swift
        // SwiftDatabaseBridge returns false. This method is not @Throws, so an
        // uncaught throw here would cross into Swift and terminate the process.
        // Two properties are both required and neither alone is enough:
        //   (1) it MUST run here, before run.db and its -wal/-shm/-journal are
        //       unlinked below — once close() drops the last fd on an unlinked
        //       inode its blocks are freed immediately, so DELETEs issued after
        //       the unlink execute against nothing and the row-level hygiene
        //       this exists for silently does not happen (the earlier "run it
        //       after the deletions" version was a no-op with a comment that
        //       claimed otherwise);
        //   (2) it MUST stay wrapped in try/catch — a throw from execChecked
        //       must never be able to gate or abort the deletions that follow.
        // By the time this runs the device key is already erased (deleteKey()
        // above), so even a failed/partial table wipe leaves nothing but
        // undecryptable ciphertext on disk — the DB file deletion and
        // close()+wipeKey() further down still finish the job regardless.
        try { vault?.wipeAllTables() } catch (_: Exception) { /* best-effort — see above */ }

        // Delete encrypted database files from disk (Application Support + legacy Caches)
        val fm = platform.Foundation.NSFileManager.defaultManager
        for (dir in listOf(platform.Foundation.NSApplicationSupportDirectory, platform.Foundation.NSCachesDirectory)) {
            val path = platform.Foundation.NSSearchPathForDirectoriesInDomains(
                dir, platform.Foundation.NSUserDomainMask, true
            ).firstOrNull() as? String ?: continue
            for (name in VAULT_DB_FILE_NAMES) {
                fm.removeItemAtPath("$path/$name", null)
                for (suffix in SQLITE_SIDECAR_SUFFIXES) {
                    fm.removeItemAtPath("$path/$name$suffix", null)
                }
            }
        }

        // Delete Tor data directory
        deleteTorData()

        // Clear the in-memory log buffer so a RAM capture after a
        // panic wipe can't recover buffered id prefixes / lengths / events.
        LogBuffer.clear()
        // Same reasoning, and NOT debug-gated: the connection-log panel's ring
        // buffer is live in RELEASE builds too (ConnectionLog.kt). No marker line
        // is appended here — a wipe leaves nothing, deniably. Android sibling:
        // WipeRoutine.kt.
        ConnectionLog.clear()
        // Swift clears the same ring again as AppState.emergencyWipe's LAST step
        // (after Tor's stop lines); both are needed, see there.

        // Zero the in-memory device key too — deleteKey() above erases the
        // persisted Keychain copy, but the live 32-byte AES key would otherwise
        // linger in CryptoProvider until process exit (RAM-capture residue).
        crypto.wipeKey()

        // Close the SQLCipher connection so its derived page key leaves process
        // RAM — parity with lock() and Android RunViewModel.onCleared. Load-
        // bearing on the panic path specifically: emergencyWipe() runs under the
        // deniability latch that deliberately keeps this process ALIVE on a black
        // screen (AppState.wipedThisSession), so an un-closed handle would hold
        // the raw page key until process exit, and a RAM acquisition could then
        // decrypt an earlier full-filesystem image of run.db — bypassing the
        // crypto-erase entirely.
        // wipeAllTables() already ran above (best-effort), so the handle is no
        // longer needed; this close is best-effort + lock-serialized like
        // lock()'s close.
        try { vault?.close() } catch (_: Exception) { /* best-effort */ }
        vault          = null
        // Stop the unread prime, exactly as [lock] does — deliberately HERE, long
        // after the crypto-erase above: cancellation performs no I/O and no write,
        // so it can neither delay the erase nor re-create residue after it. Without
        // it a pass in flight would keep peeking the relay (a burst of requests is
        // the opposite of a deniable wipe) using capabilities it snapshotted from
        // the now-erased vault.
        sessionWorkScope.coroutineContext.cancelChildren()
        // Same, for an export/import still in flight: cancellation performs no I/O
        // and no write, so it can neither delay the crypto-erase nor re-create
        // residue after it. scrubInMemory drops the RAM-only one-time code from a
        // process this path deliberately keeps alive on a black screen.
        moveScope.coroutineContext.cancelChildren()
        moveManager.scrubInMemory()
        // The session's RAM, from the deliberately-kept-alive process — RAM only
        // (no I/O, no write), so it cannot delay the crypto-erase above or leave
        // residue after it.
        endSessionRam()
    }

    /**
     * The common tail of [lock] and [emergencyWipe]: the session managers' RAM
     * and the parked-send ledger.
     *
     *  - Each manager is scrubbed BEFORE its reference is dropped (a scrub after
     *    the null is dead): decrypted message/group buffers and the ephemeral
     *    referral X25519 key.
     *  - Parked transport-failed sends (plaintext, RAM-only, process-wide) are
     *    recorded exactly when [messageManager] is null (AppState.sendMessage's
     *    no-transport branch), so the manager scrub cannot be their only clear.
     *    `endSession()` bumps the session epoch AND clears, so a send still in
     *    flight that captured the old epoch cannot re-park after this.
     *    Unconditional — parity with Android `RunViewModel.lockSession` /
     *    `performEmergencyWipe`; [adoptOpenedVault] begins the next session.
     */
    private fun endSessionRam() {
        messageManager?.scrubInMemory()
        messageManager = null
        TransportFailedSends.shared.endSession()
        groupManager?.scrubInMemory()
        referralManager?.scrubInMemory()
        groupManager = null
        referralManager = null
    }

    private fun deleteTorData() {
        val path = platform.Foundation.NSSearchPathForDirectoriesInDomains(
            platform.Foundation.NSCachesDirectory,
            platform.Foundation.NSUserDomainMask, true
        ).firstOrNull() as? String ?: return
        // `TorManager.workingDirPath()` (Swift) on device is <Caches>/tor; the
        // pid-suffixed simulator dir is the Swift side's to remove. The old
        // split("/").take(2) math produced "/var/tor" on a real device, so the
        // Tor working set (onion-client-auth keys, guard state) survived the
        // wipe. (TorManager.stop() also wipes this on the main panic path; this
        // is the correct path for wipe entry points that don't call stop().)
        val torDir = "$path/tor"
        platform.Foundation.NSFileManager.defaultManager.removeItemAtPath(torDir, null)
    }

    companion object {
        // Tri-state result codes for [unlock]. Mirrored by Swift's UnlockOutcome.
        const val UNLOCK_OPENED = 0
        const val UNLOCK_DENIED = 1
        const val UNLOCK_ERROR = 2

        /**
         * The credential was CORRECT but the Secure Enclave key wrapping the DB
         * key is permanently gone (the device passcode was removed, which purges it).
         * Like [UNLOCK_ERROR] it never counts toward the budget, but unlike it a retry
         * can NEVER succeed — the UI must send the user to their recovery code.
         * Keep in sync with `UnlockOutcome` in AppState.swift.
         */
        const val UNLOCK_RECOVERY_REQUIRED = 3

        /**
         * Vault database files [emergencyWipe] unlinks from every searched
         * directory. `run_b.db` is the removed decoy file; still deleted to clean
         * up installs provisioned before the decoy feature was removed.
         */
        private val VAULT_DB_FILE_NAMES = listOf("run.db", "run_b.db")

        /**
         * SQLite sidecars deleted after each base file, in this order. SQLCipher
         * runs in WAL mode (so -wal/-shm are the usual sidecars), but a
         * journal_mode fallback or an interrupted transaction can leave a
         * "-journal" holding pre-image ciphertext pages. Crypto-erase (deleteKey
         * in [emergencyWipe]) is the primary control; the file is deleted too for
         * parity with Android WipeRoutine (which removes -journal).
         */
        private val SQLITE_SIDECAR_SUFFIXES = listOf("-wal", "-shm", "-journal")

        /**
         * Budget for [awaitMoveTransport] — the new phone's wait for Tor + an open
         * vault before the move import runs. 300 s, the value the Swift-side loop
         * this replaced already used (moving the wait here did not change the budget).
         */
        private const val MOVE_IMPORT_TRANSPORT_WAIT_MS = 300_000L

        /** Poll step of that wait; also its cancellation granularity. */
        private const val MOVE_TRANSPORT_POLL_MS = 1_000L
    }
}
