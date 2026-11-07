package com.vg.run

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Push opt-out left the Firebase identity alive.
 *
 * Before this fix, `VendorPush.currentToken` persistently enabled Firebase
 * auto-init, and the only caller of `VendorPush.destroyLocalPushIdentity` was
 * `WipeRoutine` (wipe-only). The disable branch of
 * `RunViewModel.setBackgroundNotificationsEnabledAwaiting` cleared the
 * persisted level, cancelled notifications, and best-effort unregistered from
 * the relay — but left a live, Google-side-correlatable FCM token + Firebase
 * Installation ID on disk indefinitely.
 *
 * A source-level check, not a full behavioural one: exercising
 * `destroyLocalPushIdentity` end-to-end means awaiting REAL, network-dependent
 * Firebase `Task`s (`deleteToken()` / `FirebaseInstallations.delete()`) — the
 * same reason `WipeRoutineResidueTest`'s own kdoc gives for not exercising its
 * post-settle re-sweep pass ("needs live Play Services and is not exercised
 * here"). [VendorPushArtifactSweepTest] (androidTest) separately proves the
 * deterministic, non-network half — that `VendorPush.sweepLocalArtifacts`
 * actually deletes the on-disk artifacts once invoked. This test proves the
 * WIRING: that the opt-out branch actually reaches the identity teardown at
 * all, which is the part `RunViewModel` (an `AndroidViewModel` needing a real
 * `Application`/`Context` to construct — `CryptoProvider`, `KeyValueStore`,
 * `VaultSelector`, `AndroidDbKeyProtector`, …) cannot be exercised for at the
 * plain-JVM tier this project's `androidUnitTest`/`test` sources run at (no
 * Robolectric, no Mockito/MockK on this module's test classpath).
 *
 * Same technique as [PrefsApplySourceGuardTest] (a source-level scan for a
 * property that's about a call site's PRESENCE, not its runtime behaviour).
 *
 * Non-vacuousness: removing the `VendorPush.destroyLocalPushIdentity(app) { ... }`
 * call from the disable branch (or reverting it entirely) makes
 * [optOutBranch_callsDestroyLocalPushIdentity] fail.
 *
 * SCOPE, since the class name under-sells it: this pins the identity teardown in
 * BOTH branches of that function — the opt-out one it was first added to, and
 * the ENABLE-FAILURE one (`if (!success)`), for both transports. The asymmetry
 * between the two branches is precisely what hid the follow-up bug: a failed
 * enable used to remove only the persisted level while the connector database,
 * the Keystore alias, our endpoint prefs, the Firebase installation identity and
 * a LIVE distributor-side subscription all survived, with no path left to
 * rediscover them. See the section comment above the enable-failure guards.
 */
class VendorPushOptOutTeardownSourceTest {

    @Test
    fun optOutBranch_callsDestroyLocalPushIdentity() {
        val src = File(repoRoot(), COORDINATOR).readText()

        val fnStart = src.indexOf("suspend fun setBackgroundNotificationsEnabledAwaiting")
        assertTrue("PushRegistrationCoordinator.setBackgroundNotificationsEnabledAwaiting must exist", fnStart >= 0)

        val branchStart = src.indexOf("if (!enabled) {", fnStart)
        assertTrue("the disable (!enabled) branch must exist", branchStart >= 0)

        // Bound the scan to the disable branch's own body: it is the only
        // branch that returns immediately with a literal `true` (the enable
        // path returns a computed `success`), so the first
        // "return@withContext true" after branchStart is exactly this
        // branch's close, without hand-parsing braces.
        val branchEnd = src.indexOf("return@withContext true", branchStart)
        assertTrue("the disable branch must return true unconditionally", branchEnd >= 0)
        val branch = src.substring(branchStart, branchEnd)

        assertTrue(
            "the opt-out (disable) branch must call VendorPush.destroyLocalPushIdentity so " +
                "the local Firebase push identity doesn't survive turning push off (before " +
                "this fix, only WipeRoutine called it, on a full wipe). Branch body was:\n$branch",
            branch.contains("VendorPush.destroyLocalPushIdentity("),
        )
    }

    /**
     * Process-death gap (adversarially-verified code review finding): the
     * async `destroyLocalPushIdentity(...) { sweepLocalArtifacts(...) }` call
     * alone is not enough, because [optOutBranch_callsDestroyLocalPushIdentity]
     * above only proves that ASYNC call exists — it would pass even if the
     * whole synchronous sweep were missing, which is exactly the bug: per
     * this app's whole-session-teardown-on-background design
     * (`MainActivity.onStop` -> `finishAndRemoveTask()`), a process death
     * before the Firebase `Task`s inside that callback settle leaves the FCM
     * token / Firebase Installation ID artifacts on disk indefinitely.
     * `WipeRoutine.wipePersistentState` gets this right (fires the async call,
     * then unconditionally calls `VendorPush.sweepLocalArtifacts` again,
     * synchronously, right after — see its own kdoc for why the synchronous
     * half is required).
     *
     * This test proves the disable branch has that SAME synchronous half: it
     * strips the `destroyLocalPushIdentity(...) { ... }` call (including its
     * onSettled lambda) out of the branch text entirely, then requires a
     * `VendorPush.sweepLocalArtifacts(...)` call to still be present in what's
     * left — i.e. a call that exists OUTSIDE that lambda, so it does not
     * depend on the async Task ever completing.
     *
     * Non-vacuousness: reverting to the async-only call (deleting the
     * standalone `VendorPush.sweepLocalArtifacts(app)` line that follows it)
     * makes [optOutBranch_alsoSweepsArtifactsSynchronously] fail, while
     * [optOutBranch_callsDestroyLocalPushIdentity] above would still pass —
     * which is exactly how the original gap slipped past that older test.
     */
    @Test
    fun optOutBranch_alsoSweepsArtifactsSynchronously() {
        val src = File(repoRoot(), COORDINATOR).readText()

        val fnStart = src.indexOf("suspend fun setBackgroundNotificationsEnabledAwaiting")
        assertTrue("PushRegistrationCoordinator.setBackgroundNotificationsEnabledAwaiting must exist", fnStart >= 0)

        val branchStart = src.indexOf("if (!enabled) {", fnStart)
        assertTrue("the disable (!enabled) branch must exist", branchStart >= 0)

        val branchEnd = src.indexOf("return@withContext true", branchStart)
        assertTrue("the disable branch must return true unconditionally", branchEnd >= 0)
        val branch = src.substring(branchStart, branchEnd)

        // A regex, not a fixed literal, so this survives incidental
        // reformatting of the one-liner — it matches the async call together
        // with its trailing `{ ... }` onSettled lambda, and nothing past the
        // lambda's closing brace.
        val asyncCallRegex = Regex("""VendorPush\.destroyLocalPushIdentity\([^)]*\)\s*\{[^}]*\}""")
        assertTrue(
            "expected exactly one VendorPush.destroyLocalPushIdentity(...) { ... } call in " +
                "the disable branch. Branch body was:\n$branch",
            asyncCallRegex.containsMatchIn(branch),
        )
        val withoutAsyncCall = asyncCallRegex.replace(branch, "")

        assertTrue(
            "process-death gap: the opt-out (disable) branch must ALSO call " +
                "VendorPush.sweepLocalArtifacts(...) SYNCHRONOUSLY, outside the " +
                "destroyLocalPushIdentity onSettled callback — mirroring " +
                "WipeRoutine.wipePersistentState's ordering (async call, then an " +
                "unconditional synchronous sweep right after) — so the local FCM token / " +
                "Firebase Installation ID residue is removed even if MainActivity.onStop's " +
                "finishAndRemoveTask() kills the process before the async Firebase Tasks the " +
                "callback awaits ever settle. Branch body with the async call (and its " +
                "lambda) stripped out was:\n$withoutAsyncCall",
            withoutAsyncCall.contains("VendorPush.sweepLocalArtifacts("),
        )
    }

    /**
     * The UnifiedPush sibling of the two guards above, and the reason it exists
     * is the specific gap the plan called out: opting out must tear down BOTH
     * transports UNCONDITIONALLY, not "whichever one the persisted level says is
     * active". The level is the thing that can be wrong — a reverted enable, a
     * Play-Services availability change under a restored data dir, or a
     * distributor uninstalled
     * while the app was closed all leave state behind that no level names.
     *
     * Three calls are required, in this ORDER — the same one `WipeRoutine` uses:
     *  1. `eraseKeySurface`. Crypto-erase FIRST: deleting the AndroidKeyStore
     *     alias is what makes the sealed WebPush private keys unrecoverable, so
     *     a teardown interrupted anywhere after this line is still safe,
     *     whatever rows or files survive.
     *  2. `destroyLocalPushIdentity`. Row-level deletion through the connector's
     *     OWN live handle plus the distributor-side unregister. Must precede the
     *     sweep, because it constructs the connector's DBStore and would
     *     otherwise re-create artifacts a sweep placed first had just removed
     *     (the write-after-delete race the Firebase teardown hit).
     *  3. `sweepInSessionArtifacts` — and NOT `sweepLocalArtifacts`; see
     *     [inSessionTeardowns_mustNotUnlinkTheConnectorDatabase] for why that
     *     distinction is the whole fix.
     *
     * Non-vacuousness: deleting any one of the three calls, or reordering them,
     * fails this test.
     */
    @Test
    fun optOutBranch_tearsDownUnifiedPushToo_inTheDocumentedOrder() {
        val branch = optOutBranch()

        val destroyAt = branch.indexOf("UnifiedPushSupport.destroyLocalPushIdentity(")
        val eraseAt = branch.indexOf("UnifiedPushSupport.eraseKeySurface(")
        val sweepAt = branch.indexOf("UnifiedPushSupport.sweepInSessionArtifacts(")

        assertTrue(
            "the opt-out (disable) branch must call UnifiedPushSupport.destroyLocalPushIdentity " +
                "so the distributor registration, the connector's own state and our endpoint " +
                "store don't survive turning notifications off. Branch body was:\n$branch",
            destroyAt >= 0,
        )
        assertTrue(
            "the opt-out branch must crypto-erase the connector's Keystore alias " +
                "(UnifiedPushSupport.eraseKeySurface) so an interrupted opt-out leaves the " +
                "sealed WebPush private keys unrecoverable. Branch body was:\n$branch",
            eraseAt >= 0,
        )
        assertTrue(
            "the opt-out branch must call UnifiedPushSupport.sweepInSessionArtifacts — the " +
                "settings opt-out runs no full wipe, so without it our endpoint store and the " +
                "connector's legacy prefs both survive. Branch body was:\n$branch",
            sweepAt >= 0,
        )
        assertTrue(
            "ORDER: eraseKeySurface must come FIRST (crypto-erase before anything else, so " +
                "an interrupted opt-out still leaves the sealed WebPush private keys " +
                "unrecoverable). Branch body was:\n$branch",
            eraseAt < destroyAt,
        )
        assertTrue(
            "ORDER: destroyLocalPushIdentity must come BEFORE the sweep — it constructs the " +
                "connector's DBStore and re-creates artifacts a sweep placed first had just " +
                "removed. Branch body was:\n$branch",
            destroyAt < sweepAt,
        )
    }

    // -----------------------------------------------------------------------
    // The ENABLE-FAILURE branch — the sibling of everything above, and the one
    // the asymmetry hid.
    //
    // The three guards above pin the OPT-OUT branch only. That asymmetry is
    // exactly what let the following slip: by the time an enable attempt can
    // fail, real artifacts already exist, and the failure branch removed only
    // the persisted level.
    //
    //  - `unifiedpush_state_prefs` (endpoint URL + p256dh + auth) is written by
    //    `RunPushService.onNewEndpoint` BEFORE the relay leg runs, so a RELAY
    //    failure leaves it behind;
    //  - the connector's `databases/unifiedpush-connector` (distributor choice,
    //    connector token, AES-GCM-sealed WebPush PRIVATE key) and the
    //    AndroidKeyStore alias `UnifiedPush` are created during DISTRIBUTOR
    //    SELECTION in `NotificationSettingsModal.setEnabled` — EARLIER than the
    //    ViewModel call — so they exist even in the sub-cases where no endpoint
    //    ever arrived (handshake timeout, DISTRIBUTOR_REFUSED,
    //    VAPID_UNSUPPORTED, NO_DISTRIBUTOR);
    //  - the vendor sibling is the pre-existing opt-out lineage: a failed FCM
    //    enable leaves the Firebase Installation ID / token that
    //    `VendorPush.currentToken` auto-inits.
    //
    // And nothing rediscovers them: the modal's `applyLevel` sets its local
    // `enabled = false` without dispatching a disable, and the control-poll
    // dispatcher keys off the level the branch just removed. So the teardown
    // has to happen HERE, on the failure path itself.
    // -----------------------------------------------------------------------

    /**
     * The UnifiedPush half, ORDER INCLUDED — the same load-bearing order the
     * opt-out branch documents (crypto-erase first; then the connector-side
     * teardown, which re-creates artifacts a sweep placed before it had just
     * removed; then the IN-SESSION sweep).
     *
     * Non-vacuousness: deleting any one of the three calls from the `if
     * (!success)` branch, or reordering them, fails this.
     */
    @Test
    fun enableFailureBranch_tearsDownUnifiedPush_inTheDocumentedOrder() {
        val branch = enableFailureBranch()

        val destroyAt = branch.indexOf("UnifiedPushSupport.destroyLocalPushIdentity(")
        val eraseAt = branch.indexOf("UnifiedPushSupport.eraseKeySurface(")
        val sweepAt = branch.indexOf("UnifiedPushSupport.sweepInSessionArtifacts(")

        assertTrue(
            "a FAILED enable must call UnifiedPushSupport.destroyLocalPushIdentity — the " +
                "distributor-side subscription is LIVE by then (the modal selected a " +
                "distributor before the ViewModel was even called) and nothing else ever " +
                "unregisters it. Branch body was:\n$branch",
            destroyAt >= 0,
        )
        assertTrue(
            "a FAILED enable must crypto-erase the connector's AndroidKeyStore alias " +
                "(UnifiedPushSupport.eraseKeySurface): the alias is created at DISTRIBUTOR " +
                "SELECTION time, so it exists even when the handshake timed out and no " +
                "endpoint ever arrived. Branch body was:\n$branch",
            eraseAt >= 0,
        )
        assertTrue(
            "a FAILED enable must call UnifiedPushSupport.sweepInSessionArtifacts — " +
                "unifiedpush_state_prefs (endpoint + subscription public keys) is written by " +
                "RunPushService.onNewEndpoint BEFORE the relay leg runs. Branch body was:\n$branch",
            sweepAt >= 0,
        )
        assertTrue(
            "ORDER: eraseKeySurface must come FIRST — the alias is the only thing that makes " +
                "the sealed WebPush private keys unrecoverable, so an interrupted revert must " +
                "not be able to stop before it. Branch body was:\n$branch",
            eraseAt < destroyAt,
        )
        assertTrue(
            "ORDER: destroyLocalPushIdentity must come BEFORE the sweep — it constructs the " +
                "connector's DBStore and re-creates artifacts a sweep placed first had just " +
                "removed. Branch body was:\n$branch",
            destroyAt < sweepAt,
        )
    }

    /**
     * The WIRING for everything the four guards above pin: the teardown body
     * they scan lives in `revertFailedPushEnable`, so this pins that BOTH
     * non-success exits of the enable leg actually call it (hardware, Pixel,
     * 2026-08-11):
     *
     *  1. the ordinary `if (!success)` revert — a failed registration must not
     *     leave the level persisted;
     *  2. the CANCELLATION exit — the enable leg suspends for up to tens of
     *     seconds (distributor handshake, Tor round-trip) on the settings
     *     modal's `rememberCoroutineScope`, so closing the modal mid-spinner
     *     (or the whole-session teardown on background) cancels it at the next
     *     suspension point. Before this fix that skipped the revert entirely:
     *     the level written at toggle time stayed persisted with nothing
     *     registered behind it and NO error ever shown, so the switch read ON
     *     forever on the next modal open — the exact silent-opt-in the
     *     function's kdoc promises to prevent. The catch must revert and then
     *     RETHROW (cancellation must stay cancellation).
     *
     * Non-vacuousness: removing either `revertFailedPushEnable(` call, or the
     * `throw e` after the cancellation one, fails this.
     */
    @Test
    fun everyNonSuccessExitOfTheEnableLeg_routesThroughTheSharedRevert() {
        val src = File(repoRoot(), COORDINATOR).readText()

        val fnStart = src.indexOf("suspend fun setBackgroundNotificationsEnabledAwaiting")
        assertTrue("PushRegistrationCoordinator.setBackgroundNotificationsEnabledAwaiting must exist", fnStart >= 0)

        val registrationLeg = src.indexOf("val success = try", fnStart)
        assertTrue(
            "the per-transport registration leg must be wrapped in try — cancellation is a " +
                "non-success exit and must be caught",
            registrationLeg >= 0,
        )

        val catchStart = src.indexOf("catch (e: CancellationException)", registrationLeg)
        assertTrue(
            "the enable leg must catch CancellationException — the modal's scope dies " +
                "mid-handshake whenever the dialog closes during the spinner",
            catchStart >= 0,
        )

        val failBranchStart = src.indexOf("if (!success) {", registrationLeg)
        assertTrue("the enable-failure (!success) branch must exist", failBranchStart >= 0)
        val enableEnd = src.indexOf("(requested=true)", failBranchStart)
        assertTrue("the enable path must end with its (requested=true) log line", enableEnd >= 0)

        val catchBlock = src.substring(catchStart, failBranchStart)
        val revertInCatch = catchBlock.indexOf("revertFailedPushEnable(")
        assertTrue(
            "the CancellationException catch must call revertFailedPushEnable — without it a " +
                "cancelled enable leaves the persisted level claiming 'on' with nothing " +
                "registered and no error shown. Catch block was:\n$catchBlock",
            revertInCatch >= 0,
        )
        val rethrowAt = catchBlock.indexOf("throw e")
        assertTrue(
            "the CancellationException catch must RETHROW after reverting — swallowing " +
                "cancellation would let a dead coroutine keep executing. Catch block " +
                "was:\n$catchBlock",
            rethrowAt >= 0 && revertInCatch < rethrowAt,
        )

        val failBranch = src.substring(failBranchStart, enableEnd)
        assertTrue(
            "the (!success) branch must call revertFailedPushEnable. Branch body " +
                "was:\n$failBranch",
            failBranch.contains("revertFailedPushEnable("),
        )
    }

    // -----------------------------------------------------------------------
    // The IN-SESSION vs. WIPE sweep split (regression 2026-08-03).
    //
    // `UnifiedPushSupport.sweepLocalArtifacts` unlinks
    // `databases/unifiedpush-connector`. The connector caches an open handle to
    // that file in a private STATIC singleton (`DBStore.instance`) and exposes
    // no close(), so unlinking it pins that handle in SQLITE_READONLY_DBMOVED
    // (extended result 1032) — `SQLiteOpenHelper.getWritableDatabase()` keeps
    // handing the same dead connection back, and every later write throws:
    //
    //   E/SQLiteLog (1032) statement aborts at 76: attempt to write a readonly
    //   database; [INSERT OR REPLACE INTO distributors(...)]
    //
    // On a wipe the unlink is REQUIRED (nothing may survive), which is why
    // `sweepLocalArtifacts` now CLOSES the connector's cached handle before
    // unlinking (2026-08-11): "a wipe is terminal, no retry follows in this
    // process" turned out to be false — most wipe entry points fall through to
    // setup in the same cached process, where the wedge made every re-enable
    // fail (see UnifiedPushWipeWedgeSourceTest). On the two IN-SESSION
    // teardowns the unlink stays forbidden outright: both return into a live
    // process where the user can toggle straight back ON, their retry needs
    // the LIVE handle, and the file removal adds nothing eraseKeySurface plus
    // the row deletes don't already cover.
    // -----------------------------------------------------------------------

    /**
     * Neither in-session branch may call the file-unlinking sweep.
     *
     * Stated as an ABSENCE because that is what regressed: the enable-failure
     * branch was ADDED (correctly) by a fix and simply reached for the
     * wipe-path sweep, which is the only one that existed at the time.
     *
     * Non-vacuousness: swapping either `sweepInSessionArtifacts` call back to
     * `sweepLocalArtifacts` fails this test.
     */
    @Test
    fun inSessionTeardowns_mustNotUnlinkTheConnectorDatabase() {
        listOf("opt-out (disable)" to optOutBranch(), "enable-failure" to enableFailureBranch())
            .forEach { (name, branch) ->
                assertFalse(
                    "the $name branch must NOT call UnifiedPushSupport.sweepLocalArtifacts: it " +
                        "unlinks databases/unifiedpush-connector out from under the open handle " +
                        "the connector caches in its static DBStore singleton, which pins that " +
                        "handle in SQLITE_READONLY_DBMOVED and makes every later " +
                        "saveDistributor throw for the rest of the process — so a retry after " +
                        "this teardown can never select a distributor again. Use " +
                        "sweepInSessionArtifacts; the sealed WebPush private keys are protected " +
                        "by eraseKeySurface, not by deleting the file. Branch body was:\n$branch",
                    branch.contains("UnifiedPushSupport.sweepLocalArtifacts("),
                )
            }
    }

    /**
     * The other half of the split: `WipeRoutine` must KEEP the full sweep. The
     * fix must not be "in-session is safe now" at the cost of leaving the
     * connector's database behind on a wipe, where nothing may survive.
     *
     * Non-vacuousness: changing WipeRoutine's call to `sweepInSessionArtifacts`
     * fails this test.
     */
    @Test
    fun wipeRoutine_keepsTheFullConnectorSweep() {
        val src = SourcePins.text(SourcePins.WIPE_ROUTINE)
        assertTrue(
            "WipeRoutine must call UnifiedPushSupport.sweepLocalArtifacts — nothing may " +
                "survive a wipe, so the connector's SQLite file must be unlinked. (The sweep " +
                "closes the connector's cached handle FIRST — 2026-08-11 — because most wipe " +
                "entry points fall through to setup in the same cached process, where an " +
                "unclosed unlink wedged every later re-enable; see " +
                "UnifiedPushWipeWedgeSourceTest.)",
            src.contains("UnifiedPushSupport.sweepLocalArtifacts("),
        )
    }

    /**
     * And the implementation half: `sweepInSessionArtifacts` must not acquire a
     * database path at all. A guard on the CALL SITES alone would be defeated by
     * someone "helpfully" adding the deleteDatabase back into the in-session
     * function.
     *
     * Non-vacuousness: adding `context.deleteDatabase(CONNECTOR_DB_NAME)` to
     * that function's body fails this test.
     */
    @Test
    fun sweepInSessionArtifacts_touchesNoDatabaseFile() {
        val src = SourcePins.text(SourcePins.UNIFIED_PUSH_SUPPORT)

        val fnStart = src.indexOf("fun sweepInSessionArtifacts(")
        assertTrue("UnifiedPushSupport.sweepInSessionArtifacts must exist", fnStart >= 0)
        val open = src.indexOf('{', fnStart)
        assertTrue("sweepInSessionArtifacts must have a body", open >= 0)
        // Brace-match the body so the scan can't wander into a neighbouring
        // function (and so it stays correct if one is added after it).
        var depth = 0
        var i = open
        while (i < src.length) {
            when (src[i]) {
                '{' -> depth++
                '}' -> { depth--; if (depth == 0) break }
            }
            i++
        }
        assertTrue("sweepInSessionArtifacts's body must be brace-balanced", depth == 0)
        val body = src.substring(open, i + 1)

        assertFalse(
            "sweepInSessionArtifacts must not call deleteDatabase — unlinking " +
                "databases/unifiedpush-connector wedges the connector's cached SQLite handle " +
                "for the life of the process. Body was:\n$body",
            body.contains("deleteDatabase"),
        )
        assertFalse(
            "sweepInSessionArtifacts must not resolve the connector's database path either — " +
                "getDatabasePath() is the other route to unlinking the file (and it mkdirs " +
                "databases/ on the way). Body was:\n$body",
            body.contains("getDatabasePath"),
        )
    }

    /**
     * The crypto-erase slot must cover BOTH of this tier's Keystore aliases.
     *
     * Every teardown path (WipeRoutine, opt-out, enable-failure) calls exactly
     * one erase function, pinned by the three guards above — so anything sealed
     * under a key that function does not name survives every one of them. Since
     * 2026-08-11 there are two such keys:
     *  - the connector's `UnifiedPush`, wrapping the WebPush PRIVATE keys;
     *  - `UnifiedPushStateStore.KEYSTORE_ALIAS`, sealing the RFC 8291
     *    (`p256dh`, `auth`) pair in `unifiedpush_state_prefs`. `auth` is a
     *    16-octet SHARED SECRET (RFC 8291 §3.2) — misclassifying it as a public
     *    half is what justified storing it in cleartext until then.
     *
     * Source-level for the same reason as the rest of this class: the
     * behavioural proof (`UnifiedPushArtifactSweepTest
     * .eraseKeySurface_alsoCryptoErasesOurOwnStateKey`) needs a device, and this
     * tier runs on every `./gradlew test`.
     *
     * Non-vacuousness: dropping either alias from `eraseKeySurface`'s body fails
     * this.
     */
    @Test
    fun eraseKeySurface_coversBothKeystoreAliases() {
        val body = fileFunctionBody(
            SourcePins.UNIFIED_PUSH_SUPPORT,
            "fun eraseKeySurface(",
        )

        assertTrue(
            "eraseKeySurface must still destroy the connector's own alias (the WebPush " +
                "PRIVATE keys). Body was:\n$body",
            body.contains("CONNECTOR_KEYSTORE_ALIAS"),
        )
        assertTrue(
            "eraseKeySurface must ALSO destroy UnifiedPushStateStore.KEYSTORE_ALIAS — it " +
                "seals the RFC 8291 auth SHARED SECRET, and no other teardown entry point " +
                "exists, so an alias this function does not name survives every wipe and every " +
                "opt-out. Body was:\n$body",
            body.contains("UnifiedPushStateStore.KEYSTORE_ALIAS"),
        )
    }

    /**
     * The VENDOR half — the sibling path to the same sink, and the reason this
     * test exists at all: `VendorPushArtifactSweepTest`'s opt-out lineage was fixed
     * on the opt-out path only, so a FAILED vendor enable still left the
     * Firebase installation identity that `VendorPush.currentToken`'s
     * just-in-time auto-init had already minted.
     *
     * Requires BOTH halves, exactly as [optOutBranch_alsoSweepsArtifactsSynchronously]
     * does: the async `destroyLocalPushIdentity(...) { ... }` for its
     * best-effort server-side revocation, AND a synchronous
     * `sweepLocalArtifacts` OUTSIDE that lambda — because this app's
     * whole-session-teardown-on-background design can kill the process before
     * the Firebase `Task`s ever settle.
     */
    @Test
    fun enableFailureBranch_tearsDownVendorPushToo_withASynchronousSweep() {
        val branch = enableFailureBranch()

        val asyncCallRegex = Regex("""VendorPush\.destroyLocalPushIdentity\([^)]*\)\s*\{[^}]*\}""")
        assertTrue(
            "a FAILED enable must ALSO retire the local Firebase push identity " +
                "(VendorPush.destroyLocalPushIdentity) — VendorPush.currentToken auto-inits " +
                "Firebase just to read the token, so a vendor enable that fails at the relay " +
                "leaves a live, Google-side-correlatable installation identity on disk with " +
                "nothing left to remove it. Branch body was:\n$branch",
            asyncCallRegex.containsMatchIn(branch),
        )
        val withoutAsyncCall = asyncCallRegex.replace(branch, "")
        assertTrue(
            "process-death gap: the enable-failure branch must ALSO call " +
                "VendorPush.sweepLocalArtifacts(...) SYNCHRONOUSLY, outside the " +
                "destroyLocalPushIdentity onSettled callback, so the residue is gone even if " +
                "MainActivity.onStop's finishAndRemoveTask() kills the process before the " +
                "async Firebase Tasks settle. Branch body with the async call (and its " +
                "lambda) stripped out was:\n$withoutAsyncCall",
            withoutAsyncCall.contains("VendorPush.sweepLocalArtifacts("),
        )
    }

    /**
     * The write-after-delete guard, stated as an ORDER: the persisted level must
     * be cleared BEFORE the teardown runs.
     *
     * `UnifiedPushSupport.destroyLocalPushIdentity` asks the distributor to
     * unregister, and the connector broadcasts UNREGISTERED straight back into
     * our own `RunPushService.onUnregistered` — which writes the "your
     * distributor dropped you" marker (RE-CREATING `unifiedpush_state_prefs.xml`
     * after the sweep already deleted it) whenever the level still reads
     * UNIFIED_PUSH. A cleared level is the "the user did not ask for this"
     * signal that suppresses it, and the enable-failure path sets no
     * [ProcessWipeLatch], so this ordering is its only defence — the same
     * property `RunPushServiceCallbackTest
     * .onUnregistered_afterADeliberateOptOut_writesNothingAndRecreatesNoFile`
     * pins from the callback's side.
     *
     * Non-vacuousness: moving `NotificationLevelStore.clearLevel` below the
     * teardown calls fails this.
     */
    @Test
    fun enableFailureBranch_clearsTheLevelBeforeTearingDown() {
        val branch = enableFailureBranch()

        val clearAt = branch.indexOf("NotificationLevelStore.clearLevel(")
        val destroyAt = branch.indexOf("UnifiedPushSupport.destroyLocalPushIdentity(")
        assertTrue(
            "the enable-failure branch must REMOVE the persisted level. Branch body was:\n$branch",
            clearAt >= 0,
        )
        assertTrue(
            "the enable-failure branch must tear the UnifiedPush identity down. " +
                "Branch body was:\n$branch",
            destroyAt >= 0,
        )
        assertTrue(
            "ORDER: the level must be cleared BEFORE UnifiedPushSupport" +
                ".destroyLocalPushIdentity, so the UNREGISTERED broadcast that teardown " +
                "provokes sees 'the user did not ask for this' and neither arms the " +
                "distributor-dropped notice nor re-creates unifiedpush_state_prefs.xml after " +
                "the sweep. Branch body was:\n$branch",
            clearAt < destroyAt,
        )
    }

    /**
     * The enable-failure branch stranded the RELAY's push row (2026-08-09).
     *
     * `clearLevel` → `destroyLocalPushIdentity` destroys the LOCAL receiving
     * address while leaving `inboxId -> token` rows on the relay: "failed" only
     * means no inbox got a 2xx on THIS pass, and rows survive from a partially
     * successful earlier pass or from any earlier session. With the level
     * cleared, nothing ever revisits them. The opt-out branch has always issued
     * the unregister; this pins that the failure branch now mirrors it, ORDER
     * included — the DELETE needs the vault and the transport, so it must run
     * before the teardowns, exactly as in the opt-out branch.
     *
     * It is `DELETE /inbox/{id}/push` (platform-agnostic, one pass covers FCM and
     * UnifiedPush), NOT the irreversible `DELETE /inbox/{id}` — so the "never
     * from a block or wipe path" rule that guards inbox destruction is not in
     * play here.
     *
     * Non-vacuousness: deleting the `unregisterPushInBackground()` call, or
     * moving it below either teardown, fails this.
     */
    @Test
    fun enableFailureBranch_unregistersFromTheRelayBeforeTearingTheAddressDown() {
        val branch = enableFailureBranch()

        val unregisterAt = branch.indexOf("unregisterPushInBackground()")
        val vendorDestroyAt = branch.indexOf("VendorPush.destroyLocalPushIdentity(")
        val unifiedDestroyAt = branch.indexOf("UnifiedPushSupport.destroyLocalPushIdentity(")

        assertTrue(
            "a FAILED enable must call unregisterPushInBackground() — the relay can already " +
                "hold push rows for these inboxes (an earlier pass or an earlier session), and " +
                "the teardown below destroys the address they point at while the cleared level " +
                "means nothing revisits them. Branch body was:\n$branch",
            unregisterAt >= 0,
        )
        assertTrue(
            "the enable-failure branch must tear the vendor identity down. Branch body was:\n$branch",
            vendorDestroyAt >= 0,
        )
        assertTrue(
            "the enable-failure branch must tear the UnifiedPush identity down. " +
                "Branch body was:\n$branch",
            unifiedDestroyAt >= 0,
        )
        assertTrue(
            "ORDER: unregisterPushInBackground() must run BEFORE both local teardowns — it " +
                "reads the inbound-inbox refs out of the still-open vault and sends over the " +
                "still-live transport, mirroring the opt-out branch. Branch body was:\n$branch",
            unregisterAt < vendorDestroyAt && unregisterAt < unifiedDestroyAt,
        )
    }

    // -----------------------------------------------------------------------
    // The identity-epoch latch (2026-08-09) — the root fix for "push silently
    // stops forever after one failed teardown".
    //
    // Verified against firebase-messaging 24.1.0 bytecode:
    // `FirebaseMessaging.deleteToken()` runs `Tasks.await(gmsRpc.deleteToken())`
    // and only THEN `Store.deleteToken(...)`, so an RPC failure sets the Task's
    // exception and leaves the local token cache intact. `destroyLocalPushIdentity`
    // chained the Firebase Installation delete off `addOnCompleteListener`, i.e.
    // ran it either way — leaving a live cached token bound to a destroyed
    // installation, which FCM accepts (2xx) and never delivers. `getToken()`
    // serves that token from a process-wide static `Store` for its 7-day window,
    // the SDK has no force-refresh, and `RunFcmService.onNewToken` is a no-op by
    // design, so every later session re-registered the identical dead token.
    // -----------------------------------------------------------------------

    /**
     * The latch must be armed by the FIRST statement of `destroyLocalPushIdentity`
     * — before the auto-init flip, before `deleteToken()` is even requested, and
     * before the caller's synchronous `sweepLocalArtifacts`. Anything later
     * leaves a window in which a concurrent `currentToken` adopts the very token
     * this teardown is about to strand.
     *
     * Non-vacuousness: moving the `markIdentityDestroyed()` call below the
     * `val settled = AtomicBoolean(false)` line fails this.
     */
    @Test
    fun destroyLocalPushIdentity_armsTheEpochLatchAsItsFirstStatement() {
        val body = vendorPushFunctionBody("fun destroyLocalPushIdentity(")

        val firstStatement = body.lines()
            .map { it.trim() }
            .firstOrNull { it.isNotEmpty() && !it.startsWith("//") && it != "{" }

        assertTrue(
            "the first statement of destroyLocalPushIdentity must arm " +
                "VendorPushIdentityEpoch — every token the SDK can hand out is suspect from " +
                "that instruction on. First statement found was: $firstStatement",
            firstStatement == "VendorPushIdentityEpoch.markIdentityDestroyed()",
        )
    }

    /**
     * `currentToken` must consult the latch BEFORE it fetches, and the proof it
     * accepts must be a SUCCESS, never a completion: `deleteToken()` evicts the
     * SDK's local `Store` entry only on the branch where its RPC succeeded, so
     * `addOnCompleteListener` here would re-assert exactly the dead token this
     * fix exists to stop re-registering.
     *
     * The latch may only be cleared AFTER that proven delete, and a delete that
     * fails must leave it armed (`return null` without clearing) — pinned as an
     * ordering plus the absence of any `addOnComplete` in the delete helper.
     *
     * ORDERING ALONE IS NOT ENOUGH, and that gap was real (adversarial review of
     * dd5804a, 2026-08-09). This test used to assert only that the four anchors
     * were PRESENT and in order, which the mutation
     *
     *     awaitProvenTokenDelete(fcm)                    // Boolean discarded
     *     VendorPushIdentityEpoch.markRefreshProven()    // cleared regardless
     *
     * satisfies perfectly — while reinstating the original bug in full: a failed
     * revocation disarms the latch and the dead token is fetched and registered
     * anyway. So the shape is now pinned as well: the delete's Boolean must be
     * CONSUMED as a negated guard whose outcome is an early `return null`, and no
     * unguarded call to it may exist. [theProvenDeleteGuardDetectorActuallyRejectsThatMutation]
     * pins that this detector really does reject that exact source.
     *
     * The other half of the property — that an armed latch STAYS armed until a
     * delete is proven — is behavioural, in `VendorPushIdentityEpochTest`
     * (`t3_refreshRequired_neverAutoClears`, `t4_onlyAProvenRefreshClears`).
     * Together: the latch cannot self-clear, and this call site cannot clear it
     * without proof, nor reach the fetch without it.
     *
     * Non-vacuousness: swapping `awaitProvenTokenDelete`'s listeners for
     * `addOnCompleteListener`, moving `markRefreshProven()` above the await,
     * dropping the latch check entirely, or discarding the delete's Boolean,
     * fails this.
     */
    @Test
    fun currentToken_consultsTheLatchAndClearsItOnlyOnAProvenDelete() {
        val body = stripComments(vendorPushFunctionBody("suspend fun currentToken("))

        val checkAt = body.indexOf("VendorPushIdentityEpoch.refreshRequired()")
        val awaitAt = body.indexOf("awaitProvenTokenDelete(")
        val provenAt = body.indexOf("VendorPushIdentityEpoch.markRefreshProven()")
        val fetchAt = body.indexOf("fcm.token")

        assertTrue(
            "currentToken must consult VendorPushIdentityEpoch. Body was:\n$body",
            checkAt >= 0,
        )
        assertTrue("currentToken must await a proven delete. Body was:\n$body", awaitAt >= 0)
        assertTrue("currentToken must clear the latch. Body was:\n$body", provenAt >= 0)
        assertTrue("currentToken must still fetch the token. Body was:\n$body", fetchAt >= 0)
        assertTrue(
            "ORDER: the latch must be consulted BEFORE the token fetch — after it, the " +
                "suspect token has already been adopted. Body was:\n$body",
            checkAt < fetchAt,
        )
        assertTrue(
            "ORDER: the latch may be cleared only AFTER the delete has been PROVEN. " +
                "Body was:\n$body",
            awaitAt < provenAt && provenAt < fetchAt,
        )

        // THE SHAPE, not just the order: a failed delete must suppress the fetch.
        val guards = PROVEN_DELETE_GUARD.findAll(body).toList()
        assertTrue(
            "a FAILED delete must SUPPRESS the token fetch and leave the latch armed, so the " +
                "delete's Boolean has to be consumed as `if (!awaitProvenTokenDelete(…)) return " +
                "null`. Merely calling it and clearing the latch afterwards re-creates the " +
                "dead-token bug this fix exists for. Body was:\n$body",
            guards.isNotEmpty(),
        )
        assertEquals(
            "every call to awaitProvenTokenDelete must be that guarded form — an unguarded " +
                "call is one whose answer is discarded, i.e. a delete that failed still " +
                "reaches the fetch. Body was:\n$body",
            PROVEN_DELETE_CALL.findAll(body).count(),
            guards.size,
        )
        assertTrue(
            "ORDER: the guard's early return must precede the latch clear, so the failure " +
                "path can never reach markRefreshProven(). Body was:\n$body",
            guards.first().range.first < provenAt,
        )

        val deleteHelper = vendorPushFunctionBody("private suspend fun awaitProvenTokenDelete(")
        assertTrue(
            "awaitProvenTokenDelete must key on SUCCESS (addOnSuccessListener + " +
                "addOnFailureListener). Body was:\n$deleteHelper",
            deleteHelper.contains("addOnSuccessListener") && deleteHelper.contains("addOnFailureListener"),
        )
        assertFalse(
            "addOnCompleteListener answers 'it finished', not 'it succeeded' — and " +
                "deleteToken() evicts the local Store entry ONLY on the success branch. Using " +
                "it here is the original bug. Body was:\n$deleteHelper",
            deleteHelper.contains("addOnComplete"),
        )
    }

    /**
     * The detector's own non-vacuousness, in the shape
     * [PrefsApplySourceGuardTest.theDetectorActuallyDetects] uses: a guard that
     * cannot fire reads as coverage but is none.
     *
     * The first negative is VERBATIM the mutation adversarial review used to walk
     * through the previous version of the test above — call the delete, discard
     * its answer, clear the latch unconditionally.
     */
    @Test
    fun theProvenDeleteGuardDetectorActuallyRejectsThatMutation() {
        val accepted = listOf(
            "if (!awaitProvenTokenDelete(fcm)) return null",
            "if (!awaitProvenTokenDelete(fcm)) { return null }",
            "if ( ! awaitProvenTokenDelete( fcm ) )\n    return null",
        )
        for (src in accepted) {
            assertTrue(
                "the guarded shape must be accepted: $src",
                PROVEN_DELETE_GUARD.containsMatchIn(src) &&
                    PROVEN_DELETE_CALL.findAll(src).count() == PROVEN_DELETE_GUARD.findAll(src).count(),
            )
        }

        val rejected = listOf(
            // The reviewer's mutation: answer discarded, latch cleared anyway.
            "awaitProvenTokenDelete(fcm)\nVendorPushIdentityEpoch.markRefreshProven()",
            "val proven = awaitProvenTokenDelete(fcm)\nVendorPushIdentityEpoch.markRefreshProven()",
            // Guarded but with no suppression: execution falls through to the fetch.
            "if (!awaitProvenTokenDelete(fcm)) { }\nVendorPushIdentityEpoch.markRefreshProven()",
            // Latch left armed, but the dead token is still fetched.
            "if (awaitProvenTokenDelete(fcm)) VendorPushIdentityEpoch.markRefreshProven()",
            // One guarded call plus a stray unguarded one.
            "if (!awaitProvenTokenDelete(fcm)) return null\nawaitProvenTokenDelete(fcm)",
        )
        for (src in rejected) {
            assertFalse(
                "the detector must reject: $src",
                PROVEN_DELETE_GUARD.containsMatchIn(src) &&
                    PROVEN_DELETE_CALL.findAll(src).count() == PROVEN_DELETE_GUARD.findAll(src).count(),
            )
        }
    }

    /** Brace-matched body of a `VendorPush.kt` function (raw text, comments kept). */
    private fun vendorPushFunctionBody(signature: String): String =
        fileFunctionBody(SourcePins.VENDOR_PUSH, signature)

    /**
     * The toggle moved from RunViewModel into PushRegistrationCoordinator, and the
     * ViewModel keeps a facade under the SAME signature text. Every scan above
     * therefore reads the coordinator; this pins that the facade stays a single
     * delegating expression, so an `indexOf("suspend fun
     * setBackgroundNotificationsEnabledAwaiting")` landing on it can never find a
     * branch body of its own (or scan on into an unrelated `if (!enabled) {`).
     *
     * Non-vacuousness: giving the facade a body, or moving any teardown back into
     * the ViewModel, fails this.
     */
    @Test
    fun theViewModelToggleIsAOneExpressionFacadeOverTheCoordinator() {
        val vm = SourcePins.text(SourcePins.RUN_VIEW_MODEL)
        val sig = "suspend fun setBackgroundNotificationsEnabledAwaiting(level: NotificationLevel): Boolean ="
        val at = vm.indexOf(sig)
        assertTrue("RunViewModel must keep the facade `$sig`", at >= 0)
        assertTrue("…exactly once", vm.indexOf(sig, at + 1) < 0)
        val afterSig = vm.substring(at + sig.length)
        val end = afterSig.indexOf("\n\n")
        assertTrue("the facade must be followed by a blank line", end >= 0)
        assertEquals(
            "the RunViewModel facade must be ONE delegating expression",
            "push.setBackgroundNotificationsEnabledAwaiting(level)",
            afterSig.substring(0, end).trim(),
        )
        for (moved in listOf("private fun revertFailedPushEnable(", "if (!enabled) {")) {
            assertFalse(
                "`$moved` moved to PushRegistrationCoordinator — no copy may stay in RunViewModel",
                vm.contains(moved),
            )
        }
    }

    /**
     * The OPT-OUT branch body: `if (!enabled) { … }`, bounded by the single
     * unconditional `return@withContext true` that closes it (the enable path
     * returns a computed `success`, so that literal is unambiguous). Both
     * anchors are asserted rather than defaulted — a guard that silently scans
     * nothing is worse than no guard.
     */
    private fun optOutBranch(): String {
        val src = File(repoRoot(), COORDINATOR).readText()

        val fnStart = src.indexOf("suspend fun setBackgroundNotificationsEnabledAwaiting")
        assertTrue("PushRegistrationCoordinator.setBackgroundNotificationsEnabledAwaiting must exist", fnStart >= 0)

        val branchStart = src.indexOf("if (!enabled) {", fnStart)
        assertTrue("the disable (!enabled) branch must exist", branchStart >= 0)

        val branchEnd = src.indexOf("return@withContext true", branchStart)
        assertTrue("the disable branch must return true unconditionally", branchEnd >= 0)
        return src.substring(branchStart, branchEnd)
    }

    /**
     * The enable-FAILURE teardown body. Since 2026-08-11 the inline `if
     * (!success) { … }` block is a named function, `revertFailedPushEnable`,
     * because the failure branch stopped being the only non-success exit: a
     * CANCELLATION mid-handshake (settings modal closed during the spinner,
     * whole-session teardown on background) used to skip the revert entirely,
     * leaving the persisted level claiming "on" with nothing registered behind
     * it and no error ever shown. Every teardown-content guard above now scans
     * that function's brace-matched body;
     * [everyNonSuccessExitOfTheEnableLeg_routesThroughTheSharedRevert] pins
     * that both exits actually reach it.
     */
    private fun enableFailureBranch(): String = fileFunctionBody(
        COORDINATOR,
        "private fun revertFailedPushEnable(",
    )

    /**
     * 2026-09-17, root-caused on a Samsung A20e (API 30, Play Services 26.33)
     * after the `push:unregister` FCM leg failed at RE-opt-in twice in one day
     * with `notif_register_error` while the same leg passed on a Pixel 7.
     *
     * The synchronous sweep the two guards above pin is REQUIRED (process-death
     * residue) and stays — but it must not take the Firebase Installations SDK's
     * own state file out from under the revocation chain this very teardown
     * started. `FirebaseMessaging.deleteToken()` needs an installation to
     * authenticate its RPC, so it runs `doRegistrationOrRefresh`, which re-reads
     * `PersistedInstallation.<key>.json` on the FIS network executor a few
     * hundred ms later. With the file gone the SDK reads the absent-file default
     * (`Status = ATTEMPT_MIGRATION`, no fid, no auth token); `doNetworkCallIfNecessary`
     * re-registers only for `isErrored() || isUnregistered()`, so it fell through
     * to `fetchAuthTokenFromServer` and POSTed
     * `projects/{p}/installations/{NULL}/authTokens:generate`. FIS answers 400
     * INVALID_ARGUMENT (proven by calling the SDK's own service client with an
     * empty fid; an empty refresh token answers 401 instead), and
     * `RequestLimiter` blocks EVERY later FIS request for 24 HOURS because 400 is
     * neither retryable nor "requires a new fid". `currentToken()` then returns
     * null for the rest of the process.
     *
     * The fix is ONE deferred file, gated on [FisTeardownGate]. This guard pins
     * the gate to the sweep: delete the `isPending()` check and the sweep is free
     * to race the chain again.
     *
     * Non-vacuousness: removing the `if (!FisTeardownGate.isPending())` wrapper
     * (or moving the two `listFiles(persistedInstallationFilter)` deletions out
     * of it) fails this test.
     */
    @Test
    fun sweep_defersTheInstallationsStateFileWhileATeardownChainIsPending() {
        val src = SourcePins.stripped(SourcePins.VENDOR_PUSH)

        val fnStart = src.indexOf("fun sweepLocalArtifacts(")
        assertTrue("VendorPush.sweepLocalArtifacts must exist", fnStart >= 0)
        val fnEnd = src.indexOf("fun deleteHeartbeatStore(", fnStart).let {
            if (it >= 0) it else src.length
        }
        val body = src.substring(fnStart, fnEnd)

        val gateSource = "if (!FisTeardownGate.isPending())"
        val gateAt = body.indexOf(gateSource)
        assertTrue(
            "sweepLocalArtifacts must gate the PersistedInstallation deletion on " +
                "FisTeardownGate.isPending() — deleting that file while this process's own " +
                "revocation chain is re-reading it costs a 24-hour FIS lockout. Body was:\n$body",
            gateAt >= 0,
        )
        val deletions = Regex("""listFiles\(persistedInstallationFilter\)""").findAll(body).toList()
        assertEquals(
            "both PersistedInstallation locations (filesDir + noBackupFilesDir) must be swept",
            2,
            deletions.size,
        )
        for (d in deletions) {
            assertTrue(
                "every PersistedInstallation deletion must sit INSIDE the FisTeardownGate " +
                    "guard, not before it. Body was:\n$body",
                d.range.first > gateAt,
            )
        }
        assertFalse(
            "nothing else in the sweep may be gated on the teardown — every other artifact " +
                "(token store, auto-init prefs, heartbeat datastore, lock file, no-backup " +
                "marker) must still be removed SYNCHRONOUSLY. Body was:\n$body",
            body.indexOf("FisTeardownGate.isPending()", gateAt + gateSource.length) >= 0,
        )
    }

    /**
     * The other half of the same fix: the gate has to be ARMED before the chain
     * can start (i.e. before the caller's synchronous sweep can run) and RELEASED
     * when it settles, or the deferral is either never applied or never lifted —
     * the second of which would strand a live Fid/AuthToken/RefreshToken on disk.
     *
     * Also pins that the late passes wait for that settle: they used to be timed
     * from the poke, which put the first pass inside the window the chain is
     * still reading its state in.
     */
    @Test
    fun destroyLocalPushIdentity_armsTheGateBeforeTheChainAndReleasesItAtSettle() {
        val src = SourcePins.stripped(SourcePins.VENDOR_PUSH)

        val fnStart = src.indexOf("fun destroyLocalPushIdentity(")
        assertTrue("VendorPush.destroyLocalPushIdentity must exist", fnStart >= 0)
        val fnEnd = src.indexOf("fun sweepLocalArtifacts(", fnStart).let {
            if (it >= 0) it else src.length
        }
        val body = src.substring(fnStart, fnEnd)

        val armAt = body.indexOf("FisTeardownGate.arm()")
        val deleteTokenAt = body.indexOf("deleteToken()")
        assertTrue("destroyLocalPushIdentity must arm FisTeardownGate. Body was:\n$body", armAt >= 0)
        assertTrue("destroyLocalPushIdentity must still start the revocation chain", deleteTokenAt >= 0)
        assertTrue(
            "the gate must be armed BEFORE the revocation chain starts — otherwise the " +
                "caller's synchronous sweep can still win the race. Body was:\n$body",
            armAt < deleteTokenAt,
        )
        assertTrue(
            "the deferral must be released when the chain settles, or a live bearer " +
                "credential stays on disk. Body was:\n$body",
            body.contains("FisTeardownGate.release()") || body.contains("releaseDefer()"),
        )
        assertTrue(
            "the late passes must WAIT for that settle (a pass timed from the poke lands " +
                "inside the window the chain is still reading its state in). Body was:\n$body",
            body.contains("scheduleLateArtifactSweeps(context, settledLatch"),
        )
    }

    companion object {
        /** The toggle and both teardown branches live here (moved out of RunViewModel). */
        private const val COORDINATOR = SourcePins.PUSH_REGISTRATION_COORDINATOR

        /**
         * The delete's Boolean CONSUMED as a negated guard with an early return —
         * the only shape in which a failed revocation can suppress the fetch.
         * `[^()]*` keeps the argument list from swallowing a following call.
         */
        private val PROVEN_DELETE_GUARD =
            Regex("""if\s*\(\s*!\s*awaitProvenTokenDelete\s*\([^()]*\)\s*\)\s*(\{\s*)?return\s+null""")

        /** Any invocation at all, guarded or not — the two counts must match. */
        private val PROVEN_DELETE_CALL = Regex("""awaitProvenTokenDelete\s*\(""")
    }
}
