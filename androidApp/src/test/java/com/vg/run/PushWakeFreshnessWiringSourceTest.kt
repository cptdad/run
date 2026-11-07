package com.vg.run

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Late-delivered FCM wake suppression (2026-10-14) — the WIRING.
 *
 * The decisions themselves are pure and pinned behaviourally
 * ([PushWakeFreshnessTest] for the gate, [PushWakeStampPolicyTest] for the
 * stamp policy). What those cannot see is whether the two Android entry points
 * still hand them the right facts, in the right order:
 *
 *  - `RunFcmService.onMessageReceived` must consult the gate with FCM's own
 *    `sentTime` BEFORE posting the banner, inside the VENDOR_PUSH branch, and
 *    the UnifiedPush service (which has no sentTime) must never go near it;
 *  - `RunViewModel.startControlPoll` must record the cycle START (the wall clock
 *    taken before the control pass issues its first request), gated on the
 *    sweep-completeness callback AND on the control pass having returned;
 *  - the stamp must die with the level (both `PushWakeFreshness.clear` sites)
 *    and with the whole prefs file (`WipeRoutine.PREFS_FILES`), and no
 *    wipe/tamper logic may ever read it.
 *
 * SOURCE-LEVEL, same technique and same reason as [FcmNotificationDelegationSourceTest]
 * / [GroupInboxAndroidWiringTest]: `RunViewModel` is an `AndroidViewModel` and
 * `RunFcmService` a `FirebaseMessagingService`, neither constructible at this
 * module's plain-JVM tier (no Robolectric, no mocking framework). Bodies are
 * scanned with comments STRIPPED so prose that merely names a call can neither
 * satisfy nor trip a guard.
 */
class PushWakeFreshnessWiringSourceTest {

    private val viewModel: String by lazy { stripComments(read(SourcePins.RUN_VIEW_MODEL)) }
    /** The toggle and the enable-failure revert moved here out of RunViewModel. */
    private val pushCoordinator: String by lazy { stripComments(read(SourcePins.PUSH_REGISTRATION_COORDINATOR)) }
    private val fcmService: String by lazy { stripComments(read(SourcePins.RUN_FCM_SERVICE)) }
    private val upService: String by lazy { stripComments(read("androidApp/src/main/java/com/vg/run/RunPushService.kt")) }
    private val freshness: String by lazy { stripComments(read("androidApp/src/main/java/com/vg/run/PushWakeFreshness.kt")) }
    private val wipeRoutine: String by lazy { stripComments(read(SourcePins.WIPE_ROUTINE)) }

    // -----------------------------------------------------------------------
    // 1. RunFcmService: gate BEFORE the banner, with FCM's sentTime, VENDOR_PUSH only.
    // -----------------------------------------------------------------------

    @Test
    fun fcmService_consultsTheGateWithFcmsSentTime_beforeShowingTheBanner() {
        val body = fcmService.functionBody("override fun onMessageReceived(message: RemoteMessage) {")
        val gate = "PushWakeFreshness.isStaleWake(levelStore, message.sentTime, System.currentTimeMillis())"
        val gateAt = body.indexOf(gate)
        val showAt = body.indexOf("NotificationHelper.showNewMessages(")
        assertTrue("onMessageReceived must call exactly `$gate`. Body was:\n$body", gateAt >= 0)
        assertTrue("onMessageReceived must still post the banner", showAt >= 0)
        assertTrue("the gate must run BEFORE showNewMessages", gateAt < showAt)
        // A suppressed wake RETURNS — it never falls through to the banner.
        val between = body.substring(gateAt, showAt)
        assertTrue("a stale wake must `return` before the banner. Segment was:\n$between", between.contains("return"))
        assertEquals("exactly one banner post", 1, body.occurrences("NotificationHelper.showNewMessages("))
    }

    @Test
    fun fcmService_gateSitsInsideTheVendorPushBranch_andReadsTheSameStore() {
        val body = fcmService.functionBody("override fun onMessageReceived(message: RemoteMessage) {")
        val levelCheckAt = body.indexOf("NotificationLevelStore.getLevel(levelStore) == NotificationLevel.VENDOR_PUSH")
        val gateAt = body.indexOf("PushWakeFreshness.isStaleWake(levelStore,")
        assertTrue("the VENDOR_PUSH level gate must exist", levelCheckAt >= 0)
        assertTrue("the freshness gate must exist", gateAt >= 0)
        assertTrue("the freshness gate must be evaluated AFTER (inside) the level gate", levelCheckAt < gateAt)
        assertTrue(
            "levelStore must be the notification-level prefs the ViewModel stamps into",
            body.contains("KeyValueStore(applicationContext, RunViewModel.NOTIFICATION_LEVEL_PREFS_NAME)"),
        )
    }

    @Test
    fun unifiedPushService_neverConsultsTheGate() {
        // A UnifiedPush message carries no sender-side sentTime, so there is
        // nothing to order against the sweep; its guard is PushReplayGuard.
        assertFalse(
            "RunPushService must not reference PushWakeFreshness (no sentTime to gate on)",
            upService.contains("PushWakeFreshness"),
        )
        val body = upService.functionBody("override fun onMessage(message: PushMessage, instance: String) {")
        assertTrue("precondition: the UnifiedPush path still posts the banner", body.contains("NotificationHelper.showNewMessages("))
    }

    @Test
    fun isStaleWake_hasExactlyOneCaller_theFcmService() {
        val callers = mainSources().filter { stripComments(it.readText()).contains("PushWakeFreshness.isStaleWake(") }
        assertEquals(
            "PushWakeFreshness.isStaleWake must be called from RunFcmService.kt only, found: " +
                callers.map { it.name },
            listOf("RunFcmService.kt"), callers.map { it.name },
        )
    }

    // -----------------------------------------------------------------------
    // 2. RunViewModel: the stamp carries the cycle START, gated on completeness
    //    and on the control pass having returned.
    // -----------------------------------------------------------------------

    @Test
    fun controlPoll_recordsTheCycleStart_takenBeforeTheControlPass() {
        val body = viewModel.functionBody("private fun startControlPoll() {")
        val startAt = body.indexOf("val cycleStartedAtMs = System.currentTimeMillis()")
        val controlAt = body.indexOf("pollAllControls()")
        val recordAt = body.indexOf("PushWakeFreshness.recordInboxSweep(")
        assertTrue("the cycle start must be a single `val` taken from the wall clock", startAt >= 0)
        assertTrue("the control pass must still run in this loop", controlAt >= 0)
        assertTrue("the stamp must be recorded in this loop", recordAt >= 0)
        assertTrue("the cycle start must be taken BEFORE the control pass's first request", startAt < controlAt)
        assertTrue("the stamp must be recorded AFTER the unread sweep (end of cycle)", controlAt < recordAt)
        assertEquals("cycleStartedAtMs is assigned exactly once (a val, never re-stamped)", 1, body.occurrences("cycleStartedAtMs ="))
        assertEquals(
            "the loop reads the wall clock exactly once — the START; nothing re-reads it at the end",
            1, body.occurrences("System.currentTimeMillis()"),
        )
        val call = body.functionCall("PushWakeFreshness.recordInboxSweep(")
        assertTrue("the recorded value must be the cycle start:\n$call", call.contains("cycleStartedAtMs"))
        assertTrue("the stamp goes to the notification-level store:\n$call", call.contains("notificationLevelStore"))
    }

    @Test
    fun controlPoll_passesTheSweepCompletenessCallback_andTheControlPassFlag() {
        val body = viewModel.functionBody("private fun startControlPoll() {")
        assertTrue(
            "the unread sweep must be asked for its completeness through onSweepFinished",
            body.contains("contactUnreadCounts(onSweepFinished = { c -> peekComplete = c })"),
        )
        val call = body.functionCall("PushWakeFreshness.recordInboxSweep(")
        assertTrue("sweepComplete must be the callback's answer:\n$call", call.contains("sweepComplete = peekComplete"))
        assertTrue("controlPassRan must be the control-pass flag:\n$call", call.contains("controlPassRan = controlPassOk"))
        // peekComplete starts FALSE and is only ever set by the callback: a sweep
        // that never answered (threw before the callback) reads incomplete.
        assertTrue(body.contains("var peekComplete = false"))
        val declAt = body.indexOf("var peekComplete = false")
        val sweepAt = body.indexOf("contactUnreadCounts(onSweepFinished")
        val recordAt = body.indexOf("PushWakeFreshness.recordInboxSweep(")
        assertTrue(declAt < sweepAt && sweepAt < recordAt)
    }

    @Test
    fun controlPoll_controlPassFlag_isSetOnlyAfterPollAllControlsReturned() {
        val body = viewModel.functionBody("private fun startControlPoll() {")
        val declAt = body.indexOf("var controlPassOk = false")
        val controlAt = body.indexOf("pollAllControls()")
        val setAt = body.indexOf("controlPassOk = groupManager != null")
        assertTrue("controlPassOk must start false", declAt >= 0)
        assertTrue("controlPassOk must be set from the control pass", setAt >= 0)
        assertTrue("declared before the pass, set strictly after it returned", declAt < controlAt && controlAt < setAt)
        // Both sit in the same try — a throwing pass skips the assignment.
        val tryAt = body.lastIndexOf("try {", controlAt)
        val catchAt = body.indexOf("catch", controlAt)
        assertTrue(tryAt in 0 until controlAt && setAt < catchAt)
        assertEquals(
            "the flag has exactly two `=` sites: the false initialiser and the one post-pass assignment",
            2, body.occurrences("controlPassOk = "),
        )
        assertEquals(1, body.occurrences("controlPassOk = groupManager != null"))
    }

    // -----------------------------------------------------------------------
    // 3. The stamp dies with the level (both clear sites) and with the file.
    // -----------------------------------------------------------------------

    @Test
    fun optOut_clearsTheStamp_rightAfterTheLevel() {
        val fn = pushCoordinator.functionBody("suspend fun setBackgroundNotificationsEnabledAwaiting(level: NotificationLevel): Boolean =")
        val branchStart = fn.indexOf("if (!enabled) {")
        assertTrue("the opt-out branch must exist", branchStart >= 0)
        val branch = fn.substring(branchStart).let { it.substring(0, it.balancedBlockEnd()) }
        val levelAt = branch.indexOf("NotificationLevelStore.clearLevel(notificationLevelStore,")
        val stampAt = branch.indexOf("PushWakeFreshness.clear(notificationLevelStore)")
        assertTrue("opt-out must remove the level", levelAt >= 0)
        assertTrue("opt-out must remove the stamp. Branch was:\n$branch", stampAt >= 0)
        assertTrue("level first, then the stamp (both before any best-effort/async work)", levelAt < stampAt)
        val relayAt = branch.indexOf("unregisterPushInBackground()")
        assertTrue("the stamp clear precedes the relay unregister", relayAt < 0 || stampAt < relayAt)
    }

    @Test
    fun failedEnableRevert_clearsTheStamp_rightAfterTheLevel() {
        val body = pushCoordinator.functionBody("private fun revertFailedPushEnable(app: Application) {")
        val levelAt = body.indexOf("NotificationLevelStore.clearLevel(notificationLevelStore,")
        val stampAt = body.indexOf("PushWakeFreshness.clear(notificationLevelStore)")
        assertTrue(levelAt >= 0)
        assertTrue("revertFailedPushEnable must remove the stamp. Body was:\n$body", stampAt >= 0)
        assertTrue(levelAt < stampAt)
    }

    @Test
    fun theTwoClearSites_areTheOnlyOnes() {
        assertEquals(
            "PushRegistrationCoordinator must clear the stamp at exactly the two level-removal sites",
            2, pushCoordinator.occurrences("PushWakeFreshness.clear(notificationLevelStore)"),
        )
        assertEquals(
            "RunViewModel must not clear the stamp itself (the two sites moved to the coordinator)",
            0, viewModel.occurrences("PushWakeFreshness.clear(notificationLevelStore)"),
        )
    }

    @Test
    fun wipeRoutine_deletesTheWholeNotificationLevelFile() {
        val list = wipeRoutine.functionCall("private val PREFS_FILES = listOf(")
        assertTrue(
            "WipeRoutine.PREFS_FILES must carry RunViewModel.NOTIFICATION_LEVEL_PREFS_NAME — the file the stamp lives in",
            list.contains("RunViewModel.NOTIFICATION_LEVEL_PREFS_NAME"),
        )
        assertTrue(
            "the wipe must still delete every listed prefs file",
            wipeRoutine.contains("PREFS_FILES.forEach { context.deleteSharedPreferences(it) }"),
        )
    }

    // -----------------------------------------------------------------------
    // 4. Where the key lives, and who may read it.
    // -----------------------------------------------------------------------

    /**
     * INIT-ORDER HAZARD (not compiler-checked): Kotlin runs property initializers
     * in text order, so a `push` coordinator declared ABOVE the store it is handed
     * would capture a null store and NPE at the first prefs read.
     */
    @Test
    fun thePushCoordinator_isDeclaredBelowTheStoreItIsHanded() {
        val storeAt = viewModel.indexOf("private val notificationLevelStore = KeyValueStore(application, NOTIFICATION_LEVEL_PREFS_NAME)")
        val pushAt = viewModel.indexOf("private val push = PushRegistrationCoordinator(")
        assertTrue("precondition: both declarations exist", storeAt >= 0 && pushAt >= 0)
        assertTrue("`push` must be declared BELOW notificationLevelStore", storeAt < pushAt)
        assertTrue(
            "…and it must be handed that store",
            viewModel.substring(pushAt).substringBefore("\n    )").contains("notificationLevelStore = notificationLevelStore,"),
        )
    }

    @Test
    fun theKey_isInboxSweepMs_inNotificationLevelPrefs_outsideTheVault() {
        assertEquals("inbox_sweep_ms", PushWakeFreshness.KEY_LAST_SWEEP)
        assertTrue(
            "the prefs file name must stay notification_level_prefs",
            viewModel.contains("const val NOTIFICATION_LEVEL_PREFS_NAME = \"notification_level_prefs\""),
        )
        assertTrue(
            "the ViewModel's store must be that file",
            viewModel.contains("private val notificationLevelStore = KeyValueStore(application, NOTIFICATION_LEVEL_PREFS_NAME)"),
        )
        // The writer is a plain prefs put under that key; never a vault row.
        assertTrue(freshness.contains("store.putString(KEY_LAST_SWEEP, sweepStartedAtMs.toString())"))
        for (vaultSymbol in listOf("putMeta(", "getMeta(", "VaultDatabase", "vault.")) {
            assertFalse("PushWakeFreshness must not touch the vault ($vaultSymbol)", freshness.contains(vaultSymbol))
        }
    }

    @Test
    fun noWipeOrTamperLogic_everReadsTheStamp() {
        // The stamp is NOT evidence and NOT an anchor: the only file that may name
        // the key is its owner. Scanned across every main source set, both modules.
        val mentions = mainSources()
            .filter { f ->
                val s = stripComments(f.readText())
                s.contains("inbox_sweep_ms") || s.contains("KEY_LAST_SWEEP")
            }
            .map { it.name }
        assertEquals(listOf("PushWakeFreshness.kt"), mentions)
    }

    @Test
    fun recordInboxSweep_honoursTheWipeLatch_beforeTheReadAndBeforeTheWrite() {
        val body = freshness.functionBody("fun recordInboxSweep(")
        val latchChecks = body.occurrences("ProcessWipeLatch.wipedThisProcess")
        assertTrue("recordInboxSweep must consult the latch before reading AND re-check before the write (found $latchChecks)", latchChecks >= 3)
        val firstLatchAt = body.indexOf("ProcessWipeLatch.wipedThisProcess")
        val readAt = body.indexOf("store.getString(KEY_LAST_SWEEP)")
        val writeAt = body.indexOf("store.putString(KEY_LAST_SWEEP")
        val lastLatchAt = body.lastIndexOf("ProcessWipeLatch.wipedThisProcess")
        assertTrue(firstLatchAt in 0 until readAt)
        assertTrue("the re-check sits immediately before the write", readAt < lastLatchAt && lastLatchAt < writeAt)
        assertFalse("never apply()", body.contains("apply()"))
        assertTrue("the decision is the pure policy", body.contains("sweepStampAction("))
    }

    // -----------------------------------------------------------------------

    private fun mainSources(): List<File> =
        listOf(
            "androidApp/src/main/java/com/vg/run",
            "shared/src/commonMain/kotlin/com/vg/run",
            "shared/src/androidMain/kotlin/com/vg/run",
            "shared/src/iosMain/kotlin/com/vg/run",
        ).flatMap { dir ->
            File(repoRoot(), dir).walkTopDown().filter { it.isFile && it.extension == "kt" }.toList()
        }.sortedBy { it.path }

    private fun read(relativePath: String): String = File(repoRoot(), relativePath).readText()

    /** Brace-matched body of a function, same technique as [FcmNotificationDelegationSourceTest]. */
    private fun String.functionBody(signature: String): String {
        val fnStart = indexOf(signature)
        assertTrue("source must declare `$signature`", fnStart >= 0)
        val open = indexOf('{', fnStart)
        assertTrue("`$signature` must have a body", open >= 0)
        val end = substring(open).balancedBlockEnd()
        return substring(open, open + end)
    }

    /** Length of the `{`-balanced block that starts at this string's first `{`. */
    private fun String.balancedBlockEnd(): Int {
        val open = indexOf('{')
        assertTrue("block must open", open >= 0)
        var depth = 0
        var i = open
        while (i < length) {
            when (this[i]) {
                '{' -> depth++
                '}' -> { depth--; if (depth == 0) return i + 1 }
            }
            i++
        }
        throw AssertionError("block must be brace-balanced")
    }

    /** The full parenthesised call starting at [call], balanced by paren depth. */
    private fun String.functionCall(call: String): String {
        val start = indexOf(call)
        assertTrue("precondition: `$call` must exist", start >= 0)
        var depth = 0
        var i = start
        while (i < length) {
            when (this[i]) {
                '(' -> depth++
                ')' -> { depth--; if (depth == 0) return substring(start, i + 1) }
            }
            i++
        }
        throw AssertionError("precondition: `$call` call must be closed")
    }

    private fun String.occurrences(needle: String): Int {
        var n = 0
        var from = 0
        while (true) {
            val at = indexOf(needle, from)
            if (at < 0) return n
            n++
            from = at + needle.length
        }
    }
}
