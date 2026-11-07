package com.vg.run

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The "move-handle lifetime" cluster, pinned at the SOURCE level on BOTH platforms.
 *
 * Why these four are one file: they are four leaks of the SAME secret. A
 * transfer handle is `inboxId | readCap | code`; the read capability is the
 * inbox OWNER capability and the code is the 160-bit HKDF input that unseals the
 * bundle. Together they export the whole vault — and the seal's key is derived
 * from the code alone, so locking, closing or even CRYPTO-ERASING the vault does
 * not reach a handle that is still in RAM or on a clipboard. The handle
 * therefore has to be bounded by the SESSION (lock/wipe) and by the SCREEN, and
 * it must never reach an unguarded system clipboard.
 *
 * SOURCE-LEVEL for the reason this file's siblings state: `RunViewModel` is an
 * `AndroidViewModel` needing a real `Application`, and the iOS halves are Swift.
 * The RUNTIME companion is `MoveHandleLifetimeTest` (commonTest), which pins the
 * `MoveManager` state-machine behaviour these teardowns depend on. Bodies are
 * scanned with comments STRIPPED, so prose that merely names a call can neither
 * satisfy nor trip a guard.
 */
class MoveHandleLifetimeSourceTest {

    private val viewModel: String by lazy { read(SourcePins.RUN_VIEW_MODEL) }
    private val appState: String by lazy { stripComments(iosAppStateSources()) }
    private val contentView: String by lazy { read("iosApp/iosApp/ContentView.swift") }
    private val controller: String by lazy { read("shared/src/iosMain/kotlin/com/vg/run/IosAppController.kt") }
    private val moveImport: String by lazy { read("iosApp/iosApp/MoveFromDeviceView.swift") }
    private val moveScreenKt: String by lazy { read(SourcePins.MOVE_TO_NEW_DEVICE_SCREEN) }
    private val moveScreenSwift: String by lazy { read("iosApp/iosApp/MoveToNewDeviceView.swift") }

    // -----------------------------------------------------------------------
    // Both move jobs belong on BOTH Android cancel lists
    // -----------------------------------------------------------------------

    /**
     * The wipe half. Before the fix an in-flight export survived
     * `performEmergencyWipe`, finished over the Tor instance the wipe is about
     * to stop, and published `Ready(handle)` AFTER `scrubMoveSecrets()` had
     * already run — in a process the deniable path deliberately keeps alive.
     *
     * The cancel has to come BEFORE the scrub (and before the crypto-erase), or
     * the job simply re-plants what the scrub just dropped.
     *
     * Non-vacuousness: delete either cancel and this fails.
     */
    @Test
    fun emergencyWipe_cancelsBothMoveJobsBeforeItScrubsTheMoveSecrets() {
        val body = viewModel.functionBody("    fun performEmergencyWipe(deniable: Boolean = true) {")
        val opAt = sessionJobCancelIndex(viewModel, body, "moveOpJob")
        val pollAt = sessionJobCancelIndex(viewModel, body, "movePollJob")
        val scrubAt = body.indexOf("scrubMoveSecrets()")
        assertTrue(
            "performEmergencyWipe must cancel moveOpJob — an export finishing across the wipe " +
                "publishes the transfer code into a kept-alive process. Body was:\n$body",
            opAt >= 0,
        )
        assertTrue(
            "performEmergencyWipe must cancel movePollJob — the 10 s transfer peek keeps talking " +
                "to the relay with the transfer read capability after the crypto-erase",
            pollAt >= 0,
        )
        assertTrue("precondition: the wipe must still scrub the move secrets", scrubAt >= 0)
        assertTrue("the cancels must precede scrubMoveSecrets(), or the job re-plants what it dropped", opAt < scrubAt)
        assertTrue("…the same for the peek job", pollAt < scrubAt)
        assertTrue(
            "the cancels must also precede the crypto-erase, so nothing new goes on the wire after it",
            opAt < body.indexOf("WipeRoutine.wipePersistentState(app)"),
        )
        assertTrue(
            "the wipe must still drop the NEW phone's scanned handle",
            body.contains("pendingMoveHandle = null"),
        )
    }

    /**
     * The lock half. [RunViewModel.lockForReauth] keeps Tor AND this ViewModel
     * alive across the lock, so without these cancels an export ran to
     * completion and re-published the code, while an import held the scanned
     * handle for the rest of its transport-wait budget.
     */
    @Test
    fun lockSession_cancelsBothMoveJobsAndDropsTheScannedHandle() {
        val body = viewModel.functionBody("    private fun lockSession(stopTor: Boolean) {")
        val opAt = sessionJobCancelIndex(viewModel, body, "moveOpJob")
        val pollAt = sessionJobCancelIndex(viewModel, body, "movePollJob")
        val scrubAt = body.indexOf("scrubMoveSecrets()")
        assertTrue("lockSession must cancel moveOpJob. Body was:\n$body", opAt >= 0)
        assertTrue("lockSession must cancel movePollJob", pollAt >= 0)
        assertTrue("precondition: lockSession must still scrub the move secrets", scrubAt >= 0)
        assertTrue("the cancels must precede scrubMoveSecrets()", opAt < scrubAt)
        assertTrue("…the same for the peek job", pollAt < scrubAt)
        assertTrue(
            "the cancels must precede the vault close, so nothing in flight writes through a dead handle",
            opAt < body.indexOf("vault = null"),
        )
        assertTrue(
            "lockSession must still drop the NEW phone's scanned handle (read cap + one-time code)",
            body.contains("pendingMoveHandle = null"),
        )
    }

    // -----------------------------------------------------------------------
    // The iOS lock must drop the scanned handle too
    // -----------------------------------------------------------------------

    /**
     * `AppState.lock()` scrubbed the OLD phone's export code but left the NEW
     * phone's scanned handle resident. iOS keeps the process alive indefinitely
     * after a background lock, so that is a full vault-export credential sitting
     * in the RAM of a locked device — and its seal key is HKDF-derived from the
     * code, independently of the vault the line below closes.
     */
    @Test
    fun iosLock_dropsBothHalvesOfTheMoveSecret() {
        val body = appState.functionBody("    func lock() {")
        assertTrue(
            "lock() must scrub the OLD phone's one-time export code. Body was:\n$body",
            body.contains("controller.moveScrubExportCode()"),
        )
        assertTrue(
            "lock() must drop the NEW phone's scanned handle — Android's lockSession always does — " +
                "It carries the inbox read capability AND the one-time code.",
            body.contains("pendingMoveHandle = nil"),
        )
        // The wipe sibling already did it; keep the two from drifting.
        val wipe = appState.functionBody("    func emergencyWipe(deniable: Bool = true) {")
        assertTrue("emergencyWipe must keep dropping the scanned handle", wipe.contains("pendingMoveHandle = nil"))
    }

    /**
     * The sibling `lock()` can never reach: every `AppState.lock()` call site is
     * gated on a prior unlock, but the handle is scanned BEFORE onboarding and
     * lives across the whole PIN/passphrase setup. A background in that window
     * is the pre-unlock branch of ContentView's scenePhase handler. Android drops
     * it there too (onStop → finishAndRemoveTask → onCleared → lockSession).
     */
    @Test
    fun iosPreUnlockBackground_dropsTheScannedHandle() {
        val sweepAt = contentView.indexOf("appState.sweepDeliveredNotificationsWhileLocked()")
        // From `sweepAt`, not from 0: the import screen's `onFinished` closure
        // clears the same field far earlier in the file.
        val dropAt = contentView.indexOf("appState.pendingMoveHandle = nil", sweepAt)
        // The recycle condition gained a `!keepingTor,` guard with the bounded
        // Tor keep-alive (2026-10-23); anchor on the condition itself.
        val recycleAt = contentView.indexOf(
            "TorManager.shared.relaunchRequired || ExternalProxyMode.shared.isExternalThisProcess",
        )
        assertTrue("precondition: the locked-background branch must still sweep notifications", sweepAt >= 0)
        assertTrue("precondition: the process-recycle check must still follow that branch", recycleAt > sweepAt)
        assertTrue(
            "the PRE-UNLOCK background must drop the scanned transfer handle — it is the one " +
                "window lock() cannot reach, and it spans the whole of onboarding",
            dropAt >= 0,
        )
        assertTrue(
            "…and it must sit inside the locked-background branch, not somewhere else in the file",
            dropAt in (sweepAt + 1) until recycleAt,
        )
    }

    // -----------------------------------------------------------------------
    // The import wait must be owned by the session, not by a stray Task
    // -----------------------------------------------------------------------

    /**
     * `MoveImportView.startImport()` used to spin an UNOWNED `Task` whose only
     * loop condition was `messageManager == nil` — and a lock is precisely what
     * makes that nil, so the loop, and the handle it had captured, outlived the
     * lock for the whole budget. The wait now runs on `moveScope`, which both
     * `IosAppController.lock()` and `emergencyWipe()` cancel.
     */
    @Test
    fun iosImportWait_runsOnTheCancellableMoveScope_notInAnUnownedTask() {
        val body = moveImport.functionBody("    private func startImport() {")
        assertFalse(
            "the 300 s wait must NOT live in this view any more — `messageManager == nil` is " +
                "exactly what a lock produces, so the loop survived the lock. Body was:\n$body",
            body.contains("while appState.controller.messageManager == nil"),
        )
        assertTrue(
            "the task must be OWNED so it can be cancelled with the screen",
            body.contains("importTask = Task"),
        )
        assertTrue(
            "…and it must re-check the session before handing the handle across the bridge: the " +
                "task is main-actor ENQUEUED, so a lock can land between startImport() and its body",
            body.contains("appState.isUnlocked"),
        )
        assertTrue(
            "the view must cancel the owned task when it leaves",
            moveImport.contains("importTask?.cancel()"),
        )
        assertTrue(
            "…from onDisappear, so the screen's lifetime bounds it",
            moveImport.indexOf(".onDisappear") in 0 until moveImport.indexOf("importTask?.cancel()"),
        )

        val wait = controller.functionBody("    private suspend fun awaitMoveTransport() {")
        assertTrue(
            "IosAppController must own the bounded wait, and it must be a cancellable delay loop " +
                "(a blocking wait cannot be cut by moveScope). Body was:\n$wait",
            wait.contains("delay(MOVE_TRANSPORT_POLL_MS)"),
        )
        val importBridge = controller.functionBody("    fun moveImportFromHandle(")
        assertTrue(
            "moveImportFromHandle must run the wait inside its moveScope launch",
            importBridge.indexOf("moveScope.launch") in 0 until importBridge.indexOf("awaitMoveTransport()"),
        )
        for (entry in listOf("    fun lock() {", "    fun emergencyWipe() {")) {
            assertTrue(
                "`$entry` must cancel moveScope's children — that is what now reaches the import wait",
                controller.functionBody(entry).contains("moveScope.coroutineContext.cancelChildren()"),
            )
        }
    }

    // -----------------------------------------------------------------------
    // The handle is readable, never selectable
    // -----------------------------------------------------------------------

    /**
     * Rendering the handle as SELECTABLE text hands it to the system Copy
     * action, which writes an unguarded clip: on Android with no
     * `EXTRA_IS_SENSITIVE` and no timed clear, on iOS without `.localOnly`, so
     * Universal Clipboard can carry a full vault-export credential to every
     * other device on the Apple ID. Both screens already ship a guarded copy
     * button; that is the only copy path.
     */
    @Test
    fun theTransferHandleIsNotSelectableOnEitherPlatform() {
        assertFalse(
            "MoveToNewDeviceScreen must not wrap the handle in a SelectionContainer",
            moveScreenKt.contains("SelectionContainer"),
        )
        assertTrue(
            "…but it must still expose the handle for reading (the e2e reads this node)",
            moveScreenKt.contains("""testTag("move_handle_text")"""),
        )
        assertTrue(
            "…and keep the guarded copy button as the only copy path",
            moveScreenKt.contains("""testTag = "move_copy_button""""),
        )

        assertFalse(
            "MoveToNewDeviceView must not enable text selection on the handle",
            moveScreenSwift.contains(".textSelection(.enabled)"),
        )
        assertTrue(
            "…but it must still publish the handle as an a11y value (the e2e reads `value` first)",
            moveScreenSwift.contains(".accessibilityValue(handleText)"),
        )
        assertTrue(
            "…and keep the guarded copy button",
            moveScreenSwift.contains("""accessibilityIdentifier("move_copy_button")"""),
        )
    }

    /** The guards the copy BUTTON provides, and which the removed selection path had none of. */
    @Test
    fun theGuardedCopyButtonsKeepTheirGuards() {
        val copy = moveScreenKt.functionBody(
            "private fun copyTransferHandle(context: android.content.Context, text: String) {"
        )
        // The copy goes through the shared helper, with a timed clear…
        assertTrue(
            "the Android copy must go through SensitiveClipboard with a timed clear. Body was:\n$copy",
            copy.contains("SensitiveClipboard.copy(context, \"transfer\", text, clearAfterMs = 60_000)"),
        )
        // …and the helper is what flags the clip sensitive and clears it.
        val helper = read("androidApp/src/main/java/com/vg/run/SensitiveClipboard.kt")
        assertTrue(
            "SensitiveClipboard must flag the clip sensitive (suppresses preview/history)",
            helper.contains("ClipDescription.EXTRA_IS_SENSITIVE"),
        )
        assertTrue("…and self-clear it", helper.contains("clearPrimaryClip()"))

        val swiftCopy = moveScreenSwift.functionBody("    private func copyHandle() {")
        // The iOS copy goes through the shared helper, with an expiration and a timed clear…
        assertTrue(
            "the iOS copy must go through SensitivePasteboard with a 120 s expiration and a " +
                "60 s timed clear. Body was:\n$swiftCopy",
            swiftCopy.contains("SensitivePasteboard.copy(handleText, expiresAfter: 120, clearAfter: 60)"),
        )
        assertFalse(
            "…and must not write the pasteboard directly (bypassing the local-only helper). Body was:\n$swiftCopy",
            swiftCopy.contains("UIPasteboard"),
        )
        // …and the helper is what keeps it local-only, expiring and self-clearing.
        val swiftHelper = read("iosApp/iosApp/UIComponents.swift")
            .functionBody("    static func copy(_ value: String, expiresAfter: TimeInterval, clearAfter: TimeInterval?) {")
        assertTrue(
            "the iOS copy must stay local-only — Universal Clipboard would put the handle on " +
                "every device on the Apple ID. SensitivePasteboard.copy was:\n$swiftHelper",
            swiftHelper.contains("UIPasteboard.general.setItems(") && swiftHelper.contains(".localOnly: true"),
        )
        assertTrue("…and carry an expiration",
            swiftHelper.contains(".expirationDate: Date().addingTimeInterval(expiresAfter)"))
        assertTrue("…and clear only its own value after clearAfter",
            swiftHelper.contains("if UIPasteboard.general.string == value {") &&
                swiftHelper.contains("UIPasteboard.general.items = []"))
    }

    // -----------------------------------------------------------------------
    // Helpers — see [PeriodicReauthLockSourceTest], same walk, same contract.
    // -----------------------------------------------------------------------

    private fun read(relativePath: String): String =
        stripComments(File(repoRoot(), relativePath).readText())

    private fun String.functionBody(signature: String): String {
        val start = indexOf(signature)
        assertTrue("precondition: `$signature` must exist", start >= 0)
        val indent = signature.takeWhile { it == ' ' }
        val closer = "\n$indent}"
        val end = indexOf(closer, start)
        assertTrue("precondition: `$signature` must be closed", end > start)
        return substring(start, end)
    }
}
