package com.vg.run

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * "TransportFailedSends ledger survives lock/wipe when
 * the MessageManager is null" — the WIRING, on both platforms.
 *
 * The ledger (`TransportFailedSends.shared`, commonMain) is process-wide RAM
 * holding PLAINTEXT of 1:1 sends that failed on the transport. Its only clear
 * used to be `MessageManager.scrubInMemory()`, reached from lock / wipe only
 * through `messageManager?.scrubInMemory()`. Entries are recorded EXACTLY when
 * that manager is null (Android `sendMessageInBackground`, iOS
 * `AppState.sendMessage`), and Android nulls the manager on Tor Failed / Idle /
 * restart WITHOUT scrubbing — deliberately, so a parked send survives a
 * transport outage inside the unlocked session. So a lock or wipe taken while
 * Tor was down never cleared the ledger.
 *
 * What this pins:
 *  - `RunViewModel.lockSession` and `performEmergencyWipe` call
 *    `TransportFailedSends.shared.endSession()` UNCONDITIONALLY (bare statements at
 *    the function's own brace depth — not behind `messageManager?.`, not inside
 *    any `if`/`try` block) TWICE: once right after the manager is dropped, and
 *    once as the LAST statement, AFTER the Tor stop — stopping Tor is what fails
 *    an in-flight POST, i.e. exactly when a late send tries to re-park its
 *    plaintext. `endSession()` bumps the session epoch, so that late `record`
 *    (which carries the epoch captured when the send was enqueued) is refused;
 *  - `onVaultOpened` begins a new session epoch before anything else;
 *  - `onCleared` still routes through `lockSession`;
 *  - `IosAppController.lock()` and `emergencyWipe()` end it too (parity), through
 *    their shared tail `endSessionRam()`, and the iOS vault open
 *    (`adoptOpenedVault`, both `unlock` and `recoverWithCode`) begins one;
 *  - the Tor `Failed` / `Idle` branches and `restartTor()` null the manager but
 *    do NOT clear the ledger — the feature is that a parked send survives a
 *    transport outage within the session;
 *  - the two no-manager parking sites still exist (the reason the seam matters).
 *
 * SOURCE-LEVEL, same technique and reason as [PushWakeFreshnessWiringSourceTest]:
 * `RunViewModel` is an `AndroidViewModel` and `IosAppController` is iosMain,
 * neither constructible at this module's plain-JVM tier. Bodies are scanned with
 * comments STRIPPED so prose that merely names a call can neither satisfy nor
 * trip a guard.
 */
class TransportFailedSendsLockWiringSourceTest {

    private val viewModel: String by lazy { stripComments(read(SourcePins.RUN_VIEW_MODEL)) }
    private val iosController: String by lazy { stripComments(read("shared/src/iosMain/kotlin/com/vg/run/IosAppController.kt")) }
    private val appState: String by lazy { stripComments(iosAppStateSources()) }

    private companion object {
        const val CLEAR = "TransportFailedSends.shared.clear()"
        const val END = "TransportFailedSends.shared.endSession()"
        const val BEGIN = "TransportFailedSends.shared.beginSession()"
        const val IOS_END_RAM = "endSessionRam()"
        const val CANCEL_SENDS = "cancelInFlightSends()"
        const val RECORD_KT = "TransportFailedSends.shared.record("
        const val RECORD_SWIFT = "TransportFailedSends.companion.shared.record("
    }

    // -----------------------------------------------------------------------
    // 1. Android: lockSession + performEmergencyWipe end the session
    //    unconditionally, the last time after the Tor stop.
    // -----------------------------------------------------------------------

    @Test
    fun lockSession_endsTheSession_unconditionally_andLastAfterTheTorStop() {
        val body = viewModel.functionBody("private fun lockSession(stopTor: Boolean) {")
        body.assertUnconditionalTopLevelCalls(END, "lockSession", expected = 2)
        // The first one sits AFTER the manager is dropped: it must not depend on it.
        val nullAt = body.indexOf("messageManager = null")
        assertTrue("lockSession must still null the manager", nullAt >= 0)
        assertTrue("the first endSession must come after `messageManager = null`", nullAt < body.indexOf(END))
        // The in-flight send jobs are cancelled with it.
        val cancelAt = body.indexOf(CANCEL_SENDS)
        assertTrue("lockSession must cancel the in-flight sends", cancelAt >= 0)
        assertTrue("…before the first endSession", cancelAt < body.indexOf(END))
        // The last one comes after the Tor stop (or keep-alive hand-off).
        val torStopAt = body.lastIndexOf("tor.stop()")
        assertTrue("lockSession must still stop Tor", torStopAt >= 0)
        assertTrue("the final endSession must come AFTER the Tor stop", torStopAt < body.lastIndexOf(END))
        assertEquals(
            "endSession must be the function's last statement",
            END, body.trimEnd().removeSuffix("}").trimEnd().lines().last().trim(),
        )
    }

    @Test
    fun performEmergencyWipe_endsTheSession_unconditionally_andLastAfterTheTorStop() {
        val body = viewModel.functionBody("fun performEmergencyWipe(deniable: Boolean = true) {")
        body.assertUnconditionalTopLevelCalls(END, "performEmergencyWipe", expected = 2)
        // Crypto-erase-first: the clear is RAM-only and must come AFTER the
        // persistent wipe (never delay the erase), and after the manager is gone.
        val wipeAt = body.indexOf("WipeRoutine.wipePersistentState(app)")
        assertTrue("performEmergencyWipe must still crypto-erase through WipeRoutine", wipeAt >= 0)
        assertTrue("the ledger clear comes after the crypto-erase", wipeAt < body.indexOf(END))
        assertTrue(body.indexOf("messageManager = null") < body.indexOf(END))
        val cancelAt = body.indexOf(CANCEL_SENDS)
        assertTrue("performEmergencyWipe must cancel the in-flight sends", cancelAt in 0 until body.indexOf(END))
        val torStopAt = body.indexOf("torManager?.stopAndDiscardState()")
        assertTrue("performEmergencyWipe must still stop + discard Tor", torStopAt >= 0)
        assertTrue("the final endSession must come AFTER the Tor stop", torStopAt < body.lastIndexOf(END))
        assertEquals(
            "endSession must be the function's last statement",
            END, body.trimEnd().removeSuffix("}").trimEnd().lines().last().trim(),
        )
    }

    @Test
    fun onVaultOpened_beginsANewSessionFirst() {
        val body = viewModel.functionBody("fun onVaultOpened(openedVault: VaultDatabase) {")
        val beginAt = body.indexOf(BEGIN)
        assertTrue("onVaultOpened must begin a new session epoch", beginAt >= 0)
        assertTrue("…before the vault is published", beginAt < body.indexOf("vault = openedVault"))
        assertEquals("exactly one beginSession in RunViewModel", 1, viewModel.occurrences(BEGIN))
    }

    @Test
    fun onCleared_stillRoutesThroughLockSession() {
        val body = viewModel.functionBody("override fun onCleared() {")
        assertTrue("onCleared must call lockSession(stopTor = true)", body.contains("lockSession(stopTor = true)"))
    }

    @Test
    fun theAndroidEndSites_areTheOnlyOnes() {
        assertEquals(
            "RunViewModel must end the session at exactly the two session-ending seams (lock + wipe), twice each",
            4, viewModel.occurrences(END),
        )
        assertEquals("RunViewModel uses endSession(), not the epoch-less clear()", 0, viewModel.occurrences(CLEAR))
        val lock = viewModel.functionBody("private fun lockSession(stopTor: Boolean) {")
        val wipe = viewModel.functionBody("fun performEmergencyWipe(deniable: Boolean = true) {")
        assertEquals(2, lock.occurrences(END))
        assertEquals(2, wipe.occurrences(END))
    }

    // -----------------------------------------------------------------------
    // 2. Android: the transport-outage branches must NOT clear it.
    // -----------------------------------------------------------------------

    @Test
    fun torFailedAndIdleBranches_nullTheManager_butKeepTheParkedSends() {
        val monitor = viewModel.functionBody("private fun startTorMonitor(openedVault: VaultDatabase, tor: TorManager) {")
        // The monitor has an earlier, logging-only `when` over the same states; the
        // outage branches are the block-bodied ones that null the manager.
        val failedAt = monitor.indexOf("is TorManager.ConnectionState.Failed -> {")
        val bootstrappingAt = monitor.indexOf("is TorManager.ConnectionState.Bootstrapping ->", failedAt)
        assertTrue("the Tor monitor must still have the Failed branch", failedAt >= 0)
        assertTrue("…and the Bootstrapping branch after Failed/Idle", bootstrappingAt > failedAt)
        val outage = monitor.substring(failedAt, bootstrappingAt)
        assertTrue("precondition: the Failed branch nulls the manager", outage.contains("messageManager = null"))
        assertTrue("precondition: the Idle branch exists in the same span", outage.contains("is TorManager.ConnectionState.Idle ->"))
        assertEquals("Failed AND Idle both null the manager", 2, outage.occurrences("messageManager = null"))
        assertFalse(
            "a transport outage inside the unlocked session must NOT drop parked sends — that is the re-drive feature. Span was:\n$outage",
            outage.contains("TransportFailedSends"),
        )
    }

    @Test
    fun restartTor_nullsTheManager_butKeepsTheParkedSends() {
        val body = viewModel.functionBody("private fun restartTor() {")
        assertTrue("precondition: restartTor nulls the manager", body.contains("messageManager = null"))
        assertFalse("a self-heal restart must not drop parked sends. Body was:\n$body", body.contains("TransportFailedSends"))
    }

    // -----------------------------------------------------------------------
    // 3. iOS parity: IosAppController.lock() + emergencyWipe().
    // -----------------------------------------------------------------------

    // The common tail of lock() and emergencyWipe() is endSessionRam(): each
    // calls it exactly once, unconditionally, and it ends the session (bump +
    // clear) unconditionally after dropping the manager — same property as the
    // Android pins above.

    @Test
    fun iosLock_endsTheSession_unconditionally() {
        val body = iosController.functionBody("fun lock() {")
        body.assertUnconditionalTopLevelCalls(IOS_END_RAM, "IosAppController.lock", expected = 1)
        assertTrue("lock must close the vault before ending the session RAM",
            body.indexOf("vault = null") in 0 until body.indexOf(IOS_END_RAM))
    }

    // The ACK FENCE (LockAckFenceTest): a closed iOS vault reads as "no rows", so the
    // MessageManager's acks must be closed BEFORE the close. The pin above (the full
    // endSessionRam() scrub stays AFTER `vault = null`) is unchanged.
    @Test
    fun iosLock_fencesAcksBeforeTheVaultCloses() {
        val body = iosController.functionBody("fun lock() {")
        val fence = body.indexOf("messageManager?.scrubInMemory()")
        assertTrue("lock must fence the MessageManager's acks BEFORE closing the vault",
            fence in 0 until body.indexOf("vault?.close()"))
    }

    @Test
    fun iosEmergencyWipe_endsTheSession_unconditionally() {
        val body = iosController.functionBody("fun emergencyWipe() {")
        body.assertUnconditionalTopLevelCalls(IOS_END_RAM, "IosAppController.emergencyWipe", expected = 1)
        assertTrue("the wipe ends the session RAM after the crypto-erase",
            body.indexOf("KeychainBridgeHolder.bridge?.deleteKey()") in 0 until body.indexOf(IOS_END_RAM))
    }

    @Test
    fun iosEndSessionRam_endsTheLedgerSession_afterDroppingTheManager() {
        val body = iosController.functionBody("private fun endSessionRam() {")
        body.assertUnconditionalTopLevelCalls(END, "IosAppController.endSessionRam", expected = 1)
        assertTrue(body.indexOf("messageManager = null") in 0 until body.indexOf(END))
    }

    @Test
    fun theIosEndSites_areTheOnlyOnes() {
        assertEquals("IosAppController ends the session in endSessionRam only", 1, iosController.occurrences(END))
        assertEquals("IosAppController uses endSession(), not the epoch-less clear()", 0, iosController.occurrences(CLEAR))
        assertEquals(
            "endSessionRam is called from lock + emergencyWipe only",
            2, Regex("""(?m)^\s*endSessionRam\(\)\s*$""").findAll(iosController).count(),
        )
    }

    @Test
    fun iosVaultOpen_beginsANewSessionFirst() {
        val body = iosController.functionBody("private fun adoptOpenedVault(opened: VaultDatabase) {")
        val beginAt = body.indexOf(BEGIN)
        assertTrue("adoptOpenedVault must begin a new session epoch", beginAt >= 0)
        assertTrue("…before the vault is published", beginAt < body.indexOf("vault = opened"))
        assertTrue("…before the session managers are built", beginAt < body.indexOf("createSessionManagers("))
        assertEquals("exactly one beginSession in IosAppController", 1, iosController.occurrences(BEGIN))
        for (open in listOf("fun unlock(credential: String): Int {", "fun recoverWithCode(recoveryCode: String, credential: String): Int {")) {
            assertTrue("$open must wire the opened vault through adoptOpenedVault",
                iosController.functionBody(open).contains("adoptOpenedVault(result.vault)"))
        }
    }

    // -----------------------------------------------------------------------
    // 4. The no-manager parking sites still exist on both platforms — the
    //    state the seam exists for.
    // -----------------------------------------------------------------------

    @Test
    fun androidParksDirectly_whenTheManagerIsNull() {
        val body = viewModel.functionBody("fun sendMessageInBackground(contactId: String, text: String, redriveToken: String? = null, onDelivered: () -> Unit) {")
        val nullCheckAt = body.indexOf("if (mm == null) {")
        val recordAt = body.indexOf(RECORD_KT)
        assertTrue("the null-manager branch must exist", nullCheckAt >= 0)
        assertTrue("…and park into the shared ledger", recordAt > nullCheckAt)
        val branch = body.substring(nullCheckAt).let { it.substring(0, it.balancedBlockEnd()) }
        assertTrue("the record sits INSIDE the null-manager branch", branch.contains(RECORD_KT))
        // …under the epoch captured when the send was ENQUEUED, not a fresh read.
        assertTrue(
            "the park must pass the enqueue-time epoch:\n$branch",
            branch.contains("$RECORD_KT" + "token, contactId, text, false, onRedriven, sendEpoch)"),
        )
        val captureAt = body.indexOf("val sendEpoch = TransportFailedSends.shared.sessionEpoch")
        assertTrue("sendEpoch must be captured before the send job is launched", captureAt in 0 until body.indexOf("viewModelScope.launch("))
        assertTrue("the send job must be tracked for lock/wipe cancellation", body.contains("inFlightSendJobs.add(job)"))
    }

    @Test
    fun iosParksDirectly_whenTheManagerIsNil() {
        val guardAt = appState.indexOf("guard let msgManager else {")
        val recordAt = appState.indexOf(RECORD_SWIFT)
        assertTrue("AppState.sendMessage's no-manager guard must exist", guardAt >= 0)
        assertTrue("…and park into the shared ledger", recordAt > guardAt)
        val branch = appState.substring(guardAt).let { it.substring(0, it.balancedBlockEnd()) }
        assertTrue("the record sits INSIDE the nil-manager guard", branch.contains(RECORD_SWIFT))
    }

    // -----------------------------------------------------------------------

    /**
     * The call must appear exactly [expected] times, each as a bare statement at the
     * function's own brace depth (depth 1 inside the body's outer braces) — i.e. not
     * behind a `?.` receiver, not inside an `if`, `try`, lambda or `when` branch.
     */
    private fun String.assertUnconditionalTopLevelCalls(call: String, where: String, expected: Int) {
        assertTrue("$where must call `$call`. Body was:\n$this", indexOf(call) >= 0)
        assertEquals("$where must call `$call` exactly $expected time(s)", expected, occurrences(call))
        var at = indexOf(call)
        while (at >= 0) {
            // Bare statement: the line is nothing but the call.
            val lineStart = lastIndexOf('\n', at) + 1
            val lineEnd = indexOf('\n', at).let { if (it < 0) length else it }
            assertEquals("$where: `$call` must be a bare statement, not a guarded/receiver call", call, substring(lineStart, lineEnd).trim())
            // Depth: count braces from the body's opening brace up to the call.
            var depth = 0
            for (i in 0 until at) {
                when (this[i]) {
                    '{' -> depth++
                    '}' -> depth--
                }
            }
            assertEquals("$where: `$call` must sit at the function's own brace depth (unconditional), was depth $depth", 1, depth)
            at = indexOf(call, at + call.length)
        }
    }

    private fun read(relativePath: String): String = File(repoRoot(), relativePath).readText()

    /** Brace-matched body of a function, same technique as [PushWakeFreshnessWiringSourceTest]. */
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
