package com.vg.run

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The PROCESS-wide receive state (`TextLeaseLedger` — contact ids + lease tokens —
 * and the uncommitted-legacy registry — contact id, inbox id, read capability,
 * lease token per part) is ended at lock and at wipe UNCONDITIONALLY on both
 * platforms, through `MessageManager.endProcessReceiveSession()`.
 *
 * Why it cannot ride `messageManager?.scrubInMemory()` alone: Android nulls the
 * manager WITHOUT a scrub on Tor Failed / Idle / restart (so a parked send survives
 * the outage), and the lock / wipe that follows then has no manager to scrub — the
 * same gap `TransportFailedSendsLockWiringSourceTest` pins for the parked-send
 * ledger, with the same technique (comment-stripped source, bare statements at the
 * function's own brace depth).
 */
class ProcessReceiveSessionWiringSourceTest {

    private val viewModel: String by lazy { stripComments(read(SourcePins.RUN_VIEW_MODEL)) }
    private val iosController: String by lazy { stripComments(read("shared/src/iosMain/kotlin/com/vg/run/IosAppController.kt")) }
    private val messageManager: String by lazy {
        stripComments(read("shared/src/commonMain/kotlin/com/vg/run/MessageManager.kt"))
    }

    private companion object {
        const val END = "MessageManager.endProcessReceiveSession()"
        const val TFS_END = "TransportFailedSends.shared.endSession()"
    }

    @Test
    fun lockSession_endsTheReceiveSession_unconditionally_afterTheManagerDrop_andAfterTheTorStop() {
        val body = viewModel.functionBody("private fun lockSession(stopTor: Boolean) {")
        body.assertUnconditionalTopLevelCalls(END, "lockSession", expected = 2)
        assertTrue("the first end comes after `messageManager = null`",
            body.indexOf("messageManager = null") in 0 until body.indexOf(END))
        assertTrue("the second comes after the Tor stop", body.lastIndexOf("tor.stop()") < body.lastIndexOf(END))
        assertTrue("…and before the parked-send ledger's final end", body.lastIndexOf(END) < body.lastIndexOf(TFS_END))
    }

    @Test
    fun performEmergencyWipe_endsTheReceiveSession_unconditionally_afterTheErase_andAfterTheTorStop() {
        val body = viewModel.functionBody("fun performEmergencyWipe(deniable: Boolean = true) {")
        body.assertUnconditionalTopLevelCalls(END, "performEmergencyWipe", expected = 2)
        assertTrue("crypto-erase first: the RAM clear comes after WipeRoutine",
            body.indexOf("WipeRoutine.wipePersistentState(app)") in 0 until body.indexOf(END))
        assertTrue(body.indexOf("messageManager = null") in 0 until body.indexOf(END))
        assertTrue("the second comes after the Tor stop",
            body.indexOf("torManager?.stopAndDiscardState()") < body.lastIndexOf(END))
    }

    @Test
    fun theTransportOutagePaths_doNotEndTheReceiveSession() {
        // Mid-session: a Tor outage keeps the session, and with it the guards and any
        // uncommitted screen drain the re-drive still needs.
        assertFalse(viewModel.functionBody("private fun restartTor() {").contains(END))
        val monitor = viewModel.functionBody("private fun startTorMonitor(openedVault: VaultDatabase, tor: TorManager) {")
        assertFalse(monitor.contains(END))
        assertEquals("Android ends it at lock + wipe only, twice each", 4, viewModel.occurrences(END))
    }

    @Test
    fun iosEndSessionRam_endsTheReceiveSession_unconditionally() {
        val body = iosController.functionBody("private fun endSessionRam() {")
        body.assertUnconditionalTopLevelCalls(END, "IosAppController.endSessionRam", expected = 1)
        assertTrue(body.indexOf("messageManager = null") in 0 until body.indexOf(END))
        assertEquals("IosAppController ends it in endSessionRam only", 1, iosController.occurrences(END))
        // endSessionRam is the shared tail of lock() and emergencyWipe().
        for (sig in listOf("fun lock() {", "fun emergencyWipe() {")) {
            assertTrue("$sig must reach endSessionRam", iosController.functionBody(sig).contains("endSessionRam()"))
        }
    }

    @Test
    fun theManagerScrub_stillEndsTheLedger_andAClosedManagerTakesNoMark() {
        val scrub = messageManager.functionBody("fun scrubInMemory() {")
        assertTrue(scrub.contains("TextLeaseLedger.scrub()"))
        val fetch = messageManager.functionBody("internal fun fetchDrain(p: PreparedDrain): HttpResult? {")
        assertTrue("the in-flight mark is gated on the instance not being closed",
            fetch.contains("if (p.chan == Chan.MAIN && !acksClosed) p.leaseMark = TextLeaseLedger.beginFetch(p.contactId, receiveEpoch)"))
        assertTrue("…and taken BEFORE the GET",
            fetch.indexOf("TextLeaseLedger.beginFetch") < fetch.indexOf("httpClient.get("))
    }

    // -----------------------------------------------------------------------

    private fun String.assertUnconditionalTopLevelCalls(call: String, where: String, expected: Int) {
        assertEquals("$where must call `$call` exactly $expected time(s)", expected, occurrences(call))
        var at = indexOf(call)
        while (at >= 0) {
            val lineStart = lastIndexOf('\n', at) + 1
            val lineEnd = indexOf('\n', at).let { if (it < 0) length else it }
            assertEquals("$where: `$call` must be a bare statement", call, substring(lineStart, lineEnd).trim())
            var depth = 0
            for (i in 0 until at) {
                when (this[i]) {
                    '{' -> depth++
                    '}' -> depth--
                }
            }
            assertEquals("$where: `$call` must sit at the function's own brace depth (unconditional)", 1, depth)
            at = indexOf(call, at + call.length)
        }
    }

    private fun read(relativePath: String): String = File(repoRoot(), relativePath).readText()

    private fun String.functionBody(signature: String): String {
        val fnStart = indexOf(signature)
        assertTrue("source must declare `$signature`", fnStart >= 0)
        val open = indexOf('{', fnStart)
        var depth = 0
        var i = open
        while (i < length) {
            when (this[i]) {
                '{' -> depth++
                '}' -> { depth--; if (depth == 0) return substring(open, i + 1) }
            }
            i++
        }
        throw AssertionError("`$signature` must be brace-balanced")
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
