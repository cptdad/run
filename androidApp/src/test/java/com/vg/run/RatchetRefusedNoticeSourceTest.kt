package com.vg.run

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Guards the ratchet-refused UI consumer:
 * `MessageManager.ratchetRefused(contactId)` shipped in commonMain with no UI
 * consumer. This wires it into the 1:1 conversation screen mirroring EXACTLY how
 * [ForwardSecrecyStalledNoticeSourceTest] guards `fs_stalled_notice` — same
 * technique, same reason (`RunViewModel`/`ConversationScreen`/`ConversationView`
 * need a live vault + relay this module's unit-test tier can't provide, so the
 * decision under test is checked structurally). Bodies are scanned with comments
 * STRIPPED so prose that merely names a call can neither satisfy nor trip a guard.
 *
 * Two behaviors this signal adds beyond `fs_stalled_notice`'s shape, both
 * asserted below:
 *  - it GATES the retry loop (a refused send makes zero HTTP attempts), not just
 *    advises after the fact;
 *  - it is re-read on every poll tick, not only open + after-send, because it is
 *    cleared by an INBOUND ratchet blob rather than only by this device's own
 *    send landing.
 */
class RatchetRefusedNoticeSourceTest {

    private val viewModel: String by lazy {
        SourcePins.stripped(SourcePins.RUN_VIEW_MODEL)
    }
    private val conversationScreen: String by lazy {
        SourcePins.stripped(SourcePins.CONVERSATION_SCREEN)
    }
    private val groupConversationScreen: String by lazy {
        SourcePins.stripped(SourcePins.GROUP_CONVERSATION_SCREEN)
    }
    private val appState: String by lazy {
        stripComments(iosAppStateSources())
    }
    private val conversationView: String by lazy {
        stripComments(File(repoRoot(), "iosApp/iosApp/ConversationView.swift").readText())
    }
    private val groupViews: String by lazy {
        stripComments(File(repoRoot(), "iosApp/iosApp/GroupViews.swift").readText())
    }

    // -----------------------------------------------------------------------
    // 1. Android: RunViewModel exposes the flag and refreshes it correctly
    // -----------------------------------------------------------------------

    @Test
    fun runViewModel_exposesAPerContactRefusedMap() {
        assertTrue(
            "RunViewModel must expose ratchetRefused as a Map-shaped StateFlow, mirroring " +
                "forwardSecrecyStalled — a per-contact flag, not a single global Boolean",
            viewModel.contains("val ratchetRefused: StateFlow<Map<String, Boolean>>"),
        )
    }

    /**
     * Non-vacuousness: replacing `messageManager?.ratchetRefused(contactId) ?: false` with a
     * bare (non-null-safe) call fails this — a null transport must read as "not refused",
     * never crash or false-positive (which would tell a user to re-pair a healthy contact).
     */
    @Test
    fun refreshRatchetRefused_isNullSafeTowardNotRefused() {
        val fn = viewModel.functionBody("    fun refreshRatchetRefused(contactId: String) {")
        assertTrue(
            "refreshRatchetRefused must read through messageManager with a null-safe " +
                "fallback to false. Body was:\n$fn",
            fn.contains("messageManager?.ratchetRefused(contactId) ?: false"),
        )
    }

    /**
     * The refusal must be checked BEFORE the retry loop and, when true, skip it entirely —
     * zero HTTP attempts, matching MessageManager's own no-throw refusal contract. Also must
     * be recomputed once the whole attempt (retried or skipped) concludes, exactly like
     * forwardSecrecyStalled.
     *
     * Non-vacuousness: moving the refusal check inside the `for` loop, or deleting it, fails
     * the ordering assertion; moving the refresh into the `if (sent)` branch, or deleting it,
     * fails the refresh assertion.
     */
    @Test
    fun sendMessageInBackground_shortCircuitsBeforeRetryAndRefreshesOnBothOutcomes() {
        val fn = viewModel.functionBody(
            "    fun sendMessageInBackground(contactId: String, text: String, redriveToken: String? = null, onDelivered: () -> Unit) {",
        )
        val refusedCheckAt = fn.indexOf("messageManager?.ratchetRefused(contactId)")
        val retryLoopAt = fn.indexOf("for (attempt in 1..3)")
        val ifSentAt = fn.indexOf("if (sent) {")
        val elseAt = fn.indexOf("} else {", ifSentAt)
        val elseCloseAt = fn.indexOf("}", elseAt + "} else {".length)
        val refreshAt = fn.indexOf("refreshRatchetRefused(contactId)")
        assertTrue("precondition: the retry loop must exist", retryLoopAt >= 0)
        assertTrue("precondition: the success/failure branch must exist", ifSentAt >= 0)
        assertTrue("precondition: the else branch must exist", elseAt >= 0)
        assertTrue(
            "sendMessageInBackground must read messageManager.ratchetRefused(contactId). Body " +
                "was:\n$fn",
            refusedCheckAt >= 0,
        )
        assertTrue(
            "the refusal must be checked BEFORE the retry loop, so a refused send makes ZERO " +
                "HTTP attempts, not a check made mid- or post-loop",
            refusedCheckAt in 0 until retryLoopAt,
        )
        assertTrue(
            "sendMessageInBackground must call refreshRatchetRefused(contactId). Body was:\n$fn",
            refreshAt >= 0,
        )
        assertTrue(
            "the refresh must come AFTER the if/else — so it runs on BOTH outcomes, not just " +
                "the success branch",
            refreshAt > elseCloseAt,
        )
    }

    // -----------------------------------------------------------------------
    // 2. Android: the conversation screen refreshes on open, on every poll
    //    tick, renders the notice for 1:1 only with PRECEDENCE over
    //    fs_stalled_notice, never for groups
    // -----------------------------------------------------------------------

    @Test
    fun conversationScreen_refreshesOnOpen() {
        assertTrue(
            "ConversationScreen must refresh ratchetRefused when the conversation opens, " +
                "alongside refreshForwardSecrecyStalled",
            conversationScreen.contains("viewModel.refreshRatchetRefused(contactId)"),
        )
    }

    @Test
    fun conversationScreen_refreshesOnEveryPollTick() {
        // Unlike forwardSecrecyStalled (open + after-send only), this signal is cleared by an
        // INBOUND ratchet blob, so it must ALSO be re-read inside the poll loop — i.e. there
        // must be a second call site beyond the on-open one.
        val occurrences = Regex("viewModel\\.refreshRatchetRefused\\(contactId\\)")
            .findAll(conversationScreen).count()
        assertTrue(
            "ConversationScreen must call refreshRatchetRefused both on open AND inside the " +
                "poll loop (>= 2 call sites); found $occurrences",
            occurrences >= 2,
        )
    }

    @Test
    fun conversationScreen_rendersTheNoticeGatedOnTheMapWithPrecedence() {
        assertTrue(
            "ConversationScreen must collect viewModel.ratchetRefused",
            conversationScreen.contains("viewModel.ratchetRefused.collectAsState()"),
        )
        assertTrue(
            "ConversationScreen must carry the ratchet_refused_notice a11y test tag — the e2e " +
                "suite and any future test key on this exact id; never rename it",
            conversationScreen.contains("\"ratchet_refused_notice\""),
        )
        val ratchetCheckAt = conversationScreen.indexOf("ratchetRefusedContacts[contactId] == true")
        val fsCheckAt = conversationScreen.indexOf("fsStalledContacts[contactId] == true")
        assertTrue("precondition: both gates must exist", ratchetCheckAt >= 0 && fsCheckAt >= 0)
        assertTrue(
            "the ratchet-refused gate must be checked BEFORE (and win precedence over) the " +
                "forward-secrecy-stalled gate — both would otherwise render at once",
            ratchetCheckAt < fsCheckAt,
        )
    }

    @Test
    fun groupConversationScreen_hasNoRatchetRefusedNotice() {
        assertFalse(
            "the ratchet-refused signal is per 1:1 contact, same scope as " +
                "forwardSecrecyStalled — GroupConversationScreen must not reference it",
            groupConversationScreen.contains("ratchetRefused") ||
                groupConversationScreen.contains("ratchet_refused_notice"),
        )
    }

    // -----------------------------------------------------------------------
    // 3. iOS parity: AppState exposes the same shape, ConversationView wires
    //    the same refresh points (open + every poll tick + after send), the
    //    same short-circuit, the same a11y id and precedence, GroupViews
    //    stays untouched
    // -----------------------------------------------------------------------

    @Test
    fun appState_exposesAPerContactRefusedMap() {
        assertTrue(
            "AppState must expose ratchetRefused as a [String: Bool] — mirroring " +
                "forwardSecrecyStalled, matching RunViewModel's per-contact map shape",
            appState.contains("@Published var ratchetRefused: [String: Bool] = [:]"),
        )
    }

    @Test
    fun conversationView_refreshesOnAppearAndOnEveryPollTickAndAfterSend() {
        assertTrue(
            "ConversationView.onAppear must refresh ratchetRefused when the conversation opens",
            conversationView.functionBody("        .onAppear  {")
                .contains("appState.refreshRatchetRefused(contactId: contactId)"),
        )
        val occurrences = Regex("appState\\.refreshRatchetRefused\\(contactId: contactId\\)")
            .findAll(conversationView).count()
        assertTrue(
            "ConversationView must refresh ratchetRefused at (at least) onAppear, inside the " +
                "poll loop, and after the send retry sequence — 3 call sites; found $occurrences",
            occurrences >= 3,
        )
    }

    @Test
    fun conversationView_sendMessage_shortCircuitsBeforeRetry() {
        // The 1:1 retry loop is AppState.runDirectSendLoop (shared with the group
        // screen's private reply); ConversationView.sendMessage must route through it.
        val send = conversationView.functionBody("    private func sendMessage() {")
        assertTrue(
            "ConversationView.sendMessage must deliver through appState.runDirectSendLoop(. Body was:\n$send",
            send.contains("appState.runDirectSendLoop("),
        )
        val fn = appState.functionBody("    func runDirectSendLoop(")
        val refusedCheckAt = fn.indexOf("controller.ratchetRefused(contactId: contactId)")
        val retryLoopAt = fn.indexOf("for attempt in 1...maxRetries")
        assertTrue("precondition: the retry loop must exist", retryLoopAt >= 0)
        assertTrue(
            "runDirectSendLoop must read controller.ratchetRefused(contactId:). Body was:\n$fn",
            refusedCheckAt >= 0,
        )
        assertTrue(
            "the refusal must be checked BEFORE the retry loop, so a refused send makes ZERO " +
                "HTTP attempts",
            refusedCheckAt in 0 until retryLoopAt,
        )
    }

    @Test
    fun conversationView_rendersTheNoticeWithTheSameA11yIdAndPrecedence() {
        assertTrue(
            "ConversationView must gate the notice on appState.ratchetRefused[contactId]",
            conversationView.contains("appState.ratchetRefused[contactId] == true"),
        )
        assertTrue(
            "ConversationView must carry the SAME ratchet_refused_notice a11y identifier as " +
                "Android — e2e/a11y parity, never a platform-specific id for the same signal",
            conversationView.contains("\"ratchet_refused_notice\""),
        )
        val ratchetCheckAt = conversationView.indexOf("appState.ratchetRefused[contactId] == true")
        val fsCheckAt = conversationView.indexOf("appState.forwardSecrecyStalled[contactId] == true")
        assertTrue("precondition: both gates must exist", ratchetCheckAt >= 0 && fsCheckAt >= 0)
        assertTrue(
            "the ratchet-refused gate must be checked BEFORE (and win precedence over) the " +
                "forward-secrecy-stalled gate — both would otherwise render at once",
            ratchetCheckAt < fsCheckAt,
        )
    }

    @Test
    fun groupViews_hasNoRatchetRefusedNotice() {
        assertFalse(
            "the ratchet-refused signal is per 1:1 contact — GroupViews must not reference it",
            groupViews.contains("ratchetRefused") || groupViews.contains("ratchet_refused_notice"),
        )
    }

    // -----------------------------------------------------------------------

    /** See [PeriodicReauthLockSourceTest] — same walk, same fail-loud contract. */
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
