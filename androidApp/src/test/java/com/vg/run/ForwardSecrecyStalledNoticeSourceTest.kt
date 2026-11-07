package com.vg.run

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Guards the forward-secrecy-stalled UI consumer:
 * `MessageManager.forwardSecrecyStalled(contactId)` existed with NO UI consumer
 * on either platform. This wires it into the 1:1 conversation screen as a
 * SIGNAL, never a send gate.
 *
 * SOURCE-LEVEL, same technique and same reason as
 * [PeriodicReauthLockSourceTest] / [SpeculativeTorAdoptionSourceTest]:
 * `RunViewModel` is an `AndroidViewModel` needing a real `Application` and a
 * live `MessageManager`, and `ConversationScreen`/`ConversationView` need a
 * live vault + relay to reach the state this feature depends on. This
 * module's unit-test tier has no Robolectric and no mocking framework, so the
 * decision under test — WHEN the flag is refreshed, and that it is a signal
 * rather than a gate — is checked structurally instead. Bodies are scanned
 * with comments STRIPPED so prose that merely names a call can neither
 * satisfy nor trip a guard.
 */
class ForwardSecrecyStalledNoticeSourceTest {

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
    fun runViewModel_exposesAPerContactStalledMap() {
        assertTrue(
            "RunViewModel must expose forwardSecrecyStalled as a Map-shaped StateFlow, " +
                "mirroring unreadCounts — a per-contact flag, not a single global Boolean",
            viewModel.contains("val forwardSecrecyStalled: StateFlow<Map<String, Boolean>>"),
        )
    }

    /**
     * Non-vacuousness: replacing `messageManager?.forwardSecrecyStalled(contactId) ?: false`
     * with a bare (non-null-safe) call fails this — a null transport must read as
     * "not stalled", never crash or false-positive.
     */
    @Test
    fun refreshForwardSecrecyStalled_isNullSafeTowardNotStalled() {
        val fn = viewModel.functionBody("    fun refreshForwardSecrecyStalled(contactId: String) {")
        assertTrue(
            "refreshForwardSecrecyStalled must read through messageManager with a null-safe " +
                "fallback to false. Body was:\n$fn",
            fn.contains("messageManager?.forwardSecrecyStalled(contactId) ?: false"),
        )
    }

    /**
     * The flag must be recomputed once the WHOLE retry sequence concludes — success
     * or exhausted — not per attempt, and never only on success (a stuck contact
     * would then never learn it stalled from a message that keeps failing).
     *
     * Non-vacuousness: moving the call inside the `if (sent)` branch, or deleting
     * it, fails this.
     */
    @Test
    fun sendMessageInBackground_refreshesTheFlagOnBothOutcomes() {
        val fn = viewModel.functionBody(
            "    fun sendMessageInBackground(contactId: String, text: String, redriveToken: String? = null, onDelivered: () -> Unit) {",
        )
        val ifSentAt = fn.indexOf("if (sent) {")
        val elseAt = fn.indexOf("} else {", ifSentAt)
        // The FIRST "}" is "} else {"'s own opening brace-close; skip past the whole
        // token to land on the else BLOCK's closing brace, not the if block's.
        val elseCloseAt = fn.indexOf("}", elseAt + "} else {".length)
        val refreshAt = fn.indexOf("refreshForwardSecrecyStalled(contactId)")
        assertTrue("precondition: the else branch must exist", elseAt >= 0)
        assertTrue("precondition: the success/failure branch must exist", ifSentAt >= 0)
        assertTrue(
            "sendMessageInBackground must call refreshForwardSecrecyStalled(contactId). Body " +
                "was:\n$fn",
            refreshAt >= 0,
        )
        assertTrue(
            "the refresh must come AFTER the if/else — so it runs on BOTH outcomes, not just " +
                "the success branch",
            refreshAt > elseCloseAt,
        )
        assertFalse(
            "the refresh must not sit inside the retry `for` loop — once per completed send, " +
                "not once per attempt",
            fn.substring(fn.indexOf("for (attempt in 1..3)"), ifSentAt).contains("refreshForwardSecrecyStalled"),
        )
    }

    // -----------------------------------------------------------------------
    // 2. Android: the conversation screen refreshes on open and renders the
    //    notice for 1:1 only, never groups
    // -----------------------------------------------------------------------

    @Test
    fun conversationScreen_refreshesOnOpen() {
        assertTrue(
            "ConversationScreen must refresh the flag when the conversation opens (the poll " +
                "LaunchedEffect keyed on contactId) — the other evaluation point is a completed " +
                "send; there is no polling loop for this flag",
            conversationScreen.contains("viewModel.refreshForwardSecrecyStalled(contactId)"),
        )
    }

    @Test
    fun conversationScreen_rendersTheNoticeGatedOnTheMap() {
        assertTrue(
            "ConversationScreen must collect viewModel.forwardSecrecyStalled",
            conversationScreen.contains("viewModel.forwardSecrecyStalled.collectAsState()"),
        )
        assertTrue(
            "ConversationScreen must carry the fs_stalled_notice a11y test tag — the e2e " +
                "suite and any future test key on this exact id; never rename it",
            conversationScreen.contains("\"fs_stalled_notice\""),
        )
    }

    @Test
    fun groupConversationScreen_hasNoForwardSecrecyStalledNotice() {
        assertFalse(
            "the forward-secrecy-stalled signal is per 1:1 contact — GroupConversationScreen " +
                "must not reference it",
            groupConversationScreen.contains("forwardSecrecyStalled") ||
                groupConversationScreen.contains("fs_stalled_notice"),
        )
    }

    // -----------------------------------------------------------------------
    // 3. iOS parity: AppState exposes the same shape, ConversationView wires
    //    the same two refresh points and the same a11y id, GroupViews stays
    //    untouched
    // -----------------------------------------------------------------------

    @Test
    fun appState_exposesAPerContactStalledMap() {
        assertTrue(
            "AppState must expose forwardSecrecyStalled as a [String: Bool] — mirroring " +
                "unreadCounts, matching RunViewModel's per-contact map shape",
            appState.contains("@Published var forwardSecrecyStalled: [String: Bool] = [:]"),
        )
    }

    @Test
    fun conversationView_refreshesOnAppearAndAfterSend() {
        assertTrue(
            "ConversationView.onAppear must refresh the flag when the conversation opens",
            conversationView.functionBody("        .onAppear  {")
                .contains("appState.refreshForwardSecrecyStalled(contactId: contactId)"),
        )
        val send = conversationView.functionBody("    private func sendMessage() {")
        val refreshAt = send.indexOf("appState.refreshForwardSecrecyStalled(contactId: contactId)")
        val updateDeliveryAt = send.indexOf("messages[idx] = ChatMessage(")
        assertTrue(
            "sendMessage's retry Task must refresh the flag once the retry loop concludes",
            refreshAt >= 0,
        )
        assertTrue(
            "the refresh must run for BOTH outcomes — before the delivery-status update, " +
                "which runs unconditionally after the success/failure branch, not gated on it",
            refreshAt in 0 until updateDeliveryAt,
        )
    }

    @Test
    fun conversationView_rendersTheNoticeWithTheSameA11yId() {
        assertTrue(
            "ConversationView must gate the notice on appState.forwardSecrecyStalled[contactId]",
            conversationView.contains("appState.forwardSecrecyStalled[contactId] == true"),
        )
        assertTrue(
            "ConversationView must carry the SAME fs_stalled_notice a11y identifier as Android " +
                "— e2e/a11y parity, never a platform-specific id for the same signal",
            conversationView.contains("\"fs_stalled_notice\""),
        )
    }

    @Test
    fun groupViews_hasNoForwardSecrecyStalledNotice() {
        assertFalse(
            "the forward-secrecy-stalled signal is per 1:1 contact — GroupViews must not " +
                "reference it",
            groupViews.contains("forwardSecrecyStalled") || groupViews.contains("fs_stalled_notice"),
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
