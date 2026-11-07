package com.vg.run

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Guards the Android admin-handoff-then-leave fix.
 *
 * Before this fix, `RunViewModel.transferAdminThenLeaveInBackground` discarded
 * `GroupManager.transferAdmin`'s `Boolean` result and called `leaveGroup`
 * regardless. `transferAdmin` returns `false` (no throw) when the chosen
 * successor's member row is already gone (e.g. it left while the Group Info
 * sheet was open, since `members` there is only re-derived on `refreshKey`).
 * Leaving anyway leaves every remaining member's `adminMemberId` pointing at a
 * departed, unresolvable admin — `GroupManager.handleRoster` drops every future
 * roster once the admin contact can't be resolved, which PERMANENTLY freezes
 * membership. iOS already gated this correctly (`GroupViews.swift`'s
 * `chooseAdminAndLeave`, `guard transferred else { ... return }`).
 *
 * SOURCE-LEVEL, same technique and same reason as [ForwardSecrecyStalledNoticeSourceTest]:
 * `RunViewModel` is an `AndroidViewModel` needing a real `Application` and a live
 * `GroupManager`, and `GroupInfoScreen` needs a live vault + relay to reach the
 * state this decision depends on. This module's unit-test tier has no
 * Robolectric and no mocking framework, so the gating order is checked
 * structurally instead. Bodies are scanned with comments STRIPPED so prose that
 * merely names a call can neither satisfy nor trip a guard.
 */
class AdminHandoffLeaveGateSourceTest {

    private val viewModel: String by lazy {
        SourcePins.stripped(SourcePins.RUN_VIEW_MODEL)
    }
    private val groupInfoScreen: String by lazy {
        SourcePins.stripped(SourcePins.GROUP_INFO_SCREEN)
    }
    private val groupInfoStrings: String by lazy {
        File(repoRoot(), "androidApp/src/main/res/values/strings_groups.xml").readText()
    }
    private val groupViewsSwift: String by lazy {
        stripComments(File(repoRoot(), "iosApp/iosApp/GroupViews.swift").readText())
    }

    // -----------------------------------------------------------------------
    // 1. RunViewModel: the leave is gated on transferAdmin's boolean result
    // -----------------------------------------------------------------------

    @Test
    fun transferAdminThenLeaveInBackground_exposesAFailureCallback() {
        assertTrue(
            "transferAdminThenLeaveInBackground must take an onTransferFailed callback so the " +
                "caller can distinguish a gated failure from a successful leave",
            viewModel.contains("onTransferFailed: () -> Unit"),
        )
    }

    /**
     * Non-vacuousness: reverting to `gm.transferAdmin(groupId, newAdminMemberId)` as a bare,
     * unassigned statement (the original bug) fails this — the result MUST be captured.
     */
    @Test
    fun transferAdminThenLeaveInBackground_capturesTheTransferResult() {
        val fn = viewModel.functionBody("    fun transferAdminThenLeaveInBackground(")
        assertTrue(
            "the transferAdmin call must be assigned to a variable, never a discarded " +
                "statement. Body was:\n$fn",
            fn.contains("val transferred = try {") &&
                fn.contains("gm.transferAdmin(groupId, newAdminMemberId)"),
        )
        val firstCatchAt = fn.indexOf("catch (e: Exception) {")
        val transferredGateAt = fn.indexOf("if (!transferred)")
        assertTrue("precondition: a catch block must precede the transferred gate", firstCatchAt in 0 until transferredGateAt)
        assertTrue(
            "a thrown exception from transferAdmin must be treated as a failed transfer " +
                "(false), never silently swallowed into a leave. Catch block was:\n" +
                fn.substring(firstCatchAt, transferredGateAt),
            fn.substring(firstCatchAt, transferredGateAt).contains("false"),
        )
    }

    /**
     * The core gate: on a failed transfer, `onTransferFailed()` and `return@launch` must both
     * be reached BEFORE `gm.leaveGroup(...)` is ever called — i.e. `leaveGroup` is textually
     * (and therefore, on this single straight-line coroutine body, control-flow) reachable only
     * past the `if (!transferred)` early return.
     *
     * Non-vacuousness: calling `gm.leaveGroup(...)` unconditionally after the transfer attempt
     * (the original bug) fails this because `leaveGroupAt` would then sit BEFORE (or regardless
     * of) the gate's `return@launch`, not after it.
     */
    @Test
    fun transferAdminThenLeaveInBackground_neverLeavesOnAFailedTransfer() {
        val fn = viewModel.functionBody("    fun transferAdminThenLeaveInBackground(")
        val gateAt = fn.indexOf("if (!transferred) {")
        val onTransferFailedCallAt = fn.indexOf("onTransferFailed()")
        val gatedReturnAt = fn.indexOf("return@launch", gateAt)
        val leaveGroupAt = fn.indexOf("gm.leaveGroup(")
        assertTrue("precondition: the failure gate must exist", gateAt >= 0)
        assertTrue(
            "the failure branch must call onTransferFailed()",
            onTransferFailedCallAt in gateAt until leaveGroupAt.let { if (it < 0) fn.length else it },
        )
        assertTrue(
            "the failure branch must return@launch (never fall through to leaveGroup)",
            gatedReturnAt in gateAt until leaveGroupAt,
        )
        assertTrue(
            "gm.leaveGroup must be positioned AFTER the gated return, so a failed transfer " +
                "can never reach it",
            leaveGroupAt > gatedReturnAt,
        )
    }

    // -----------------------------------------------------------------------
    // 2. GroupInfoScreen: fresh member snapshot at tap time, failure UI wiring
    // -----------------------------------------------------------------------

    // Anchors the choose-admin-row block uniquely: `.clickable(enabled = !working) {`
    // also matches the (unrelated) add-member row above it, so the handler under
    // test is located relative to this forEach, which appears exactly once.
    private val chooseAdminForEachAt: Int by lazy {
        groupInfoScreen.indexOf("members.filter { !it.isSelf && it.resolved }.forEach { member ->")
    }

    @Test
    fun chooseAdminRow_reReadsMembersAtTapTimeBeforeTransferring() {
        val handlerAt = chooseAdminForEachAt
        val stillMemberAt = groupInfoScreen.indexOf(
            "val stillMember = vault.getGroupMembers(groupId)",
        )
        val transferCallAt = groupInfoScreen.indexOf("viewModel.transferAdminThenLeaveInBackground(")
        assertTrue("precondition: the choose-admin-row forEach must exist", handlerAt >= 0)
        assertTrue(
            "the choose-admin-row tap handler must re-read vault.getGroupMembers(groupId) — " +
                "the `members` list above is only re-derived on refreshKey and can go stale " +
                "while the sheet is open",
            stillMemberAt > handlerAt,
        )
        assertTrue(
            "the fresh re-read must happen BEFORE transferAdminThenLeaveInBackground is called",
            stillMemberAt in handlerAt until transferCallAt,
        )
    }

    @Test
    fun chooseAdminRow_showsTheFailureDialogWhenTheChosenTargetIsAlreadyGone() {
        val handlerAt = chooseAdminForEachAt
        val stillMemberCheckAt = groupInfoScreen.indexOf("if (!stillMember) {", handlerAt)
        val transferCallAt = groupInfoScreen.indexOf("viewModel.transferAdminThenLeaveInBackground(")
        assertTrue("precondition: the stillMember guard must exist", stillMemberCheckAt in handlerAt until transferCallAt)
        val guardBody = groupInfoScreen.substring(stillMemberCheckAt, transferCallAt)
        assertTrue(
            "a gone target must set transferFailed = true without ever attempting the " +
                "transfer. Guard body was:\n$guardBody",
            guardBody.contains("transferFailed = true"),
        )
    }

    @Test
    fun transferAdminThenLeaveInBackground_call_wiresOnTransferFailed() {
        val callAt = groupInfoScreen.indexOf("viewModel.transferAdminThenLeaveInBackground(")
        assertTrue("precondition: the call site must exist", callAt >= 0)
        val callSite = groupInfoScreen.substring(callAt, minOf(callAt + 700, groupInfoScreen.length))
        assertTrue(
            "the call site must pass onTransferFailed, and it must set transferFailed = true. " +
                "Call site was:\n$callSite",
            callSite.contains("onTransferFailed = {") &&
                callSite.substring(callSite.indexOf("onTransferFailed = {")).contains("transferFailed = true"),
        )
    }

    @Test
    fun transferFailedDialog_carriesTheRequiredTestTagAndASingleOkAction() {
        assertTrue(
            "the failure dialog must carry the group_transfer_failed_dialog test tag — the " +
                "e2e suite keys on this exact id",
            groupInfoScreen.contains("testTag = \"group_transfer_failed_dialog\"") ||
                groupInfoScreen.contains("\"group_transfer_failed_dialog\""),
        )
        val dialogAt = groupInfoScreen.indexOf("if (transferFailed) {")
        assertTrue("precondition: the failure dialog block must exist", dialogAt >= 0)
        val dialogBlock = groupInfoScreen.substring(dialogAt, minOf(dialogAt + 600, groupInfoScreen.length))
        val okActionCount = Regex("RuneDialogAction\\(").findAll(dialogBlock).count()
        assertTrue(
            "the failure dialog must offer exactly ONE action (a single OK). Dialog block " +
                "was:\n$dialogBlock",
            okActionCount == 1,
        )
    }

    // -----------------------------------------------------------------------
    // 3. The strings are the EXISTING translated ones — never new keys
    // -----------------------------------------------------------------------

    @Test
    fun groupInfoScreen_referencesTheExistingTranslatedFailureStrings() {
        assertTrue(
            "GroupInfoScreen must reference R.string.group_info_transfer_failed_title",
            groupInfoScreen.contains("R.string.group_info_transfer_failed_title"),
        )
        assertTrue(
            "GroupInfoScreen must reference R.string.group_info_transfer_failed_message",
            groupInfoScreen.contains("R.string.group_info_transfer_failed_message"),
        )
    }

    @Test
    fun theReferencedStrings_alreadyExistInTheEnglishResourceFile() {
        assertTrue(
            "group_info_transfer_failed_title must already be defined in strings_groups.xml " +
                "— this fix wires an EXISTING translated string, it does not add a new one",
            groupInfoStrings.contains("name=\"group_info_transfer_failed_title\""),
        )
        assertTrue(
            "group_info_transfer_failed_message must already be defined in strings_groups.xml",
            groupInfoStrings.contains("name=\"group_info_transfer_failed_message\""),
        )
    }

    // -----------------------------------------------------------------------
    // 4. iOS parity check (read-only reference — GroupViews.swift is not owned
    //    by this fix): the sibling gate this Android fix mirrors must still exist.
    // -----------------------------------------------------------------------

    @Test
    fun iosSiblingGate_stillExists() {
        assertTrue(
            "GroupViews.swift's chooseAdminAndLeave must still gate the leave on the " +
                "transfer's result — this Android fix mirrors that gate",
            groupViewsSwift.contains("guard transferred else"),
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
