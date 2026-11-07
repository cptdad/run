package com.vg.run

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Guards the ContactListScreen dialog routing: the single `ContactListDialog` slot,
 * the per-dialog composables and the shared [RuneScrimOverlay]. Several of these
 * ids have no Android e2e coverage (leave_group_alert, the mnemonic_* and menu_*
 * ids, reset_relay_*), so this source test is their only guard.
 *
 * SOURCE-LEVEL (the screen needs a live vault this JVM tier cannot build);
 * comments are stripped first so prose cannot satisfy a check.
 */
class ContactListDialogRoutingSourceTest {

    private val screen = stripComments(read(SourcePins.CONTACT_LIST_SCREEN))
    private val runeDialog = stripComments(read("androidApp/src/main/java/com/vg/run/RuneDialog.kt"))

    /** Every id the screen's dialogs and menus expose, with its expected count. */
    private val tags: Map<String, Int> = listOf(
        "delete_alert", "delete_confirm_button", "leave_group_alert", "leave_group_confirm_button",
        "mnemonic_alert", "mnemonic_edit_input", "mnemonic_save_button", "mnemonic_remove_button",
        "menu_memory_text", "menu_memory", "menu_memory_remove", "menu_new_name", "menu_introduce",
        "menu_reset_relay_access", "reset_relay_alert", "reset_relay_confirm_button", "reset_relay_result",
        "reset_relay_result_ok", "report_bug_dialog", "report_bug_text_field", "report_bug_error",
        "report_bug_cancel_button", "report_bug_send_button", "report_bug_thanks_dialog",
        "report_bug_thanks_ok_button", "debug_mode_dialog", "debug_mode_cancel", "debug_mode_confirm",
        "push_prompt", "push_prompt_yes", "push_prompt_no", "update_nudge_dialog", "update_nudge_message",
        "update_nudge_store_button", "introduce_confirm", "introduce_error_dialog", "referral_offer_dialog",
        "referral_approve", "referral_decline", "referral_relayed_dialog", "referral_relayed_ok",
        "group_invite_dialog", "group_invite_join", "group_invite_decline", "settings_button",
        "settings_ext_proxy", "settings_debug_mode", "report_bug_menu_item", "add_contact_button",
        "create_group_menu_button", "move_to_new_device_button", "menu_notifications", "menu_language",
        "menu_about", "menu_about_info", "menu_donate", "change_pin_button", "protection_level_menu_button",
    ).associateWith { 1 } + mapOf(
        // Both nudge variants (Play: Later; sideload: OK) reuse one e2e selector.
        "update_nudge_later_button" to 2,
    )

    @Test
    fun everyDialogId_appearsExactlyAsOften() {
        for ((tag, expected) in tags) {
            assertEquals("ContactListScreen: \"$tag\" count", expected, screen.split("\"$tag\"").size - 1)
        }
        assertEquals("the introduce picker rows", 1, screen.split("\"introduce_pick_").size - 1)
    }

    @Test
    fun destructiveActions_sitLastInTheirRow() {
        for (tag in listOf("delete_confirm_button", "leave_group_confirm_button", "mnemonic_remove_button")) {
            val tagAt = screen.indexOf("testTag = \"$tag\"")
            assertTrue("$tag must exist", tagAt >= 0)
            val rowAt = screen.lastIndexOf("RuneActionRow(", tagAt)
            assertTrue("$tag must sit in a RuneActionRow", rowAt >= 0)
            val rowEnd = matchingParen(screen, screen.indexOf('(', rowAt))
            assertTrue("$tag must be inside that row", tagAt < rowEnd)
            val before = screen.substring(rowAt, tagAt)
            val after = screen.substring(tagAt, rowEnd)
            assertTrue("$tag: a Cancel (runeSecondary) comes first", before.contains("runeSecondary("))
            assertFalse("$tag: nothing follows the destructive action", after.contains("RuneDialogAction("))
            assertFalse("$tag: nothing follows the destructive action", after.contains("runeSecondary("))
        }
    }

    @Test
    fun noForcedUnwraps() {
        assertFalse("ContactListScreen.kt must not use !! (check-then-!! is a TOCTOU)", screen.contains("!!"))
    }

    @Test
    fun theMenuHandOffs_replaceTheSlotInOneAssignment() {
        val call = screen.substring(screen.indexOf("ContactMenuDialog(\n"))
        for (handOff in listOf(
            "onEditMemory = { dialog = ContactListDialog.EditMemory(c) }",
            "onIntroduce = { dialog = ContactListDialog.Introduce(c) }",
            "onResetRelay = { dialog = ContactListDialog.ResetRelayConfirm(c) }",
            "onDelete = { dialog = ContactListDialog.DeleteContact(c) }",
            "viewModel.rollContactAliasInBackground(c) { updated ->",
            "dialog = ContactListDialog.ContactMenu(updated)",
        )) {
            assertTrue("missing hand-off `$handOff`", call.contains(handOff))
        }
        // The menu rows call the hand-offs (the dialog itself owns no routing).
        val menu = screen.substring(screen.indexOf("private fun ContactMenuDialog("))
        for ((tag, cb) in listOf(
            "menu_memory" to "onClick = onEditMemory",
            "menu_memory_remove" to "onClick = onRemoveMemory",
            "menu_new_name" to "onClick = onRollAlias",
            "menu_introduce" to "onClick = onIntroduce",
            "menu_reset_relay_access" to "onClick = onResetRelay",
        )) {
            val at = menu.indexOf(".testTag(\"$tag\")")
            assertTrue("$tag row must exist", at >= 0)
            val rowEnd = menu.indexOf(".padding(", at)
            assertTrue("$tag row must use $cb", menu.substring(at, rowEnd).contains(cb))
        }
        // The introduce picker suppresses the consent prompts, as before (the
        // freeze itself is consentToShow's rule 1, unit-tested in ConsentToShowTest).
        assertTrue(screen.contains("introduceOpen = dialog is ContactListDialog.Introduce,"))
        assertEquals("one dialog slot", 1, screen.split("mutableStateOf<ContactListDialog?>(null)").size - 1)
    }

    @Test
    fun theTaggedScrims_keepTheTagOnTheScrimBeforeItsBackground() {
        for (tag in listOf("delete_alert", "leave_group_alert", "mnemonic_alert")) {
            val tagAt = screen.indexOf("testTag = \"$tag\"")
            assertTrue("$tag must exist", tagAt >= 0)
            val callAt = screen.lastIndexOf("RuneScrimOverlay(", tagAt)
            assertTrue("$tag must be an argument of RuneScrimOverlay", callAt >= 0)
            assertTrue("…of that call", tagAt < matchingParen(screen, screen.indexOf('(', callAt)))
        }
        val helper = runeDialog.substring(runeDialog.indexOf("internal fun RuneScrimOverlay("))
        val tagAt = helper.indexOf("Modifier.testTag(testTag)")
        val bgAt = helper.indexOf(".background(RunBlack.copy(alpha = SCRIM_ALPHA))")
        val clickAt = helper.indexOf(".clickable(onClick = onDismiss)")
        val imeAt = helper.indexOf("Modifier.imePadding()")
        assertTrue("scrim chain order: testTag < background < clickable < imePadding", tagAt in 0 until bgAt && bgAt < clickAt && clickAt < imeAt)
        assertTrue(runeDialog.contains("private const val SCRIM_ALPHA = 0.8f"))
    }

    private fun matchingParen(src: String, open: Int): Int {
        var depth = 0
        for (i in open until src.length) {
            when (src[i]) {
                '(' -> depth++
                ')' -> { depth--; if (depth == 0) return i }
            }
        }
        throw AssertionError("unbalanced parentheses from $open")
    }

    private fun read(relativePath: String): String = File(repoRoot(), relativePath).readText()
}
