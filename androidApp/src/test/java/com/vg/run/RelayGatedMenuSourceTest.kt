package com.vg.run

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Guards the 2026-09-28 directive ("all menu items that require connection to
 * the relay should be disabled when relay is unavailable"): the settings
 * cogwheel's relay-dependent rows (Move to new device, Notifications / Push
 * settings, Report bug — Add contact and Create group were already gated)
 * must be disabled while the relay hasn't answered, on BOTH platforms, using
 * the SAME debounced signal the runestone itself uses (Android:
 * `contactsReady`; iOS: `rowsEnabled`, which e8602f0f made the single flag the
 * list rows, the lit marker and the menu rows share — `litVisible` alone is
 * animation-coupled and can lag a contactsReady flip) — never the raw reachability flag,
 * which flaps, and never Android's old `relayHandshakeComplete`, which is a
 * monotonic latch that never turns back off once the relay has answered once.
 *
 * A relay-dependent row that stays tappable while the relay is unavailable
 * leads to a flow that can only fail or wait; the runestone already tells the
 * user the relay is not answering, so these rows follow it.
 *
 * `settings_debug_mode` is deliberately excluded: it is a local toggle and
 * must stay switchable OFF even while offline.
 *
 * SOURCE-LEVEL, same technique and same reason as
 * [AdminHandoffLeaveGateSourceTest]: `ContactListScreen`/`ContactListView`
 * need a live vault + relay to reach the state this decision depends on, and
 * this module's unit-test tier has no Robolectric and no mocking framework, so
 * the gating is checked structurally instead. Bodies are scanned with
 * comments STRIPPED so prose that merely names a signal can neither satisfy
 * nor trip a guard.
 */
class RelayGatedMenuSourceTest {

    private val contactListScreen: String by lazy {
        SourcePins.stripped(SourcePins.CONTACT_LIST_SCREEN)
    }
    private val contactListView: String by lazy {
        stripComments(File(repoRoot(), "iosApp/iosApp/ContactListView.swift").readText())
    }

    // -----------------------------------------------------------------------
    // Android: every relay-dependent DropdownMenuItem carries
    // `enabled = contactsReady`.
    // -----------------------------------------------------------------------

    private val androidRelayGatedIds = listOf(
        "add_contact_button",
        "create_group_menu_button",
        "move_to_new_device_button",
        "menu_notifications",
        "report_bug_menu_item",
    )

    @Test
    fun android_everyRelayDependentRow_isGatedOnContactsReady() {
        for (id in androidRelayGatedIds) {
            val block = contactListScreen.itemBlock("\"$id\"", "DropdownMenuItem(")
            assertTrue(
                "DropdownMenuItem carrying testTag(\"$id\") must be `enabled = contactsReady`. " +
                    "Block was:\n$block",
                block.contains("enabled = contactsReady"),
            )
        }
    }

    /**
     * Non-vacuousness / regression guard for `report_bug_menu_item` specifically:
     * before this fix it was `enabled = relayHandshakeComplete`, a latch that
     * never turns back off. Reverting to that flag must fail this test even
     * though it also disables the row on first launch.
     */
    @Test
    fun android_reportBugRow_isNotGatedOnTheMonotonicHandshakeLatch() {
        val block = contactListScreen.itemBlock("\"report_bug_menu_item\"", "DropdownMenuItem(")
        assertFalse(
            "report_bug_menu_item must not be gated on relayHandshakeComplete (a monotonic " +
                "latch that never turns back off once true) — it must track live reachability " +
                "via contactsReady instead. Block was:\n$block",
            block.contains("enabled = relayHandshakeComplete"),
        )
    }

    @Test
    fun android_debugModeRow_isNotRelayGated() {
        val block = contactListScreen.itemBlock("\"settings_debug_mode\"", "DropdownMenuItem(")
        assertFalse(
            "settings_debug_mode is a local toggle and must stay switchable OFF while " +
                "offline — it must not carry an `enabled = ` relay gate. Block was:\n$block",
            block.contains("enabled = "),
        )
    }

    // -----------------------------------------------------------------------
    // iOS: every relay-dependent settingsRow carries `disabled: !rowsEnabled`.
    // -----------------------------------------------------------------------

    private val iosRelayGatedIds = listOf(
        "add_contact_button",
        "create_group_menu_button",
        "move_to_new_device_button",
        "push_settings_menu_button",
        "report_bug_menu_item",
    )

    @Test
    fun ios_everyRelayDependentRow_isGatedOnRowsEnabled() {
        for (id in iosRelayGatedIds) {
            val block = contactListView.itemBlock("\"$id\"", "settingsRow(")
            assertTrue(
                "settingsRow(...\"$id\"...) must carry `disabled: !rowsEnabled`. Block was:\n$block",
                block.contains("disabled: !rowsEnabled"),
            )
        }
    }

    @Test
    fun ios_debugModeRow_isNotRelayGated() {
        val block = contactListView.itemBlock("\"settings_debug_mode\"", "settingsRow(")
        assertFalse(
            "settings_debug_mode is a local toggle and must stay switchable OFF while " +
                "offline — it must not carry a `disabled:` relay gate. Block was:\n$block",
            block.contains("disabled:"),
        )
    }

    // -----------------------------------------------------------------------

    /**
     * Locates the single call block that contains [idToken]: the substring
     * from the nearest preceding occurrence of [callStart] (which must end in
     * an opening paren, e.g. `"DropdownMenuItem("`) up to that call's OWN
     * matching closing paren (found by depth-counting parens — every paren
     * opened inside the call, e.g. by a nested `stringResource(...)`, is
     * balanced by a matching close, so simple depth-counting lands exactly on
     * the outer call's closer). Bounding on the matching close paren — rather
     * than "the next occurrence of [callStart]" or "end of source" — matters
     * for the LAST item in a list, which would otherwise swallow unrelated
     * code below it (e.g. this screen's own `enabled = isRelayReachable`
     * rows elsewhere in the file, which would falsely trip the
     * not-relay-gated assertions on `settings_debug_mode`). Robust to
     * formatting: callers grep the whole enclosing item/row block rather than
     * a single line.
     */
    private fun String.itemBlock(idToken: String, callStart: String): String {
        assertTrue("precondition: $callStart must end in an opening paren", callStart.endsWith("("))
        val idAt = indexOf(idToken)
        assertTrue("precondition: $idToken must exist in the source", idAt >= 0)
        val blockStart = lastIndexOf(callStart, idAt)
        assertTrue(
            "precondition: an enclosing `$callStart` must precede $idToken",
            blockStart in 0 until idAt,
        )
        val openParenAt = blockStart + callStart.length - 1
        var depth = 0
        var closeAt = -1
        for (i in openParenAt until length) {
            when (this[i]) {
                '(' -> depth++
                ')' -> {
                    depth--
                    if (depth == 0) {
                        closeAt = i
                        break
                    }
                }
            }
        }
        assertTrue("precondition: `$callStart` call starting at $blockStart must close", closeAt > openParenAt)
        return substring(blockStart, closeAt + 1)
    }
}
