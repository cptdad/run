package com.vg.run

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Source guard for the two pieces of platform glue behind "a text for a group
 * whose invitation is still unanswered" (2026-11-16). The routing itself is shared
 * code, pinned by `InvitedGroupTextTest`; what no unit test reaches is the UI:
 *
 *  - an echo of a group we are only INVITED to (`groupJoined == false`) must not
 *    offer "Open group" — there is no group conversation to open, and the route
 *    it would push names a group that does not exist on this phone. Both echo
 *    bubbles take an OPTIONAL open action, and all four call sites (the 1:1 screen
 *    and the group screen, on each platform) pass none for such an echo;
 *  - joining replays the activity notices parked while the group was only an
 *    invitation, so both platforms republish the group unread counts right after
 *    `acceptInvite` returns (they otherwise refresh on the control loop's next
 *    60–90 s cycle, and the freshly joined row sat dark that long).
 *
 * Bodies are scanned with comments stripped.
 */
class InvitedGroupEchoSourceTest {

    private fun kotlin(name: String) =
        stripComments(File(repoRoot(), "androidApp/src/main/java/com/vg/run/$name").readText())

    private fun swift(name: String) =
        stripComments(File(repoRoot(), "iosApp/iosApp/$name").readText())

    private fun String.flat() = replace(Regex("\\s+"), " ")

    @Test
    fun android_echoBubble_takesAnOptionalOpenAction_andOnlyRendersItWhenGiven() {
        val src = kotlin("MarkedBubbles.kt")
        val at = src.indexOf("internal fun GroupEchoBubble(")
        assertTrue("GroupEchoBubble not found", at >= 0)
        val fn = src.substring(at).flat()
        assertTrue("onOpenGroup must be optional", fn.contains("onOpenGroup: (() -> Unit)?"))
        val guard = fn.indexOf("if (onOpenGroup != null)")
        val action = fn.indexOf("R.string.conversation_group_echo_open")
        assertTrue("the Open group text must sit inside the null guard", guard in 0 until action)
    }

    @Test
    fun android_bothScreens_passNoOpenActionForAnInvitedOnlyGroup() {
        val direct = kotlin("ConversationScreen.kt").flat()
        assertTrue(direct.contains("echoGroupJoined = rm.groupJoined"))
        assertTrue(direct.contains("onOpenGroup = if (message.echoGroupJoined) { { onOpenGroup(echoGroupId) } } else null"))
        val group = kotlin("GroupConversationScreen.kt").flat()
        assertTrue(group.contains("echoGroupJoined = gm.groupJoined"))
        assertTrue(group.contains("onOpenGroup = if (message.echoGroupJoined) { { onOpenGroup(message.echoGroupId) } } else null"))
    }

    @Test
    fun ios_echoBubble_takesAnOptionalOpenAction_andBothScreensPassNoneForAnInvitedOnlyGroup() {
        val direct = swift("ConversationView.swift").flat()
        assertTrue("onOpenGroup must be optional", direct.contains("let onOpenGroup: (() -> Void)?"))
        val guard = direct.indexOf("if let onOpenGroup {")
        val action = direct.indexOf("L10n.conversationGroupEchoOpen")
        assertTrue("the Open group button must sit inside the unwrap", guard in 0 until action)
        assertTrue(direct.contains("echoGroupJoined: item.groupJoined"))
        assertTrue(direct.contains("onOpenGroup: msg.echoGroupJoined ? { onOpenGroup(echoGroupId) } : nil"))
        val group = swift("GroupViews.swift").flat()
        assertTrue(group.contains("echoGroupJoined: gm.groupJoined"))
        assertTrue(group.contains("onOpenGroup: msg.echoGroupJoined ? { onOpenGroup(msg.echoGroupId) } : nil"))
    }

    @Test
    fun bothPlatforms_republishGroupUnreadCountsRightAfterAcceptingAnInvitation() {
        val android = kotlin("ContactListScreen.kt")
        val accept = android.indexOf("viewModel.groupManager?.acceptInvite(id)")
        assertTrue("Android accept call not found", accept >= 0)
        val completion = braceBody(android, android.indexOf('{', android.indexOf(")", accept + 40)))
        assertTrue(
            "Android must refresh the group unread counts in the accept completion",
            completion.contains("viewModel.refreshGroupUnreadCounts()"),
        )

        val ios = swift("AppState+Conversations.swift")
        val fn = ios.indexOf("func acceptGroupInvite(groupId: String) async -> Bool")
        assertTrue("iOS acceptGroupInvite not found", fn >= 0)
        val body = braceBody(ios, ios.indexOf('{', fn))
        val accepted = body.indexOf("acceptInvite(groupId: groupId)")
        val refresh = body.indexOf("refreshGroupUnreadCounts()")
        assertTrue("iOS must refresh the group unread counts after acceptInvite", accepted in 0 until refresh)
    }
}
