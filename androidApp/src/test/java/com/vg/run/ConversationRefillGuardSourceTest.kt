package com.vg.run

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * RÚN-05: a closed iOS conversation screen must never be refilled.
 *
 * Both iOS conversation screens poll in a `@MainActor` task that `onDisappear` cancels
 * right before it erases the screen's `messages`. A task resumes after an `await`
 * even when it was cancelled meanwhile, so every `await` in the poll loop must be
 * followed by the session check (`appState.isConversationPollCurrent(session)`:
 * cancelled, locked, or a new session generation) BEFORE the next write to the
 * list. Before the fix, the screenshot-notice drain's await was followed by appends
 * with no check at all (ConversationView / GroupViews).
 *
 * SOURCE-LEVEL, like [BackTapLatencySourceTest]: this module has no Swift host. Comments
 * are stripped; nested `Task { … }` blocks inside the loop (the rune-whisper verdict
 * task, which writes only the whisper) are cut out by brace matching, not by literals.
 *
 * What it still CANNOT see: whether the check is on the path actually taken (it only
 * requires the check text between the `await` and the next write, e.g. inside an `if`
 * that guards that write); writes through a helper other than `insertByTimestamp`;
 * writes to the list from other functions than the ones listed here; and whether the
 * runtime ever resumes a cancelled task at those points (that is the e2e suites'
 * and the device check's job).
 */
class ConversationRefillGuardSourceTest {

    private val check = "isConversationPollCurrent(session)"
    private val await = Regex("""\bawait\b""")
    // Any write to the list: assignment, a mutating method, a subscript (read or write —
    // conservative), or the group screen's sorted-insert helper.
    private val mutation = Regex(
        """\bmessages\s*(=(?!=)|\.\s*(append|insert|removeAll|removeFirst|removeLast|remove|sort|swapAt)\b|\[)|insertByTimestamp\(""",
    )

    @Test
    fun everyAwaitInTheDirectPollLoop_isFollowedByTheSessionCheck_beforeTheListIsTouched() =
        assertGuarded("ConversationView", pollLoop("iosApp/iosApp/ConversationView.swift"))

    @Test
    fun everyAwaitInTheGroupPollLoop_isFollowedByTheSessionCheck_beforeTheListIsTouched() =
        assertGuarded("GroupViews", pollLoop("iosApp/iosApp/GroupViews.swift"))

    @Test
    fun theSessionTokenIsCapturedOnce_atLoopStart() {
        for (path in listOf("iosApp/iosApp/ConversationView.swift", "iosApp/iosApp/GroupViews.swift")) {
            val body = read(path).functionBody("    private func startPolling() {")
            assertTrue("$path: the loop must capture its session", body.contains("let session = appState.conversationPollToken"))
        }
    }

    /** The group SEND outlives its screen; after its await it may write back only while its row still exists. */
    @Test
    fun theGroupSend_writesNothingBack_onceItsRowIsGone() {
        val body = read("iosApp/iosApp/GroupViews.swift").functionBody("    private func sendMessage() {")
        val send = body.indexOf("await appState.sendGroupMessage(")
        assertTrue("precondition: the group send awaits sendGroupMessage", send >= 0)
        val rest = body.substring(send)
        val guard = rest.indexOf("guard messages.contains(where: { \$0.id == msgId }) else { return }")
        val firstWrite = mutation.find(rest.substringAfter("\n"))?.range?.first?.let { it + rest.indexOf("\n") + 1 } ?: -1
        assertTrue("GroupViews.sendMessage: the row-exists guard must come right after the send's await", guard >= 0)
        assertTrue("GroupViews.sendMessage: no list write before the row-exists guard", firstWrite < 0 || guard < firstWrite)
    }

    private fun pollLoop(path: String): String =
        cutNestedTasks(read(path).functionBody("    private func startPolling() {"))

    /** Removes every `Task {` block after the first (the poll task itself) by brace matching. */
    private fun cutNestedTasks(body: String): String {
        val outer = body.indexOf("Task {")
        assertTrue("precondition: the poll loop is a Task", outer >= 0)
        var s = body
        var from = outer + 1
        while (true) {
            val at = s.indexOf("Task {", from)
            if (at < 0) return s
            var depth = 0
            var end = -1
            for (i in s.indexOf('{', at) until s.length) {
                if (s[i] == '{') depth++ else if (s[i] == '}') { depth--; if (depth == 0) { end = i; break } }
            }
            assertTrue("precondition: a nested Task block is closed", end > at)
            s = s.removeRange(at, end + 1)
            from = at
        }
    }

    private fun assertGuarded(name: String, body: String) {
        val lines = body.lines()
        var awaits = 0
        for ((i, line) in lines.withIndex()) {
            if (!await.containsMatchIn(line)) continue
            awaits++
            val rest = lines.drop(i + 1)
            val m = rest.indexOfFirst { mutation.containsMatchIn(it) }
            if (m < 0) continue
            val between = rest.take(m + 1).joinToString("\n")
            assertTrue(
                "$name: the await on line ${i + 1} of startPolling reaches a write to the list without `$check`:\n$line",
                between.contains(check),
            )
        }
        assertTrue("precondition: $name's poll loop has awaits", awaits >= 4)
    }

    private fun read(relativePath: String): String = stripComments(File(repoRoot(), relativePath).readText())

    private fun String.functionBody(signature: String): String {
        val start = indexOf(signature)
        assertTrue("precondition: `$signature` must exist", start >= 0)
        val indent = signature.takeWhile { it == ' ' }
        val end = indexOf("\n$indent}", start)
        assertTrue("precondition: `$signature` must be closed", end > start)
        return substring(start, end)
    }
}
