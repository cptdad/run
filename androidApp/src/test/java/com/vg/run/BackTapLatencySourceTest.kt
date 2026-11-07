package com.vg.run

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Guards the LEAVE PATH of all four conversation screens (RETRIEVE-ACK, 2026-11-03).
 *
 * The relay now deletes a blob only when the client ACKS it, and a screen acks
 * (commits its `PendingDrain`) only AFTER the messages are on screen. That removed the
 * reason for the old back-tap guard ("finish the in-flight poll, stay if it landed a
 * message"): leaving is IMMEDIATE, and a drain the user walked away from is abandoned
 * (or simply dropped) and re-delivered by the relay after its lease. Each property
 * below is one way the old cost, or the old loss, silently comes back:
 *
 *  - the guard machinery (`backRequested`, `leaving`, the "Leaving the runes…" /
 *    "Runes whispered while trying to leave" whispers, `guardedBack`) is gone;
 *  - the screens poll through the PENDING api and commit only AFTER appending to the
 *    list — committing first would ack a message that is not yet on screen;
 *  - nothing on the lock / background teardown path commits (an uncommitted drain is
 *    exactly what protects a message across a teardown);
 *  - the iOS conversation loops do not probe the relay themselves (a full onion
 *    round-trip in front of every poll).
 *
 * SOURCE-LEVEL, for the reason this file's siblings state: these are SwiftUI
 * modifiers and Compose lifecycle effects, and this module's unit-test tier has
 * neither Robolectric nor a Swift host. Same technique as
 * [PeriodicReauthLockSourceTest] / [SpeculativeTorAdoptionSourceTest]; bodies
 * are scanned with comments STRIPPED, so prose that merely names a call can
 * neither satisfy nor trip a guard. The runtime companions are the e2e suites
 * (conversation open/leave runs in every cross suite).
 */
class BackTapLatencySourceTest {

    private val androidDirect: String by lazy { read(SourcePins.CONVERSATION_SCREEN) }
    private val androidGroup: String by lazy { read(SourcePins.GROUP_CONVERSATION_SCREEN) }
    private val iosDirect: String by lazy { read("iosApp/iosApp/ConversationView.swift") }
    private val iosGroup: String by lazy { read("iosApp/iosApp/GroupViews.swift") }

    private val allScreens: List<Pair<String, String>> by lazy {
        listOf(
            "ConversationScreen" to androidDirect,
            "GroupConversationScreen" to androidGroup,
            "ConversationView" to iosDirect,
            "GroupViews" to iosGroup,
        )
    }

    /** Android: the arrow and system back both route to `requestBack`, which just leaves. */
    @Test
    fun androidBackLeavesImmediately() {
        for ((name, src) in listOf("ConversationScreen" to androidDirect, "GroupConversationScreen" to androidGroup)) {
            assertTrue(
                "$name.requestBack must leave directly (leaveCleanly())",
                src.contains("val requestBack: () -> Unit = { leaveCleanly() }"),
            )
            assertTrue("$name must keep the system-back handler", src.contains("BackHandler { requestBack() }"))
        }
    }

    /** iOS: the chevron dismisses directly. */
    @Test
    fun iosBackChevronDismissesImmediately() {
        for ((name, src, id) in listOf(
            Triple("ConversationView", iosDirect, "conversation_back"),
            Triple("GroupViews", iosGroup, "group_conversation_back"),
        )) {
            assertTrue("$name: back chevron must call dismiss() directly", src.contains("Button { dismiss() } label: {"))
            assertTrue("$name must keep the $id a11y id", src.contains("\"$id\""))
        }
    }

    /** The whole leave-guard vocabulary is gone from all four screens. */
    @Test
    fun theLeaveGuardIsGone() {
        for ((name, src) in allScreens) {
            for (token in listOf("backRequested", "guardedBack", "ConversationRunes.LEAVING", "WHISPERED_ON_LEAVE",
                "ConversationRunes.shared.LEAVING", "var leaving", "leaving = ", "awaitWithBackGrace")) {
                assertFalse("$name must not contain `$token` — back is immediate under retrieve-ack", src.contains(token))
            }
        }
    }

    /**
     * Every screen polls through the pending API and abandons an un-shown drain; no screen
     * uses the immediate persist+ack polls any more.
     */
    @Test
    fun screensUseThePendingDrainApi() {
        assertTrue(androidDirect.contains("pollDirectPending(contactId)"))
        assertTrue(androidGroup.contains("pollGroupPending(groupId)"))
        assertTrue(iosDirect.contains("pollDirectPending(contactId: contactId)"))
        assertTrue(iosGroup.contains("pollGroupPending(groupId: groupId)"))
        for ((name, src) in allScreens) {
            for (token in listOf("pollDirectIntoBuffer", "pollGroupIntoBuffer", "pollMessagesIntoBuffer",
                "takeDirectScreenItems", "takeGroupScreenItems", "pollMessages(")) {
                assertFalse("$name must not use `$token` — screens ack only after display", src.contains(token))
            }
        }
        for ((name, src) in listOf("ConversationScreen" to androidDirect, "GroupConversationScreen" to androidGroup)) {
            assertTrue("$name must abandon an un-committed drain when it is torn down", src.contains(".abandon()"))
        }
        for ((name, src) in listOf("ConversationView" to iosDirect, "GroupViews" to iosGroup)) {
            assertTrue("$name must abandon a drain that lands after cancellation", src.contains("abandonDrain("))
        }
    }

    /**
     * Commit comes AFTER the items were appended to the on-screen list — committing first
     * would ack (and burn) a message that is not yet displayed.
     */
    @Test
    fun commitFollowsTheAppend() {
        val shapes = listOf(
            listOf("ConversationScreen", "pollDirectPending(contactId)", "messages.add(", "drain.commit()"),
            listOf("GroupConversationScreen", "pollGroupPending(groupId)", "messages.add(", "drain.commit()"),
            listOf("ConversationView", "pollDirectPending(contactId: contactId)", "messages.append(", "commitDrain(drain)"),
            listOf("GroupViews", "pollGroupPending(groupId: groupId)", "insertByTimestamp(", "commitDrain(drain)"),
        )
        val sources = allScreens.toMap()
        for ((name, poll, append, commit) in shapes) {
            val src = sources.getValue(name)
            val p = src.indexOf(poll)
            val a = src.indexOf(append, p)
            val c = src.indexOf(commit, p)
            assertTrue("$name: precondition — poll, append and commit must all exist", p >= 0 && a > p && c > p)
            assertTrue("$name must append to the list BEFORE committing the drain", a < c)
        }
    }

    /** Teardown / lock paths never commit: an uncommitted drain is what protects the message. */
    @Test
    fun noTeardownPathCommits() {
        for (f in listOf("iosApp/iosApp/RunApp.swift", "iosApp/iosApp/ContentView.swift", "iosApp/iosApp/InactivityAutoLock.swift")) {
            val src = read(f)
            assertFalse("$f must not commit a conversation drain", src.contains("commitDrain") || src.contains(".commit()"))
        }
        for (f in listOf(SourcePins.MAIN_ACTIVITY, SourcePins.WIPE_ROUTINE)) {
            assertFalse("$f must not commit a conversation drain", read(f).contains("PendingDrain") )
        }
    }

    // -----------------------------------------------------------------------
    // iOS conversation loops do not probe the relay themselves
    // -----------------------------------------------------------------------

    /**
     * `AppState.checkRelayReachability` is the health loop's job (it also drives
     * the update nudge, the review prompt, the miss-streak/NEWNYM ladder and
     * `relayHandshakeComplete` — all of which the 8–12 s loop still reaches).
     * The views only READ `appState.isRelayReachable`.
     */
    @Test
    fun iosConversationLoopsDoNotProbeReachability() {
        for ((name, src) in listOf("ConversationView" to iosDirect, "GroupViews" to iosGroup)) {
            assertFalse(
                "$name must not call checkRelayReachability() — that adds a full onion round-trip to every poll",
                src.contains("checkRelayReachability"),
            )
            assertTrue(
                "$name must still READ appState.isRelayReachable (whisper / runestone / send gate)",
                src.contains("appState.isRelayReachable"),
            )
        }
    }

    /** The Android grace helper stays deleted; the Swift helper stays wired into the Xcode target. */
    @Test
    fun theDrainHelpersAreWired() {
        assertFalse(
            "BackDrainGrace.kt must stay deleted",
            File(repoRoot(), "androidApp/src/main/java/com/vg/run/BackDrainGrace.kt").exists(),
        )
        val swift = read("iosApp/iosApp/BackDrainGrace.swift")
        assertFalse("BackDrainGrace.swift must not declare a grace window", swift.contains("backDrainGraceMs"))
        assertTrue("BackDrainGrace.swift must still provide awaitDrain", swift.contains("func awaitDrain"))
        val pbxproj = File(repoRoot(), "iosApp/iosApp.xcodeproj/project.pbxproj").readText()
        assertTrue(pbxproj.contains("/* BackDrainGrace.swift */ = {isa = PBXFileReference;"))
        assertTrue(pbxproj.contains("/* BackDrainGrace.swift in Sources */"))
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
