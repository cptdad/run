package com.vg.run

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Pins the Done-step decision that caused the App Store 2.1(a) rejection of
 * 1.6.13 ("both devices stuck on waiting after scanned code").
 *
 * The QR pairing is a TWO-scan dance: phone A shows an instant SECRET-ONLY code,
 * B scans it, and B must then have ITS (now full) code scanned back by A — that
 * second scan is the only thing that produces the inbox announce POST. After the
 * FIRST scan the Done step claimed "✓ Contact added" and offered Done; tapping it
 * dropped the transient inbox write capability + secret half (never persisted, and
 * they must never be), leaving a permanently un-completable "Waiting for
 * their inbox…" contact. Both reviewers did that on both phones, so both were
 * stuck and neither device ever POSTed.
 *
 * [addContactDoneState] is the whole decision, extracted precisely so it can be
 * pinned here instead of only by a two-phones-with-cameras manual run (the e2e
 * harness cannot scan a QR code, so this path has no automated device coverage).
 * The second half of the file guards the WIRING and the iOS sibling — a correct
 * decision function that nothing consults, or that only one platform consults, is
 * the same shipped defect.
 */
class AddContactDoneStateTest {

    // -----------------------------------------------------------------------
    // 1. The decision itself
    // -----------------------------------------------------------------------

    /** THE regression. A secret-only scan may never be reported as finished. */
    @Test
    fun secretOnlyScan_isNotComplete_untilThePeerScansBack() {
        assertEquals(
            "a save with no peer inbox means we scanned a SECRET-ONLY code: the peer still " +
                "has to scan our full code, and until they do there is no send channel and " +
                "no announce — claiming success here is what stranded both review devices",
            AddContactDoneState.AWAITING_SCAN_BACK,
            addContactDoneState(savedPeerInboxId = null, peerInboxArrived = false),
        )
    }

    /** The announce landing while the screen is open is what completes it. */
    @Test
    fun secretOnlyScan_completesWhenThePeersAnnounceArrives() {
        assertEquals(
            AddContactDoneState.COMPLETE,
            addContactDoneState(savedPeerInboxId = null, peerInboxArrived = true),
        )
    }

    /**
     * Full-code scan (and the no-camera paste exchange, which always trades full
     * codes): we hold their inbox, we already announced ours, nothing is owed.
     */
    @Test
    fun fullCodeScan_isCompleteImmediately() {
        assertEquals(
            AddContactDoneState.COMPLETE,
            addContactDoneState(savedPeerInboxId = "inbox-abc", peerInboxArrived = false),
        )
        assertEquals(
            AddContactDoneState.COMPLETE,
            addContactDoneState(savedPeerInboxId = "inbox-abc", peerInboxArrived = true),
        )
    }

    /** Exactly two states, so "not complete" can never silently become a third. */
    @Test
    fun theStateSpaceIsTotal() {
        assertEquals(2, AddContactDoneState.entries.size)
        for (arrived in listOf(false, true)) {
            for (peer in listOf(null, "inbox-abc")) {
                assertTrue(addContactDoneState(peer, arrived) in AddContactDoneState.entries)
            }
        }
    }

    // -----------------------------------------------------------------------
    // 2. The wiring — source-level, for the reason this file's siblings state:
    //    the screens are Composables / SwiftUI views and this module's unit-test
    //    tier has no Robolectric and no mocking framework. Bodies are scanned
    //    with comments STRIPPED so prose naming a symbol can neither satisfy nor
    //    trip a guard.
    // -----------------------------------------------------------------------

    private val screen: String by lazy {
        SourcePins.stripped(SourcePins.ADD_CONTACT_SCREEN)
    }
    private val view: String by lazy {
        stripComments(File(repoRoot(), "iosApp/iosApp/AddContactView.swift").readText())
    }

    /**
     * The Done step must read the DECISION, not the raw scan. It used to read
     * `scannedData?.inboxId == null`, which is null on the PASTE path too (that tab
     * keeps its own parsed value), so the paste exchange rendered the scan-back
     * role over an already-complete pairing.
     */
    @Test
    fun theDoneStepConsultsTheDecisionFunction() {
        assertTrue(
            "AddContactScreen must derive the scan-back state from addContactDoneState",
            screen.contains("addContactDoneState(savedPeerInboxId, peerInboxArrived)"),
        )
        assertTrue(
            "…and must NOT go back to reading the raw scan for the Done-step role",
            !screen.contains("scanBackNeeded = scannedData?.inboxId == null"),
        )
        assertTrue(
            "both save paths must record the peer inbox they saved: the camera save…",
            screen.contains("savedPeerInboxId = data.inboxId"),
        )
        assertTrue(
            "…and the paste exchange, which always trades FULL codes",
            screen.contains("savedPeerInboxId = peerInboxId"),
        )
    }

    /**
     * The half-done state must be un-leavable except through the confirm, on every
     * exit affordance: no Done button, a system BACK that routes through the
     * confirm, and an abandon that DELETES the pending contact (otherwise the
     * un-completable row the fix exists to prevent is left behind anyway).
     */
    @Test
    fun theHalfDonePairingCanOnlyBeLeftThroughTheConfirm() {
        assertTrue(
            "system BACK must route through the confirm while the pairing is half done",
            screen.contains("BackHandler(enabled = scanBackNeeded) { showCancelPairing = true }"),
        )
        assertTrue(
            "abandoning must delete the pending contact (shared purge path)",
            screen.contains("viewModel.deleteContactInBackground(cid) { onBack() }"),
        )
        val done = screen.functionBody("private fun DoneStep(")
        assertTrue(
            "the Done button must be gated on the pairing NOT being half done",
            done.contains("if (scanBackNeeded)") && done.contains("add_contact_done"),
        )
        assertTrue(
            "…and the half-done arm must offer keep-waiting + cancel-pairing instead",
            done.contains("add_contact_keep_waiting") && done.contains("add_contact_cancel_pairing"),
        )
    }

    /**
     * Parity: the identical ids on both platforms, or the shared e2e selectors
     * (and any future cross-platform spec) only work on one of them. iOS is the
     * platform the rejection landed on, so this guard reads its source too.
     */
    @Test
    fun bothPlatformsExposeTheSameScanBackIdentifiers() {
        val ids = listOf(
            "add_contact_scan_back_title",
            "add_contact_scan_back_qr",
            "add_contact_scan_back_hint",
            "add_contact_keep_waiting",
            "add_contact_cancel_pairing",
            "add_contact_cancel_pairing_confirm",
            "add_contact_cancel_pairing_keep",
        )
        for (id in ids) {
            assertTrue("AddContactScreen.kt is missing the a11y id `$id`", screen.contains(id))
            assertTrue("AddContactView.swift is missing the a11y id `$id`", view.contains(id))
        }
        // The pre-existing ids must survive — other sessions run against pre-deploy
        // binaries, and the e2e helpers key on them (widen, never narrow).
        for (id in listOf("add_contact_done", "add_contact_cancel", "add_done_alias")) {
            assertTrue("AddContactScreen.kt dropped the existing id `$id`", screen.contains(id))
            assertTrue("AddContactView.swift dropped the existing id `$id`", view.contains(id))
        }
    }

    /**
     * iOS parity for the behaviour itself: the same two-input decision, the same
     * sheet-dismiss gate, the same delete-on-abandon.
     */
    @Test
    fun iosMirrorsTheDecisionAndTheAbandonPath() {
        assertTrue(
            "iOS must derive the state from the same two inputs, in the same order",
            view.contains("step == .done && peerInbox == nil && !peerInboxArrived"),
        )
        assertTrue(
            "a swipe-down sheet dismiss must be blocked while the pairing is half done",
            view.contains(".interactiveDismissDisabled(scanBackNeeded)"),
        )
        assertTrue(
            "abandoning must delete the pending contact through the shared purge",
            view.contains("appState.deleteContactPurgingRelay(contactId: cid)"),
        )
        assertTrue(
            "…and the peer's announce must be able to complete the pairing in place",
            view.contains("MessageManagerKt.contactFullyPaired(vault: vault, contactId: cid)"),
        )
    }

    // -----------------------------------------------------------------------
    // Helpers (same idiom as PeriodicReauthLockSourceTest)
    // -----------------------------------------------------------------------

    private fun String.functionBody(signature: String): String {
        val start = indexOf(signature)
        assertTrue("precondition: `$signature` must exist", start >= 0)
        val end = indexOf("\n}", start)
        assertTrue("precondition: `$signature` must be closed", end > start)
        return substring(start, end)
    }
}
