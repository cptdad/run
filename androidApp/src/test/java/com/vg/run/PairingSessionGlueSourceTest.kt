package com.vg.run

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Source guard for the platform glue between the pairing screens and the shared
 * [PairingSession] (ratchet-bootstrap plan, step B2). The decisions (both code
 * shapes, the parse, the v3 rule, the save) are shared code with their own tests;
 * what no unit test reaches is that BOTH screens actually route through the session
 * and no longer reach around it:
 *
 *  - the codes come from the session (`secretOnlyCode` / `fullCode`), parsing goes
 *    through `parsePeerCode`, saving through `save`;
 *  - neither screen derives the pairing secret, builds a payload or saves a paired
 *    contact itself any more;
 *  - the waiting loop consults `contactPairingFailed` and the failure notice is NOT
 *    terminal: the loop keeps polling, a later success clears it, and the contact is
 *    deleted only from the user's "Start again" handler;
 *  - the session is ended on a real leave.
 *
 * Comments are stripped before scanning.
 */
class PairingSessionGlueSourceTest {

    private val android: String by lazy {
        stripComments(File(repoRoot(), "androidApp/src/main/java/com/vg/run/AddContactScreen.kt").readText())
    }
    private val androidVm: String by lazy {
        stripComments(File(repoRoot(), "androidApp/src/main/java/com/vg/run/AddContactSessionViewModel.kt").readText())
    }
    private val ios: String by lazy {
        stripComments(File(repoRoot(), "iosApp/iosApp/AddContactView.swift").readText())
    }

    private fun String.flat() = replace(Regex("\\s+"), " ")

    @Test
    fun android_codesParseAndSaveGoThroughTheSession() {
        assertTrue(android.contains("pairing.secretOnlyCode()"))
        assertTrue(android.contains("pairing.fullCode("))
        assertTrue("both the scan and the paste path parse through the session",
            Regex("""pairing\.parsePeerCode\(""").findAll(android).count() >= 2)
        assertTrue("both the camera save and the paste save go through the session",
            Regex("""pairing\.save\(""").findAll(android).count() >= 2)
        for (banned in listOf("deriveSharedSecret", "PairingPayload.buildSecretOnly", "PairingPayload.buildFull",
            "PairingPayload.parse", "PairingVault.savePairedContact", "saveScannedContact", "parseQrPayload")) {
            assertFalse("AddContactScreen must not call $banned any more", android.contains(banned))
        }
    }

    @Test
    fun ios_codesParseAndSaveGoThroughTheSession() {
        assertTrue(ios.contains("pairing?.secretOnlyCode()"))
        assertTrue(ios.contains("pairing.fullCode("))
        assertTrue("both the scan and the paste path parse through the session",
            Regex("""pairing\.parsePeerCode\(""").findAll(ios).count() >= 2)
        assertTrue(ios.contains("pairing.save("))
        for (banned in listOf("deriveSharedSecret", "PairingPayload.shared.buildSecretOnly", "PairingPayload.shared.buildFull",
            "PairingPayload.shared.parse", "PairingVault.shared.savePairedContact")) {
            assertFalse("AddContactView must not call $banned any more", ios.contains(banned))
        }
    }

    @Test
    fun bothPlatforms_switchOnEverySaveOutcome() {
        for (o in listOf("SAVED_V3", "SAVED_LEGACY", "INBOX_IN_USE", "INVALID_CODE", "START_AGAIN")) {
            assertTrue("Android must handle $o", android.contains("PairingSaveOutcome.$o"))
        }
        for (o in listOf("inboxInUse", "invalidCode", "startAgain")) {
            assertTrue("iOS must handle $o", ios.contains("PairingSaveOutcome.$o"))
        }
        assertTrue(ios.contains("restartPairing(error: L10n.addContactStartAgainError)"))
        assertTrue(android.contains("session.restartPairing(resources.getString(R.string.add_contact_start_again_error))"))
    }

    @Test
    fun android_waitingLoopPollsPairingFailed_isNotTerminal_andDeletesOnlyFromTheAction() {
        val at = android.indexOf("LaunchedEffect(step, savedPeerInboxId, pendingContactId, peerInboxArrived)")
        assertTrue("waiting loop not found", at >= 0)
        val loop = braceBody(android, android.indexOf('{', at))
        assertTrue(loop.contains("contactPairingFailed(vault, cid)"))
        assertTrue("success still wins", loop.contains("contactFullyPaired(vault, cid)"))
        assertTrue("a success clears the notice", loop.flat().contains("session.pairingFailed = false peerInboxArrived = true"))
        assertTrue("the notice follows the verdict both ways", loop.contains("session.pairingFailed = failedNow"))
        assertFalse("the failed branch must not stop the loop", loop.flat().contains("pairingFailed = true return@LaunchedEffect"))
        assertFalse("the loop must not key on the notice (it would restart or stop)", at >= 0 && android.substring(at, at + 120).contains("pairingFailed"))
        assertFalse("the loop must never delete", loop.contains("deleteContact"))
        assertFalse("the loop must never restart the session", loop.contains("restartPairing"))
        val action = braceBody(android, android.indexOf('{', android.indexOf("fun startAgainAfterFailure()")))
        assertTrue(action.contains("deleteContactInBackground(cid)"))
        assertTrue(action.contains("session.restartPairing()"))
        assertTrue("the delete is reachable only from the action",
            Regex("""deleteContactInBackground\(""").findAll(android).count() == 2 &&
                android.contains("onStartAgain = { startAgainAfterFailure() }"))
    }

    @Test
    fun ios_pollConsultsPairingFailed_isNotTerminal_andDeletesOnlyFromTheAction() {
        val at = ios.indexOf("private func pollScanBackPairing()")
        assertTrue(at >= 0)
        val poll = braceBody(ios, ios.indexOf('{', at))
        assertTrue(poll.contains("MessageManagerKt.contactPairingFailed(vault: vault, contactId: cid)"))
        assertTrue("success still wins and clears the notice",
            poll.flat().contains("pairingFailed = false peerInboxArrived = true"))
        assertTrue("the notice follows the verdict both ways", poll.contains("pairingFailed = failedNow"))
        assertFalse("the poll must never delete", poll.contains("deleteContactPurgingRelay"))
        assertFalse("the poll must never restart the session", poll.contains("restartPairing"))
        assertTrue("the poll keeps nudging the sweep while the notice shows",
            poll.contains("notePairingAwaitingPeer"))
        val action = braceBody(ios, ios.indexOf('{', ios.indexOf("private func startAgainAfterFailure()")))
        assertTrue(action.contains("deleteContactPurgingRelay"))
        assertTrue(action.contains("restartPairing(error: nil)"))
        assertTrue("the notice's only action is the start-again handler",
            ios.contains("Button { startAgainAfterFailure() }"))
    }

    @Test
    fun bothPlatforms_endTheSessionOnARealLeave() {
        assertTrue(androidVm.contains("pairing?.end()"))
        assertTrue(android.contains("if (hostActivity?.isChangingConfigurations != true) session.endSession()"))
        val disappear = ios.substring(ios.indexOf(".onDisappear {"))
        assertTrue(disappear.indexOf("pairing?.end()") in 0 until disappear.indexOf("pairingSession = .ended"))
        assertFalse("iOS ends nothing on .inactive", ios.contains(".inactive"))
    }
}
