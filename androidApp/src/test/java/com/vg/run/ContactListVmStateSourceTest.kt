package com.vg.run

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * ContactListScreen holds no vault access and no polling loop of its own: the
 * contact list, the stale/pending sets and the pending consent come from
 * RunViewModel flows (loaded on IO, cleared on lock and wipe), and the
 * mnemonic / alias / decline writes go through the ViewModel's IO helpers.
 *
 * Comment-stripped, so prose naming a call cannot trip or satisfy it.
 */
class ContactListVmStateSourceTest {

    private val screen = SourcePins.stripped(SourcePins.CONTACT_LIST_SCREEN)

    @Test
    fun screenNeverReadsOrWritesTheVaultDirectly() {
        for (needle in listOf(
            "getAllContacts(", "getAllGroups(", "pendingOffers()", "pendingInvites()",
            "declineOffer(", "saveContactMnemonic(", "rollContactAlias(", "ContactEdits.",
            "contactNeedsRepair(", "contactAwaitingPeerInbox(",
            // The vault handle itself (viewModel.vaultSelector mode reads are fine: no rows).
            "viewModel.vault.", "viewModel.vault?.", "viewModel.vault!!", "viewModel.vault ",
        )) {
            assertFalse("ContactListScreen.kt must not call `$needle` (route it through RunViewModel)", needle in screen)
        }
    }

    @Test
    fun screenCollectsTheViewModelFlows() {
        assertTrue(screen.contains("viewModel.contactList.collectAsState()"))
        assertTrue(screen.contains("viewModel.pendingConsent.collectAsState()"))
        assertTrue(screen.contains("consentToShow("))
        assertTrue(screen.contains("viewModel.declineReferralOfferInBackground("))
        assertTrue(screen.contains("viewModel.saveContactMnemonicInBackground("))
        assertTrue(screen.contains("viewModel.rollContactAliasInBackground("))
    }

    @Test
    fun theMovedVaultHelpers_stillWipeEverySourceSecret() {
        val edits = SourcePins.stripped("androidApp/src/main/java/com/vg/run/ContactListEdits.kt")
        val load = functionBody(edits, "internal fun loadContactListSnapshot(")
        assertTrue(load.contains("records.forEach { it.sharedSecret.secureWipe() }"))
        assertTrue(load.indexOf("it.toListItem()") < load.indexOf("secureWipe()"))
        val roll = functionBody(edits, "internal fun rollContactAlias(")
        assertTrue(roll.contains("updated.sharedSecret.secureWipe()"))
    }

    @Test
    fun onlyTheAnimationAndPacerLoopsRemain() {
        val loops = Regex("""while \(true\)""").findAll(screen).map { it.range.first }.toList()
        val dots = functionBody(screen, "private fun rememberConnectDotsStep(")
        val dotsStart = screen.indexOf(dots)
        val allowed = loops.filter { at ->
            (at in dotsStart until dotsStart + dots.length) ||
                screen.substring(at, minOf(screen.length, at + 120)).contains("connectPacer.observe(")
        }
        assertEquals("a `while (true)` loop outside the dots step / connect pacer: $loops", loops, allowed)
        assertEquals(2, loops.size)
    }
}
