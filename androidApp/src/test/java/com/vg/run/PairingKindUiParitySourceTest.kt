package com.vg.run

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * RÚN-03 parity: both contact lists label a contact from the SAME shared rule over the
 * record they already loaded (never a live MessageManager read), both expose the same
 * accessibility ids for the label, the guide and the banner, both persist the banner
 * dismissal only through the shared [OlderPairingBanner], and both add-contact screens
 * show the "ask them to update" note from the shared outcome rule. No per-row marker.
 *
 * SOURCE-LEVEL (the screens need a live vault this JVM tier cannot build); comments
 * are stripped first so prose cannot satisfy a check.
 */
class PairingKindUiParitySourceTest {

    private val androidList = SourcePins.stripped(SourcePins.CONTACT_LIST_SCREEN)
    private val androidAdd = SourcePins.stripped(SourcePins.ADD_CONTACT_SCREEN)
    private val androidEdits = SourcePins.stripped("androidApp/src/main/java/com/vg/run/ContactListEdits.kt")
    private val androidItem = SourcePins.stripped("androidApp/src/main/java/com/vg/run/ContactListItem.kt")
    private val iosList = SourcePins.stripped("iosApp/iosApp/ContactListView.swift")
    private val iosAdd = SourcePins.stripped("iosApp/iosApp/AddContactView.swift")

    private val sharedIds = listOf(
        "menu_pairing_kind", "menu_pair_again_help", "pair_again_guide", "pair_again_guide_close",
        "older_pairing_banner", "older_pairing_banner_close",
    )

    @Test
    fun bothListsExposeTheSameIds_once() {
        for (id in sharedIds) {
            assertEquals("Android \"$id\"", 1, androidList.split("\"$id\"").size - 1)
            assertEquals("iOS \"$id\"", 1, iosList.split("\"$id\"").size - 1)
        }
        assertEquals(1, androidAdd.split("\"add_contact_older_pairing_note\"").size - 1)
        assertEquals(1, iosAdd.split("\"add_contact_older_pairing_note\"").size - 1)
    }

    @Test
    fun bothProjectTheLabelFromTheRowThroughTheSharedRule() {
        assertTrue(androidItem.contains("pairingKind = ContactPairing.kindOf(this)"))
        assertTrue(iosList.contains("olderPairing: ContactPairing.shared.isOlder(record: contact)"))
        for (src in listOf(androidList, androidEdits, androidItem, iosList)) {
            assertFalse("the label must never come from a live MessageManager read", src.contains("isRatchetBootstrapV3"))
        }
    }

    @Test
    fun bothPersistTheDismissalOnlyThroughTheSharedFlag() {
        assertTrue(androidEdits.contains("OlderPairingBanner.isDismissed(vault)"))
        assertTrue(androidEdits.contains("OlderPairingBanner.dismiss(vault)"))
        assertTrue(iosList.contains("OlderPairingBanner.shared.isDismissed(vault: vault)"))
        assertTrue(iosList.contains("OlderPairingBanner.shared.dismiss(vault: vault)"))
        assertTrue(iosList.contains("OlderPairingBanner.shared.shouldShow("))
        assertTrue(SourcePins.stripped("androidApp/src/main/java/com/vg/run/ContactListState.kt")
            .contains("OlderPairingBanner.shouldShow("))
        // The literal key lives only in commonMain.
        for (src in listOf(androidList, androidEdits, iosList)) {
            assertFalse(src.contains("older_pairing_banner_v1"))
        }
    }

    @Test
    fun bothAddContactScreensShowTheNoteFromTheSharedOutcomeRule() {
        assertTrue(androidAdd.contains("ContactPairing.savedAsOlder(outcome)"))
        assertTrue(iosAdd.contains("ContactPairing.shared.savedAsOlder(outcome: outcome)"))
    }

    @Test
    fun noPerRowMarker() {
        // Owner decision: the label lives in the menu and the banner; the rows stay as they are.
        val androidRow = androidList.substring(androidList.indexOf("private fun ContactRow("))
            .let { it.substring(0, it.indexOf("private fun GroupRow(")) }
        assertFalse(androidRow.contains("pairingKind"))
        assertFalse(iosList.contains("contact_older_pairing_"))
        assertFalse(androidList.contains("contact_older_pairing_"))
    }
}
