package com.vg.run

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Guards the "sharedSecret wipe parity" cluster:
 *
 *   - iOS had NO `sharedSecret.secureWipe()` anywhere — nine-plus UI
 *     sites held live Contact records with an un-zeroed legacy-envelope key
 *     pre-image.
 *   - `GroupInfoScreen.kt` / `CreateGroupScreen.kt` wiped the
 *     FILTERED subset, leaving the filtered-out records (the group's own
 *     members) with a live secret.
 *   - `GroupInfoScreen.kt` / `GroupConversationScreen.kt` had two more
 *     `getContact` sites that never wiped `sharedSecret` at all.
 *
 * SOURCE-LEVEL, same technique as [AdminHandoffLeaveGateSourceTest]: these
 * screens need a live vault + Compose runtime to exercise behaviorally, and
 * this module's unit-test tier has no Robolectric. Bodies are scanned with
 * comments STRIPPED so prose that merely names a call can neither satisfy
 * nor trip a guard. Non-vacuousness: reverting any one of these fixes (wipe
 * the filtered list instead of the source list, or drop the wipe entirely)
 * fails the corresponding assertion.
 */
class SharedSecretWipeParitySourceTest {

    private val groupInfoScreen: String by lazy {
        SourcePins.stripped(SourcePins.GROUP_INFO_SCREEN)
    }
    private val createGroupScreen: String by lazy {
        stripComments(File(repoRoot(), "androidApp/src/main/java/com/vg/run/CreateGroupScreen.kt").readText())
    }
    private val groupConversationScreen: String by lazy {
        SourcePins.stripped(SourcePins.GROUP_CONVERSATION_SCREEN)
    }
    private val groupViewsSwift: String by lazy {
        stripComments(File(repoRoot(), "iosApp/iosApp/GroupViews.swift").readText())
    }
    private val contactListViewSwift: String by lazy {
        stripComments(File(repoRoot(), "iosApp/iosApp/ContactListView.swift").readText())
    }
    private val conversationViewSwift: String by lazy {
        stripComments(File(repoRoot(), "iosApp/iosApp/ConversationView.swift").readText())
    }
    private val userSafetySwift: String by lazy {
        stripComments(File(repoRoot(), "iosApp/iosApp/UserSafety.swift").readText())
    }
    private val appStateSwift: String by lazy {
        stripComments(iosAppStateSources())
    }

    // -----------------------------------------------------------------------
    // The wipe must run over the UNFILTERED source list, not the
    // filtered subset (the bug: filtered-out records kept a live
    // secret because the wipe loop only ever saw the post-filter list).
    // -----------------------------------------------------------------------

    @Test
    fun groupInfoScreen_eligibleToAdd_wipesTheUnfilteredSourceList() {
        val block = groupInfoScreen.namedBlock("val eligibleToAdd = remember(refreshKey) {")
        val allRecordsAt = block.indexOf("val allRecords = vault.getAllContacts()")
        val filterAt = block.indexOf(".filter {")
        val wipeAt = block.indexOf("allRecords.forEach { it.sharedSecret.secureWipe() }")
        assertTrue("precondition: an unfiltered allRecords binding must exist. Block was:\n$block", allRecordsAt >= 0)
        assertTrue("precondition: a filter must exist", filterAt > allRecordsAt)
        assertTrue(
            "the wipe MUST run over allRecords (the unfiltered source), never over the " +
                "filtered `records` subset — reverting to `records.forEach { ... }` re-opens " +
                "the bug where filtered-out group members keep a live sharedSecret. Block was:\n$block",
            wipeAt > filterAt,
        )
    }

    @Test
    fun createGroupScreen_eligibleContacts_wipesTheUnfilteredSourceList() {
        val block = createGroupScreen.namedBlock("val eligibleContacts = remember {")
        val allRecordsAt = block.indexOf("val allRecords = vault.getAllContacts()")
        val filterAt = block.indexOf(".filter {")
        val wipeAt = block.indexOf("allRecords.forEach { it.sharedSecret.secureWipe() }")
        assertTrue("precondition: an unfiltered allRecords binding must exist. Block was:\n$block", allRecordsAt >= 0)
        assertTrue("precondition: a filter must exist", filterAt > allRecordsAt)
        assertTrue(
            "the wipe MUST run over allRecords (the unfiltered source), never over the " +
                "filtered `records` subset. Block was:\n$block",
            wipeAt > filterAt,
        )
    }

    // -----------------------------------------------------------------------
    // The two previously-un-wiped single-contact getContact() sites.
    // -----------------------------------------------------------------------

    @Test
    fun groupInfoScreen_membersMap_wipesTheResolvedContactSecret() {
        val block = groupInfoScreen.namedBlock("val members = remember(refreshKey) {")
        val getContactAt = block.indexOf("vault.getContact(it)")
        val wipeAt = block.indexOf("contact?.sharedSecret?.secureWipe()")
        assertTrue("precondition: the per-member getContact() call must exist", getContactAt >= 0)
        assertTrue(
            "GroupInfoScreen's member-resolution loop must wipe the resolved contact's " +
                "sharedSecret after projecting alias/mnemonic/resolved. Block was:\n$block",
            wipeAt > getContactAt,
        )
    }

    @Test
    fun groupConversationScreen_senderMnemonicLookup_wipesTheSecret() {
        val onLongClickAt = groupConversationScreen.indexOf("val senderRecord = vault.getContact(message.senderContactId)")
        assertTrue("precondition: the sender mnemonic lookup must exist", onLongClickAt >= 0)
        val window = groupConversationScreen.substring(onLongClickAt, minOf(onLongClickAt + 300, groupConversationScreen.length))
        assertTrue(
            "GroupConversationScreen's sender-mnemonic long-click lookup must wipe " +
                "senderRecord.sharedSecret. Window was:\n$window",
            window.contains("senderRecord?.sharedSecret?.secureWipe()"),
        )
    }

    // -----------------------------------------------------------------------
    // iOS parity (read-only reference checks): every sibling Swift
    // site this Android fix mirrors must carry the corresponding secureWipe() call.
    // -----------------------------------------------------------------------

    @Test
    fun iosContactListView_loadContacts_wipesAllContacts() {
        val block = contactListViewSwift.namedBlock("private func loadContacts() {")
        assertTrue(
            "ContactListView.loadContacts() must wipe every source record's sharedSecret " +
                "Block was:\n$block",
            block.contains("for contact in allContacts { contact.sharedSecret.secureWipe() }"),
        )
    }

    @Test
    fun iosContactListView_rollAlias_wipesTheUpdatedRecord() {
        val block = contactListViewSwift.namedBlock("private func rollAlias(contactId: String) {")
        assertTrue(
            "ContactListView.rollAlias() must wipe `updated.sharedSecret` after projecting " +
                "the alias. Block was:\n$block",
            block.contains("updated.sharedSecret.secureWipe()"),
        )
    }

    @Test
    fun iosAppState_reviewPromptCount_wipesTheRecords() {
        assertTrue(
            "AppState's review-prompt contact-count read must wipe every record's " +
                "sharedSecret — the old comment falsely claimed no touch/retain was needed " +
                "File was scanned for the fix.",
            appStateSwift.contains("for record in records { record.sharedSecret.secureWipe() }"),
        )
    }

    @Test
    fun iosAppState_pushWakeContactIds_wipesTheRecords() {
        assertTrue(
            "AppState's push-wake contactIds derivation must wipe every record's " +
                "sharedSecret before dropping the array.",
            appStateSwift.contains("for record in allContactRecords { record.sharedSecret.secureWipe() }"),
        )
    }

    @Test
    fun iosConversationView_contactLookups_wipeTheirRecords() {
        assertTrue(
            "ConversationView.contactAlias() must wipe the looked-up record.",
            conversationViewSwift.namedBlock("private func contactAlias() -> String {")
                .contains("record?.sharedSecret.secureWipe()"),
        )
        assertTrue(
            "ConversationView.vouchedByContactId() must wipe the looked-up record.",
            conversationViewSwift.namedBlock("private func vouchedByContactId() -> String? {")
                .contains("record?.sharedSecret.secureWipe()"),
        )
        assertTrue(
            "ConversationView.introducerAlias() must wipe the looked-up record.",
            conversationViewSwift.namedBlock("private func introducerAlias() -> String? {")
                .contains("record?.sharedSecret.secureWipe()"),
        )
    }

    @Test
    fun iosUserSafety_load_wipesTheUnfilteredSourceList() {
        val block = userSafetySwift.namedBlock("private func load() {")
        val allContactsAt = block.indexOf("let allContacts = vault.getAllContacts()")
        val filterAt = block.indexOf(".filter {")
        val wipeAt = block.indexOf("for contact in allContacts { contact.sharedSecret.secureWipe() }")
        assertTrue("precondition: an unfiltered allContacts binding must exist. Block was:\n$block", allContactsAt >= 0)
        assertTrue("precondition: a filter must exist", filterAt > allContactsAt)
        assertTrue(
            "UserSafety.load() must wipe the UNFILTERED allContacts list, mirroring " +
                "the Android fix (never just the blocked subset). Block was:\n$block",
            wipeAt > filterAt,
        )
    }

    @Test
    fun iosGroupViews_loadEligibleContacts_wipesTheUnfilteredSourceList() {
        val block = groupViewsSwift.namedBlock("private func loadEligibleContacts() {")
        val allContactsAt = block.indexOf("let allContacts = vault.getAllContacts()")
        val filterAt = block.indexOf(".filter {")
        val wipeAt = block.indexOf("for contact in allContacts { contact.sharedSecret.secureWipe() }")
        assertTrue("precondition: an unfiltered allContacts binding must exist. Block was:\n$block", allContactsAt >= 0)
        assertTrue("precondition: a filter must exist", filterAt > allContactsAt)
        assertTrue(
            "GroupViews' create-group loadEligibleContacts() must wipe the UNFILTERED " +
                "allContacts list (parity). Block was:\n$block",
            wipeAt > filterAt,
        )
    }

    @Test
    fun iosGroupViews_groupInfoReload_wipesMemberContactAndUnfilteredEligibleList() {
        val block = groupViewsSwift.namedBlock("private func reload() {")
        assertTrue(
            "GroupViews' group-info reload() must wipe the per-member resolved contact's " +
                "sharedSecret (parity). Block was:\n$block",
            block.contains("contact?.sharedSecret.secureWipe()"),
        )
        val allContactsAt = block.indexOf("let allContacts = vault.getAllContacts()")
        val filterAt = block.indexOf(".filter {", allContactsAt)
        val wipeAt = block.indexOf("for contact in allContacts { contact.sharedSecret.secureWipe() }")
        assertTrue("precondition: an unfiltered allContacts binding must exist for eligibleToAdd. Block was:\n$block", allContactsAt >= 0)
        assertTrue(
            "GroupViews' eligibleToAdd must wipe the UNFILTERED allContacts list " +
                "(parity), not the filtered subset. Block was:\n$block",
            wipeAt > filterAt,
        )
    }

    @Test
    fun iosGroupViews_senderMnemonicLookup_wipesTheSecret() {
        val at = groupViewsSwift.indexOf("let senderRecord = appState.vault?.getContact(contactId: msg.senderContactId)")
        assertTrue("precondition: the sender mnemonic lookup must exist", at >= 0)
        val window = groupViewsSwift.substring(at, minOf(at + 300, groupViewsSwift.length))
        assertTrue(
            "GroupViews' sender-mnemonic long-press lookup must wipe senderRecord's " +
                "sharedSecret (parity). Window was:\n$window",
            window.contains("senderRecord?.sharedSecret.secureWipe()"),
        )
    }

    // -----------------------------------------------------------------------

    /** Extracts the brace-balanced body starting at a Kotlin/Swift block-opening anchor. */
    private fun String.namedBlock(anchor: String): String {
        val start = indexOf(anchor)
        assertTrue("precondition: `$anchor` must exist", start >= 0)
        var depth = 0
        var i = start
        var seenOpen = false
        while (i < length) {
            when (this[i]) {
                '{' -> { depth++; seenOpen = true }
                '}' -> {
                    depth--
                    if (seenOpen && depth == 0) return substring(start, i + 1)
                }
            }
            i++
        }
        throw AssertionError("`$anchor` block never closes (unbalanced braces)")
    }
}
