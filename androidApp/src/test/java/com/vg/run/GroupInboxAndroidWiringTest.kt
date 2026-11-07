package com.vg.run

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Android platform wiring for the third
 * GROUP-text pairing inbox.
 *
 * Source-level, same idiom as [AddContactDoneStateTest]: AddContactScreen is a
 * Composable and RunViewModel's unread sweep runs against a live vault + transport,
 * so this module's unit-test tier (no Robolectric, no mocking framework) can only
 * pin the WIRING, not exercise it behaviourally. Comments are stripped before
 * matching so prose that merely NAMES a symbol can neither satisfy nor trip a guard.
 */
class GroupInboxAndroidWiringTest {

    private val screen: String by lazy {
        SourcePins.stripped(SourcePins.ADD_CONTACT_SCREEN)
    }
    private val viewModel: String by lazy {
        SourcePins.stripped(SourcePins.RUN_VIEW_MODEL)
    }

    // -----------------------------------------------------------------------
    // 1. The QR/paste payload and the vault write carry the three pairs.
    // -----------------------------------------------------------------------

    /** The Done-step / paste QR must call the extended [PairingPayload.buildFull]
     *  signature with the group pair, not the pre-group-inbox positional call. */
    @Test
    fun theFullPayloadCarriesTheGroupPair() {
        val call = screen.functionCall("PairingPayload.buildFull(")
        assertTrue(
            "buildFull must pass grpInboxId from the third mint",
            call.contains("grpInboxId = ready.grpMinted?.inboxId"),
        )
        assertTrue(
            "buildFull must pass grpWriteCap from the third mint",
            call.contains("grpWriteCap = ready.grpMinted?.writeCapability"),
        )
    }

    /** Both the camera-save and the paste-save paths must persist the peer's and
     *  our own group inbox rows via [PairingVault.savePairedContact]'s optional
     *  grp parameters (routed through saveScannedContact). */
    @Test
    fun bothSavePathsWireTheGroupRows() {
        // Distinguishes the two CALL sites from the function DEFINITION, which
        // also contains the bare substring "saveScannedContact(".
        val saveScannedContactCalls = screen.functionBodyOccurrences("val newContactId = saveScannedContact(")
        assertTrue(
            "expected the camera-scan save and the paste-exchange save (2 call sites), found ${saveScannedContactCalls.size}",
            saveScannedContactCalls.size >= 2,
        )
        for (call in saveScannedContactCalls) {
            assertTrue(
                "saveScannedContact call must forward the peer's group inbox id:\n$call",
                call.contains("peerGrpInboxId"),
            )
            assertTrue(
                "saveScannedContact call must forward the peer's group write cap:\n$call",
                call.contains("peerGrpWriteCap"),
            )
            assertTrue(
                "saveScannedContact call must forward our minted group inbox id:\n$call",
                call.contains("myGrpInboxId"),
            )
            assertTrue(
                "saveScannedContact call must forward our minted group read cap:\n$call",
                call.contains("myGrpReadCap"),
            )
        }
        // And saveScannedContact itself must relay all four into PairingVault.
        val def = screen.functionBody("private fun saveScannedContact(")
        assertTrue(def.contains("peerGrpInboxId = peerGrpInboxId"))
        assertTrue(def.contains("peerGrpWriteCap = peerGrpWriteCap"))
        assertTrue(def.contains("myGrpInboxId = myGrpInboxId"))
        assertTrue(def.contains("myGrpReadCap = myGrpReadCap"))
    }

    /** The in-band announce fired after a full-code scan must carry the group
     *  pair too, so the scan-back peer learns our group inbox without waiting
     *  for the backfill sweep. */
    @Test
    fun theAnnounceAfterPairingCarriesTheGroupPair() {
        val call = screen.functionCall("viewModel.announceInbox(")
        assertTrue(
            "announceInbox call must pass our minted group inbox + write cap:\n$call",
            call.contains("r.grpMinted?.inboxId, r.grpMinted?.writeCapability"),
        )
        val def = viewModel.functionSignature("fun announceInbox(")
        assertTrue("announceInbox must accept myGrpInboxId", def.contains("myGrpInboxId"))
        assertTrue("announceInbox must accept peerGrpWriteCap", def.contains("peerGrpWriteCap"))
        val body = viewModel.functionBody("fun announceInbox(")
        assertTrue(
            "announceInbox must forward the group pair into sendInboxAnnounce",
            body.contains("myGrpInboxId, peerGrpWriteCap"),
        )
    }

    /** The mint pipeline's Ready state must carry the third (group) mint result,
     *  not just the text + control pair. */
    @Test
    fun theMintReadyStateCarriesTheGroupMint() {
        val def = screen.functionBody("data class Ready(")
        assertTrue("MintState.Ready must carry the group-inbox mint result", def.contains("grpMinted"))
        assertTrue(
            "the mint pipeline must construct Ready with all three mint results",
            screen.contains("MintState.Ready(result.main, result.ctl, result.grp, mySecret)"),
        )
    }

    // -----------------------------------------------------------------------
    // 2. Unread publish: the contact dot must never consume a group-only signal.
    // -----------------------------------------------------------------------

    /**
     * No path in RunViewModel may reach the
     * contact-unread map through the pre-group-inbox [MessageManager.peekUnreadCounts]
     * wrapper, nor through the group-inbox's RAM-only pending map. RunViewModel is
     * only ever allowed to consume [GroupManager.contactUnreadCounts] /
     * [GroupManager.groupUnreadCounts] / [GroupManager.primeUnreadCounts], which do
     * the mixing (or deliberately don't) in commonMain where it is pinned by
     * MetaResiduePurgeTest's siblings, not re-derived per platform.
     */
    @Test
    fun runViewModelNeverTouchesTheLegacyOrGroupInternalUnreadSymbols() {
        assertFalse(
            "RunViewModel must not call the pre-group-inbox peekUnreadCounts( wrapper — " +
                "it must go through GroupManager's contactUnreadCounts()/primeUnreadCounts()",
            viewModel.contains("peekUnreadCounts("),
        )
        assertFalse(
            "RunViewModel must never reference GroupManager's RAM-only group-inbox-pending " +
                "map directly — it is not an input to the contact dot (R8)",
            viewModel.contains("groupInboxPendingByContact"),
        )
    }

    /** The contact dot's three writers must all be sourced from the shared
     *  contact-only API, never from arithmetic RunViewModel performs itself. */
    @Test
    fun theContactDotIsPublishedOnlyFromTheSharedContactApi() {
        assertTrue(
            "the steady-state sweep must publish _unreadCounts from GroupManager.contactUnreadCounts()",
            // Prefix, not the full `()`: since 2026-10-14 the call also passes the
            // PushWakeFreshness completeness callback (a Boolean out, never a count).
            // Since the session-epoch guard the sweep result is held in a local and
            // published only while the session is still current — same source.
            viewModel.contains("val sweptContactCounts = it.contactUnreadCounts(") &&
                viewModel.contains("_unreadCounts.value = sweptContactCounts"),
        )
        assertTrue(
            "the connect-time prime must publish per-contact counts from GroupManager.primeUnreadCounts's callback",
            viewModel.contains("gm.primeUnreadCounts(blockedContactIds = emptySet())"),
        )
    }

    // -----------------------------------------------------------------------
    // Helpers (same idiom as AddContactDoneStateTest / ProcessWipeCoverTest)
    // -----------------------------------------------------------------------

    private fun String.functionSignature(signature: String): String {
        val start = indexOf(signature)
        assertTrue("precondition: `$signature` must exist", start >= 0)
        val end = indexOf(")", start).let { if (it < 0) length else it }
        return substring(start, end)
    }

    private fun String.functionBody(signature: String): String {
        val start = indexOf(signature)
        assertTrue("precondition: `$signature` must exist", start >= 0)
        val end = indexOf("\n}", start)
        assertTrue("precondition: `$signature` must be closed", end > start)
        return substring(start, end)
    }

    /** The full parenthesised call starting at [call], balanced by paren depth —
     *  robust to the multi-line, named-argument call style this codebase uses. */
    private fun String.functionCall(call: String): String {
        val start = indexOf(call)
        assertTrue("precondition: `$call` must exist", start >= 0)
        var depth = 0
        var i = start
        while (i < length) {
            when (this[i]) {
                '(' -> depth++
                ')' -> {
                    depth--
                    if (depth == 0) return substring(start, i + 1)
                }
            }
            i++
        }
        throw AssertionError("precondition: `$call` call must be closed")
    }

    /** Every balanced call to [call] in the source, in order. */
    private fun String.functionCallOccurrences(call: String): List<String> {
        val results = mutableListOf<String>()
        var from = 0
        while (true) {
            val start = indexOf(call, from)
            if (start < 0) break
            var depth = 0
            var i = start
            while (i < length) {
                when (this[i]) {
                    '(' -> depth++
                    ')' -> {
                        depth--
                        if (depth == 0) { results += substring(start, i + 1); break }
                    }
                }
                i++
            }
            from = start + call.length
        }
        return results
    }

    private fun String.functionBodyOccurrences(call: String): List<String> = functionCallOccurrences(call)
}
