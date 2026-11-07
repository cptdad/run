package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// HSDIR PIN (2026-10-08). The two worst prod connects (Android 110 s, iOS 215 s)
// both had a RECEIVED from a healthy HSDir before a NEWNYM; the post-NEWNYM
// re-fetch then hung on a dead HSDir because NEWNYM purges Tor's
// recently-asked-HSDir memory. HsDirLedger remembers, per Tor process, which
// HSDir worked; the watchdog's HSFETCH pins to it (`SERVER=$<fp>`). Both
// platforms run this class and RelayDescriptorWatchdog.parseEvent.
// ---------------------------------------------------------------------------

class HsDirLedgerTest {

    // Synthetic values — NOT any real service or relay.
    private val ours = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx"
    private val goodFp = "0123456789ABCDEF0123456789ABCDEF01234567"
    private val deadFp = "FEDCBA9876543210FEDCBA9876543210FEDCBA98"
    private val slowFp = "AAAABBBBCCCCDDDDEEEEFFFF0000111122223333"

    private fun ev(action: String, fp: String, tail: String = "", nickSep: Char = '~') =
        RelayDescriptorWatchdog.parseEvent("650 HS_DESC $action $ours NO_AUTH \$$fp${nickSep}SomeNick descIdAAAA $tail", ours)!!

    private fun pinOf(fp: String) = "SERVER=\$$fp"

    // --- the parser -------------------------------------------------------

    @Test
    fun parser_keepsOnlyTheFortyHexFingerprint() {
        assertEquals(goodFp, ev("RECEIVED", goodFp).hsDirFingerprint)
        assertEquals(goodFp, ev("RECEIVED", goodFp, nickSep = '=').hsDirFingerprint)
        assertEquals(goodFp, ev("REQUESTED", goodFp.lowercase()).hsDirFingerprint, "upper-cased")
        val bare = RelayDescriptorWatchdog.parseEvent("650 HS_DESC RECEIVED $ours NO_AUTH \$$goodFp", ours)!!
        assertEquals(goodFp, bare.hsDirFingerprint)
        val unknown = RelayDescriptorWatchdog.parseEvent("650 HS_DESC FAILED $ours NO_AUTH UNKNOWN REASON=QUERY_NO_HSDIR", ours)!!
        assertNull(unknown.hsDirFingerprint)
        assertEquals("QUERY_NO_HSDIR", unknown.failureReason)
    }

    @Test
    fun parser_rejectsMalformedAndInjectionShapedFingerprints() {
        assertNull(RelayDescriptorWatchdog.hsDirFingerprint("\$${goodFp.dropLast(1)}"))
        assertNull(RelayDescriptorWatchdog.hsDirFingerprint("\$${goodFp}0"))
        assertNull(RelayDescriptorWatchdog.hsDirFingerprint(goodFp))               // no `$`
        assertNull(RelayDescriptorWatchdog.hsDirFingerprint("\$${goodFp.dropLast(1)}G"))
        assertNull(RelayDescriptorWatchdog.hsDirFingerprint("\$${goodFp.dropLast(2)}\r\n"))
    }

    @Test
    fun parser_failureReasonIsAllowlisted() {
        assertEquals("NOT_FOUND", ev("FAILED", deadFp, "REASON=NOT_FOUND").failureReason)
        assertNull(ev("FAILED", deadFp, "REASON=SomethingSmuggled").failureReason)
        assertNull(ev("RECEIVED", goodFp).failureReason)
    }

    @Test
    fun eventAndLedgerRendering_neverCarryTheFingerprint() {
        val l = HsDirLedger()
        val e = ev("RECEIVED", goodFp)
        l.observe(e)
        for (rendered in listOf(e.toString(), l.toString(), HsDirLedger.PINNED_PHRASE, HsDirLedger.PIN_DROPPED_PHRASE)) {
            assertFalse(rendered.contains(goodFp, ignoreCase = true), rendered)
            assertFalse(rendered.contains("SomeNick"), rendered)
            assertFalse(rendered.any { it.isDigit() }, rendered)
        }
    }

    // --- the ledger -------------------------------------------------------

    @Test
    fun noReceivedYet_noPin_torPicks() {
        val l = HsDirLedger()
        assertNull(l.pinnedServerArgument())
        l.observe(ev("REQUESTED", goodFp))
        assertNull(l.pinnedServerArgument())
    }

    @Test
    fun goodHsDirIsSetOnReceived() {
        val l = HsDirLedger()
        l.observe(ev("REQUESTED", goodFp))
        l.observe(ev("RECEIVED", goodFp))
        assertEquals(pinOf(goodFp), l.pinnedServerArgument())
    }

    @Test
    fun failedHsDir_isNeverChosen_anyReason() {
        val l = HsDirLedger()
        l.observe(ev("RECEIVED", goodFp))
        l.observe(ev("FAILED", goodFp, "REASON=NOT_FOUND"))
        assertNull(l.pinnedServerArgument(), "a FAILED good HSDir loses the pin")
        l.observe(ev("RECEIVED", goodFp))
        assertNull(l.pinnedServerArgument(), "and a later RECEIVED from a bad HSDir does not restore it")
    }

    @Test
    fun stalledHsDir_isNeverChosen() {
        val l = HsDirLedger()
        l.observe(ev("RECEIVED", goodFp))
        // A later fetch stalls on a dead HSDir; the watchdog fires.
        l.observe(ev("REQUESTED", deadFp))
        l.noteStallFired()
        assertEquals(pinOf(goodFp), l.pinnedServerArgument(), "the stalled HSDir is bad; the good one stays pinned")
        // The slow one stalls the watchdog, then answers 25 s later: still not pinned to.
        l.observe(ev("REQUESTED", slowFp))
        l.noteStallFired()
        l.observe(ev("RECEIVED", slowFp))
        assertEquals(pinOf(goodFp), l.pinnedServerArgument())
    }

    @Test
    fun aPinnedHsDirThatStallsItself_isDropped() {
        val l = HsDirLedger()
        l.observe(ev("RECEIVED", goodFp))
        l.observe(ev("REQUESTED", goodFp))   // Tor's REQUESTED for our pinned HSFETCH
        l.noteStallFired()
        assertNull(l.pinnedServerArgument(), "a pin that stalled is bad now — next re-fetch goes plain")
    }

    @Test
    fun rejectedPin_isDropped_andTheRetryIsPlain_andCharged() {
        assertTrue(RelayDescriptorWatchdog.isPinRejectedReply(552))
        assertTrue(RelayDescriptorWatchdog.isPinRejectedReply(551))
        assertFalse(RelayDescriptorWatchdog.isPinRejectedReply(250))
        assertFalse(RelayDescriptorWatchdog.isPinRejectedReply(-1))
        assertFalse(RelayDescriptorWatchdog.isPinRejectedReply(512))

        // The platforms' SECOND-stage sequence, modelled on the shared pieces:
        // since 2026-10-12 (DescriptorHedge) EVERY HSFETCH is charged, so the
        // plain retry after a 552 costs a second budget unit.
        val l = HsDirLedger()
        val budget = DescriptorHedge()
        l.observe(ev("RECEIVED", goodFp))
        l.noteStallFired()
        val sent = mutableListOf<String?>()
        val server = l.pinnedServerArgument()
        sent += server
        val reply = 552
        if (server != null && RelayDescriptorWatchdog.isPinRejectedReply(reply)) {
            l.dropPin()
            assertTrue(budget.tryChargeRetry(), "budget left for the plain retry")
            sent += l.pinnedServerArgument()   // the retry
        }
        assertEquals(listOf(pinOf(goodFp), null), sent, "pinned first, then the plain retry")
        assertEquals(1, budget.spentThisSession, "the plain retry consumed a unit")
        assertNull(l.pinnedServerArgument(), "the pin stays dropped")
        // A dropped pin is not a BAD HSDir: a later RECEIVED from it pins again.
        l.observe(ev("RECEIVED", goodFp))
        assertEquals(pinOf(goodFp), l.pinnedServerArgument())
    }

    @Test
    fun newnymDoesNotClearTheLedger() {
        val l = HsDirLedger()
        l.observe(ev("RECEIVED", goodFp))
        l.observe(ev("FAILED", deadFp, "REASON=NOT_FOUND"))
        l.noteNewnym()
        assertEquals(pinOf(goodFp), l.pinnedServerArgument(), "THE point: the pin survives NEWNYM")
        // The dead one is still bad after NEWNYM.
        l.observe(ev("RECEIVED", deadFp))
        assertEquals(pinOf(goodFp), l.pinnedServerArgument())
    }

    @Test
    fun newnymForgetsPendingRequests_soTheyAreNotBlamedForTheNextStall() {
        val l = HsDirLedger()
        l.observe(ev("REQUESTED", slowFp))   // cancelled by Tor at the NEWNYM
        l.noteNewnym()
        l.noteStallFired()                   // a later stall with nothing pending
        l.observe(ev("RECEIVED", slowFp))
        assertEquals(pinOf(slowFp), l.pinnedServerArgument(), "a cancelled request proved nothing")
    }

    @Test
    fun newTorProcessClearsIt() {
        val l = HsDirLedger()
        l.observe(ev("RECEIVED", goodFp))
        l.observe(ev("FAILED", deadFp))
        l.resetForNewTorProcess()
        assertNull(l.pinnedServerArgument())
        l.observe(ev("RECEIVED", deadFp))
        assertEquals(pinOf(deadFp), l.pinnedServerArgument(), "bad marks died with the old process")
    }

    @Test
    fun anotherServicesEvents_neverReachTheLedger() {
        val other = "zyxwvutsrqponmlkjihgfedcba765432zyxwvutsrqponmlkjihgfedc"
        assertNull(RelayDescriptorWatchdog.parseEvent("650 HS_DESC RECEIVED $other NO_AUTH \$$goodFp~X", ours))
    }

    @Test
    fun pinnedArgumentHasTheOnlyShapeTheControlChannelAccepts() {
        val l = HsDirLedger()
        l.observe(ev("RECEIVED", goodFp.lowercase()))
        val arg = l.pinnedServerArgument()!!
        assertTrue(Regex("SERVER=\\$[0-9A-F]{40}").matches(arg), arg)
    }
}
