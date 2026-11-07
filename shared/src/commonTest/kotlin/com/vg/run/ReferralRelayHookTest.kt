package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// The INTRODUCER-side platform contract: ReferralManager.onIntroRelayed.
//
// The introducer is the one party that learns an introduction is progressing
// (each accept passes through her) and the only one with nothing to show for it:
// onIntroFinalized fires on the two INTRODUCEES, never on her. This hook is the
// missing signal — "<X> approved", and "introduction complete" when the second
// accept crosses.
//
// Everything pinned here is RAM-ONLY derived state. The cases are written so a
// regression is loud in the direction that matters:
//  - a re-delivered accept (the relay re-serves a control blob for its retention
//    window) must NOT re-raise the event;
//  - a refused relay must still fire, as "queued" — the obligation is durable,
//    so silence would be the lie;
//  - a redrive that merely lands must NOT re-announce what the user already saw;
//    only the one that COMPLETES the introduction speaks again;
//  - a control sweep that beats the platform's hook installation must not lose
//    the event (the deferred latch), and must not hoard aliases past a lock
//    (scrubInMemory);
//  - a deleted contact must produce NOTHING, not a placeholder naming a
//    relationship the user erased.
// ---------------------------------------------------------------------------

private const val RH_RELAY = "http://relay.test"
private val RH_CAP_W = "W".repeat(43)
private val RH_CAP_X = "X".repeat(43)

private fun rhOk() = HttpResult(202, "", true)
private fun rhRefused() = HttpResult(500, "nope", false)

/** A minimal ref-accept body: the introducer only ever reads `ii` and forwards
 *  the rest verbatim, so the peer material can be fixed filler here. */
private fun rhAcceptJson(introId: String) =
    """{"ii":${jsonEscapeString(introId)},"pk":"AAAA","ib":"ib","wc":"wc","cib":"cib","cwc":"cwc"}"""

/** Introducer ("me") paired with both introducees on the control channel. */
private class RhFixture {
    val vault = InMemoryVault()
    val http = RecordingRelayHttp()
    val mgr = MessageManager(vault, RH_RELAY, http as RelayHttp)
    val bCtlOut = "bbct" + "1".repeat(28)
    val cCtlOut = "ccct" + "2".repeat(28)

    init {
        vault.insertContact(ContactRecord("bb", generateSecureRandom(32), 0, "Bob", 0L))
        vault.insertContact(ContactRecord("cc", generateSecureRandom(32), 0, "Carol", 0L))
        vault.insertInboxId(InboxIdRecord(bCtlOut, "bb", 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, RH_CAP_W))
        vault.insertInboxId(InboxIdRecord(cCtlOut, "cc", 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, RH_CAP_X))
    }

    fun newManager() = ReferralManager(vault) { mgr }

    /** A manager with NO transport — every relay attempt folds to `false`, which
     *  is the "queued for redrive" half of the contract and needs no AEAD. */
    fun newOfflineManager() = ReferralManager(vault) { null }

    /** Seeds an introducer session as if [startReferral] had already run and both
     *  offers had landed, so the offline cases never touch the transport. */
    fun seedSession(introId: String, relayed: Set<String> = emptySet()) {
        vault.putMeta(
            ReferralMetaKeys.SESSION_PREFIX + introId,
            encodeStoredSession(
                StoredSession("bb", "cc", relayed, currentTimeMillis(), setOf("bb", "cc"), 0)
            ),
        )
    }

    fun sessionRecord(introId: String) = vault.getMeta(ReferralMetaKeys.SESSION_PREFIX + introId)

    fun accept(rm: ReferralManager, from: String, introId: String) =
        rm.handleControl(from, MessageManager.CONTROL_KIND_REFERRAL_ACCEPT, rhAcceptJson(introId))
}

private fun rhCollector(): Pair<MutableList<ReferralRelayEvent>, (ReferralRelayEvent) -> Unit> {
    val seen = mutableListOf<ReferralRelayEvent>()
    val hook: (ReferralRelayEvent) -> Unit = { seen.add(it) }
    return seen to hook
}

class ReferralRelayHookTest {

    // -----------------------------------------------------------------------
    // The two happy fires: one accept, then the one that completes.
    // -----------------------------------------------------------------------

    @Test
    fun theFirstAcceptFiresOneRelayedEventThatIsNotYetComplete() {
        if (!aeadUp()) return
        val f = RhFixture()
        f.http.script(rhOk(), rhOk())
        val rm = f.newManager()
        val introId = assertNotNull(rm.startReferral("bb", "cc"))
        val (seen, hook) = rhCollector()
        rm.onIntroRelayed = hook

        f.http.script(rhOk())
        f.accept(rm, "bb", introId)

        val e = seen.single()
        assertEquals(introId, e.introId)
        assertEquals("bb", e.acceptedByContactId, "the accept's SENDER is the party who approved")
        assertEquals("Bob", e.acceptedByAlias)
        assertEquals("cc", e.otherContactId, "the event names the party it was forwarded to")
        assertEquals("Carol", e.otherAlias)
        assertTrue(e.relayed, "the forward succeeded")
        assertFalse(e.complete, "one side of two has crossed — the introduction is not done")
        assertNotNull(f.sessionRecord(introId), "an incomplete session is still durable")
    }

    @Test
    fun theSecondAcceptCompletesTheIntroduction() {
        if (!aeadUp()) return
        val f = RhFixture()
        f.http.script(rhOk(), rhOk())
        val rm = f.newManager()
        val introId = assertNotNull(rm.startReferral("bb", "cc"))
        val (seen, hook) = rhCollector()
        rm.onIntroRelayed = hook

        f.http.script(rhOk(), rhOk())
        f.accept(rm, "bb", introId)
        f.accept(rm, "cc", introId)

        assertEquals(2, seen.size)
        assertFalse(seen[0].complete)
        val e = seen[1]
        assertEquals("cc", e.acceptedByContactId)
        assertEquals("Carol", e.acceptedByAlias)
        assertEquals("bb", e.otherContactId)
        assertEquals("Bob", e.otherAlias)
        assertTrue(e.relayed)
        assertTrue(e.complete, "BOTH accepts have now been relayed")
        assertNull(
            f.sessionRecord(introId),
            "`complete` must be the SAME condition that drops the session — not an independent guess",
        )
    }

    /** The aliases are read at FIRE time, never snapshotted at session creation:
     *  an alias may have rotated while the introduction was in flight. */
    @Test
    fun theAliasesAreReadFromTheVaultAtFireTime() {
        if (!aeadUp()) return
        val f = RhFixture()
        f.http.script(rhOk(), rhOk())
        val rm = f.newManager()
        val introId = assertNotNull(rm.startReferral("bb", "cc"))
        val (seen, hook) = rhCollector()
        rm.onIntroRelayed = hook

        val bob = assertNotNull(f.vault.getContact("bb"))
        f.vault.insertContact(bob.copy(alias = "Bob (rotated)"))
        f.http.script(rhOk())
        f.accept(rm, "bb", introId)

        assertEquals("Bob (rotated)", seen.single().acceptedByAlias)
    }

    // -----------------------------------------------------------------------
    // A refused relay is "queued", never silence — and the durable obligation
    // is untouched by the hook.
    // -----------------------------------------------------------------------

    @Test
    fun aRefusedRelayFiresAQueuedEvent_andStillRecordsTheRedrive() {
        val f = RhFixture()
        f.seedSession("rh1")
        val rm = f.newOfflineManager()            // no transport ⇒ the forward folds to false
        val (seen, hook) = rhCollector()
        rm.onIntroRelayed = hook

        f.accept(rm, "bb", "rh1")

        val e = seen.single()
        assertEquals("rh1", e.introId)
        assertEquals("bb", e.acceptedByContactId)
        assertEquals("cc", e.otherContactId)
        assertFalse(e.relayed, "a queued accept must be reported as queued, not as delivered")
        assertFalse(e.complete)
        assertNotNull(
            f.vault.getMeta(ReferralMetaKeys.REDRIVE_PREFIX + "rh1:cc"),
            "the durable `ref_r` obligation is unchanged by the UI hook",
        )
    }

    // -----------------------------------------------------------------------
    // Dedupe: one approval, one event.
    // -----------------------------------------------------------------------

    @Test
    fun aReDeliveredAcceptDoesNotReRelayOrFireASecondEvent() {
        if (!aeadUp()) return
        val f = RhFixture()
        f.http.script(rhOk(), rhOk())
        val rm = f.newManager()
        val introId = assertNotNull(rm.startReferral("bb", "cc"))
        val (seen, hook) = rhCollector()
        rm.onIntroRelayed = hook

        f.http.script(rhOk())
        f.accept(rm, "bb", introId)
        assertEquals(1, seen.size)

        // The relay keeps serving the blob for its retention window, so the very
        // same accept arrives again on the next control poll — and a malicious
        // sender could replay it indefinitely. A leg already in the
        // session's `relayed` set must not be forwarded again (that would
        // push-bomb the OTHER party through the introducer on every replay), nor
        // re-raise the UI event.
        val before = f.http.calls.size
        f.accept(rm, "bb", introId)

        assertEquals(1, seen.size, "a side already in the session's relayed set must not re-raise the event")
        assertEquals(
            before, f.http.calls.size,
            "a leg already relayed must not be re-forwarded — a genuine redelivery need recovers via relayRedrives, not via re-forwarding an inbound accept",
        )
    }

    /** The offline twin: an accept we could not forward is NOT in `relayed`, so a
     *  later re-delivery is still news (it may be the one that lands). */
    @Test
    fun aReDeliveredAcceptThatWasNeverRelayed_isStillReported() {
        val f = RhFixture()
        f.seedSession("rh2")
        val rm = f.newOfflineManager()
        val (seen, hook) = rhCollector()
        rm.onIntroRelayed = hook

        f.accept(rm, "bb", "rh2")
        f.accept(rm, "bb", "rh2")

        assertEquals(2, seen.size, "nothing was relayed, so the dedupe gate must not suppress the retry")
        assertTrue(seen.all { !it.relayed && !it.complete })
    }

    // -----------------------------------------------------------------------
    // The redrive leg: only COMPLETION is worth a second event.
    // -----------------------------------------------------------------------

    @Test
    fun aRedriveSuccessThatCompletesTheSession_firesExactlyOneCompleteEvent() {
        if (!aeadUp()) return
        val f = RhFixture()
        f.http.script(rhOk(), rhOk())
        val rm = f.newManager()
        val introId = assertNotNull(rm.startReferral("bb", "cc"))
        val (seen, hook) = rhCollector()
        rm.onIntroRelayed = hook

        f.http.script(rhOk())                      // Bob's accept is forwarded to Carol
        f.accept(rm, "bb", introId)
        f.http.script(rhRefused())                 // Carol's accept cannot reach Bob
        f.accept(rm, "cc", introId)
        assertEquals(2, seen.size)
        assertTrue(seen.none { it.complete })
        assertNotNull(f.vault.getMeta(ReferralMetaKeys.REDRIVE_PREFIX + "$introId:bb"))

        f.http.script(rhOk())                      // …and lands on the next control sweep
        rm.runMaintenance()

        assertEquals(3, seen.size, "the completion is the one redrive outcome worth announcing")
        val e = seen[2]
        assertEquals("cc", e.acceptedByContactId, "the redrive event names the accept's SENDER")
        assertEquals("Carol", e.acceptedByAlias)
        assertEquals("bb", e.otherContactId)
        assertEquals("Bob", e.otherAlias)
        assertTrue(e.relayed)
        assertTrue(e.complete)
        assertNull(f.sessionRecord(introId), "the completed session is dropped")

        // A further sweep has nothing left to do and must stay silent.
        f.http.script(rhOk())
        rm.runMaintenance()
        assertEquals(3, seen.size)
    }

    @Test
    fun aRedriveSuccessThatLeavesTheSessionIncomplete_firesNothing() {
        if (!aeadUp()) return
        val f = RhFixture()
        f.http.script(rhOk(), rhOk())
        val rm = f.newManager()
        val introId = assertNotNull(rm.startReferral("bb", "cc"))
        val (seen, hook) = rhCollector()
        rm.onIntroRelayed = hook

        f.http.script(rhRefused())                 // Bob's accept is queued
        f.accept(rm, "bb", introId)
        assertEquals(1, seen.size)
        assertFalse(seen.single().relayed)

        f.http.script(rhOk())                      // the redrive lands, Carol has not accepted
        rm.runMaintenance()

        assertEquals(
            1, seen.size,
            "the user already saw this accept as queued — a landing that completes nothing is not news",
        )
        assertNull(f.vault.getMeta(ReferralMetaKeys.REDRIVE_PREFIX + "$introId:cc"), "the obligation is settled")
        assertNotNull(f.sessionRecord(introId), "…but the session waits for Carol")
    }

    // -----------------------------------------------------------------------
    // The deferred latch — a control sweep can beat the platform's hook.
    // -----------------------------------------------------------------------

    @Test
    fun aHookInstalledAfterTheEventFired_stillReceivesIt() {
        val f = RhFixture()
        f.seedSession("rh3")
        val rm = f.newOfflineManager()
        f.accept(rm, "bb", "rh3")                  // no hook installed yet

        val (seen, hook) = rhCollector()
        rm.onIntroRelayed = hook
        assertEquals(1, seen.size, "an event that predates the hook must be delivered on installation")
        assertEquals("rh3", seen.single().introId)
        assertEquals("Bob", seen.single().acceptedByAlias)

        // …and exactly once: the latch is drained, not replayed.
        val (again, hook2) = rhCollector()
        rm.onIntroRelayed = hook2
        assertTrue(again.isEmpty(), "the deferred list is one-shot")
    }

    @Test
    fun theDeferredListIsBounded_andDropsTheOLDEST() {
        val f = RhFixture()
        repeat(12) { i -> f.seedSession("rhb$i") }
        // Constructed AFTER the seeding so all twelve sessions rehydrate into RAM.
        val rm = f.newOfflineManager()
        repeat(12) { i -> f.accept(rm, "bb", "rhb$i") }

        val (seen, hook) = rhCollector()
        rm.onIntroRelayed = hook
        assertEquals(8, seen.size, "the pending list is capped at 8")
        assertEquals(
            (4..11).map { "rhb$it" }, seen.map { it.introId },
            "the OLDEST are dropped — a live UI wants the most recent approvals",
        )
    }

    /** The pending list holds contact ALIASES, so a lock/wipe must clear it — the
     *  same reason every other handshake map is cleared there. */
    @Test
    fun scrubInMemoryClearsTheDeferredEvents() {
        val f = RhFixture()
        f.seedSession("rh4")
        val rm = f.newOfflineManager()
        f.accept(rm, "bb", "rh4")

        rm.scrubInMemory()

        val (seen, hook) = rhCollector()
        rm.onIntroRelayed = hook
        assertTrue(seen.isEmpty(), "aliases latched for the UI must not survive a lock")
    }

    // -----------------------------------------------------------------------
    // A deleted contact has nothing to show.
    // -----------------------------------------------------------------------

    @Test
    fun aDeletedSender_firesNothing() {
        val f = RhFixture()
        f.seedSession("rh5")
        val rm = f.newOfflineManager()
        val (seen, hook) = rhCollector()
        rm.onIntroRelayed = hook

        f.vault.deleteContact("bb")
        f.accept(rm, "bb", "rh5")

        assertTrue(seen.isEmpty(), "there is nothing to show for a contact the user erased")
        assertNotNull(
            f.vault.getMeta(ReferralMetaKeys.REDRIVE_PREFIX + "rh5:cc"),
            "the relay path itself is unchanged — only the UI signal is suppressed",
        )
    }

    @Test
    fun aDeletedOtherParty_firesNothing() {
        val f = RhFixture()
        f.seedSession("rh6")
        val rm = f.newOfflineManager()
        val (seen, hook) = rhCollector()
        rm.onIntroRelayed = hook

        f.vault.deleteContact("cc")
        f.accept(rm, "bb", "rh6")

        assertTrue(seen.isEmpty())
    }

    // -----------------------------------------------------------------------
    // Blast radius: a hostile/buggy hook, and zero persistence.
    // -----------------------------------------------------------------------

    @Test
    fun aThrowingHookNeverBreaksTheRelayPath() {
        val f = RhFixture()
        f.seedSession("rh7")
        val rm = f.newOfflineManager()
        rm.onIntroRelayed = { throw RuntimeException("UI blew up") }

        f.accept(rm, "bb", "rh7")

        assertNotNull(
            f.vault.getMeta(ReferralMetaKeys.REDRIVE_PREFIX + "rh7:cc"),
            "the durable obligation is recorded before the hook runs, and a throw must not undo it",
        )
    }

    /** RAM-ONLY: installing a hook must not change a single byte of vault state.
     *  Two identical runs, one observed and one not, must leave the same keys. */
    @Test
    fun theHookPersistsNothing() {
        val withHook = RhFixture()
        withHook.seedSession("rh8")
        val observed = withHook.newOfflineManager()
        val (seen, hook) = rhCollector()
        observed.onIntroRelayed = hook
        withHook.accept(observed, "bb", "rh8")
        assertEquals(1, seen.size, "precondition: the observed run really did fire")

        val withoutHook = RhFixture()
        withoutHook.seedSession("rh8")
        val silent = withoutHook.newOfflineManager()
        withoutHook.accept(silent, "bb", "rh8")

        assertEquals(
            withoutHook.vault.meta.keys.sorted(), withHook.vault.meta.keys.sorted(),
            "the UI hook must introduce no `_meta` key of its own",
        )
    }
}
