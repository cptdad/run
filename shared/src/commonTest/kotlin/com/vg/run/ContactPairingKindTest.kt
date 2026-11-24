package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// RÚN-03: the per-contact pairing label ("Current" / "Older pairing") and the
// contact-list banner's one global dismissal flag.
//
// The label is a projection of the persisted row flag (`ContactRecord
// .ratchetBootstrapV3`), never a live MessageManager read, so it can only change
// when the row does. These tests pin the rule, that every rewrite of an existing
// row keeps the flag (the `copy()` invariant the label depends on), and the
// dismissal flag's lifetime: per vault, not carried by a move, gone after a wipe.
// ---------------------------------------------------------------------------
class ContactPairingKindTest {

    private fun up() = aeadUp() && x25519Up()
    private val cid = V3Messaging.CID

    private fun record(v3: Boolean) = ContactRecord(
        contactId = "c-k", sharedSecret = ByteArray(32) { 4 }, trustLevel = 1,
        alias = "A", aliasLastRotated = 0L, ratchetBootstrapV3 = v3,
    )

    // --- the label rule ---------------------------------------------------------------

    @Test
    fun theLabelIsTheRowFlag() {
        assertEquals(ContactPairingKind.CURRENT, ContactPairing.kindOf(record(v3 = true)))
        assertEquals(ContactPairingKind.OLDER, ContactPairing.kindOf(record(v3 = false)))
        assertFalse(ContactPairing.isOlder(record(v3 = true)))
        assertTrue(ContactPairing.isOlder(record(v3 = false)))
    }

    @Test
    fun aRowWithNoFlag_andTheSwiftBridgeShape_areOlder() {
        // A row written before DB v11 reads DEFAULT 0; the default argument is that row.
        val preV11 = ContactRecord("c-old", ByteArray(32), 0, "B", 0L)
        assertEquals(ContactPairingKind.OLDER, ContactPairing.kindOf(preV11))
        // The 15-argument constructor the Swift bridge uses always builds a legacy record.
        val bridge = ContactRecord("c-b", ByteArray(32), 0, "C", 0L, "", 0L, 0L, "", 0L, 0L, 0L, 0L, null, 0L)
        assertEquals(ContactPairingKind.OLDER, ContactPairing.kindOf(bridge))
    }

    @Test
    fun olderCount_countsOnlyOlder() {
        val k = listOf(ContactPairingKind.OLDER, ContactPairingKind.CURRENT, ContactPairingKind.OLDER)
        assertEquals(2, ContactPairing.olderCount(k))
        assertEquals(0, ContactPairing.olderCount(listOf(ContactPairingKind.CURRENT)))
        assertEquals(0, ContactPairing.olderCount(emptyList()))
    }

    @Test
    fun onlyALegacySaveIsAnOlderPairing_theAddContactNote() {
        assertTrue(ContactPairing.savedAsOlder(PairingSaveOutcome.SAVED_LEGACY))
        for (o in PairingSaveOutcome.entries.filter { it != PairingSaveOutcome.SAVED_LEGACY }) {
            assertFalse(ContactPairing.savedAsOlder(o), "$o must not show the older-pairing note")
        }
    }

    // --- every rewrite of an existing row keeps the label -------------------------------

    private fun move(from: V3TestVault): V3TestVault {
        val snapshot = VaultSnapshotIo.export(from)
        val bundle = MigrationBundle(
            schema = MigrationBundleCodec.exportSchemaFor(snapshot), from = MigrationBundle.FROM_ANDROID,
            createdMs = 1L, bundleId = MoveHandleCodec.newBundleId(), snapshot = snapshot,
        )
        val decoded = MigrationBundleCodec.decodeFromString(MigrationBundleCodec.encodeToString(bundle))
        val to = V3TestVault()
        VaultSnapshotIo.import(to, decoded.snapshot, MoveConstants.COUNTER_JUMP, decoded.bundleId)
        return to
    }

    private fun kindIn(v: VaultDatabase, id: String) = ContactPairing.kindOf(v.getContact(id)!!)

    @Test
    fun aCurrentPairing_staysCurrentThroughEditsSendsAndAMove() {
        if (!up()) return
        val p = V3Messaging.pair()
        val v = p.a.vault
        assertEquals(ContactPairingKind.CURRENT, kindIn(v, cid))
        ContactEdits.updateMnemonic(v, cid, "met at the market")
        assertEquals(ContactPairingKind.CURRENT, kindIn(v, cid), "memory edit")
        ContactEdits.rollAlias(v, cid)
        assertEquals(ContactPairingKind.CURRENT, kindIn(v, cid), "new name")
        assertTrue(p.a.mm.sendMessage(cid, "one")); p.b.mm.pollMessages(cid)
        assertTrue(p.b.mm.sendMessage(cid, "two")); p.a.mm.pollMessages(cid)
        assertEquals(ContactPairingKind.CURRENT, kindIn(v, cid), "sends and receives")
        assertEquals(ContactPairingKind.CURRENT, kindIn(move(v), cid), "a phone move")
    }

    @Test
    fun anOlderPairing_staysOlderThroughCounterBumpsEditsAndAMove() {
        if (!up()) return
        val relay = RecordingLeasingRelay()
        val vA = V3TestVault(); val vB = V3TestVault()
        LegacyPairingFixture.pair(vA, vB, "old", IN_A, IN_B, CTL_A, CTL_B)
        val a = MessageManager(vA, "http://relay.test", relay).syncAcks()
        val b = MessageManager(vB, "http://relay.test", relay).syncAcks()
        assertEquals(ContactPairingKind.OLDER, kindIn(vA, "old"))

        val before = vA.getContact("old")!!
        assertTrue(a.sendMessage("old", "static text"))
        assertTrue(vA.getContact("old")!!.outboundCounter > before.outboundCounter, "the send rewrote the row")
        assertEquals(ContactPairingKind.OLDER, kindIn(vA, "old"), "text counter bump")
        assertTrue(a.sendInboxAnnounce("old", IN_A, LegacyPairingFixture.WRITE_CAP, CTL_A, LegacyPairingFixture.WRITE_CAP))
        assertTrue(vA.getContact("old")!!.outboundCtlCounter > before.outboundCtlCounter, "the announce rewrote the row")
        assertEquals(ContactPairingKind.OLDER, kindIn(vA, "old"), "control counter bump")
        assertEquals(listOf("static text"), b.pollMessages("old").map { it.text })
        assertEquals(ContactPairingKind.OLDER, kindIn(vB, "old"), "the receiver's inbound counter bump")
        ContactEdits.updateMnemonic(vA, "old", "x")
        ContactEdits.rollAlias(vA, "old")
        assertEquals(ContactPairingKind.OLDER, kindIn(vA, "old"), "edits")
        assertEquals(ContactPairingKind.OLDER, kindIn(move(vA), "old"), "a phone move")
    }

    // --- the banner's one global dismissal flag -----------------------------------------

    @Test
    fun theBannerShows_onlyWhileAnOlderPairingExists_andUntilDismissed() {
        assertFalse(OlderPairingBanner.shouldShow(olderCount = 0, dismissed = false))
        assertTrue(OlderPairingBanner.shouldShow(olderCount = 1, dismissed = false))
        assertTrue(OlderPairingBanner.shouldShow(olderCount = 5, dismissed = false))
        assertFalse(OlderPairingBanner.shouldShow(olderCount = 5, dismissed = true))
        assertFalse(OlderPairingBanner.shouldShow(olderCount = 0, dismissed = true))
    }

    @Test
    fun dismissal_isOneGlobalRow_andStaysDismissed() {
        val v = InMemoryVault()
        v.insertContact(record(v3 = false))
        assertFalse(OlderPairingBanner.isDismissed(v))
        assertTrue(OlderPairingBanner.dismiss(v))
        assertTrue(OlderPairingBanner.isDismissed(v))
        assertEquals(listOf(OlderPairingBanner.META_KEY), v.metaKeys(), "exactly one row, naming no contact")
        // A later older pairing does not bring it back: the dismissal is one flag, not per contact.
        v.insertContact(record(v3 = false).copy(contactId = "c-later"))
        assertTrue(OlderPairingBanner.isDismissed(v))
        // Deleting contacts does not reset it either.
        v.deleteContact("c-k"); v.deleteContact("c-later")
        assertTrue(OlderPairingBanner.isDismissed(v))
    }

    @Test
    fun aReadError_showsTheBanner_andAWriteErrorNeverThrows() {
        val v = V3TestVault()
        v.inner.putMeta(OlderPairingBanner.META_KEY, "1")
        v.hookedKey = OlderPairingBanner.META_KEY
        v.hook = { throw RuntimeException("injected read error") }
        assertFalse(OlderPairingBanner.isDismissed(v), "an unreadable flag fails toward showing the notice")
        val throwing = object : VaultDatabase by InMemoryVault() {
            override fun putMeta(key: String, value: String) = throw RuntimeException("injected write error")
        }
        assertFalse(OlderPairingBanner.dismiss(throwing))
    }

    @Test
    fun theDismissal_isNotCarriedByAMove() {
        val k = OlderPairingBanner.META_KEY
        assertFalse(MoveMetaPolicy.isAllowedKey(k))
        assertTrue(
            MoveMetaPolicy.deniedPrefixes.any { k.startsWith(it) },
            "denied explicitly, so a future broad allow prefix cannot pick it up",
        )
        val v = V3TestVault()
        LegacyPairingFixture.pair(v, InMemoryVault(), "old", IN_A, IN_B, CTL_A, CTL_B)
        OlderPairingBanner.dismiss(v)
        assertFalse(k in VaultSnapshotIo.export(v).meta, "the export never carries it")
        assertFalse(OlderPairingBanner.isDismissed(move(v)), "the new phone shows the banner again")
    }

    @Test
    fun theDismissal_isGoneAfterAWipe_andIsNoContactOrGroupResidue() {
        val v = InMemoryVault()
        OlderPairingBanner.dismiss(v)
        val k = OlderPairingBanner.META_KEY
        for (id in listOf("c-k", "")) {
            assertFalse(isGroupMetaResidueForGroup(k, id))
            assertFalse(isGroupMetaResidueForContact(k, id))
            assertFalse(isScreenshotNoticeResidueForGroup(k, id))
            assertFalse(isScreenshotNoticeResidueForContact(k, id))
            assertFalse(k in ratchetMetaKeysForContact(id))
        }
        assertFalse(isReferralMetaKey(k))
        v.wipeAllTables()
        assertFalse(OlderPairingBanner.isDismissed(v))
    }

    private companion object {
        val IN_A = "E".repeat(32)
        val IN_B = "F".repeat(32)
        val CTL_A = "e".repeat(32)
        val CTL_B = "f".repeat(32)
    }
}
