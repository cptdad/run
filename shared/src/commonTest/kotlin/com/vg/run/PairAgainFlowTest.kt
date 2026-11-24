package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// RÚN-03: "pair again" for a contact on an OLDER pairing, through the real shared
// pairing session and the real MessageManager, in the order the in-app guide gives:
// pair again → check the new contact works both ways → delete the old one.
//
// Pairing again is NOT an in-place upgrade: it makes a second, independent contact
// (RepairWhileAlreadyPairedTest pins the independence). These tests pin what the
// guide tells the user:
//  - a cancelled pair-again leaves the existing contact usable, still "Older";
//  - a completed pair-again between two current builds is "Current" and its first
//    text from either side rides the ratchet; the old contact keeps working until
//    it is deleted;
//  - pairing again with a build that has no one-time key exchange gives another
//    older pairing (what the add-contact note reports);
//  - the new pairing's lost-state rule is unchanged (the send is refused);
//  - in an existing group the re-paired person stays unresolved until the admin
//    removes and re-adds them (today's behaviour, pinned so the guide's sentence
//    changes together with it).
// ---------------------------------------------------------------------------
class PairAgainFlowTest {

    private fun up() = aeadUp() && x25519Up()
    private val r = LegacyPairingFixture.READ_CAP
    private val wc = LegacyPairingFixture.WRITE_CAP
    private fun texts(l: List<ReceivedMessage>) = l.map { it.text }

    /** One phone: its vault and its session manager on the shared relay. */
    private class Phone(val vault: V3TestVault, val mm: MessageManager)

    private class World(val relay: RecordingLeasingRelay, val a: Phone, val b: Phone)

    /** Two phones that already share the OLDER pairing [OLD]. */
    private fun withOlderPairing(): World {
        val relay = RecordingLeasingRelay()
        val vA = V3TestVault(); val vB = V3TestVault()
        LegacyPairingFixture.pair(vA, vB, OLD, OLD_IN_A, OLD_IN_B, OLD_CTL_A, OLD_CTL_B)
        fun mm(v: VaultDatabase) = MessageManager(v, "http://relay.test", relay).syncAcks()
        return World(relay, Phone(vA, mm(vA)), Phone(vB, mm(vB)))
    }

    private fun talk(x: Phone, y: Phone, id: String, tag: String) {
        assertTrue(x.mm.sendMessage(id, "$tag x→y")); assertEquals(listOf("$tag x→y"), texts(y.mm.pollMessages(id)))
        assertTrue(y.mm.sendMessage(id, "$tag y→x")); assertEquals(listOf("$tag y→x"), texts(x.mm.pollMessages(id)))
    }

    private fun kind(p: Phone, id: String) = ContactPairing.kindOf(assertNotNull(p.vault.getContact(id)))

    /** Every field of a row except identity-free formatting, secret included (as base64). */
    private fun rowPrint(c: ContactRecord) = listOf(
        c.contactId, encodeBase64(c.sharedSecret), c.alias, c.mnemonic, c.trustLevel, c.aliasLastRotated,
        c.outboundCounter, c.inboundCounter, c.inboundEpoch, c.outboundCtlCounter, c.inboundCtlCounter,
        c.outboundGrpCounter, c.inboundGrpCounter, c.vouchedByContactId, c.vouchedAt, c.ratchetBootstrapV3,
    )

    private fun oldPrint(v: V3TestVault) = Triple(
        rowPrint(v.inner.contacts.getValue(OLD)),
        v.inner.inboxes.filter { it.contactId == OLD }.map { Triple(it.inboxId, it.direction, it.cap) },
        v.inner.meta.filterKeys { NEW !in it },
    )

    /**
     * The two-scan pair-again on a fresh session per phone: A scans B's secret-only
     * code (A is the pending side), B scans A's full code and announces, A applies it.
     */
    private fun pairAgain(w: World, bLegacyBuild: Boolean = false): Pair<PairingSaveOutcome, PairingSaveOutcome> {
        val sA = PairingSession.start()
        val oA: PairingSaveOutcome
        val oB: PairingSaveOutcome
        if (!bLegacyBuild) {
            val sB = PairingSession.start()
            val scanA = assertNotNull(sA.parsePeerCode(sB.secretOnlyCode()!!, NEW_IN_A, requireFull = false))
            oA = sA.save(w.a.vault, NEW, scanA, NEW_IN_A, r, NEW_CTL_A, r, alias = "new")
            val scanB = assertNotNull(sB.parsePeerCode(sA.fullCode(NEW_IN_A, wc, NEW_CTL_A, wc)!!, NEW_IN_B, requireFull = true))
            oB = sB.save(w.b.vault, NEW, scanB, NEW_IN_B, r, NEW_CTL_B, r, alias = "new")
            sB.end()
        } else {
            // B runs a build from before the one-time key exchange: its code has no `ek`,
            // and it saves with the old transaction (PairingSessionTest.newOld_* shape).
            val oldHalf = generateSecureRandom(32)
            val scanA = assertNotNull(
                sA.parsePeerCode(PairingPayload.buildSecretOnly(encodeBase64(oldHalf)), NEW_IN_A, requireFull = false)
            )
            oA = sA.save(w.a.vault, NEW, scanA, NEW_IN_A, r, NEW_CTL_A, r, alias = "new")
            val full = sA.fullCode(NEW_IN_A, wc, NEW_CTL_A, wc)!!
            val scanB = assertNotNull(StoreBuildPairingParser.parse(full, NEW_IN_B, encodeBase64(oldHalf), true))
            val peerHalf = decodeBase64(scanB.secretB64)
            PairingVault.savePairedContact(
                w.b.vault, NEW, deriveSharedSecret(oldHalf, peerHalf), scanB.inboxId, scanB.writeCap,
                scanB.ctlInboxId, scanB.ctlWriteCap, NEW_IN_B, r, NEW_CTL_B, r, "new",
                mySecretHalf = oldHalf, peerSecretHalf = peerHalf, peerRoleRuleV2 = scanB.roleRuleV2,
            )
            oB = PairingSaveOutcome.SAVED_LEGACY
        }
        sA.end()
        assertTrue(w.b.mm.sendInboxAnnounce(NEW, NEW_IN_B, wc, NEW_CTL_B, wc), "B's announce leaves")
        w.a.mm.pollControlMessages(NEW)
        assertNotNull(w.a.vault.getInboxIdForContact(NEW, "outbound"), "the pending side applied the announce")
        return oA to oB
    }

    // --- a cancelled pair-again ---------------------------------------------------------

    @Test
    fun aPairAgainAbandonedBeforeTheSave_changesNothing_andTheOldContactStillWorks() {
        if (!up()) return
        val w = withOlderPairing()
        talk(w.a, w.b, OLD, "before")
        val printA = oldPrint(w.a.vault); val printB = oldPrint(w.b.vault)
        val allMetaA = w.a.vault.inner.meta.toMap()

        // Both open Add contact, A scans B's code, then they give up (back out / leave).
        val sA = PairingSession.start(); val sB = PairingSession.start()
        assertNotNull(sA.parsePeerCode(sB.secretOnlyCode()!!, NEW_IN_A, requireFull = false))
        sA.end(); sB.end()

        assertEquals(printA, oldPrint(w.a.vault)); assertEquals(printB, oldPrint(w.b.vault))
        assertEquals(allMetaA, w.a.vault.inner.meta, "nothing at all was written")
        assertEquals(1, w.a.vault.getAllContacts().size)
        assertEquals(ContactPairingKind.OLDER, kind(w.a, OLD)); assertEquals(ContactPairingKind.OLDER, kind(w.b, OLD))
        talk(w.a, w.b, OLD, "after")
    }

    @Test
    fun aPairAgainCancelledAfterTheSave_deletesOnlyTheNewContact_andTheOldOneStillWorks() {
        if (!up()) return
        val w = withOlderPairing()
        talk(w.a, w.b, OLD, "before")
        val printA = oldPrint(w.a.vault)

        // A saved the half-done pairing ("Almost there"), then tapped Cancel pairing /
        // Start again: the screens delete exactly the pending contact through the
        // shared delete path.
        val sA = PairingSession.start(); val sB = PairingSession.start()
        val scan = assertNotNull(sA.parsePeerCode(sB.secretOnlyCode()!!, NEW_IN_A, requireFull = false))
        assertEquals(PairingSaveOutcome.SAVED_V3, sA.save(w.a.vault, NEW, scan, NEW_IN_A, r, NEW_CTL_A, r, alias = "new"))
        assertEquals(2, w.a.vault.getAllContacts().size)
        assertTrue(deleteContactAndPurgeRelay(w.a.vault, null, NEW))
        sA.end(); sB.end()

        assertNull(w.a.vault.getContact(NEW))
        assertEquals(printA, oldPrint(w.a.vault), "the old row, its inboxes and its meta are untouched")
        assertTrue(w.a.vault.inner.meta.keys.none { NEW in it }, "no residue of the cancelled pairing")
        assertEquals(ContactPairingKind.OLDER, kind(w.a, OLD))
        talk(w.a, w.b, OLD, "after")
    }

    // --- a completed pair-again ---------------------------------------------------------

    @Test
    fun aCompletedPairAgain_isCurrent_itsFirstTextsRideTheRatchet_andTheOldOneWorksUntilDeleted() {
        if (!up()) return
        val w = withOlderPairing()
        talk(w.a, w.b, OLD, "old")
        val from = w.relay.posted.size

        assertEquals(PairingSaveOutcome.SAVED_V3 to PairingSaveOutcome.SAVED_V3, pairAgain(w))
        assertEquals(ContactPairingKind.CURRENT, kind(w.a, NEW)); assertEquals(ContactPairingKind.CURRENT, kind(w.b, NEW))
        assertEquals(ContactPairingKind.OLDER, kind(w.a, OLD), "the old contact is not changed by the new pairing")
        assertEquals("", w.a.vault.getContact(NEW)!!.mnemonic, "the new contact starts with no memory note")

        // The FIRST text on the new contact, from each side, is a ratchet message.
        assertTrue(w.a.mm.sendMessage(NEW, "first from A"))
        assertEquals(listOf("first from A"), texts(w.b.mm.pollMessages(NEW)))
        assertTrue(w.b.mm.sendMessage(NEW, "first from B"))
        assertEquals(listOf("first from B"), texts(w.a.mm.pollMessages(NEW)))
        val sinceRepair = w.relay.posted.drop(from)
        assertTrue(sinceRepair.isNotEmpty())
        assertTrue(sinceRepair.all { MessageManager.isRatchetWire(it) }, "nothing on the static envelope since the pair-again")
        for (p in listOf(w.a, w.b)) {
            assertNull(p.vault.inner.meta[MessageManager.drLegacyFallbackKey(NEW)], "no legacy fallback was counted")
        }

        // Step 3 of the guide: the old contact still works, then both delete it.
        talk(w.a, w.b, OLD, "still")
        for (p in listOf(w.a, w.b)) {
            assertTrue(deleteContactAndPurgeRelay(p.vault, null, OLD))
            assertTrue(p.vault.inner.meta.keys.none { it.endsWith("/$OLD") || it.contains("/$OLD/") }, "no residue of the old pairing")
        }
        talk(w.a, w.b, NEW, "after delete")
        assertEquals(ContactPairingKind.CURRENT, kind(w.a, NEW))
    }

    @Test
    fun pairingAgainWithAnOlderBuild_givesAnotherOlderPairing_andTheNoteSaysSo() {
        if (!up()) return
        val w = withOlderPairing()
        val (oA, _) = pairAgain(w, bLegacyBuild = true)
        assertEquals(PairingSaveOutcome.SAVED_LEGACY, oA)
        assertTrue(ContactPairing.savedAsOlder(oA), "the add-contact screen shows the 'ask them to update' note")
        assertEquals(ContactPairingKind.OLDER, kind(w.a, NEW)); assertEquals(ContactPairingKind.OLDER, kind(w.b, NEW))
        talk(w.a, w.b, NEW, "legacy again")
    }

    // --- the new pairing keeps the lost-state rule ----------------------------------------

    @Test
    fun afterAPairAgain_aLostStateStillRefusesTheSend_andTheLabelStaysCurrent() {
        if (!up()) return
        val w = withOlderPairing()
        pairAgain(w)
        val stateKey = VaultRatchetStore.stateKey(NEW, MessageManager.RATCHET_TEXT_CHANNEL)

        // Absent state: the send fails, nothing is posted, nothing falls back to static.
        val saved = assertNotNull(w.a.vault.inner.meta.remove(stateKey))
        var posts = w.relay.posted.size
        assertFalse(w.a.mm.sendMessage(NEW, "no state"))
        assertEquals(posts, w.relay.posted.size)
        w.a.vault.inner.meta[stateKey] = saved

        // Proven corrupt: latched lost, still refused, still "Current" (kind is not health).
        w.a.vault.inner.meta[stateKey] = encodeBase64(ByteArray(48) { (it * 7 + 3).toByte() })
        posts = w.relay.posted.size
        assertFalse(w.a.mm.sendMessage(NEW, "after corruption"))
        assertEquals(posts, w.relay.posted.size, "never on the static envelope")
        assertTrue(w.a.mm.secureChannelLost(NEW))
        assertEquals(ContactPairingKind.CURRENT, kind(w.a, NEW))
        // The old pairing is a different contact and is unaffected.
        talk(w.a, w.b, OLD, "old still")
    }

    // --- groups: today's behaviour, which the guide discloses ------------------------------

    @Test
    fun inAnExistingGroup_theRePairedPerson_staysUnresolvedUntilTheAdminRemovesAndReAddsThem() {
        // We are a member (not admin). Bob is in the group, resolved through our OLD
        // pairing with him. We pair again with Bob and delete the old contact.
        val vault = InMemoryVault()
        val gm = GroupManager(vault) { null }
        seed(vault, "admin-contact", generateSecureRandom(32))
        val bobOld = generateSecureRandom(32)
        seed(vault, "bob-old", bobOld)
        val gid = GroupManager.newGroupId()
        val adm = mid(10); val me = mid(20); val bob = mid(30)
        gm.handleControl("admin-contact", gid, GroupManager.KIND_INVITE,
            """{"n":"crew","ep":1,"adm":"$adm","you":"$me","mem":["$adm","$me","$bob"]}""")
        gm.acceptInvite(gid)
        val oldTag = GroupManager.boundTag(bobOld, gid, bob)
        fun roster(ep: Int, vararg entries: String) = gm.handleControl("admin-contact", gid, GroupManager.KIND_ROSTER,
            """{"n":"crew","ep":$ep,"adm":"$adm","mem":[${entries.joinToString(",") { "\"$it\"" }}]}""")
        fun bobRow(id: String = bob) = vault.getGroupMembers(gid).firstOrNull { it.memberId == id }

        roster(2, "$adm:", "$me:", "$bob:$oldTag")
        assertEquals("bob-old", bobRow()?.contactId)

        // Pair again, then delete the old contact: the member row goes unresolved.
        val bobNew = generateSecureRandom(32)
        seed(vault, "bob-new", bobNew)
        vault.deleteContact("bob-old")
        assertNull(bobRow()?.contactId, "the old pairing's member row is unresolved after the delete")

        // The admin's next roster still carries the tag Bob's JOIN computed over the old
        // pairing (nothing re-sends a join for an existing membership): no resolution.
        roster(3, "$adm:", "$me:", "$bob:$oldTag")
        assertNull(bobRow()?.contactId, "the new pairing does not take over the old membership")
        assertTrue(vault.getGroupMembers(gid).none { it.contactId == "bob-new" })

        // What the guide asks for: the admin removes Bob and adds him again. The re-add
        // is a fresh membership whose tag is computed over the NEW pairing.
        roster(4, "$adm:", "$me:")
        assertNull(bobRow())
        val bob2 = mid(40)
        roster(5, "$adm:", "$me:", "$bob2:${GroupManager.boundTag(bobNew, gid, bob2)}")
        assertEquals("bob-new", bobRow(bob2)?.contactId, "after remove + re-add the new contact is in the group")
    }

    private fun mid(seed: Int) = bytesToHex(ByteArray(8) { (seed + it).toByte() })

    private fun seed(vault: InMemoryVault, contactId: String, secret: ByteArray) {
        vault.insertContact(ContactRecord(contactId, secret, 1, "A-$contactId", 0L))
        val base = contactId.hashCode().toUInt().toString(16).padStart(8, '0')
        vault.insertInboxId(InboxIdRecord(("in$base".padEnd(32, 'A')).take(32), contactId, 1L, Long.MAX_VALUE, "inbound", "A".repeat(43)))
        vault.insertInboxId(InboxIdRecord(("ou$base".padEnd(32, 'B')).take(32), contactId, 1L, Long.MAX_VALUE, "outbound", "B".repeat(43)))
    }

    private companion object {
        const val OLD = "c-old"
        const val NEW = "c-new"
        val OLD_IN_A = "G".repeat(32)
        val OLD_IN_B = "H".repeat(32)
        val OLD_CTL_A = "g".repeat(32)
        val OLD_CTL_B = "h".repeat(32)
        val NEW_IN_A = "J".repeat(32)
        val NEW_IN_B = "K".repeat(32)
        val NEW_CTL_A = "j".repeat(32)
        val NEW_CTL_B = "k".repeat(32)
    }
}
