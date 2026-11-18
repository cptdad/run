package com.vg.run

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// Step A of the v3 ratchet bootstrap (docs/ratchet-bootstrap-plan.md §3.4, §3.5,
// §4.3, §7): the pairing transaction and the message rules of a v3 contact,
// through the REAL MessageManager over a leasing relay double. No production path
// can create a v3 contact yet — these tests build one through
// PairingVault.savePairedContactV3, exactly as step B will.
// ---------------------------------------------------------------------------
class RatchetV3MessageRulesTest {

    private fun up() = aeadUp() && x25519Up()
    private val cid = V3Messaging.CID

    private fun texts(l: List<ReceivedMessage>) = l.map { it.text }
    private fun allRatchet(bodies: List<ByteArray>) = bodies.all { MessageManager.isRatchetWire(it) }

    // --- the pairing transaction -------------------------------------------------------

    @Test
    fun pairingTransaction_writesFlagSsPrimeStateAndEveryMarker_failClosed() {
        if (!up()) return
        val p = V3Messaging.pair()
        for (d in listOf(p.a, p.b)) {
            val c = d.contact()
            assertTrue(c.ratchetBootstrapV3, "the v3 flag is in the contact row")
            assertFalse(c.sharedSecret.contentEquals(p.ssHalves), "the row stores ss', never ss_halves (D1)")
            assertNotNull(d.stateBlob(), "the initial ratchet state is written at pairing")
            val m = d.vault.inner.meta
            assertEquals("1", m[MessageManager.drIntentKey(cid)])
            assertEquals("1", m[MessageManager.drOnKey(cid)])
            assertEquals("1", m[MessageManager.drRecvLockKey(cid)], "lock at birth")
            assertEquals("1", m[MessageManager.drPeerRoleRuleV2Key(cid)])
            assertEquals("1", m[MessageManager.drCtlCapKey(cid)])
            assertNotNull(m[MessageManager.drRoleOrderKey(cid)])
            assertTrue(d.ekPrivHandedOver.all { it.toInt() == 0 }, "the one-time private key is wiped")
        }
        assertContentEquals(p.a.contact().sharedSecret, p.b.contact().sharedSecret, "both sides store the same ss'")
        assertTrue(p.a.isBobAtBirth() != p.b.isBobAtBirth(), "exactly one Bob")
    }

    @Test
    fun pairingTransaction_noOneTimePrivateKeyAnywhereInEitherVault() {
        if (!up()) return
        val p = V3Messaging.pair(leakKeys = true)
        for ((d, priv) in listOf(p.a to p.a.leakedEkPriv!!, p.b to p.b.leakedEkPriv!!)) {
            fun contains(hay: ByteArray) =
                (0..hay.size - priv.size).any { o -> priv.indices.all { hay[o + it] == priv[it] } }
            for (v in d.vault.inner.meta.values) {
                val raw = try { decodeBase64(v) } catch (_: Exception) { v.encodeToByteArray() }
                assertFalse(contains(raw), "a one-time private key is in a _meta value")
            }
            assertFalse(contains(d.contact().sharedSecret))
        }
    }

    @Test
    fun pairingTransaction_aWriteFailure_rollsBackStateAndFlag() {
        if (!up()) return
        val v = RollbackVault()
        v.failInsertInboxOnCall = 3          // after the contact row and two inbox rows
        val eA = x25519GenerateKeypair(); val eB = x25519GenerateKeypair()
        val hA = generateSecureRandom(32); val hB = generateSecureRandom(32)
        val r = PairingVault.savePairedContactV3(
            vault = v, contactId = cid, pairingSecretFromHalves = deriveSharedSecret(hA, hB),
            myEphemeralPriv = eA.privateKey, peerEphemeralPub = eB.publicKey,
            mySecretHalf = hA, peerSecretHalf = hB,
            peerInboxId = V3Messaging.IN_B, peerWriteCap = V3Messaging.WRITE_CAP,
            peerCtlInboxId = V3Messaging.CTL_B, peerCtlWriteCap = V3Messaging.WRITE_CAP,
            myInboxId = V3Messaging.IN_A, myReadCap = V3Messaging.READ_CAP,
            myCtlInboxId = V3Messaging.CTL_A, myCtlReadCap = V3Messaging.READ_CAP,
            alias = "p",
        )
        assertIs<PairingVault.V3SaveResult.WriteFailed>(r)
        assertNull(v.getContact(cid), "no contact row (and no v3 flag) survives an aborted pairing")
        assertTrue(v.inner.inboxes.isEmpty())
        assertTrue(v.inner.meta.isEmpty(), "no ratchet state, no marker survives an aborted pairing")
        assertTrue(eA.privateKey.all { it.toInt() == 0 }, "the one-time key is wiped on the failure path too")
    }

    /** A store that keeps the record it was handed, to see what the save leaves in that array. */
    private class KeepingVault(private val failInsert: Boolean = false) : InMemoryVault() {
        var handed: ContactRecord? = null
        override fun insertContact(contact: ContactRecord): Long {
            handed = contact
            if (failInsert) throw IllegalStateException("insert refused")
            return super.insertContact(contact)
        }
    }

    @Test
    fun pairingTransaction_wipesTheRowSecretItHandedToTheStore_onBothPaths() {
        if (!up()) return
        for (fail in listOf(false, true)) {
            val v = KeepingVault(failInsert = fail)
            val eA = x25519GenerateKeypair(); val eB = x25519GenerateKeypair()
            val hA = generateSecureRandom(32); val hB = generateSecureRandom(32)
            val r = PairingVault.savePairedContactV3(
                vault = v, contactId = cid, pairingSecretFromHalves = deriveSharedSecret(hA, hB),
                myEphemeralPriv = eA.privateKey, peerEphemeralPub = eB.publicKey,
                mySecretHalf = hA, peerSecretHalf = hB,
                peerInboxId = V3Messaging.IN_B, peerWriteCap = V3Messaging.WRITE_CAP,
                peerCtlInboxId = V3Messaging.CTL_B, peerCtlWriteCap = V3Messaging.WRITE_CAP,
                myInboxId = V3Messaging.IN_A, myReadCap = V3Messaging.READ_CAP,
                myCtlInboxId = V3Messaging.CTL_A, myCtlReadCap = V3Messaging.READ_CAP,
                alias = "p",
            )
            val handed = assertNotNull(v.handed, "the store was handed a record").sharedSecret
            assertEquals(32, handed.size)
            assertTrue(handed.all { it.toInt() == 0 }, "the array handed to the store is wiped after the save (fail=$fail)")
            if (fail) {
                assertIs<PairingVault.V3SaveResult.WriteFailed>(r)
                assertNull(v.getContact(cid))
            } else {
                assertIs<PairingVault.V3SaveResult.Saved>(r)
                val stored = assertNotNull(v.getContact(cid)).sharedSecret
                assertFalse(stored.all { it.toInt() == 0 }, "the stored row keeps its own bytes")
            }
        }
    }

    @Test
    fun pairingTransaction_refusals_writeNothing_andMapOneToOne() {
        if (!up()) return
        val v = InMemoryVault()
        val hA = generateSecureRandom(32); val hB = generateSecureRandom(32)
        fun save(priv: ByteArray, peerPub: ByteArray, mine: ByteArray = hA, peer: ByteArray = hB) =
            PairingVault.savePairedContactV3(
                vault = v, contactId = cid, pairingSecretFromHalves = deriveSharedSecret(mine, peer),
                myEphemeralPriv = priv, peerEphemeralPub = peerPub, mySecretHalf = mine, peerSecretHalf = peer,
                peerInboxId = null, peerWriteCap = null, peerCtlInboxId = null, peerCtlWriteCap = null,
                myInboxId = V3Messaging.IN_A, myReadCap = V3Messaging.READ_CAP,
                myCtlInboxId = V3Messaging.CTL_A, myCtlReadCap = V3Messaging.READ_CAP, alias = "p",
            )
        val low = save(x25519GenerateKeypair().privateKey, ByteArray(32))
        assertEquals(PairingVault.V3Refusal.LOW_ORDER_PEER_KEY, assertIs<PairingVault.V3SaveResult.Refused>(low).reason)
        val mine = x25519GenerateKeypair()
        val refl = save(mine.privateKey, mine.publicKey.copyOf())
        assertEquals(PairingVault.V3Refusal.REFLECTED_PEER_KEY, assertIs<PairingVault.V3SaveResult.Refused>(refl).reason)
        val spent = save(ByteArray(32), x25519GenerateKeypair().publicKey)
        assertEquals(PairingVault.V3Refusal.SPENT_EPHEMERAL_KEY, assertIs<PairingVault.V3SaveResult.Refused>(spent).reason)
        val malformed = save(ByteArray(31) { 1 }, x25519GenerateKeypair().publicKey)
        assertEquals(PairingVault.V3Refusal.MALFORMED_INPUT, assertIs<PairingVault.V3SaveResult.Refused>(malformed).reason)
        val same = save(x25519GenerateKeypair().privateKey, x25519GenerateKeypair().publicKey, hA, hA.copyOf())
        assertIs<PairingVault.V3SaveResult.IdenticalSecretHalves>(same)
        assertNull(v.getContact(cid)); assertTrue(v.inboxes.isEmpty()); assertTrue(v.meta.isEmpty())
        // 1:1: every internal refusal has exactly one public mirror.
        assertEquals(
            RatchetBootstrapV3.Refusal.entries.map { it.name },
            PairingVault.V3Refusal.entries.map { it.name },
        )
        for (r in RatchetBootstrapV3.Refusal.entries) assertEquals(r.name, PairingVault.v3Refusal(r).name)
    }

    @Test
    fun pairingTransaction_inboxOwnedElsewhere_isRefused_nothingWritten() {
        if (!up()) return
        val v = InMemoryVault()
        v.insertContact(ContactRecord("victim", ByteArray(32) { 9 }, 0, "V", 0L))
        v.insertInboxId(InboxIdRecord(V3Messaging.IN_B, "victim", 1L, Long.MAX_VALUE, "outbound", "w"))
        val hA = generateSecureRandom(32); val hB = generateSecureRandom(32)
        val r = PairingVault.savePairedContactV3(
            vault = v, contactId = cid, pairingSecretFromHalves = deriveSharedSecret(hA, hB),
            myEphemeralPriv = x25519GenerateKeypair().privateKey, peerEphemeralPub = x25519GenerateKeypair().publicKey,
            mySecretHalf = hA, peerSecretHalf = hB,
            peerInboxId = V3Messaging.IN_B, peerWriteCap = V3Messaging.WRITE_CAP,
            peerCtlInboxId = null, peerCtlWriteCap = null,
            myInboxId = V3Messaging.IN_A, myReadCap = V3Messaging.READ_CAP,
            myCtlInboxId = V3Messaging.CTL_A, myCtlReadCap = V3Messaging.READ_CAP, alias = "p",
        )
        assertIs<PairingVault.V3SaveResult.InboxInUse>(r)
        assertNull(v.getContact(cid)); assertTrue(v.meta.isEmpty())
        assertEquals("victim", v.getInboxId(V3Messaging.IN_B)?.contactId)
    }

    // --- text both ways, both role assignments, ratchet-only ---------------------------------

    private fun exchange(p: V3Messaging, firstIsA: Boolean) {
        val (x, y) = if (firstIsA) p.a to p.b else p.b to p.a
        val first = (0 until 3).map { "first $it" }
        for (t in first) assertTrue(x.mm.sendMessage(cid, t))
        assertEquals(first, texts(y.mm.pollMessages(cid)))
        val reply = (0 until 3).map { "reply $it" }
        for (t in reply) assertTrue(y.mm.sendMessage(cid, t))
        assertEquals(reply, texts(x.mm.pollMessages(cid)))
        // And on, past the first DH steps both ways.
        repeat(2) { i ->
            assertTrue(x.mm.sendMessage(cid, "x$i")); assertEquals(listOf("x$i"), texts(y.mm.pollMessages(cid)))
            assertTrue(y.mm.sendMessage(cid, "y$i")); assertEquals(listOf("y$i"), texts(x.mm.pollMessages(cid)))
        }
        assertTrue(allRatchet(p.relay.posted), "a v3 pairing never puts text on the static envelope — from the first message")
        assertFalse(x.mm.forwardSecrecyStalled(cid)); assertFalse(x.mm.ratchetRefused(cid))
        assertFalse(y.mm.forwardSecrecyStalled(cid)); assertFalse(y.mm.ratchetRefused(cid))
    }

    @Test
    fun text_responderWritesFirst_onThePreChain() {
        if (!up()) return
        val p = V3Messaging.pairWithAAs(bob = true)
        exchange(p, firstIsA = true)
    }

    @Test
    fun text_initiatorWritesFirst() {
        if (!up()) return
        val p = V3Messaging.pairWithAAs(bob = false)
        exchange(p, firstIsA = true)
    }

    @Test
    fun text_otherSideFirst_bothRoleAssignments() {
        if (!up()) return
        exchange(V3Messaging.pairWithAAs(bob = true), firstIsA = false)
        exchange(V3Messaging.pairWithAAs(bob = false), firstIsA = false)
    }

    /**
     * "Never legacy" must not depend on any `_meta` read: on iOS a failed read answers
     * null, which for a legacy pairing means "dr-on off ⇒ static envelope". A v3
     * contact's rule is read off the contact row, so text still rides the ratchet, and
     * a sealed control kind still rides it with an unreadable capability marker.
     */
    @Test
    fun v3Send_ignoresUnreadableDrOnAndCapabilityMarkers_neverStatic() {
        if (!up()) return
        val p = V3Messaging.pair()
        p.a.vault.hookedKey = MessageManager.drOnKey(cid); p.a.vault.hook = { null }
        assertTrue(p.a.mm.sendMessage(cid, "dr-on unreadable"))
        assertTrue(MessageManager.isRatchetWire(p.relay.posted.last()), "text rides the ratchet with dr-on unreadable")
        assertEquals(listOf("dr-on unreadable"), texts(p.b.mm.pollMessages(cid)))
        p.a.vault.hookedKey = MessageManager.drCtlCapKey(cid); p.a.vault.hook = { throw RuntimeException("injected") }
        assertTrue(p.a.mm.sendDirectControl(cid, MessageManager.CONTROL_KIND_REFERRAL_OFFER, "{}"))
        assertTrue(MessageManager.isRatchetWire(p.relay.posted.last()), "sealed control rides the ratchet with the marker unreadable")
        p.a.vault.hook = null
        assertEquals(listOf(MessageManager.CONTROL_KIND_REFERRAL_OFFER), p.b.mm.pollControlMessages(cid).mapNotNull { it.controlKind })
        assertTrue(allRatchet(p.relay.posted))
    }

    // --- lock at birth: legacy is hard-dropped ------------------------------------------------

    /** A forger holding the stored secret ss' and B's routing sends static envelopes. */
    private fun forger(p: V3Messaging): MessageManager {
        val v = InMemoryVault()
        v.insertContact(ContactRecord(cid, p.b.contact().sharedSecret.copyOf(), 0, "f", 0L))
        v.insertInboxId(InboxIdRecord(V3Messaging.IN_B, cid, 0L, Long.MAX_VALUE, "inbound", V3Messaging.READ_CAP))
        v.insertInboxId(InboxIdRecord(V3Messaging.IN_A, cid, 0L, Long.MAX_VALUE, "outbound", V3Messaging.WRITE_CAP))
        v.insertInboxId(InboxIdRecord(V3Messaging.CTL_A, cid, 0L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, V3Messaging.WRITE_CAP))
        return MessageManager(v, "http://relay.test", p.relay).syncAcks()
    }

    @Test
    fun legacyTextToAV3Contact_isHardDropped_fromTheFirstDrain() {
        if (!up()) return
        val p = V3Messaging.pair()
        val f = forger(p)
        assertTrue(f.sendMessage(cid, "forged static text"))
        assertFalse(MessageManager.isRatchetWire(p.relay.posted.last()), "precondition: the forger sent a static envelope")
        assertEquals(emptyList(), texts(p.a.mm.pollMessages(cid)), "lock at birth: no legacy text is ever accepted")
        // …even when the `_meta` lock marker reads as absent (an iOS read error answers null).
        p.a.vault.hookedKey = MessageManager.drRecvLockKey(cid); p.a.vault.hook = { null }
        assertTrue(f.sendMessage(cid, "forged again"))
        assertEquals(emptyList(), texts(p.a.mm.pollMessages(cid)), "the lock is read off the contact row, not _meta")
        p.a.vault.hook = null
        // The genuine peer still gets through.
        assertTrue(p.b.mm.sendMessage(cid, "genuine"))
        assertEquals(listOf("genuine"), texts(p.a.mm.pollMessages(cid)))
        assertNull(p.a.vault.inner.meta[MessageManager.drRecvLockGraceKey(cid)], "no grace is ever recorded for v3")
    }

    @Test
    fun legacyAnnounceAndLegacySealedControl_fromAForger_areDropped() {
        if (!up()) return
        val p = V3Messaging.pair()
        val f = forger(p)
        val before = p.a.vault.inner.inboxes.toList()
        assertTrue(f.sendInboxAnnounce(cid, "Z".repeat(32), "W".repeat(43)))
        assertTrue(f.sendDirectControl(cid, MessageManager.CONTROL_KIND_REFERRAL_OFFER, "{}"))
        assertFalse(MessageManager.isRatchetWire(p.relay.posted.last()), "precondition: static control")
        val ctl = p.a.mm.pollControlMessages(cid)
        assertTrue(ctl.none { it.controlKind == MessageManager.CONTROL_KIND_REFERRAL_OFFER }, "a legacy sealed kind is a forgery for v3")
        assertEquals(before, p.a.vault.inner.inboxes, "a legacy announce cannot rewrite a v3 contact's routing")
    }

    // --- the first announce: receive-side id relaxation -----------------------------------

    @Test
    fun secretOnlyScan_thePendingSideDecryptsTheRatchetSealedAnnounce_thenTextFlows() {
        if (!up()) return
        val p = V3Messaging.pair(secretOnlyA = true)
        assertNull(p.a.vault.getInboxIdForContact(cid, "outbound"), "precondition: A is the pending side")
        // B scanned A's full code, so it announces its own inboxes — over the ratchet.
        assertTrue(p.b.mm.sendInboxAnnounce(cid, V3Messaging.IN_B, V3Messaging.WRITE_CAP, V3Messaging.CTL_B, V3Messaging.WRITE_CAP))
        assertTrue(MessageManager.isRatchetWire(p.relay.posted.last()), "the first announce is ratchet-sealed (no static fallback)")
        p.a.mm.pollControlMessages(cid)
        assertEquals(V3Messaging.IN_B, p.a.vault.getInboxIdForContact(cid, "outbound")?.inboxId, "the pending side applied it")
        assertTrue(p.a.mm.sendMessage(cid, "hello from the pending side"))
        assertEquals(listOf("hello from the pending side"), texts(p.b.mm.pollMessages(cid)))
        assertTrue(p.b.mm.sendMessage(cid, "and back"))
        assertEquals(listOf("and back"), texts(p.a.mm.pollMessages(cid)))
        assertTrue(allRatchet(p.relay.posted))
    }

    @Test
    fun aLegacyContactWithoutTextIds_isStillNotRelaxed() {
        // Pin: the relaxation is v3-only — a legacy contact with no outbound row
        // still leaves ratchet wires NOT_PROCESSED (unchanged behaviour).
        if (!up()) return
        val p = V3Messaging.pair(secretOnlyA = true)
        // Turn A into a legacy row (same secret, no flag): it must not decrypt.
        p.a.vault.inner.contacts[cid] = p.a.contact().copy(ratchetBootstrapV3 = false)
        assertTrue(p.b.mm.sendInboxAnnounce(cid, V3Messaging.IN_B, V3Messaging.WRITE_CAP, V3Messaging.CTL_B, V3Messaging.WRITE_CAP))
        p.a.mm.pollControlMessages(cid)
        assertNull(p.a.vault.getInboxIdForContact(cid, "outbound"))
    }

    // --- no fresh init: absent / unreadable state -----------------------------------------------

    @Test
    fun absentState_sendFails_writesNothing_neverLegacy_andRetryWorks() {
        if (!up()) return
        val p = V3Messaging.pair()
        val key = p.a.stateKey
        val saved = p.a.vault.inner.meta.remove(key)!!
        val posts = p.relay.posted.size
        val metaBefore = p.a.vault.inner.meta.toMap()
        assertFalse(p.a.mm.sendMessage(cid, "no state"), "the send fails visibly")
        assertEquals(posts, p.relay.posted.size, "nothing was sent — not even on the static envelope")
        assertEquals(metaBefore, p.a.vault.inner.meta, "nothing was written: no init, no latch, no reset")
        assertFalse(p.a.mm.secureChannelLost(cid), "an absent state is never latched as lost")
        p.a.vault.inner.meta[key] = saved
        assertTrue(p.a.mm.sendMessage(cid, "state back"))
        assertEquals(listOf("state back"), texts(p.b.mm.pollMessages(cid)))
    }

    @Test
    fun unreadableState_onReceive_leavesTheBlobsForTheNextDrain_thenTheyOpen() {
        if (!up()) return
        val p = V3Messaging.pair()
        assertTrue(p.b.mm.sendMessage(cid, "while unreadable"))
        p.a.vault.hookedKey = p.a.stateKey
        p.a.vault.hook = { throw RuntimeException("injected read error") }
        assertEquals(emptyList(), texts(p.a.mm.pollMessages(cid)))
        assertFalse(p.a.mm.secureChannelLost(cid), "a transient read failure never latches")
        assertEquals(0, p.relay.inner.ackedIds(V3Messaging.IN_A).size, "the unread blob is not acked away")
        p.a.vault.hook = null
        p.relay.inner.expireLeases()
        assertEquals(listOf("while unreadable"), texts(p.a.mm.pollMessages(cid)), "retry works: the relay re-delivers")
    }

    // --- relay refuses the POST: fails on the ratchet, never legacy ------------------------------

    /** Records every append like [RecordingLeasingRelay] but answers each one 404 (a peer who deleted us). */
    private class RefusingRelay(val inner: RecordingLeasingRelay) : RelayHttp by inner {
        val posted = mutableListOf<ByteArray>()
        override fun post(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult {
            if (url.contains("/inbox/") && !url.endsWith("/ack")) {
                posted.add(body.copyOf())
                return HttpResult(404, null, false)
            }
            return inner.post(url, body, contentType, headers, timeoutSeconds)
        }
    }

    @Test
    fun relayRefusedPost_failsOnTheRatchet_nothingLegacy_andIsTheRefusedOutcomeNotNoChain() {
        if (!up()) return
        val p = V3Messaging.pair()
        val refusing = RefusingRelay(p.relay)
        val a = MessageManager(p.a.vault, "http://relay.test", refusing).syncAcks()

        assertFalse(a.sendMessage(cid, "refused text"), "a refused POST fails the send visibly")
        assertEquals(SendOutcome.FAILED, a.sendMessageWithOutcome(cid, "refused again"),
            "a relay refusal is a plain failure, not a parked transport failure")
        assertFalse(a.sendDirectControl(cid, MessageManager.CONTROL_KIND_REFERRAL_OFFER, "{}"), "sealed control fails the same way")
        assertTrue(refusing.posted.isNotEmpty(), "the encrypt worked and the ratchet blob WAS posted (the refused case, not no-chain)")
        assertTrue(allRatchet(refusing.posted), "nothing went out on the static envelope after the refusal")
        assertFalse(a.secureChannelLost(cid), "a relay refusal never latches the channel as lost")

        // The two failure kinds log distinct, identifier-free lines.
        val refused = MessageManager.v3RatchetSendFailureLine(false)
        val noChain = MessageManager.v3RatchetSendFailureLine(null)
        assertTrue(refused != noChain, "refused and no-chain must not share a log line")
        assertTrue("relay refused" in refused && "static envelope" in refused)
        assertTrue("no ratchet send" in noChain)
        for (line in listOf(refused, noChain)) {
            for (id in listOf(cid, V3Messaging.IN_A, V3Messaging.IN_B, V3Messaging.CTL_A, V3Messaging.CTL_B, V3Messaging.WRITE_CAP, "peer")) {
                assertFalse(id in line, "a log line must carry no identifier")
            }
        }

        // The relay accepts again: the next send rides the ratchet and lands (the
        // refused sends only cost the peer skipped keys).
        assertTrue(p.a.mm.sendMessage(cid, "after the refusal"))
        assertEquals(listOf("after the refusal"), texts(p.b.mm.pollMessages(cid)))
        assertTrue(allRatchet(p.relay.posted))
    }

    // --- proven corrupt: dr-lost, nothing reset, nothing legacy, the peer told ------------------

    @Test
    fun corruptState_latchesLost_resetsNothing_sendsNothingLegacy_andThePeerIsTold() {
        if (!up()) return
        val p = V3Messaging.pair()
        val junk = encodeBase64(ByteArray(48) { (it * 5 + 1).toByte() })
        p.a.vault.inner.meta[p.a.stateKey] = junk
        val posts = p.relay.posted.size
        assertFalse(p.a.mm.sendMessage(cid, "after corruption"))
        assertEquals(posts, p.relay.posted.size, "nothing sent, and never on the static envelope")
        assertTrue(p.a.mm.secureChannelLost(cid))
        assertEquals(MessageManager.DR_LOST_NOTICE_OWED, p.a.vault.inner.meta[MessageManager.drLostKey(cid)])
        // Nothing reset: the corrupt-reinit path never ran.
        val m = p.a.vault.inner.meta
        assertEquals(junk, m[p.a.stateKey], "the stored state is left exactly as it was")
        for (k in listOf(MessageManager.drOnKey(cid), MessageManager.drRecvLockKey(cid), MessageManager.drIntentKey(cid))) {
            assertEquals("1", m[k], "$k must survive")
        }
        assertFalse(p.a.mm.ratchetRefused(cid), "lost is not the role-collision refusal")
        // Every ratchet-only kind is blocked: text, group text, announce, sealed control.
        assertFalse(p.a.mm.sendGroupText(cid, "G".repeat(32), "h", "group text"))
        assertFalse(p.a.mm.sendInboxAnnounce(cid, V3Messaging.IN_A, V3Messaging.WRITE_CAP))
        assertFalse(p.a.mm.sendDirectControl(cid, MessageManager.CONTROL_KIND_REFERRAL_OFFER, "{}"))
        assertEquals(posts, p.relay.posted.size)

        // The peer is told (static chatty notice, no secret content) and shows the same state.
        assertEquals(1, p.a.mm.redriveChannelLostNotices())
        assertEquals(MessageManager.DR_LOST_NOTICE_SENT, p.a.vault.inner.meta[MessageManager.drLostKey(cid)])
        assertEquals(0, p.a.mm.redriveChannelLostNotices(), "sent once")
        assertFalse(p.b.mm.secureChannelLost(cid))
        p.b.mm.pollControlMessages(cid)
        assertTrue(p.b.mm.secureChannelLost(cid), "the other phone shows 'pair again' too")
        assertEquals(MessageManager.DR_LOST_BY_PEER, p.b.vault.inner.meta[MessageManager.drLostKey(cid)])
        val bPosts = p.relay.posted.size
        assertFalse(p.b.mm.sendMessage(cid, "to a lost peer"), "B no longer sends into a channel the peer cannot read")
        assertEquals(bPosts, p.relay.posted.size)
    }

    @Test
    fun aChannelLostNotice_forALegacyContact_isIgnored() {
        if (!up()) return
        val p = V3Messaging.pair()
        // B's row as a legacy contact: the notice must not latch anything.
        p.b.vault.inner.contacts[cid] = p.b.contact().copy(ratchetBootstrapV3 = false)
        p.a.vault.inner.meta[p.a.stateKey] = encodeBase64(ByteArray(48) { 3 })
        assertFalse(p.a.mm.sendMessage(cid, "x"))
        assertEquals(1, p.a.mm.redriveChannelLostNotices())
        p.b.mm.pollControlMessages(cid)
        assertFalse(p.b.mm.secureChannelLost(cid))
    }

    // --- delete + re-pair -----------------------------------------------------------------------

    @Test
    fun deleteAndRepair_leavesNoRatchetResidue_andTheNewPairingWorks() {
        if (!up()) return
        val p = V3Messaging.pair()
        exchange(p, firstIsA = true)
        p.a.vault.inner.meta[MessageManager.drLostKey(cid)] = MessageManager.DR_LOST_NOTICE_SENT
        for (d in listOf(p.a, p.b)) {
            d.vault.deleteContact(cid)
            assertTrue(
                d.vault.inner.meta.keys.none { it.endsWith("/$cid") || it.contains("/$cid/") },
                "no per-contact residue: ${d.vault.inner.meta.keys}",
            )
            assertNull(d.vault.getContact(cid))
        }
        // Re-pair into the SAME vaults, same contact id: the new pairing starts clean
        // (nothing inherited — not the lost latch, not the old state) and works.
        val q = V3Messaging.pair(vA = p.a.vault, vB = p.b.vault, relay = p.relay)
        assertFalse(q.a.mm.secureChannelLost(cid))
        exchange(q, firstIsA = false)
    }

    // --- device move (§4.3, D4) -----------------------------------------------------------------

    private fun move(from: VaultDatabase, to: VaultDatabase, schema: Int) {
        val bundleId = MoveHandleCodec.newBundleId()
        val bundle = MigrationBundle(
            schema = schema, from = MigrationBundle.FROM_ANDROID, createdMs = 1L,
            bundleId = bundleId, snapshot = VaultSnapshotIo.export(from),
        )
        val decoded = MigrationBundleCodec.decodeFromString(MigrationBundleCodec.encodeToString(bundle))
        VaultSnapshotIo.import(to, decoded.snapshot, MoveConstants.COUNTER_JUMP, decoded.bundleId)
    }

    @Test
    fun move_aV3Contact_flagStateAndMarkersSurvive_andTheMovedPhoneTalks() {
        if (!up()) return
        val p = V3Messaging.pair()
        exchange(p, firstIsA = true)
        val snapshot = VaultSnapshotIo.export(p.a.vault)
        assertEquals(MigrationBundleCodec.CURRENT_SCHEMA, MigrationBundleCodec.exportSchemaFor(snapshot), "D4: a v3 contact forces the new schema")
        val fresh = V3TestVault()
        move(p.a.vault, fresh, MigrationBundleCodec.exportSchemaFor(snapshot))
        val c = fresh.inner.contacts.getValue(cid)
        assertTrue(c.ratchetBootstrapV3, "the flag travels")
        for (k in listOf(p.a.stateKey, MessageManager.drRecvLockKey(cid), MessageManager.drOnKey(cid),
                MessageManager.drIntentKey(cid), MessageManager.drRoleOrderKey(cid), MessageManager.drPeerRoleRuleV2Key(cid),
                MessageManager.drCtlCapKey(cid))) {
            assertEquals(p.a.vault.inner.meta[k], fresh.inner.meta[k], "$k travels")
        }
        val moved = MessageManager(fresh, "http://relay.test", p.relay).syncAcks()
        assertTrue(moved.sendMessage(cid, "from the new phone"))
        assertEquals(listOf("from the new phone"), texts(p.b.mm.pollMessages(cid)))
        assertTrue(p.b.mm.sendMessage(cid, "to the new phone"))
        assertEquals(listOf("to the new phone"), texts(moved.pollMessages(cid)))
    }

    /** A `_meta` read of the ratchet state answering null (an iOS read error) must never drop it from a move. */
    @Test
    fun move_aV3ContactWhoseStateReadsAsNull_isNotExported() {
        if (!up()) return
        val p = V3Messaging.pair()
        p.a.vault.hookedKey = p.a.stateKey; p.a.vault.hook = { null }
        var refused = false
        try { VaultSnapshotIo.export(p.a.vault) } catch (_: VaultSnapshotIo.IncompleteSnapshotException) { refused = true }
        assertTrue(refused, "the export refuses instead of shipping the contact without its state")
        p.a.vault.hook = null
        assertFalse(VaultSnapshotIo.v3ContactsMissingRatchetState(VaultSnapshotIo.export(p.a.vault)), "healthy again once the read works")
    }

    /**
     * A bundle that carries a v3 contact WITHOUT its ratchet state — what an export
     * through a failed read on a build without the export check produces — is refused
     * as malformed by the decoder, and by import itself, before anything is written.
     */
    @Test
    fun import_aBundleWithAV3ContactButNoRatchetState_isRejected_vaultUnchanged() {
        if (!up()) return
        val p = V3Messaging.pair()
        val healthy = MigrationBundleCodec.encodeToString(
            MigrationBundle(schema = MigrationBundleCodec.CURRENT_SCHEMA, from = MigrationBundle.FROM_IOS, createdMs = 1L,
                bundleId = MoveHandleCodec.newBundleId(), snapshot = VaultSnapshotIo.export(p.a.vault)),
        )
        val stateEntry = Regex(""""${Regex.escape(p.a.stateKey)}":"[^"]*"""")
        assertTrue(stateEntry.containsMatchIn(healthy), "precondition: the healthy bundle carries the state")
        val stripped = healthy.replace(Regex(""",?"${Regex.escape(p.a.stateKey)}":"[^"]*""""), "").replace("{,", "{")
        var malformed = false
        try { MigrationBundleCodec.decodeFromString(stripped) } catch (_: MigrationBundleCodec.FormatException) { malformed = true }
        assertTrue(malformed, "the decoder refuses a v3 contact without its state")

        // Import itself refuses too (any caller), and writes nothing.
        val snap = VaultSnapshotIo.export(p.a.vault).let { it.copy(meta = it.meta - p.a.stateKey) }
        val fresh = V3TestVault()
        var refused = false
        try {
            VaultSnapshotIo.import(fresh, snap, MoveConstants.COUNTER_JUMP, MoveHandleCodec.newBundleId())
        } catch (_: VaultSnapshotIo.IncompleteSnapshotException) { refused = true }
        assertTrue(refused)
        assertTrue(fresh.inner.contacts.isEmpty() && fresh.inner.inboxes.isEmpty() && fresh.inner.meta.isEmpty(), "vault unchanged")
        // …and the encoder never produces one.
        var encodeRefused = false
        try {
            MigrationBundleCodec.encodeToString(
                MigrationBundle(schema = MigrationBundleCodec.CURRENT_SCHEMA, from = MigrationBundle.FROM_IOS, createdMs = 1L,
                    bundleId = MoveHandleCodec.newBundleId(), snapshot = snap),
            )
        } catch (_: MigrationBundleCodec.FormatException) { encodeRefused = true }
        assertTrue(encodeRefused)
    }

    @Test
    fun move_theLostLatchTravels() {
        if (!up()) return
        val p = V3Messaging.pair()
        p.a.vault.inner.meta[MessageManager.drLostKey(cid)] = MessageManager.DR_LOST_BY_PEER
        val fresh = V3TestVault()
        move(p.a.vault, fresh, MigrationBundleCodec.CURRENT_SCHEMA)
        assertEquals(MessageManager.DR_LOST_BY_PEER, fresh.inner.meta[MessageManager.drLostKey(cid)])
    }

    @Test
    fun bundleSchema_D4_legacyVaultExportsTheOldSchemaByteIdentical() {
        val v = V3TestVault()
        v.insertContact(ContactRecord(cid, ByteArray(32) { 1 }, 0, "legacy", 0L))
        v.insertInboxId(InboxIdRecord(V3Messaging.IN_A, cid, 0L, 1L, "inbound", "r"))
        val snap = VaultSnapshotIo.export(v)
        assertEquals(MigrationBundleCodec.LEGACY_EXPORT_SCHEMA, MigrationBundleCodec.exportSchemaFor(snap))
        val text = MigrationBundleCodec.encodeToString(
            MigrationBundle(schema = MigrationBundleCodec.exportSchemaFor(snap), from = MigrationBundle.FROM_IOS, createdMs = 1L,
                bundleId = MoveHandleCodec.newBundleId(), snapshot = snap),
        )
        assertTrue("\"schema\":10" in text)
        assertFalse("ratchetV3" in text, "no new field for a vault without a v3 contact")
        // …and the new importer reads it back as legacy.
        assertFalse(MigrationBundleCodec.decodeFromString(text).snapshot.contacts.single().ratchetBootstrapV3)
    }

    @Test
    fun bundleSchema_aV3ContactAtTheOldSchema_isRefusedByTheEncoder_andAMalformedFlagByTheDecoder() {
        val v3 = ContactRecord(cid, ByteArray(32) { 1 }, 0, "v3", 0L, ratchetBootstrapV3 = true)
        // A v3 contact always travels with its ratchet state (see the incomplete-bundle test below).
        val state = mapOf(VaultRatchetStore.stateKey(cid, MessageManager.RATCHET_TEXT_CHANNEL) to encodeBase64(ByteArray(40) { 2 }))
        val snap = VaultSnapshot(listOf(v3), emptyList(), emptyList(), emptyList(), state)
        var refused = false
        try {
            MigrationBundleCodec.encodeToString(
                MigrationBundle(schema = MigrationBundleCodec.LEGACY_EXPORT_SCHEMA, from = MigrationBundle.FROM_IOS,
                    createdMs = 1L, bundleId = MoveHandleCodec.newBundleId(), snapshot = snap),
            )
        } catch (_: MigrationBundleCodec.FormatException) { refused = true }
        assertTrue(refused, "a v3 contact must never ride a bundle an older importer accepts")
        val good = MigrationBundleCodec.encodeToString(
            MigrationBundle(schema = MigrationBundleCodec.CURRENT_SCHEMA, from = MigrationBundle.FROM_IOS,
                createdMs = 1L, bundleId = MoveHandleCodec.newBundleId(), snapshot = snap),
        )
        assertTrue(MigrationBundleCodec.decodeFromString(good).snapshot.contacts.single().ratchetBootstrapV3)
        var malformed = false
        try {
            MigrationBundleCodec.decodeFromString(good.replace("\"ratchetV3\":1", "\"ratchetV3\":2"))
        } catch (_: MigrationBundleCodec.FormatException) { malformed = true }
        assertTrue(malformed, "a flag other than 0/1 is a malformed bundle, never 'legacy'")
    }

    // --- the plan's acceptance test G-B at the MessageManager layer ------------------------------

    /** Everything at rest on both phones + both QR codes + every wire the relay recorded. */
    private fun vaultSnapshot(p: V3Messaging, extra: List<ByteArray> = emptyList()): V3BootstrapOracle.Snapshot {
        val blobs = mutableListOf<ByteArray>()
        val secrets = mutableListOf<ByteArray>()
        for (d in listOf(p.a, p.b)) {
            d.stateBlob()?.let { blobs += it }
            // Every 32-byte value at rest, in any encoding (base64 / base64url / hex), in any
            // contact-row field or `_meta` value — not only the shared secret.
            secrets += V3BootstrapOracle.secretsAtRest(d.vault.inner, exclude = setOf(d.stateKey))
        }
        return V3BootstrapOracle.Snapshot(blobs, secrets + extra, listOf(p.a.half, p.b.half), listOf(p.a.ekPub, p.b.ekPub), p.relay.posted.toList())
    }

    private fun conversation(p: V3Messaging, firstIsA: Boolean): List<String> {
        val (x, y) = if (firstIsA) p.a to p.b else p.b to p.a
        val sent = mutableListOf<String>()
        for (i in 0 until 3) { val t = "first $i"; sent += t; assertTrue(x.mm.sendMessage(cid, t)) }
        assertEquals(sent.toList(), texts(y.mm.pollMessages(cid)))
        val reply = (0 until 3).map { "reply $it" }
        for (t in reply) { sent += t; assertTrue(y.mm.sendMessage(cid, t)) }
        assertEquals(reply, texts(x.mm.pollMessages(cid)))
        return sent
    }

    private fun staticOpens(p: V3Messaging, sent: List<String>): List<String> {
        val keys = listOf(p.a.contact().sharedSecret, p.ssHalves, p.a.half, p.b.half)
        return p.relay.posted.flatMap { body -> keys.mapNotNull { LegacyBootstrapAttacker.openStatic(it, body) } }.filter { it in sent }
    }

    @Test
    fun acceptanceGB_responderWritesFirst_afterCommit_nothingOpens() {
        if (!up()) return
        val p = V3Messaging.pairWithAAs(bob = true)
        val sent = conversation(p, firstIsA = true)
        assertEquals(emptyList(), V3BootstrapOracle.open(vaultSnapshot(p)))
        assertEquals(emptyList(), staticOpens(p, sent))
    }

    @Test
    fun acceptanceGB_initiatorWritesFirst_afterCommit_nothingOpens() {
        if (!up()) return
        val p = V3Messaging.pairWithAAs(bob = false)
        val sent = conversation(p, firstIsA = true)
        assertEquals(emptyList(), V3BootstrapOracle.open(vaultSnapshot(p)))
        assertEquals(emptyList(), staticOpens(p, sent))
    }

    /** Non-vacuity at this layer: with a one-time private key left unwiped the same oracle opens all of it. */
    @Test
    fun acceptanceGB_control_aLeakedOneTimeKeyOpensTheBootstrapEpoch() {
        if (!up()) return
        val p = V3Messaging.pairWithAAs(bob = true, leakKeys = true)
        val sent = conversation(p, firstIsA = true)
        assertEquals(sent, V3BootstrapOracle.open(vaultSnapshot(p, extra = listOf(p.a.leakedEkPriv!!))))
    }
}
