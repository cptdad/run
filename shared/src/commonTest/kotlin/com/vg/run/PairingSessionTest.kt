package com.vg.run

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// The shared pairing session (docs/ratchet-bootstrap-plan.md §4.1, §6) end to end
// over the leasing relay double, exactly as both platforms run the two-scan flow:
//
//   SCAN-FIRST side ("pending"): scans the peer's SECRET-ONLY code, saves with no
//   peer inbox rows, then shows its FULL code;
//   SHOW-FIRST side: shows its secret-only code, then scans the peer's FULL code,
//   saves with the peer's rows and ANNOUNCES its own inboxes (ratchet-sealed for v3);
//   the pending side's control poll applies the announce.
// ---------------------------------------------------------------------------
class PairingSessionTest {

    private fun up() = aeadUp() && x25519Up()
    private val cid = V3Messaging.CID
    private val R = V3Messaging.READ_CAP
    private val W = V3Messaging.WRITE_CAP
    private fun texts(l: List<ReceivedMessage>) = l.map { it.text }

    /** One device: a vault, a session, its manager on the shared relay, its inboxes. */
    private class Dev(val vault: V3TestVault, val session: PairingSession?, val mm: MessageManager, val inId: String, val ctlId: String)

    private fun dev(relay: RelayHttp, inId: String, ctlId: String, legacy: Boolean = false): Dev {
        val v = V3TestVault()
        return Dev(v, if (legacy) null else PairingSession.start(), MessageManager(v, "http://relay.test", relay).syncAcks(), inId, ctlId)
    }

    private fun Dev.full(): String = session!!.fullCode(inId, W, ctlId, W)!!

    private fun Dev.saveFrom(code: String, requireFull: Boolean): PairingSaveOutcome {
        val scan = assertNotNull(session!!.parsePeerCode(code, inId, requireFull), "the peer's code must parse")
        return session.save(vault, cid, scan, inId, R, ctlId, R, alias = "peer")
    }

    private fun Dev.announce() =
        assertTrue(mm.sendInboxAnnounce(cid, inId, W, ctlId, W), "the announce must leave")

    /**
     * The two-scan flow between two sessions: [scanner] scans [shower]'s secret-only
     * code first (pending), then [shower] scans [scanner]'s full code and announces.
     */
    private class TwoScan(val scannerOutcome: PairingSaveOutcome, val showerOutcome: PairingSaveOutcome,
                          val scannerIsBob: Boolean?, val showerIsBob: Boolean?)

    private fun twoScan(scanner: Dev, shower: Dev): TwoScan {
        val o1 = scanner.saveFrom(shower.session!!.secretOnlyCode()!!, requireFull = false)
        val o2 = shower.saveFrom(scanner.full(), requireFull = true)
        // Roles read off the states AT BIRTH, before any receive moves them.
        val rs = if (o1 == PairingSaveOutcome.SAVED_V3) isBob(scanner) else null
        val rh = if (o2 == PairingSaveOutcome.SAVED_V3) isBob(shower) else null
        shower.announce()
        scanner.mm.pollControlMessages(cid)
        return TwoScan(o1, o2, rs, rh)
    }

    private fun isBob(d: Dev): Boolean =
        V3BootstrapOracle.parseState(decodeBase64(d.vault.inner.meta.getValue(VaultRatchetStore.stateKey(cid, MessageManager.RATCHET_TEXT_CHANNEL)))).remote == null

    private fun talk(x: Dev, y: Dev) {
        assertTrue(x.mm.sendMessage(cid, "x→y")); assertEquals(listOf("x→y"), texts(y.mm.pollMessages(cid)))
        assertTrue(y.mm.sendMessage(cid, "y→x")); assertEquals(listOf("y→x"), texts(x.mm.pollMessages(cid)))
        assertTrue(x.mm.sendMessage(cid, "again")); assertEquals(listOf("again"), texts(y.mm.pollMessages(cid)))
    }

    // --- new ↔ new: v3 on both sides -----------------------------------------------------

    private fun newNew(scannerIsA: Boolean, wantScannerBob: Boolean?) {
        repeat(64) {
            val relay = RecordingLeasingRelay()
            val a = dev(relay, V3Messaging.IN_A, V3Messaging.CTL_A)
            val b = dev(relay, V3Messaging.IN_B, V3Messaging.CTL_B)
            val (scanner, shower) = if (scannerIsA) a to b else b to a
            val t = twoScan(scanner, shower)
            assertEquals(PairingSaveOutcome.SAVED_V3, t.scannerOutcome); assertEquals(PairingSaveOutcome.SAVED_V3, t.showerOutcome)
            assertTrue(t.scannerIsBob != t.showerIsBob, "exactly one Bob")
            if (wantScannerBob != null && t.scannerIsBob != wantScannerBob) return@repeat
            for (d in listOf(a, b)) assertTrue(d.vault.getContact(cid)!!.ratchetBootstrapV3)
            assertContentEquals(a.vault.getContact(cid)!!.sharedSecret, b.vault.getContact(cid)!!.sharedSecret, "identical ss'")
            assertEquals(V3Messaging.IN_B.takeIf { scanner === a } ?: V3Messaging.IN_A,
                scanner.vault.getInboxIdForContact(cid, "outbound")?.inboxId, "the pending side applied the announce")
            talk(scanner, shower)
            assertTrue(relay.posted.all { MessageManager.isRatchetWire(it) }, "nothing static, from the first message")
            for (d in listOf(a, b)) {
                assertFalse(d.mm.pairingKeyConfirmationFailed(cid))
                assertEquals(MessageManager.KEY_CONFIRMED, d.vault.inner.meta[MessageManager.drKeyConfirmKey(cid)])
            }
            noEphemeralPrivateKey(a, listOf(a, b)); noEphemeralPrivateKey(b, listOf(a, b))
            return
        }
        error("no pairing with the wanted role in 64 tries")
    }

    @Test fun newNew_scanFirstA_scannerIsBob() { if (up()) newNew(scannerIsA = true, wantScannerBob = true) }
    @Test fun newNew_scanFirstA_scannerIsAlice() { if (up()) newNew(scannerIsA = true, wantScannerBob = false) }
    @Test fun newNew_scanFirstB_scannerIsBob() { if (up()) newNew(scannerIsA = false, wantScannerBob = true) }
    @Test fun newNew_scanFirstB_scannerIsAlice() { if (up()) newNew(scannerIsA = false, wantScannerBob = false) }

    /**
     * No stored value is the private key of either published one-time key: every
     * 32-byte window of every `_meta` value and of the contact secret is tried as a
     * scalar against the base point.
     */
    private fun noEphemeralPrivateKey(d: Dev, both: List<Dev>) {
        val pubs = both.map { PairingPayload.decodeEphemeralKey(it.session!!.myEphemeralPubB64Url()!!)!! }
        val base = ByteArray(32).also { it[0] = 9 }
        val values = d.vault.inner.meta.values.mapNotNull { v -> try { decodeBase64(v) } catch (_: Exception) { null } } +
            listOf(d.vault.getContact(cid)!!.sharedSecret)
        for (raw in values) for (o in 0..raw.size - 32) {
            val cand = raw.copyOfRange(o, o + 32)
            val pub = try { x25519Ecdh(cand, base) } catch (_: Exception) { continue }
            assertTrue(pubs.none { it.contentEquals(pub) }, "a one-time private key is stored in the vault")
        }
    }

    // --- new ↔ old: legacy on both sides --------------------------------------------------

    @Test
    fun newOld_pairsLegacyOnBothSides_inBothScanOrders() {
        if (!up()) return
        for (newScansFirst in listOf(true, false)) {
            val relay = RecordingLeasingRelay()
            val n = dev(relay, V3Messaging.IN_A, V3Messaging.CTL_A)
            val o = dev(relay, V3Messaging.IN_B, V3Messaging.CTL_B, legacy = true)
            val oldHalf = generateSecureRandom(32)
            val oldSecretOnly = PairingPayload.buildSecretOnly(encodeBase64(oldHalf))
            val oldFull = PairingPayload.buildFull(o.inId, W, o.ctlId, W, encodeBase64(oldHalf))
            // The OLD side: the store build's parser and today's save.
            fun oldSaves(code: String, full: Boolean) {
                val scan = assertNotNull(StoreBuildPairingParser.parse(code, o.inId, encodeBase64(oldHalf), full))
                val peerHalf = decodeBase64(scan.secretB64)
                PairingVault.savePairedContact(
                    o.vault, cid, deriveSharedSecret(oldHalf, peerHalf), scan.inboxId, scan.writeCap,
                    scan.ctlInboxId, scan.ctlWriteCap, o.inId, R, o.ctlId, R, "peer",
                    mySecretHalf = oldHalf, peerSecretHalf = peerHalf, peerRoleRuleV2 = scan.roleRuleV2,
                )
            }
            if (newScansFirst) {
                assertEquals(PairingSaveOutcome.SAVED_LEGACY, n.saveFrom(oldSecretOnly, requireFull = false))
                oldSaves(n.full(), full = true)
                assertTrue(o.mm.sendInboxAnnounce(cid, o.inId, W, o.ctlId, W))
                n.mm.pollControlMessages(cid)
            } else {
                oldSaves(n.session!!.secretOnlyCode()!!, full = false)
                assertEquals(PairingSaveOutcome.SAVED_LEGACY, n.saveFrom(oldFull, requireFull = true))
                n.announce()
                o.mm.pollControlMessages(cid)
            }
            for (d in listOf(n, o)) assertFalse(d.vault.getContact(cid)!!.ratchetBootstrapV3, "legacy on both sides")
            assertContentEquals(n.vault.getContact(cid)!!.sharedSecret, o.vault.getContact(cid)!!.sharedSecret)
            assertFalse(n.session!!.let { it.myEphemeralPubB64Url() == null }, "the public key stays for display")
            talk(n, o)
        }
    }

    // --- the holder and the session lifetime -----------------------------------------------

    @Test
    fun keyHolder_unusableAfterWipe_andAfterSave() {
        if (!up()) return
        val h = PairingKeyHolder.generate()
        assertTrue(h.canSave); assertNotNull(h.publicKeyB64Url())
        val k = assertNotNull(h.takePrivateKeyForSave())
        assertFalse(h.canSave, "the private key is handed out exactly once")
        assertNull(h.takePrivateKeyForSave())
        assertNotNull(h.publicKeyB64Url(), "the public key stays for the full code shown after the save")
        k.secureWipe()
        val w = PairingKeyHolder.generate()
        w.wipe()
        assertFalse(w.canSave); assertNull(w.publicKeyB64Url()); assertNull(w.takePrivateKeyForSave())
    }

    @Test
    fun session_afterEnd_isUnusable() {
        if (!up()) return
        val s = PairingSession.start()
        val half = s.mySecretHalf()
        val code = PairingSession.start().secretOnlyCode()!!
        s.end()
        assertFalse(s.isActive)
        assertTrue(half.all { it.toInt() == 0 }, "end() zeroes the half in place (every alias)")
        assertNull(s.secretOnlyCode()); assertNull(s.fullCode("i".repeat(32), W, "c".repeat(32), W))
        assertNull(s.myEphemeralPubB64Url()); assertNull(s.parsePeerCode(code, null, false))
        var threw = false
        try { s.mySecretHalf() } catch (_: IllegalStateException) { threw = true }
        assertTrue(threw, "a wiped half is never handed out")
        val scan = PairingSession.start().parsePeerCode(code, null, false)!!
        assertEquals(PairingSaveOutcome.START_AGAIN, s.save(InMemoryVault(), cid, scan, V3Messaging.IN_A, R, V3Messaging.CTL_A, R, "p"))
    }

    @Test
    fun aSecondV3SaveInOneSession_neverPairsWithASpentKey() {
        if (!up()) return
        val s = PairingSession.start()
        val peer = PairingSession.start()
        val scan = s.parsePeerCode(peer.secretOnlyCode()!!, null, false)!!
        val v1 = InMemoryVault()
        assertEquals(PairingSaveOutcome.SAVED_V3, s.save(v1, cid, scan, V3Messaging.IN_A, R, V3Messaging.CTL_A, R, "p"))
        val v2 = InMemoryVault()
        assertEquals(PairingSaveOutcome.START_AGAIN, s.save(v2, cid, scan, V3Messaging.IN_A, R, V3Messaging.CTL_A, R, "p"))
        assertNull(v2.getContact(cid)); assertTrue(v2.meta.isEmpty(), "nothing written with a spent key")
    }

    @Test
    fun ourOwnCodeEchoedBack_isAnInvalidCode() {
        if (!up()) return
        val s = PairingSession.start()
        assertNull(s.parsePeerCode(s.secretOnlyCode()!!, null, false), "our own secret half and key echoed")
    }

    @Test
    fun saveOutcomes_mapOneToOne() {
        assertEquals(PairingSaveOutcome.SAVED_V3, PairingSession.outcomeOf(PairingVault.V3SaveResult.Saved))
        assertEquals(PairingSaveOutcome.INBOX_IN_USE, PairingSession.outcomeOf(PairingVault.V3SaveResult.InboxInUse))
        assertEquals(PairingSaveOutcome.START_AGAIN, PairingSession.outcomeOf(PairingVault.V3SaveResult.WriteFailed))
        assertEquals(PairingSaveOutcome.INVALID_CODE, PairingSession.outcomeOf(PairingVault.V3SaveResult.IdenticalSecretHalves))
        for (r in PairingVault.V3Refusal.entries) {
            val o = PairingSession.outcomeOf(PairingVault.V3SaveResult.Refused(r))
            assertTrue(o == PairingSaveOutcome.INVALID_CODE || o == PairingSaveOutcome.START_AGAIN)
        }
    }

    // --- key confirmation ------------------------------------------------------------------

    /**
     * The two phones derived DIFFERENT keys (here: the show-first side saved against a
     * substituted one-time key). The pending side cannot decrypt the ratchet-sealed
     * announce; after the grace it shows "pairing failed — start again" — not before,
     * and never silently.
     */
    @Test
    fun keyConfirmation_mismatchedKeys_failAfterTheBound_notBefore() {
        if (!up()) return
        val relay = RecordingLeasingRelay()
        val a = dev(relay, V3Messaging.IN_A, V3Messaging.CTL_A)   // scans first: pending
        val b = dev(relay, V3Messaging.IN_B, V3Messaging.CTL_B)
        assertEquals(PairingSaveOutcome.SAVED_V3, a.saveFrom(b.session!!.secretOnlyCode()!!, requireFull = false))
        val aFull = a.full()
        val swapped = aFull.replace(a.session!!.myEphemeralPubB64Url()!!, encodeBase64Url(x25519GenerateKeypair().publicKey))
        assertEquals(PairingSaveOutcome.SAVED_V3, b.saveFrom(swapped, requireFull = true))
        b.announce()
        a.mm.pollControlMessages(cid)
        assertNull(a.vault.getInboxIdForContact(cid, "outbound"), "the announce could not be read")
        val stamp = a.vault.inner.meta[MessageManager.drKeyConfirmKey(cid)]!!.toLong()
        assertFalse(MessageManager.pairingKeyConfirmationFailed(a.vault, cid, nowMs = stamp + MessageManager.KEY_CONFIRM_GRACE_MS - 1))
        assertTrue(MessageManager.pairingKeyConfirmationFailed(a.vault, cid, nowMs = stamp + MessageManager.KEY_CONFIRM_GRACE_MS))
        // A later failure does not move the stamp (the bound is from the FIRST refusal).
        b.announce(); relay.inner.expireLeases(); a.mm.pollControlMessages(cid)
        assertEquals(stamp, a.vault.inner.meta[MessageManager.drKeyConfirmKey(cid)]!!.toLong())
        // "Start again" = deleting the pending contact: nothing of it remains.
        a.vault.deleteContact(cid)
        assertNull(a.vault.inner.meta[MessageManager.drKeyConfirmKey(cid)])
    }

    @Test
    fun keyConfirmation_junkBeforeTheGenuineAnnounce_isCancelledByIt() {
        if (!up()) return
        val relay = RecordingLeasingRelay()
        val a = dev(relay, V3Messaging.IN_A, V3Messaging.CTL_A)
        val b = dev(relay, V3Messaging.IN_B, V3Messaging.CTL_B)
        assertEquals(PairingSaveOutcome.SAVED_V3, a.saveFrom(b.session!!.secretOnlyCode()!!, requireFull = false))
        // A relay puts a ratchet-shaped junk wire in front of everything.
        relay.inner.deliver(V3Messaging.CTL_A, MessageManager.RATCHET_WIRE_MAGIC + ByteArray(120) { (it * 7).toByte() })
        a.mm.pollControlMessages(cid)
        assertNotNull(a.vault.inner.meta[MessageManager.drKeyConfirmKey(cid)]?.toLongOrNull(), "junk is stamped")
        assertEquals(PairingSaveOutcome.SAVED_V3, b.saveFrom(a.full(), requireFull = true))
        b.announce()
        a.mm.pollControlMessages(cid)
        assertEquals(MessageManager.KEY_CONFIRMED, a.vault.inner.meta[MessageManager.drKeyConfirmKey(cid)])
        assertFalse(MessageManager.pairingKeyConfirmationFailed(a.vault, cid, nowMs = Long.MAX_VALUE), "confirmed is sticky")
        relay.inner.deliver(V3Messaging.CTL_A, MessageManager.RATCHET_WIRE_MAGIC + ByteArray(120) { 5 })
        a.mm.pollControlMessages(cid)
        assertFalse(MessageManager.pairingKeyConfirmationFailed(a.vault, cid, nowMs = Long.MAX_VALUE))
    }

    // --- `ek` stripped from ONE code (docs/ratchet-bootstrap-plan.md §5.4) -----------------

    /** [code] with its `"ek"` field removed — a tampered code, as an attacker would show it. */
    private fun stripEk(code: String, d: Dev): String {
        val ek = d.session!!.myEphemeralPubB64Url()!!
        val stripped = code.replace(",\"${PairingPayload.EPHEMERAL_KEY_FIELD}\":\"$ek\"", "")
        assertTrue(stripped != code && !stripped.contains(ek), "the one-time key must be gone from the code")
        return stripped
    }

    /** A static-shaped (non-ratchet) wire nobody's keys open. */
    private fun staticJunk(seed: Int): ByteArray =
        ByteArray(120) { (it * 13 + seed).toByte() }.also { assertFalse(MessageManager.isRatchetWire(it)) }

    /**
     * Plan §5.4: `ek` stripped from the PENDING side's FULL code. The pending side saved
     * v3 (the peer's secret-only code carried `ek`), the show-first side saved legacy
     * and announces on the static envelope, which the v3 side's keys cannot open. The
     * v3 side must end in "pairing failed" after the grace — not wait forever — while
     * still never accepting anything static, and deleting nothing.
     */
    @Test
    fun keyConfirmation_ekStrippedFromThePendingSidesFullCode_v3PendingSideFailsAfterTheGrace() {
        if (!up()) return
        val relay = RecordingLeasingRelay()
        val a = dev(relay, V3Messaging.IN_A, V3Messaging.CTL_A)   // scans first: pending, saves v3
        val b = dev(relay, V3Messaging.IN_B, V3Messaging.CTL_B)   // scans the tampered code: saves legacy
        assertEquals(PairingSaveOutcome.SAVED_V3, a.saveFrom(b.session!!.secretOnlyCode()!!, requireFull = false))
        assertEquals(PairingSaveOutcome.SAVED_LEGACY, b.saveFrom(stripEk(a.full(), a), requireFull = true))
        val stateBefore = a.vault.inner.meta[VaultRatchetStore.stateKey(cid, MessageManager.RATCHET_TEXT_CHANNEL)]
        b.announce()
        assertFalse(MessageManager.isRatchetWire(relay.posted.last()), "the legacy side announces on the static envelope")
        a.mm.pollControlMessages(cid)
        assertNull(a.vault.getInboxIdForContact(cid, "outbound"), "a v3 contact never applies a static announce")
        val stamp = assertNotNull(
            a.vault.inner.meta[MessageManager.drKeyConfirmKey(cid)]?.toLongOrNull(),
            "the static announce the v3 side cannot open is recorded",
        )
        assertFalse(MessageManager.pairingKeyConfirmationFailed(a.vault, cid, nowMs = stamp + MessageManager.KEY_CONFIRM_GRACE_MS - 1))
        assertTrue(MessageManager.pairingKeyConfirmationFailed(a.vault, cid, nowMs = stamp + MessageManager.KEY_CONFIRM_GRACE_MS))
        // The bound runs from the FIRST such wire.
        b.announce(); relay.inner.expireLeases(); a.mm.pollControlMessages(cid)
        assertEquals(stamp, a.vault.inner.meta[MessageManager.drKeyConfirmKey(cid)]!!.toLong())
        // Nothing reset, nothing deleted: the verdict only records.
        assertNotNull(a.vault.getContact(cid)); assertTrue(a.vault.getContact(cid)!!.ratchetBootstrapV3)
        assertEquals(stateBefore, a.vault.inner.meta[VaultRatchetStore.stateKey(cid, MessageManager.RATCHET_TEXT_CHANNEL)])
        // The LEGACY side: its save succeeded and it holds both inbox rows, so its screen
        // shows a paired contact at once; it never gets a failure verdict (legacy), and
        // its texts leave (the relay takes them) but the v3 side drops every one.
        assertFalse(b.mm.pairingKeyConfirmationFailed(cid))
        assertNull(b.vault.inner.meta[MessageManager.drKeyConfirmKey(cid)])
        assertTrue(b.mm.sendMessage(cid, "hello?"))
        assertTrue(a.mm.pollMessages(cid).isEmpty(), "a v3 contact never accepts static text")
        assertTrue(relay.posted.none { MessageManager.isRatchetWire(it) }, "nothing ratchet-sealed exists in this split")
    }

    /**
     * Plan §5.4, the other half: `ek` stripped from the show-first side's SECRET-ONLY
     * code, so the PENDING side saved legacy and the announcer v3. The legacy pending
     * side cannot open the ratchet-sealed announce and keeps waiting (no verdict exists
     * for a legacy contact); the wire is left on the relay, nothing is deleted.
     */
    @Test
    fun keyConfirmation_ekStrippedFromTheSecretOnlyCode_legacyPendingSideKeepsWaiting() {
        if (!up()) return
        val relay = RecordingLeasingRelay()
        val a = dev(relay, V3Messaging.IN_A, V3Messaging.CTL_A)   // scans the tampered code first: pending, legacy
        val b = dev(relay, V3Messaging.IN_B, V3Messaging.CTL_B)   // scans a's intact full code: v3
        assertEquals(PairingSaveOutcome.SAVED_LEGACY, a.saveFrom(stripEk(b.session!!.secretOnlyCode()!!, b), requireFull = false))
        assertEquals(PairingSaveOutcome.SAVED_V3, b.saveFrom(a.full(), requireFull = true))
        b.announce()
        assertTrue(MessageManager.isRatchetWire(relay.posted.last()), "the v3 side announces over the ratchet only")
        a.mm.pollControlMessages(cid)
        assertNull(a.vault.getInboxIdForContact(cid, "outbound"), "the legacy side cannot read it")
        assertNull(a.vault.inner.meta[MessageManager.drKeyConfirmKey(cid)])
        assertFalse(MessageManager.pairingKeyConfirmationFailed(a.vault, cid, nowMs = Long.MAX_VALUE))
        assertNotNull(a.vault.getContact(cid))
        // The v3 side holds both rows (paired on its screen); its texts never open.
        assertTrue(b.mm.sendMessage(cid, "hello?"))
        assertTrue(a.mm.pollMessages(cid).isEmpty())
    }

    /**
     * The recording of a static wire is confined to the pairing wait: it never moves
     * a CONFIRMED contact, never stamps the show-first side (it has the peer's rows),
     * and an AUTHENTIC static chatty kind from a v3 peer (keyed by `ss'`) is not
     * mistaken for a legacy peer.
     */
    @Test
    fun keyConfirmation_staticWire_neverFlipsConfirmed_neverStampsTheAnnouncer_neverAnAuthenticChattyKind() {
        if (!up()) return
        // (1) A confirmed v3 pair: static junk on both control inboxes changes nothing.
        run {
            val relay = RecordingLeasingRelay()
            val a = dev(relay, V3Messaging.IN_A, V3Messaging.CTL_A)
            val b = dev(relay, V3Messaging.IN_B, V3Messaging.CTL_B)
            twoScan(a, b); talk(a, b)
            relay.inner.deliver(V3Messaging.CTL_A, staticJunk(1)); relay.inner.deliver(V3Messaging.CTL_B, staticJunk(2))
            a.mm.pollControlMessages(cid); b.mm.pollControlMessages(cid)
            for (d in listOf(a, b)) assertEquals(MessageManager.KEY_CONFIRMED, d.vault.inner.meta[MessageManager.drKeyConfirmKey(cid)])
        }
        // (2) + (3) Mid-pairing, nothing confirmed yet.
        val relay = RecordingLeasingRelay()
        val a = dev(relay, V3Messaging.IN_A, V3Messaging.CTL_A)   // pending
        val b = dev(relay, V3Messaging.IN_B, V3Messaging.CTL_B)   // announcer
        assertEquals(PairingSaveOutcome.SAVED_V3, a.saveFrom(b.session!!.secretOnlyCode()!!, requireFull = false))
        assertEquals(PairingSaveOutcome.SAVED_V3, b.saveFrom(a.full(), requireFull = true))
        assertTrue(b.mm.sendMaximumAnnouncement(cid, true), "a chatty kind leaves on the static envelope")
        assertFalse(MessageManager.isRatchetWire(relay.posted.last()))
        a.mm.pollControlMessages(cid)
        assertNull(a.vault.inner.meta[MessageManager.drKeyConfirmKey(cid)], "an authentic static chatty kind is not a legacy peer")
        relay.inner.deliver(V3Messaging.CTL_B, staticJunk(3))
        b.mm.pollControlMessages(cid)
        assertNull(b.vault.inner.meta[MessageManager.drKeyConfirmKey(cid)], "the announcer is not waiting for anything")
        b.announce()
        a.mm.pollControlMessages(cid)
        assertEquals(MessageManager.KEY_CONFIRMED, a.vault.inner.meta[MessageManager.drKeyConfirmKey(cid)])
    }

    /** A PENDING v3 side: scanned the peer's secret-only code, holds no outbound row. */
    private fun pendingV3(): Pair<Dev, RecordingLeasingRelay> {
        val relay = RecordingLeasingRelay()
        val a = dev(relay, V3Messaging.IN_A, V3Messaging.CTL_A)
        val b = dev(relay, V3Messaging.IN_B, V3Messaging.CTL_B)
        assertEquals(PairingSaveOutcome.SAVED_V3, a.saveFrom(b.session!!.secretOnlyCode()!!, requireFull = false))
        assertNull(a.vault.getInboxIdForContact(cid, "outbound"), "pending")
        assertNull(a.vault.inner.meta[MessageManager.drKeyConfirmKey(cid)], "nothing seen yet")
        return a to relay
    }

    /**
     * Control inbox only: a static blob on the pending v3 side's TEXT inbox is not
     * counted. (Today the v3 birth lock already rejects every static text blob before
     * any decrypt, so this pins the outcome rather than the `Chan.CTL` guard itself.
     * No group inbox exists on a secret-only pending save.)
     */
    @Test
    fun keyConfirmation_staticBlobOnTheTextInbox_ofAPendingV3Side_isNotCounted() {
        if (!up()) return
        val (a, relay) = pendingV3()
        relay.inner.deliver(V3Messaging.IN_A, staticJunk(4))
        assertTrue(a.mm.pollMessages(cid).isEmpty())
        assertNull(a.vault.inner.meta[MessageManager.drKeyConfirmKey(cid)])
        assertFalse(MessageManager.pairingKeyConfirmationFailed(a.vault, cid, nowMs = Long.MAX_VALUE))
    }

    /** v3 only: static junk on a LEGACY pending side's control inbox never writes the marker. */
    @Test
    fun keyConfirmation_staticJunk_onALegacyPendingSide_writesNoMarker() {
        if (!up()) return
        val relay = RecordingLeasingRelay()
        val a = dev(relay, V3Messaging.IN_A, V3Messaging.CTL_A)
        val b = dev(relay, V3Messaging.IN_B, V3Messaging.CTL_B)
        assertEquals(PairingSaveOutcome.SAVED_LEGACY, a.saveFrom(stripEk(b.session!!.secretOnlyCode()!!, b), requireFull = false))
        assertNull(a.vault.getInboxIdForContact(cid, "outbound"), "pending")
        relay.inner.deliver(V3Messaging.CTL_A, staticJunk(5))
        a.mm.pollControlMessages(cid)
        assertNull(a.vault.inner.meta[MessageManager.drKeyConfirmKey(cid)])
    }

    /** First stamp wins, with no same-millisecond loophole: a seeded old stamp is never moved. */
    @Test
    fun keyConfirmation_unopenableStaticBlob_neverMovesAnEarlierStamp() {
        if (!up()) return
        val (a, relay) = pendingV3()
        a.vault.inner.meta[MessageManager.drKeyConfirmKey(cid)] = "1000"
        relay.inner.deliver(V3Messaging.CTL_A, staticJunk(6))
        a.mm.pollControlMessages(cid)
        assertEquals("1000", a.vault.inner.meta[MessageManager.drKeyConfirmKey(cid)])
        assertTrue(MessageManager.pairingKeyConfirmationFailed(a.vault, cid))
    }

    /** "ok" with NO outbound row (seeded): an unopenable static blob never overwrites it. */
    @Test
    fun keyConfirmation_unopenableStaticBlob_neverOverwritesConfirmed_evenWithoutAnOutboundRow() {
        if (!up()) return
        val (a, relay) = pendingV3()
        a.vault.inner.meta[MessageManager.drKeyConfirmKey(cid)] = MessageManager.KEY_CONFIRMED
        relay.inner.deliver(V3Messaging.CTL_A, staticJunk(7))
        a.mm.pollControlMessages(cid)
        assertEquals(MessageManager.KEY_CONFIRMED, a.vault.inner.meta[MessageManager.drKeyConfirmKey(cid)])
        assertFalse(MessageManager.pairingKeyConfirmationFailed(a.vault, cid, nowMs = Long.MAX_VALUE))
    }

    /** Android semantics: a marker read that THROWS is not "absent" — nothing is stamped. */
    @Test
    fun keyConfirmation_unopenableStaticBlob_whenTheMarkerReadThrows_stampsNothing() {
        if (!up()) return
        val (a, relay) = pendingV3()
        a.vault.hookedKey = MessageManager.drKeyConfirmKey(cid)
        a.vault.hook = { throw IllegalStateException("read failed") }
        relay.inner.deliver(V3Messaging.CTL_A, staticJunk(8))
        a.mm.pollControlMessages(cid)
        assertNull(a.vault.inner.meta[MessageManager.drKeyConfirmKey(cid)])
    }

    @Test
    fun keyConfirmation_neverForALegacyContact_orWithNothingSeen() {
        if (!up()) return
        val v = InMemoryVault()
        v.insertContact(ContactRecord(cid, ByteArray(32) { 1 }, 0, "l", 0L))
        v.putMeta(MessageManager.drKeyConfirmKey(cid), "0")
        assertFalse(MessageManager.pairingKeyConfirmationFailed(v, cid, nowMs = Long.MAX_VALUE), "legacy contact")
        val w = InMemoryVault()
        w.insertContact(ContactRecord(cid, ByteArray(32) { 1 }, 0, "v", 0L, ratchetBootstrapV3 = true))
        assertFalse(MessageManager.pairingKeyConfirmationFailed(w, cid, nowMs = Long.MAX_VALUE), "nothing seen yet")
        w.putMeta(MessageManager.drKeyConfirmKey(cid), "garbage")
        assertFalse(MessageManager.pairingKeyConfirmationFailed(w, cid, nowMs = Long.MAX_VALUE), "unreadable marker")
    }

    // --- the refutation fix: a stored state that is not base64 ------------------------------

    @Test
    fun aStoredStateThatIsNotBase64_isProvenLost_notUnavailableForever() {
        if (!up()) return
        val p = V3Messaging.pair()
        p.a.vault.inner.meta[p.a.stateKey] = "!!! not base64 !!!"
        assertFalse(p.a.mm.sendMessage(cid, "x"))
        assertTrue(p.a.mm.secureChannelLost(cid), "a stable undecodable value is proven corrupt — 'pair again', not a silent dead end")
        assertEquals("!!! not base64 !!!", p.a.vault.inner.meta[p.a.stateKey], "and left untouched")
    }

    @Test
    fun aNonBase64ValueThatChangesBetweenReads_isOnlyUnavailable() {
        if (!up()) return
        val p = V3Messaging.pair()
        var n = 0
        p.a.vault.hookedKey = p.a.stateKey
        p.a.vault.hook = { n++; "!!! junk $n !!!" }
        assertFalse(p.a.mm.sendMessage(cid, "x"))
        assertFalse(p.a.mm.secureChannelLost(cid))
    }
}
