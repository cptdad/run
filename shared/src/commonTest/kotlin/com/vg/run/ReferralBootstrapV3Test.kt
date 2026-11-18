package com.vg.run

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// Phase 3 of the one-time ratchet bootstrap: the REFERRAL (vouched introduction)
// path — docs/ratchet-bootstrap-plan.md §4.2, §7 "Referral".
//
// What is pinned here, through the real ReferralManager handshake
// (support/V3ReferralFixture):
//  - the `bv` capability: stored in `ref_p` at stage time, the accept emits it only
//    from there (same bytes on every send and after a restart / an app update), and a
//    record without it stays legacy;
//  - v3 iff our stored `bv` AND the peer's accept carries it — new ↔ old is legacy on
//    BOTH sides, with today's accept bytes toward the old side apart from `bv`;
//  - the commit: contact row flag + initial state + the §3.5 markers in ONE
//    transaction that also deletes `ref_p`; an aborted commit leaves nothing but a
//    retryable `ref_p`;
//  - both introducees derive the same state with opposite roles and talk (3 each way,
//    either side first), never on the static envelope;
//  - a flag stripped on one side by the introducer: the v3 side never sends on the
//    static envelope and none of its text opens from stored values;
//  - purge on delete, device move with a pending and with a committed v3 introduction.
// The forward-secrecy oracle cases for the referral live in
// RatchetBootstrapForwardSecrecyTest.
// ---------------------------------------------------------------------------
class ReferralBootstrapV3Test {

    private fun up() = aeadUp() && x25519Up()
    private fun texts(l: List<ReceivedMessage>) = l.map { it.text }

    private fun pkOf(acceptBody: String): ByteArray = decodeBase64(firstStringFieldAnywhere(acceptBody, "pk")!!)

    private fun ssRef(r: V3Referral): ByteArray = hkdfSha256(
        x25519Ecdh(r.b.leakedPriv, r.c.publicKey), ByteArray(0), "run-referral-v1|${r.introId}".encodeToByteArray(), 32,
    )

    private fun sRef(r: V3Referral): ByteArray = hkdfSha256(
        x25519Ecdh(r.b.leakedPriv, r.c.publicKey), ByteArray(0), "run-referral-drboot-v3|${r.introId}".encodeToByteArray(), 32,
    )

    private fun metaFor(s: ReferralSide): Map<String, String?> = listOf(
        s.stateKey, MessageManager.drRoleOrderKey(s.cid), MessageManager.drPeerRoleRuleV2Key(s.cid),
        MessageManager.drIntentKey(s.cid), MessageManager.drOnKey(s.cid), MessageManager.drRecvLockKey(s.cid),
        MessageManager.drCtlCapKey(s.cid),
    ).associateWith { s.inner.meta[it] }

    // --- the `bv` field: codec, stage, redrive stability -------------------------------------

    private val mintedFixed = MintedInboxPair(
        MintedInbox("M".repeat(32), "C".repeat(43), "D".repeat(43), Long.MAX_VALUE),
        MintedInbox("N".repeat(32), "C".repeat(43), "D".repeat(43), Long.MAX_VALUE),
    )

    @Test
    fun storedAccept_bvRoundTrips_andARecordWithoutItDecodesLegacy_withItsOldShape() {
        val priv = ByteArray(32) { (it + 1).toByte() }
        val pub = ByteArray(32) { (it + 50).toByte() }
        val legacy = StoredAccept("aa", "Running Fox", priv, pub, mintedFixed, true, 0, 1000L)
        val legacyEnc = encodeStoredAccept(legacy)
        assertNull(firstStringFieldAnywhere(legacyEnc, "bv"), "a legacy record keeps today's exact shape")
        assertFalse(assertNotNull(decodeStoredAccept(legacyEnc)).bootstrapV3)

        val v3 = StoredAccept("aa", "Running Fox", priv, pub, mintedFixed, true, 0, 1000L, bootstrapV3 = true)
        val v3Enc = encodeStoredAccept(v3)
        assertEquals(legacyEnc.dropLast(1) + ""","bv":"3"}""", v3Enc, "only the trailing field differs")
        assertTrue(assertNotNull(decodeStoredAccept(v3Enc)).bootstrapV3)
        // Exact value only: anything else is legacy (never an error — a live handshake).
        assertFalse(assertNotNull(decodeStoredAccept(v3Enc.replace(""""bv":"3"""", """"bv":"1""""))).bootstrapV3)
        assertTrue(storedAcceptCarriesBootstrapV3(v3Enc))
        assertFalse(storedAcceptCarriesBootstrapV3(legacyEnc))
    }

    @Test
    fun stage_recordsBvInRefP_andTheAcceptCarriesIt_afterRv() {
        if (!x25519Up()) return
        val r = V3Referral.stage()
        val rec = assertNotNull(decodeStoredAccept(assertNotNull(r.b.refP())))
        assertTrue(rec.bootstrapV3, "this build stages every new introduction v3-capable")
        assertEquals("3", firstStringFieldAnywhere(r.b.acceptBody, "bv"))
        assertTrue(r.b.acceptBody.endsWith(""""rv":"2","bv":"3"}"""), "rv then bv, both last")
        assertEquals(r.b.rm.acceptBody(r.introId, r.b.publicKey, r.b.minted, bootstrapV3 = true), r.b.acceptBody)
    }

    @Test
    fun redrive_sameAcceptBytesAfterARestart_andTheDecisionNeverFlips() {
        if (!x25519Up()) return
        // v3-staged: the body every later send would carry equals the first, also from a
        // manager rebuilt over the same vault (backgrounding / process death).
        val r = V3Referral.stage()
        assertEquals(r.b.acceptBody, r.b.rm.stagedAcceptBody(r.introId))
        r.b.rm.scrubInMemory()
        val again = ReferralManager(r.b.vault) { null }
        assertEquals(r.b.acceptBody, again.stagedAcceptBody(r.introId), "a redrive after a restart sends the same bytes")

        // Staged by an older build (no `bv`), redriven by this one ("updated between stage
        // and redrive"): still no `bv` — the decision is the stored one, never re-derived.
        val old = V3Referral.stage(bLegacy = true)
        assertNull(firstStringFieldAnywhere(old.b.acceptBody, "bv"))
        old.b.rm.scrubInMemory()
        val upgraded = ReferralManager(old.b.vault) { null }
        assertFalse(upgraded.simulatePreBootstrapV3BuildForTest, "precondition: the rebuilt manager is this build")
        assertEquals(old.b.acceptBody, upgraded.stagedAcceptBody(old.introId), "the old decision survives the update")
    }

    /** The sweep's real redrive (an `st=0` record) sends exactly the stored decision, over the wire. */
    @Test
    fun theSweepRedrive_sendsTheStoredDecision_bothWays() {
        if (!up()) return
        for (stored in listOf(true, false)) {
            val vault = InMemoryVault()
            val http = RecordingRelayHttp()
            val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)
            val secret = generateSecureRandom(32)
            val ctlOut = "q".repeat(32)
            vault.insertContact(ContactRecord("aa", secret.copyOf(), 0, "Alice", 0L))
            vault.insertInboxId(InboxIdRecord(ctlOut, "aa", 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, "C".repeat(43)))
            val pub = x25519GenerateKeypair().publicKey
            vault.putMeta(
                ReferralMetaKeys.ACCEPT_PREFIX + "rd1",
                encodeStoredAccept(
                    StoredAccept("aa", "Carol", ByteArray(32) { 7 }, pub, mintedFixed, false, 0, currentTimeMillis(), bootstrapV3 = stored),
                ),
            )
            val rm = ReferralManager(vault) { mgr }
            http.script(HttpResult(202, "", true))
            rm.runMaintenance()
            val post = http.calls.single { it.method == "POST" }
            val sentBody = assertNotNull(firstStringFieldAnywhere(openLegacyEnvelope(secret, post.body), "b"))
            assertEquals(rm.acceptBody("rd1", pub, mintedFixed, bootstrapV3 = stored), sentBody)
            assertEquals(if (stored) "3" else null, firstStringFieldAnywhere(sentBody, "bv"))
        }
    }

    // --- the decision: v3 iff stored bv AND peer bv ----------------------------------------------

    @Test
    fun v3Referral_bothDeriveIdenticalStateWithOppositeRoles_andTheBirthMarkers() {
        if (!up()) return
        val r = V3Referral.pair()
        val ss = ssRef(r)
        val s = sRef(r)
        for (side in listOf(r.b, r.c)) {
            val c = assertNotNull(side.contact(), "${side.name} committed")
            assertTrue(c.ratchetBootstrapV3, "${side.name}: the contact-row flag")
            assertContentEquals(ss, c.sharedSecret, "${side.name}: the row keeps ss_ref (plan §4.2), not a DH-mixed ss'")
            assertNull(side.refP(), "${side.name}: ref_p (the one-time private key) died in the commit")
            assertTrue(side.inner.meta.keys.none { it.startsWith("ref_a:") || it.startsWith("ref_o:") })
            val m = metaFor(side)
            assertNotNull(m[side.stateKey], "${side.name}: the state is written at birth")
            for (k in listOf(MessageManager.drPeerRoleRuleV2Key(side.cid), MessageManager.drIntentKey(side.cid),
                    MessageManager.drOnKey(side.cid), MessageManager.drRecvLockKey(side.cid), MessageManager.drCtlCapKey(side.cid))) {
                assertEquals("1", m[k], "${side.name}: $k")
            }
        }
        assertNotEquals(r.b.inner.meta[MessageManager.drRoleOrderKey(r.cid)], r.c.inner.meta[MessageManager.drRoleOrderKey(r.cid)])

        // The role rule, computed independently: rule v2 over ss_ref with the public-key order bit.
        val bOrder = assertNotNull(ratchetRoleOrderBit(r.b.publicKey, r.c.publicKey))
        assertEquals(if (bOrder) "1" else "0", r.b.inner.meta[MessageManager.drRoleOrderKey(r.cid)])
        assertEquals(ratchetSelfIsBobFromRoleOrder(ss, bOrder), r.b.isBobAtBirth())
        assertNotEquals(r.b.isBobAtBirth(), r.c.isBobAtBirth(), "exactly one Bob")

        // The state is the §3.2 one keyed by S_ref/ss_ref over T(pkB, pkC), on both sides.
        val d = V3BootstrapOracle.deriveV3(s, ss, listOf(r.b.publicKey, r.c.publicKey))
        val bob = V3BootstrapOracle.parseState(r.bob.stateBlob()!!)
        val alice = V3BootstrapOracle.parseState(r.alice.stateBlob()!!)
        fun has(st: V3BootstrapOracle.ParsedState, k: ByteArray) = st.secrets.any { it.contentEquals(k) }
        assertTrue(has(bob, d.getValue("root")) && has(bob, d.getValue("bob-key")) && has(bob, d.getValue("pre-chain")))
        assertTrue(has(alice, d.getValue("pre-chain")), "Alice receives on Bob's pre-chain")
        assertFalse(has(alice, d.getValue("root")) || has(alice, d.getValue("bob-key")), "Alice keeps neither rk0 nor rB_seed")
        assertContentEquals(bob.selfPub, alice.remote, "Alice's remote key is Bob's first ratchet key")
        assertContentEquals(x25519Ecdh(d.getValue("bob-key"), ByteArray(32).also { it[0] = 9 }), bob.selfPub)
        // The pkB/pkC that went into T are the ones the accepts carried.
        assertContentEquals(r.b.publicKey, pkOf(r.b.acceptBody))
        assertContentEquals(r.c.publicKey, pkOf(r.c.acceptBody))
    }

    private fun conversation(r: V3Referral, first: ReferralSide): List<String> {
        val second = if (first === r.b) r.c else r.b
        val sent = mutableListOf<String>()
        val a = (0 until 3).map { "first $it" }
        for (t in a) { sent += t; assertTrue(first.mm.sendMessage(r.cid, t), "send '$t'") }
        assertEquals(a, texts(second.mm.pollMessages(r.cid)))
        val b = (0 until 3).map { "reply $it" }
        for (t in b) { sent += t; assertTrue(second.mm.sendMessage(r.cid, t), "send '$t'") }
        assertEquals(b, texts(first.mm.pollMessages(r.cid)))
        return sent
    }

    private fun assertNothingStatic(r: V3Referral, sent: List<String>) {
        val text = r.relay.posted.filter { !LegacyBootstrapAttacker.isRatchetBody(it) }
            .mapNotNull { LegacyBootstrapAttacker.openStatic(ssRef(r), it) }
        assertTrue(text.none { it in sent }, "no text on the static envelope: $text")
    }

    @Test
    fun v3Referral_threeEachWay_theResponderFirst() {
        if (!up()) return
        val r = V3Referral.pair().attachMessaging()
        val sent = conversation(r, first = r.bob)
        assertNothingStatic(r, sent)
        assertFalse(r.b.mm.secureChannelLost(r.cid) || r.c.mm.secureChannelLost(r.cid))
        assertEquals(MessageManager.KEY_CONFIRMED, r.b.inner.meta[MessageManager.drKeyConfirmKey(r.cid)], "key confirmation runs for a referral contact")
        assertEquals(MessageManager.KEY_CONFIRMED, r.c.inner.meta[MessageManager.drKeyConfirmKey(r.cid)])
    }

    @Test
    fun v3Referral_threeEachWay_theInitiatorFirst() {
        if (!up()) return
        val r = V3Referral.pair().attachMessaging()
        val sent = conversation(r, first = r.alice)
        assertNothingStatic(r, sent)
    }

    // --- mixed versions ----------------------------------------------------------------------------

    /**
     * New ↔ old: B is an older build (no `bv` anywhere). Both sides commit LEGACY, and the
     * bytes toward B are today's accept plus the one unknown `bv` field, which B's parser
     * (fields by name) never reads. The legacy referral then works exactly as before.
     */
    @Test
    fun newAndOldIntroducee_areLegacyOnBothSides_andTalk() {
        if (!up()) return
        val r = V3Referral.pair(bLegacy = true).attachMessaging()
        assertNull(firstStringFieldAnywhere(r.b.acceptBody, "bv"))
        assertEquals(
            r.c.rm.acceptBody(r.introId, r.c.publicKey, r.c.minted, bootstrapV3 = false).dropLast(1) + ""","bv":"3"}""",
            r.c.acceptBody,
            "toward the old side: today's bytes + the unknown field",
        )
        for (side in listOf(r.b, r.c)) {
            val c = assertNotNull(side.contact())
            assertFalse(c.ratchetBootstrapV3, "${side.name}: legacy")
            assertNull(side.stateBlob(), "${side.name}: no state at birth (legacy inits on first use)")
            assertNull(side.inner.meta[MessageManager.drRecvLockKey(side.cid)])
            assertEquals("1", side.inner.meta[MessageManager.drIntentKey(side.cid)])
        }
        assertTrue(r.c.mm.sendMessage(r.cid, "hello old"))
        assertEquals(listOf("hello old"), texts(r.b.mm.pollMessages(r.cid)))
        assertTrue(r.b.mm.sendMessage(r.cid, "hello new"))
        assertEquals(listOf("hello new"), texts(r.c.mm.pollMessages(r.cid)))
    }

    /** A `ref_p` an older build staged, finalized by this build against a v3 peer's accept: legacy. */
    @Test
    fun aRefPWithoutBv_rehydratedByThisBuild_staysLegacy_evenAgainstAPeerBv() {
        if (!up()) return
        val r = V3Referral.stage(bLegacy = true)
        r.b.rm.scrubInMemory()
        val rebuilt = ReferralManager(r.b.vault) { null }
        assertNotNull(firstStringFieldAnywhere(r.c.acceptBody, "bv"), "precondition: the peer is v3-capable")
        rebuilt.handleControl(V3Referral.INTRODUCER, MessageManager.CONTROL_KIND_REFERRAL_ACCEPT, r.c.acceptBody)
        val c = assertNotNull(r.b.contact())
        assertFalse(c.ratchetBootstrapV3)
        assertNull(r.b.stateBlob())
    }

    // --- the commit transaction ------------------------------------------------------------------

    /** Real snapshot/rollback + a putMeta that fails for one key (the last birth marker). */
    private class FailingMarkerVault(val inner: InMemoryVault) : VaultDatabase by inner {
        var failKey: String? = null
        override fun getAllInboxIds(): List<InboxIdRecord> = inner.inboxes.toList()
        override fun putMeta(key: String, value: String) {
            if (key == failKey) throw RuntimeException("injected marker write failure")
            inner.putMeta(key, value)
        }
        override fun withTransaction(block: () -> Unit) {
            val c = inner.contacts.toMap(); val i = inner.inboxes.toList(); val m = inner.meta.toMap()
            try { block() } catch (e: Throwable) {
                inner.contacts.clear(); inner.contacts.putAll(c)
                inner.inboxes.clear(); inner.inboxes.addAll(i)
                inner.meta.clear(); inner.meta.putAll(m)
                throw e
            }
        }
    }

    @Test
    fun anAbortedCommit_rollsBackStateFlagAndRows_leavesRefP_andTheRetryCommitsV3() {
        if (!up()) return
        var failing: FailingMarkerVault? = null
        val r = V3Referral.stage(wrapB = { FailingMarkerVault(it).also { v -> failing = v } })
        val v = failing!!
        v.failKey = MessageManager.drCtlCapKey(r.cid)   // the LAST write of the v3 birth
        val refPBefore = assertNotNull(r.b.refP())
        r.deliverToB()

        assertNull(r.b.contact(), "no contact row (and so no flag, no secret)")
        assertTrue(r.b.inner.inboxes.none { it.contactId == r.cid }, "no inbox rows")
        assertTrue(metaFor(r.b).values.all { it == null }, "no state, no marker: ${metaFor(r.b)}")
        assertEquals(refPBefore, r.b.refP(), "ref_p (with its bv) is intact — a retry is possible, nothing half-born")

        // The peer accept is re-delivered (relay retention) once the vault writes again.
        v.failKey = null
        r.deliverToB()
        val c = assertNotNull(r.b.contact())
        assertTrue(c.ratchetBootstrapV3)
        assertNotNull(r.b.stateBlob())
        assertNull(r.b.refP())
    }

    // --- a malicious introducer strips the flag on ONE side ------------------------------------

    /**
     * The introducer removes `bv` from C's accept before relaying it to B. B finalizes LEGACY
     * (stored bv, peer none); C, which got B's intact accept, finalizes v3. The plan's LOW
     * case. Pinned: the v3 side never puts text on the static envelope and never accepts the
     * legacy side's static text; no text C sends is recoverable from anything stored on
     * either phone. What C then shows is pinned by the option-(a) tests below.
     */
    @Test
    fun aFlagStrippedOnOneSide_theV3SideNeverSendsStatic_andItsTextNeverOpens() {
        if (!up()) return
        val r = V3Referral.stage()
        r.deliverToB(r.c.acceptBody.replace(""","bv":"3"""", ""))
        r.deliverToC()
        r.attachMessaging()
        assertFalse(assertNotNull(r.b.contact()).ratchetBootstrapV3, "B: legacy")
        assertTrue(assertNotNull(r.c.contact()).ratchetBootstrapV3, "C: v3")

        val fromC = (0 until 3).map { "c $it" }
        val postedBefore = r.relay.posted.size
        for (t in fromC) assertTrue(r.c.mm.sendMessage(r.cid, t))
        val cWires = r.relay.posted.drop(postedBefore)
        assertEquals(3, cWires.size)
        assertTrue(cWires.all { LegacyBootstrapAttacker.isRatchetBody(it) }, "C (v3) sends ratchet wire only")
        assertEquals(emptyList(), texts(r.b.mm.pollMessages(r.cid)), "B cannot read v3 traffic")

        val fromB = (0 until 3).map { "b $it" }
        for (t in fromB) assertTrue(r.b.mm.sendMessage(r.cid, t))
        assertEquals(emptyList(), texts(r.c.mm.pollMessages(r.cid)), "C never accepts static text from a v3 contact")
        // B's authenticated static text is the proof: C latched "secure channel lost" and
        // refuses to send (see the option-(a) tests below) — nothing static either way.
        assertTrue(r.c.mm.secureChannelLost(r.cid))
        val before = r.relay.posted.size
        assertFalse(r.c.mm.sendMessage(r.cid, "c again"))
        assertEquals(before, r.relay.posted.size)

        // Everything at rest on both phones + every wire: none of C's text opens.
        val blobs = listOfNotNull(r.b.stateBlob(), r.c.stateBlob())
        val secrets = mutableListOf<ByteArray>()
        for (s in listOf(r.b, r.c)) secrets += V3BootstrapOracle.secretsAtRest(s.inner, exclude = setOf(s.stateKey))
        val opened = V3BootstrapOracle.open(
            V3BootstrapOracle.Snapshot(
                blobs, secrets, emptyList(), listOf(r.b.publicKey, r.c.publicKey), r.relay.posted.toList(), r.introId,
            ),
        )
        assertTrue(opened.none { it.startsWith("c ") }, "no v3-side text opens: $opened")
        val staticOpened = r.relay.posted.mapNotNull { LegacyBootstrapAttacker.openStatic(ssRef(r), it) }
        assertTrue(staticOpened.none { it.startsWith("c ") })
        assertEquals(fromB, staticOpened, "control: the legacy side's own text IS static (today's legacy exposure)")
    }

    // --- purge -----------------------------------------------------------------------------------

    @Test
    fun deletingAV3ReferralContact_purgesEveryKeyItsBirthWrote() {
        if (!up()) return
        val r = V3Referral.pair().attachMessaging()
        conversation(r, first = r.b)
        val purge = ratchetMetaKeysForContact(r.cid).toSet()
        for (k in metaFor(r.b).keys + MessageManager.drKeyConfirmKey(r.cid)) assertTrue(k in purge, "$k is in the shared purge list")
        r.b.vault.deleteContact(r.cid)
        assertNull(r.b.contact())
        assertTrue(r.b.inner.meta.keys.none { it.contains(r.cid) }, "no residue: ${r.b.inner.meta.keys}")
    }

    // --- device move --------------------------------------------------------------------------------

    private fun move(from: VaultDatabase, to: VaultDatabase, schema: Int) {
        val bundle = MigrationBundle(
            schema = schema, from = MigrationBundle.FROM_ANDROID, createdMs = 1L,
            bundleId = MoveHandleCodec.newBundleId(), snapshot = VaultSnapshotIo.export(from),
        )
        val decoded = MigrationBundleCodec.decodeFromString(MigrationBundleCodec.encodeToString(bundle))
        VaultSnapshotIo.import(to, decoded.snapshot, MoveConstants.COUNTER_JUMP, decoded.bundleId)
    }

    @Test
    fun move_aPendingV3Introduction_keepsItsBvDecision_andFinalizesV3OnTheNewPhone() {
        if (!up()) return
        val r = V3Referral.stage()
        r.deliverToC()                       // C committed v3 against B's bv accept; B still pending
        val snap = VaultSnapshotIo.export(r.b.vault)
        assertTrue(snap.contacts.none { it.ratchetBootstrapV3 }, "precondition: no v3 CONTACT on B yet")
        assertEquals(MigrationBundleCodec.CURRENT_SCHEMA, MigrationBundleCodec.exportSchemaFor(snap),
            "a pending bv introduction must not reach an older importer")
        var refusedOld = false
        try {
            MigrationBundleCodec.encodeToString(
                MigrationBundle(schema = MigrationBundleCodec.LEGACY_EXPORT_SCHEMA, from = MigrationBundle.FROM_IOS,
                    createdMs = 1L, bundleId = MoveHandleCodec.newBundleId(), snapshot = snap),
            )
        } catch (_: MigrationBundleCodec.FormatException) { refusedOld = true }
        assertTrue(refusedOld)

        val fresh = V3TestVault()
        move(r.b.vault, fresh, MigrationBundleCodec.exportSchemaFor(snap))
        val moved = ReferralManager(fresh) { null }
        assertEquals(r.b.acceptBody, moved.stagedAcceptBody(r.introId), "the moved record emits the same bv accept")
        moved.handleControl(V3Referral.INTRODUCER, MessageManager.CONTROL_KIND_REFERRAL_ACCEPT, r.c.acceptBody)
        val c = assertNotNull(fresh.inner.contacts[r.cid])
        assertTrue(c.ratchetBootstrapV3, "the moved phone commits v3, matching the peer")
        val mm = MessageManager(fresh, "http://relay.test", r.relay).syncAcks()
        r.c.mm = MessageManager(r.c.vault, "http://relay.test", r.relay).syncAcks()
        assertTrue(mm.sendMessage(r.cid, "from the new phone"))
        assertEquals(listOf("from the new phone"), texts(r.c.mm.pollMessages(r.cid)))
        assertTrue(r.c.mm.sendMessage(r.cid, "to the new phone"))
        assertEquals(listOf("to the new phone"), texts(mm.pollMessages(r.cid)))
    }

    @Test
    fun move_aPendingLegacyIntroduction_keepsTheOldSchema() {
        if (!x25519Up()) return
        val r = V3Referral.stage(bLegacy = true)
        assertEquals(MigrationBundleCodec.LEGACY_EXPORT_SCHEMA, MigrationBundleCodec.exportSchemaFor(VaultSnapshotIo.export(r.b.vault)))
    }

    @Test
    fun move_aCommittedV3ReferralContact_travelsAndTalks() {
        if (!up()) return
        val r = V3Referral.pair().attachMessaging()
        conversation(r, first = r.c)
        val snap = VaultSnapshotIo.export(r.b.vault)
        assertEquals(MigrationBundleCodec.CURRENT_SCHEMA, MigrationBundleCodec.exportSchemaFor(snap))
        val fresh = V3TestVault()
        move(r.b.vault, fresh, MigrationBundleCodec.CURRENT_SCHEMA)
        assertTrue(fresh.inner.contacts.getValue(r.cid).ratchetBootstrapV3)
        for ((k, v) in metaFor(r.b)) assertEquals(v, fresh.inner.meta[k], "$k travels")
        val mm = MessageManager(fresh, "http://relay.test", r.relay).syncAcks()
        assertTrue(mm.sendMessage(r.cid, "moved"))
        assertEquals(listOf("moved"), texts(r.c.mm.pollMessages(r.cid)))
        assertTrue(r.c.mm.sendMessage(r.cid, "back"))
        assertEquals(listOf("back"), texts(mm.pollMessages(r.cid)))
    }

    // --- the bootstrap entry point itself ----------------------------------------------------

    @Test
    fun bootstrapReferral_refusals_andTheStoredSecretIsACopyOfSsRef() {
        if (!x25519Up()) return
        val a = x25519GenerateKeypair(); val b = x25519GenerateKeypair()
        val s = generateSecureRandom(32); val ss = generateSecureRandom(32)
        fun run(sIn: ByteArray = s, ssIn: ByteArray = ss, my: ByteArray = a.publicKey, peer: ByteArray = b.publicKey) =
            RatchetBootstrapV3.bootstrapReferral(sIn, ssIn, my, peer, mineSortsFirst = true)
        fun refusal(res: RatchetBootstrapV3.Result) = (res as? RatchetBootstrapV3.Result.Refused)?.reason
        assertEquals(RatchetBootstrapV3.Refusal.MALFORMED_INPUT, refusal(run(sIn = ByteArray(31))))
        assertEquals(RatchetBootstrapV3.Refusal.SPENT_EPHEMERAL_KEY, refusal(run(sIn = ByteArray(32))))
        assertEquals(RatchetBootstrapV3.Refusal.SPENT_EPHEMERAL_KEY, refusal(run(ssIn = ByteArray(32))))
        assertEquals(RatchetBootstrapV3.Refusal.LOW_ORDER_PEER_KEY, refusal(run(peer = ByteArray(32).also { it[0] = 1 })))
        assertEquals(RatchetBootstrapV3.Refusal.REFLECTED_PEER_KEY, refusal(run(peer = a.publicKey.copyOf())))
        val reflectedBit255 = a.publicKey.copyOf().also { it[31] = (it[31].toInt() or 0x80).toByte() }
        assertEquals(RatchetBootstrapV3.Refusal.REFLECTED_PEER_KEY, refusal(run(peer = reflectedBit255)))

        val ready = run() as RatchetBootstrapV3.Result.Ready
        assertContentEquals(ss, ready.pairingSecret, "the referral keeps ss_ref as the stored secret")
        ready.wipe()
        assertTrue(ss.any { it.toInt() != 0 } && s.any { it.toInt() != 0 }, "the inputs are the caller's: never wiped here")
        // Opposite order bits → opposite roles over the same secrets.
        val x = RatchetBootstrapV3.bootstrapReferral(s, ss, a.publicKey, b.publicKey, true) as RatchetBootstrapV3.Result.Ready
        val y = RatchetBootstrapV3.bootstrapReferral(s, ss, b.publicKey, a.publicKey, false) as RatchetBootstrapV3.Result.Ready
        assertNotEquals(x.selfIsBob, y.selfIsBob)
    }

    // --- the stripped flag made visible: authenticated static text latches `dr-lost` ------
    //
    // Plan §4.2 (option (a)): a v3 contact born through the REFERRAL commit
    // (`vouchedByContactId` set — only that commit writes it) that receives, on its MESSAGE
    // inbox, a static TEXT envelope authenticating under the stored `ss_ref` with every
    // legacy envelope check passing, has positive proof the peer finalized the old way.
    // It latches `dr-lost` through the phase-2 function: the lost notice shows, sends are
    // refused, the `chlost` peer notice goes out. The text itself is dropped by the birth
    // lock exactly as before.

    private fun inboxOf(s: ReferralSide) = s.minted.main.inboxId

    /** One static envelope delivered onto [to]'s message inbox, sealed under [secret]. */
    private fun injectStatic(
        r: V3Referral, to: ReferralSide, secret: ByteArray, counter: Long,
        extra: String = "", di: String = inboxOf(to), ch: String = MessageManager.CHANNEL_TAG_MAIN,
    ): ByteArray {
        val json = """{"e":"${legacyEpochFor(secret)}","c":$counter,"t":0,"ch":"$ch","di":"$di"$extra,"m":"x"}"""
        return sealLegacyEnvelopeBytes(secret, json).also { r.relay.inner.deliver(inboxOf(to), it) }
    }

    private fun strippedPair(): V3Referral {
        val r = V3Referral.stage()
        r.deliverToB(r.c.acceptBody.replace(""","bv":"3"""", ""))
        r.deliverToC()
        return r.attachMessaging()
    }

    private fun lostValue(s: ReferralSide) = s.inner.meta[MessageManager.drLostKey(s.cid)]

    @Test
    fun strippedFlag_theLegacySideWrites_theV3SideLatchesLost_refusesSends_andOnlyThePeerNoticeIsStatic() {
        if (!up()) return
        val r = strippedPair()
        val ss = ssRef(r)
        // C (v3) writes first: ratchet only, nothing latched yet.
        var mark = r.relay.posted.size
        assertTrue(r.c.mm.sendMessage(r.cid, "c 0"))
        assertTrue(r.relay.posted.drop(mark).all { LegacyBootstrapAttacker.isRatchetBody(it) })
        // B (legacy) writes: a static text under ss_ref.
        assertTrue(r.b.mm.sendMessage(r.cid, "b 0"))
        val bText = r.relay.posted.last().copyOf()
        assertEquals("b 0", LegacyBootstrapAttacker.openStatic(ss, bText))

        assertEquals(emptyList(), texts(r.c.mm.pollMessages(r.cid)), "the text is never shown")
        assertTrue(r.c.mm.secureChannelLost(r.cid), "the public accessor the screens read")
        assertEquals(MessageManager.DR_LOST_NOTICE_OWED, lostValue(r.c))
        assertTrue(r.c.inner.contacts.getValue(r.cid).ratchetBootstrapV3, "nothing reset")
        assertNotNull(r.c.stateBlob(), "nothing wiped")

        mark = r.relay.posted.size
        assertFalse(r.c.mm.sendMessage(r.cid, "refused"), "sends are refused")
        assertEquals(mark, r.relay.posted.size, "…and nothing is posted for them")

        // The peer notice: the ONLY static thing C ever emits.
        assertEquals(1, r.c.mm.redriveChannelLostNotices())
        val notice = r.relay.posted.drop(mark)
        assertEquals(1, notice.size)
        assertFalse(LegacyBootstrapAttacker.isRatchetBody(notice.single()))
        assertEquals(MessageManager.CONTROL_KIND_CHANNEL_LOST, firstStringFieldAnywhere(openLegacyEnvelope(ss, notice.single()), "k"))
        assertEquals(MessageManager.DR_LOST_NOTICE_SENT, lostValue(r.c))

        // The legacy side (this build, a LEGACY contact) on the notice: dropped as
        // "channel-lost notice for a non-v3 pairing" — nothing latched, nothing shown.
        // Recorded, not changed by this work.
        r.b.mm.pollControlMessages(r.cid)
        assertFalse(r.b.mm.secureChannelLost(r.cid))
        assertNull(lostValue(r.b))

        // Idempotent: a re-served copy of the same envelope changes nothing further.
        r.relay.inner.deliver(inboxOf(r.c), bText)
        assertEquals(emptyList(), texts(r.c.mm.pollMessages(r.cid)))
        assertEquals(MessageManager.DR_LOST_NOTICE_SENT, lostValue(r.c), "not reset to 'owed'")
        assertEquals(0, r.c.mm.redriveChannelLostNotices(), "no second notice")
    }

    /** The stated LIMIT: while only the v3 side writes (the legacy side stays silent),
     *  there is no positive evidence and nothing is latched or shown on either side. */
    @Test
    fun strippedFlag_limit_onlyTheV3SideWrites_nothingLatches() {
        if (!up()) return
        val r = strippedPair()
        repeat(3) { assertTrue(r.c.mm.sendMessage(r.cid, "c $it")) }
        assertEquals(emptyList(), texts(r.b.mm.pollMessages(r.cid)))
        assertEquals(emptyList(), texts(r.c.mm.pollMessages(r.cid)))
        assertFalse(r.c.mm.secureChannelLost(r.cid) || r.b.mm.secureChannelLost(r.cid))
    }

    /** Only POSITIVE proof latches: a wrong secret, a counter at/below the baseline (a
     *  replay), a wrong `di`, and a non-text (control) envelope do not; then one that
     *  passes every check does — so the negatives are not vacuous. */
    @Test
    fun onlyAnAuthenticatedFreshTextLatches_notAWrongSecretAReplayAWrongDiOrAControlBlob() {
        if (!up()) return
        val r = V3Referral.pair().attachMessaging()
        val ss = ssRef(r)
        val c = r.c.inner.contacts.getValue(r.cid)
        r.c.inner.contacts[r.cid] = c.copy(inboundEpoch = legacyEpochFor(ss), inboundCounter = 10)
        injectStatic(r, r.c, generateSecureRandom(32), counter = 50)                          // wrong secret
        injectStatic(r, r.c, ss, counter = 7)                                                  // replay: ≤ baseline
        injectStatic(r, r.c, ss, counter = 51, di = "z".repeat(32))                             // reflected / spliced
        injectStatic(r, r.c, ss, counter = 52, extra = ""","k":"${MessageManager.CONTROL_KIND_SCREENSHOT}"""")   // control
        injectStatic(r, r.c, ss, counter = 53, extra = ""","k":"${MessageManager.CONTROL_KIND_CHANNEL_LOST}"""") // a chlost on MAIN
        assertEquals(emptyList(), texts(r.c.mm.pollMessages(r.cid)))
        assertFalse(r.c.mm.secureChannelLost(r.cid), "none of these is proof")
        assertNull(lostValue(r.c))
        assertTrue(r.c.mm.sendMessage(r.cid, "still fine"))

        injectStatic(r, r.c, ss, counter = 11)
        r.c.mm.pollMessages(r.cid)
        assertTrue(r.c.mm.secureChannelLost(r.cid), "control: an authenticated fresh text does latch")
    }

    /** A QR-born v3 contact is unaffected: its row stores `ss'`. A static text under the
     *  halves-secret (what a stripped QR peer would use) does not open and latches nothing;
     *  even one sealed under the row's own `ss'` latches nothing (no referral provenance). */
    @Test
    fun aQrBornV3Contact_isUnaffected() {
        if (!up()) return
        val p = V3Messaging.pair()
        val cid = V3Messaging.CID
        fun inject(secret: ByteArray, counter: Long) {
            val json = """{"e":"${legacyEpochFor(secret)}","c":$counter,"t":0,"ch":"m","di":"${V3Messaging.IN_A}","m":"x"}"""
            p.relay.inner.deliver(V3Messaging.IN_A, sealLegacyEnvelopeBytes(secret, json))
        }
        assertNull(p.a.contact().vouchedByContactId)
        inject(p.ssHalves, 1)
        inject(p.a.contact().sharedSecret, 2)
        assertEquals(emptyList(), texts(p.a.mm.pollMessages(cid)))
        assertFalse(p.a.mm.secureChannelLost(cid))
        assertNull(p.a.vault.inner.meta[MessageManager.drLostKey(cid)])
        assertTrue(p.a.mm.sendMessage(cid, "still talking"))
        assertEquals(listOf("still talking"), texts(p.b.mm.pollMessages(cid)))
    }

    @Test
    fun theLatch_isClearedByDelete_andANewIntroductionStartsClean() {
        if (!up()) return
        val r = strippedPair()
        assertTrue(r.b.mm.sendMessage(r.cid, "b 0"))
        r.c.mm.pollMessages(r.cid)
        assertNotNull(lostValue(r.c))
        assertTrue(MessageManager.drLostKey(r.cid) in ratchetMetaKeysForContact(r.cid))
        r.c.vault.deleteContact(r.cid)
        assertTrue(r.c.inner.meta.keys.none { it.contains(r.cid) }, "no residue: ${r.c.inner.meta.keys}")

        // The same two vaults are introduced again (a fresh introduction, honest both sides).
        val again = V3Referral.stage(
            innerB = r.b.inner, innerC = r.c.inner,
            ids = listOf("T".repeat(32), "t".repeat(32), "U".repeat(32), "u".repeat(32)),
        )
        again.deliverToB(); again.deliverToC(); again.attachMessaging()
        assertFalse(again.c.mm.secureChannelLost(again.cid))
        assertTrue(again.c.mm.sendMessage(again.cid, "new"))
        assertEquals(listOf("new"), texts(again.b.mm.pollMessages(again.cid)))
    }

    @Test
    fun theLatch_travelsWithAMove() {
        if (!up()) return
        val r = strippedPair()
        assertTrue(r.b.mm.sendMessage(r.cid, "b 0"))
        r.c.mm.pollMessages(r.cid)
        val owed = assertNotNull(lostValue(r.c))
        val fresh = V3TestVault()
        move(r.c.vault, fresh, MigrationBundleCodec.exportSchemaFor(VaultSnapshotIo.export(r.c.vault)))
        assertEquals(owed, fresh.inner.meta[MessageManager.drLostKey(r.cid)])
        assertNotNull(fresh.inner.contacts.getValue(r.cid).vouchedByContactId, "the referral provenance travels too")
        val moved = MessageManager(fresh, "http://relay.test", r.relay).syncAcks()
        assertTrue(moved.secureChannelLost(r.cid))
        assertFalse(moved.sendMessage(r.cid, "refused on the new phone"))
    }
}
