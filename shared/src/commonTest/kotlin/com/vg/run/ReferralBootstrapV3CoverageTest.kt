package com.vg.run

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// Coverage for phase 3 (docs/ratchet-bootstrap-plan.md §4.2) beyond ReferralBootstrapV3Test:
//  A. the lost-channel probe (`MessageManager.referralPeerProvablyLegacy`): one drain per
//     negative, each followed by a positive control on the same pair (so none is vacuous);
//     scope; no side effects; ordering inside a mixed drain;
//  B. known-answer vectors for both bootstrap entry points; the `ref_p` delete inside the
//     commit transaction;
//  C. compatibility: a downgrade between stage and finalize, both accepts stripped, a relay
//     by the introducer code of a build without the one-time bootstrap.
// ---------------------------------------------------------------------------
class ReferralBootstrapV3CoverageTest {

    private fun up() = aeadUp() && x25519Up()
    private fun texts(l: List<ReceivedMessage>) = l.map { it.text }

    private fun ssRef(r: V3Referral): ByteArray = assertNotNull(r.b.inner.contacts[r.cid]).sharedSecret
    private fun lost(s: ReferralSide) = s.inner.meta[MessageManager.drLostKey(s.cid)]
    private fun mainOf(s: ReferralSide) = s.minted.main.inboxId
    private fun deliver(r: V3Referral, inbox: String, bytes: ByteArray) { r.relay.inner.deliver(inbox, bytes) }

    /** An envelope that passes every check on [to]'s MESSAGE inbox (the positive control). */
    private fun proof(r: V3Referral, to: ReferralSide, counter: Long = 1) =
        staticEnvelopeBytes(ssRef(r), counter, di = mainOf(to))

    private fun setBaseline(r: V3Referral, s: ReferralSide, counter: Long) {
        val c = s.inner.contacts.getValue(r.cid)
        s.inner.contacts[r.cid] = c.copy(inboundEpoch = legacyEpochFor(ssRef(r)), inboundCounter = counter)
    }

    // --- A1: one drain per negative, then a positive control on the same pair ---------------

    private fun negativeThenControl(baseline: Long = 0, negative: (V3Referral) -> ByteArray) {
        val r = V3Referral.pair().attachMessaging()
        if (baseline > 0) setBaseline(r, r.c, baseline)
        deliver(r, mainOf(r.c), negative(r))
        assertEquals(emptyList(), texts(r.c.mm.pollMessages(r.cid)))
        assertNull(lost(r.c), "the negative must not latch")
        deliver(r, mainOf(r.c), proof(r, r.c, counter = baseline + 1))
        assertEquals(emptyList(), texts(r.c.mm.pollMessages(r.cid)))
        assertEquals(MessageManager.DR_LOST_NOTICE_OWED, lost(r.c), "control: a valid proof on the same pair latches")
    }

    @Test fun probe_staleEpoch_doesNotLatch() {
        if (!up()) return
        negativeThenControl { r -> staticEnvelopeBytes(ssRef(r), 1, mainOf(r.c), epoch = legacyEpochFor(generateSecureRandom(32))) }
    }

    @Test fun probe_wrongChannelTag_doesNotLatch() {
        if (!up()) return
        negativeThenControl { r -> staticEnvelopeBytes(ssRef(r), 1, mainOf(r.c), ch = MessageManager.CHANNEL_TAG_CTL) }
    }

    @Test fun probe_missingEpoch_doesNotLatch() {
        if (!up()) return
        negativeThenControl { r -> staticEnvelopeBytes(ssRef(r), 1, mainOf(r.c), epoch = null) }
    }

    @Test fun probe_missingCounter_doesNotLatch() {
        if (!up()) return
        negativeThenControl { r -> staticEnvelopeBytes(ssRef(r), null, mainOf(r.c)) }
    }

    @Test fun probe_counterEqualToTheBaseline_doesNotLatch() {
        if (!up()) return
        negativeThenControl(baseline = 10) { r -> staticEnvelopeBytes(ssRef(r), 10, mainOf(r.c)) }
    }

    @Test fun probe_wrongSecret_doesNotLatch() {
        if (!up()) return
        negativeThenControl { r -> staticEnvelopeBytes(generateSecureRandom(32), 1, mainOf(r.c)) }
    }

    @Test fun probe_wrongDestinationInbox_doesNotLatch() {
        if (!up()) return
        negativeThenControl { r -> staticEnvelopeBytes(ssRef(r), 1, "z".repeat(32)) }
    }

    @Test fun probe_controlKind_doesNotLatch() {
        if (!up()) return
        negativeThenControl { r ->
            staticEnvelopeBytes(ssRef(r), 1, mainOf(r.c), extra = ""","k":"${MessageManager.CONTROL_KIND_SCREENSHOT}"""")
        }
    }

    // --- A2: scope ---------------------------------------------------------------------------

    @Test
    fun probe_aStaticTextOnTheControlInbox_doesNotLatch() {
        if (!up()) return
        val r = V3Referral.pair().attachMessaging()
        val ctl = r.c.minted.ctl.inboxId
        deliver(r, ctl, staticEnvelopeBytes(ssRef(r), 1, ctl, ch = MessageManager.CHANNEL_TAG_CTL))
        r.c.mm.pollControlMessages(r.cid)
        assertNull(lost(r.c), "the probe runs on the MESSAGE inbox only")
        deliver(r, mainOf(r.c), proof(r, r.c))
        r.c.mm.pollMessages(r.cid)
        assertNotNull(lost(r.c), "control")
    }

    @Test
    fun probe_aStaticTextOnTheGroupInbox_doesNotLatch() {
        if (!up()) return
        val r = V3Referral.stage(withGrp = true).also { it.deliverToB(); it.deliverToC() }.attachMessaging()
        val grp = V3Referral.GRP_C
        assertNotNull(r.c.inner.getInboxIdForContact(r.cid, MessageManager.DIR_INBOUND_GRP), "precondition: a group inbox")
        deliver(r, grp, staticEnvelopeBytes(ssRef(r), 1, grp, ch = MessageManager.CHANNEL_TAG_GRP, extra = ""","g":"${"K".repeat(32)}""""))
        assertEquals(emptyList(), texts(r.c.mm.pollGroupInbox(r.cid)))
        assertNull(lost(r.c), "the probe runs on the MESSAGE inbox only")
        deliver(r, mainOf(r.c), proof(r, r.c))
        r.c.mm.pollMessages(r.cid)
        assertNotNull(lost(r.c), "control")
    }

    @Test
    fun probe_aLegacyReferralContact_neverProbes_itsStaticTextIsDelivered() {
        if (!up()) return
        val r = V3Referral.pair(bLegacy = true).attachMessaging()
        val c = r.c.inner.contacts.getValue(r.cid)
        assertFalse(c.ratchetBootstrapV3)
        assertNotNull(c.vouchedByContactId, "precondition: referral-born")
        deliver(r, mainOf(r.c), proof(r, r.c))
        assertEquals(listOf("x"), texts(r.c.mm.pollMessages(r.cid)), "a legacy contact accepts it, as today")
        assertNull(lost(r.c))
    }

    @Test
    fun probe_anEmptyOrNullVouchedBy_behavesAsNotReferralBorn() {
        if (!up()) return
        for (v in listOf("", null)) {
            val r = V3Referral.pair().attachMessaging()
            r.c.inner.contacts[r.cid] = r.c.inner.contacts.getValue(r.cid).copy(vouchedByContactId = v)
            deliver(r, mainOf(r.c), proof(r, r.c))
            assertEquals(emptyList(), texts(r.c.mm.pollMessages(r.cid)), "still dropped by the birth lock")
            assertNull(lost(r.c), "vouchedBy=${v?.let { "\"$it\"" } ?: "null"}: no probe")
        }
    }

    @Test
    fun probe_aMoveImportedReferralV3Contact_stillLatches() {
        if (!up()) return
        val r = V3Referral.pair().attachMessaging()
        val fresh = V3TestVault()
        val bundle = MigrationBundle(
            schema = MigrationBundleCodec.CURRENT_SCHEMA, from = MigrationBundle.FROM_ANDROID, createdMs = 1L,
            bundleId = MoveHandleCodec.newBundleId(), snapshot = VaultSnapshotIo.export(r.c.vault),
        )
        val decoded = MigrationBundleCodec.decodeFromString(MigrationBundleCodec.encodeToString(bundle))
        VaultSnapshotIo.import(fresh, decoded.snapshot, MoveConstants.COUNTER_JUMP, decoded.bundleId)
        val moved = MessageManager(fresh, "http://relay.test", r.relay).syncAcks()
        deliver(r, mainOf(r.c), proof(r, r.c))
        assertEquals(emptyList(), texts(moved.pollMessages(r.cid)))
        assertTrue(moved.secureChannelLost(r.cid))
        assertEquals(MessageManager.DR_LOST_NOTICE_OWED, fresh.inner.meta[MessageManager.drLostKey(r.cid)])
    }

    // --- A3: no side effects --------------------------------------------------------------

    private val NO_SECRET = ByteArray(0)

    private class Observed(val row: ContactRecord, val secretHex: String, val meta: Map<String, String>, val unread: Int?)

    private fun observe(r: V3Referral): Observed {
        val c = r.c.inner.contacts.getValue(r.cid)
        return Observed(
            // One shared empty array: a data-class equals compares ByteArray by reference.
            c.copy(sharedSecret = NO_SECRET), bytesToHex(c.sharedSecret),
            r.c.inner.meta.toMap(), r.c.mm.peekUnreadCounts()[r.cid],
        )
    }

    private fun assertSame(before: Observed, after: Observed, allowedNewKeys: Set<String>) {
        assertEquals(before.row, after.row, "contact row (counters, epoch) unchanged")
        assertEquals(before.secretHex, after.secretHex)
        assertEquals(before.meta, after.meta - allowedNewKeys, "no `_meta` change but $allowedNewKeys")
        assertEquals(before.unread, after.unread, "unread count unchanged")
    }

    @Test
    fun probe_hasNoSideEffects_whetherItLatchesOrNot() {
        if (!up()) return
        val r = V3Referral.pair().attachMessaging()
        r.c.mm.pollMessages(r.cid)                     // settle the drain's own bookkeeping
        val before = observe(r)
        assertNull(before.meta[MessageManager.channelTagSeenKey(r.cid)], "precondition: no ch upgrade mark")
        assertNull(before.meta[MessageManager.inboxBoundSeenKey(r.cid)], "precondition: no di upgrade mark")

        // Not latching: authenticates, carries ch + di (which the drain would mark), but its
        // counter equals the baseline (0) — rejected after the ch/di checks ran.
        deliver(r, mainOf(r.c), staticEnvelopeBytes(ssRef(r), 0, mainOf(r.c)))
        r.c.mm.pollMessages(r.cid)
        assertNull(lost(r.c))
        assertSame(before, observe(r), allowedNewKeys = emptySet())

        // Latching: exactly ONE new key, the latch.
        deliver(r, mainOf(r.c), proof(r, r.c))
        r.c.mm.pollMessages(r.cid)
        assertNotNull(lost(r.c))
        assertSame(before, observe(r), allowedNewKeys = setOf(MessageManager.drLostKey(r.cid)))
    }

    // --- A4: ordering in a mixed drain ---------------------------------------------------------

    @Test
    fun probe_theProofFirstInAMixedDrain_latches_andTheRatchetTextStillArrives() {
        if (!up()) return
        val r = V3Referral.pair().attachMessaging()
        deliver(r, mainOf(r.c), proof(r, r.c))
        deliver(r, mainOf(r.c), staticEnvelopeBytes(generateSecureRandom(32), 1, mainOf(r.c)))
        assertTrue(r.b.mm.sendMessage(r.cid, "ratchet"))
        assertEquals(listOf("ratchet"), texts(r.c.mm.pollMessages(r.cid)))
        assertNotNull(lost(r.c))
    }

    @Test
    fun probe_theProofLastInAMixedDrain_latches_andTheRatchetTextStillArrives() {
        if (!up()) return
        val r = V3Referral.pair().attachMessaging()
        assertTrue(r.b.mm.sendMessage(r.cid, "ratchet"))
        deliver(r, mainOf(r.c), staticEnvelopeBytes(generateSecureRandom(32), 1, mainOf(r.c)))
        deliver(r, mainOf(r.c), proof(r, r.c))
        assertEquals(listOf("ratchet"), texts(r.c.mm.pollMessages(r.cid)))
        assertNotNull(lost(r.c))
    }

    // --- B5: known-answer vectors ------------------------------------------------------------
    //
    // The expected hex below was GENERATED FROM THE CURRENT CODE (2026-11-16, phase 3) and is
    // pinned so that a change applied identically on both sides — a renamed label, a flipped
    // transcript order, a different salt — cannot pass unnoticed (two-sided tests would).
    // Inputs: private keys 01..20 and 65..84 (hex bytes, consecutive), QR salt C9..E8, referral
    // S_ref 33..52 and ss_ref 97..B6. In both vectors side B takes Bob.

    private fun seq(start: Int) = ByteArray(32) { (start + it).toByte() }
    private val basepoint = ByteArray(32).also { it[0] = 9 }
    private fun hex(b: ByteArray) = bytesToHex(b)

    private fun assertBobVector(bob: RatchetBootstrapV3.Result, root: String, seed: String, pre: String) {
        val ready = bob as RatchetBootstrapV3.Result.Ready
        assertTrue(ready.selfIsBob)
        val st = V3BootstrapOracle.parseState(ready.ratchet.serialize())
        assertNull(st.remote)
        assertEquals(root, hex(st.secrets[0]), "rk0")
        assertEquals(seed, hex(st.secrets[1]), "rB_seed")
        assertEquals(pre, hex(st.secrets[2]), "CK_pre")
    }

    @Test
    fun kat_qrBootstrap() {
        if (!x25519Up()) return
        val pubA = x25519Ecdh(seq(1), basepoint); val pubB = x25519Ecdh(seq(101), basepoint)
        assertEquals("07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c", hex(pubA))
        assertEquals("5714769d116bf76436ae74bc793d2c30ad1903c59ac5273805c7e2698b410c36", hex(pubB))
        val a = RatchetBootstrapV3.bootstrap(seq(1), pubB, seq(201), mineSortsFirst = true) as RatchetBootstrapV3.Result.Ready
        val b = RatchetBootstrapV3.bootstrap(seq(101), pubA, seq(201), mineSortsFirst = false)
        assertFalse(a.selfIsBob)
        assertBobVector(
            b,
            root = "d8cf28f1a6d37818941dd3239628de35cb124767c07e6aa5d1cefed2ef512219",
            seed = "23e2188869451922f892c3e32dd03bc371d0191b98eacf15613336eef1fd765e",
            pre = "cf2da2783c434c972f0af900c600cd68e8d6c9d47ce65d7e12d2b1b914da0300",
        )
        val ssPrime = "e57450f3df2fdc6ddd5a6757f1b251167ae1d2e6dd3a6c65cdc240b801536b8b"
        assertEquals(ssPrime, hex(a.pairingSecret), "ss'")
        assertEquals(ssPrime, hex((b as RatchetBootstrapV3.Result.Ready).pairingSecret))
        // Alice receives on the same pre-chain.
        assertTrue(V3BootstrapOracle.parseState(a.ratchet.serialize()).secrets.any { hex(it) == "cf2da2783c434c972f0af900c600cd68e8d6c9d47ce65d7e12d2b1b914da0300" })
    }

    @Test
    fun kat_referralBootstrap() {
        if (!x25519Up()) return
        val pubA = x25519Ecdh(seq(1), basepoint); val pubB = x25519Ecdh(seq(101), basepoint)
        val a = RatchetBootstrapV3.bootstrapReferral(seq(51), seq(151), pubA, pubB, mineSortsFirst = true) as RatchetBootstrapV3.Result.Ready
        val b = RatchetBootstrapV3.bootstrapReferral(seq(51), seq(151), pubB, pubA, mineSortsFirst = false)
        assertFalse(a.selfIsBob)
        assertBobVector(
            b,
            root = "8cbcf525d3017d1454e893b0919f6f4a4eaf08170a014b8ed0163bf33465e852",
            seed = "d911f18391b1cf5c21ec9d36d190682538982cef08c842460c405a54a07caa3d",
            pre = "919840b3e45de1eeeee3e29736781a1f3e2ef13e155495bfaf32470f30e26c0b",
        )
        assertContentEquals(seq(151), a.pairingSecret, "the referral keeps ss_ref")
    }

    // --- B7: the ref_p delete is inside the commit transaction --------------------------------

    private class FailingDeleteVault(val inner: InMemoryVault) : VaultDatabase by inner {
        var failDeleteKey: String? = null
        override fun getAllInboxIds(): List<InboxIdRecord> = inner.inboxes.toList()
        override fun deleteMeta(key: String) {
            if (key == failDeleteKey) throw RuntimeException("injected delete failure")
            inner.deleteMeta(key)
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
    fun aFailedRefPDeleteInsideTheCommit_rollsTheWholeCommitBack_andTheRetryCommitsV3() {
        if (!up()) return
        var v: FailingDeleteVault? = null
        val r = V3Referral.stage(wrapB = { FailingDeleteVault(it).also { x -> v = x } })
        val vault = assertNotNull(v)
        vault.failDeleteKey = ReferralMetaKeys.ACCEPT_PREFIX + r.introId
        val refP = assertNotNull(r.b.refP())
        r.deliverToB()
        assertNull(r.b.contact(), "no contact row, so no flag and no secret")
        assertNull(r.b.stateBlob(), "no state")
        assertTrue(r.b.inner.meta.keys.none { it.endsWith("/" + r.cid) || it.contains("/" + r.cid + "/") }, "no marker: ${r.b.inner.meta.keys}")
        assertTrue(r.b.inner.inboxes.none { it.contactId == r.cid })
        assertEquals(refP, r.b.refP(), "ref_p intact")
        vault.failDeleteKey = null
        r.deliverToB()
        assertTrue(assertNotNull(r.b.contact()).ratchetBootstrapV3)
        assertNotNull(r.b.stateBlob())
        assertNull(r.b.refP())
    }

    // --- C9: a downgrade between stage and finalize --------------------------------------------

    /**
     * B stages on this build (its accept leaves WITH `bv`), then finalizes as a build without
     * the one-time bootstrap would: that build's codec ignores `bv`, so the record it reads
     * has none (modelled by removing the field and rebuilding the manager). B commits LEGACY,
     * C — which received B's `bv` accept — commits v3. When B writes, C latches lost; nothing
     * static leaves C except the peer notice.
     */
    @Test
    fun aDowngradeBetweenStageAndFinalize_theV3SideLatchesLostWhenTheOtherWrites() {
        if (!up()) return
        val r = V3Referral.stage()
        assertNotNull(firstStringFieldAnywhere(r.b.acceptBody, "bv"), "B's accept left with bv")
        val key = ReferralMetaKeys.ACCEPT_PREFIX + r.introId
        r.b.inner.meta[key] = assertNotNull(r.b.inner.meta[key]).replace(""","bv":"3"""", "")
        r.b.rm.scrubInMemory()
        val older = ReferralManager(r.b.vault) { null }.also { it.simulatePreBootstrapV3BuildForTest = true }
        older.handleControl(V3Referral.INTRODUCER, MessageManager.CONTROL_KIND_REFERRAL_ACCEPT, r.c.acceptBody)
        r.deliverToC()
        r.attachMessaging()
        assertFalse(assertNotNull(r.b.contact()).ratchetBootstrapV3, "B: legacy")
        assertTrue(assertNotNull(r.c.contact()).ratchetBootstrapV3, "C: v3")

        val ss = ssRef(r)
        val cPosts = mutableListOf<ByteArray>()
        var mark = r.relay.posted.size
        assertTrue(r.c.mm.sendMessage(r.cid, "c 0"))
        cPosts += r.relay.posted.drop(mark)
        assertTrue(r.b.mm.sendMessage(r.cid, "b 0"))
        assertEquals(emptyList(), texts(r.c.mm.pollMessages(r.cid)))
        assertTrue(r.c.mm.secureChannelLost(r.cid))
        mark = r.relay.posted.size
        assertFalse(r.c.mm.sendMessage(r.cid, "refused"))
        assertEquals(1, r.c.mm.redriveChannelLostNotices())
        cPosts += r.relay.posted.drop(mark)
        val static = cPosts.filter { !LegacyBootstrapAttacker.isRatchetBody(it) }
        assertEquals(1, static.size, "only the notice is static")
        assertEquals(MessageManager.CONTROL_KIND_CHANNEL_LOST, firstStringFieldAnywhere(openLegacyEnvelope(ss, static.single()), "k"))
    }

    // --- C10: both accepts stripped -----------------------------------------------------------

    private fun normalizedKeys(s: ReferralSide) = s.inner.meta.keys.map { it.replace(s.cid, "<cid>") }.sorted()

    private fun talk(r: V3Referral): List<Boolean> {
        val start = r.relay.posted.size
        for (i in 0 until 3) {
            assertTrue(r.b.mm.sendMessage(r.cid, "b$i")); assertEquals(listOf("b$i"), texts(r.c.mm.pollMessages(r.cid)))
            assertTrue(r.c.mm.sendMessage(r.cid, "c$i")); assertEquals(listOf("c$i"), texts(r.b.mm.pollMessages(r.cid)))
        }
        return r.relay.posted.drop(start).map { LegacyBootstrapAttacker.isRatchetBody(it) }
    }

    /** Inside the accepted introducer residual: an introducer that strips `bv` from BOTH
     *  accepts gets today's legacy referral, exactly as two older builds would have it. */
    @Test
    fun bothAcceptsStripped_bothCommitLegacy_andTalkExactlyLikeAnOldPairing() {
        if (!up()) return
        val stripped = V3Referral.stage()
        stripped.deliverToB(stripped.c.acceptBody.replace(""","bv":"3"""", ""))
        stripped.deliverToC(stripped.b.acceptBody.replace(""","bv":"3"""", ""))
        stripped.attachMessaging()
        // The legacy role is a per-introduction coin flip (rule v2 over ss_ref and the key
        // order) and it decides who may send ratchet first, so compare against an old pairing
        // in which C took the SAME legacy role.
        fun legacyCIsBob(r: V3Referral) =
            ratchetSelfIsBobFromRoleOrder(ssRef(r), assertNotNull(ratchetRoleOrderBit(r.c.publicKey, r.b.publicKey)))
        val target = legacyCIsBob(stripped)
        val old = (0 until 64).asSequence().map { V3Referral.pair(bLegacy = true, cLegacy = true) }
            .first { legacyCIsBob(it) == target }.attachMessaging()
        for (r in listOf(stripped, old)) for (s in listOf(r.b, r.c)) {
            assertEquals("1", s.inner.meta[MessageManager.drPeerRoleRuleV2Key(s.cid)], "both run role rule v2")
        }
        for (s in listOf(stripped.b, stripped.c)) {
            assertFalse(assertNotNull(s.contact()).ratchetBootstrapV3)
            assertNull(s.stateBlob())
        }
        assertEquals(normalizedKeys(old.b), normalizedKeys(stripped.b), "same markers at birth")
        assertEquals(normalizedKeys(old.c), normalizedKeys(stripped.c))
        val wireOld = talk(old)
        val wireStripped = talk(stripped)
        assertEquals(wireOld, wireStripped, "the same static → ratchet transition on the wire")
        assertEquals(normalizedKeys(old.b), normalizedKeys(stripped.b), "same markers after talking")
        assertEquals(normalizedKeys(old.c), normalizedKeys(stripped.c))
        assertFalse(stripped.b.mm.secureChannelLost(stripped.cid) || stripped.c.mm.secureChannelLost(stripped.cid))
    }

    // --- C11: the introducer relays a `bv` accept unchanged --------------------------------------

    /**
     * The test seam changes how an introducee STAGES; it does not reach the introducer role.
     * The introducer path (`handleAccept` → `relayAcceptAsIntroducer` → the control send, and
     * the `ref_r` redrive) is unchanged by this work, i.e. it IS the code of a build without
     * the one-time bootstrap. Pinned: a `bv` accept leaves the introducer byte-identical.
     */
    @Test
    fun theIntroducer_relaysABvAcceptVerbatim() {
        if (!up()) return
        val vault = InMemoryVault()
        val http = RecordingRelayHttp()
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)
        val bbSecret = generateSecureRandom(32); val ccSecret = generateSecureRandom(32)
        val bbCtl = "e".repeat(32); val ccCtl = "f".repeat(32)
        vault.insertContact(ContactRecord("bb", bbSecret.copyOf(), 0, "Bob", 0L))
        vault.insertContact(ContactRecord("cc", ccSecret.copyOf(), 0, "Carol", 0L))
        vault.insertInboxId(InboxIdRecord(bbCtl, "bb", 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, "C".repeat(43)))
        vault.insertInboxId(InboxIdRecord(ccCtl, "cc", 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, "C".repeat(43)))
        val rm = ReferralManager(vault) { mgr }
        http.script(HttpResult(202, "", true), HttpResult(202, "", true))
        val introId = assertNotNull(rm.startReferral("bb", "cc"))
        val minted = MintedInboxPair(
            MintedInbox("M".repeat(32), "C".repeat(43), "D".repeat(43), 1L),
            MintedInbox("N".repeat(32), "C".repeat(43), "D".repeat(43), 1L),
        )
        val body = ReferralManager(InMemoryVault()) { null }
            .acceptBody(introId, x25519GenerateKeypair().publicKey, minted, bootstrapV3 = true)
        http.script(HttpResult(202, "", true))
        rm.handleControl("bb", MessageManager.CONTROL_KIND_REFERRAL_ACCEPT, body)
        val post = http.calls.last()
        assertTrue(post.url.contains("/inbox/$ccCtl"), "relayed to the OTHER introducee")
        assertEquals(body, firstStringFieldAnywhere(openLegacyEnvelope(ccSecret, post.body), "b"), "byte-identical, bv included")
    }
}
