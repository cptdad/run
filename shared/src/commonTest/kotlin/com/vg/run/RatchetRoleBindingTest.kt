package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail

// ---------------------------------------------------------------------------
// Role binding:
// the Double-Ratchet role must stop being a function of the peer-supplied
// OUTBOUND inbox id.
//
// Old rule: `selfIsBob = myInboundInboxId < myOutboundInboxId`, where the
// outbound id is whatever the peer declared over the QR payload or the in-band
// `inbox` announce — mutable after pairing, and therefore movable by the peer at
// a moment of its choosing (an announce, an inbox rotation, or a re-init after
// `onCorruptReinit`).
//
// New rule, in force ONLY when the peer has proven it runs it too (`rv:2`):
//   selfIsBob = parity(HKDF(sharedSecret,"run-dr-role-v1",1)) XOR mineSortsFirst
// where `mineSortsFirst` is fixed at pairing from the two pairing-secret halves
// (QR/paste) or the two ephemeral X25519 public keys (referral).
//
// Every fixture below is deliberately built so the two rules DISAGREE — a
// pairing where they happen to agree proves nothing about which one ran. The
// role itself is read from POSITIVE evidence: a freshly-initialised Alice holds
// a sending chain and a freshly-initialised Bob does not, which is exactly the
// asymmetry the collision destroys.
// ---------------------------------------------------------------------------

private const val RB_CID = "c1"
private val RB_RCAP = "R".repeat(43)
private val RB_WCAP_A = "W".repeat(43)   // write cap for A's inboxes (B holds it)
private val RB_WCAP_B = "X".repeat(43)   // write cap for B's inboxes (A holds it)

/** Both bridges this file needs: AES-GCM/SHA-256 (the envelope + the role parity). */
private fun rbCryptoUp(): Boolean = try {
    aesGcmEncrypt(ByteArray(1), generateSecureRandom(32), ByteArray(0))
    true
} catch (_: Exception) { false }

/** The referral cases additionally need the X25519 bridge. */
private fun rbX25519Up(): Boolean = try { x25519GenerateKeypair(); true } catch (_: Exception) { false }

/** Relay double: stores POSTed blobs per inbox, drains on GET (real relay semantics). */
private class RbRelay : InboxQueueRelay()

/**
 * The role a device's PERSISTED ratchet state was born with, read as POSITIVE
 * evidence rather than inferred from the absence of something: `initAsAlice`
 * gives a sending chain immediately, `initAsBob` does not.
 *
 * ONLY valid on a FRESH init — the first receiving DH step hands Bob a sending
 * chain too, so every caller below reads it before that device has decrypted
 * anything. Fails loudly when no state exists at all, so a test that silently
 * never computed a role cannot pass (the vacuity trap).
 */
private fun freshRoleIsBob(vault: InMemoryVault, contactId: String = RB_CID): Boolean {
    val b64 = vault.getMeta("dr/$contactId/${MessageManager.RATCHET_TEXT_CHANNEL}")
        ?: fail("no ratchet state persisted for $contactId — the role was never computed")
    val blob = decodeBase64(b64)
    val dr = DoubleRatchet.deserialize(blob)
    try {
        return !dr.canSend()
    } finally {
        dr.wipe(); blob.secureWipe()
    }
}

/** A pairing whose v2 (secret-order) role DISAGREES with the legacy id-order role. */
private class RbFixture(
    val aHalf: ByteArray,
    val bHalf: ByteArray,
    val sharedSecret: ByteArray,
    /** What the v2 rule says about side A; the id rule says the opposite. */
    val aIsBobUnderV2: Boolean,
)

/**
 * Searches deterministic secret halves for a pair whose v2 role for side A is the
 * OPPOSITE of what `ratchetSelfIsBob(aInbound, aOutbound)` would give. Roughly
 * half of all pairs qualify, so this settles in a couple of iterations; the bound
 * exists so a broken parity can never hang the suite.
 */
private fun fixtureWhereRulesDisagree(aInbound: String, aOutbound: String): RbFixture {
    val aIsBobUnderIds = ratchetSelfIsBob(aInbound, aOutbound)
    for (seed in 0 until 512) {
        val aHalf = sha256(byteArrayOf(1, seed.toByte(), (seed ushr 8).toByte()))
        val bHalf = sha256(byteArrayOf(2, seed.toByte(), (seed ushr 8).toByte()))
        val order = ratchetRoleOrderBit(aHalf, bHalf) ?: continue
        val shared = deriveSharedSecret(aHalf, bHalf)
        val aIsBob = ratchetSelfIsBobFromRoleOrder(shared, order)
        if (aIsBob != aIsBobUnderIds) return RbFixture(aHalf, bHalf, shared, aIsBob)
    }
    fail("no secret pair found whose v2 role disagrees with the id-order role")
}

/**
 * Two devices paired through the REAL `PairingVault.savePairedContact`
 * transaction (contact + four inbox rows + the ratchet-capable marker + the
 * role inputs), over one storing relay.
 *
 * [aRoleRuleV2] / [bRoleRuleV2] model what each side saw in the OTHER's pairing
 * code: `false` is a pre-step-A peer. [aHalf]/[bHalf] null models a pre-step-A
 * build on that side (it persists no role inputs at all).
 */
private class RbPair(
    aInText: String,
    bInText: String,
    aHalf: ByteArray?,
    bHalf: ByteArray?,
    sharedSecret: ByteArray,
    aRoleRuleV2: Boolean,
    bRoleRuleV2: Boolean,
) {
    val relay = RbRelay()
    val aVault = InMemoryVault()
    val bVault = InMemoryVault()
    val a: MessageManager
    val b: MessageManager
    val aIn = aInText
    val bIn = bInText
    val aInCtl = "a".repeat(32)
    val bInCtl = "b".repeat(32)

    init {
        PairingVault.savePairedContact(
            vault = aVault, contactId = RB_CID, sharedSecret = sharedSecret,
            peerInboxId = bInText, peerWriteCap = RB_WCAP_B,
            peerCtlInboxId = bInCtl, peerCtlWriteCap = RB_WCAP_B,
            myInboxId = aInText, myReadCap = RB_RCAP,
            myCtlInboxId = aInCtl, myCtlReadCap = RB_RCAP,
            alias = "peer",
            mySecretHalf = aHalf, peerSecretHalf = bHalf, peerRoleRuleV2 = aRoleRuleV2,
        )
        PairingVault.savePairedContact(
            vault = bVault, contactId = RB_CID, sharedSecret = sharedSecret,
            peerInboxId = aInText, peerWriteCap = RB_WCAP_A,
            peerCtlInboxId = aInCtl, peerCtlWriteCap = RB_WCAP_A,
            myInboxId = bInText, myReadCap = RB_RCAP,
            myCtlInboxId = bInCtl, myCtlReadCap = RB_RCAP,
            alias = "peer",
            mySecretHalf = bHalf, peerSecretHalf = aHalf, peerRoleRuleV2 = bRoleRuleV2,
        )
        // Back-date the four pairing rows. `selectOperationalInbox` picks the
        // HIGHEST `createdAt` and `maxByOrNull` keeps the FIRST maximum, so a row an
        // inbox announce writes microseconds later would TIE with the pairing row and
        // lose — a purely test-harness artefact of pairing and announcing inside one
        // millisecond (in production they are minutes apart). Nothing else reads
        // `createdAt`.
        for (v in listOf(aVault, bVault)) {
            for (r in v.inboxes.toList()) v.insertInboxId(r.copy(createdAt = 0L))
        }
        a = MessageManager(aVault, "http://relay.test", relay)
        b = MessageManager(bVault, "http://relay.test", relay)
    }

    /**
     * Turn SEND-ratchet on directly, on both sides, exactly as the poll loop's
     * `enableRatchetIfReady` would once the first legacy exchange has landed. It is
     * planted rather than driven so that NEITHER side has decrypted anything when
     * its role is first computed — which is the only window in which the role is
     * readable from the persisted state (see [freshRoleIsBob]).
     */
    fun armSendRatchetOnBothSides() {
        for (v in listOf(aVault, bVault)) {
            v.putMeta(MessageManager.drRxSeenKey(RB_CID), "1")
            v.putMeta(MessageManager.drOnKey(RB_CID), "1")
        }
    }
}

class RatchetRoleBindingTest {

    // -- §6 "rv2Pairing_rolesAreComplementary" ------------------------------

    @Test
    fun rv2Pairing_rolesAreComplementary() {
        if (!rbCryptoUp()) return
        // The id rule would make A Bob (aIn sorts first); the fixture guarantees the
        // v2 rule says the opposite, so "the roles are complementary" cannot be
        // satisfied by the OLD rule quietly still being in charge.
        val aIn = "M".repeat(32)
        val bIn = "Z".repeat(32)
        val f = fixtureWhereRulesDisagree(aIn, bIn)
        assertTrue(ratchetSelfIsBob(aIn, bIn), "fixture precondition: the id rule makes A Bob")
        assertFalse(f.aIsBobUnderV2, "fixture precondition: the v2 rule makes A Alice")

        val h = RbPair(aIn, bIn, f.aHalf, f.bHalf, f.sharedSecret, aRoleRuleV2 = true, bRoleRuleV2 = true)

        // The pairing transaction persisted both role inputs, on both sides, with
        // COMPLEMENTARY order bits — that complementarity is the whole tie-break.
        assertEquals("1", h.aVault.getMeta(MessageManager.drPeerRoleRuleV2Key(RB_CID)))
        assertEquals("1", h.bVault.getMeta(MessageManager.drPeerRoleRuleV2Key(RB_CID)))
        val aOrder = assertNotNull(h.aVault.getMeta(MessageManager.drRoleOrderKey(RB_CID)))
        val bOrder = assertNotNull(h.bVault.getMeta(MessageManager.drRoleOrderKey(RB_CID)))
        assertNotEquals(aOrder, bOrder, "the two devices must derive OPPOSITE order bits")

        // First ratchet op on each side, with NO poll in between, so each role is
        // read exactly as it was born.
        h.armSendRatchetOnBothSides()
        assertTrue(h.a.sendMessage(RB_CID, "a-first"))
        assertTrue(h.b.sendMessage(RB_CID, "b-first"))

        val aIsBob = freshRoleIsBob(h.aVault)
        val bIsBob = freshRoleIsBob(h.bVault)
        assertNotEquals(aIsBob, bIsBob, "exactly one device must be Bob")
        assertEquals(f.aIsBobUnderV2, aIsBob, "the role must follow the pairing secrets, not the inbox ids")
        assertNotEquals(ratchetSelfIsBob(aIn, bIn), aIsBob, "…and it must NOT follow the id-order rule here")

        // The channel really works, in both directions, past the bootstrap.
        assertEquals(listOf("b-first"), h.a.pollMessages(RB_CID).map { it.text })
        assertEquals(listOf("a-first"), h.b.pollMessages(RB_CID).map { it.text })
        repeat(50) { i ->
            assertTrue(h.a.sendMessage(RB_CID, "a$i"), "a$i must send")
            assertEquals(listOf("a$i"), h.b.pollMessages(RB_CID).map { it.text })
            assertTrue(h.b.sendMessage(RB_CID, "b$i"), "b$i must send")
            assertEquals(listOf("b$i"), h.a.pollMessages(RB_CID).map { it.text })
        }
        assertTrue(h.relay.sawRatchetWire, "the ratchet must really have engaged")
        assertFalse(h.a.ratchetRefused(RB_CID), "a correctly-roled pairing must never be refused")
        assertFalse(h.b.ratchetRefused(RB_CID))
        assertEquals(0, h.a.ratchetUnackedCount(RB_CID))
        assertEquals(0, h.b.ratchetUnackedCount(RB_CID))
    }

    // -- §6 item 6 "roleRuleSkew_fallsBackToIdOrder" ------------------------

    @Test
    fun roleRuleSkew_fallsBackToIdOrder() {
        if (!rbCryptoUp()) return
        // A runs THIS build (it persists its order bit); B is a pre-step-A build, so
        // its code carried no `rv` and it writes no role inputs at all. A must NOT
        // apply the v2 rule — agreement, not strength, is what a role rule needs, and
        // applying v2 unilaterally here would MANUFACTURE the collision (the fixture
        // is built so the two rules disagree).
        val aIn = "M".repeat(32)
        val bIn = "Z".repeat(32)
        val f = fixtureWhereRulesDisagree(aIn, bIn)

        val h = RbPair(
            aIn, bIn, f.aHalf, f.bHalf, f.sharedSecret,
            aRoleRuleV2 = false,   // B's code carried no rv:2
            bRoleRuleV2 = false,   // …and B, being old, records nothing anyway
        )
        // A did persist its (harmless) order bit; the peer observation is a hard "0",
        // not an omission — see drPeerRoleRuleV2Key.
        assertNotNull(h.aVault.getMeta(MessageManager.drRoleOrderKey(RB_CID)))
        assertEquals(
            "0", h.aVault.getMeta(MessageManager.drPeerRoleRuleV2Key(RB_CID)),
            "no rv:2 in the peer's code ⇒ the peer is LATCHED as a v1 build",
        )

        h.armSendRatchetOnBothSides()
        assertTrue(h.a.sendMessage(RB_CID, "a-first"))
        assertTrue(h.b.sendMessage(RB_CID, "b-first"))

        val aIsBob = freshRoleIsBob(h.aVault)
        val bIsBob = freshRoleIsBob(h.bVault)
        assertEquals(ratchetSelfIsBob(aIn, bIn), aIsBob, "A must fall back to the id-order rule")
        assertEquals(ratchetSelfIsBob(bIn, aIn), bIsBob, "…and so must B")
        assertNotEquals(aIsBob, bIsBob, "the two sides still agree on exactly one Bob")
        assertNotEquals(f.aIsBobUnderV2, aIsBob, "…and it is NOT the v2 answer (the rules disagree here)")

        // …and messages flow, which is the point: skew must cost nothing.
        assertEquals(listOf("b-first"), h.a.pollMessages(RB_CID).map { it.text })
        assertEquals(listOf("a-first"), h.b.pollMessages(RB_CID).map { it.text })
        repeat(10) { i ->
            assertTrue(h.a.sendMessage(RB_CID, "a$i"))
            assertEquals(listOf("a$i"), h.b.pollMessages(RB_CID).map { it.text })
            assertTrue(h.b.sendMessage(RB_CID, "b$i"))
            assertEquals(listOf("b$i"), h.a.pollMessages(RB_CID).map { it.text })
        }
        assertTrue(h.relay.sawRatchetWire, "an id-order pairing still engages the ratchet")
        assertFalse(h.a.ratchetRefused(RB_CID))
        assertFalse(h.b.ratchetRefused(RB_CID))
    }

    @Test
    fun aLyingPeerThatAdvertisesRv2ButActsOnTheIdRule_collides_andThatIsStepBsJob() {
        if (!rbCryptoUp()) return
        // Honest same-version devices can NEVER end up one-sided: each side must scan
        // the other's code to get the peer's pairing contribution at all, so the
        // peer-version observation always arrives with the order bit. One-sided
        // evidence therefore means a MODIFIED peer that advertises `rv:2` and then
        // acts on the id rule — which §2 says no role rule can prevent (the role is a
        // private choice on each device).
        //
        // Pinned here so the residual is stated by a test rather than only by prose:
        // the outcome is a role COLLISION, which the collision detector detects and refuses; it is not
        // a silent downgrade, and role binding never claimed to stop it.
        val aIn = "M".repeat(32)
        val bIn = "Z".repeat(32)
        val f = fixtureWhereRulesDisagree(aIn, bIn)
        val h = RbPair(aIn, bIn, f.aHalf, f.bHalf, f.sharedSecret, aRoleRuleV2 = true, bRoleRuleV2 = false)

        h.armSendRatchetOnBothSides()
        assertTrue(h.a.sendMessage(RB_CID, "a-first"))
        assertTrue(h.b.sendMessage(RB_CID, "b-first"))

        assertEquals(f.aIsBobUnderV2, freshRoleIsBob(h.aVault), "A has evidence, so A uses v2")
        assertEquals(ratchetSelfIsBob(bIn, aIn), freshRoleIsBob(h.bVault), "B has none, so B uses the id rule")
        assertEquals(
            freshRoleIsBob(h.aVault), freshRoleIsBob(h.bVault),
            "a lying peer collides — a documented limitation, caught by dr-refused",
        )
    }

    @Test
    fun aMixedVersionPairingWhoseOldPeerLaterUpgrades_staysOnTheIdRule() {
        if (!rbCryptoUp()) return
        // The honest sequence role binding could have broken: A is a NEW build, B is OLD, so
        // they pair on the id rule (correctly — B has no order bit and never will,
        // because its pairing predates the change). B then UPDATES and its next inbox
        // announce carries `rv:2`. If that could flip A to the v2 rule, A's next
        // re-init would pick a role B can never agree with — a collision produced by
        // nothing but an app update.
        //
        // The `"0"` latch is what stops it: A's pairing already made a COMPLETE
        // observation of B's build, and a later announce may only fill an ABSENT one.
        val aIn = "M".repeat(32)
        val bIn = "Z".repeat(32)
        val f = fixtureWhereRulesDisagree(aIn, bIn)
        val h = RbPair(aIn, bIn, f.aHalf, f.bHalf, f.sharedSecret, aRoleRuleV2 = false, bRoleRuleV2 = false)
        assertEquals("0", h.aVault.getMeta(MessageManager.drPeerRoleRuleV2Key(RB_CID)))

        // B "updates" and re-announces; the announce now carries the marker.
        assertTrue(h.b.sendInboxAnnounce(RB_CID, "N".repeat(32), RB_WCAP_B, "n".repeat(32), RB_WCAP_B))
        h.a.pollControlMessages(RB_CID)
        assertNotNull(h.aVault.getInboxId("N".repeat(32)), "precondition: the announce really was applied")
        assertEquals(
            "0", h.aVault.getMeta(MessageManager.drPeerRoleRuleV2Key(RB_CID)),
            "a post-pairing announce must NOT upgrade a pairing observed as v1",
        )

        h.aVault.putMeta(MessageManager.drRxSeenKey(RB_CID), "1")
        h.aVault.putMeta(MessageManager.drOnKey(RB_CID), "1")
        assertTrue(h.a.sendMessage(RB_CID, "a0"))
        assertEquals(
            ratchetSelfIsBob(aIn, "N".repeat(32)), freshRoleIsBob(h.aVault),
            "…so the role still comes from the inbox ids, which is what the old peer uses",
        )
    }

    // -- §6 item 5 "roleIsStableAcrossAnnounceAndReinit" --------------------

    @Test
    fun roleIsStableAcrossAnnounceAndReinit() {
        if (!rbCryptoUp()) return
        // The honest-path hazard §1 names: the outbound row is rewritten by an inbox
        // announce at any time, and `loadOrInit` recomputes the role whenever no state
        // is persisted — which is exactly what `onCorruptReinit` produces. Under the
        // id rule those two together FLIP one side's role on a perfectly honest
        // pairing. The control half of this test proves that is real; the v2 half
        // proves it is fixed.
        val aIn = "M".repeat(32)
        val bIn = "Z".repeat(32)
        val newBIn = "A".repeat(32)      // sorts BELOW aIn ⇒ flips A's id-order role
        val newBInCtl = "n".repeat(32)
        assertTrue(ratchetSelfIsBob(aIn, bIn), "before the announce the id rule makes A Bob")
        assertFalse(ratchetSelfIsBob(aIn, newBIn), "after it, the id rule would make A Alice")
        val f = fixtureWhereRulesDisagree(aIn, bIn)

        fun run(rv2: Boolean): Pair<Boolean, Boolean> {
            val h = RbPair(aIn, bIn, f.aHalf, f.bHalf, f.sharedSecret, aRoleRuleV2 = rv2, bRoleRuleV2 = rv2)
            // A alone is send-ratchet; B stays pre-ratchet so its announce rides the
            // static control envelope, which is what a real re-announce/rotation does
            // before the peer's ratchet is live.
            h.aVault.putMeta(MessageManager.drRxSeenKey(RB_CID), "1")
            h.aVault.putMeta(MessageManager.drOnKey(RB_CID), "1")
            assertTrue(h.a.sendMessage(RB_CID, "a-first"))
            val before = freshRoleIsBob(h.aVault)

            // B announces a DIFFERENT inbound inbox, through the real control path.
            assertTrue(h.b.sendInboxAnnounce(RB_CID, newBIn, RB_WCAP_B, newBInCtl, RB_WCAP_B))
            h.a.pollControlMessages(RB_CID)
            assertEquals(
                newBIn, h.aVault.getInboxIdForContact(RB_CID, "outbound")?.inboxId,
                "precondition: the announce really did rewrite A's outbound routing",
            )

            // Local disk anomaly ⇒ onCorruptReinit ⇒ a FRESH init on the next op.
            h.aVault.putMeta("dr/$RB_CID/${MessageManager.RATCHET_TEXT_CHANNEL}", encodeBase64(byteArrayOf(9, 9, 9)))
            h.aVault.putMeta(MessageManager.drOnKey(RB_CID), "1")   // re-arm: the reinit clears it
            assertTrue(h.a.sendMessage(RB_CID, "a-second"))
            return before to freshRoleIsBob(h.aVault)
        }

        val (legacyBefore, legacyAfter) = run(rv2 = false)
        assertNotEquals(
            legacyBefore, legacyAfter,
            "control: under the id-order rule an announce + re-init really does flip the role " +
                "(if this ever stops being true the v2 assertion below proves nothing)",
        )

        val (v2Before, v2After) = run(rv2 = true)
        assertEquals(
            v2Before, v2After,
            "P1-1 A: with the v2 rule in force the role must survive an announce AND a re-init",
        )
        assertEquals(f.aIsBobUnderV2, v2After, "…and it must still be the secret-derived role")
    }

    @Test
    fun anAnnounceCarryingRv2_recordsThePeerEvidence_andAnOldAnnounceDoesNot() {
        if (!rbCryptoUp()) return
        // Round-trip pin of the second wire carrier: `sendInboxAnnounce` emits the
        // optional marker and `applyInboxAnnounce` records it. The negative half uses
        // a pre-step-A body (no `rv`), which must still apply normally and must leave
        // the pairing on the id rule.
        val aIn = "M".repeat(32)
        val bIn = "Z".repeat(32)
        val f = fixtureWhereRulesDisagree(aIn, bIn)

        // Positive: a real announce from a v2 peer.
        val h = RbPair(aIn, bIn, null, null, f.sharedSecret, aRoleRuleV2 = false, bRoleRuleV2 = false)
        assertNull(h.aVault.getMeta(MessageManager.drPeerRoleRuleV2Key(RB_CID)), "precondition: no evidence yet")
        assertTrue(h.b.sendInboxAnnounce(RB_CID, "N".repeat(32), RB_WCAP_B, "n".repeat(32), RB_WCAP_B))
        h.a.pollControlMessages(RB_CID)
        assertEquals(
            "1", h.aVault.getMeta(MessageManager.drPeerRoleRuleV2Key(RB_CID)),
            "an announce from a v2 peer must record the evidence",
        )
        // …but with no order bit (this pairing predates role binding) the rule still cannot
        // engage: BOTH inputs are required, so a half-upgraded vault keeps the id rule.
        assertNull(h.aVault.getMeta(MessageManager.drRoleOrderKey(RB_CID)))
        h.aVault.putMeta(MessageManager.drRxSeenKey(RB_CID), "1")
        h.aVault.putMeta(MessageManager.drOnKey(RB_CID), "1")
        assertTrue(h.a.sendMessage(RB_CID, "a0"))
        assertEquals(
            ratchetSelfIsBob(aIn, "N".repeat(32)), freshRoleIsBob(h.aVault),
            "evidence without an order bit must leave the id-order rule in force",
        )

        // Negative: a pre-step-A announce body carries no `rv`.
        val h2 = RbPair(aIn, bIn, f.aHalf, f.bHalf, f.sharedSecret, aRoleRuleV2 = false, bRoleRuleV2 = false)
        h2.aVault.putMeta(MessageManager.drRxSeenKey(RB_CID), "1")
        assertTrue(
            h2.b.sendDirectControl(
                RB_CID, MessageManager.CONTROL_KIND_INBOX,
                """{"ib":"${"N".repeat(32)}","wc":"$RB_WCAP_B","cib":"${"n".repeat(32)}","cwc":"$RB_WCAP_B"}""",
            ),
            "the pre-step-A announce body must still be sendable",
        )
        h2.a.pollControlMessages(RB_CID)
        // Positive evidence that the announce landed: the row it writes exists, bound
        // to this contact in the outbound direction.
        val learned = assertNotNull(
            h2.aVault.getInboxId("N".repeat(32)),
            "a pre-step-A announce must still apply",
        )
        assertEquals("outbound", learned.direction)
        assertEquals(RB_CID, learned.contactId)
        assertEquals(
            "0", h2.aVault.getMeta(MessageManager.drPeerRoleRuleV2Key(RB_CID)),
            "…and must leave the peer observed as a v1 build",
        )
    }

    // -- the resolver's fail direction --------------------------------------

    @Test
    fun roleOrderBit_isComplementary_andNullOnIdenticalInputs() {
        if (!rbCryptoUp()) return
        val x = sha256(byteArrayOf(1))
        val y = sha256(byteArrayOf(2))
        val xy = assertNotNull(ratchetRoleOrderBit(x, y))
        val yx = assertNotNull(ratchetRoleOrderBit(y, x))
        assertNotEquals(xy, yx, "the two devices must see opposite order bits")
        // Identical inputs have NO ordering. Answering `false` on both sides would
        // hand them the same role — manufacturing the very collision this removes —
        // so the helper must refuse, and the caller then persists nothing.
        assertNull(ratchetRoleOrderBit(x, x.copyOf()))
    }

    @Test
    fun roleRuleV2_producesComplementaryRolesForEveryOrderBit() {
        if (!rbCryptoUp()) return
        // The rule itself, exhaustively over the only free variable: whatever the
        // parity bit turns out to be for a given secret, the two sides differ.
        repeat(32) { i ->
            val secret = sha256(byteArrayOf(7, i.toByte()))
            assertNotEquals(
                ratchetSelfIsBobFromRoleOrder(secret, true),
                ratchetSelfIsBobFromRoleOrder(secret, false),
                "secret #$i produced the same role for both order bits",
            )
        }
    }

    @Test
    fun roleInputsAreNotWritten_whenTheHalvesAreIdenticalOrTheHalvesAreAbsent() {
        if (!rbCryptoUp()) return
        // Both "can't happen" inputs write NOTHING, which lands the pairing on the id
        // rule — the agreeing answer — rather than on a silently-colliding v2 role.
        val v = InMemoryVault()
        val same = sha256(byteArrayOf(3))
        MessageManager.recordRatchetRoleInputs(v, RB_CID, same, same.copyOf(), peerRunsRoleRuleV2 = true)
        assertNull(v.getMeta(MessageManager.drRoleOrderKey(RB_CID)), "identical halves have no ordering")
        assertNull(v.getMeta(MessageManager.drPeerRoleRuleV2Key(RB_CID)), "…so nothing at all is recorded")

        val v2 = InMemoryVault()
        PairingVault.savePairedContact(
            vault = v2, contactId = RB_CID, sharedSecret = ByteArray(32) { 5 },
            peerInboxId = "Z".repeat(32), peerWriteCap = RB_WCAP_B,
            peerCtlInboxId = "z".repeat(32), peerCtlWriteCap = RB_WCAP_B,
            myInboxId = "M".repeat(32), myReadCap = RB_RCAP,
            myCtlInboxId = "m".repeat(32), myCtlReadCap = RB_RCAP,
            alias = "peer",
        )
        assertNull(v2.getMeta(MessageManager.drRoleOrderKey(RB_CID)), "no halves ⇒ no role inputs")
        assertNull(v2.getMeta(MessageManager.drPeerRoleRuleV2Key(RB_CID)))
        assertEquals("1", v2.getMeta(MessageManager.drIntentKey(RB_CID)), "…and the pairing is otherwise untouched")
    }

    @Test
    fun legacyPairingWithNoMarkers_isNeverReRoled_andNeverFails() {
        if (!rbCryptoUp()) return
        // Brick-safety / migration: a vault provisioned before role binding carries neither
        // key. Nothing may be re-derived, nothing may be refused, and the ratchet blob
        // it already holds is its own authority.
        val aIn = "M".repeat(32)
        val bIn = "Z".repeat(32)
        val h = RbPair(aIn, bIn, null, null, generateSecureRandom(32), aRoleRuleV2 = false, bRoleRuleV2 = false)
        h.armSendRatchetOnBothSides()
        assertTrue(h.a.sendMessage(RB_CID, "a0"))
        val bornAs = freshRoleIsBob(h.aVault)
        assertEquals(ratchetSelfIsBob(aIn, bIn), bornAs)

        // Planting the peer-evidence key alone (a half-written vault, a partial
        // import) must not move an EXISTING ratchet: the blob is the role.
        h.aVault.putMeta(MessageManager.drPeerRoleRuleV2Key(RB_CID), "1")
        h.aVault.putMeta(MessageManager.drRoleOrderKey(RB_CID), if (bornAs) "0" else "1")
        assertTrue(h.a.sendMessage(RB_CID, "a1"))
        assertEquals(bornAs, freshRoleIsBob(h.aVault), "an established ratchet must never be re-roled")
    }

    // -- §3A(c) the REFERRAL path: no symmetric halves, so the pubkeys ------

    @Test
    fun rv2Referral_rolesAreComplementary() {
        if (!rbCryptoUp() || !rbX25519Up()) return
        val introId = "i-role-1"
        val cid = ReferralManager.referredContactIdFor(introId)
        val bobKp = x25519GenerateKeypair()
        val carolKp = x25519GenerateKeypair()

        // What the two devices will end up holding, computed here so the expected
        // role is independent of the code under test's own bookkeeping.
        val shared = hkdfSha256(
            x25519EcdhChecked(bobKp.privateKey, carolKp.publicKey),
            ByteArray(0), "run-referral-v1|$introId".encodeToByteArray(), 32,
        )
        val bobOrder = assertNotNull(ratchetRoleOrderBit(bobKp.publicKey, carolKp.publicKey))
        val bobIsBobUnderV2 = ratchetSelfIsBobFromRoleOrder(shared, bobOrder)

        // Mint ids that make the ID rule say the OPPOSITE, so "complementary" cannot
        // be satisfied by the old rule quietly still being in charge.
        val lowIb = "aa" + "1".repeat(30); val lowCib = "ab" + "1".repeat(30)
        val highIb = "zz" + "9".repeat(30); val highCib = "zy" + "9".repeat(30)
        val bobIb = if (bobIsBobUnderV2) highIb else lowIb
        val bobCib = if (bobIsBobUnderV2) highCib else lowCib
        val carolIb = if (bobIsBobUnderV2) lowIb else highIb
        val carolCib = if (bobIsBobUnderV2) lowCib else highCib
        assertNotEquals(
            bobIsBobUnderV2, ratchetSelfIsBob(bobIb, carolIb),
            "fixture precondition: the two rules must disagree for Bob",
        )

        fun mintedFor(ib: String, cib: String, r: String, w: String) = MintedInboxPair(
            MintedInbox(ib, r, w, Long.MAX_VALUE),
            MintedInbox(cib, r, w, Long.MAX_VALUE),
        )
        val bobMinted = mintedFor(bobIb, bobCib, "R".repeat(43), "W".repeat(43))
        val carolMinted = mintedFor(carolIb, carolCib, "S".repeat(43), "X".repeat(43))

        val relay = RbRelay()
        val bobVault = InMemoryVault()
        val carolVault = InMemoryVault()
        for (v in listOf(bobVault, carolVault)) {
            v.insertContact(ContactRecord("alice", generateSecureRandom(32), 0, "Alice", 0L))
        }
        val bobRm = ReferralManager(bobVault) { null }
        val carolRm = ReferralManager(carolVault) { null }
        val offerJson = """{"ii":${jsonEscapeString(introId)},"pa":${jsonEscapeString("Running Fox")}}"""
        for (rm in listOf(bobRm, carolRm)) {
            rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_OFFER, offerJson)
        }
        bobRm.registerAccepted(introId, bobRm.pendingOffers().single(), bobKp, bobMinted)
        carolRm.registerAccepted(introId, carolRm.pendingOffers().single(), carolKp, carolMinted)

        // The bodies are built by the PRODUCTION builder, so the optional `rv:2` field
        // on the referral carrier is pinned end to end here (it has no other
        // round-trip: the QR is pinned through PairingPayload.parse and the announce
        // through applyInboxAnnounce).
        val bobAccept = bobRm.acceptBody(introId, bobKp.publicKey, bobMinted)
        val carolAccept = carolRm.acceptBody(introId, carolKp.publicKey, carolMinted)
        assertTrue(carolAccept.contains("\"rv\":\"2\""), "the referral accept must advertise role rule v2")

        // The introducer relays each accept to the other introducee, verbatim.
        bobRm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_ACCEPT, carolAccept)
        carolRm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_ACCEPT, bobAccept)

        assertNotNull(bobVault.getContact(cid), "Bob must have finalized the referred contact")
        assertNotNull(carolVault.getContact(cid), "…and so must Carol")
        assertEquals("1", bobVault.getMeta(MessageManager.drPeerRoleRuleV2Key(cid)))
        assertEquals("1", carolVault.getMeta(MessageManager.drPeerRoleRuleV2Key(cid)))
        assertNotEquals(
            assertNotNull(bobVault.getMeta(MessageManager.drRoleOrderKey(cid))),
            assertNotNull(carolVault.getMeta(MessageManager.drRoleOrderKey(cid))),
            "the two devices must derive OPPOSITE order bits from the two pubkeys",
        )

        // Behavioural: exactly one Bob, and it is the pubkey-derived one.
        val bobMgr = MessageManager(bobVault, "http://relay.test", relay)
        val carolMgr = MessageManager(carolVault, "http://relay.test", relay)
        for (v in listOf(bobVault, carolVault)) {
            v.putMeta(MessageManager.drRxSeenKey(cid), "1")
            v.putMeta(MessageManager.drOnKey(cid), "1")
        }
        assertTrue(bobMgr.sendMessage(cid, "bob-first"))
        assertTrue(carolMgr.sendMessage(cid, "carol-first"))
        val bobIsBob = freshRoleIsBob(bobVault, cid)
        val carolIsBob = freshRoleIsBob(carolVault, cid)
        assertNotEquals(bobIsBob, carolIsBob, "exactly one referred device must be Bob")
        assertEquals(bobIsBobUnderV2, bobIsBob, "the role must follow the two X25519 public keys")
        assertNotEquals(ratchetSelfIsBob(bobIb, carolIb), bobIsBob, "…and NOT the inbox ids")

        // …and the referred channel works both ways.
        assertEquals(listOf("carol-first"), bobMgr.pollMessages(cid).map { it.text })
        assertEquals(listOf("bob-first"), carolMgr.pollMessages(cid).map { it.text })
        repeat(20) { i ->
            assertTrue(bobMgr.sendMessage(cid, "b$i"))
            assertEquals(listOf("b$i"), carolMgr.pollMessages(cid).map { it.text })
            assertTrue(carolMgr.sendMessage(cid, "c$i"))
            assertEquals(listOf("c$i"), bobMgr.pollMessages(cid).map { it.text })
        }
        assertTrue(relay.sawRatchetWire, "the referred pairing must really engage the ratchet")
        assertFalse(bobMgr.ratchetRefused(cid))
        assertFalse(carolMgr.ratchetRefused(cid))
    }

    @Test
    fun referralAcceptWithoutRv_keepsTheIdOrderRule() {
        if (!rbCryptoUp() || !rbX25519Up()) return
        // A pre-step-A peer's accept carries no `rv`. The order bit is still recorded
        // (it is harmless and costs nothing), but WITHOUT the peer evidence the v2
        // rule must not engage — otherwise this device alone would move to the secret
        // order while the peer stayed on the ids, i.e. a manufactured collision.
        val introId = "i-role-2"
        val cid = ReferralManager.referredContactIdFor(introId)
        val bobKp = x25519GenerateKeypair()
        val carolKp = x25519GenerateKeypair()
        val bobIb = "aa" + "2".repeat(30); val bobCib = "ab" + "2".repeat(30)
        val carolIb = "zz" + "8".repeat(30); val carolCib = "zy" + "8".repeat(30)

        val vault = InMemoryVault()
        vault.insertContact(ContactRecord("alice", generateSecureRandom(32), 0, "Alice", 0L))
        val rm = ReferralManager(vault) { null }
        rm.handleControl(
            "alice", MessageManager.CONTROL_KIND_REFERRAL_OFFER,
            """{"ii":${jsonEscapeString(introId)},"pa":${jsonEscapeString("Running Fox")}}""",
        )
        rm.registerAccepted(
            introId, rm.pendingOffers().single(), bobKp,
            MintedInboxPair(
                MintedInbox(bobIb, "R".repeat(43), "W".repeat(43), Long.MAX_VALUE),
                MintedInbox(bobCib, "R".repeat(43), "W".repeat(43), Long.MAX_VALUE),
            ),
        )
        // A pre-step-A accept body: identical to today's minus the `rv` field.
        val legacyAccept = """{"ii":${jsonEscapeString(introId)},""" +
            """"pk":${jsonEscapeString(encodeBase64(carolKp.publicKey))},""" +
            """"ib":${jsonEscapeString(carolIb)},"wc":${jsonEscapeString("X".repeat(43))},""" +
            """"cib":${jsonEscapeString(carolCib)},"cwc":${jsonEscapeString("X".repeat(43))}}"""
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_ACCEPT, legacyAccept)

        assertNotNull(vault.getContact(cid), "a pre-step-A accept must still finalize")
        assertNotNull(vault.getMeta(MessageManager.drRoleOrderKey(cid)), "the order bit is recorded regardless")
        assertEquals(
            "0", vault.getMeta(MessageManager.drPeerRoleRuleV2Key(cid)),
            "…but the peer is latched as a v1 build, so the id-order rule stays in force",
        )

        vault.putMeta(MessageManager.drRxSeenKey(cid), "1")
        vault.putMeta(MessageManager.drOnKey(cid), "1")
        val mgr = MessageManager(vault, "http://relay.test", RbRelay())
        assertTrue(mgr.sendMessage(cid, "hello"))
        assertEquals(
            ratchetSelfIsBob(bobIb, carolIb), freshRoleIsBob(vault, cid),
            "without the peer's rv:2 the referral role must come from the inbox ids",
        )
    }

    @Test
    fun roleResolution_failsTowardTheIdRule_onAnUnreadableVault() {
        if (!rbCryptoUp()) return
        // A throwing `_meta` read must not throw out of the send path and must not
        // pick a role out of thin air — it must land on the id rule, which is what the
        // peer is using whenever we cannot prove otherwise.
        val aIn = "M".repeat(32)
        val bIn = "Z".repeat(32)
        val f = fixtureWhereRulesDisagree(aIn, bIn)
        val h = RbPair(aIn, bIn, f.aHalf, f.bHalf, f.sharedSecret, aRoleRuleV2 = true, bRoleRuleV2 = true)

        // A vault that answers every role-marker read with a throw, and everything
        // else normally — the transient-failure shape, not a corrupt vault.
        val flaky = object : InMemoryVault() {
            override fun getMeta(key: String): String? {
                if (key.startsWith("dr-roleord/") || key.startsWith("dr-rolerv2/")) {
                    throw IllegalStateException("vault unavailable")
                }
                return super.getMeta(key)
            }
        }
        for ((k, v) in h.aVault.meta) flaky.putMeta(k, v)
        h.aVault.getContact(RB_CID)?.let { flaky.insertContact(it) }
        for (r in h.aVault.inboxes) flaky.insertInboxId(r)
        flaky.putMeta(MessageManager.drRxSeenKey(RB_CID), "1")
        flaky.putMeta(MessageManager.drOnKey(RB_CID), "1")

        val mgr = MessageManager(flaky, "http://relay.test", RbRelay())
        assertTrue(mgr.sendMessage(RB_CID, "a0"), "an unreadable role marker must never fail a send")
        assertEquals(
            ratchetSelfIsBob(aIn, bIn), freshRoleIsBob(flaky),
            "an unreadable role marker must fall back to the id-order rule",
        )
    }
}
