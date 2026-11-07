package com.vg.run

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// DoubleRatchet correctness + the forward-secrecy property it exists to provide.
// Pure JVM/common test — no device, no relay, no vault.
// ---------------------------------------------------------------------------
class DoubleRatchetTest {

    private fun pair(): Pair<DoubleRatchet, DoubleRatchet> {
        val secret = generateSecureRandom(32)
        // Roles are assigned deterministically by the wiring layer; here we pick.
        return DoubleRatchet.initAsAlice(secret) to DoubleRatchet.initAsBob(secret)
    }

    private fun msg(s: String) = s.encodeToByteArray()
    private fun str(b: ByteArray) = b.decodeToString()

    @Test
    fun aliceToBob_inOrder() {
        val (alice, bob) = pair()
        for (i in 0 until 5) {
            val m = alice.encrypt(msg("hello $i"))
            assertEquals("hello $i", str(bob.decrypt(m.header, m.ciphertext)))
        }
    }

    @Test
    fun bidirectional_withDhRatchetSteps() {
        val (alice, bob) = pair()
        // Alice opens; Bob can only send after receiving (his sending chain is
        // established by the DH ratchet on first receive).
        val a0 = alice.encrypt(msg("a0"))
        assertEquals("a0", str(bob.decrypt(a0.header, a0.ciphertext)))

        val b0 = bob.encrypt(msg("b0"))
        assertEquals("b0", str(alice.decrypt(b0.header, b0.ciphertext)))

        // Several back-and-forth rounds, each reply triggering a DH ratchet step.
        repeat(4) { i ->
            val a = alice.encrypt(msg("a-r$i"))
            assertEquals("a-r$i", str(bob.decrypt(a.header, a.ciphertext)))
            val b = bob.encrypt(msg("b-r$i"))
            assertEquals("b-r$i", str(alice.decrypt(b.header, b.ciphertext)))
        }
    }

    @Test
    fun outOfOrderDelivery_withinAChain() {
        val (alice, bob) = pair()
        val m0 = alice.encrypt(msg("m0"))
        val m1 = alice.encrypt(msg("m1"))
        val m2 = alice.encrypt(msg("m2"))
        // Deliver 2, 0, 1 — skipped-key cache must recover the order.
        assertEquals("m2", str(bob.decrypt(m2.header, m2.ciphertext)))
        assertEquals("m0", str(bob.decrypt(m0.header, m0.ciphertext)))
        assertEquals("m1", str(bob.decrypt(m1.header, m1.ciphertext)))
    }

    @Test
    fun outOfOrderAcrossADhRatchetStep() {
        val (alice, bob) = pair()
        // Alice sends two, Bob receives one then replies (DH step), then the
        // delayed first-chain message arrives after the ratchet advanced.
        val a0 = alice.encrypt(msg("a0"))
        val a1 = alice.encrypt(msg("a1"))
        assertEquals("a0", str(bob.decrypt(a0.header, a0.ciphertext)))
        val b0 = bob.encrypt(msg("b0"))
        assertEquals("b0", str(alice.decrypt(b0.header, b0.ciphertext)))
        // a1 (from the previous chain) still decrypts via the PN-skip path.
        assertEquals("a1", str(bob.decrypt(a1.header, a1.ciphertext)))
    }

    @Test
    fun tamperedCiphertextIsRejected() {
        val (alice, bob) = pair()
        val m = alice.encrypt(msg("secret"))
        val bad = m.ciphertext.copyOf()
        bad[bad.size - 1] = (bad[bad.size - 1] + 1).toByte()   // flip a tag byte
        assertFailsWith<RatchetException> { bob.decrypt(m.header, bad) }
    }

    @Test
    fun headerIsBoundAsAad_swappedIndexFails() {
        val (alice, bob) = pair()
        val m0 = alice.encrypt(msg("m0"))
        // Forge a header with a different n: AAD mismatch must make AEAD fail.
        val forged = RatchetHeader(m0.header.dhPub, m0.header.pn, m0.header.n + 7)
        assertFailsWith<RatchetException> { bob.decrypt(forged, m0.ciphertext) }
    }

    @Test
    fun skipBeyondMaxSkipIsRejected() {
        val (alice, bob) = pair()
        // First real message establishes Bob's receiving chain.
        val first = alice.encrypt(msg("first"))
        assertEquals("first", str(bob.decrypt(first.header, first.ciphertext)))
        // Forge a header claiming an index far beyond MAX_SKIP in the same chain.
        val farAhead = RatchetHeader(first.header.dhPub, first.header.pn, DoubleRatchet.MAX_SKIP + 100)
        assertFailsWith<RatchetException> { bob.decrypt(farAhead, first.ciphertext) }
    }

    @Test
    fun headerEncodeDecodeRoundTrips() {
        val pub = generateSecureRandom(32)
        val h = RatchetHeader(pub, pn = 0x01020304, n = 0x0A0B0C0D)
        val back = RatchetHeader.decode(h.encode())
        assertContentEquals(pub, back.dhPub)
        assertEquals(0x01020304, back.pn)
        assertEquals(0x0A0B0C0D, back.n)
    }

    // -- The property this whole file exists for -----------------------------

    @Test
    fun forwardSecrecy_consumedMessageCannotBeDecryptedFromAdvancedState() {
        val (alice, bob) = pair()
        val m0 = alice.encrypt(msg("m0"))
        val m1 = alice.encrypt(msg("m1"))
        val m2 = alice.encrypt(msg("m2"))
        // Bob consumes m0, m1, m2 in order — each message key is derived once and
        // wiped, and the receiving chain advances irreversibly.
        assertEquals("m0", str(bob.decrypt(m0.header, m0.ciphertext)))
        assertEquals("m1", str(bob.decrypt(m1.header, m1.ciphertext)))
        assertEquals("m2", str(bob.decrypt(m2.header, m2.ciphertext)))

        // A relay that re-serves m1 now cannot be decrypted: its key was wiped,
        // the chain moved on, and it was consumed in-order (no skipped entry).
        // This is forward secrecy at the receiving end — Bob's CURRENT state
        // holds no key capable of reopening an already-consumed message.
        assertFailsWith<RatchetException> { bob.decrypt(m1.header, m1.ciphertext) }
    }

    @Test
    fun postCompromiseSecurity_dhStepReseedsRootWithFreshEntropy() {
        // Two independent pairings from the SAME secret must diverge once a DH
        // ratchet injects fresh randomness — i.e. the post-bootstrap key stream
        // is not a deterministic function of `sharedSecret` alone (the property
        // that makes seizure of the secret insufficient to derive future keys).
        val secret = generateSecureRandom(32)
        val a1 = DoubleRatchet.initAsAlice(secret); val b1 = DoubleRatchet.initAsBob(secret)
        val a2 = DoubleRatchet.initAsAlice(secret); val b2 = DoubleRatchet.initAsBob(secret)

        // Drive each pairing one full round so both have taken a DH step.
        fun round(a: DoubleRatchet, b: DoubleRatchet): ByteArray {
            val am = a.encrypt(msg("ping")); b.decrypt(am.header, am.ciphertext)
            val bm = b.encrypt(msg("pong")); a.decrypt(bm.header, bm.ciphertext)
            // Bob's reply header carries his FRESH ratchet pubkey — random per run.
            return bm.header.dhPub
        }
        val pub1 = round(a1, b1)
        val pub2 = round(a2, b2)
        assertTrue(!pub1.contentEquals(pub2), "fresh DH keys must differ across runs from the same secret")
    }

    @Test
    fun serializeDeserialize_midConversation_continues() {
        val (alice, bob) = pair()
        // Exchange a few rounds so Bob has both chains + a DH step behind him.
        val a0 = alice.encrypt(msg("a0")); bob.decrypt(a0.header, a0.ciphertext)
        val b0 = bob.encrypt(msg("b0")); alice.decrypt(b0.header, b0.ciphertext)
        val a1 = alice.encrypt(msg("a1")); bob.decrypt(a1.header, a1.ciphertext)

        // Persist Bob mid-stream, then restore into a fresh instance.
        val restoredBob = DoubleRatchet.deserialize(bob.serialize())

        // The restored Bob must decrypt the next message AND be able to reply.
        val a2 = alice.encrypt(msg("a2"))
        assertEquals("a2", str(restoredBob.decrypt(a2.header, a2.ciphertext)))
        val b1 = restoredBob.encrypt(msg("b1"))
        assertEquals("b1", str(alice.decrypt(b1.header, b1.ciphertext)))
    }

    @Test
    fun serializeDeserialize_preservesSkippedKeys() {
        val (alice, bob) = pair()
        val m0 = alice.encrypt(msg("m0"))
        val m1 = alice.encrypt(msg("m1"))
        // Bob receives m1 first → m0's key is cached as skipped.
        assertEquals("m1", str(bob.decrypt(m1.header, m1.ciphertext)))
        // Persist/restore across the gap, then the delayed m0 must still open.
        val restored = DoubleRatchet.deserialize(bob.serialize())
        assertEquals("m0", str(restored.decrypt(m0.header, m0.ciphertext)))
    }

    @Test
    fun deserialize_rejectsCorruptBlob() {
        assertFailsWith<IllegalArgumentException> { DoubleRatchet.deserialize(byteArrayOf(9, 0)) }  // bad version
        assertFailsWith<IllegalArgumentException> { DoubleRatchet.deserialize(ByteArray(0)) }         // empty
        // a TRUNCATED blob must fail as a clean
        // IllegalArgumentException (the bounds guard), NOT an IndexOutOfBounds
        // crash (which SIGABRTs iOS); trailing garbage must be rejected too.
        val valid = pair().second.serialize()
        assertFailsWith<IllegalArgumentException> {
            DoubleRatchet.deserialize(valid.copyOfRange(0, valid.size - 3))   // truncated
        }
        assertFailsWith<IllegalArgumentException> {
            DoubleRatchet.deserialize(valid + byteArrayOf(1, 2, 3))            // trailing bytes
        }
        // an UNKNOWN flag bit (only 0x1/0x2/0x4 defined) is rejected.
        assertFailsWith<IllegalArgumentException> {
            DoubleRatchet.deserialize(valid.copyOf().also { it[1] = (it[1].toInt() or 0x08).toByte() })
        }
        DoubleRatchet.deserialize(valid)   // the same valid blob still restores (no regression)
    }

    @Test
    fun bootstrap_isDeterministicAcrossInit() {
        // Both peers derive Bob's initial ratchet key from the shared secret, so
        // two Bob inits from the same secret agree — and Alice can talk to either.
        val secret = generateSecureRandom(32)
        val alice = DoubleRatchet.initAsAlice(secret)
        val bob = DoubleRatchet.initAsBob(secret)
        val m = alice.encrypt(msg("bootstrap-ok"))
        assertEquals("bootstrap-ok", str(bob.decrypt(m.header, m.ciphertext)))
    }

    @Test
    fun wireCodec_roundTripsAndDrivesADecrypt() {
        val (alice, bob) = pair()
        val wire = alice.encrypt(msg("over-the-wire")).encodeWire()
        // The blob is what the relay actually stores; the receiver splits it back.
        val rm = decodeRatchetWire(wire)
        assertEquals("over-the-wire", str(bob.decrypt(rm.header, rm.ciphertext)))
        assertFailsWith<IllegalArgumentException> { decodeRatchetWire(ByteArray(10)) }
    }

    @Test
    fun roleAssignment_isOppositeOnTheTwoDevices_exactlyOneBob() {
        // Device A minted inbox "aaa", writes to peer's "bbb"; device B is the mirror.
        val aIsBob = ratchetSelfIsBob(myInboundInboxId = "aaa", myOutboundInboxId = "bbb")
        val bIsBob = ratchetSelfIsBob(myInboundInboxId = "bbb", myOutboundInboxId = "aaa")
        assertTrue(aIsBob != bIsBob, "exactly one peer must be Bob")
        // And the role each device computes uses ONLY ids both sides know, so a
        // full handshake-free pairing actually works: wire Alice↔Bob by role.
        val secret = generateSecureRandom(32)
        val a = if (aIsBob) DoubleRatchet.initAsBob(secret) else DoubleRatchet.initAsAlice(secret)
        val b = if (bIsBob) DoubleRatchet.initAsBob(secret) else DoubleRatchet.initAsAlice(secret)
        val alice = if (aIsBob) b else a
        val bob = if (aIsBob) a else b
        val m = alice.encrypt(msg("role-ok"))
        assertEquals("role-ok", str(bob.decrypt(m.header, m.ciphertext)))
    }

    // -- Bootstrap-window gate for dr-rxlock arming --------------

    @Test
    fun hasRatchetedPastBootstrap_falseUntilSecondReceivingDhStep() {
        val (alice, bob) = pair()
        assertTrue(!bob.hasRatchetedPastBootstrap(), "fresh Bob is in the bootstrap window")
        val a0 = alice.encrypt(msg("a0"))
        bob.decrypt(a0.header, a0.ciphertext)                 // Bob's 1st receiving DH step
        assertTrue(!bob.hasRatchetedPastBootstrap(),
            "one DH step (the forgeable bootstrap) must NOT count as past-bootstrap")
        val b0 = bob.encrypt(msg("b0"))
        alice.decrypt(b0.header, b0.ciphertext)               // Alice ratchets onto Bob's fresh key
        val a1 = alice.encrypt(msg("a1"))
        bob.decrypt(a1.header, a1.ciphertext)                 // Bob's 2nd receiving DH step
        assertTrue(bob.hasRatchetedPastBootstrap(),
            "after a full round-trip Bob is past the bootstrap window")
    }

    @Test
    fun forgedBootstrapMessage_doesNotMarkVictimPastBootstrap() {
        // An attacker holding sharedSecret runs a SECOND independent initAsAlice and
        // injects a bootstrap blob. The victim (Bob) decrypts it (the bootstrap key
        // is sharedSecret-derived), but it must NOT arm the sticky lock — so a
        // transient forgery cannot permanently brick the channel.
        val secret = generateSecureRandom(32)
        val bob = DoubleRatchet.initAsBob(secret)
        val attacker = DoubleRatchet.initAsAlice(secret)      // forger with the stolen secret
        val forged = attacker.encrypt(msg("spoofed"))
        assertEquals("spoofed", str(bob.decrypt(forged.header, forged.ciphertext)))
        assertTrue(!bob.hasRatchetedPastBootstrap(),
            "a single forged bootstrap message must not mark the victim past-bootstrap")
    }

    @Test
    fun serialize_roundTripsDhRecvSteps() {
        val (alice, bob) = pair()
        val a0 = alice.encrypt(msg("a0")); bob.decrypt(a0.header, a0.ciphertext)
        val b0 = bob.encrypt(msg("b0")); alice.decrypt(b0.header, b0.ciphertext)
        val a1 = alice.encrypt(msg("a1")); bob.decrypt(a1.header, a1.ciphertext)
        assertTrue(bob.hasRatchetedPastBootstrap())
        val restored = DoubleRatchet.deserialize(bob.serialize())
        assertTrue(restored.hasRatchetedPastBootstrap(),
            "dhRecvSteps must survive serialize → deserialize")
    }

    @Test
    fun deserialize_v1Blob_defaultsToPastBootstrap() {
        val (_, bob) = pair()                                 // fresh Bob, dhRecvSteps = 0
        val v2 = bob.serialize()
        // Forge a pre-counter v1 blob: version byte → 1, drop the trailing 4-byte
        // dhRecvSteps int. A v1 blob predates the counter and must default to
        // past-bootstrap so an upgrade doesn't force existing ratchets to re-bootstrap.
        val v1 = v2.copyOf(v2.size - 4).also { it[0] = 1 }
        assertTrue(DoubleRatchet.deserialize(v1).hasRatchetedPastBootstrap())
    }

    // -- Skipped message keys must not live forever --------
    //
    // A skipped key is the ONE piece of state that reopens a message the chain has
    // already ratcheted past, and a hostile relay chooses which ones exist (withhold
    // #k, deliver #k+1). Before the age-out they were bounded only by capacity (1024) and sat
    // in the vault for the life of the pairing. Now: a persisted creation stamp
    // (SER_VERSION 3), a 24 h age-out evaluated on every load and every decrypt, a
    // flush of any chain two DH steps back, and a much smaller cap.

    private val T0 = 1_700_000_000_000L   // fixed "now" for the clock seam

    private fun readIntBE(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xFF) shl 24) or ((b[off + 1].toInt() and 0xFF) shl 16) or
            ((b[off + 2].toInt() and 0xFF) shl 8) or (b[off + 3].toInt() and 0xFF)

    private fun writeIntBE(b: ByteArray, off: Int, v: Int) {
        b[off] = (v ushr 24).toByte(); b[off + 1] = (v ushr 16).toByte()
        b[off + 2] = (v ushr 8).toByte(); b[off + 3] = v.toByte()
    }

    /** Byte offset of the skipped-key COUNT in a serialized ratchet. Layout:
     *  ver(1) flags(1) root(32) priv(32) pub(32) [remote(32)] [sendCk(32)] [recvCk(32)]
     *  sN(4) rN(4) pN(4) skCount(4) entries… dhRecvSteps(4). */
    private fun skippedCountOffset(blob: ByteArray): Int {
        val flags = blob[1].toInt() and 0xFF
        var o = 98
        if (flags and 0x1 != 0) o += 32
        if (flags and 0x2 != 0) o += 32
        if (flags and 0x4 != 0) o += 32
        return o + 12   // sendN, recvN, prevSendN
    }

    private fun skippedCount(blob: ByteArray): Int = readIntBE(blob, skippedCountOffset(blob))

    /**
     * Down-convert a v3 blob to the PREVIOUS on-disk format (v2): drop the 8-byte
     * per-entry creation stamp and set the version byte. Models a ratchet persisted by
     * the build that shipped before the age-out, which must still load.
     */
    private fun downgradeToV2(v3: ByteArray): ByteArray {
        var o = skippedCountOffset(v3)
        val count = readIntBE(v3, o); o += 4
        val headLen = o
        val out = ByteArray(headLen + count * 68 + 4)
        v3.copyInto(out, 0, 0, headLen)
        out[0] = 2
        var src = headLen
        var dst = headLen
        repeat(count) {
            v3.copyInto(out, dst, src, src + 68)   // pub(32) ‖ n(4) ‖ mk(32)
            src += 76                              // …skipping the 8-byte stamp
            dst += 68
        }
        v3.copyInto(out, dst, src, src + 4)        // dhRecvSteps
        return out
    }

    @Test
    fun skippedKey_agesOutOnLoad_butADelayedMessageInsideTheWindowStillDecrypts() {
        val secret = generateSecureRandom(32)
        val alice = DoubleRatchet.initAsAlice(secret)
        val bob = DoubleRatchet.initAsBob(secret, nowMs = { T0 })
        val m0 = alice.encrypt(msg("m0"))
        val m1 = alice.encrypt(msg("m1"))
        // Relay withholds m0 and delivers m1 → m0's key is cached, stamped at T0.
        assertEquals("m1", str(bob.decrypt(m1.header, m1.ciphertext)))
        val blob = bob.serialize()
        assertEquals(1, skippedCount(blob))
        assertEquals(3, blob[0].toInt(), "a fresh persist must be SER_VERSION 3")

        // Inside the window: a genuinely delayed message still opens (this is what the
        // cache is FOR — Tor reordering must not cost a message).
        val inWindow = DoubleRatchet.deserialize(blob, nowMs = { T0 + DoubleRatchet.SKIPPED_KEY_TTL_MS - 1 })
        assertEquals("m0", str(inWindow.decrypt(m0.header, m0.ciphertext)))

        // Past the window: the key is dropped (and zeroed) on load, so the blob the
        // relay archived is simply undecryptable from the seized vault.
        val expired = DoubleRatchet.deserialize(blob, nowMs = { T0 + DoubleRatchet.SKIPPED_KEY_TTL_MS })
        assertEquals(0, skippedCount(expired.serialize()), "an expired skipped key must not persist")
        assertFailsWith<RatchetException> { expired.decrypt(m0.header, m0.ciphertext) }
    }

    @Test
    fun skippedKeyExpiry_doesNotDisturbTheLiveConversation() {
        // The age-out must never be a brick: an expired cache costs one withheld
        // message, and the chain itself keeps working.
        val secret = generateSecureRandom(32)
        val alice = DoubleRatchet.initAsAlice(secret)
        val bob = DoubleRatchet.initAsBob(secret, nowMs = { T0 })
        alice.encrypt(msg("withheld"))
        val m1 = alice.encrypt(msg("m1"))
        assertEquals("m1", str(bob.decrypt(m1.header, m1.ciphertext)))

        val later = DoubleRatchet.deserialize(
            bob.serialize(), nowMs = { T0 + DoubleRatchet.SKIPPED_KEY_TTL_MS * 10 },
        )
        val m2 = alice.encrypt(msg("m2"))
        assertEquals("m2", str(later.decrypt(m2.header, m2.ciphertext)))
        val reply = later.encrypt(msg("reply"))
        assertEquals("reply", str(alice.decrypt(reply.header, reply.ciphertext)))
    }

    @Test
    fun dhRatchet_flushesSkippedKeysOfAChainTwoStepsBack_butKeepsTheJustRetiredOne() {
        val (alice, bob) = pair()
        // Chain 0: send two, deliver only the second → chain-0 index 0 stays cached.
        val c0m0 = alice.encrypt(msg("c0m0"))
        val c0m1 = alice.encrypt(msg("c0m1"))
        assertEquals("c0m1", str(bob.decrypt(c0m1.header, c0m1.ciphertext)))
        assertEquals(1, skippedCount(bob.serialize()))

        // ONE DH step: the chain being retired right now may still have messages in
        // flight (that is exactly what PN-skip is for), so its keys must SURVIVE.
        val b0 = bob.encrypt(msg("b0")); alice.decrypt(b0.header, b0.ciphertext)
        val c1m0 = alice.encrypt(msg("c1m0"))
        assertEquals("c1m0", str(bob.decrypt(c1m0.header, c1m0.ciphertext)))
        assertEquals(1, skippedCount(bob.serialize()), "one DH step must not flush the just-retired chain")
        assertEquals(
            "c0m0",
            str(DoubleRatchet.deserialize(bob.serialize()).decrypt(c0m0.header, c0m0.ciphertext)),
            "a delayed message from the just-retired chain must still open",
        )

        // SECOND DH step: chain 0 is now two steps back — the peer has ratcheted twice
        // since, so nothing can still arrive in it. Flushed unconditionally.
        val b1 = bob.encrypt(msg("b1")); alice.decrypt(b1.header, b1.ciphertext)
        val c2m0 = alice.encrypt(msg("c2m0"))
        assertEquals("c2m0", str(bob.decrypt(c2m0.header, c2m0.ciphertext)))
        assertEquals(0, skippedCount(bob.serialize()), "a chain two DH steps back must be flushed")
        assertFailsWith<RatchetException> { bob.decrypt(c0m0.header, c0m0.ciphertext) }
    }

    @Test
    fun skippedStore_capsAtMaxSkippedStore_evictingTheLowestIndicesFirst() {
        val (alice, bob) = pair()
        val sent = (0 until 200).map { alice.encrypt(msg("m$it")) }
        // Deliver only the last: 199 keys are skipped in one go (MAX_SKIP allows it)
        // but only MAX_SKIPPED_STORE may be RETAINED.
        assertEquals("m199", str(bob.decrypt(sent[199].header, sent[199].ciphertext)))
        assertEquals(DoubleRatchet.MAX_SKIPPED_STORE, skippedCount(bob.serialize()))
        assertTrue(DoubleRatchet.MAX_SKIPPED_STORE < DoubleRatchet.MAX_SKIP,
            "the at-rest bound must be tighter than the per-decrypt skip bound")
        // The newest skipped index still opens; the oldest was evicted (+ zeroed).
        assertEquals("m198", str(bob.decrypt(sent[198].header, sent[198].ciphertext)))
        assertFailsWith<RatchetException> { bob.decrypt(sent[0].header, sent[0].ciphertext) }
    }

    // -- backward compatibility: a ratchet persisted by the PREVIOUS build ---------

    @Test
    fun deserialize_previousSerVersions_readSkippedKeys_andStampThemAtLoad() {
        val (alice, bob) = pair()
        val m0 = alice.encrypt(msg("m0"))
        val m1 = alice.encrypt(msg("m1"))
        assertEquals("m1", str(bob.decrypt(m1.header, m1.ciphertext)))

        val v2 = downgradeToV2(bob.serialize())
        assertEquals(2, v2[0].toInt())
        assertEquals(1, skippedCount(v2))
        // v1 = v2 without the trailing dhRecvSteps int (the older format).
        val v1 = v2.copyOf(v2.size - 4).also { it[0] = 1 }

        // Both legacy formats still load AND still open the delayed message: an
        // existing vault must never lose its cache on upgrade.
        assertEquals("m0", str(DoubleRatchet.deserialize(v2, nowMs = { T0 }).decrypt(m0.header, m0.ciphertext)))
        assertEquals("m0", str(DoubleRatchet.deserialize(v1, nowMs = { T0 }).decrypt(m0.header, m0.ciphertext)))

        // Migrate-on-write: the next persist is v3 with the entry stamped at LOAD time,
        // so the window starts at the upgrade rather than being unbounded or instant.
        val migrated = DoubleRatchet.deserialize(v2, nowMs = { T0 }).serialize()
        assertEquals(3, migrated[0].toInt())
        assertEquals(1, skippedCount(migrated))
        assertEquals(1, skippedCount(
            DoubleRatchet.deserialize(migrated, nowMs = { T0 + DoubleRatchet.SKIPPED_KEY_TTL_MS - 1 }).serialize()))
        assertEquals(0, skippedCount(
            DoubleRatchet.deserialize(migrated, nowMs = { T0 + DoubleRatchet.SKIPPED_KEY_TTL_MS }).serialize()))
    }

    @Test
    fun deserialize_legacyOverCapSkippedStore_isAcceptedAndTrimmed_neverRejected() {
        // A vault written by the previous build may legitimately hold up to the OLD
        // cap (1024). Rejecting it would make RatchetManager throw the whole ratchet
        // away and re-bootstrap the pairing, so it is read and TRIMMED instead.
        val bob = DoubleRatchet.initAsBob(generateSecureRandom(32))
        val fresh = bob.serialize()
        assertEquals(0, fresh[1].toInt() and 0xFF, "fixture expects a flagless fresh ratchet")
        val count = 400
        val headLen = skippedCountOffset(fresh) + 4     // through skCount
        val blob = ByteArray(headLen + count * 68 + 4)
        fresh.copyInto(blob, 0, 0, headLen)
        blob[0] = 2                                     // previous SER_VERSION
        writeIntBE(blob, headLen - 4, count)
        val pub = generateSecureRandom(32)
        var o = headLen
        repeat(count) { i ->
            pub.copyInto(blob, o); o += 32
            writeIntBE(blob, o, i); o += 4
            generateSecureRandom(32).copyInto(blob, o); o += 32
        }
        writeIntBE(blob, o, 2)                          // dhRecvSteps

        val migrated = DoubleRatchet.deserialize(blob, nowMs = { T0 }).serialize()
        assertEquals(DoubleRatchet.MAX_SKIPPED_STORE, skippedCount(migrated),
            "an over-cap legacy store must be trimmed to the current bound, not rejected")
        assertTrue(count <= DoubleRatchet.MAX_SKIPPED_STORE_LEGACY)
        // Beyond the LEGACY bound is still refused (a corrupt/hostile count).
        val absurd = blob.copyOf().also { writeIntBE(it, headLen - 4, DoubleRatchet.MAX_SKIPPED_STORE_LEGACY + 1) }
        assertFailsWith<IllegalArgumentException> { DoubleRatchet.deserialize(absurd) }
    }

    // -- kdfRk must zero the raw ECDH output it consumes ----

    @Test
    fun kdfRk_wipesConsumedDhOut_afterDerivation() {
        // kdfRk consumes a raw X25519 ECDH shared point (dhOut) as HKDF ikm and must
        // scrub it — AND only AFTER the HKDF read, so the derived keys are unchanged.
        val rootKey = generateSecureRandom(32)
        val dhOut = generateSecureRandom(32)
        val dhCopy = dhOut.copyOf()
        val (newRoot, chain) = DoubleRatchet.kdfRk(rootKey, dhOut)
        // (a) the consumed ECDH secret is zeroed in place (every alias, since Kotlin
        //     ByteArrays are shared by reference).
        assertTrue(dhOut.all { it == 0.toByte() }, "kdfRk must wipe the consumed dhOut")
        // (b) the wipe ran AFTER the HKDF read: recomputing KDF_RK from the ORIGINAL
        //     dhOut reproduces both outputs. A wipe-before-read regression would have
        //     derived from zeros and mismatched here. (kdfRk does not touch rootKey,
        //     so it is still valid as the salt.)
        val infoRoot = "run-dr-root-v1".encodeToByteArray()   // == DoubleRatchet.INFO_ROOT
        val expected = hkdfSha256(ikm = dhCopy, salt = rootKey, info = infoRoot, length = 64)
        assertContentEquals(expected.copyOfRange(0, 32), newRoot)
        assertContentEquals(expected.copyOfRange(32, 64), chain)
    }

    // -- Pre-authentication work is BOUNDED ----
    //
    // decrypt() cannot check the AEAD tag first — the message key is what the skip
    // loop and the DH step produce — so a 72-byte blob with a fresh random dhPub and
    // n = pn = MAX_SKIP used to buy ~1024 HMAC + 2 ECDH + 1 keygen from an
    // unauthenticated sender. MAX_SKIP bounds ONE decrypt; RatchetWorkBudget bounds
    // the SUM over a drain, and the hoisted n check below makes an out-of-range
    // header cost nothing at all.

    /** A syntactically valid wire header from an attacker: any 32 bytes are a dhPub. */
    private fun forgedHeader(n: Int, pn: Int = 0) =
        RatchetHeader(generateSecureRandom(32), pn = pn, n = n)

    /** 28 bytes = the minimum AEAD payload (IV 12 + tag 16). Never opens. */
    private fun junkCiphertext() = generateSecureRandom(28)

    @Test
    fun newChainHeaderWithNBeyondMaxSkip_isRejectedWithoutTakingTheDhStep() {
        val (alice, bob) = pair()
        val first = alice.encrypt(msg("first"))
        assertEquals("first", str(bob.decrypt(first.header, first.ciphertext)))
        val before = bob.serialize()

        // A NEW ratchet key (so the DH branch is taken) plus an n the post-step
        // skipMessageKeys would refuse anyway. The rejection must now happen BEFORE
        // the step: the serialized state proves it, because dhRatchet rewrites the
        // remote pubkey, both chains, the root key and dhRecvSteps.
        assertFailsWith<RatchetException> {
            bob.decrypt(forgedHeader(n = DoubleRatchet.MAX_SKIP + 1), junkCiphertext())
        }
        assertContentEquals(before, bob.serialize(),
            "an out-of-range n on a new chain must not mutate the ratchet at all")

        // Same for a negative n, which only a forged header can carry (the wire field
        // is a raw big-endian Int).
        assertFailsWith<RatchetException> { bob.decrypt(forgedHeader(n = -1), junkCiphertext()) }
        assertContentEquals(before, bob.serialize())

        // …and the channel is untouched: the next real message still decrypts.
        val next = alice.encrypt(msg("next"))
        assertEquals("next", str(bob.decrypt(next.header, next.ciphertext)))
    }

    @Test
    fun aLongHonestChain_isNotRejectedByTheHoistedBound() {
        // The hoisted check is scoped to the NEW-key branch on purpose: within an
        // established chain n is bounded RELATIVE to recvN, so a conversation longer
        // than MAX_SKIP in one direction must keep working. 400 > MAX_SKIP = 256.
        val (alice, bob) = pair()
        for (i in 0 until 400) {
            val m = alice.encrypt(msg("m$i"))
            assertEquals("m$i", str(bob.decrypt(m.header, m.ciphertext)))
        }
        assertTrue(400 > DoubleRatchet.MAX_SKIP)
    }

    @Test
    fun workBudget_stopsAFloodOfForgedNewKeyHeaders() {
        val (alice, bob) = pair()
        val first = alice.encrypt(msg("first"))
        bob.decrypt(first.header, first.ciphertext)

        val budget = RatchetWorkBudget()
        bob.workBudget = budget
        // Each forgery: a fresh dhPub (⇒ one DH step) and n at the per-decrypt
        // ceiling (⇒ MAX_SKIP derivations). The budget is 8 DH steps and
        // 8 x MAX_SKIP derivations, so the flood stops after 8 blobs.
        var accepted = 0
        repeat(64) {
            try {
                bob.decrypt(forgedHeader(n = DoubleRatchet.MAX_SKIP), junkCiphertext())
            } catch (e: RatchetException) {
                if (e.message?.contains("work budget") != true) accepted += 1
            }
        }
        assertEquals(RatchetWorkBudget.MAX_FAILED_DH_STEPS, budget.spentDhSteps(),
            "no more than the DH ceiling may be spent, however many blobs arrive")
        assertTrue(budget.spentChainDerivations() <= RatchetWorkBudget.MAX_FAILED_CHAIN_DERIVATIONS,
            "derivations stay under the ceiling: ${budget.spentChainDerivations()}")
        assertTrue(accepted <= RatchetWorkBudget.MAX_FAILED_DH_STEPS,
            "only the pre-ceiling blobs may reach the crypto at all")
    }

    @Test
    fun workBudget_refundKeepsHonestTrafficUnaffected() {
        // What RatchetManager.decryptBatch does per blob: begin, decrypt, refund on
        // success. A real conversation must therefore never consume the ceiling.
        val (alice, bob) = pair()
        val budget = RatchetWorkBudget()
        bob.workBudget = budget
        repeat(30) { i ->
            val a = alice.encrypt(msg("a$i"))
            budget.beginAttempt()
            assertEquals("a$i", str(bob.decrypt(a.header, a.ciphertext)))
            budget.refundAttempt()
            // A reply makes the NEXT inbound carry a new ratchet key ⇒ a DH step.
            val b = bob.encrypt(msg("b$i"))
            alice.decrypt(b.header, b.ciphertext)
        }
        assertEquals(0, budget.spentDhSteps(), "authenticated DH steps must be refunded")
        assertEquals(0, budget.spentChainDerivations(), "authenticated derivations must be refunded")
    }

    @Test
    fun workBudget_chargesAndRefundsAreAccountedExactly() {
        val budget = RatchetWorkBudget(maxDhSteps = 2, maxChainDerivations = 10)
        budget.beginAttempt()
        budget.chargeDhStep(); budget.chargeChainDerivations(4)
        assertEquals(1, budget.spentDhSteps()); assertEquals(4, budget.spentChainDerivations())
        budget.refundAttempt()
        assertEquals(0, budget.spentDhSteps()); assertEquals(0, budget.spentChainDerivations())
        // Non-positive charges are free (a zero-length skip is the common case).
        budget.chargeChainDerivations(0); budget.chargeChainDerivations(-5)
        assertEquals(0, budget.spentChainDerivations())
        // Ceilings are inclusive; the charge that would cross them is REFUSED, and
        // refused without tallying — an exhausted budget must make every further blob
        // free, not keep counting.
        budget.chargeChainDerivations(10)
        assertFailsWith<RatchetException> { budget.chargeChainDerivations(1) }
        assertFailsWith<RatchetException> { budget.chargeChainDerivations(1) }
        assertEquals(10, budget.spentChainDerivations())
        budget.chargeDhStep(); budget.chargeDhStep()
        repeat(3) { assertFailsWith<RatchetException> { budget.chargeDhStep() } }
        assertEquals(2, budget.spentDhSteps())
    }

}
