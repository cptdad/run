package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// MOVE → MESSAGE CONTINUITY, end to end (docs/device-move.md D1/D3).
//
// WHY THIS FILE EXISTS. `cross:move-i2i` (old=iPhone, fresh=iPhone, peer=Pixel,
// 2026-09-11) failed at "peer: only 2/3 received 1:1 bubbles": the relay log
// proves the MIGRATED phone's first 1:1 message was POSTed and that the Android
// peer DRAINED it (blobsReturned=1), yet no bubble ever rendered. The sibling
// suites — which run the IDENTICAL protocol sequence, byte sizes included —
// passed the same night, so nothing above the transport distinguishes them
// except the receiving platform. Until now nothing pinned the property itself:
// MoveManagerTest covers the export/import mechanics and RatchetWiringTest
// covers the ratchet over the relay, but NO test ever put a MIGRATED sender back
// on the wire and required the untouched peer to accept its next message.
//
// These tests do exactly that, through the REAL pieces:
//   VaultSnapshotIo.export → MigrationBundleCodec.encode/decode →
//   VaultSnapshotIo.import(+MoveConstants.COUNTER_JUMP) → MessageManager.send →
//   peer MessageManager.pollMessages.
// They run on every target, so they also exercise each platform's crypto
// `actual`s (Tink X25519 / AES-GCM on the JVM-Android side) against the exact
// state transition the failing run performed — a migrated ratchet whose next
// DH step is computed from a private key that has round-tripped the vault.
//
// ROLE SETUP MIRRORS THE FAILING RUN. Ratchet roles are lexicographic on the
// inbox-id pair ([ratchetSelfIsBob]): `old`'s inbound ("WWW…") sorts AFTER its
// outbound ("PPP…"), so OLD IS ALICE and PEER IS BOB — the assignment the relay
// log proves for the i2i/i2a runs (old's second message was a 328-byte ratchet
// blob while the peer's was a 284-byte legacy fallback).
// ---------------------------------------------------------------------------

/** Exposes [getAllInboxIds] (the interface default throws) so export works. */
private class MoveContinuityVault(val inner: InMemoryVault = InMemoryVault()) : VaultDatabase by inner {
    override fun getAllInboxIds(): List<InboxIdRecord> = inner.inboxes.toList()
}

/** Storing relay double: POST appends, GET drains, base64 into `{"blobs":[…]}`. */
private class MoveContinuityRelay : InboxQueueRelay()

class MoveRatchetContinuityTest {

    private val idPeer = "P".repeat(32)   // peer inbound / old outbound
    private val idOld  = "W".repeat(32)   // old inbound  / peer outbound ("W" > "P" ⇒ old = Alice)
    private val capR = "C".repeat(43)
    private val capW = "D".repeat(43)
    private val cid = "c1"

    private fun provision(vault: VaultDatabase, secret: ByteArray, inId: String, outId: String) {
        vault.insertContact(
            ContactRecord(contactId = cid, sharedSecret = secret, trustLevel = 0, alias = "p", aliasLastRotated = 0)
        )
        vault.insertInboxId(InboxIdRecord(inId, cid, 0L, 1L, "inbound", capR))
        vault.insertInboxId(InboxIdRecord(outId, cid, 0L, 1L, "outbound", capW))
    }

    /**
     * The move itself, through the production codec: export `from`, encode, decode,
     * import into `to` with the D3 counter jump. Returns the bundleId.
     */
    private fun move(from: VaultDatabase, to: VaultDatabase): String {
        val bundleId = MoveHandleCodec.newBundleId()
        val bundle = MigrationBundle(
            schema = MigrationBundleCodec.CURRENT_SCHEMA,
            from = MigrationBundle.FROM_IOS,
            createdMs = 1_700_000_000_000L,
            bundleId = bundleId,
            snapshot = VaultSnapshotIo.export(from),
        )
        val decoded = MigrationBundleCodec.decodeFromString(MigrationBundleCodec.encodeToString(bundle))
        VaultSnapshotIo.import(to, decoded.snapshot, MoveConstants.COUNTER_JUMP, decoded.bundleId)
        return bundleId
    }

    /**
     * THE PROPERTY the failing suite asserts on hardware: after `old` exports its
     * vault to `fresh`, the untouched `peer` — same contactId, same sharedSecret,
     * same Double-Ratchet chain — must still decrypt `fresh`'s FIRST outbound
     * message. That message is a ratchet blob carrying a brand-new DH public key
     * and `pn` = the chain length the MIGRATED state contributed, so it drives the
     * peer's SECOND receiving DH step against state that has never been re-derived
     * on this device.
     */
    @Test
    fun migratedSender_firstRatchetMessage_isAcceptedByTheUntouchedPeer() {
        val relay = MoveContinuityRelay()
        val secret = generateSecureRandom(32)
        val vaultOld = MoveContinuityVault()
        val vaultPeer = MoveContinuityVault()
        provision(vaultOld, secret, inId = idOld, outId = idPeer)    // Alice
        provision(vaultPeer, secret, inId = idPeer, outId = idOld)   // Bob
        val mgrOld = MessageManager(vaultOld, "http://relay.test", relay)
        val mgrPeer = MessageManager(vaultPeer, "http://relay.test", relay)
        MessageManager.markRatchetCapable(vaultOld, cid)
        MessageManager.markRatchetCapable(vaultPeer, cid)

        // --- pre-move: the suite's two "ratchet-arm" rounds, in the run's order.
        // Round 1 is legacy on both sides (dr-on flips only after a first receive).
        assertTrue(mgrOld.sendMessage(cid, "arm1 old"))
        assertTrue(mgrPeer.sendMessage(cid, "arm1 peer"))
        assertEquals(listOf("arm1 old"), mgrPeer.pollMessages(cid).map { it.text })
        assertEquals(listOf("arm1 peer"), mgrOld.pollMessages(cid).map { it.text })
        // Round 2: Alice(old) ratchets immediately; Bob(peer) has no sending chain
        // yet and falls back to legacy — exactly the 328/284 split seen on the wire.
        assertTrue(mgrOld.sendMessage(cid, "arm2 old"))
        assertTrue(mgrPeer.sendMessage(cid, "arm2 peer"))
        assertEquals(listOf("arm2 old"), mgrPeer.pollMessages(cid).map { it.text })
        assertEquals(listOf("arm2 peer"), mgrOld.pollMessages(cid).map { it.text })
        assertTrue(
            relay.posted.any { MessageManager.isRatchetWire(it) },
            "pre-move: the ratchet must have engaged, or the move leg below proves nothing",
        )

        // --- the move. `old` is now frozen; `fresh` carries its logical identity.
        val vaultFresh = MoveContinuityVault()
        val bundleId = move(vaultOld, vaultFresh)
        assertEquals(bundleId, vaultFresh.getMeta(MoveMetaKeys.IMPORTED), "import must commit last")
        assertEquals(
            vaultOld.getContact(cid)!!.outboundCounter + MoveConstants.COUNTER_JUMP,
            vaultFresh.getContact(cid)!!.outboundCounter,
            "the outbound counter jumps exactly once",
        )
        assertEquals(
            vaultOld.getMeta("dr/$cid/${MessageManager.RATCHET_TEXT_CHANNEL}"),
            vaultFresh.getMeta("dr/$cid/${MessageManager.RATCHET_TEXT_CHANNEL}"),
            "the serialized ratchet state must travel byte-for-byte",
        )
        val mgrFresh = MessageManager(vaultFresh, "http://relay.test", relay)

        // --- continuity, direction 1: peer → fresh (this leg passed on hardware).
        assertTrue(mgrPeer.sendMessage(cid, "post-move: hello from peer"))
        assertEquals(
            listOf("post-move: hello from peer"),
            mgrFresh.pollMessages(cid).map { it.text },
            "the migrated vault must still decrypt the peer's ratchet blob",
        )

        // --- continuity, direction 2: fresh → peer. THIS is the leg that failed.
        val before = relay.posted.size
        assertTrue(mgrFresh.sendMessage(cid, "post-move: hello from fresh"))
        assertTrue(
            MessageManager.isRatchetWire(relay.posted[before]),
            "the migrated sender must ship over the ratchet (a legacy blob would test the wrong path)",
        )
        assertEquals(
            listOf("post-move: hello from fresh"),
            mgrPeer.pollMessages(cid).map { it.text },
            "the untouched peer must accept the MIGRATED sender's first message",
        )

        // --- and the channel keeps working in both directions afterwards.
        repeat(3) { i ->
            assertTrue(mgrFresh.sendMessage(cid, "f$i"))
            assertEquals(listOf("f$i"), mgrPeer.pollMessages(cid).map { it.text })
            assertTrue(mgrPeer.sendMessage(cid, "p$i"))
            assertEquals(listOf("p$i"), mgrFresh.pollMessages(cid).map { it.text })
        }
    }

    /**
     * The same property on the LEGACY (static-envelope) path, which is what a
     * pairing that never engaged the ratchet uses: [MoveConstants.COUNTER_JUMP]
     * pushes the migrated sender's outbound counter 10 000 ahead, and the peer's
     * strict-monotonic anti-replay check must treat that as a GAP (accept), never
     * as a replay (drop). The `ch` / `di` / epoch bindings must survive the move
     * too — the peer has already latched `m2-chseen` / `ib-bound-seen` from the
     * pre-move traffic, so a migrated sender that stopped emitting either would be
     * dropped as a downgrade.
     */
    @Test
    fun migratedSender_legacyEnvelope_survivesTheCounterJumpAndTheBindingLatches() {
        val relay = MoveContinuityRelay()
        val secret = generateSecureRandom(32)
        val vaultOld = MoveContinuityVault()
        val vaultPeer = MoveContinuityVault()
        provision(vaultOld, secret, inId = idOld, outId = idPeer)
        provision(vaultPeer, secret, inId = idPeer, outId = idOld)
        val mgrOld = MessageManager(vaultOld, "http://relay.test", relay)
        val mgrPeer = MessageManager(vaultPeer, "http://relay.test", relay)
        // Deliberately NOT ratchet-capable: this pairing stays on the static envelope.

        assertTrue(mgrOld.sendMessage(cid, "pre-move old"))
        assertEquals(listOf("pre-move old"), mgrPeer.pollMessages(cid).map { it.text })
        assertTrue(mgrPeer.sendMessage(cid, "pre-move peer"))
        assertEquals(listOf("pre-move peer"), mgrOld.pollMessages(cid).map { it.text })
        // The peer has now SEEN a tagged + inbox-bound blob, so it REQUIRES both
        // from this contact from here on (the downgrade rules).
        assertEquals("1", vaultPeer.getMeta(MessageManager.channelTagSeenKey(cid)))
        assertEquals("1", vaultPeer.getMeta(MessageManager.inboxBoundSeenKey(cid)))

        val vaultFresh = MoveContinuityVault()
        move(vaultOld, vaultFresh)
        val mgrFresh = MessageManager(vaultFresh, "http://relay.test", relay)

        assertTrue(mgrFresh.sendMessage(cid, "post-move from fresh"))
        assertFalse(
            MessageManager.isRatchetWire(relay.posted.last()),
            "this test must exercise the LEGACY envelope",
        )
        assertEquals(
            listOf("post-move from fresh"),
            mgrPeer.pollMessages(cid).map { it.text },
            "a +10 000 counter gap is a GAP, never a replay",
        )
        // The peer's baseline really did follow the jump, so the next message is
        // accepted too (and a re-served pre-move blob still cannot be).
        assertTrue(mgrFresh.sendMessage(cid, "post-move 2"))
        assertEquals(listOf("post-move 2"), mgrPeer.pollMessages(cid).map { it.text })
        assertTrue(
            vaultPeer.getContact(cid)!!.inboundCounter > MoveConstants.COUNTER_JUMP,
            "the receiver's replay baseline must have followed the jump",
        )
    }
}
