package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// End-to-end wiring test: two MessageManagers (each with its own in-memory
// vault) exchange real relay traffic through a storing in-memory relay, with
// the Double Ratchet wired into the text channel. This exercises the live
// send/poll path and the self-synchronizing activation model:
//
//   * pairing marks both contacts ratchet-CAPABLE (intent), but SEND stays
//     legacy until each side has received ≥1 message from the peer (proof both
//     are fully paired) — so the FIRST exchange is legacy (the bootstrap cost);
//   * thereafter sends flip to the ratchet; the responder, which has no sending
//     chain until its first ratchet receive, transparently falls back to a
//     legacy envelope, which the peer auto-detects by wire format;
//   * the wire is self-describing (4-byte magic), so a mid-transition poll where
//     one side has flipped and the other hasn't is lossless.
//
// Inbox-id wiring mirrors production: device A's OUTBOUND id == device B's
// INBOUND id (and vice-versa). Role is lexicographic, so A="AAA…" is the
// responder ("Bob") and B="BBB…" the initiator ("Alice").
// ---------------------------------------------------------------------------
class RatchetWiringTest {

    /** Relay double: stores POSTed blobs per inbox, drains on GET, base64s raw
     *  bodies into `{"blobs":[...]}` (as the real relay does). Records whether
     *  any ratchet-magic (forward-secret) blob was ever posted. */
    private class StoringRelay : InboxQueueRelay()

    private val idA = "A".repeat(32)   // A inbound / B outbound
    private val idB = "B".repeat(32)   // B inbound / A outbound
    private val capR = "C".repeat(43)
    private val capW = "D".repeat(43)
    private val CID = "c1"

    private fun provision(vault: InMemoryVault, secret: ByteArray, inId: String, outId: String) {
        vault.insertContact(ContactRecord(contactId = CID, sharedSecret = secret, trustLevel = 0, alias = "p", aliasLastRotated = 0))
        vault.insertInboxId(InboxIdRecord(inId, CID, 0L, 1L, "inbound", capR))
        vault.insertInboxId(InboxIdRecord(outId, CID, 0L, 1L, "outbound", capW))
    }

    @Test
    fun firstExchangeLegacy_thenRatchetEngages_fullDuplexOverTheRelay() {
        val relay = StoringRelay()
        val secret = generateSecureRandom(32)
        val vaultA = InMemoryVault(); val vaultB = InMemoryVault()
        provision(vaultA, secret, inId = idA, outId = idB)   // A: in<out ⇒ responder (Bob)
        provision(vaultB, secret, inId = idB, outId = idA)   // B: in>out ⇒ initiator (Alice)
        val mgrA = MessageManager(vaultA, "http://relay.test", relay)
        val mgrB = MessageManager(vaultB, "http://relay.test", relay)

        // Pairing: both contacts become ratchet-capable (intent only).
        MessageManager.markRatchetCapable(vaultA, CID)
        MessageManager.markRatchetCapable(vaultB, CID)

        // The very first send is LEGACY: A has not heard from the peer, so SEND
        // activation has not flipped — the unavoidable bootstrap cost.
        assertTrue(mgrA.sendMessage(CID, "a0"))
        assertEquals(false, relay.sawRatchetWire, "the first send must be legacy")

        // B receives a0 → flips B's dr-on; B (initiator) then sends ratchet, which
        // A auto-detects and decodes (self-describing wire), flipping A in turn.
        assertEquals(listOf("a0"), mgrB.pollMessages(CID).map { it.text })
        assertTrue(mgrB.sendMessage(CID, "b0"))
        assertEquals(listOf("b0"), mgrA.pollMessages(CID).map { it.text })

        // Both sides have now received from the peer → SEND activation flipped.
        assertEquals("1", vaultA.getMeta("dr-on/$CID"))
        assertEquals("1", vaultB.getMeta("dr-on/$CID"))

        // Subsequent rounds engage the ratchet (initiator immediately; the
        // responder falls back to legacy for its first send, then ratchets after
        // its first ratchet receive). Full duplex holds throughout the round-trip
        // of vault-persisted ratchet state.
        repeat(5) { i ->
            assertTrue(mgrA.sendMessage(CID, "a${i + 1}"))
            assertEquals(listOf("a${i + 1}"), mgrB.pollMessages(CID).map { it.text })
            assertTrue(mgrB.sendMessage(CID, "b${i + 1}"))
            assertEquals(listOf("b${i + 1}"), mgrA.pollMessages(CID).map { it.text })
        }

        // The ratchet really engaged on the wire (a forward-secret, magic-tagged
        // blob was posted) — not merely a legacy channel that happened to work.
        assertTrue(relay.sawRatchetWire, "ratchet must engage after the first exchange")

        // GROUP text rides the same 1:1 (ratcheted) channel; its routing fields
        // must survive the ratchet envelope so the receiver re-attributes it to
        // the group (this is the cross:multi step-4 path).
        val gid = "G".repeat(32); val mh = "hash123"
        val gw = mgrA.sendGroupText(CID, gid, mh, "hello crew")
        assertTrue(gw)
        val gmsg = mgrB.pollMessages(CID).single()
        assertEquals("hello crew", gmsg.text)
        assertEquals(gid, gmsg.groupId)
        assertEquals(mh, gmsg.membershipHash)
    }

    /**
     * Once B has decrypted a ratchet blob from A (receive-lock
     * armed), a NON-magic legacy text blob is a post-compromise forgery — an
     * attacker who stole sharedSecret can mint a valid static-key blob but not a
     * ratchet blob — and must be DROPPED. Modelled by a fresh MessageManager that
     * shares the sharedSecret and posts to B's inbox but has no ratchet state, so
     * it sends legacy. The attacker sends TWO messages so its second counter
     * exceeds B's legacy baseline (proving the drop is the downgrade guard, not anti-replay).
     */
    @Test
    fun ratchetLocked_dropsForgedLegacyBlob_postCompromise() {
        val relay = StoringRelay()
        val secret = generateSecureRandom(32)
        val vaultA = InMemoryVault(); val vaultB = InMemoryVault()
        provision(vaultA, secret, inId = idA, outId = idB)
        provision(vaultB, secret, inId = idB, outId = idA)
        val mgrA = MessageManager(vaultA, "http://relay.test", relay)
        val mgrB = MessageManager(vaultB, "http://relay.test", relay)
        MessageManager.markRatchetCapable(vaultA, CID)
        MessageManager.markRatchetCapable(vaultB, CID)

        // Drive the exchange until B has received a ratchet blob from A.
        assertTrue(mgrA.sendMessage(CID, "a0"))
        assertEquals(listOf("a0"), mgrB.pollMessages(CID).map { it.text })
        assertTrue(mgrB.sendMessage(CID, "b0"))
        assertEquals(listOf("b0"), mgrA.pollMessages(CID).map { it.text })
        repeat(3) { i ->
            assertTrue(mgrA.sendMessage(CID, "a${i + 1}"))
            assertEquals(listOf("a${i + 1}"), mgrB.pollMessages(CID).map { it.text })
            assertTrue(mgrB.sendMessage(CID, "b${i + 1}"))
            assertEquals(listOf("b${i + 1}"), mgrA.pollMessages(CID).map { it.text })
        }
        assertTrue(relay.sawRatchetWire, "precondition: ratchet engaged")
        assertEquals("1", vaultB.getMeta("dr-rxlock/$CID"), "B's receive-lock must be armed")

        // Attacker: same sharedSecret, posts to B's inbox (idB), NO ratchet state
        // ⇒ legacy. Two sends so counter 2 > B's legacy baseline (=1 from a0).
        val atkVault = InMemoryVault()
        atkVault.insertContact(ContactRecord(CID, secret, 0, "atk", 0))
        atkVault.insertInboxId(InboxIdRecord(idB, CID, 0L, 1L, "outbound", capW))
        val attacker = MessageManager(atkVault, "http://relay.test", relay)
        assertTrue(attacker.sendMessage(CID, "forged1"))
        assertTrue(attacker.sendMessage(CID, "forged2"))

        assertEquals(
            emptyList(),
            mgrB.pollMessages(CID).map { it.text },
            "legacy forgeries must be dropped after the ratchet receive-lock (M1)",
        )
    }

    /**
     * a relay that drops the INITIATOR's ratchet blobs pins
     * the responder's whole outbound direction on the static (no-forward-secrecy)
     * envelope — the responder has no sending chain until its first ratchet receive,
     * and the send path falls through to legacy without buffering. That fallthrough
     * is by design (refusing to send would let the relay silence the conversation),
     * but it used to be silent and uncounted. It is now COUNTED per contact and
     * readable, and the counter clears the moment a ratchet send actually lands.
     */
    @Test
    fun relayDroppingRatchetBlobs_pinsResponderOnLegacy_andTheStallIsCounted() {
        val relay = StoringRelay()
        val secret = generateSecureRandom(32)
        val vaultA = InMemoryVault(); val vaultB = InMemoryVault()
        provision(vaultA, secret, inId = idA, outId = idB)   // A: in<out ⇒ responder (Bob)
        provision(vaultB, secret, inId = idB, outId = idA)   // B: in>out ⇒ initiator (Alice)
        val mgrA = MessageManager(vaultA, "http://relay.test", relay)
        val mgrB = MessageManager(vaultB, "http://relay.test", relay)
        MessageManager.markRatchetCapable(vaultA, CID)
        MessageManager.markRatchetCapable(vaultB, CID)
        // The relay blackholes every ratchet append addressed to the RESPONDER's inbox.
        relay.dropRatchetTo.add(idA)

        // Bootstrap: B's first send is legacy (its own dr-on has not flipped yet), so
        // it lands. A now has dr-on set but, as the responder, still has NO sending
        // chain — and the relay is making sure it never gets one.
        assertTrue(mgrB.sendMessage(CID, "b0"))
        assertEquals(listOf("b0"), mgrA.pollMessages(CID).map { it.text })
        assertEquals("1", vaultA.getMeta("dr-on/$CID"))
        assertEquals(0, mgrA.ratchetFallbackCount(CID))
        assertTrue(!mgrA.forwardSecrecyStalled(CID))

        repeat(MessageManager.RATCHET_FALLBACK_STALL_THRESHOLD) { i ->
            assertTrue(mgrA.sendMessage(CID, "a$i"))                       // falls back to legacy
            assertEquals(listOf("a$i"), mgrB.pollMessages(CID).map { it.text })
            assertTrue(mgrB.sendMessage(CID, "dropped$i"))                 // ratchet → blackholed
            assertEquals(emptyList(), mgrA.pollMessages(CID).map { it.text })
        }
        assertEquals(MessageManager.RATCHET_FALLBACK_STALL_THRESHOLD, mgrA.ratchetFallbackCount(CID))
        assertTrue(mgrA.forwardSecrecyStalled(CID), "a pinned responder must be visible, not silent")
        assertTrue(!mgrB.forwardSecrecyStalled(CID), "the initiator is not stalled")
        // The counter is per-contact vault state, so it survives a new manager over
        // the same vault (this is what a future UI would read at unlock).
        assertTrue(MessageManager(vaultA, "http://relay.test", relay).forwardSecrecyStalled(CID))

        // The relay relents: B's ratchet blob lands, A bootstraps, A's next send is
        // forward-secret — and the "consecutive" counter resets.
        relay.dropRatchetTo.clear()
        assertTrue(mgrB.sendMessage(CID, "b-fs"))
        assertEquals(listOf("b-fs"), mgrA.pollMessages(CID).map { it.text })
        assertTrue(mgrA.sendMessage(CID, "a-fs"))
        assertEquals(0, mgrA.ratchetFallbackCount(CID), "a landed ratchet send clears the stall")
        assertTrue(!mgrA.forwardSecrecyStalled(CID))
        assertEquals(listOf("a-fs"), mgrB.pollMessages(CID).map { it.text })
    }

    /** The fallback counter is per-contact `_meta`, so it must be in the single purge
     *  list both VaultDatabase actuals iterate — otherwise a delete/re-pair inherits a
     *  stale "forward secrecy stalled" verdict for a brand-new pairing. */
    @Test
    fun fallbackCounter_isPurgedWithTheContact() {
        val vault = InMemoryVault()
        vault.insertContact(ContactRecord(contactId = CID, sharedSecret = generateSecureRandom(32), trustLevel = 0, alias = "p", aliasLastRotated = 0))
        vault.putMeta(MessageManager.drLegacyFallbackKey(CID), "42")
        assertTrue(MessageManager.drLegacyFallbackKey(CID) in ratchetMetaKeysForContact(CID))
        vault.deleteContact(CID)
        assertEquals(null, vault.getMeta(MessageManager.drLegacyFallbackKey(CID)))
    }

    @Test
    fun legacyContact_neverMarked_staysOnStaticEnvelope_andSendsFirstFreely() {
        // No markRatchetCapable ⇒ no intent ⇒ pure legacy. Notably the responder
        // can send FIRST (no ratchet bootstrap ordering), proving the legacy path
        // is completely untouched for pre-existing contacts.
        val relay = StoringRelay()
        val secret = generateSecureRandom(32)
        val vaultA = InMemoryVault(); val vaultB = InMemoryVault()
        provision(vaultA, secret, inId = idA, outId = idB)
        provision(vaultB, secret, inId = idB, outId = idA)
        val mgrA = MessageManager(vaultA, "http://relay.test", relay)
        val mgrB = MessageManager(vaultB, "http://relay.test", relay)

        assertTrue(mgrA.sendMessage(CID, "legacy-from-A"))
        assertEquals(listOf("legacy-from-A"), mgrB.pollMessages(CID).map { it.text })
        assertEquals(false, relay.sawRatchetWire, "unmarked contact must never ratchet")
        assertEquals(null, vaultA.getMeta("dr-on/$CID"))
    }
}
