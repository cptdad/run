package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// The peer's control-inbox WRITE capability
// has no revocation path, and the control channel is keyed by the static
// sharedSecret with no post-compromise security. An attacker who opened the
// vault ONCE holds everything needed to forge a control "inbox" announce that
// the peer accepts, silently redirecting that peer's outbound routing to an
// attacker-minted inbox — even after the text ratchet is fully engaged.
//
// Two live MessageManagers exchange real traffic through a storing relay
// double until the ratchet is on. The attacker then acts using ONLY fields a
// vault image contains (contacts.shared_secret, the outbound-ctl row, the
// persisted outbound-ctl counter) and posts to the relay with the stolen
// write capability. The victim's ordinary background control sweep does the
// rest.
//
// These were RED before the fix (they reproduced the redirect). The fix:
// once dr-on, an announce is sealed by the TEXT ratchet and posted to the
// control inbox; once the peer's dr-rxlock is armed, a static-key announce is
// dropped. The positive control (honest re-announce still lands) pins that
// the fix did not simply refuse re-announces — the ownership rule "an unknown
// inbox is available" is load-bearing for rotation and the 404 self-heal
// (InboxOwnershipTest).
// ---------------------------------------------------------------------------

private val H1_CONTACT = "c1"
private val H1_IN_A = "A".repeat(32)   // Alice inbound  / Bob outbound   (text)
private val H1_IN_B = "B".repeat(32)   // Bob inbound    / Alice outbound (text)
private val H1_CTL_A = "a".repeat(32)   // Alice inbound-ctl / Bob outbound-ctl
private val H1_CTL_B = "b".repeat(32)   // Bob inbound-ctl   / Alice outbound-ctl
private val H1_RCAP = "R".repeat(43)
private val H1_WCAP_A = "W".repeat(43)   // write cap for Alice's inboxes (Bob holds it)
private val H1_WCAP_B = "X".repeat(43)   // write cap for Bob's inboxes (Alice holds it)
private val H1_EVIL_IB = "EVIL" + "x".repeat(28)   // attacker-minted text inbox
private val H1_EVIL_CIB = "EVIL" + "c".repeat(28)   // attacker-minted ctl inbox
private val H1_EVIL_CAP = "Z".repeat(43)

/** Seals exactly as the production sender does (mirrors AntiSpliceReplayTest). */
private fun h1Seal(sharedSecret: ByteArray, envelopeJson: String): ByteArray {
    val key = sha256(sharedSecret)
    val ctx = sha256(key + "message-aead".encodeToByteArray())
    return aesGcmEncrypt(padMessage(envelopeJson.encodeToByteArray()), key, ctx)
}

/** The epoch the receiver expects for this secret (mirrors messageEpoch). */
private fun h1Epoch(sharedSecret: ByteArray): String =
    bytesToHex(sha256(sharedSecret + "msg-epoch".encodeToByteArray()).copyOfRange(0, 6))

/**
 * Relay double: stores POSTed blobs per inbox, drains on GET. Records the
 * write capability presented on every POST so the test can show the forged
 * announce was accepted on the strength of the stolen cap alone.
 */
private class H1Relay : InboxQueueRelay()

private class H1Harness {
    val relay = H1Relay()
    val secret = generateSecureRandom(32)
    val alice = InMemoryVault()   // the VICTIM whose routing gets rewritten
    val bob = InMemoryVault()     // the SEIZED device (vault image source)
    val aliceMgr: MessageManager
    val bobMgr: MessageManager

    init {
        provision(alice, inText = H1_IN_A, outText = H1_IN_B, inCtl = H1_CTL_A, outCtl = H1_CTL_B, peerWcap = H1_WCAP_B)
        provision(bob,   inText = H1_IN_B, outText = H1_IN_A, inCtl = H1_CTL_B, outCtl = H1_CTL_A, peerWcap = H1_WCAP_A)
        aliceMgr = MessageManager(alice, "http://relay.test", relay)
        bobMgr = MessageManager(bob, "http://relay.test", relay)
        MessageManager.markRatchetCapable(alice, H1_CONTACT)
        MessageManager.markRatchetCapable(bob, H1_CONTACT)
    }

    private fun provision(v: InMemoryVault, inText: String, outText: String, inCtl: String, outCtl: String, peerWcap: String) {
        v.insertContact(ContactRecord(contactId = H1_CONTACT, sharedSecret = secret, trustLevel = 0, alias = "p", aliasLastRotated = 0))
        v.insertInboxId(InboxIdRecord(inText, H1_CONTACT, 0L, 1L, "inbound", H1_RCAP))
        v.insertInboxId(InboxIdRecord(outText, H1_CONTACT, 0L, 1L, "outbound", peerWcap))
        v.insertInboxId(InboxIdRecord(inCtl, H1_CONTACT, 0L, 1L, MessageManager.DIR_INBOUND_CTL, H1_RCAP))
        v.insertInboxId(InboxIdRecord(outCtl, H1_CONTACT, 0L, 1L, MessageManager.DIR_OUTBOUND_CTL, peerWcap))
    }

    /** Drive the pairing until the Double Ratchet is live on the text channel. */
    fun engageRatchet() {
        assertTrue(aliceMgr.sendMessage(H1_CONTACT, "a0"))
        assertEquals(listOf("a0"), bobMgr.pollMessages(H1_CONTACT).map { it.text })
        assertTrue(bobMgr.sendMessage(H1_CONTACT, "b0"))
        assertEquals(listOf("b0"), aliceMgr.pollMessages(H1_CONTACT).map { it.text })
        repeat(3) { i ->
            assertTrue(aliceMgr.sendMessage(H1_CONTACT, "a${i + 1}"))
            assertEquals(listOf("a${i + 1}"), bobMgr.pollMessages(H1_CONTACT).map { it.text })
            assertTrue(bobMgr.sendMessage(H1_CONTACT, "b${i + 1}"))
            assertEquals(listOf("b${i + 1}"), aliceMgr.pollMessages(H1_CONTACT).map { it.text })
        }
        assertTrue(relay.sawRatchetWire, "precondition: the text ratchet must be engaged")
        assertEquals("1", alice.getMeta("dr-on/$H1_CONTACT"))
        assertEquals("1", bob.getMeta("dr-on/$H1_CONTACT"))
    }

    /**
     * The attacker's entire haul is one read of BOB's vault: the shared secret,
     * Bob's outbound-ctl row (= Alice's inbound-ctl inbox id + its write cap),
     * and the persisted outbound-ctl counter. No live device, no ratchet state
     * needed. [counterBump] models how far ahead the forged counter sits.
     */
    fun forgeAnnounceFromBobsVault(counterBump: Long): ByteArray {
        val snapshot = bob.getContact(H1_CONTACT)!!
        val peerCtl = bob.getInboxIdForContact(H1_CONTACT, MessageManager.DIR_OUTBOUND_CTL)!!
        assertEquals(H1_CTL_A, peerCtl.inboxId)
        val body = """{"ib":"$H1_EVIL_IB","wc":"$H1_EVIL_CAP","cib":"$H1_EVIL_CIB","cwc":"$H1_EVIL_CAP"}"""
        val env = """{"e":"${h1Epoch(snapshot.sharedSecret)}","c":${snapshot.outboundCtlCounter + counterBump},"t":0,"ch":"${MessageManager.CHANNEL_TAG_CTL}","di":"${peerCtl.inboxId}","k":"${MessageManager.CONTROL_KIND_INBOX}","b":${jsonEscapeString(body)},"m":""}"""
        return h1Seal(snapshot.sharedSecret, env)
    }

    /** Post to the relay exactly as a stranger with the stolen write cap would. */
    fun postAsAttacker(blob: ByteArray) {
        val stolenCap = bob.getInboxIdForContact(H1_CONTACT, MessageManager.DIR_OUTBOUND_CTL)!!.cap!!
        relay.post("http://relay.test/inbox/$H1_CTL_A", blob, "application/octet-stream", mapOf("X-Write-Capability" to stolenCap), 30)
    }

    fun aliceOutbound(): Pair<String, String> =
        alice.getInboxIdForContact(H1_CONTACT, "outbound")!!.inboxId to
            alice.getInboxIdForContact(H1_CONTACT, MessageManager.DIR_OUTBOUND_CTL)!!.inboxId
}

class ForgedAnnounceRedirectTest {

    /**
     * RED today. A forged announce built from a vault snapshot, with the
     * counter jumped far ahead, must NOT rewrite an established peer's routing.
     */
    @Test
    fun forgedAnnounce_fromVaultSnapshot_mustNotRedirectAnEstablishedPeer() {
        if (!aeadUp()) return
        val h = H1Harness()
        h.engageRatchet()
        assertEquals(H1_IN_B to H1_CTL_B, h.aliceOutbound(), "precondition: Alice routes to Bob")

        h.postAsAttacker(h.forgeAnnounceFromBobsVault(counterBump = 1_000_000L))
        h.aliceMgr.pollControlMessages(H1_CONTACT)   // Alice's ordinary background sweep

        assertEquals(
            H1_IN_B to H1_CTL_B, h.aliceOutbound(),
            "a forged control announce built from vault contents rewrote Alice's outbound routing",
        )

        // Consequence check: Alice's next text must still reach Bob, not the attacker.
        assertTrue(h.aliceMgr.sendMessage(H1_CONTACT, "after"))
        assertTrue(h.relay.blobsIn(H1_EVIL_IB).isEmpty(), "Alice's text was delivered to the attacker's inbox")
        assertTrue(h.relay.blobsIn(H1_IN_B).isNotEmpty(), "Alice's text must still land in Bob's inbox")
    }

    /**
     * RED today. Same forgery with the counter advanced by ONE — the
     * receiver has no ceiling on counter jumps, but the fix must not depend on
     * one either: a minimal-step forgery is just as valid to today's code.
     */
    @Test
    fun forgedAnnounce_withMinimalCounterStep_mustNotRedirectEither() {
        if (!aeadUp()) return
        val h = H1Harness()
        h.engageRatchet()

        h.postAsAttacker(h.forgeAnnounceFromBobsVault(counterBump = 1L))
        h.aliceMgr.pollControlMessages(H1_CONTACT)

        assertEquals(H1_IN_B to H1_CTL_B, h.aliceOutbound(), "minimal-counter forged announce redirected Alice")
    }

    /**
     * "Reset relay access" on BOB's side (the seized device) rotates only Bob's
     * READ caps — it neither helps nor hurts this vector. The forgery must be
     * dropped regardless, on the strength of the peer's ratchet lock alone.
     */
    @Test
    fun forgedAnnounce_isDropped_regardlessOfResetRelayAccessOnTheSeizedDevice() {
        if (!aeadUp()) return
        val h = H1Harness()
        h.engageRatchet()

        // Bob learns of the seizure and runs the shipped remedy.
        h.bobMgr.resetRelayAccess(H1_CONTACT)

        // The attacker's snapshot predates the reset; it still works.
        h.postAsAttacker(h.forgeAnnounceFromBobsVault(counterBump = 1_000_000L))
        h.aliceMgr.pollControlMessages(H1_CONTACT)

        assertEquals(H1_IN_B to H1_CTL_B, h.aliceOutbound(), "forged announce still redirects Alice after Bob's Reset relay access")
    }

    /**
     * GREEN today and MUST STAY GREEN through the fix: Bob's honest re-announce
     * of a rotated inbox must still land — the fix cannot simply refuse
     * re-announces on established contacts.
     */
    @Test
    fun honestReAnnounce_fromTheRealPeer_stillLands() {
        if (!aeadUp()) return
        val h = H1Harness()
        h.engageRatchet()

        val newIb = "N".repeat(32); val newCib = "n".repeat(32); val newCap = "Y".repeat(43)
        assertTrue(h.bobMgr.sendInboxAnnounce(H1_CONTACT, newIb, newCap, newCib, newCap))

        // The announce landed on Alice's CONTROL inbox and is RATCHET wire — sealed
        // by the text ratchet, so a static-key forger cannot produce it.
        val posted = h.relay.blobsIn(H1_CTL_A)
        assertEquals(1, posted.size, "announce must be posted to the control inbox")
        assertTrue(MessageManager.isRatchetWire(posted.single()), "post-ratchet announce must be ratchet wire, not the static envelope")

        h.aliceMgr.pollControlMessages(H1_CONTACT)

        assertEquals(newIb to newCib, h.aliceOutbound(), "an honest re-announce must still be applied")
    }
}
