package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// KNOWN LIMITATION, PINNED ON PURPOSE — DO NOT "FIX" THIS TEST.
//
// These tests document that, with the LEGACY pairing bootstrap, an attacker who
// holds ONLY the stored pairing secret (`contact.sharedSecret`) plus the wires a
// hostile relay recorded can read:
//   case 1 — the initiator's ratchet messages sent before the responder's first
//            ratchet reply (its whole first chain), and
//   case 2 — every text that rode the static envelope before / around `dr-on`
//            (both directions, including the responder's legacy fallback),
// even after the recipient drained and COMMITTED them.
//
// The attack ([LegacyBootstrapAttacker]) re-derives the keys with the real KDFs
// and labels; it never touches either device's ratchet objects.
//
// The "attacker succeeds" assertions are a NON-VACUITY CONTROL for the v3
// bootstrap (docs/ratchet-bootstrap-plan.md, §5 and §7): the v3 oracle must fail
// on new pairings while this keeps passing on the legacy path, proving the oracle
// can see a recoverable message when one exists. If this test starts failing,
// either the legacy path changed (update the attacker, never delete the test) or
// the attacker helpers broke — investigate; do not invert the assertions.
// ---------------------------------------------------------------------------
class RatchetBootstrapRecoverabilityTest {

    private class Relay : InboxQueueRelay()

    // Production-shaped wiring: A's outbound == B's inbound and vice versa. Role is
    // the legacy id order (no `rv:2` evidence): A ("AAA…" < "BBB…") is the
    // responder (Bob), B the initiator (Alice).
    private val idA = "A".repeat(32)
    private val idB = "B".repeat(32)
    private val capR = "C".repeat(43)
    private val capW = "D".repeat(43)
    private val cid = "c1"

    private fun provision(vault: InMemoryVault, secret: ByteArray, inId: String, outId: String) {
        vault.insertContact(ContactRecord(contactId = cid, sharedSecret = secret.copyOf(), trustLevel = 0, alias = "p", aliasLastRotated = 0))
        vault.insertInboxId(InboxIdRecord(inId, cid, 0L, 1L, "inbound", capR))
        vault.insertInboxId(InboxIdRecord(outId, cid, 0L, 1L, "outbound", capW))
    }

    private class Pair2(val relay: Relay, val vaultA: InMemoryVault, val vaultB: InMemoryVault, val a: MessageManager, val b: MessageManager)

    /** Two in-memory devices paired through the real legacy path (ratchet-capable, legacy roles). */
    private fun pairLegacy(): Pair2 {
        val relay = Relay()
        val secret = generateSecureRandom(32)
        val vaultA = InMemoryVault(); val vaultB = InMemoryVault()
        provision(vaultA, secret, inId = idA, outId = idB)
        provision(vaultB, secret, inId = idB, outId = idA)
        secret.secureWipe()
        MessageManager.markRatchetCapable(vaultA, cid)
        MessageManager.markRatchetCapable(vaultB, cid)
        return Pair2(relay, vaultA, vaultB, MessageManager(vaultA, "http://relay.test", relay), MessageManager(vaultB, "http://relay.test", relay))
    }

    /** What the attacker is handed from the RECIPIENT's vault: the stored pairing secret, nothing else. */
    private fun storedPairingSecret(vault: InMemoryVault): ByteArray = vault.getContact(cid)!!.sharedSecret

    @Test
    fun knownLimitation_legacyBootstrap_initiatorFirstChain_isRecoverableFromStoredPairingSecret() {
        val p = pairLegacy()
        // A (responder) writes first — static envelope; B receives it, which flips B's dr-on.
        assertTrue(p.a.sendMessage(cid, "hello"))
        assertEquals(listOf("hello"), p.b.pollMessages(cid).map { it.text })

        // B (initiator) can ratchet at once: three messages before A's first ratchet reply.
        val sent = listOf("first secret", "second secret", "third secret")
        for (t in sent) assertTrue(p.b.sendMessage(cid, t))
        assertTrue(p.relay.sawRatchetWire, "precondition: the initiator's texts rode the ratchet")

        // The recipient drains and COMMITS them (persisting drain: the advance is in its vault).
        assertEquals(sent, p.a.pollMessages(cid).map { it.text })

        // Precondition for "consumed": the recipient's own committed state no longer opens
        // the same wires (a relay replaying them gets nothing out of the victim).
        val ratchetBodies = p.relay.posted.filter { LegacyBootstrapAttacker.isRatchetBody(it) }
        assertEquals(sent.size, ratchetBodies.size)
        for (body in ratchetBodies) p.relay.inject(idA, body)
        assertEquals(emptyList(), p.a.pollMessages(cid).map { it.text }, "the recipient must not re-open committed messages")

        // The attack: the stored pairing secret + the recorded wires.
        val ss = storedPairingSecret(p.vaultA)
        val recovered = LegacyBootstrapAttacker.openInitiatorFirstChain(ss, p.relay.posted)
        assertEquals(
            sent, recovered,
            "KNOWN LIMITATION (legacy bootstrap): the initiator's first chain is derivable from the stored pairing " +
                "secret — removed for new pairings by the v3 plan (docs/ratchet-bootstrap-plan.md)",
        )
        // And the static text that started it.
        assertTrue("hello" in p.relay.posted.mapNotNull { LegacyBootstrapAttacker.openStatic(ss, it) })
    }

    @Test
    fun knownLimitation_legacyBootstrap_staticEnvelopeTextAroundDrOn_isRecoverableFromStoredPairingSecret() {
        val p = pairLegacy()
        // Both sides write before hearing anything: no dr-on anywhere ⇒ static envelope.
        assertTrue(p.a.sendMessage(cid, "a before dr-on"))
        assertTrue(p.b.sendMessage(cid, "b before dr-on"))
        assertFalse(p.relay.sawRatchetWire, "precondition: nothing ratcheted yet")
        assertEquals(listOf("b before dr-on"), p.a.pollMessages(cid).map { it.text })
        // A (responder) now has dr-on but no sending chain: its next text is the legacy
        // fallback (plan §1 T2), still on the static envelope.
        assertEquals("1", p.vaultA.getMeta(MessageManager.drOnKey(cid)))
        assertTrue(p.a.sendMessage(cid, "a after dr-on, before its first ratchet receive"))
        assertFalse(p.relay.sawRatchetWire, "precondition: the responder fell back to the static envelope")
        assertEquals(
            listOf("a before dr-on", "a after dr-on, before its first ratchet receive"),
            p.b.pollMessages(cid).map { it.text },
        )

        val ssFromA = storedPairingSecret(p.vaultA)
        val ssFromB = storedPairingSecret(p.vaultB)
        for (ss in listOf(ssFromA, ssFromB)) {
            val recovered = p.relay.posted.mapNotNull { LegacyBootstrapAttacker.openStatic(ss, it) }
            assertEquals(
                setOf("a before dr-on", "b before dr-on", "a after dr-on, before its first ratchet receive"),
                recovered.toSet(),
                "KNOWN LIMITATION (legacy bootstrap): static-envelope text opens with the stored pairing secret " +
                    "from either vault — removed for new pairings by the v3 plan (docs/ratchet-bootstrap-plan.md)",
            )
        }
    }

    /** The attacker is not a blanket decryptor: a secret from a DIFFERENT pairing opens nothing. */
    @Test
    fun attackerHelpers_needTheRealPairingSecret() {
        val p = pairLegacy()
        assertTrue(p.a.sendMessage(cid, "hello"))
        assertEquals(listOf("hello"), p.b.pollMessages(cid).map { it.text })
        assertTrue(p.b.sendMessage(cid, "ratcheted"))
        val wrong = generateSecureRandom(32)
        assertEquals(emptyList(), LegacyBootstrapAttacker.openInitiatorFirstChain(wrong, p.relay.posted))
        assertEquals(emptyList(), p.relay.posted.mapNotNull { LegacyBootstrapAttacker.openStatic(wrong, it) })
    }
}
