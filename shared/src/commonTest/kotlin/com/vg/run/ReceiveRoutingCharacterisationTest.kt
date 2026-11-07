package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// Characterisation of `receiveOverTextRatchet`'s routing order: the both-Alice
// evidence is cleared and the peer's adverts are recorded from every envelope that
// DECRYPTED, before any routing drop; the drop itself consumes the message key.
// (The missing-text-row rule is pinned in DrainCharacterisationTest.)
// ---------------------------------------------------------------------------

class ReceiveRoutingCharacterisationTest {

    // RR2 + RR5 + RR6: a ratchet TEXT spliced onto the control inbox is dropped (no
    // bare text on control) — yet it is acked as authenticated, its `cr` advert is
    // recorded, the both-Alice count is cleared, and the genuine copy on the text
    // inbox no longer opens (the key was consumed by the drop).
    @Test
    fun aRatchetTextSplicedOntoTheControlInbox_isDropped_butItsEvidenceAndAdvertsCount() {
        if (!legacyEnvelopeCryptoUp()) return
        val h = LaHarness(ratchet = true)
        h.alice.deleteMeta(MessageManager.drCtlCapKey(LA))
        h.alice.putMeta(MessageManager.drRatUnackedKey(LA), "3")
        assertTrue(h.bobMgr.sendMessage(LA, "spliced"))
        val wire = h.relay.blobsOf(LA_IN_A).single()
        assertTrue(MessageManager.isRatchetWire(wire), "precondition: a ratchet text")
        val splicedId = h.relay.deliver(LA_CTL_A, wire)

        assertTrue(h.aliceMgr.pollControlMessages(LA).isEmpty(), "a bare ratchet text on the control inbox is a splice")
        assertTrue(splicedId in h.relay.ackedIds(LA_CTL_A), "it decrypted: acked like any authenticated blob")
        assertEquals("1", h.alice.getMeta(MessageManager.drCtlCapKey(LA)), "the advert is a fact about the peer")
        assertEquals(0, h.aliceMgr.ratchetUnackedCount(LA), "a decrypted blob is the both-Alice counter-evidence")
        assertTrue(h.aliceMgr.pollMessages(LA).isEmpty(), "the drop consumed the message key")
    }
}
