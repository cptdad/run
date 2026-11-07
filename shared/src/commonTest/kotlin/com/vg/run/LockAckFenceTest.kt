package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// The ACK FENCE that `IosAppController.lock()` raises BEFORE it closes the vault
// (TransportFailedSendsLockWiringSourceTest pins the order). A closed iOS vault
// does not throw — it reads as "no rows" — so a drain finishing after the close
// would take the contact for deleted and ACK its wires (a relay DELETE: lost
// mail). `MessageManager.scrubInMemory()` closes the acks; this pins that
// property, which the reorder relies on. Sibling of
// DrainCharacterisationTest.ratchetWires_ofAContactDeletedMidDrain_areAcked_andNothingIsResurrected
// (kept in its own file while that one is being edited elsewhere).
class LockAckFenceTest {

    // A teardown scrub that lands while a drain is in flight fences its acks, even
    // when the vault then reads the contact as gone (what a CLOSED iOS vault answers).
    @Test
    fun aDrainFinishingAfterTheTeardownScrub_acksNothing_evenWhenTheContactReadsGone() {
        if (!legacyEnvelopeCryptoUp()) return
        val h = LaHarness(ratchet = true)
        assertTrue(h.bobMgr.sendMessage(LA, "in flight"))
        val id = h.relay.idsOf(LA_IN_A).single()
        h.relay.beforeGet = { url ->
            if ("/inbox/$LA_IN_A?" in url) {
                h.aliceMgr.scrubInMemory()
                h.alice.deleteContact(LA)
            }
        }
        h.aliceMgr.pollMessages(LA)
        h.relay.beforeGet = null
        assertFalse(id in h.relay.ackedIds(LA_IN_A), "no ack after the teardown scrub")
        assertEquals(1, h.relay.total(LA_IN_A), "the wire is still on the relay for the next session")
    }

    // lock() scrubs twice (the fence, then endSessionRam): the scrub is idempotent.
    @Test
    fun theTeardownScrub_isIdempotent() {
        val h = LaHarness(ratchet = false)
        h.aliceMgr.scrubInMemory()
        h.aliceMgr.scrubInMemory()
    }
}
