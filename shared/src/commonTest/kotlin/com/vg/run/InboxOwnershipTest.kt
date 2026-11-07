package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

// ---------------------------------------------------------------------------
// The ownership gate every `inbox_ids` write goes through.
//
// `inbox_ids.inbox_id` is the PRIMARY KEY with replace-on-conflict on BOTH
// platforms, so writing a peer-supplied id that already exists silently
// overwrites that row (direction flipped, contactId reassigned, capability
// destroyed) and nothing throws. These tests pin exactly which claims are
// refused — and, just as importantly, which are NOT, because a false positive
// here breaks pairing / cap rotation outright.
// ---------------------------------------------------------------------------

private const val OWN_ID_1 = "o1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
private const val OWN_ID_2 = "o2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
private const val OWN_ID_3 = "o3AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
private val OWN_CAP = "K".repeat(43)

class InboxOwnershipTest {

    private fun vaultWith(vararg rows: InboxIdRecord): InMemoryVault {
        val v = InMemoryVault()
        for (r in rows) v.insertInboxId(r)
        return v
    }

    private fun row(id: String, contact: String, direction: String, expiresAt: Long = Long.MAX_VALUE) =
        InboxIdRecord(id, contact, 1L, expiresAt, direction, OWN_CAP)

    @Test
    fun unknownInboxId_isAvailable() {
        // The normal first-announce / fresh-pairing case. Rejecting it would break
        // pairing outright, so this is the load-bearing NEGATIVE case.
        val v = vaultWith(row(OWN_ID_1, "alice", "outbound"))
        assertNull(firstUnavailableInboxClaim(v, listOf(InboxClaim(OWN_ID_2, "bob", "outbound"))))
    }

    @Test
    fun sameContactSameDirection_isAvailable_capRotationAndReAnnounce() {
        // A rightful owner re-announcing its own id (rotated write cap, post-404
        // re-announce) must still land — the row is upserted in place.
        val v = vaultWith(row(OWN_ID_1, "alice", "outbound"))
        assertNull(firstUnavailableInboxClaim(v, listOf(InboxClaim(OWN_ID_1, "alice", "outbound"))))
    }

    @Test
    fun anotherContactsRow_isUnavailable() {
        // An authenticated peer naming a THIRD party's inbox id.
        val v = vaultWith(row(OWN_ID_1, "alice", "outbound"))
        val bad = assertNotNull(firstUnavailableInboxClaim(v, listOf(InboxClaim(OWN_ID_1, "bob", "outbound"))))
        assertEquals(OWN_ID_1, bad.inboxId)
        assertEquals("bob", bad.contactId)
    }

    @Test
    fun sameContactWrongDirection_isUnavailable() {
        // The row survives the PK collision only by being overwritten, so a claim
        // that would change the direction of an existing row is a destructive write
        // even when the contact matches (it would silently drop the other channel).
        val v = vaultWith(row(OWN_ID_1, "alice", MessageManager.DIR_OUTBOUND_CTL))
        assertNotNull(firstUnavailableInboxClaim(v, listOf(InboxClaim(OWN_ID_1, "alice", "outbound"))))
    }

    @Test
    fun ourOwnInboundRow_isUnavailable() {
        // A relay reflecting our own announce back at us would
        // repoint our sends at our own inbox and overwrite our READ capability.
        val v = vaultWith(row(OWN_ID_1, "alice", "inbound"))
        assertNotNull(firstUnavailableInboxClaim(v, listOf(InboxClaim(OWN_ID_1, "alice", "outbound"))))
        val v2 = vaultWith(row(OWN_ID_2, "alice", MessageManager.DIR_INBOUND_CTL))
        assertNotNull(firstUnavailableInboxClaim(v2, listOf(InboxClaim(OWN_ID_2, "alice", MessageManager.DIR_OUTBOUND_CTL))))
    }

    @Test
    fun duplicateIdWithinOneBatch_isUnavailable() {
        // Nothing is stored yet, so a per-id check against the vault passes both
        // claims — and the second insert then REPLACES the first. Caught here.
        val v = InMemoryVault()
        val bad = assertNotNull(
            firstUnavailableInboxClaim(
                v,
                listOf(
                    InboxClaim(OWN_ID_1, "bob", "outbound"),
                    InboxClaim(OWN_ID_1, "bob", MessageManager.DIR_OUTBOUND_CTL),
                ),
            )
        )
        // The SECOND claim is the one reported — the first is legitimately writable.
        assertEquals(MessageManager.DIR_OUTBOUND_CTL, bad.direction)
    }

    @Test
    fun expiredRow_stillBlocks_becauseThePrimaryKeyIsStillOccupied() {
        // getInboxId is the PK lookup and is deliberately NOT expiry-filtered
        // (unlike getInboxIdForContact): an expired row is still overwritten by an
        // INSERT OR REPLACE, so it must still block.
        val v = vaultWith(row(OWN_ID_1, "alice", "outbound", expiresAt = 1L))
        assertNotNull(firstUnavailableInboxClaim(v, listOf(InboxClaim(OWN_ID_1, "bob", "outbound"))))
    }

    @Test
    fun emptyBatch_isAvailable() {
        assertNull(firstUnavailableInboxClaim(vaultWith(row(OWN_ID_1, "alice", "outbound")), emptyList()))
    }

    @Test
    fun allFreshBatch_isAvailable() {
        // A genuine re-pair mints a fresh contactId AND fresh inbox ids on both
        // platforms — the four-row pairing batch must pass untouched.
        val v = vaultWith(row(OWN_ID_1, "alice", "outbound"))
        assertNull(
            firstUnavailableInboxClaim(
                v,
                listOf(
                    InboxClaim(OWN_ID_2, "bob", "inbound"),
                    InboxClaim(OWN_ID_3, "bob", MessageManager.DIR_INBOUND_CTL),
                    InboxClaim("n1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "bob", "outbound"),
                    InboxClaim("n2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "bob", MessageManager.DIR_OUTBOUND_CTL),
                ),
            )
        )
    }
}
