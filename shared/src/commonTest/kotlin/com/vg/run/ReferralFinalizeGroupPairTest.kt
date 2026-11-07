package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// The GROUP inbox pair through a referral finalize — each half independently
// optional (our stored accept may carry no grp mint; the peer may announce none),
// and a collision on either grp id is the same TERMINAL, write-nothing rejection
// as a collision on the text or control ids. Pinned before the finalize's
// transaction body is split into helpers.
// ---------------------------------------------------------------------------

private val FG_PEER_IB = "in" + "A".repeat(30)
private val FG_PEER_CIB = "ct" + "B".repeat(30)
private val FG_PEER_GIB = "gr" + "P".repeat(30)
private val FG_MY_GIB = "gr" + "Q".repeat(30)

private fun fgMint(withGrp: Boolean) = MintedInboxPair(
    MintedInbox("in" + "M".repeat(30), "R".repeat(43), "w".repeat(43), Long.MAX_VALUE),
    MintedInbox("ct" + "N".repeat(30), "S".repeat(43), "x".repeat(43), Long.MAX_VALUE),
    if (withGrp) MintedInbox(FG_MY_GIB, "T".repeat(43), "y".repeat(43), Long.MAX_VALUE) else null,
)

private fun fgAcceptBody(introId: String, peerPub: ByteArray, withGrp: Boolean): String {
    val grp = if (withGrp) ""","gib":${jsonEscapeString(FG_PEER_GIB)},"gwc":${jsonEscapeString("Z".repeat(43))}""" else ""
    return """{"ii":${jsonEscapeString(introId)},"pk":${jsonEscapeString(encodeBase64(peerPub))},""" +
        """"ib":${jsonEscapeString(FG_PEER_IB)},"wc":${jsonEscapeString("W".repeat(43))},""" +
        """"cib":${jsonEscapeString(FG_PEER_CIB)},"cwc":${jsonEscapeString("X".repeat(43))}$grp}"""
}

class ReferralFinalizeGroupPairTest {

    private val noTransport: () -> MessageManager? = { null }

    private fun accepted(vault: InMemoryVault, introId: String, withGrpMint: Boolean): ReferralManager {
        vault.insertContact(ContactRecord("alice", generateSecureRandom(32), 0, "Alice", 0L))
        val rm = ReferralManager(vault, noTransport)
        rm.handleControl(
            "alice", MessageManager.CONTROL_KIND_REFERRAL_OFFER,
            """{"ii":${jsonEscapeString(introId)},"pa":${jsonEscapeString("Running Fox")}}""",
        )
        rm.registerAccepted(introId, rm.pendingOffers().single(), x25519GenerateKeypair(), fgMint(withGrpMint))
        return rm
    }

    private fun referred(vault: InMemoryVault) = vault.getAllContacts().singleOrNull { it.contactId != "alice" }

    @Test
    fun finalize_writesBothGroupRows_whenOurMintAndThePeerBothCarryOne() {
        if (!x25519Up()) return
        val vault = InMemoryVault()
        val rm = accepted(vault, "g1", withGrpMint = true)
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_ACCEPT, fgAcceptBody("g1", x25519GenerateKeypair().publicKey, withGrp = true))

        val c = assertNotNull(referred(vault), "the referral must commit")
        val inGrp = assertNotNull(vault.getInboxIdForContact(c.contactId, MessageManager.DIR_INBOUND_GRP))
        assertEquals(FG_MY_GIB, inGrp.inboxId)
        assertEquals("T".repeat(43), inGrp.cap, "our grp row carries OUR read cap")
        val outGrp = assertNotNull(vault.getInboxIdForContact(c.contactId, MessageManager.DIR_OUTBOUND_GRP))
        assertEquals(FG_PEER_GIB, outGrp.inboxId)
        assertEquals("Z".repeat(43), outGrp.cap, "the peer's grp row carries the PEER's write cap")
        assertEquals(6, vault.inboxes.count { it.contactId == c.contactId })
    }

    @Test
    fun finalize_writesNoOutboundGrp_whenThePeerAnnouncesNone_andStillCommits() {
        if (!x25519Up()) return
        val vault = InMemoryVault()
        val rm = accepted(vault, "g2", withGrpMint = true)
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_ACCEPT, fgAcceptBody("g2", x25519GenerateKeypair().publicKey, withGrp = false))

        val c = assertNotNull(referred(vault), "a peer with no group inbox still completes the referral")
        assertNotNull(vault.getInboxIdForContact(c.contactId, MessageManager.DIR_INBOUND_GRP))
        assertNull(vault.getInboxIdForContact(c.contactId, MessageManager.DIR_OUTBOUND_GRP))
        assertEquals(5, vault.inboxes.count { it.contactId == c.contactId })
    }

    @Test
    fun finalize_grpClaimCollision_isTerminal_andWritesNothing() {
        if (!x25519Up()) return
        val vault = InMemoryVault()
        // An unrelated live contact already owns the inbox id the peer announces as `gib`.
        vault.insertContact(ContactRecord("victim", generateSecureRandom(32), 1, "Victim", 0L))
        vault.insertInboxId(InboxIdRecord(FG_PEER_GIB, "victim", 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_GRP, "V".repeat(43)))
        val rm = accepted(vault, "g3", withGrpMint = true)
        val before = vault.inboxes.toList()

        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_ACCEPT, fgAcceptBody("g3", x25519GenerateKeypair().publicKey, withGrp = true))

        assertTrue(vault.getAllContacts().none { it.contactId != "alice" && it.contactId != "victim" }, "no referred contact")
        assertEquals(before, vault.inboxes.toList(), "a rejected finalize writes no inbox row")
        assertEquals("victim", vault.getInboxId(FG_PEER_GIB)?.contactId, "the victim keeps its row")
        assertEquals("V".repeat(43), vault.getInboxId(FG_PEER_GIB)?.cap)
        // Terminal: a re-delivery of the same accept settles nothing new either.
        rm.handleControl("alice", MessageManager.CONTROL_KIND_REFERRAL_ACCEPT, fgAcceptBody("g3", x25519GenerateKeypair().publicKey, withGrp = true))
        assertEquals(before, vault.inboxes.toList())
    }
}
