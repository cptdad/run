package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Pins the paired-contact vault transaction. Guards the exact drift that hit
 * iOS — a hardcoded trustLevel/lifetime diverging from Android's VaultSeedDefaults
 * — plus the inbox-row shape (directions, caps, both-channel pairs, optionality).
 */
class PairingVaultTest {

    private val secret = ByteArray(32) { (it + 3).toByte() }

    private fun saveFull(vault: VaultDatabase, peerInbox: String? = "peer-in", peerCtl: String? = "peer-ctl") {
        PairingVault.savePairedContact(
            vault = vault,
            contactId = "c1",
            sharedSecret = secret,
            peerInboxId = peerInbox,
            peerWriteCap = peerInbox?.let { "peer-wcap" },
            peerCtlInboxId = peerCtl,
            peerCtlWriteCap = peerCtl?.let { "peer-cwcap" },
            myInboxId = "my-in",
            myReadCap = "my-rcap",
            myCtlInboxId = "my-ctl-in",
            myCtlReadCap = "my-ctl-rcap",
            alias = "Alias One",
            mnemonic = "note",
        )
    }

    @Test
    fun savePairedContact_usesVaultSeedDefaults_notHardcodedValues() {
        val vault = InMemoryVault()
        saveFull(vault)
        val c = vault.getContact("c1")!!
        assertEquals(VaultSeedDefaults.DEFAULT_TRUST_LEVEL, c.trustLevel, "trustLevel must come from VaultSeedDefaults")
        assertEquals("Alias One", c.alias)
        assertEquals("note", c.mnemonic)
        assertTrue(c.sharedSecret.contentEquals(secret))
        // fresh anti-replay state
        assertEquals(0L, c.outboundCounter)
        assertEquals(0L, c.inboundCounter)
        assertEquals("", c.inboundEpoch)
        assertNull(c.vouchedByContactId)

        // inbox lifetime = createdAt + INBOX_LIFETIME_MS (not a hardcoded literal)
        val my = vault.inboxes.first { it.inboxId == "my-in" }
        assertEquals(my.createdAt + VaultSeedDefaults.INBOX_LIFETIME_MS, my.expiresAt)
    }

    @Test
    fun savePairedContact_writesAllFourInboxRows_withCorrectDirectionsAndCaps() {
        val vault = InMemoryVault()
        saveFull(vault)
        assertEquals(4, vault.inboxes.size, "expected peer out+ctl-out and our in+ctl-in")

        val out = vault.inboxes.first { it.inboxId == "peer-in" }
        assertEquals("outbound", out.direction); assertEquals("peer-wcap", out.cap)
        val ctlOut = vault.inboxes.first { it.inboxId == "peer-ctl" }
        assertEquals(MessageManager.DIR_OUTBOUND_CTL, ctlOut.direction); assertEquals("peer-cwcap", ctlOut.cap)
        val inb = vault.inboxes.first { it.inboxId == "my-in" }
        assertEquals("inbound", inb.direction); assertEquals("my-rcap", inb.cap)
        val ctlIn = vault.inboxes.first { it.inboxId == "my-ctl-in" }
        assertEquals(MessageManager.DIR_INBOUND_CTL, ctlIn.direction); assertEquals("my-ctl-rcap", ctlIn.cap)
    }

    @Test
    fun savePairedContact_secretOnly_skipsPeerRows_keepsOurRows() {
        val vault = InMemoryVault()
        saveFull(vault, peerInbox = null, peerCtl = null)
        // Only OUR two inbox rows; the peer's inbox arrives later via announce.
        assertEquals(2, vault.inboxes.size)
        assertNull(vault.inboxes.firstOrNull { it.direction == "outbound" })
        assertTrue(vault.inboxes.any { it.direction == "inbound" })
        assertTrue(vault.inboxes.any { it.direction == MessageManager.DIR_INBOUND_CTL })
    }

    @Test
    fun savePairedContact_marksRatchetCapable() {
        val vault = InMemoryVault()
        saveFull(vault)
        assertTrue(vault.meta.isNotEmpty(), "markRatchetCapable should have written a meta flag")
    }

    // The whole write sequence is ONE transaction, so a
    // torn add (a later insertInboxId throwing) must leave NO orphan contact row —
    // and therefore no live 32-byte pairing sharedSecret — behind in the vault.
    @Test
    fun savePairedContact_abortedWrite_rollsBackLeavingNoOrphanContactOrSecret() {
        val v = RollbackVault()
        v.failInsertInboxOnCall = 1   // fail on the FIRST inbox write, right after insertContact
        var threw = false
        try { saveFull(v) } catch (_: Throwable) { threw = true }
        assertTrue(threw, "the injected write failure must propagate to the caller (@Throws)")
        assertNull(v.getContact("c1"), "an aborted add must leave NO orphan contact row / live pairing secret")
        assertTrue(v.inner.inboxes.isEmpty(), "no inbox rows may survive a rolled-back add")
        assertTrue(v.inner.meta.isEmpty(), "no ratchet marker may survive a rolled-back add")
    }

    // --- The ownership gate -------------------------------------------
    //
    // `inbox_ids` is keyed by inboxId with replace-on-conflict, so a peer-supplied
    // id that already exists would SILENTLY overwrite that row — reassigning it to
    // the brand-new contact, flipping its direction and destroying the stored
    // capability. savePairedContact had no ownership check at all. A rejection must
    // write NOTHING (brick-safety: refusing an add may never damage the vault).

    private fun assertNothingWritten(vault: InMemoryVault, seededInboxRows: Int) {
        assertNull(vault.getContact("c1"), "a refused add must leave no contact row / live pairing secret")
        assertEquals(seededInboxRows, vault.inboxes.size, "a refused add must write no inbox rows")
        assertTrue(vault.meta.isEmpty(), "a refused add must write no ratchet marker")
    }

    @Test
    fun savePairedContact_rejectsPeerInboxOwnedByAnotherContact() {
        val vault = InMemoryVault()
        // A real, fully-paired victim we already send to.
        vault.insertContact(ContactRecord("victim", ByteArray(32) { 9 }, 0, "Victim", 0L))
        vault.insertInboxId(InboxIdRecord("peer-in", "victim", 1L, Long.MAX_VALUE, "outbound", "victim-wcap"))

        var threw = false
        try { saveFull(vault) } catch (_: InboxInUseException) { threw = true }
        assertTrue(threw, "an inbox id owned by another contact must be refused")

        // The victim's route is untouched…
        val row = vault.getInboxId("peer-in")!!
        assertEquals("victim", row.contactId)
        assertEquals("outbound", row.direction)
        assertEquals("victim-wcap", row.cap)
        // …and the refused add left nothing behind (1 seeded inbox row).
        assertNothingWritten(vault, seededInboxRows = 1)
        assertNotNull(vault.getContact("victim"))
    }

    @Test
    fun savePairedContact_rejectsPeerCtlInboxEqualToOurOwnInbox() {
        // The cross-pair PairingPayload.parse does NOT catch: it only compares the
        // peer's MESSAGE inbox against myInboxId. A peer echoing our message inbox
        // back as its CONTROL inbox would collide our inbound row on the same PK.
        val vault = InMemoryVault()
        var threw = false
        try {
            PairingVault.savePairedContact(
                vault = vault, contactId = "c1", sharedSecret = secret,
                peerInboxId = "peer-in", peerWriteCap = "peer-wcap",
                peerCtlInboxId = "my-in", peerCtlWriteCap = "peer-cwcap",
                myInboxId = "my-in", myReadCap = "my-rcap",
                myCtlInboxId = "my-ctl-in", myCtlReadCap = "my-ctl-rcap",
                alias = "Alias One",
            )
        } catch (_: InboxInUseException) { threw = true }
        assertTrue(threw, "a peer ctl inbox equal to our own inbox must be refused")
        assertNothingWritten(vault, seededInboxRows = 0)
    }

    @Test
    fun savePairedContact_rejectsOurOwnTwoInboxesBeingIdentical() {
        // Self-inflicted (a mint bug / a caller wiring the same id twice) rather
        // than hostile, but the consequence is the same destroyed row, so it is
        // refused rather than written half-way.
        val vault = InMemoryVault()
        var threw = false
        try {
            PairingVault.savePairedContact(
                vault = vault, contactId = "c1", sharedSecret = secret,
                peerInboxId = "peer-in", peerWriteCap = "peer-wcap",
                peerCtlInboxId = "peer-ctl", peerCtlWriteCap = "peer-cwcap",
                myInboxId = "my-in", myReadCap = "my-rcap",
                myCtlInboxId = "my-in", myCtlReadCap = "my-ctl-rcap",
                alias = "Alias One",
            )
        } catch (_: InboxInUseException) { threw = true }
        assertTrue(threw, "our own inbox and control-inbox ids must differ")
        assertNothingWritten(vault, seededInboxRows = 0)
    }

    @Test
    fun savePairedContact_secretOnlyScan_stillAcceptedWhenOurIdsAreFresh() {
        // No-false-positive proof for the optional-peer-rows branch: the claim set
        // must NARROW with the write set, not stay wide and reject a legitimate
        // secret-only pairing.
        val vault = InMemoryVault()
        vault.insertContact(ContactRecord("victim", ByteArray(32) { 9 }, 0, "Victim", 0L))
        vault.insertInboxId(InboxIdRecord("peer-in", "victim", 1L, Long.MAX_VALUE, "outbound", "victim-wcap"))
        saveFull(vault, peerInbox = null, peerCtl = null)
        assertNotNull(vault.getContact("c1"))
        assertEquals(3, vault.inboxes.size, "the victim row plus our two fresh rows")
    }
}

/**
 * Test double: an [InMemoryVault] decorator that gives
 * [withTransaction] REAL snapshot/rollback semantics (the base stub merely runs
 * the block) plus write-failure injection, so an aborted pairing can be proven to
 * leave no partial state. Mirrors what a real SQLCipher transaction (Android) /
 * the putStringsSync journal (iOS) delivers.
 */
internal class RollbackVault(val inner: InMemoryVault = InMemoryVault()) : VaultDatabase by inner {
    /** 1-based index of the insertInboxId call that should throw; 0 disables. */
    var failInsertInboxOnCall: Int = 0
    private var inboxCalls = 0

    override fun withTransaction(block: () -> Unit) {
        val c = inner.contacts.toMap()
        val i = inner.inboxes.toList()
        val g = inner.groups.toMap()
        val gm = inner.groupMembers.toList()
        val m = inner.meta.toMap()
        try {
            block()
        } catch (e: Throwable) {
            inner.contacts.clear(); inner.contacts.putAll(c)
            inner.inboxes.clear(); inner.inboxes.addAll(i)
            inner.groups.clear(); inner.groups.putAll(g)
            inner.groupMembers.clear(); inner.groupMembers.addAll(gm)
            inner.meta.clear(); inner.meta.putAll(m)
            throw e
        }
    }

    override fun insertInboxId(record: InboxIdRecord): Long {
        if (++inboxCalls == failInsertInboxOnCall) throw RuntimeException("inbox id write failed (injected)")
        return inner.insertInboxId(record)
    }
}
