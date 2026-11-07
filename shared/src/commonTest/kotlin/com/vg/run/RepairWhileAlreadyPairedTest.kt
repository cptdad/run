package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// RE-PAIR WHILE ALREADY PAIRED — the App Store 2.1(a) "both devices stuck on
// waiting after scanned code" investigation (1.6.13, repro spec
// e2e-tests/tests/adhoc/repair.ios2.spec.ts).
//
// The hypothesis under test was that the session's control-poll target list
// (the inbound-ctl inbox rows) is SNAPSHOTTED once and never refreshed, so a
// pairing minted mid-session — while other contacts already exist — is never
// polled and its peer's announce is never drained.
//
// It is NOT snapshotted (GroupManager.pollAllControls re-reads
// vault.getAllContacts() on every cycle, and MessageManager.pollChannel
// re-resolves the inbox row per call), and these tests PIN that, because the
// "optimisation" of caching that enumeration on the long-lived MessageManager /
// GroupManager instance is exactly the regression that WOULD produce the
// reported symptom:
//
//   • a contact saved AFTER the sweep loop started must be peeked/drained on
//     the very next cycle, with an older contact already present;
//   • the announce that lands on that fresh contact's control inbox must
//     complete it (awaiting → fully paired) without disturbing the existing
//     pairing;
//   • a SECOND pairing with the same peer is a second, independent
//     ContactRecord by design — it must not merge into, replace, or corrupt
//     the first one, and it must still be refused (writing nothing) if it
//     would overwrite an inbox row that is already spoken for.
//
// What these tests deliberately do NOT claim: that a device which only SHOWED
// its code can converge from the peer's announce. It cannot — the announce is
// AEAD-sealed under sha256(deriveSharedSecret(mine, theirs)) and the showing
// device does not hold the peer's half until it scans back. A minted-but-
// unsaved inbox pair has no ContactRecord, hence no key and nothing to poll.
// ---------------------------------------------------------------------------

/** 32-char base64url-alphabet inbox id derived from [tag]. */
private fun rpInbox(tag: String) = ("rp$tag".padEnd(32, 'A')).take(32)

private val OLD_CTL = rpInbox("oldctl")
private val OLD_TXT = rpInbox("oldtxt")
private val OLD_PEER_CTL = rpInbox("oldpeerctl")
private val OLD_PEER_TXT = rpInbox("oldpeertxt")
private val NEW_CTL = rpInbox("newctl")
private val NEW_TXT = rpInbox("newtxt")
// The peer's freshly minted pair, delivered by the announce.
private val PEER_TXT = rpInbox("peertxt")
private val PEER_CTL = rpInbox("peerctl")

private val CAP_R = "R".repeat(43)
private val CAP_W = "W".repeat(43)
private val PEER_TXT_WCAP = "P".repeat(43)
private val PEER_CTL_WCAP = "Q".repeat(43)

/**
 * Inbox-aware relay double: records every URL and serves per-inbox queues, so a
 * test can assert WHICH inbox the sweep touched (the whole point here) and hand
 * a real announce blob to one specific control inbox.
 */
private class RepairRelay : InboxQueueRelay(
    peek = true,
    storePosts = false,
    postReply = HttpResult(code = 202, body = "", isSuccess = true),
    putReply = HttpResult(code = 200, body = "", isSuccess = true),
    deleteReply = HttpResult(code = 200, body = "", isSuccess = true),
) {
    // The control sweep PEEKS with CONTROL_PEEK_CONCURRENCY threads, so this fake is
    // called concurrently: every read and write of the call log goes through
    // [lock], or an append can be lost and `touched` flakes (seen 2026-10-26).
    private val lock = SyncLock()
    private val callLog = mutableListOf<String>()
    val calls: MutableList<String>
        get() = lock.withLock { callLog.toMutableList() }

    private fun record(call: String) = lock.withLock { callLog.add(call) }
    fun clearCalls() = lock.withLock { callLog.clear() }

    fun touched(inboxId: String) = calls.any { it.contains(inboxId) }
    fun drained(inboxId: String) =
        calls.any { it.startsWith("GET") && it.contains(inboxId) && !it.endsWith("/peek") }

    fun enqueue(inboxId: String, blobB64: String) = queue(inboxId, blobB64)

    override fun post(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult {
        record("POST $url"); return super.post(url, body, contentType, headers, timeoutSeconds)
    }
    override fun put(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult {
        record("PUT $url"); return super.put(url, body, contentType, headers, timeoutSeconds)
    }
    override fun delete(url: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult {
        record("DELETE $url"); return super.delete(url, headers, timeoutSeconds)
    }
    override fun get(url: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult {
        record("GET $url"); return super.get(url, headers, timeoutSeconds)
    }
}

/** The already-established pairing this device carries into the re-pair. */
private fun seedExistingPairing(vault: InMemoryVault, contactId: String = "old-contact") {
    vault.insertContact(ContactRecord(contactId, generateSecureRandom(32), 1, "Old", 0L))
    vault.insertInboxId(InboxIdRecord(OLD_TXT, contactId, 1L, Long.MAX_VALUE, "inbound", CAP_R))
    vault.insertInboxId(InboxIdRecord(OLD_CTL, contactId, 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_CTL, CAP_R))
    vault.insertInboxId(InboxIdRecord(OLD_PEER_TXT, contactId, 1L, Long.MAX_VALUE, "outbound", CAP_W))
    vault.insertInboxId(InboxIdRecord(OLD_PEER_CTL, contactId, 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, CAP_W))
}

/**
 * The vault state a device is in one instant after the Add Contact flow saved a
 * re-pair whose peer half is still missing (it scanned the peer's SECRET-ONLY
 * code): a brand-new ContactRecord, our freshly minted inbound + inbound-ctl
 * rows, and NO outbound rows — exactly what
 * [PairingVault.savePairedContact] writes with a null peer inbox.
 */
private fun saveRepairPairing(
    vault: VaultDatabase,
    contactId: String,
    shared: ByteArray,
    myTxt: String = NEW_TXT,
    myCtl: String = NEW_CTL,
    peerTxt: String? = null,
    peerTxtCap: String? = null,
) = PairingVault.savePairedContact(
    vault = vault,
    contactId = contactId,
    sharedSecret = shared,
    peerInboxId = peerTxt,
    peerWriteCap = peerTxtCap,
    peerCtlInboxId = null,
    peerCtlWriteCap = null,
    myInboxId = myTxt,
    myReadCap = CAP_R,
    myCtlInboxId = myCtl,
    myCtlReadCap = CAP_R,
    alias = "Repair",
)

class RepairWhileAlreadyPairedTest {

    // -----------------------------------------------------------------------
    // 1. The control sweep's target set is derived from the VAULT every cycle.
    // -----------------------------------------------------------------------

    @Test
    fun contactSavedMidSession_isPolledOnTheVeryNextSweep_withAnExistingContactPresent() {
        val vault = InMemoryVault()
        seedExistingPairing(vault)
        val relay = RepairRelay()
        // ONE long-lived MessageManager for the whole session, like the real
        // platform loops hold — so this fails if the enumeration is ever cached
        // on the instance instead of re-read.
        val mgr = MessageManager(vault, "http://relay.test", relay)
        val gm = GroupManager(vault) { mgr }

        gm.pollAllControls()
        assertTrue(relay.touched(OLD_CTL), "the established control inbox must be swept")
        assertTrue(!relay.touched(NEW_CTL), "the re-pair inbox does not exist yet")

        // …the user re-opens Add Contact and completes a second pairing.
        saveRepairPairing(vault, "repair-contact", generateSecureRandom(32))

        relay.clearCalls()
        gm.pollAllControls()
        assertTrue(
            relay.touched(NEW_CTL),
            "a control inbox minted mid-session must be swept on the NEXT cycle — the poll " +
                "targets are re-read from the vault, never snapshotted",
        )
        assertTrue(relay.touched(OLD_CTL), "the established pairing must keep being swept too")
    }

    @Test
    fun repairPairing_startsAwaitingThePeerInbox_andIsStillPolled() {
        val vault = InMemoryVault()
        seedExistingPairing(vault)
        saveRepairPairing(vault, "repair-contact", generateSecureRandom(32))
        // No outbound row yet: the peer's inbox arrives in-band (or never).
        assertTrue(contactAwaitingPeerInbox(vault, "repair-contact"))

        val relay = RepairRelay()
        val mgr = MessageManager(vault, "http://relay.test", relay)
        GroupManager(vault) { mgr }.pollAllControls()

        assertTrue(
            relay.touched(NEW_CTL),
            "an AWAITING contact must still be polled — the announce is what completes it",
        )
    }

    // -----------------------------------------------------------------------
    // 2. The announce completes the re-pair without touching the old pairing.
    // -----------------------------------------------------------------------

    @Test
    fun announceOnTheFreshControlInbox_completesTheRepair_andLeavesTheOldPairingIntact() {
        if (!aeadUp()) return
        val shared = generateSecureRandom(32)

        // The PEER: it scanned our full code, so it holds our fresh control
        // inbox as its outbound-ctl route and announces its own pair to us.
        val peerVault = InMemoryVault()
        val peerRelay = RecordingRelayHttp()
        val peerMgr = MessageManager(peerVault, "http://relay.test", peerRelay as RelayHttp)
        peerVault.insertContact(ContactRecord("us", shared, 0, "Us", 0L))
        peerVault.insertInboxId(InboxIdRecord(NEW_TXT, "us", 1L, Long.MAX_VALUE, "outbound", CAP_W))
        peerVault.insertInboxId(InboxIdRecord(NEW_CTL, "us", 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, CAP_W))
        peerRelay.script(HttpResult(code = 202, body = "", isSuccess = true))
        assertTrue(
            peerMgr.sendInboxAnnounce("us", PEER_TXT, PEER_TXT_WCAP, PEER_CTL, PEER_CTL_WCAP),
            "the peer's announce must send",
        )
        val announceBlob = encodeBase64(peerRelay.calls.last().body)

        // US: an established pairing plus the freshly saved re-pair.
        val vault = InMemoryVault()
        seedExistingPairing(vault)
        saveRepairPairing(vault, "repair-contact", shared)
        val oldRowsBefore = vault.inboxes.filter { it.contactId == "old-contact" }.map { it.inboxId to it.direction }

        val relay = RepairRelay()
        relay.enqueue(NEW_CTL, announceBlob)
        val mgr = MessageManager(vault, "http://relay.test", relay)

        assertTrue(GroupManager(vault) { mgr }.pollAllControls(), "the announce is a meaningful drain")
        assertTrue(relay.drained(NEW_CTL), "the announce must be drained from the fresh control inbox")

        val outbound = vault.getInboxIdForContact("repair-contact", "outbound")
        assertNotNull(outbound, "the announce must land the peer's text inbox")
        assertEquals(PEER_TXT, outbound.inboxId)
        assertEquals(PEER_TXT_WCAP, outbound.cap)
        assertEquals(
            PEER_CTL,
            vault.getInboxIdForContact("repair-contact", MessageManager.DIR_OUTBOUND_CTL)?.inboxId,
            "the announce must land the peer's CONTROL inbox too",
        )
        assertEquals(false, contactAwaitingPeerInbox(vault, "repair-contact"))

        // The established pairing is untouched: same rows, same directions.
        assertEquals(
            oldRowsBefore,
            vault.inboxes.filter { it.contactId == "old-contact" }.map { it.inboxId to it.direction },
            "a re-pair must never rewrite the existing pairing's routes",
        )
        assertEquals(2, vault.getAllContacts().size, "both pairings coexist")
    }

    // -----------------------------------------------------------------------
    // 3. The peer's side: a second pairing with the same person is a SECOND
    //    ContactRecord by design — independent, never a merge or an overwrite.
    // -----------------------------------------------------------------------

    @Test
    fun secondPairingWithTheSamePeer_isASecondIndependentContact() {
        val vault = InMemoryVault()
        seedExistingPairing(vault)
        val firstSecret = vault.getContact("old-contact")!!.sharedSecret.copyOf()

        saveRepairPairing(
            vault, "repair-contact", generateSecureRandom(32),
            peerTxt = PEER_TXT, peerTxtCap = PEER_TXT_WCAP,
        )

        assertEquals(2, vault.getAllContacts().size, "the re-pair adds a contact, it never replaces one")
        // The first pairing keeps its own secret and all four routes.
        assertTrue(firstSecret.contentEquals(vault.getContact("old-contact")!!.sharedSecret))
        assertEquals(OLD_TXT, vault.getInboxIdForContact("old-contact", "inbound")?.inboxId)
        assertEquals(OLD_CTL, vault.getInboxIdForContact("old-contact", MessageManager.DIR_INBOUND_CTL)?.inboxId)
        assertEquals(OLD_PEER_TXT, vault.getInboxIdForContact("old-contact", "outbound")?.inboxId)
        assertEquals(OLD_PEER_CTL, vault.getInboxIdForContact("old-contact", MessageManager.DIR_OUTBOUND_CTL)?.inboxId)
        // The second pairing has its own.
        assertEquals(NEW_TXT, vault.getInboxIdForContact("repair-contact", "inbound")?.inboxId)
        assertEquals(NEW_CTL, vault.getInboxIdForContact("repair-contact", MessageManager.DIR_INBOUND_CTL)?.inboxId)
    }

    @Test
    fun repairThatWouldOverwriteAnEstablishedRoute_isRefusedAndWritesNothing() {
        val vault = InMemoryVault()
        seedExistingPairing(vault)
        val contactsBefore = vault.getAllContacts().size
        val rowsBefore = vault.inboxes.map { it.inboxId to it.contactId }

        // A peer code naming an inbox id we already own for someone else. A GENUINE re-pair never hits this — both sides mint fresh ids —
        // so this stays a refusal, not a re-pair blocker.
        assertFailsWith<InboxInUseException> {
            saveRepairPairing(
                vault, "repair-contact", generateSecureRandom(32),
                peerTxt = OLD_PEER_TXT, peerTxtCap = CAP_W,
            )
        }
        assertEquals(contactsBefore, vault.getAllContacts().size, "a refused add writes no contact")
        assertEquals(rowsBefore, vault.inboxes.map { it.inboxId to it.contactId }, "…and no inbox rows")
    }
}
