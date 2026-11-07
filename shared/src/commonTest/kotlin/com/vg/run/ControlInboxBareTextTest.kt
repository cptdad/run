package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals

// ---------------------------------------------------------------------------
// a bare TEXT envelope — no
// control kind AND no group id — has no legitimate reason to arrive on the
// CONTROL inbox. The control inbox carries only k/b control messages
// (env.controlKind != null) and group-tagged blobs (env.groupId != null —
// sendGroupText routes group TEXT over the normal 1:1 channel via
// sendEnvelope(control = false); only sendGroupControl sets control = true,
// and it always includes "g"). Before this fix a bare text sailed through and
// fed GroupManager.pendingDirect's unbounded buffer (see
// PendingBufferCapTest) even with no conversation ever open.
//
// Mirrors AntiSpliceReplayTest's harness style: seal a REAL envelope (real
// AEAD, real padding, real counters, correctly "ch"/"di"-bound so only the
// NEW gate under test can be responsible for a drop) and drive it through a
// real pollControlMessages/pollMessages, asserting the RECEIVER's behaviour —
// not the parser's.
// ---------------------------------------------------------------------------

private const val CIB_CTL_IN  = "CIBCTLinnnnnnnnnnnnnnnnnnnnnnnnn"
private const val CIB_CAP     = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
private val CIB_ANNOUNCE_IB   = "CIBANNC".padEnd(32, 'y')
private val CIB_ANNOUNCE_WC   = "C".repeat(43)
private val CIB_GROUP_ID      = "g".repeat(32)   // isValidGroupId == isValidInboxId: exactly 32 chars
private val CIB_MEMBERSHIP_HASH = "h".repeat(16)

/** Seals [envelopeJson] exactly as the production sender does (see AntiSpliceReplayTest). */
private fun cibSealEnvelope(sharedSecret: ByteArray, envelopeJson: String): String {
    val key = sha256(sharedSecret)
    val ctx = sha256(key + "message-aead".encodeToByteArray())
    return encodeBase64(aesGcmEncrypt(padMessage(envelopeJson.encodeToByteArray()), key, ctx))
}

private fun cibEpochFor(sharedSecret: ByteArray): String =
    bytesToHex(sha256(sharedSecret + "msg-epoch".encodeToByteArray()).copyOfRange(0, 6))

/** Receiver B, paired with A, holding only a control inbound inbox (a text poll is
 *  not exercised by these tests). */
private class ControlBareTextHarness {
    val shared = generateSecureRandom(32)
    val vault = InMemoryVault()
    val http = RecordingRelayHttp()
    val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)
    val epoch = cibEpochFor(shared)

    init {
        vault.insertContact(ContactRecord("a", shared, 0, "A", 0L))
        vault.insertInboxId(
            InboxIdRecord(CIB_CTL_IN, "a", 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_CTL, CIB_CAP)
        )
    }

    fun serve(blob: String) {
        http.script(HttpResult(200, """{"blobs":["$blob"]}""", true))
    }

    /** A correctly channel/inbox-bound control-inbox envelope; [extraFields] carries
     *  "g"/"h"/"k"/"b" verbatim as production senders serialize them (see
     *  sendGroupControl / sendDirectControl / sendInboxAnnounce). */
    fun envelope(counter: Long, text: String, extraFields: String = ""): String =
        cibSealEnvelope(
            shared,
            """{"e":"$epoch","c":$counter,"t":0,"ch":"c","di":"$CIB_CTL_IN"$extraFields,"m":"$text"}""",
        )
}

class ControlInboxBareTextTest {

    @Test
    fun bareTextEnvelope_onControlInbox_isDropped() {
        if (!aeadUp()) return
        val h = ControlBareTextHarness()
        // No "g", no "k" — a bare 1:1 text, otherwise correctly sealed and bound to
        // the control inbox: exactly what an authenticated-peer attacker posts.
        h.serve(h.envelope(counter = 1, text = "bare-on-control"))

        val surfaced = h.mgr.pollControlMessages("a")

        assertEquals(0, surfaced.size, "a bare text has no legitimate reason to be on the control inbox")
        assertEquals(
            0L, h.vault.getContact("a")!!.inboundCtlCounter,
            "a dropped bare text must not advance the control counter",
        )
    }

    @Test
    fun groupTaggedBareText_onControlInbox_isDroppedToo() {
        if (!aeadUp()) return
        val h = ControlBareTextHarness()
        // a GROUP-TAGGED envelope with no "k" — the guard
        // used to require `groupId == null` too, so this sailed through and reached
        // GroupManager.acceptGroupText on the BACKGROUND sweep (no conversation
        // open), which parked it in the FIX-B unresolved buffer. Nothing legitimate
        // produces one: sendGroupText routes group TEXT over the 1:1 channel
        // (control = false) and sendGroupControl always writes "k".
        h.serve(
            h.envelope(
                counter = 1, text = "group-tagged-bare",
                extraFields = ""","g":"$CIB_GROUP_ID","h":"$CIB_MEMBERSHIP_HASH"""",
            )
        )

        val surfaced = h.mgr.pollControlMessages("a")

        assertEquals(0, surfaced.size, "a group-tagged bare text has no legitimate reason to be on the control inbox")
        assertEquals(
            0L, h.vault.getContact("a")!!.inboundCtlCounter,
            "a dropped bare text must not advance the control counter",
        )
    }

    @Test
    fun groupTaggedControl_onControlInbox_stillApplies() {
        if (!aeadUp()) return
        val h = ControlBareTextHarness()
        // groupId != null (a real group control, e.g. an activity notice) must NOT
        // be caught by the new bare-text gate — only group-LESS, control-kind-LESS
        // envelopes are dropped.
        h.serve(
            h.envelope(
                counter = 1, text = "",
                extraFields = ""","g":"$CIB_GROUP_ID","h":"$CIB_MEMBERSHIP_HASH","k":"act","b":"{}"""",
            )
        )

        val surfaced = h.mgr.pollControlMessages("a")

        assertEquals(1, surfaced.size, "a group-tagged control must still be surfaced to the caller (GroupManager.ingest)")
        assertEquals(CIB_GROUP_ID, surfaced[0].groupId)
        assertEquals("act", surfaced[0].controlKind)
        assertEquals(1L, h.vault.getContact("a")!!.inboundCtlCounter)
    }

    @Test
    fun directInboxAnnounce_onControlInbox_stillApplies() {
        if (!aeadUp()) return
        val h = ControlBareTextHarness()
        // controlKind != null (an inbox announce) with groupId == null must also
        // survive the new gate — it is APPLIED (never surfaced as a message), so the
        // proof it wasn't dropped is the control counter advancing.
        val body = """{"ib":"$CIB_ANNOUNCE_IB","wc":"$CIB_ANNOUNCE_WC"}"""
        h.serve(
            h.envelope(
                counter = 1, text = "",
                extraFields = ""","k":"inbox","b":${jsonEscapeString(body)}""",
            )
        )

        val surfaced = h.mgr.pollControlMessages("a")

        assertEquals(0, surfaced.size, "an inbox announce is applied, never surfaced, same as before this fix")
        assertEquals(
            1L, h.vault.getContact("a")!!.inboundCtlCounter,
            "the announce must still have been PROCESSED (counter advanced), not silently dropped by the new gate",
        )
    }
}
