package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// End-to-end anti-splice / anti-replay tests.
//
// These are the highest-value defenses in MessageManager, and until now they
// rested on PARSE-ONLY unit tests: ChannelBindingTest asserted that
// parseEnvelope READS the "ch" field, and nothing anywhere sealed a mismatched
// blob and actually polled it. A regression that dropped the enforcement while
// keeping the parsing would have passed the whole suite.
//
// Each test below seals a real blob (real AEAD, real padding, real counters) and
// feeds it to a real pollMessages/pollControlMessages, asserting the RECEIVER's
// behaviour — accept or drop — not the parser's.
// ---------------------------------------------------------------------------

private const val SPL_MAIN_IN  = "SPLMAINinnnnnnnnnnnnnnnnnnnnnnnn"
private const val SPL_MAIN_OUT = "SPLMAINouttttttttttttttttttttttt"
private const val SPL_CTL_IN   = "SPLCTLinnnnnnnnnnnnnnnnnnnnnnnnn"
private const val SPL_CAP      = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

/**
 * Seals [envelopeJson] exactly as the production sender does — sha256(secret) key,
 * the "message-aead" context, bucket padding — so the receiver's decrypt path is
 * fully exercised and only the FIELDS under test differ.
 */
private fun sealEnvelope(sharedSecret: ByteArray, envelopeJson: String): String {
    val key = sha256(sharedSecret)
    val ctx = sha256(key + "message-aead".encodeToByteArray())
    return encodeBase64(aesGcmEncrypt(padMessage(envelopeJson.encodeToByteArray()), key, ctx))
}

/** The epoch the receiver will expect for this secret (mirrors messageEpoch). */
private fun epochFor(sharedSecret: ByteArray): String =
    bytesToHex(sha256(sharedSecret + "msg-epoch".encodeToByteArray()).copyOfRange(0, 6))

/** Receiver B, paired with A, holding a main + control inbound inbox. */
private class SpliceHarness(ctlInboxId: String = SPL_CTL_IN) {
    val shared = generateSecureRandom(32)
    val vault = InMemoryVault()
    val http = RecordingRelayHttp()
    val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)
    val epoch = epochFor(shared)

    init {
        vault.insertContact(ContactRecord("a", shared, 0, "A", 0L))
        vault.insertInboxId(InboxIdRecord(SPL_MAIN_IN, "a", 1L, Long.MAX_VALUE, "inbound", SPL_CAP))
        vault.insertInboxId(
            InboxIdRecord(ctlInboxId, "a", 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_CTL, SPL_CAP)
        )
    }

    /** Script one poll response carrying [blobs]. */
    fun serve(vararg blobs: String) {
        http.script(HttpResult(200, """{"blobs":[${blobs.joinToString(",") { "\"$it\"" }}]}""", true))
    }

    fun envelope(
        counter: Long,
        text: String,
        channel: String? = MessageManager.CHANNEL_TAG_MAIN,
        destInbox: String? = SPL_MAIN_IN,
        epochOverride: String? = null,
    ): String {
        val ch = channel?.let { ""","ch":"$it"""" } ?: ""
        val di = destInbox?.let { ""","di":"$it"""" } ?: ""
        return sealEnvelope(
            shared,
            """{"e":"${epochOverride ?: epoch}","c":$counter,"t":0$ch$di,"m":"$text"}""",
        )
    }
}

class AntiSpliceReplayTest {

    @Test
    fun crossChannelSplice_mainTaggedBlobOnControlInbox_isDropped() {
        if (!aeadUp()) return
        // The control inbox deliberately shares the MAIN inbox id here, so the "di"
        // binding PASSES and this test isolates the "ch" check: a relay moving an
        // authentic text blob onto the control inbox must still be caught, because
        // the two channels keep independent counter spaces and the replay check
        // alone would let it through.
        val h = SpliceHarness(ctlInboxId = SPL_MAIN_IN)
        h.serve(h.envelope(counter = 1, text = "spliced", channel = MessageManager.CHANNEL_TAG_MAIN))

        val surfaced = h.mgr.pollControlMessages("a")

        assertEquals(0, surfaced.size, "a main-tagged blob must not be accepted on the control inbox")
        assertEquals(0L, h.vault.getContact("a")!!.inboundCtlCounter,
            "a dropped splice must not advance the control counter")
    }

    @Test
    fun reflectedOwnOutboundBlob_onInboundInbox_isDroppedByInboxBinding() {
        if (!aeadUp()) return
        // A hostile relay reflects a blob addressed to a DIFFERENT inbox of the same
        // pairing back onto the one we poll. "ch" cannot catch this (both are "m");
        // only the sealed destination-inbox id can.
        val h = SpliceHarness()
        h.serve(h.envelope(counter = 1, text = "reflected", destInbox = SPL_MAIN_OUT))

        val surfaced = h.mgr.pollMessages("a")

        assertEquals(0, surfaced.size, "a blob sealed for another inbox must be dropped")
        assertEquals(0L, h.vault.getContact("a")!!.inboundCounter)
    }

    @Test
    fun matchingChannelAndInbox_isAccepted() {
        if (!aeadUp()) return
        // The control: with both bindings correct the same machinery ACCEPTS, so the
        // drops above are the bindings working — not the harness failing to decrypt.
        val h = SpliceHarness()
        h.serve(h.envelope(counter = 1, text = "legit"))

        val surfaced = h.mgr.pollMessages("a")

        assertEquals(1, surfaced.size)
        assertEquals("legit", surfaced[0].text)
        assertEquals(1L, h.vault.getContact("a")!!.inboundCounter)
    }

    @Test
    fun untaggedBlob_fromChannelTagCapablePeer_isDropped() {
        if (!aeadUp()) return
        // Once a peer has demonstrably tagged its channels, an UNTAGGED blob is a
        // relay downgrade or a replayed pre-channel-binding blob — not a legacy peer. Drop it.
        val h = SpliceHarness()
        h.serve(h.envelope(counter = 1, text = "tagged"))
        assertEquals(1, h.mgr.pollMessages("a").size)      // marks the peer capable

        h.serve(h.envelope(counter = 2, text = "downgraded", channel = null))
        val surfaced = h.mgr.pollMessages("a")

        assertEquals(0, surfaced.size, "untagged blob from a tag-capable peer must be dropped")
        assertEquals(1L, h.vault.getContact("a")!!.inboundCounter, "counter must not advance on a drop")
    }

    @Test
    fun staleEpochBlob_isDropped() {
        if (!aeadUp()) return
        // A blob from a PREVIOUS shared secret being replayed after a re-pair. It
        // still decrypts here (same key in this fixture), so only the sealed epoch
        // distinguishes it.
        val h = SpliceHarness()
        h.serve(h.envelope(counter = 1, text = "old-epoch", epochOverride = "deadbeefcafe"))

        assertEquals(0, h.mgr.pollMessages("a").size)
        assertEquals(0L, h.vault.getContact("a")!!.inboundCounter)
    }

    @Test
    fun replayedCounter_isDropped() {
        if (!aeadUp()) return
        val h = SpliceHarness()
        h.serve(h.envelope(counter = 1, text = "first"))
        assertEquals(1, h.mgr.pollMessages("a").size)

        // The relay re-serves the very same counter — strict-monotonic must reject.
        h.serve(h.envelope(counter = 1, text = "first"))
        assertEquals(0, h.mgr.pollMessages("a").size, "counter 1 must not be accepted twice")
        assertEquals(1L, h.vault.getContact("a")!!.inboundCounter)
    }

    @Test
    fun outOfOrderBlobsInOneDrain_areSortedAndBothAccepted() {
        if (!aeadUp()) return
        // The relay serves the HIGH counter first. Without the in-drain sort the
        // higher one would be accepted and the lower one then rejected as a replay,
        // silently losing a real message.
        val h = SpliceHarness()
        h.serve(
            h.envelope(counter = 2, text = "second"),
            h.envelope(counter = 1, text = "first"),
        )

        val surfaced = h.mgr.pollMessages("a")

        assertEquals(2, surfaced.size, "both messages must survive an out-of-order drain")
        assertEquals(listOf("first", "second"), surfaced.map { it.text })
        assertEquals(2L, h.vault.getContact("a")!!.inboundCounter)
    }

    @Test
    fun skippedCounter_isAcceptedAndFlaggedAsAGap() {
        if (!aeadUp()) return
        // Counter gaps are TOLERATED (a send can persist its counter and then fail
        // to transmit), but surfaced: the receiver flags the gap rather than
        // silently pretending the stream was continuous.
        val h = SpliceHarness()
        h.serve(h.envelope(counter = 1, text = "first"))
        assertEquals(1, h.mgr.pollMessages("a").size)

        h.serve(h.envelope(counter = 5, text = "after-gap"))
        val surfaced = h.mgr.pollMessages("a")

        assertEquals(1, surfaced.size)
        assertTrue(surfaced[0].sequenceGap, "a skipped counter must be reported as a sequence gap")
        assertEquals(5L, h.vault.getContact("a")!!.inboundCounter)
    }
}
