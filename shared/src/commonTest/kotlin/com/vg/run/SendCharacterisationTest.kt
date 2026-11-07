package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// Characterisation of `sendEnvelopeSerialized`: the exact legacy envelope bytes
// and field order, the size probe's limit, the counter-before-POST rule, the
// requested-vs-used channel on a fallback, and the ratchet no-sending-chain
// fallthrough — what a split of the send must keep byte for byte.
// ---------------------------------------------------------------------------

private val SC_IN = "SCina".padEnd(32, 'a')       // our inbound text   (sorts BEFORE the outbound ⇒ ratchet role Bob)
private val SC_OUT = "SCoutz".padEnd(32, 'z')     // our outbound text  (the peer's inbox)
private val SC_OUT_CTL = "SCctlz".padEnd(32, 'z')
private val SC_OUT_GRP = "SCgrpz".padEnd(32, 'z')
private val SC_CAP = "W".repeat(43)
private val SC_GID = "G".repeat(32)

private var scSeq = 0

// One sender over a recording [FakeRelayHttp] (every append answers [answer]).
private class Tx(ctl: Boolean = true, grp: Boolean = false) {
    val cid = "sc-${++scSeq}"
    val secret = generateSecureRandom(32)
    val vault = InMemoryVault()
    var answer: HttpResult = RELAY_OK_202
    var onAppend: (FakeRelayHttp.Request) -> Unit = {}
    val relay = FakeRelayHttp(onPost = { r -> onAppend(r); answer })
    val mgr = MessageManager(vault, "http://relay.test", relay)
    val epoch = legacyEpochFor(secret)

    init {
        vault.insertContact(ContactRecord(cid, secret, 0, "B", 0L))
        vault.insertInboxId(InboxIdRecord(SC_IN, cid, 1L, Long.MAX_VALUE, "inbound", "R".repeat(43)))
        vault.insertInboxId(InboxIdRecord(SC_OUT, cid, 1L, Long.MAX_VALUE, "outbound", SC_CAP))
        if (ctl) vault.insertInboxId(InboxIdRecord(SC_OUT_CTL, cid, 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, SC_CAP))
        if (grp) vault.insertInboxId(InboxIdRecord(SC_OUT_GRP, cid, 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_GRP, SC_CAP))
    }

    fun appends(): List<FakeRelayHttp.Request> = relay.requestsOf("POST").filter { "/inbox/" in it.url }
    fun opened(r: FakeRelayHttp.Request): String = openLegacyEnvelope(secret, r.body)
    fun contact(): ContactRecord = vault.getContact(cid)!!
}

private fun sealedCounterOf(json: String): Long = Regex(""""c":(\d+)""").find(json)!!.groupValues[1].toLong()

class SendCharacterisationTest {

    // S1: the legacy envelope is exactly the template, field for field, on all three
    // channels; `t` is minute-rounded; the ttl rides only in the URL.
    @Test
    fun legacyEnvelope_bytesAndFieldOrder_areExactlyTheTemplate() {
        if (!legacyEnvelopeCryptoUp()) return

        val main = Tx()
        assertTrue(main.mgr.sendMessage(main.cid, "hi"))
        val mainPost = main.appends().single()
        val mainJson = main.opened(mainPost)
        val mainMatch = Regex("""^\{"e":"${main.epoch}","c":1,"t":(\d+),"ch":"m","di":"$SC_OUT","cr":"1","m":"hi"\}$""").find(mainJson)
        assertNotNull(mainMatch, mainJson)
        assertEquals(0L, mainMatch.groupValues[1].toLong() % 60_000L, "the timestamp is minute-rounded")
        assertTrue(mainPost.url.endsWith("/inbox/$SC_OUT"), "a text append carries no query: ${mainPost.url}")

        val ctl = Tx()
        assertTrue(ctl.mgr.sendDirectControl(ctl.cid, "ref-offer", "{}", ttlSeconds = MessageManager.CONTROL_APPEND_TTL_SECONDS))
        val ctlPost = ctl.appends().single()
        val ctlJson = ctl.opened(ctlPost)
        assertTrue(
            Regex("""^\{"e":"${ctl.epoch}","c":1,"t":\d+,"ch":"c","di":"$SC_OUT_CTL","cr":"1","k":"ref-offer","b":"\{\}","m":""\}$""").matches(ctlJson),
            ctlJson,
        )
        assertTrue(ctlPost.url.endsWith("/inbox/$SC_OUT_CTL?ttl=${MessageManager.CONTROL_APPEND_TTL_SECONDS}"), ctlPost.url)

        val grp = Tx(grp = true)
        assertTrue(grp.mgr.sendGroupText(grp.cid, SC_GID, "hash1", "hi"))
        val grpPost = grp.appends().single()
        val grpJson = grp.opened(grpPost)
        assertTrue(
            Regex("""^\{"e":"${grp.epoch}","c":1,"t":\d+,"ch":"g","di":"$SC_OUT_GRP","cr":"1","g":"$SC_GID","h":"hash1","m":"hi"\}$""").matches(grpJson),
            grpJson,
        )
        assertEquals(1L, grp.contact().outboundGrpCounter, "the group channel's own counter")
        assertEquals(0L, grp.contact().outboundCounter)
    }

    // S2: the size probe is the envelope with Long.MAX_VALUE in both numeric fields;
    // a message whose probe is exactly MAX_PADDED_PAYLOAD_BYTES is sent, one byte more
    // is refused before the counter moves or anything is POSTed.
    @Test
    fun sizeProbe_isExactlyTheEnvelopeWithMaxLongPlaceholders() {
        if (!legacyEnvelopeCryptoUp()) return
        val tx = Tx()
        val probeOverhead =
            """{"e":"${tx.epoch}","c":${Long.MAX_VALUE},"t":${Long.MAX_VALUE},"ch":"m","di":"$SC_OUT","cr":"1","m":""}"""
                .encodeToByteArray().size
        val fits = MAX_PADDED_PAYLOAD_BYTES - probeOverhead
        assertFalse(tx.mgr.sendMessage(tx.cid, "a".repeat(fits + 1)), "one byte over the probe limit")
        assertEquals(0L, tx.contact().outboundCounter, "refused before the counter bump")
        assertTrue(tx.appends().isEmpty())
        assertTrue(tx.mgr.sendMessage(tx.cid, "a".repeat(fits)), "exactly at the probe limit")
        assertEquals(1L, tx.contact().outboundCounter)
        assertEquals(1, tx.appends().size)
    }

    // S3: the bumped counter is persisted BEFORE the POST and equals the sealed one; a
    // refused POST still consumed its counter (skip, never reuse).
    @Test
    fun counterIsPersistedBeforeThePost_andEqualsTheSealedCounter() {
        if (!legacyEnvelopeCryptoUp()) return
        val tx = Tx()
        val atPost = mutableListOf<Pair<Long, Long>>()   // (persisted, sealed) at POST time
        tx.onAppend = { r -> atPost.add(tx.contact().outboundCounter to sealedCounterOf(tx.opened(r))) }
        assertTrue(tx.mgr.sendMessage(tx.cid, "one"))
        assertTrue(tx.mgr.sendMessage(tx.cid, "two"))
        tx.answer = HttpResult(500, "", false)
        assertFalse(tx.mgr.sendMessage(tx.cid, "refused"))
        assertEquals(listOf(1L to 1L, 2L to 2L, 3L to 3L), atPost)
        assertEquals(3L, tx.contact().outboundCounter, "the refused send's counter stays consumed")
    }

    // S4: a CONTROL send to a peer with no outbound-ctl row falls back to MAIN, and the
    // counter, the `ch` tag and the row all follow the channel actually USED; the
    // text refusal is not applied (it gates the REQUESTED channel, CTL), and without
    // the peer's `cr` advert the send stays legacy even with dr-on.
    @Test
    fun controlToAPreV7Peer_fallsBackToMain_counterAndTagFollowTheUsedChannel_refusalNotApplied() {
        if (!legacyEnvelopeCryptoUp()) return
        val tx = Tx(ctl = false)
        tx.vault.putMeta(MessageManager.drRefusedKey(tx.cid), "1")
        tx.vault.putMeta(MessageManager.drOnKey(tx.cid), "1")
        assertTrue(tx.mgr.sendDirectControl(tx.cid, "ref-offer", "{}"))
        val post = tx.appends().single()
        assertTrue(post.url.endsWith("/inbox/$SC_OUT"), post.url)
        assertFalse(MessageManager.isRatchetWire(post.body), "no ratchet branch without the peer's advert")
        val json = tx.opened(post)
        assertTrue(""""ch":"m"""" in json, json)
        assertTrue(""""di":"$SC_OUT"""" in json, json)
        assertEquals(1L, tx.contact().outboundCounter)
        assertEquals(0L, tx.contact().outboundCtlCounter)
    }

    // S5: with dr-on but no sending chain (the responder before its first ratchet
    // receive) a TEXT send falls back to legacy and is COUNTED; a sealed control kind
    // falls back the same way and is NOT counted.
    @Test
    fun ratchetNoSendingChain_textFallsBackAndCounts_sealedControlFallsBackUncounted() {
        if (!legacyEnvelopeCryptoUp()) return
        val tx = Tx()
        tx.vault.putMeta(MessageManager.drOnKey(tx.cid), "1")
        tx.vault.putMeta(MessageManager.drCtlCapKey(tx.cid), "1")
        assertEquals(0, tx.mgr.ratchetFallbackCount(tx.cid))
        assertTrue(tx.mgr.sendMessage(tx.cid, "pre-bootstrap"))
        assertFalse(MessageManager.isRatchetWire(tx.appends().last().body))
        assertEquals(1, tx.mgr.ratchetFallbackCount(tx.cid), "a text fallthrough is counted")
        assertTrue(tx.mgr.sendDirectControl(tx.cid, MessageManager.CONTROL_KIND_REFERRAL_ACCEPT, "{}"))
        val ctlPost = tx.appends().last()
        assertTrue(ctlPost.url.endsWith("/inbox/$SC_OUT_CTL"), ctlPost.url)
        assertFalse(MessageManager.isRatchetWire(ctlPost.body))
        assertEquals(1, tx.mgr.ratchetFallbackCount(tx.cid), "a sealed-control fallthrough is not")
    }
}
