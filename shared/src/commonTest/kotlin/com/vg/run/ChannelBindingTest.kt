package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * The static envelope carries a channel-binding tag
 * ("ch") sealed INSIDE the AEAD, so a malicious relay cannot move an authentic
 * blob from one of a pairing's two inboxes (main "m" / control "c") to the
 * other — the two channels keep independent counter spaces, so a cross-inbox
 * splice would otherwise pass the per-channel replay check. These tests lock the
 * parse contract; the drop on mismatch lives in pollChannel (control? "c":"m").
 */
class ChannelBindingTest {
    private val mm = MessageManager(InMemoryVault(), "http://x.onion", RecordingRelayHttp())

    @Test
    fun control_channel_tag_is_parsed() {
        val env = mm.parseEnvelope("""{"e":"abc","c":1,"t":0,"ch":"c","k":"inbox","b":"{}","m":""}""")
        assertNotNull(env)
        assertEquals(MessageManager.CHANNEL_TAG_CTL, env.channel)
    }

    @Test
    fun main_channel_tag_is_parsed() {
        val env = mm.parseEnvelope("""{"e":"abc","c":2,"t":0,"ch":"m","m":"hi"}""")
        assertNotNull(env)
        assertEquals(MessageManager.CHANNEL_TAG_MAIN, env.channel)
    }

    @Test
    fun legacy_envelope_has_null_channel_so_check_is_skipped() {
        // A sender without channel binding omits "ch"; channel must be null so the receive-side
        // mismatch check is skipped (backward compatibility, not a silent drop).
        val env = mm.parseEnvelope("""{"e":"abc","c":3,"t":0,"m":"hi"}""")
        assertNotNull(env)
        assertNull(env.channel)
    }
}
