package com.vg.run

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * DNS-leak guard — wiring check on the real Android transport.
 * The guard short-circuits before any network call, so these are
 * deterministic and need no server/Tor.
 */
@RunWith(AndroidJUnit4::class)
class PlatformHttpClientGuardTest {

    private val onion    = "http://abcdefghijklmnop234567.onion/inbox/x"
    private val clearnet = "http://localhost:8080/inbox/x"

    @Test
    fun directClient_refusesOnion_onGet() {
        val r = PlatformHttpClient.direct().get(onion)
        assertEquals(-1, r.code)
        assertFalse(r.isSuccess)
        assertTrue("must report a refusal", r.body?.contains("refused") == true)
    }

    @Test
    fun directClient_refusesOnion_onPost() {
        val r = PlatformHttpClient.direct()
            .post(onion, byteArrayOf(1, 2, 3), "application/octet-stream")
        assertEquals(-1, r.code)
        assertFalse(r.isSuccess)
    }

    @Test
    fun socksClient_refusesClearnet() {
        // torProxy with no Tor running — the guard rejects before connecting.
        val r = PlatformHttpClient.torProxy(9050).get(clearnet)
        assertEquals(-1, r.code)
        assertFalse(r.isSuccess)
        assertTrue("must report a refusal", r.body?.contains("refused") == true)
    }
}
