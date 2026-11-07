package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Pins the shared DNS-leak transport guard. Both platforms now
 * route through this one function, so the accept/reject matrix is enforced once:
 * a .onion may ONLY travel the SOCKS5h path; a clearnet host may ONLY travel the
 * direct path. A regression here re-opens the DNS-leak / misroute vector.
 */
class OnionTransportGuardTest {

    private val onion = "http://vwxyz2345abcdef67.onion/inbox/abc"
    private val clearnet = "https://relay.example.com/inbox/abc"

    @Test
    fun direct_onion_isBlocked_wouldLeakDns() {
        val r = onionTransportGuard(onion, viaSocks = false)
        assertTrue(r != null, ".onion on the direct path must be refused")
        assertEquals(-1, r!!.code)
        assertEquals(false, r.isSuccess)
        assertTrue(r.body!!.contains(".onion via direct"), "refusal body: ${r.body}")
    }

    @Test
    fun socks_nonOnion_isBlocked_misroute() {
        val r = onionTransportGuard(clearnet, viaSocks = true)
        assertTrue(r != null, "clearnet on the SOCKS path must be refused")
        assertEquals(-1, r!!.code)
        assertTrue(r.body!!.contains("non-onion via SOCKS"), "refusal body: ${r.body}")
    }

    @Test
    fun correctPairings_areAllowed() {
        // .onion over SOCKS, clearnet over direct — both pass (null = no refusal).
        assertNull(onionTransportGuard(onion, viaSocks = true))
        assertNull(onionTransportGuard(clearnet, viaSocks = false))
    }
}
