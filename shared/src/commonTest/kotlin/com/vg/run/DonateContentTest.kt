package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Guards the data the Support-page crypto tab depends on. Real addresses
 * shipped 2026-08-25 (Monero + Bitcoin; Lightning removed as a choice), so
 * this pins the EXACT address strings: the QR and the Copy button both feed
 * from them, and a silently corrupted donation address means lost funds.
 */
class DonateContentTest {

    private val monero = DonateContent.methods.first { it.id == "monero" }
    private val bitcoin = DonateContent.methods.first { it.id == "bitcoin" }

    @Test
    fun monero_address_is_pinned_verbatim() {
        assertFalse(monero.isPlaceholder)
        assertEquals(
            "47gkTtxs5McJfw1QKyaPMnPwdoWeePYQQZ7WvnDkkBsHWKWwN7e7nxwYRzV7PHwpYqPsjWa5qc5G4Efr8RFreJuwGk889oX",
            monero.address,
        )
        // Standard-address shape: 95 base58 chars, network byte prefix "4".
        assertEquals(95, monero.address.length)
        assertTrue(monero.address.first() == '4')
        assertTrue(monero.address.all { it in "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz" })
    }

    @Test
    fun bitcoin_address_is_pinned_verbatim() {
        assertFalse(bitcoin.isPlaceholder)
        assertEquals("bc1qkh3hgdt408tlcmdeac96l5v79ytul5mrrjupse", bitcoin.address)
        // Mainnet bech32 P2WPKH shape: bc1q + 38 data chars from the bech32 set.
        assertEquals(42, bitcoin.address.length)
        assertTrue(bitcoin.address.startsWith("bc1q"))
        assertTrue(bitcoin.address.drop(3).all { it in "qpzry9x8gf2tvdw0s3jn54khce6mua7l" })
    }

    @Test
    fun lightning_is_no_longer_offered() {
        assertNull(DonateContent.methods.firstOrNull { it.id == "lightning" })
        assertEquals(listOf("monero", "bitcoin"), DonateContent.methods.map { it.id })
    }

    @Test
    fun no_method_is_a_placeholder_any_more() {
        assertTrue(DonateContent.methods.none { it.isPlaceholder })
    }
}
