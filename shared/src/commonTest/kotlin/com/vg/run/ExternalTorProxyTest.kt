package com.vg.run

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * External SOCKS proxy mode — the pure parse / classify / encode rules
 * ([ExternalTorProxy]). The mode exists so a user can PROVE the embedded Tor is
 * never used; a lenient parser here is the one place a different address than
 * the one the user sees could reach the socket layer, so the hostile inputs
 * below are the point of this file.
 */
class ExternalTorProxyTest {

    // --- classify ----------------------------------------------------------

    @Test
    fun classify_loopback() {
        assertEquals(HostClass.LOOPBACK, ExternalTorProxy.classify("127.0.0.1"))
        assertEquals(HostClass.LOOPBACK, ExternalTorProxy.classify("127.255.255.254"))
        assertEquals(HostClass.LOOPBACK, ExternalTorProxy.classify("::1"))
    }

    @Test
    fun classify_lanRanges_andTheirEdges() {
        for (h in listOf(
            "10.0.0.1", "10.255.255.255",
            "172.16.0.1", "172.31.255.254",
            "192.168.0.1", "192.168.255.254",
            "169.254.0.1", "169.254.255.254",
        )) assertEquals(HostClass.LAN, ExternalTorProxy.classify(h), h)
        // Just outside each range.
        for (h in listOf(
            "172.15.255.255", "172.32.0.0", "192.167.1.1", "192.169.1.1",
            "169.253.1.1", "169.255.1.1", "11.0.0.1", "9.255.255.255",
            "126.0.0.1", "128.0.0.1",
        )) assertEquals(HostClass.INVALID, ExternalTorProxy.classify(h), h)
    }

    @Test
    fun classify_publicAndSpecialAddressesAreInvalid() {
        for (h in listOf("8.8.8.8", "1.1.1.1", "0.0.0.0", "255.255.255.255", "100.64.0.1", "224.0.0.1"))
            assertEquals(HostClass.INVALID, ExternalTorProxy.classify(h), h)
    }

    @Test
    fun classify_neverAcceptsAHostname() {
        for (h in listOf(
            "localhost", "LOCALHOST", "proxy.lan", "orbot", "example.com",
            "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion",
            "127.0.0.1.nip.io", "10.0.0.1.example",
        )) assertEquals(HostClass.INVALID, ExternalTorProxy.classify(h), h)
    }

    @Test
    fun classify_rejectsNonCanonicalIpv4() {
        for (h in listOf(
            "127.1", "127.0.1", "127.0.0.1.", ".127.0.0.1", "127..0.1",
            "0127.0.0.1", "127.00.0.1", "127.0.0.01", "010.0.0.1",   // leading zeros (octal on some stacks)
            "127.0.0.256", "192.168.1.999", "1000.0.0.1",
            "0x7f.0.0.1", "0x7f000001", "2130706433",                // hex / integer forms
            "+127.0.0.1", "-1.0.0.1", "127.0.0.-1",
            " 127.0.0.1", "127.0.0.1 ", "127.0.0.1\n", "127.0.\t0.1",
            "١٢٧.0.0.1",                                             // Arabic-Indic digits
            "１２７.0.0.1",                                           // full-width digits
            "", ".", "...",
        )) assertEquals(HostClass.INVALID, ExternalTorProxy.classify(h), "[$h]")
    }

    @Test
    fun classify_onlyExactIpv6Loopback() {
        for (h in listOf(
            "[::1]", "0:0:0:0:0:0:0:1", "::0001", "::ffff:127.0.0.1", "::", "fe80::1",
            "fd00::1", "::1%lo", " ::1", "::1 ", ":::1",
        )) assertEquals(HostClass.INVALID, ExternalTorProxy.classify(h), "[$h]")
    }

    // --- parse / encode ----------------------------------------------------

    @Test
    fun parse_validForms_roundTripThroughEncode() {
        val cases = mapOf(
            "127.0.0.1:9050" to ExternalTorProxyConfig("127.0.0.1", 9050),
            "192.168.1.20:9150" to ExternalTorProxyConfig("192.168.1.20", 9150),
            "10.0.0.2:1" to ExternalTorProxyConfig("10.0.0.2", 1),
            "172.16.5.4:65535" to ExternalTorProxyConfig("172.16.5.4", 65535),
            "[::1]:9050" to ExternalTorProxyConfig("::1", 9050),
        )
        for ((stored, cfg) in cases) {
            assertEquals(cfg, ExternalTorProxy.parse(stored), stored)
            assertEquals(stored, ExternalTorProxy.encode(cfg))
            assertEquals(cfg, ExternalTorProxy.parse(ExternalTorProxy.encode(cfg)))
        }
    }

    @Test
    fun parse_rejectsBadPorts() {
        for (s in listOf(
            "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:99999", "127.0.0.1:123456",
            "127.0.0.1:09050", "127.0.0.1:+9050", "127.0.0.1:-1", "127.0.0.1:",
            "127.0.0.1:9050 ", "127.0.0.1: 9050", "127.0.0.1:9o50", "127.0.0.1:９０５０",
            "127.0.0.1:0x2352", "127.0.0.1", "127.0.0.1:9050:1",
        )) assertNull(ExternalTorProxy.parse(s), "[$s]")
    }

    @Test
    fun parse_rejectsHostileOrMalformedHosts() {
        for (s in listOf(
            null, "", ":", ":9050", "localhost:9050", "proxy.lan:9050",
            "8.8.8.8:9050", "0.0.0.0:9050", "0127.0.0.1:9050",
            "::1:9050",                 // unbracketed IPv6 — ambiguous with the port
            "[::1]9050", "[::1]:", "[::1", "::1]:9050", "[]:9050",
            "[127.0.0.1]:9050",         // brackets are for IPv6 only
            "[fe80::1]:9050", "[0:0:0:0:0:0:0:1]:9050",
            "user@127.0.0.1:9050", "socks5://127.0.0.1:9050", "127.0.0.1:9050/",
            " 127.0.0.1:9050", "127.0.0.1:9050\u0000",
            "127.0.0.1:9050" + "0".repeat(64),
        )) assertNull(ExternalTorProxy.parse(s), "[$s]")
    }

    @Test
    fun isConfiguredButInvalid_distinguishesAbsentFromCorrupt() {
        assertFalse(ExternalTorProxy.isConfiguredButInvalid(null))
        assertFalse(ExternalTorProxy.isConfiguredButInvalid("127.0.0.1:9050"))
        assertTrue(ExternalTorProxy.isConfiguredButInvalid(""))
        assertTrue(ExternalTorProxy.isConfiguredButInvalid("8.8.8.8:9050"))
        assertTrue(ExternalTorProxy.isConfiguredButInvalid("garbage"))
    }

    // --- settings-form helpers --------------------------------------------

    @Test
    fun validateInput_reportsTheFirstBadField() {
        assertEquals(ExternalTorProxy.InputError.NONE, ExternalTorProxy.validateInput("127.0.0.1", "9050"))
        assertEquals(ExternalTorProxy.InputError.NONE, ExternalTorProxy.validateInput("::1", "9050"))
        assertEquals(ExternalTorProxy.InputError.NONE, ExternalTorProxy.validateInput("[::1]", "9050"))
        assertEquals(ExternalTorProxy.InputError.HOST, ExternalTorProxy.validateInput("localhost", "9050"))
        assertEquals(ExternalTorProxy.InputError.HOST, ExternalTorProxy.validateInput(" 127.0.0.1", "9050"))
        assertEquals(ExternalTorProxy.InputError.HOST, ExternalTorProxy.validateInput("", "abc"))
        assertEquals(ExternalTorProxy.InputError.PORT, ExternalTorProxy.validateInput("127.0.0.1", "0"))
        assertEquals(ExternalTorProxy.InputError.PORT, ExternalTorProxy.validateInput("127.0.0.1", ""))
    }

    @Test
    fun fromInput_stripsIpv6Brackets_andEncodesBackWithThem() {
        val cfg = ExternalTorProxy.fromInput("[::1]", "9050")
        assertEquals(ExternalTorProxyConfig("::1", 9050), cfg)
        assertEquals("[::1]:9050", ExternalTorProxy.encode(cfg!!))
        assertNull(ExternalTorProxy.fromInput("8.8.8.8", "9050"))
    }

    @Test
    fun isLan_onlyForLanAddresses() {
        assertTrue(ExternalTorProxy.isLan("192.168.1.2"))
        assertTrue(ExternalTorProxy.isLan("169.254.3.4"))
        assertFalse(ExternalTorProxy.isLan("127.0.0.1"))
        assertFalse(ExternalTorProxy.isLan("::1"))
        assertFalse(ExternalTorProxy.isLan("8.8.8.8"))
    }

    // --- socket-layer bytes ------------------------------------------------

    @Test
    fun addressBytes_matchTheLiteral_andRefuseInvalid() {
        assertContentEquals(byteArrayOf(127, 0, 0, 1), ExternalTorProxy.addressBytes("127.0.0.1"))
        assertContentEquals(
            byteArrayOf(192.toByte(), 168.toByte(), 1, 20),
            ExternalTorProxy.addressBytes("192.168.1.20"),
        )
        assertContentEquals(ByteArray(16).also { it[15] = 1 }, ExternalTorProxy.addressBytes("::1"))
        assertNull(ExternalTorProxy.addressBytes("localhost"))
        assertNull(ExternalTorProxy.addressBytes("8.8.8.8"))
        assertNull(ExternalTorProxy.addressBytes("0127.0.0.1"))
    }

    // --- the log phrases never carry the address (word for word with iOS) ---

    @Test
    fun logPhrases_matchIosWordForWord_andCarryNoAddress() {
        assertEquals("ext proxy: loopback reachable", ExternalTorProxy.statusLogLine(HostClass.LOOPBACK, true))
        assertEquals("ext proxy: lan unreachable", ExternalTorProxy.statusLogLine(HostClass.LAN, false))
        assertEquals("ext proxy: loopback in use, embedded Tor disabled", ExternalTorProxy.inUseLogLine(HostClass.LOOPBACK))
        assertEquals("ext proxy: lan in use, embedded Tor disabled", ExternalTorProxy.inUseLogLine(HostClass.LAN))
        assertEquals("ext proxy: setting invalid - messaging unavailable", ExternalTorProxy.PHRASE_INVALID_CONFIG)
        assertEquals("ext proxy: setting unreadable - messaging unavailable", ExternalTorProxy.PHRASE_UNREADABLE_CONFIG)
        assertEquals("ext proxy: relay is not an onion - messaging unavailable", ExternalTorProxy.PHRASE_RELAY_NOT_ONION)
        val all = HostClass.entries.flatMap { c ->
            listOf(ExternalTorProxy.statusLogLine(c, true), ExternalTorProxy.statusLogLine(c, false), ExternalTorProxy.inUseLogLine(c))
        } + listOf(
            ExternalTorProxy.PHRASE_INVALID_CONFIG,
            ExternalTorProxy.PHRASE_UNREADABLE_CONFIG,
            ExternalTorProxy.PHRASE_RELAY_NOT_ONION,
        )
        for (line in all) {
            assertFalse(line.any { it in '0'..'9' }, "no digit (address/port) may appear: $line")
            assertFalse(line.contains('[') || line.contains("127") || line.contains("192"), line)
        }
    }

    // --- sealed persistence ------------------------------------------------

    private class MapStore : DebugModeStore {
        val map = mutableMapOf<String, String>()
        override fun get(key: String): String? = map[key]
        override fun putSync(key: String, value: String) { map[key] = value }
        override fun remove(key: String): Boolean { map.remove(key); return true }
    }

    @Test
    fun stored_absent_isOff() {
        val r = ExternalTorProxy.readStoredIn(MapStore(), FakeDeviceKeyCipher())
        assertEquals(ExternalTorProxy.StoredState.OFF, r.state)
        assertFalse(r.modeOn)
    }

    @Test
    fun stored_roundTrip_andClear() {
        val store = MapStore()
        val cipher = FakeDeviceKeyCipher()
        val cfg = ExternalTorProxyConfig("::1", 9050)
        assertTrue(ExternalTorProxy.writeStoredIn(store, cipher, cfg))
        val r = ExternalTorProxy.readStoredIn(store, cipher)
        assertEquals(ExternalTorProxy.StoredState.VALID, r.state)
        assertEquals(cfg, r.config)
        assertFalse(
            store.map.getValue(ExternalTorProxy.PREF_KEY).contains(":9050"),
            "persisted as a sealed blob, never as the plaintext ip:port",
        )
        assertTrue(ExternalTorProxy.writeStoredIn(store, cipher, null))
        assertEquals(ExternalTorProxy.StoredState.OFF, ExternalTorProxy.readStoredIn(store, cipher).state)
    }

    @Test
    fun stored_plantedPlaintext_failsClosed_neverRedirects_neverOff() {
        val store = MapStore().apply { map[ExternalTorProxy.PREF_KEY] = "192.168.1.66:9050" }
        val r = ExternalTorProxy.readStoredIn(store, FakeDeviceKeyCipher())
        assertEquals(ExternalTorProxy.StoredState.INVALID, r.state)
        assertNull(r.config, "a planted address must never be used")
        assertTrue(r.modeOn, "…and must not switch the mode off either (fail closed)")
    }

    @Test
    fun stored_keyOutage_isUnreadable_modeOn() {
        val store = MapStore()
        val cipher = FakeDeviceKeyCipher()
        assertTrue(ExternalTorProxy.writeStoredIn(store, cipher, ExternalTorProxyConfig("127.0.0.1", 9050)))
        cipher.throwOnOpen = true
        val r = ExternalTorProxy.readStoredIn(store, cipher)
        assertEquals(ExternalTorProxy.StoredState.UNREADABLE, r.state)
        assertNull(r.config)
        assertTrue(r.modeOn)
    }

    @Test
    fun stored_sealedButNonLocal_isInvalid() {
        val store = MapStore()
        val cipher = FakeDeviceKeyCipher()
        store.map[ExternalTorProxy.PREF_KEY] = SealedPref.seal(cipher, ExternalTorProxy.SEALED_SLOT, "8.8.8.8:9050")
        assertEquals(ExternalTorProxy.StoredState.INVALID, ExternalTorProxy.readStoredIn(store, cipher).state)
    }

    @Test
    fun stored_writeRefusesAnInvalidConfig() {
        val store = MapStore()
        assertFalse(ExternalTorProxy.writeStoredIn(store, FakeDeviceKeyCipher(), ExternalTorProxyConfig("8.8.8.8", 9050)))
        assertTrue(store.map.isEmpty())
    }
}
