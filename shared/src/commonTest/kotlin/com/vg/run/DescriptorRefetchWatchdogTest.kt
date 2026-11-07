package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// The shared HS_DESC event CLASSIFIER (RelayDescriptorWatchdog). The re-request
// decision it once fed — the 4 s watchdog, its per-NEWNYM budget and
// MessageManager.shouldFireDescriptorRefetch — was replaced on 2026-10-12 by the
// earlier bounded hedge (DescriptorHedge, tested in DescriptorHedgeTest).
// ---------------------------------------------------------------------------

class DescriptorRefetchWatchdogTest {

    // Synthetic 56-char base32 address (NOT any real service).
    private val ours = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx"
    private val other = "zyxwvutsrqponmlkjihgfedcba765432zyxwvutsrqponmlkjihgfedc"
    private val hsDir = "\$0123456789ABCDEF0123456789ABCDEF01234567~SomeNick"
    private val descId = "b64DescriptorIdAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    // --- the event classifier --------------------------------------------

    private fun classify(line: String, addr: String? = ours) =
        RelayDescriptorWatchdog.classify(line, addr)

    @Test
    fun requestedForOurOnion_arms() {
        assertEquals(
            RelayDescriptorSignal.REQUESTED,
            classify("650 HS_DESC REQUESTED $ours NO_AUTH $hsDir $descId"),
        )
        // iOS's controller hands observers the line WITHOUT the reply prefix.
        assertEquals(
            RelayDescriptorSignal.REQUESTED,
            classify("HS_DESC REQUESTED $ours NO_AUTH $hsDir $descId"),
        )
        // CRLF tolerated; mid-reply separator tolerated.
        assertEquals(
            RelayDescriptorSignal.REQUESTED,
            classify("650-HS_DESC REQUESTED $ours NO_AUTH $hsDir $descId\r\n"),
        )
    }

    @Test
    fun receivedOrFailedForOurOnion_settles() {
        assertEquals(
            RelayDescriptorSignal.SETTLED,
            classify("650 HS_DESC RECEIVED $ours NO_AUTH $hsDir $descId"),
        )
        assertEquals(
            RelayDescriptorSignal.SETTLED,
            classify("650 HS_DESC FAILED $ours NO_AUTH $hsDir $descId REASON=NOT_FOUND"),
        )
    }

    @Test
    fun addressComparisonIsCaseInsensitive() {
        assertEquals(
            RelayDescriptorSignal.REQUESTED,
            classify("650 HS_DESC REQUESTED ${ours.uppercase()} NO_AUTH $hsDir"),
        )
    }

    @Test
    fun anotherServicesDescriptor_isIgnored() {
        assertNull(classify("650 HS_DESC REQUESTED $other NO_AUTH $hsDir $descId"))
        assertNull(classify("650 HS_DESC RECEIVED $other NO_AUTH $hsDir $descId"))
        // Tor's placeholder when it cannot name the service.
        assertNull(classify("650 HS_DESC FAILED UNKNOWN NO_AUTH $hsDir REASON=QUERY_NO_HSDIR"))
    }

    @Test
    fun serviceSideAndIgnoreActions_areIgnored() {
        for (action in listOf("CREATED", "UPLOAD", "UPLOADED", "IGNORE")) {
            assertNull(classify("650 HS_DESC $action $ours NO_AUTH $hsDir $descId"), action)
        }
    }

    @Test
    fun otherEventClassesAndReplies_areIgnored() {
        assertNull(classify("650 HS_DESC_CONTENT $ours $descId $hsDir"))
        assertNull(classify("650 CIRC 12 BUILT $hsDir PURPOSE=HS_CLIENT_HSDIR"))
        assertNull(classify("650 STREAM 7 SENTCONNECT 12 $ours.onion:80"))
        assertNull(classify("250 OK"))
        assertNull(classify(""))
        assertNull(classify("650 HS_DESC REQUESTED"))
    }

    @Test
    fun noRelayAddress_neverArms() {
        assertNull(classify("650 HS_DESC REQUESTED $ours NO_AUTH $hsDir", addr = null))
        assertNull(classify("650 HS_DESC REQUESTED $ours NO_AUTH $hsDir", addr = ""))
    }

    @Test
    fun hsFetchAddress_isTheStrictV3Extraction() {
        assertEquals(ours, RelayDescriptorWatchdog.hsFetchAddress("http://$ours.onion"))
        assertEquals(ours, RelayDescriptorWatchdog.hsFetchAddress("http://$ours.onion:8080/path"))
        // Clearnet / malformed / injection-shaped values never reach HSFETCH.
        assertNull(RelayDescriptorWatchdog.hsFetchAddress("https://relay.example.com"))
        assertNull(RelayDescriptorWatchdog.hsFetchAddress(""))
        assertNull(RelayDescriptorWatchdog.hsFetchAddress("http://${ours.dropLast(1)}\n.onion"))
    }

    @Test
    fun classifierOutputCarriesNoEventField() {
        // The return type is a two-value enum: whatever the event carried (onion,
        // HSDir fingerprint~nickname, descriptor id, a smuggled string), the only
        // thing that leaves classify() is the enum's own fixed name.
        val outputs = listOf(
            classify("650 HS_DESC REQUESTED $ours NO_AUTH $hsDir $descId"),
            classify("650 HS_DESC FAILED $ours NO_AUTH $hsDir $descId REASON=NOT_FOUND"),
        )
        for (out in outputs) {
            val rendered = out.toString()
            assertFalse(rendered.contains(ours, ignoreCase = true), rendered)
            assertFalse(rendered.contains("SomeNick"), rendered)
            assertFalse(rendered.contains("0123456789ABCDEF"), rendered)
            assertFalse(rendered.contains(descId), rendered)
            assertTrue(rendered == "REQUESTED" || rendered == "SETTLED", rendered)
        }
    }
}
