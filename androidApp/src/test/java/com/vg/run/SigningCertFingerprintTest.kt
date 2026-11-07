package com.vg.run

import org.junit.Assert.assertEquals
import org.junit.Test

// Format of the About-modal signing-certificate fingerprint: uppercase hex,
// colon-separated, 32 bytes — the same shape `apksigner verify --print-certs`
// and `keytool -list` print, so a user can compare them by eye.
class SigningCertFingerprintTest {

    @Test
    fun sha256OfEmptyInputIsTheKnownVectorInColonHex() {
        assertEquals(
            "E3:B0:C4:42:98:FC:1C:14:9A:FB:F4:C8:99:6F:B9:24:" +
                "27:AE:41:E4:64:9B:93:4C:A4:95:99:1B:78:52:B8:55",
            sha256ColonHex(ByteArray(0)),
        )
    }

    @Test
    fun outputIs32UppercaseColonSeparatedBytes() {
        val fp = sha256ColonHex(ByteArray(300) { (it * 7).toByte() })
        val parts = fp.split(":")
        assertEquals(32, parts.size)
        parts.forEach { assertEquals(true, Regex("[0-9A-F]{2}").matches(it)) }
    }
}
