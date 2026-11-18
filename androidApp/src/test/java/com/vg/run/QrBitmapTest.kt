package com.vg.run

import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer
import org.junit.Assert
import org.junit.Test

/**
 * The QR tile must be CRISP: every module a whole number of pixels, a quiet zone of at least
 * four modules, an exact output size, and the picture must still decode to the same text.
 * (Rendering on screen is 1 bitmap pixel = 1 device pixel, unfiltered - CrispQrImage; that
 * part is checked on the emulator by the camera specs.)
 */
class QrBitmapTest {

    private fun assertEquals(expected: Any?, actual: Any?, message: String = "") = Assert.assertEquals(message, expected, actual)
    private fun assertTrue(cond: Boolean, message: String = "") = Assert.assertTrue(message, cond)

    /** A pairing-shaped payload of an exact length (ASCII JSON-ish, like the real codes). */
    private fun payload(bytes: Int): String {
        val head = "{\"v\":3,\"s\":\""
        val tail = "\"}"
        val fill = "AbCdEfGh0123456789_-".repeat(bytes / 10 + 1)
        return (head + fill).take(bytes - tail.length) + tail
    }

    private fun decode(q: QrPixels): String {
        val src = RGBLuminanceSource(q.sizePx, q.sizePx, q.argb)
        val hints = mapOf(DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE))
        return MultiFormatReader().decode(BinaryBitmap(HybridBinarizer(src)), hints).text
    }

    @Test fun `scale is the whole number of pixels that fits the budget`() {
        assertEquals(8, qrModuleScale(totalModules = 77, budgetPx = 682))
        assertEquals(1, qrModuleScale(totalModules = 77, budgetPx = 10))      // never below 1
        assertEquals(10, qrModuleScale(totalModules = 77, budgetPx = 800))
    }

    @Test fun `output size is exactly total modules times scale for both real code sizes`() {
        for (bytes in listOf(117, 403)) {
            for (budget in listOf(525, 682, 800, 1024)) {
                val q = renderQrPixels(payload(bytes), budget)
                assertEquals((q.modules + 2 * QR_QUIET_MODULES) * q.scale, q.sizePx, "bytes=$bytes budget=$budget")
                assertEquals(q.sizePx * q.sizePx, q.argb.size)
                assertTrue(q.sizePx <= budget, "bytes=$bytes budget=$budget size=${q.sizePx}")
                // The scale is the largest that fits: one more module-pixel would overflow.
                assertTrue((q.scale + 1) * q.totalModules > budget)
            }
        }
    }

    @Test fun `quiet zone is at least four modules and entirely light`() {
        val q = renderQrPixels(payload(403), 682)
        val quietPx = q.quietModules * q.scale
        assertTrue(q.quietModules >= 4)
        for (y in 0 until q.sizePx) for (x in 0 until q.sizePx) {
            val inQuiet = x < quietPx || y < quietPx || x >= q.sizePx - quietPx || y >= q.sizePx - quietPx
            if (inQuiet) assertEquals(0xFFFFFFFF.toInt(), q.argb[y * q.sizePx + x], "($x,$y)")
        }
    }

    @Test fun `quiet zone is wider than what the 12 dp corner clip can cut`() {
        // The clip removes at most r*(1 - 1/sqrt 2) along the diagonal of a corner; the tile's
        // quiet zone must be wider than that at the smallest density we draw the tile at.
        val density = 1.0f                                     // mdpi: the harshest (smallest px per dp)
        val clipInsetPx = 12 * density * (1 - 1 / Math.sqrt(2.0))
        val q = renderQrPixels(payload(403), (260 * density).toInt())
        assertTrue(q.quietModules * q.scale > clipInsetPx, "quiet=${q.quietModules * q.scale}px clip=$clipInsetPx")
    }

    @Test fun `every module is a uniform scale x scale block with hard edges`() {
        val q = renderQrPixels(payload(403), 682)
        // Only two pixel values exist (no anti-aliasing), and each scale-block is uniform.
        assertEquals(setOf(0xFF000000.toInt(), 0xFFFFFFFF.toInt()), q.argb.toSet())
        for (my in 0 until q.totalModules) for (mx in 0 until q.totalModules) {
            val first = q.argb[(my * q.scale) * q.sizePx + mx * q.scale]
            for (dy in 0 until q.scale) for (dx in 0 until q.scale) {
                assertEquals(first, q.argb[(my * q.scale + dy) * q.sizePx + mx * q.scale + dx], "module ($mx,$my)")
            }
        }
    }

    @Test fun `the picture decodes to the encoded text for the two real sizes`() {
        for (bytes in listOf(117, 403)) {
            val text = payload(bytes)
            assertEquals(text, decode(renderQrPixels(text, 682)), "bytes=$bytes")
            assertEquals(text, decode(renderQrPixels(text, 525)), "bytes=$bytes small")
        }
    }
}
