package com.vg.run

import android.graphics.Bitmap
import androidx.compose.foundation.Image
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.layout.size
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter

// ---------------------------------------------------------------------------
// QR code bitmaps with CRISP modules.
//
// The old helper asked ZXing for an 800 px bitmap and the screen drew it at 200-260 dp,
// i.e. at 0.5-0.7 device pixels per source pixel with bilinear filtering. Modules came out
// soft, and a camera had a harder time with the dense 403-byte full code (measured on the
// emulator's virtual camera: the raw on-screen tile often did not decode, a sharpened copy
// of the same picture did).
//
// Here every module is exactly [QrPixels.scale] x [QrPixels.scale] pixels of the bitmap, the
// bitmap is drawn at exactly its own pixel size (1 bitmap pixel = 1 device pixel) and
// without filtering, so every module is a whole number of device pixels with hard edges.
// The white quiet zone is part of the bitmap (QR_QUIET_MODULES modules on every side).
// ---------------------------------------------------------------------------

/** Quiet zone, in modules, on every side (the QR specification's minimum). */
internal const val QR_QUIET_MODULES = 4

private const val QR_DARK = 0xFF000000.toInt()
private const val QR_LIGHT = 0xFFFFFFFF.toInt()

/** A rendered QR: [sizePx] x [sizePx] ARGB pixels, [scale] px per module,
 *  [modules] modules per side without the quiet zone. */
internal class QrPixels(
    val sizePx: Int,
    val scale: Int,
    val modules: Int,
    val quietModules: Int,
    val argb: IntArray,
) {
    val totalModules: Int get() = modules + 2 * quietModules
}

/** The whole-pixel module size for a code of [totalModules] (quiet zone included) that must
 *  fit in [budgetPx]. At least 1: a budget below one pixel per module still renders (tiny). */
internal fun qrModuleScale(totalModules: Int, budgetPx: Int): Int =
    maxOf(1, budgetPx / totalModules)

/** Renders [content] as QR pixels with a whole-number module scale that fits [budgetPx].
 *  Error-correction level is ZXing's default (L), as before. Pure: no Android classes. */
internal fun renderQrPixels(content: String, budgetPx: Int): QrPixels {
    // Width/height 0 + margin 0 makes ZXing return the bare module matrix.
    val matrix = QRCodeWriter().encode(
        content, BarcodeFormat.QR_CODE, 0, 0, mapOf(EncodeHintType.MARGIN to 0),
    )
    val modules = matrix.width
    val total = modules + 2 * QR_QUIET_MODULES
    val scale = qrModuleScale(total, budgetPx)
    val size = total * scale
    val px = IntArray(size * size) { QR_LIGHT }
    for (my in 0 until modules) {
        for (mx in 0 until modules) {
            if (!matrix.get(mx, my)) continue
            val x0 = (mx + QR_QUIET_MODULES) * scale
            val y0 = (my + QR_QUIET_MODULES) * scale
            for (dy in 0 until scale) {
                val row = (y0 + dy) * size + x0
                for (dx in 0 until scale) px[row + dx] = QR_DARK
            }
        }
    }
    return QrPixels(size, scale, modules, QR_QUIET_MODULES, px)
}

/** Largest crisp QR bitmap for [content] that fits [sizePx] DEVICE pixels. Draw it with
 *  [CrispQrImage] (1 bitmap pixel = 1 device pixel); drawing it scaled would undo this.
 *  Internal (not file-private) so the Support/Donate modal and the device-move screen reuse
 *  this single helper. */
internal fun generateQrBitmap(content: String, sizePx: Int): Bitmap {
    val q = renderQrPixels(content, sizePx)
    return Bitmap.createBitmap(q.argb, q.sizePx, q.sizePx, Bitmap.Config.ARGB_8888)
}

/** Draws a [generateQrBitmap] bitmap at exactly its own pixel size, unfiltered. */
@Composable
internal fun CrispQrImage(bitmap: Bitmap, modifier: Modifier = Modifier, contentDescription: String? = null) {
    val sideDp: Dp = with(LocalDensity.current) { bitmap.width.toDp() }
    val image = remember(bitmap) { bitmap.asImageBitmap() }
    Image(
        bitmap = image,
        contentDescription = contentDescription,
        filterQuality = FilterQuality.None,
        modifier = Modifier.size(sideDp).then(modifier),
    )
}

/** Device pixels in [dp] - the budget to hand [generateQrBitmap]. */
@Composable
internal fun qrBudgetPx(dp: Dp): Int = with(LocalDensity.current) { dp.roundToPx() }
