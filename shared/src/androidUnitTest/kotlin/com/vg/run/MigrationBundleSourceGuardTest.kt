package com.vg.run

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// RÚN-04 part (b) — SOURCE guard: no String (or StringBuilder) of the WHOLE device-move
// bundle is built on either side of the codec.
//
// A source guard on purpose: "this code never materialises the whole document as an
// immutable String" is a property of the code's shape, which no behavioural test can
// observe (a String is unreachable and unwipeable by construction). The behavioural
// halves are MigrationBundleBufferHygieneTest (the encoder's byte buffers are zeroed)
// and MigrationBundleGoldenTest / MigrationBundleDifferentialTest (same wire format).
//
// Allowed by design (D2): per-field `decodeToString(start, end)` in the decoder and the
// per-value `jsonEscapeString(...)` in the encoder; the two test-only text wrappers.
// ---------------------------------------------------------------------------
class MigrationBundleSourceGuardTest {

    private val file = source("shared/src/commonMain/kotlin/com/vg/run/MigrationBundle.kt")

    private fun section(from: String, to: String?): String {
        val a = file.indexOf(from)
        assertTrue(a >= 0, "marker not found: $from")
        val b = if (to == null) file.length else file.indexOf(to, a)
        assertTrue(b > a, "marker not found: $to")
        return file.substring(a, b)
    }

    private val codec get() = section("object MigrationBundleCodec {", "\nobject MigrationSeal {")
    private val reader get() = section("internal object MigJson {", null)

    @Test
    fun productionEncodeAndDecode_goThroughTheBytePaths() {
        assertTrue(codec.contains("fun encode(b: MigrationBundle): ByteArray = encodeInto(b, WipingByteSink())"))
        assertTrue(codec.contains("val doc = MigJson.parseBundleDocument(bytes)"))
        assertTrue(reader.contains("fun parseBundleDocument(bytes: ByteArray): MigDocument?"))
        assertFalse(Regex("""fun parseBundleDocument\([^)]*String""").containsMatchIn(file), "no String entry point to the reader")
    }

    @Test
    fun noWholeDocumentStringOrBuilder_inTheCodecOrTheReader() {
        // The encoder writes into WipingByteSink only.
        assertFalse(codec.contains("StringBuilder"), "the bundle encoder must not build the document in a StringBuilder")
        // The only whole-array decodeToString() in the codec is the test-only text wrapper.
        val wholeDecodes = Regex("""\.decodeToString\(\)""").findAll(codec).count()
        assertEquals(1, wholeDecodes, "only encodeToString (test-only wrapper) may call decodeToString() on a whole bundle")
        assertTrue(codec.contains("internal fun encodeToString(b: MigrationBundle): String = encode(b).decodeToString()"))
        // The reader decodes slices only.
        assertFalse(reader.contains(".decodeToString()"), "the reader must decode per field, never the whole document")
        assertEquals(2, Regex("""decodeToString\(""").findAll(reader).count(), "one run decode + one string-token decode")
        assertTrue(reader.contains("b.decodeToString(start, i)") && reader.contains("b.decodeToString(i, e)"))
    }

    @Test
    fun theTextWrappers_areNeverCalledFromProductionCode() {
        val roots = listOf("shared/src/commonMain", "shared/src/androidMain", "shared/src/iosMain", "androidApp/src", "iosApp/iosApp")
        val offenders = ArrayList<String>()
        for (r in roots) {
            File(repoRoot(), r).walkTopDown().filter { it.isFile && (it.extension == "kt" || it.extension == "swift") }.forEach { f ->
                val text = f.readText()
                for (w in listOf("encodeToString(", "decodeFromString(")) {
                    var at = text.indexOf(w)
                    while (at >= 0) {
                        val line = text.substring(text.lastIndexOf('\n', at) + 1, text.indexOf('\n', at).let { if (it < 0) text.length else it })
                        val isDefinition = f.name == "MigrationBundle.kt" && line.trimStart().startsWith("internal fun ")
                        if (line.contains("MigrationBundleCodec") || (f.name == "MigrationBundle.kt" && !isDefinition)) {
                            offenders += "${f.path}: ${line.trim()}"
                        }
                        at = text.indexOf(w, at + 1)
                    }
                }
            }
        }
        assertTrue(offenders.isEmpty(), "test-only bundle text wrappers used in production:\n" + offenders.joinToString("\n"))
    }

    private fun source(path: String): String {
        val f = File(repoRoot(), path)
        assertTrue(f.isFile, "missing $path")
        return f.readText()
    }

    private fun repoRoot(): File {
        var d: File? = File("").absoluteFile
        while (d != null) {
            if (File(d, "settings.gradle.kts").isFile) return d
            d = d.parentFile
        }
        throw AssertionError("repo root not found above ${File("").absoluteFile}")
    }
}
