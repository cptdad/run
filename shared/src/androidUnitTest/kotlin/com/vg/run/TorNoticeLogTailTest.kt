package com.vg.run

import java.io.File
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

// The complete-lines tail of Tor's NOTICE log ([TorNoticeLogTail]). Both readers
// are checked case by case: [TorNoticeLogTail.pollLines] (the pre-SOCKS tail) and
// [TorNoticeLogTail.pollLinesAt] (the watcher, which also needs byte offsets).
// The newline discipline is the real defence against the "…127.0.0.1:443" + "21"
// trap (a half-flushed port read as 443 / 4432), so it is pinned here, not left
// to the parser.
class TorNoticeLogTailTest {

    private val file: File = File.createTempFile("tor-notice", ".log").also { it.writeBytes(ByteArray(0)) }

    @AfterTest
    fun cleanup() {
        file.delete()
    }

    private fun append(bytes: ByteArray) = file.appendBytes(bytes)
    private fun append(text: String) = append(text.toByteArray(Charsets.UTF_8))

    // Each case runs once per reader; `poll` returns the lines of one poll.
    private fun forBothReaders(case: (poll: () -> List<String>, tail: TorNoticeLogTail) -> Unit) {
        file.writeBytes(ByteArray(0))
        val a = TorNoticeLogTail(file)
        case({ a.pollLines() }, a)
        file.writeBytes(ByteArray(0))
        val b = TorNoticeLogTail(file)
        case({ b.pollLinesAt().map { it.second } }, b)
    }

    @Test
    fun noNewlineYet_yieldsNothing_andConsumesNothing() = forBothReaders { poll, _ ->
        append("[notice] Bootstrapped 5% (conn)")
        assertEquals(emptyList(), poll())
        assertEquals(emptyList(), poll())
        // Nothing was consumed: the line arrives whole once its newline does.
        append("\n")
        assertEquals(listOf("[notice] Bootstrapped 5% (conn)"), poll())
    }

    @Test
    fun aPortSplitAcrossTwoPolls_arrivesWhole() = forBothReaders { poll, _ ->
        append("[notice] Socks listener listening on 127.0.0.1:443")
        assertEquals(emptyList(), poll())
        append("21\n")
        val lines = poll()
        assertEquals(listOf("[notice] Socks listener listening on 127.0.0.1:44321"), lines)
        assertEquals(44321, TorNoticeLog.parseSocksListenerPort(lines.single()))
    }

    @Test
    fun twoCompleteLinesAndAPartial_partialWaitsForTheNextPoll() = forBothReaders { poll, _ ->
        append("one\ntwo\nthr")
        assertEquals(listOf("one", "two"), poll())
        append("ee\n")
        assertEquals(listOf("three"), poll())
    }

    @Test
    fun pollLinesAt_offsetsAreByteOffsets_evenAfterAMultiByteLine() {
        val tail = TorNoticeLogTail(file)
        // "Ä\n" is 3 bytes (C3 84 0A), so the next line starts at byte 3, not char 2.
        append("Ä\nab\n")
        assertEquals(listOf(0L to "Ä", 3L to "ab"), tail.pollLinesAt())
        append("cd\n")
        assertEquals(listOf(6L to "cd"), tail.pollLinesAt())
    }

    @Test
    fun aMalformedByte_decodesTheSameInBothReaders() {
        val bytes = byteArrayOf('x'.code.toByte(), 0xFF.toByte(), 'y'.code.toByte(), '\n'.code.toByte(), 'z'.code.toByte(), '\n'.code.toByte())
        append(bytes)
        val viaLines = TorNoticeLogTail(file).pollLines()
        val viaAt = TorNoticeLogTail(file).pollLinesAt().map { it.second }
        assertEquals(viaLines, viaAt)
        assertEquals(2, viaLines.size)
        assertTrue(viaLines[0].startsWith("x") && viaLines[0].endsWith("y"))
    }

    @Test
    fun aPollAfterNothingNew_isEmpty() = forBothReaders { poll, _ ->
        append("a\n")
        assertEquals(listOf("a"), poll())
        assertEquals(emptyList(), poll())
    }
}
