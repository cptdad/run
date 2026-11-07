package com.vg.run

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.SocketTimeoutException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

// The COMMAND socket's wire helpers (TorControlWire.kt) over a scripted stream —
// the first two cases of the planned TorControlChannelTest (review R4 P1, cases 4
// and 6), written against today's TorManager wiring:
//  (4) a reply that TIMES OUT must never be read by the next command: the read
//      throws (it is not mapped to -1), so every caller drops the socket — and
//      the startup kick, which used to swallow it and KEEP the socket, now
//      reports DROP;
//  (6) a reply line over the cap must not leave its tail in the stream: the read
//      throws, so the socket is dropped.
class TorControlWireTest {

    // A fake control connection: every complete command written (one CRLF) makes
    // the next scripted reply readable. A reply can be lines, a timeout (the
    // SO_TIMEOUT throw — the late bytes stay queued, like a real late reply),
    // or raw bytes.
    private sealed class Reply {
        class Lines(vararg val lines: String) : Reply()
        // Times out ONCE; [late] then arrives behind the timeout.
        class Timeout(val late: String) : Reply()
        class Raw(val bytes: ByteArray) : Reply()
    }

    private class ScriptedControlStream(vararg script: Reply) {
        private val replies = ArrayDeque(script.toList())
        private val pending = ArrayDeque<Int>()
        private var timeoutArmed = false
        val written = ByteArrayOutputStream()

        val output: OutputStream = object : OutputStream() {
            override fun write(b: Int) {
                written.write(b)
                if (b == '\n'.code) serveNext()
            }
        }

        val input: InputStream = object : InputStream() {
            override fun read(): Int {
                if (timeoutArmed) {
                    timeoutArmed = false
                    throw SocketTimeoutException("Read timed out")
                }
                return pending.removeFirstOrNull() ?: throw SocketTimeoutException("Read timed out")
            }
        }

        private fun serveNext() {
            when (val r = replies.removeFirstOrNull() ?: return) {
                is Reply.Lines -> r.lines.forEach { queue("$it\r\n") }
                is Reply.Timeout -> { timeoutArmed = true; queue("${r.late}\r\n") }
                is Reply.Raw -> r.bytes.forEach { pending.addLast(it.toInt() and 0xFF) }
            }
        }

        private fun queue(text: String) = text.toByteArray(Charsets.US_ASCII).forEach { pending.addLast(it.toInt()) }

        // Bytes the daemon sent that nobody has read yet.
        val unread: Int get() = pending.size
    }

    // -- case 4: a reply that times out ------------------------------------

    @Test
    fun aTimedOutReply_throws_itIsNeverMappedToACode() {
        val s = ScriptedControlStream(Reply.Timeout(late = "250 OK"))
        torControlWrite(s.output, "SIGNAL NEWNYM\r\n")
        assertFailsWith<SocketTimeoutException> { torControlReadCode(s.input) }
        // The late reply is still in the stream: whoever reads next would take this
        // "250 OK" as ITS reply — which is why every caller drops the socket here.
        assertEquals("250 OK\r\n".length, s.unread)
        assertEquals("SIGNAL NEWNYM\r\n", s.written.toString(Charsets.US_ASCII))
    }

    @Test
    fun theStartupKick_reportsDrop_onATimedOutReply() {
        val s = ScriptedControlStream(Reply.Timeout(late = "250 OK"))
        assertEquals(StartupKickResult.DROP, torControlStartupKick(s.input, s.output, "SETCONF DisableNetwork=0\r\n"))
    }

    @Test
    fun theStartupKick_keepsTheSocket_onAWholeReply() {
        assertEquals(
            StartupKickResult.APPLIED,
            ScriptedControlStream(Reply.Lines("250 OK")).let { torControlStartupKick(it.input, it.output, "SETCONF DisableNetwork=0\r\n") },
        )
        val refused = ScriptedControlStream(Reply.Lines("552 Unrecognized option"))
        assertEquals(StartupKickResult.REFUSED, torControlStartupKick(refused.input, refused.output, "SETCONF DisableNetwork=0\r\n"))
        // A refusal is a WHOLE reply: nothing is left behind, the next command is in sync.
        assertEquals(0, refused.unread)
    }

    @Test
    fun theStartupKick_reportsDrop_whenTheWriteThrows() {
        val broken = object : OutputStream() {
            override fun write(b: Int) = throw IOException("broken pipe")
        }
        assertEquals(StartupKickResult.DROP, torControlStartupKick(ScriptedControlStream().input, broken, "SETCONF DisableNetwork=0\r\n"))
    }

    // -- case 6: an over-long reply line -----------------------------------

    @Test
    fun anOverLongLine_throws_insteadOfLeavingItsTailInTheStream() {
        val long = ByteArray(CONTROL_REPLY_MAX_BYTES + 904) { '5'.code.toByte() } + "\r\n".toByteArray()
        val s = ScriptedControlStream(Reply.Raw(long))
        torControlWrite(s.output, "SIGNAL NEWNYM\r\n")
        assertFailsWith<ControlReplyTooLongException> { torControlReadCode(s.input) }
        assertTrue(s.unread > 0, "the rest of the line is still queued — the socket must be dropped")
        val k = ScriptedControlStream(Reply.Raw(long))
        assertEquals(StartupKickResult.DROP, torControlStartupKick(k.input, k.output, "SETCONF DisableNetwork=0\r\n"))
    }

    @Test
    fun aLineJustUnderTheCap_isReadWhole() {
        // "250 " + x's + CR = cap - 1 bytes before the LF: the longest line read whole.
        val line = "250 " + "x".repeat(CONTROL_REPLY_MAX_BYTES - 6)
        val s = ScriptedControlStream(Reply.Lines(line, "250 OK"))
        torControlWrite(s.output, "GETINFO x\r\n")
        assertEquals(250, torControlReadCode(s.input))
        assertEquals(250, torControlReadCode(s.input))
        assertEquals(0, s.unread)
    }

    @Test
    fun aMultiLineReply_withAnOverLongLine_throws() {
        val s = ScriptedControlStream(Reply.Raw("250-a\r\n".toByteArray() + ByteArray(CONTROL_REPLY_MAX_BYTES) { 'x'.code.toByte() } + "\r\n250 OK\r\n".toByteArray()))
        torControlWrite(s.output, "GETINFO net/listeners/socks\r\n")
        assertFailsWith<ControlReplyTooLongException> { torControlReadLines(s.input) }
    }

    // -- the multi-line read, unchanged ------------------------------------

    @Test
    fun readLines_stopsAtTheFinalLine_withoutOverReading() {
        val s = ScriptedControlStream(Reply.Lines("250-net/listeners/socks=\"127.0.0.1:9150\"", "250 OK", "250 EXTRA"))
        torControlWrite(s.output, "GETINFO net/listeners/socks\r\n")
        assertEquals(listOf("250-net/listeners/socks=\"127.0.0.1:9150\"", "250 OK"), torControlReadLines(s.input))
        assertEquals(250, torControlReadCode(s.input))
    }

    @Test
    fun readLines_withNoFinalLineWithinTheCap_throws() {
        val s = ScriptedControlStream(Reply.Lines(*Array(CONTROL_REPLY_MAX_LINES + 1) { "250-x" }))
        torControlWrite(s.output, "GETINFO x\r\n")
        assertFailsWith<ControlReplyTooLongException> { torControlReadLines(s.input) }
    }

    @Test
    fun eofBeforeTheNewline_isStillMinusOne_notAThrow() {
        // Characterisation (case 5): the daemon is gone; the caller's next command fails anyway.
        val s = ScriptedControlStream(Reply.Raw("25".toByteArray()))
        torControlWrite(s.output, "SIGNAL NEWNYM\r\n")
        val eofAfterPending = object : InputStream() {
            override fun read(): Int = if (s.unread > 0) s.input.read() else -1
        }
        assertEquals(-1, torControlReadCode(eofAfterPending))
    }
}
