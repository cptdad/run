package com.vg.run

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

// ---------------------------------------------------------------------------
// The COMMAND socket's wire helpers (split out of TorManager.kt so they run in a
// JVM unit test over a scripted stream — TorControlWireTest). Stream-level only:
// TorManager owns the LocalSocket, the lock and every drop-the-socket decision.
//
// THE ONE RULE these helpers serve: a reply that was not read WHOLE leaves the
// stream in an unknown state, and the next command would read the leftover as
// its own reply (a late `250 OK` taken as a NEWNYM's success, a GETINFO reply
// mis-parsed into SOCKS_LOST). So every helper either consumes a complete reply
// or THROWS, and every TorManager caller drops the socket on a throw:
//  * a read timeout (SO_TIMEOUT) throws `SocketTimeoutException` from the stream;
//  * a line longer than [CONTROL_REPLY_MAX_BYTES] throws [ControlReplyTooLongException]
//    (the rest of the line is still in the stream — it is never resynchronised);
//  * a multi-line reply with no final line within [CONTROL_REPLY_MAX_LINES] throws
//    the same exception, for the same reason.
// EOF before a newline is NOT a throw (unchanged): the partial line is parsed,
// usually to -1, and the daemon is gone anyway.
//
// Async 650 events never reach this socket (no SETEVENTS on it; the event socket
// is TorControlEvents.kt), so a one-line read is a whole reply for every
// single-line command.
// ---------------------------------------------------------------------------

// A cap on a single control reply line so a garbled/hostile stream can't grow
// the read unbounded; real replies here ("250 OK\r\n" / "515 …\r\n") are tiny.
internal const val CONTROL_REPLY_MAX_BYTES = 4096

// A cap on the lines of one multi-line reply (`GETINFO net/listeners/socks` is one
// `250-` line plus `250 OK`).
internal const val CONTROL_REPLY_MAX_LINES = 16

// A reply that could not be read whole within the caps: the stream is
// desynchronised and must be dropped. Carries no stream content.
internal class ControlReplyTooLongException : IOException("control reply over the cap")

// Writes one complete control [command] (already CRLF-terminated) and flushes it.
internal fun torControlWrite(output: OutputStream, command: String) {
    output.write(command.toByteArray(Charsets.US_ASCII))
    output.flush()
}

// One reply line without its CR/LF; `eof` = the stream ended before the newline.
// Throws [ControlReplyTooLongException] on a line of [CONTROL_REPLY_MAX_BYTES]
// bytes or more with no newline, and whatever the stream throws (timeout).
private fun readLine(input: InputStream): Pair<String, Boolean> {
    val line = StringBuilder()
    var count = 0
    while (true) {
        val b = input.read()
        if (b < 0) return line.toString() to true
        if (b == '\n'.code) return line.toString() to false
        count++
        if (count >= CONTROL_REPLY_MAX_BYTES) throw ControlReplyTooLongException()
        if (b != '\r'.code) line.append(b.toChar())
    }
}

// ONE reply line's 3-digit status (-1 if malformed / EOF).
internal fun torControlReadCode(input: InputStream): Int {
    val (line, _) = readLine(input)
    if (line.length < 3) return -1
    return line.substring(0, 3).toIntOrNull() ?: -1
}

// One whole reply (`250-…` lines up to the final `250 …` line, or EOF), bounded.
internal fun torControlReadLines(input: InputStream): List<String> {
    val lines = ArrayList<String>()
    while (true) {
        if (lines.size >= CONTROL_REPLY_MAX_LINES) throw ControlReplyTooLongException()
        val (line, eof) = readLine(input)
        lines += line
        if (eof || isFinalReplyLine(line)) return lines
    }
}

// What the startup kick left behind on the socket.
internal enum class StartupKickResult {
    // `250`: Tor rescanned its periodic events.
    APPLIED,
    // A whole non-250 reply was read: the stream is in sync, the socket stays.
    REFUSED,
    // The write or the read threw (timeout, over-long line, I/O): the reply may
    // still be in the stream — the caller must drop this socket.
    DROP,
}

// The startup kick's exchange (TorManager.sendStartupKick has the why): one
// re-enable SETCONF and its one-line reply. Never throws.
internal fun torControlStartupKick(input: InputStream, output: OutputStream, command: String): StartupKickResult =
    try {
        torControlWrite(output, command)
        if (torControlReadCode(input) == 250) StartupKickResult.APPLIED else StartupKickResult.REFUSED
    } catch (_: Exception) {
        StartupKickResult.DROP
    }
