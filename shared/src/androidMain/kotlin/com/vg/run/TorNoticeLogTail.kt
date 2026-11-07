package com.vg.run

import java.io.File
import java.io.RandomAccessFile

// ---------------------------------------------------------------------------
// Tor NOTICE log reading (split out of TorManager.kt): the line parsers and the
// complete-lines tail. TorManager learns bootstrap progress and the SOCKS
// listener port from this FILE (`Log notice file <dataDir>/tor.log`), never from
// the process streams (those go to /dev/null — see TorProcess.kt).
// ---------------------------------------------------------------------------

/**
 * One `Bootstrapped NN% (tag)` NOTICE line, reduced to the two identifier-free
 * fields the connection-log panel shows. See [TorNoticeLog.parseBootstrapProgress].
 */
internal data class BootstrapProgress(val percent: Int, val tag: String)

// The pure NOTICE-line parsers (TorManager calls them directly).
internal object TorNoticeLog {

    private val SOCKS_LINE =
        Regex("Socks listener listening on (?:port |127\\.0\\.0\\.1:)(\\d+)")

    /**
     * `Bootstrapped 5% (conn): Connecting to a relay` — percent plus the
     * PARENTHESISED TAG only. The rest of the line is Tor's human SUMMARY
     * prose, which is exactly the kind of free-form text the connection-log
     * producer rule keeps out of a release-visible panel (it is the same
     * field that carries "Problem bootstrapping. Stuck at …" with a relay
     * address appended on some paths). The tag is a closed vocabulary
     * (`starting`, `conn`, `handshake`, `requesting_descriptors`, …).
     */
    private val BOOTSTRAP_LINE =
        Regex("Bootstrapped (\\d+)%(?:\\s*\\(([A-Za-z0-9_]+)\\))?")

    /**
     * The SOCKS port from a Tor NOTICE log [line], or null if the line does not
     * announce one.
     *
     * Unit-tested (TorSocksLogParseTest) because this parser has a history of
     * trap-class hostile-input bugs — see [TorNoticeLogTail], where a
     * partially-flushed line let "…127.0.0.1:44321" be read as port 4432.
     * Returns null rather than a partial number for anything out of port range,
     * so a malformed or truncated line can never point the app's SOCKS traffic
     * at some other local process (a deanonymisation / capability-leak hazard).
     */
    fun parseSocksListenerPort(line: String): Int? {
        val port = SOCKS_LINE.find(line)?.groupValues?.get(1)?.toIntOrNull() ?: return null
        return if (port in 1..65535) port else null
    }

    /**
     * The bootstrap percent and phase TAG from a Tor NOTICE log [line], or
     * null if the line announces no bootstrap progress. Pure so the
     * "summary prose never reaches the connection log" property is
     * unit-testable (see [BOOTSTRAP_LINE]). [BootstrapProgress.tag] is empty
     * when the line carries no parenthesised tag.
     */
    fun parseBootstrapProgress(line: String): BootstrapProgress? {
        val m = BOOTSTRAP_LINE.find(line) ?: return null
        val pct = m.groupValues[1].toIntOrNull() ?: return null
        return BootstrapProgress(pct, m.groupValues[2])
    }

    /** The connection-log text for a bootstrap line: percent + tag, nothing else. */
    fun bootstrapLogLine(progress: BootstrapProgress): String =
        if (progress.tag.isEmpty()) "bootstrap ${progress.percent}%"
        else "bootstrap ${progress.percent}% ${progress.tag}"
}

/**
 * Tails [logFile] from offset 0, handing out only COMPLETE lines (terminated by
 * '\n'). A line Tor has only partially flushed is left in the file for the next
 * poll instead of being handed to a parser as a fragment. The old
 * RandomAccessFile.readLine() returned the partial tail AND advanced past it, so
 * a "…127.0.0.1:44321\n" split across two polls could be mis-parsed as the bogus
 * port 4432 (SOCKS on the wrong port is a deanonymization/plaintext-leak hazard),
 * and a "Bootstrapped 100%" split could wedge the state at Bootstrapping.
 *
 * One instance per tail loop; not thread-safe (each loop polls from one coroutine).
 */
internal class TorNoticeLogTail(private val logFile: File) {

    /** Offset just past the last newline consumed. */
    private var lastPos = 0L

    // The complete lines written since the last poll (empty when none). Same
    // bytes and same decode as [pollLinesAt]: '\n' (0x0A) never occurs inside a
    // UTF-8 multi-byte sequence, so a per-line decode equals the whole-buffer
    // decode + split, malformed bytes included (TorNoticeLogTailTest).
    fun pollLines(): List<String> = pollLinesAt().map { it.second }

    /**
     * [pollLines] plus each line's BYTE offset in the file, split on the raw
     * bytes (before decoding, so a non-ASCII byte cannot skew an offset). The
     * post-SOCKS watcher needs the offset to tell Tor's ORIGINAL SOCKS listener
     * line from the one a bootstrap-stall kick causes (see
     * TorManager.adoptMovedSocksListener).
     */
    fun pollLinesAt(): List<Pair<Long, String>> {
        val buf = readNew() ?: return emptyList()
        val lastNl = buf.lastIndexOf('\n'.code.toByte())
        if (lastNl < 0) return emptyList()
        val base = lastPos
        val out = ArrayList<Pair<Long, String>>()
        var start = 0
        for (i in 0..lastNl) {
            if (buf[i] == '\n'.code.toByte()) {
                out.add((base + start) to buf.copyOfRange(start, i).decodeToString())
                start = i + 1
            }
        }
        lastPos = base + lastNl + 1
        return out
    }

    /** The bytes from [lastPos] to the current end of the file, or null if none. */
    private fun readNew(): ByteArray? {
        val len = logFile.length()
        if (len <= lastPos) return null
        RandomAccessFile(logFile, "r").use { reader ->
            reader.seek(lastPos)
            val buf = ByteArray((len - lastPos).toInt())
            reader.readFully(buf)
            return buf
        }
    }
}
