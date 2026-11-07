package com.vg.run

// ---------------------------------------------------------------------------
// LogBuffer — in-memory circular log buffer for debugging.
//
// Captures log entries from platformLog/platformLogWarn/platformLogError
// and makes them available to the in-app log viewer. Purely on-device:
// nothing is shipped off the device (the old Loki telemetry sink was
// removed).
//
// Thread safety: appended concurrently from the Tor watcher (Dispatchers.IO),
// OkHttp execute threads, PoW workers, and Main. The
// backing list was originally unsynchronized — concurrent add()/removeFirst() while
// getAll()/asText() iterate can throw ConcurrentModificationException /
// IndexOutOfBounds (a crash, NOT merely a "skipped entry"). A SyncLock now
// guards every access. Release is unaffected either way (append() is a no-op
// unless LoggingState.enabled, which App Store / Play builds never flip on),
// so this only removes a debug/e2e crash-flake source.
//
// TEMPORARY: remove when beta testing is complete.
// ---------------------------------------------------------------------------

data class LogEntry(
    val timestamp: Long,
    val level: String,   // "D", "W", "E"
    val tag: String,
    val message: String,
    /**
     * Position in the process-wide [DebugLogSeq] stream, shared with
     * [ConnectionLog.Line.seq] so the two buffers merge into ONE ordered stream
     * for [DebugLogUploader]'s cursor. RAM-only, starts at 0 every launch,
     * never persisted, never on the wire. Defaulted so the data class stays
     * constructible the way every existing call site builds it.
     */
    val seq: Long = 0L
) {
    fun formatted(): String {
        val t = timestamp % 86_400_000L
        val h = (t / 3_600_000L) % 24L
        val m = (t / 60_000L) % 60L
        val s = (t / 1_000L) % 60L
        val ms = t % 1_000L
        return "${pad2(h)}:${pad2(m)}:${pad2(s)}.${pad3(ms)} $level/$tag: $message"
    }
}

private fun pad2(v: Long): String = if (v < 10) "0$v" else "$v"
private fun pad3(v: Long): String = when {
    v < 10  -> "00$v"
    v < 100 -> "0$v"
    else    -> "$v"
}

object LogBuffer {
    private const val MAX_ENTRIES = 2000
    private val entries = mutableListOf<LogEntry>()
    private val lock = SyncLock()

    fun append(level: String, tag: String, message: String) {
        // Master kill switch — see LoggingState. App Store / Play Store
        // production builds never flip this on, so this whole method is
        // a no-op there: nothing in memory, nothing on disk, no telemetry.
        if (!LoggingState.enabled) return
        lock.withLock {
            entries.add(
                LogEntry(
                    timestamp = currentTimeMillis(),
                    level = level,
                    tag = tag,
                    message = message,
                    // Drawn INSIDE the lock so the buffer stays seq-ordered.
                    seq = DebugLogSeq.next()
                )
            )
            // removeAt(0), NOT removeFirst(): the latter resolves to JDK 21's
            // SequencedCollection method and throws NoSuchMethodError on every
            // older runtime (minSdk 30 devices, the JVM unit-test tier). Latent
            // here only because a test never reaches MAX_ENTRIES; ConnectionLog
            // hit it for real. Same fix, same reason — keep them in step.
            while (entries.size > MAX_ENTRIES) {
                entries.removeAt(0)
            }
        }
    }

    fun getAll(): List<LogEntry> = lock.withLock { entries.toList() }

    /**
     * Entries whose [LogEntry.seq] is strictly above [seq], newest last — what
     * [DebugLogUploader] has not shipped yet. Ring eviction can drop entries
     * before they are ever read; that is accepted (a device producing 2000 log
     * lines faster than a 1 Hz tick can drain them has bigger problems than a
     * gap in the upload).
     */
    fun since(seq: Long): List<LogEntry> = lock.withLock { entries.filter { it.seq > seq } }

    fun clear() = lock.withLock { entries.clear() }

    fun asText(): String = getAll().joinToString("\n") { it.formatted() }
}
