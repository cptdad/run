package com.vg.run

import kotlinx.coroutines.delay
import java.io.File
import java.util.concurrent.TimeUnit

// ---------------------------------------------------------------------------
// The Tor CHILD PROCESS (split out of TorManager.kt): locating the bundled
// binary, spawning it, waiting for its notice log, and terminating it.
//
// Android runs the Tor binary directly via ProcessBuilder (not kmp-tor's
// TorService, whose ConnectivityReceiver is broken on API 34+). stdout and
// stderr are merged and discarded to /dev/null; bootstrap progress and the SOCKS
// port come from the NOTICE LOG FILE (TorNoticeLogTail.kt). TorManager keeps
// every field (torProcess, stopped) and the stop-raced-spawn check, which reads
// them.
// ---------------------------------------------------------------------------

/**
 * The Tor binary bundled (as a native lib, so Android extracts it executable) by
 * info.guardianproject:tor-android, inside [nativeLibDir].
 */
internal fun locateTorBinary(nativeLibDir: String): File {
    val torBinary = File(nativeLibDir, "libtor.so")
    // Never the path: nativeLibraryDir carries the per-install random dir name.
    platformLog("TorManager", "torBinary exists=${torBinary.exists()}")
    return torBinary
}

/** Starts Tor as a child process reading [torrc]. */
internal fun spawnTorProcess(torBinary: File, torrc: File): Process =
    ProcessBuilder(torBinary.absolutePath, "-f", torrc.absolutePath)
        // Discard the child's stdout/stderr rather than
        // leaving the merged pipe unread. Tor logs to the notice FILE (tailed
        // by TorNoticeLogTail.kt), so nothing consumes this stream — and an undrained subprocess
        // pipe DEADLOCKS the child the moment it writes > ~64 KiB to it.
        // Redirecting to /dev/null (Android is always Linux) drains it at the OS
        // level, exactly like Redirect.DISCARD.
        .redirectErrorStream(true)
        .redirectOutput(File("/dev/null"))
        .start()

/**
 * Waits up to [timeoutMs] for Tor's notice [logFile] to appear. True when it did.
 * Logs how long it took either way.
 */
internal suspend fun awaitNoticeLog(logFile: File, timeoutMs: Int = 10_000): Boolean {
    var waited = 0
    while (!logFile.exists() && waited < timeoutMs) {
        delay(200)
        waited += 200
    }
    if (!logFile.exists()) {
        platformLogError("TorManager", "Tor log never appeared after ${waited}ms")
        return false
    }
    platformLog("TorManager", "Tor log appeared after ${waited}ms")
    return true
}

/**
 * Terminates the Tor child [p]: SIGTERM, up to 2 s, then SIGKILL, up to 1 s.
 * True when the child is confirmed gone (or there was none).
 *
 * SIGTERM first: the child flushes its `state` file on the way out — exactly the
 * guard state TorManager KEEPS — so it gets the full wait rather than having
 * anything deleted underneath it. The wait matters too: destroy() only signals,
 * and a still-running Tor holding the DataDirectory would race the next
 * instance's start() (its lock file would trip it).
 *
 * Never throws. An interrupt is re-asserted on the thread and reported as "not
 * confirmed", so the caller keeps the session ephemera for the next start's purge
 * rather than deleting them under a live daemon. Deletes nothing itself.
 */
internal fun terminateTorChild(p: Process?): Boolean {
    if (p == null) return true
    return try {
        p.destroy()
        if (!p.waitFor(2, TimeUnit.SECONDS)) {
            platformLogWarn("TorManager", "Tor ignored SIGTERM — forcing")
            p.destroyForcibly()
            p.waitFor(1, TimeUnit.SECONDS)
        }
        !p.isAlive
    } catch (e: InterruptedException) {
        Thread.currentThread().interrupt()
        try { p.destroyForcibly() } catch (_: Exception) {}
        platformLogWarn("TorManager", "stop() interrupted while waiting for Tor to exit")
        false
    } catch (e: Exception) {
        try { p.destroyForcibly() } catch (_: Exception) {}
        platformLogError("TorManager", "stop() error: ${e.javaClass.simpleName}")
        false
    }
}
