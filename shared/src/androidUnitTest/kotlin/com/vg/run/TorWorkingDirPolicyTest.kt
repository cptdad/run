package com.vg.run

import java.io.File
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The preserve-vs-discard policy for Tor's working dirs (2026-08-01).
 *
 * Tor's DataDirectory now SURVIVES an ordinary stop/start so a relaunch reuses
 * its entry guards and cached consensus instead of re-sampling guards and paying
 * a full cold descriptor fetch (a live capture measured a cold Tor reporting
 * `Bootstrapped 100%` in ~7 s and then failing every onion rendezvous for
 * minutes). The two halves of that decision are pinned here at the tier where
 * they are expressible without an Application or the Tor binary:
 *
 *  1. an ordinary start keeps every cached-state file and clears ONLY the
 *     per-session ephemera;
 *  2. the start-time sibling purge can never delete the retained dir.
 *
 * The wipe half — every wipe path still destroying both trees — is pinned by the
 * instrumented `WipeRoutineTorDirTest` / `TorDataDirPreservationTest`, which need
 * a real Context.
 */
class TorWorkingDirPolicyTest {

    private val tmp: File = Files.createTempDirectory("tor-data-dir-policy").toFile()

    @AfterTest
    fun cleanUp() {
        tmp.deleteRecursively()
    }

    /**
     * The property the whole change rests on: everything Tor caches survives a
     * restart. `state` is the entry-guard file — re-sampling guards on every
     * launch is an anonymity cost, not just a latency one.
     */
    @Test
    fun preparingAPreservedDataDir_keepsGuardStateAndCaches() {
        val kept = listOf(
            "state",                          // entry guards + bw history
            "cached-microdesc-consensus",
            "cached-microdescs",
            "cached-certs",
            "lock",                           // advisory flock; released when its holder dies
        )
        kept.forEach { File(tmp, it).writeText("keep-$it") }
        File(tmp, "diff-cache").mkdirs()
        File(tmp, "diff-cache/entry").writeText("keep")

        purgeSessionEphemera(tmp)

        kept.forEach {
            assertTrue(File(tmp, it).exists(), "$it must survive an ordinary restart")
        }
        assertTrue(File(tmp, "diff-cache/entry").exists(), "diff-cache must survive too")
    }

    /**
     * `tor.log` is not hygiene, it is load-bearing: `TorManager.start` tails the
     * notice log from offset 0 to learn the SOCKS port, so a log left behind by a
     * session that died before its post-bootstrap delete would hand the new
     * session the PREVIOUS run's `Socks listener listening on 127.0.0.1:NNNN` — a
     * port this process does not own and that any local app may have re-bound.
     * `torrc` is regenerated from [buildTorrc] every start; deleting it first
     * means a stale config can never be what Tor reads.
     *
     * The control socket (`cp`) + auth cookie (`control_auth_cookie`) join them
     * (parity with iOS `purgeSessionEphemera`): a stale 32-byte cookie left by a
     * previous run would pass the length guard and be AUTHENTICATEd against the
     * FRESH daemon's newly-minted cookie, so it must be cleared before start.
     */
    @Test
    fun preparingAPreservedDataDir_removesThePerSessionFiles() {
        File(tmp, "tor.log").writeText("Sep 01 00:00:00 Socks listener listening on 127.0.0.1:41111\n")
        File(tmp, "torrc").writeText("SocksPort auto\n")
        File(tmp, "cp").writeText("stale-socket-file")
        File(tmp, "control_auth_cookie").writeBytes(ByteArray(32) { 0x11 })

        purgeSessionEphemera(tmp)

        assertFalse(File(tmp, "tor.log").exists(), "a stale notice log would leak the PREVIOUS run's SOCKS port")
        assertFalse(File(tmp, "torrc").exists(), "torrc is rewritten every start; never inherit one")
        assertFalse(File(tmp, "cp").exists(), "a stale control socket file must not be inherited")
        assertFalse(
            File(tmp, "control_auth_cookie").exists(),
            "a stale 32-byte control auth cookie would be AUTHENTICATEd against the fresh daemon's " +
                "cookie — it must be cleared before start",
        )
        assertEquals(
            listOf("control_auth_cookie", "cp", "tor.log", "torrc"),
            TOR_SESSION_EPHEMERAL_FILES.sorted(),
            "adding an ephemeral file is a deliberate act — it must not silently widen what a " +
                "restart discards",
        )
    }

    /** Idempotent, and inert on a directory that has neither file. */
    @Test
    fun preparingAPreservedDataDir_isIdempotentAndCreatesNothing() {
        File(tmp, "state").writeText("guards")
        val before = tmp.list()!!.toSortedSet()

        repeat(3) { purgeSessionEphemera(tmp) }

        assertEquals(before, tmp.list()!!.toSortedSet(), "the prepare step must never CREATE a file")
    }

    /**
     * The start-time purge exists to sweep legacy per-session dirs (`s1`, `s2`, …)
     * minted by the builds that wiped on every start, plus anything a crashed
     * launch stranded. It must never touch the retained dir — that would silently
     * restore the old wipe-on-every-start behaviour.
     */
    @Test
    fun staleDirPurge_neverTouchesTheRetainedDir() {
        val purged = staleTorDirsToPurge(
            listOf("s1", "s2", "s17", TOR_DATA_DIR_NAME, "junk"),
            TOR_DATA_DIR_NAME,
        )
        assertFalse(purged.contains(TOR_DATA_DIR_NAME), "the retained data dir must never be purged")
        assertEquals(listOf("s1", "s2", "s17", "junk"), purged)

        val cachePurged = staleTorDirsToPurge(listOf("s1", TOR_CACHE_DIR_NAME), TOR_CACHE_DIR_NAME)
        assertEquals(listOf("s1"), cachePurged)

        assertTrue(
            staleTorDirsToPurge(listOf(TOR_DATA_DIR_NAME), TOR_DATA_DIR_NAME).isEmpty(),
            "a directory holding only the retained dir must be left completely alone",
        )
    }

    /** The retained names are part of the on-disk contract every wipe path targets. */
    @Test
    fun workingDirNamesAreStable() {
        assertEquals("tor_direct", TOR_ROOT_DIR_NAME)
        assertEquals("data", TOR_DATA_DIR_NAME)
        assertEquals("cache", TOR_CACHE_DIR_NAME)
    }
}
