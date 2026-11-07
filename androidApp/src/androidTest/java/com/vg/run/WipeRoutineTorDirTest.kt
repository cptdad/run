package com.vg.run

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Every wipe entry point must delete the Tor working
 * directory so a wipe leaves no forensic proof Tor was used. This pins that
 * WipeRoutine — the single source of truth for all wipe paths — clears both Tor
 * dirs.
 *
 * LOAD-BEARING since 2026-08-01, not belt-and-braces: the working dirs are now
 * deliberately PRESERVED across an ordinary stop/start (guard + consensus reuse —
 * see `TorManager.dataDir`), so `TorManager.stop()` deletes nothing and this
 * routine is the only routine deletion left. The preserve half is pinned by
 * [TorDataDirPreservationTest].
 */
class WipeRoutineTorDirTest {

    /**
     * The EXACT production paths a preserved session leaves behind:
     * `filesDir/tor_direct/data` (entry-guard `state`) and
     * `cacheDir/tor_direct/cache` (cached consensus/microdescriptors).
     */
    @Test
    fun wipe_deletesThePreservedProductionPaths() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()

        val data = File(ctx.filesDir, "tor_direct/data").apply { mkdirs() }
        File(data, "state").writeText("guard-state")
        val cache = File(ctx.cacheDir, "tor_direct/cache").apply { mkdirs() }
        File(cache, "cached-microdesc-consensus").writeText("x")
        assertTrue(data.exists() && cache.exists())

        WipeRoutine.wipePersistentState(ctx)

        assertFalse("the preserved DataDirectory must be gone after wipe", data.exists())
        assertFalse("the preserved CacheDirectory must be gone after wipe", cache.exists())
        assertFalse(File(ctx.filesDir, "tor_direct").exists())
        assertFalse(File(ctx.cacheDir, "tor_direct").exists())
    }

    @Test
    fun wipe_deletesTorWorkingDirs() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()

        val filesTor = File(ctx.filesDir, "tor_direct")
        val sess = File(filesTor, "sess1").apply { mkdirs() }
        File(sess, "state").writeText("guard-state")
        File(sess, "cached-microdesc-consensus").writeText("x")
        val cacheTor = File(ctx.cacheDir, "tor_direct").apply { mkdirs() }
        File(cacheTor, "lock").writeText("x")
        assertTrue(filesTor.exists() && cacheTor.exists())

        WipeRoutine.wipePersistentState(ctx)

        assertFalse("filesDir/tor_direct must be gone after wipe", filesTor.exists())
        assertFalse("cacheDir/tor_direct must be gone after wipe", cacheTor.exists())
    }

    /**
     * LEGACY warm-Tor-cache: the encrypted consensus/guard-state blob lives at a
     * TOP-LEVEL sibling of tor_direct/ — OUTSIDE the tree the existing wipe
     * sweeps — so WipeRoutine must delete it EXPLICITLY, or a wipe would leave an
     * AEAD-encrypted-but-undeleted artifact behind (a forensic residue).
     *
     * The feature is RETIRED (2026-07-31) and nothing writes this blob any more,
     * but installs that ran it still carry one and the wipe must keep destroying
     * it by name — see LegacyTorWarmCachePurgeTest for the full artifact set
     * (alias + keyset + blob + .tmp) and the one-time launch purge.
     */
    @Test
    fun wipe_deletesTorWarmCacheBlob() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()

        val blob = File(ctx.filesDir, "tor_warm_cache.enc").apply { writeText("dummy-ciphertext") }
        assertTrue(blob.exists())

        WipeRoutine.wipePersistentState(ctx)

        assertFalse("tor_warm_cache.enc must be gone after wipe", blob.exists())
    }
}
