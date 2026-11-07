package com.vg.run

import java.io.File

/**
 * Every Android Tor source file, for the source guards that must FOLLOW CODE
 * ACROSS A FILE SPLIT: the log scans of [HsCircuitRungParitySourceTest],
 * [HsDirPinParitySourceTest] and [RelayAddressRaceParitySourceTest], and the
 * negative `ControlPort` check of [TorNewNymSelfHealSourceTest].
 *
 * Without this, moving a block out of TorManager.kt into a new `Tor*.kt` file
 * would silently drop it from those scans, and they would keep passing (their
 * `scanned > 20` floor is met by what stays behind).
 *
 * TorManager.kt comes FIRST, then the other `Tor*.kt` files of the package in
 * name order. TorControlEvents.kt is left out on purpose: the guards read it as
 * their separate `reader` / `events` text. Ordering pins (`indexOf`
 * comparisons) keep reading TorManager.kt alone.
 *
 * [strip] = true applies the shared [stripComments]. The three parity tests need
 * its `keepUrls = true` form (it keeps `http://` inside string literals), so they
 * pass `strip = false` and call `stripComments(text, keepUrls = true)` themselves.
 */
internal fun androidTorSources(strip: Boolean = true): String =
    androidTorFiles().joinToString("\n") { f -> f.readText().let { if (strip) stripComments(it) else it } }

/** The file names [androidTorSources] reads, for failure messages. */
internal fun androidTorSourceNames(): List<String> = androidTorFiles().map { it.name }

// The one file filter both functions use: TorManager.kt first, then the other
// `Tor*.kt` files in name order, TorControlEvents.kt excluded. Never empty.
private fun androidTorFiles(): List<File> {
    val dir = File(repoRoot(), "shared/src/androidMain/kotlin/com/vg/run")
    val files = dir.listFiles { f ->
        f.isFile && f.name.startsWith("Tor") && f.name.endsWith(".kt") && f.name != "TorControlEvents.kt"
    }!!.sortedWith(compareBy({ it.name != "TorManager.kt" }, { it.name }))
    check(files.isNotEmpty() && files.first().name == "TorManager.kt") {
        "androidTorSources: TorManager.kt not found in $dir — this guard must never silently scan nothing"
    }
    return files
}
