package com.vg.run

import kotlin.concurrent.Volatile

/**
 * Master kill switch for the on-device [LogBuffer] circular buffer that
 * backs the in-app log viewer.
 *
 * Defaults to `false`, and `scripts/verify-release-clean.sh` pins that default
 * so a production build that is never told otherwise holds nothing in memory
 * and surfaces nothing in the in-app log viewer.
 *
 * Three things flip it on, and only three:
 *   - iOS RunApp.init, under `#if DEBUG`.
 *   - Android RunApplication.onCreate, when BuildConfig.DEBUG.
 *   - [DebugMode.setEnabled] / [DebugMode.applyAtStartup] — the user-consented
 *     "Debug mode" (2026-09-14), which flips it on **in release builds too**.
 *     That is the point of the feature: the user chose to have the app collect
 *     diagnostics, and [DebugLogUploader] then ships them, redacted, to the
 *     relay. So do NOT write here (or anywhere else) that a production build
 *     never enables it — a production build never enables it *by itself*.
 *
 * With it off, [LogBuffer.append] is a no-op end to end: nothing is held in
 * memory, and memory inspection of a production install reveals no usage trail
 * beyond the encrypted DBs themselves. With it on, the buffer is RAM-only and
 * is still cleared on lock and on wipe.
 */
object LoggingState {
    @Volatile
    var enabled: Boolean = false
}
