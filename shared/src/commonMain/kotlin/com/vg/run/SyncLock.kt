package com.vg.run

// ---------------------------------------------------------------------------
// SyncLock — minimal mutual-exclusion primitive for commonMain.
//
// Kotlin commonMain has no lock type without pulling in a coroutines/atomicfu
// dependency, so this follows the project's expect/actual pattern:
// ReentrantLock on Android/JVM, NSLock on iOS. Used by GroupManager to guard
// its in-memory message-routing buffers against concurrent poll loops.
// ---------------------------------------------------------------------------

internal expect class SyncLock() {
    fun lock()
    fun unlock()
}

internal inline fun <T> SyncLock.withLock(block: () -> T): T {
    lock()
    try {
        return block()
    } finally {
        unlock()
    }
}
