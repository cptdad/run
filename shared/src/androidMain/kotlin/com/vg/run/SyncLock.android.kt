package com.vg.run

internal actual class SyncLock {
    private val lock = java.util.concurrent.locks.ReentrantLock()
    actual fun lock() = lock.lock()
    actual fun unlock() = lock.unlock()
}
