package com.vg.run

import platform.Foundation.NSLock

internal actual class SyncLock {
    private val lock = NSLock()
    actual fun lock() = lock.lock()
    actual fun unlock() = lock.unlock()
}
