package com.vg.run

import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit

// Small pure-commonMain helpers shared across the managers so the
// Kotlin/Native-safe implementations live in exactly ONE place.

private const val HEX_DIGITS = "0123456789abcdef"

/**
 * Moves the first element matching [predicate] to index 0, keeping the relative
 * order of everything else. No-op when nothing matches or it is already first.
 */
internal fun <T> MutableList<T>.moveToFront(predicate: (T) -> Boolean) {
    val i = indexOfFirst(predicate)
    if (i > 0) add(0, removeAt(i))
}

/**
 * Fisher–Yates shuffle driven by the CSPRNG ([secureRandomInt]) — fan-out / poll
 * order must not be a predictable sequence an observer can align across events.
 * Shuffles in place.
 */
internal fun <T> MutableList<T>.secureShuffle() {
    for (i in size - 1 downTo 1) {
        val j = secureRandomInt(i + 1)
        val tmp = this[i]; this[i] = this[j]; this[j] = tmp
    }
}

/**
 * A CSPRNG-shuffled COPY of this collection ([secureShuffle] on a fresh list).
 * Same generator, same algorithm, same distribution as shuffling in place.
 */
internal fun <T> Iterable<T>.secureShuffled(): List<T> = toMutableList().also { it.secureShuffle() }

/**
 * The gap between two POSTs of one fan-out (group text copies + activity
 * notices, control fan-out, re-roster and membership redrive): a uniform
 * 250..1999 ms CSPRNG delay, so N same-sized appends never leave back-to-back —
 * a tight burst of N posts is the loudest group-shaped signature on the wire.
 * Blocking; background threads only.
 */
internal fun sleepInterSendJitter() = sleepMillis(250L + secureRandomInt(1750).toLong())

/**
 * Lowercase hex encoding of [bytes]. Kotlin/Native-safe (no `java.*`, no
 * `String.format`) so both platforms encode identically.
 */
internal fun bytesToHex(bytes: ByteArray): String =
    bytes.joinToString("") {
        val v = it.toInt() and 0xFF
        HEX_DIGITS[v ushr 4].toString() + HEX_DIGITS[v and 0xF]
    }

/**
 * GROUP-FANOUT: runs [fetch] over [items] with at most [cap] in flight
 * on [ioDispatcher], BLOCKING the calling thread until every one has finished, and
 * returns the results in INPUT order (index i ↔ items[i]) whatever order they
 * completed in. A throwing [fetch] degrades to null for that item only. One item
 * runs inline, without any coroutine machinery. Never call from the UI thread.
 */
internal fun <T, R> boundedParallelBlocking(items: List<T>, cap: Int, fetch: (T) -> R?): List<R?> {
    fun one(item: T): R? = try { fetch(item) } catch (e: Exception) {
        platformLogWarn("GroupManager", "fan-out item failed: ${e::class.simpleName}"); null
    }
    if (items.size <= 1) return items.map { one(it) }
    val out = MutableList<R?>(items.size) { null }
    val outLock = SyncLock()
    runBlockingIo {
        val gate = Semaphore(cap.coerceAtLeast(1))
        coroutineScope {
            items.forEachIndexed { i, item ->
                launch(ioDispatcher) {
                    gate.withPermit {
                        val r = one(item)
                        outLock.withLock { out[i] = r }
                    }
                }
            }
        }
    }
    return out
}
