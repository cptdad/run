package com.vg.run

// ---------------------------------------------------------------------------
// Platform — expect declarations for platform-specific utilities.
//
// These functions abstract away Android/iOS differences so that code in
// commonMain can encode/decode Base64, generate random bytes, create UUIDs,
// and log messages without importing platform-specific packages.
// ---------------------------------------------------------------------------

/** Logs a debug-level message. */
expect fun platformLog(tag: String, message: String)

/** Logs a warning-level message. */
expect fun platformLogWarn(tag: String, message: String)

/** Logs an error-level message. */
expect fun platformLogError(tag: String, message: String, throwable: Throwable? = null)

/** Encodes [data] as a Base64 string (no wrapping). */
expect fun encodeBase64(data: ByteArray): String

/** Decodes a Base64 [encoded] string back to bytes. */
expect fun decodeBase64(encoded: String): ByteArray

/** Generates [size] cryptographically secure random bytes. */
expect fun generateSecureRandom(size: Int): ByteArray

/**
 * Returns a uniformly distributed Int in [0, bound) drawn from a
 * cryptographically secure source. Throws if bound <= 0. Uses rejection
 * sampling so the output is bias-free for non-power-of-two bounds.
 */
expect fun secureRandomInt(bound: Int): Int

/** Returns the current time in milliseconds since Unix epoch. */
expect fun currentTimeMillis(): Long

/**
 * Blocks the calling thread for [millis] milliseconds. MUST be called only off
 * the main/UI thread. Main callers are network backoff/jitter (MessageManager,
 * GroupManager) and the change-PIN uniform-floor (anti-PIN-probing rate-limiting
 * in VaultSelector).
 */
expect fun sleepMillis(millis: Long)

/**
 * The platform's blocking-I/O dispatcher — `Dispatchers.IO` on both platforms.
 * An expect/actual is required because the common-metadata view of
 * `kotlinx.coroutines.Dispatchers.IO` is internal (it is public only in the
 * per-platform source sets), so commonMain cannot name it directly.
 */
internal expect val ioDispatcher: kotlinx.coroutines.CoroutineDispatcher

/**
 * Runs [block] on [ioDispatcher] and BLOCKS the calling thread until every
 * child coroutine it launched has finished (`runBlocking`, which commonMain
 * cannot name directly for the same source-set reason as [ioDispatcher]).
 *
 * Callers: [GroupManager]'s control-sweep peek fan-out (fix 3a,
 * 2026-09-16) and the group-poll GET fan-out ([boundedParallelBlocking],
 * GROUP-FANOUT 2026-10-06, same reasoning for `pollGroupIntoBuffer`), plus iOS's push
 * deregistration pass ([PushRegistration.unregisterAllParallelReturningFailuresBlocking],
 * 2026-10-25 — a detached Swift Task, never main). The sweep is a BLOCKING function on both platforms —
 * `pollAllControls` is called synchronously from Android's
 * `Dispatchers.IO` coroutine and from iOS's `Task.detached` — and turning it
 * suspend would change the Swift-exported signature at every call site. This
 * confines the coroutine scope to the one phase that needs it.
 *
 * NEVER call it from the main/UI thread: it blocks, exactly like
 * [sleepMillis]. It is also never called from inside another
 * `runBlockingIo` — each fan-out is one level deep by construction (neither
 * the sweep nor a group poll is ever reached from inside the other).
 */
internal expect fun <T> runBlockingIo(block: suspend kotlinx.coroutines.CoroutineScope.() -> T): T
