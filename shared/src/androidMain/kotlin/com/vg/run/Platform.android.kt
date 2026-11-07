package com.vg.run

import android.util.Log
import java.security.SecureRandom

// NOTE (why reflective): this lookup is load-bearing beyond
// "which DEBUG flag". In the plain-JVM unit tests the app's com.vg.run.BuildConfig
// is NOT on the classpath, so this returns false — which suppresses the
// android.util.Log calls below (Log is unmocked in JVM tests and throws). Swapping
// it for BuildFlags.isDebugBuild (true in the shared debug test) makes Log.d fire
// and crashes every unit test. Removing it cleanly would need the platformLog* bodies
// hoisted to a common concrete impl behind a thin expect platformPrintLog.
private val IS_DEBUG: Boolean = try {
    Class.forName("com.vg.run.BuildConfig")
        .getField("DEBUG")
        .getBoolean(null)
} catch (_: Exception) {
    false
}

actual fun platformLog(tag: String, message: String) {
    LogBuffer.append("D", tag, message)
    if (IS_DEBUG) Log.d(tag, message)
}

actual fun platformLogWarn(tag: String, message: String) {
    LogBuffer.append("W", tag, message)
    if (IS_DEBUG) Log.w(tag, message)
}

actual fun platformLogError(tag: String, message: String, throwable: Throwable?) {
    // The throwable's CLASS NAME only: Throwable.toString() appends its message,
    // which can carry a URL, a host or a file path, and LogBuffer lines reach the
    // Debug-mode upload. The DEBUG-gated logcat line below keeps the full trace.
    val msg = "$message${throwable?.let { " — ${it::class.simpleName}" } ?: ""}"
    LogBuffer.append("E", tag, msg)
    if (IS_DEBUG) {
        if (throwable != null) Log.e(tag, message, throwable)
        else Log.e(tag, message)
    }
}

// java.util.Base64 (not android.util.Base64): byte-identical output for the
// no-wrap standard alphabet, available on API 26+ (minSdk is 30) AND on the
// plain JVM — so the encode/decode path is exercisable from unit tests
// (android.util.Base64 throws "not mocked" there).
actual fun encodeBase64(data: ByteArray): String =
    java.util.Base64.getEncoder().encodeToString(data)

actual fun decodeBase64(encoded: String): ByteArray =
    java.util.Base64.getDecoder().decode(encoded)

// internal so the other androidMain crypto/seed sites reuse this one instance
// rather than each constructing (and re-seeding) their own SecureRandom.
internal val secureRandom = SecureRandom()

actual fun generateSecureRandom(size: Int): ByteArray =
    ByteArray(size).also { secureRandom.nextBytes(it) }

actual fun secureRandomInt(bound: Int): Int = secureRandom.nextInt(bound)

actual fun currentTimeMillis(): Long =
    System.currentTimeMillis()

actual fun sleepMillis(millis: Long) {
    if (millis > 0) Thread.sleep(millis)
}

internal actual val ioDispatcher: kotlinx.coroutines.CoroutineDispatcher
    get() = kotlinx.coroutines.Dispatchers.IO

internal actual fun <T> runBlockingIo(block: suspend kotlinx.coroutines.CoroutineScope.() -> T): T =
    kotlinx.coroutines.runBlocking(kotlinx.coroutines.Dispatchers.IO, block)
