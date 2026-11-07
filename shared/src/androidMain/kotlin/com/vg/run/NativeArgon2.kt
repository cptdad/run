package com.vg.run

/**
 * The vault's KDF_VERSION_3 Argon2id, natively: librunargon2.so, built from the SAME
 * vendored PHC reference sources iOS links (iosApp/Argon2/, pinned by
 * scripts/verify-argon2-src.sh; CMake project in src/androidMain/cpp/). Same
 * algorithm, same cost, byte-identical output to the BouncyCastle generator it
 * replaces as the fast path. Measured on a Samsung A13 at the release cost
 * (64 MiB x 3, p=1): BouncyCastle 3.79 s.
 *
 * Fallback rule (enforced by the argon2id actual in PlatformCrypto.android.kt):
 * BouncyCastle is used ONLY when the library cannot be linked — loadLibrary fails,
 * or the JNI symbol is missing (UnsatisfiedLinkError either way). An argon2 error
 * returned by the native code is THROWN (IllegalStateException), never retried on
 * the other implementation: a failure must not silently become a different result.
 *
 * Public (not internal) only so the :androidApp instrumented equivalence test can
 * drive the native path directly — `internal` is invisible across modules.
 */
object NativeArgon2 {
    private const val TAG = "NativeArgon2"

    // Set once a link failure has been seen; after that every call goes straight to
    // the fallback without retrying the link (and without logging again).
    @Volatile
    private var linkFailed = false

    private val loaded: Boolean by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        try {
            System.loadLibrary("runargon2")
            true
        } catch (_: UnsatisfiedLinkError) {
            markUnavailable()
            false
        }
    }

    /** True when the native library is loaded and has not failed to link. */
    val isAvailable: Boolean get() = loaded && !linkFailed

    @Synchronized
    private fun markUnavailable() {
        if (linkFailed) return
        linkFailed = true
        // Fixed phrase, no inputs, no cost, no exception text (paths could identify the device).
        platformLogWarn(TAG, "native Argon2id unavailable; using the BouncyCastle implementation")
    }

    /**
     * Native Argon2id (v1.3) raw tag, or null ONLY if the native code cannot be
     * linked (the caller then falls back). Argon2 errors propagate as
     * IllegalStateException / IllegalArgumentException.
     */
    fun deriveOrNull(
        password: ByteArray,
        salt: ByteArray,
        memoryKiB: Int,
        iterations: Int,
        parallelism: Int,
        keyLengthBytes: Int,
    ): ByteArray? {
        if (!isAvailable) return null
        return try {
            argon2idRaw(password, salt, memoryKiB, iterations, parallelism, keyLengthBytes)
        } catch (_: UnsatisfiedLinkError) {
            // .so loaded but the JNI binding is missing (e.g. a renamed class in a
            // shrunk build): no result was produced, so the fallback is still the same
            // algorithm on the same inputs.
            markUnavailable()
            null
        }
    }

    /**
     * JNI entry point (argon2_jni.c → argon2id_hash_raw). The class and method name
     * are load-bearing for JNI symbol lookup — kept by androidApp/proguard-rules.pro.
     */
    @JvmStatic
    external fun argon2idRaw(
        password: ByteArray,
        salt: ByteArray,
        memoryKib: Int,
        iterations: Int,
        parallelism: Int,
        outLen: Int,
    ): ByteArray
}
