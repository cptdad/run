package com.vg.run

// A seeded 64-bit LCG. Deterministic and identical on JVM and Kotlin/Native —
// `kotlin.random` is neither pinned across targets nor reproducible by hand,
// and a leak a redactor simulation finds has to be reproducible. Shared by
// DebugModeTest and DebugModeRedactorPropertyTest.
internal class SeededLcg(private var state: Long) {
    fun nextBits(): Int {
        state = state * 6_364_136_223_846_793_005L + 1_442_695_040_888_963_407L
        return ((state ushr 33) and 0x7FFF_FFFFL).toInt()
    }
}

internal const val B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

internal fun SeededLcg.b64Url(length: Int): String {
    val sb = StringBuilder(length)
    for (i in 0 until length) sb.append(B64URL[nextBits() % 64])
    return sb.toString()
}
