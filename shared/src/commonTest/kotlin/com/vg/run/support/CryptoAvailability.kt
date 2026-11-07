package com.vg.run

/**
 * True when the AES-GCM bridge is present. Tests open with `if (!aeadUp()) return`, which is a
 * SKIP on the bare iOS simulator runner (no Swift crypto bridge registered) and an ordinary
 * pass everywhere else (kotlin-test common has no `assume`). The single shared copy of what
 * used to be ~45 per-file private probes.
 */
internal fun aeadUp(): Boolean = try {
    aesGcmEncrypt(ByteArray(1), generateSecureRandom(32), ByteArray(0)); true
} catch (_: Exception) { false }

/** True when the X25519 bridge is present; same skip-on-bare-iOS-simulator semantics as [aeadUp]. */
internal fun x25519Up(): Boolean = try { x25519GenerateKeypair(); true } catch (_: Exception) { false }
