package com.vg.run

import android.app.KeyguardManager
import android.content.Context

// ---------------------------------------------------------------------------
// The Android half of the DeviceLockPolicy probe: does this phone have a secure
// lock screen? Shared code decides what that MEANS (DeviceLockPolicy, commonMain);
// this only reports the fact, so the policy stays pure and unit-testable.
//
// isDeviceSecure — not isKeyguardSecure — is the right question: it is true only
// for a PIN / pattern / password (the credential Rún's hardware key can bind to),
// where isKeyguardSecure also counts a swipe-only keyguard.
// ---------------------------------------------------------------------------

/**
 * This device's lock-screen state. Never throws: a service lookup that fails
 * reports [DeviceLockState.Unknown], which the policy treats as "leave the
 * user's chosen tier alone" — the probe re-runs on every unlock.
 */
fun deviceLockState(context: Context): DeviceLockState = try {
    val km = context.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager
    when {
        km == null -> DeviceLockState.Unknown
        km.isDeviceSecure -> DeviceLockState.Present
        else -> DeviceLockState.Absent
    }
} catch (t: Throwable) {
    LogBuffer.append("W", "DeviceLock", "lock-state probe failed (${t::class.simpleName}) — treating as Unknown")
    DeviceLockState.Unknown
}
