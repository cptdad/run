package com.vg.run

// Android's term for its screen lock, shown in the forced-notice title and
// (via DeviceLockPolicy) the "no lock" stop-reason.
internal actual val protectionDeviceLockTerm: String
    get() = platformString("protection_device_lock_term_android")
