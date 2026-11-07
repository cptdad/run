package com.vg.run

// iOS's term for its screen lock ("Passcode" in Settings), shown in the
// forced-notice title and (via DeviceLockPolicy) the "no lock" stop-reason.
internal actual val protectionDeviceLockTerm: String
    get() = platformString("protection_device_lock_term_ios")
