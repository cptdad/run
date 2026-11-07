package com.vg.run

// ---------------------------------------------------------------------------
// VendorBilling — the billing seam (peer of VendorPush). Play Billing is
// linked in every build since the 2026-08-04 flavor collapse, so the
// "Support Rún" modal always shows the in-app Tip tab; on devices without
// Play Services the Billing connection simply fails and TipJar surfaces its
// unavailable state. The constant stays (always true: single universal build)
// so DonateModal keeps one seam to read.
// ---------------------------------------------------------------------------

object VendorBilling {
    /** True iff Google Play Billing is compiled into this build. */
    const val isSupported = true
}
