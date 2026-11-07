package com.vg.run

// ---------------------------------------------------------------------------
// VendorBilling — the billing seam (peer of VendorPush), `google` flavour: Play
// Billing is linked, so the "Support Rún" modal shows the in-app Tip tab. On a
// device without Play Services the Billing connection simply fails and TipJar
// surfaces its unavailable state. The `foss` flavour declares the same object
// with isSupported = false (crypto donations only); exactly one is compiled per
// variant, so DonateModal reads one constant flavour-blind.
// ---------------------------------------------------------------------------

object VendorBilling {
    /** True iff Google Play Billing is compiled into this build. */
    const val isSupported = true
}
