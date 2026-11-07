package com.vg.run

// ---------------------------------------------------------------------------
// VendorBilling — the billing seam (peer of VendorPush), `foss` flavour: Google
// Play Billing is NOT linked (zero Google code, F-Droid), so DonateModal reads
// isSupported = false, hides the in-app Tip tab and shows the crypto donation
// address only. The `google` source set declares the same object with
// isSupported = true; exactly one is compiled per variant.
// ---------------------------------------------------------------------------

object VendorBilling {
    /** True iff Google Play Billing is compiled into this build. */
    const val isSupported = false
}
