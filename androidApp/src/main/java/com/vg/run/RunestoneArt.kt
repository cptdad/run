package com.vg.run

import androidx.annotation.DrawableRes

// Per-protection-level runestone art. Each connection state (dim / bright /
// bright_and_lit) comes in three tiers: plain (Casual), blue base ring
// (Private), full blue forcefield (Maximum) — the forcefield tiers replaced
// the old Ægishjálmr-projection max-level variants.
object RunestoneArt {
    @DrawableRes
    fun dim(level: ProtectionLevel): Int = when (level) {
        ProtectionLevel.CASUAL -> R.drawable.runestone_dim
        ProtectionLevel.PRIVATE -> R.drawable.runestone_dim_ring
        ProtectionLevel.MAXIMUM -> R.drawable.runestone_dim_forcefield
    }

    @DrawableRes
    fun bright(level: ProtectionLevel): Int = when (level) {
        ProtectionLevel.CASUAL -> R.drawable.runestone_bright
        ProtectionLevel.PRIVATE -> R.drawable.runestone_bright_ring
        ProtectionLevel.MAXIMUM -> R.drawable.runestone_bright_forcefield
    }

    @DrawableRes
    fun brightAndLit(level: ProtectionLevel): Int = when (level) {
        ProtectionLevel.CASUAL -> R.drawable.runestone_bright_and_lit
        ProtectionLevel.PRIVATE -> R.drawable.runestone_bright_and_lit_ring
        ProtectionLevel.MAXIMUM -> R.drawable.runestone_bright_and_lit_forcefield
    }
}
