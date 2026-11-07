package com.vg.run

// ---------------------------------------------------------------------------
// DeviceBaseline — the ACTUAL device's own forensic-resistance baseline, shown in
// the threat-level chooser (docs/threat-level-slider-spec.md). ALWAYS assumes AFU
// (the phone is seized already-unlocked — the worst realistic case), so no device
// rates fully safe; the best only make extraction hard. Shared so Android and iOS
// agree; each platform detects the inputs (lock set? dedicated secure element?
// security patches current?) natively and calls [assess].
//
// This uses only what a phone can actually detect about ITSELF — there is no
// per-model exploit database, so a real device gets a coarser rating than the
// interactive mockup's hand-authored flaw table.
// ---------------------------------------------------------------------------

enum class DeviceBaselineTier { EXPOSED, WEAK, HARD_TARGET }

object DeviceBaseline {

    fun assess(lockSet: Boolean, secureElement: Boolean, patchesCurrent: Boolean): DeviceBaselineTier = when {
        !lockSet -> DeviceBaselineTier.EXPOSED
        !secureElement || !patchesCurrent -> DeviceBaselineTier.WEAK
        else -> DeviceBaselineTier.HARD_TARGET
    }

    fun label(t: DeviceBaselineTier): String = when (t) {
        DeviceBaselineTier.EXPOSED -> "Exposed"
        DeviceBaselineTier.WEAK -> "Weak"
        DeviceBaselineTier.HARD_TARGET -> "Hard target"
    }

    /** Filled segments of a 4-segment meter. Never 4 — nothing is fully safe in AFU. */
    fun fill(t: DeviceBaselineTier): Int = when (t) {
        DeviceBaselineTier.EXPOSED -> 1
        DeviceBaselineTier.WEAK -> 2
        DeviceBaselineTier.HARD_TARGET -> 3
    }

    /** "bad" (red) or "warn" (amber). Never "ok" (green) — AFU has no green. */
    fun severity(t: DeviceBaselineTier): String = when (t) {
        DeviceBaselineTier.EXPOSED, DeviceBaselineTier.WEAK -> "bad"
        DeviceBaselineTier.HARD_TARGET -> "warn"
    }

    fun note(t: DeviceBaselineTier): String = when (t) {
        DeviceBaselineTier.EXPOSED ->
            "No device lock — anyone who picks up the phone is already inside it."
        DeviceBaselineTier.WEAK ->
            "No dedicated secure chip, or the security patches are behind — once the phone has been unlocked since it booted, a forensic tool can reach the data."
        DeviceBaselineTier.HARD_TARGET ->
            "Dedicated secure chip and current patches. A forensic tool has to work for it — but once the phone has been unlocked since it booted, even this is not immune."
    }

    const val CAVEAT =
        "Assumes the phone has been unlocked at least once since it last booted — its normal state, even with the screen locked (forensics calls this AFU). " +
            "That's the realistic worst case, so nothing rates fully safe here. Public forensic-tooling reach today; a moving target."
}
