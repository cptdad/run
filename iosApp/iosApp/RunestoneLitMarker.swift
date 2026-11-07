import SwiftUI

// ---------------------------------------------------------------------------
// runestoneLitMarker — invisible test marker tracking whether the
// `runestone_bright_and_lit` background image is the one being shown.
// Emits a zero-size view whose accessibility identifier is
// `runestone_lit_active` when the lit image is being rendered,
// `runestone_lit_inactive` otherwise.
//
// Callers feed this from the *rendered* lit state (e.g. ContactListView's
// `litVisible`, not `appState.isRelayReachable`) so the marker would catch
// a regression where the boolean state is correct but the image layer
// fails to fade in.
// ---------------------------------------------------------------------------

// Per-protection-level runestone art. Each connection-state base name
// (runestone_dim / runestone_bright / runestone_bright_and_lit) comes in three
// tiers: plain (Casual), blue base ring (Private), full blue forcefield
// (Maximum) — the forcefield tiers replaced the old Ægishjálmr-projection
// max-level variants. `level` is the ProtectionLevel storage value from
// IosAppController.currentProtectionLevel().
func runestoneAsset(_ base: String, level: String) -> String {
    switch level {
    case "private": return base + "_ring"
    case "maximum": return base + "_forcefield"
    default: return base
    }
}

@ViewBuilder
func runestoneLitMarker(active: Bool) -> some View {
    // 1×1 invisible Color so XCUITest surfaces the node — zero-sized views
    // are typically excluded from the accessibility tree.
    Color.clear
        .frame(width: 1, height: 1)
        .accessibilityIdentifier(active ? "runestone_lit_active" : "runestone_lit_inactive")
        .accessibilityElement()
}
