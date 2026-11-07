package com.vg.run

import android.content.Context

/**
 * Localized copy for [RelayConnectHints]. `ENGLISH` is the fixture the JVM unit
 * tests pin against (byte-identical to the old hardcoded literals — see
 * [RelayConnectHintsTest]); [from] resolves the same strings from
 * `strings_contact_list.xml` (`connect_*` keys) at render time. iOS mirror:
 * `AppState.connectStatusLine` sources the identical `connect_*` L10n keys by
 * hand (Swift has no equivalent of a Context-scoped resource lookup here).
 */
data class ConnectStrings(
    val torPhase: String,
    val relayPhase: String,
    val torStalledHint: String,
    val mintStalledHint: String,
) {
    companion object {
        val ENGLISH = ConnectStrings(
            torPhase = "Connecting to Tor…",
            relayPhase = "Connecting to Relay…",
            torStalledHint = "Still connecting…\nThis network may be blocking the private connection. " +
                "Try different Wi-Fi or mobile data — we’ll keep trying.",
            mintStalledHint = "Still connecting… This network may be blocking the private connection. " +
                "Try different Wi-Fi or mobile data — we’ll keep trying.",
        )

        fun from(context: Context): ConnectStrings = ConnectStrings(
            torPhase = context.getString(R.string.connect_tor_phase),
            relayPhase = context.getString(R.string.connect_relay_phase),
            torStalledHint = context.getString(R.string.connect_tor_stalled_hint),
            mintStalledHint = context.getString(R.string.connect_mint_stalled_hint),
        )
    }
}

/**
 * Pure (device-free) copy for the PRE-CONNECT relay surfaces — the contact-list
 * empty state, contacts-present strip, and the Add-Contact mint snackbar.
 *
 * Extracted from the two Compose screens so the wording is unit-testable on
 * the JVM and cannot drift between them. The percent itself is no longer part
 * of this text (2026-09-16: replaced on-screen by an animated dots cadence,
 * see ContactListScreen.kt's `connectCaptionWithDots` / `rememberConnectDotsStep`)
 * — it stays a pure display-layer concern, still fed by the same pacer below.
 *
 * Context (App Store review 2.1 rejected iOS 0.8.159): Tor never bootstrapped in
 * Apple's review lab and BOTH pre-connect surfaces spun forever — "Connecting to
 * the relay…" / "Reaching the relay…" with no percent, no timeout, no honest
 * explanation. Android had the same hole on Add Contact. The fix is purely
 * informational: nothing here stops or restarts Tor, and every string stays
 * NON-TERMINAL ("we'll keep trying") because a slow bootstrap can still land
 * minutes later.
 *
 * Two-phase status line (2026-08-26 follow-up): a single "…100%" caption was
 * misleading because it mapped Tor-Connected straight to 100% while the relay
 * handshake was still in flight — the caption looked "done" long before the
 * connection was usable. [connectStatusLine] renders TWO phases: Tor bootstrap,
 * then the relay handshake. The WORDING is chosen here; the NUMBER is not — it
 * comes from the shared [BootstrapProgressPacer], which paces one monotone run
 * of percents across both phases.
 *
 * Percent pacing (2026-09-11, App Store review 2.1 on 1.6.15): the number used
 * to be the raw Tor percent in phase one and a `100 * (1 - e^(-t/7))` curve
 * CAPPED AT 95 in phase two. BOTH froze — Tor parks at 95% for 1-3 minutes
 * building its first circuit, and the phase-two curve hit its ceiling ~21 s in
 * — and the reviewer read the frozen "Connecting to Relay… 95%" as "loads
 * indefinitely". The curve is gone; [BootstrapProgressPacer] now supplies a
 * bounded-rate, always-moving, never-overclaiming percent for both phases.
 *
 * iOS siblings (same wording family, sourced from the SAME `connect_*` L10n
 * keys, same pacer from the shared framework): `AppState.connectStatusLine`,
 * consumed by `ContactListView` and `AddContactView`.
 */
object RelayConnectHints {

    /**
     * Contact-list caption once the bootstrap has passed
     * [RunViewModel.TOR_BOOTSTRAP_STALL_MS] without connecting. Two lines: what is
     * happening, then the one action a user can actually take.
     *
     * English fallback kept for source compatibility with callers that don't
     * (yet) thread a [ConnectStrings] through — e.g. `AddContactScreen.kt`'s
     * mint snackbar. Prefer passing `ConnectStrings.from(context)` to
     * [connectStatusLine] for localized rendering; this constant itself is
     * always [ConnectStrings.ENGLISH.torStalledHint].
     */
    val TOR_STALLED_HINT: String = ConnectStrings.ENGLISH.torStalledHint

    /**
     * Add-Contact snackbar variant of [TOR_STALLED_HINT] — same voice, compressed
     * to one paragraph for the snackbar's status line. See [TOR_STALLED_HINT]'s
     * note on localization.
     */
    val MINT_STALLED_HINT: String = ConnectStrings.ENGLISH.mintStalledHint

    /**
     * The single pre-connect status line, shared by every render site (contact-
     * list empty state, contacts-present strip, Add-Contact mint snackbar).
     * Two phases, pure wording only:
     *
     * - While Tor hasn't connected yet: "Connecting to Tor…".
     * - Once Tor IS connected but the relay hasn't answered: "Connecting to
     *   Relay…".
     *
     * The bootstrap percent no longer renders in this text at all (since 2026-09-16
     * — the frozen-percent display this line was
     * built to fix is instead addressed by an animated dots cadence at the
     * render sites, `connectCaptionWithDots` in ContactListScreen.kt). The
     * live percent ([BootstrapProgressPacer.displayed]) is UNCHANGED
     * internally: it still drives the ring-pulse opacity and is still visible
     * in the ConnectionLog panel / telemetry — only this caption stopped
     * showing the digits.
     *
     * [strings] defaults to [ConnectStrings.ENGLISH] so existing callers (and
     * the JVM unit tests, which must stay green in English) keep compiling and
     * behaving identically; screens should pass `ConnectStrings.from(context)`.
     */
    fun connectStatusLine(
        torConnected: Boolean,
        strings: ConnectStrings = ConnectStrings.ENGLISH,
    ): String = if (torConnected) strings.relayPhase else strings.torPhase

}
