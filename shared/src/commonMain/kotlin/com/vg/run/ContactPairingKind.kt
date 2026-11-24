package com.vg.run

// ---------------------------------------------------------------------------
// RÚN-03 — which kind of pairing a contact was made with, as both contact menus
// show it ("Current" / "Older pairing"), and the contact list's one dismissible
// banner while at least one contact still uses an older pairing.
//
// ONE rule for both platforms. The label is a projection of the persisted row flag
// `ContactRecord.ratchetBootstrapV3` (DB v11, docs/vault-relay-internals.md, the
// one-time ratchet bootstrap section), read from the record the contact list has
// already loaded — never `MessageManager.isRatchetBootstrapV3`, which needs a live
// transport and answers false on a read error (that would mislabel a current
// contact "older"). Nothing here changes a pairing: an app update never flips the
// flag, and pairing again makes a NEW contact (the in-app guide's order: pair again,
// check the new contact works both ways, then delete the old one).
// ---------------------------------------------------------------------------

/** The pairing a contact was made with. A label, not a health state (`dr-lost` is separate). */
enum class ContactPairingKind {
    /** Made with the one-time key exchange (both phones on 1.6.70 or later). */
    CURRENT,
    /** Made before it, or with a phone running an older build. Stays so for life. */
    OLDER,
}

object ContactPairing {
    /** The label of [record], from its persisted row flag. */
    fun kindOf(record: ContactRecord): ContactPairingKind =
        if (record.ratchetBootstrapV3) ContactPairingKind.CURRENT else ContactPairingKind.OLDER

    /** Swift-friendly shorthand for `kindOf(record) == OLDER`. */
    fun isOlder(record: ContactRecord): Boolean = kindOf(record) == ContactPairingKind.OLDER

    /** How many of [kinds] are older pairings (what the banner counts). */
    fun olderCount(kinds: List<ContactPairingKind>): Int = kinds.count { it == ContactPairingKind.OLDER }

    /**
     * True when a NEW pairing just came out as an older one: the other phone's code
     * had no one-time key, i.e. it runs a build before the exchange. Drives the
     * add-contact note ("ask them to update, then pair again").
     */
    fun savedAsOlder(outcome: PairingSaveOutcome): Boolean = outcome == PairingSaveOutcome.SAVED_LEGACY
}

/**
 * The contact list's older-pairing banner. Its dismissal is ONE global vault
 * singleton (owner decision): no contact or group id in the key, so no purge
 * classifier matches it and no per-contact delete resets it; denied by
 * [MoveMetaPolicy] so a move does not carry it (the new phone shows the banner
 * again); erased with every other `_meta` row by a wipe.
 */
object OlderPairingBanner {
    const val META_KEY = "older_pairing_banner_v1"

    /** True once the user dismissed the banner in this vault. A read error answers false (show it). */
    fun isDismissed(vault: VaultDatabase): Boolean = try {
        vault.getMeta(META_KEY) != null
    } catch (_: Exception) {
        false
    }

    /** Records the dismissal. Never throws; false when the write failed (the banner simply returns next load). */
    fun dismiss(vault: VaultDatabase): Boolean = try {
        vault.putMeta(META_KEY, "1")
        true
    } catch (_: Exception) {
        false
    }

    /** Show while at least one contact uses an older pairing and the user has not dismissed it. */
    fun shouldShow(olderCount: Int, dismissed: Boolean): Boolean = olderCount > 0 && !dismissed
}
