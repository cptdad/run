package com.vg.run

/**
 * Canonical values the add-contact flow writes into the vault.
 *
 * The iOS add-contact flow is Swift and cannot reference these directly, so it
 * hardcodes the identical values with a comment pointing here. Keeping the two
 * platforms reading one source of truth stops them drifting (e.g. a mismatched
 * inbox lifetime or trust level between Android and iOS).
 */
object VaultSeedDefaults {
    /** trustLevel stamped on an IRL QR-paired contact (the default path). */
    const val DEFAULT_TRUST_LEVEL: Int = 0

    // Note: a legacy trustLevel of -1 (former "referred, unconfirmed") may still
    // appear in old rows; it is no longer assigned and needs no constant.

    /** Referral: a contact added via an introducer. Usable immediately
     *  (transitive trust); vouchedByContactId records who introduced us. */
    const val TRUST_REFERRED_CONFIRMED: Int = 1

    /** Inbox lifetime: add-contact sets `expiresAt = createdAt + this`. */
    const val INBOX_LIFETIME_MS: Long = 365L * 24 * 60 * 60 * 1000
}
