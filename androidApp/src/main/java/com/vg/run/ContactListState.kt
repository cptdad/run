package com.vg.run

/**
 * What the contact list shows for the unlocked session, loaded off the main
 * thread by [RunViewModel] (see `startContactListLoader`). `null` in the VM flow
 * means "not loaded yet", which the screen renders as hidden-until-loaded, never
 * as "no contacts".
 *
 * Holds only the secret-free [ContactListItem] projection: every source
 * ContactRecord's shared secret is wiped the moment it is projected. The aliases
 * it carries are cleared from the VM on every lock and wipe
 * (`clearInMemoryIdentifierMaps`).
 */
data class ContactListSnapshot(
    val contacts: List<ContactListItem>,
    val groups: List<GroupRecord>,
    val staleIds: Set<String>,
    val pendingIds: Set<String>,
    /** Contacts that reported Maximum while this device is at MAXIMUM (the shield after the name). Ids only. */
    val maximumIds: Set<String> = emptySet(),
)

/**
 * The next referral offer and the next group invite parked in the session's
 * managers, waiting for the user's consent. RAM reads only. Cleared on every lock
 * and wipe, because an offer carries introducer and peer aliases.
 */
data class PendingConsent(
    val offer: ReferralOffer?,
    val invite: GroupInvite?,
    /** EVERY pending invite, in pending order ([invite] is the first). Empty means "just [invite]". */
    val invites: List<GroupInvite> = emptyList(),
    /** EVERY pending referral offer, in pending order ([offer] is the first). Empty means "just [offer]". */
    val offers: List<ReferralOffer> = emptyList(),
)
