package com.vg.run

/**
 * Secret-free projection of [ContactRecord] for the contact list screen.
 *
 * `ContactRecord.sharedSecret` is a raw 32-byte value — the
 * pre-image of the legacy static-envelope key (docs/vault-relay-internals.md:198)
 * — and Compose `remember`/`mutableStateOf` retains whatever it is handed for
 * the life of the composition with no lock/re-auth/wipe path that scrubs it.
 * `ContactListScreen` must therefore NEVER hold a bare `ContactRecord` in UI
 * state; it holds only this projection, which carries exactly the fields the
 * screen renders (alias/mnemonic/contactId/vouch provenance) and nothing an
 * attacker with a RAM image of the process could turn into a decryption key.
 *
 * Mirrors iOS `ContactItem` (ContactListView.swift ~1518-1545), which already
 * does this mapping — this type closes the Android-only divergence.
 */
data class ContactListItem(
    val contactId: String,
    val alias: String,
    val mnemonic: String,
    val vouchedByContactId: String?,
)

/**
 * Projects a [ContactRecord] into its secret-free [ContactListItem]. Callers
 * that fetch a full record for this screen (e.g. [ContactEdits.rollAlias],
 * which must return the whole row) MUST project immediately and
 * `secureWipe()` the source record's `sharedSecret` before letting the
 * [ContactRecord] go out of scope — never store the [ContactRecord] itself.
 */
fun ContactRecord.toListItem(): ContactListItem = ContactListItem(
    contactId = contactId,
    alias = alias,
    mnemonic = mnemonic,
    vouchedByContactId = vouchedByContactId,
)
