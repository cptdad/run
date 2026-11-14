package com.vg.run

/** Returned by [groupRosterStamp] when the vault could not be read (closing, torn down):
 *  "no information" — a caller must neither refresh nor treat the group as gone. */
const val ROSTER_STAMP_UNAVAILABLE: String = "?"

/**
 * A cheap comparable snapshot of what the Group Info screen shows: the group's epoch, admin
 * and name plus every member row's id and resolution. Both platforms poll it while the screen
 * is open and re-read the screen when it changes, so a roster applied by the background
 * control sweep (admin handed over, member added / removed / resolved) is reflected without
 * the user closing and reopening the screen.
 *
 * Returns null when the group no longer exists (left or removed), and
 * [ROSTER_STAMP_UNAVAILABLE] when the vault read failed. RAM-only by contract: it carries
 * member and contact ids the screen already holds, so never log or persist it.
 */
fun groupRosterStamp(vault: VaultDatabase, groupId: String): String? = try {
    val g = vault.getGroup(groupId)
    if (g == null) null else buildString {
        append(g.epoch).append('|').append(g.adminMemberId).append('|').append(g.name).append('|')
        vault.getGroupMembers(groupId)
            .map { "${it.memberId}:${it.contactId ?: ""}" }
            .sorted()
            .joinTo(this, ",")
    }
} catch (_: Throwable) {
    ROSTER_STAMP_UNAVAILABLE
}
