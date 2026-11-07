package com.vg.run

// Fixtures shared by the referral / group edge-case suites (byte-identical copies used to live
// in each file under a per-file prefix: ec / fb / rg / sg / rw).

/** A bare contact row with a random 32-byte secret. */
internal fun seedReferralContact(vault: InMemoryVault, id: String, alias: String) {
    vault.insertContact(
        ContactRecord(
            contactId = id, sharedSecret = generateSecureRandom(32),
            trustLevel = 0, alias = alias, aliasLastRotated = 0L,
        )
    )
}

internal fun referralOfferJson(introId: String, peerAlias: String) =
    """{"ii":${jsonEscapeString(introId)},"pa":${jsonEscapeString(peerAlias)}}"""

/** Meta keys of [vault] that start with [prefix]. */
internal fun metaKeysStartingWith(vault: InMemoryVault, prefix: String) =
    vault.meta.keys.filter { it.startsWith(prefix) }

internal fun httpAccepted() = HttpResult(202, "", true)
internal fun httpRefused() = HttpResult(500, "nope", false)

internal fun groupMemberId(seed: Int) = bytesToHex(ByteArray(8) { (seed + it).toByte() })
