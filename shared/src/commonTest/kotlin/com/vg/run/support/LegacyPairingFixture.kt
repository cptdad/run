package com.vg.run

/**
 * An OLDER (pre-one-time-key) pairing between two vaults, written by the real legacy
 * pairing transaction ([PairingVault.savePairedContact]) exactly as a build before
 * 1.6.70 wrote it: full codes on both sides, the secret-ordered role rule on both
 * sides, no `ratchetBootstrapV3` flag. Inbox wiring is production-shaped: A's
 * outbound == B's inbound and vice versa.
 */
internal object LegacyPairingFixture {
    val READ_CAP = "R".repeat(43)
    val WRITE_CAP = "W".repeat(43)

    fun pair(
        vA: VaultDatabase,
        vB: VaultDatabase,
        contactId: String,
        inA: String,
        inB: String,
        ctlA: String,
        ctlB: String,
    ) {
        val halfA = generateSecureRandom(32)
        val halfB = generateSecureRandom(32)
        val ss = deriveSharedSecret(halfA, halfB)
        PairingVault.savePairedContact(
            vA, contactId, ss.copyOf(), inB, WRITE_CAP, ctlB, WRITE_CAP, inA, READ_CAP, ctlA, READ_CAP, "old",
            mySecretHalf = halfA, peerSecretHalf = halfB, peerRoleRuleV2 = true,
        )
        PairingVault.savePairedContact(
            vB, contactId, ss.copyOf(), inA, WRITE_CAP, ctlA, WRITE_CAP, inB, READ_CAP, ctlB, READ_CAP, "old",
            mySecretHalf = halfB, peerSecretHalf = halfA, peerRoleRuleV2 = true,
        )
        ss.secureWipe()
    }
}
