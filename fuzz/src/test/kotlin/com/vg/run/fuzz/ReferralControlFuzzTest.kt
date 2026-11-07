package com.vg.run.fuzz

import com.code_intelligence.jazzer.api.FuzzedDataProvider
import com.code_intelligence.jazzer.junit.FuzzTest
import com.vg.run.MessageManager
import com.vg.run.ReferralManager
import org.junit.jupiter.api.Test

/**
 * Referral (vouched-introduction) OFFER and ACCEPT bodies.
 *
 * Both arrive on the CONTROL channel inside the 1:1 envelope of an existing
 * contact — the introducer. The referral flow is the one place where data from a
 * THIRD party (the person being introduced) crosses into the vault via someone
 * else's envelope, so its field parsing is the most interesting non-crypto trust
 * boundary in the app:
 *
 *   offer  {"ii": introId, "pa": peerAlias}
 *   accept {"ii": introId, "pk": base64(32-byte X25519 pub),
 *           "ib"/"wc"/"cib"/"cwc": the peer's inbox pair + capabilities}
 *
 * `pk` is the one place a referral body is BASE64-DECODED, and `ib`/`cib`/`wc`/
 * `cwc` are shape-validated before they can ever be stored as a contact.
 *
 * DOCUMENTED CONTRACT: `handleControl` drops an unknown kind with a warn line;
 * every handler bails with `return` on any field it does not like. Nothing may
 * escape it.
 */
class ReferralControlFuzzTest {

    @FuzzTest(maxDuration = "60s")
    fun fuzzReferralBody(data: FuzzedDataProvider) {
        val body = data.consumeRemainingAsString()

        for (kind in REFERRAL_KINDS) {
            val (vault, referrals) = freshReferralWorld()
            bounded("referral handleControl($kind)") {
                referrals.handleControl(FuzzIds.CONTACT, kind, body)
            }

            // A referral body may NEVER mint a contact by itself: the introducee
            // only becomes a contact once the handshake completes over the relay,
            // which cannot happen here (no MessageManager).
            val contacts = vault.getAllContacts()
            check(contacts.size == 1 && contacts[0].contactId == FuzzIds.CONTACT) {
                "a referral control body created ${contacts.size} contact(s) with no relay round trip"
            }
            // …nor an inbox row.
            check(vault.getAllInboxIds().isEmpty()) {
                "a referral control body wrote an inbox row with no relay round trip"
            }
        }

        // Unknown kind: inert.
        val (vault2, referrals2) = freshReferralWorld()
        val before = vault2.metaKeys().toSet()
        referrals2.handleControl(FuzzIds.CONTACT, "ref-$body".take(64), body)
        check(vault2.metaKeys().toSet() == before) { "an UNKNOWN referral kind wrote to the vault" }
    }

    // ------------------------------------------------------------------
    // Fixed regression tests.
    // ------------------------------------------------------------------

    /** An offer from a contact we do NOT have must be dropped, never stored. */
    @Test
    fun offerFromUnknownContactIsDropped() {
        val vault = InMemoryVault()
        val referrals = ReferralManager(vault) { null }
        referrals.handleControl(
            "stranger",
            MessageManager.CONTROL_KIND_REFERRAL_OFFER,
            """{"ii":"abcdefghijklmnop","pa":"Someone"}""",
        )
        check(vault.getAllContacts().isEmpty()) { "an offer from a stranger created state" }
    }

    /** A malformed base64 public key must fail closed, not throw out of the handler. */
    @Test
    fun malformedPeerKeyIsRejectedWithoutThrowing() {
        val (_, referrals) = freshReferralWorld()
        referrals.handleControl(
            FuzzIds.CONTACT,
            MessageManager.CONTROL_KIND_REFERRAL_ACCEPT,
            """{"ii":"abcdefghijklmnop","pk":"!!!not base64!!!","ib":"${FuzzIds.INBOX_A}",""" +
                """"wc":"${FuzzIds.CAP}","cib":"${FuzzIds.INBOX_B}","cwc":"${FuzzIds.CAP}"}""",
        )
    }

    private companion object {
        val REFERRAL_KINDS = listOf(
            MessageManager.CONTROL_KIND_REFERRAL_OFFER,
            MessageManager.CONTROL_KIND_REFERRAL_ACCEPT,
        )

        fun freshReferralWorld(): Pair<InMemoryVault, ReferralManager> {
            val vault = InMemoryVault()
            vault.insertContact(seededContact())
            return vault to ReferralManager(vault) { null }
        }
    }
}
