package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/** deleteContact must erase the contact's ratchet/session _meta. */
class RatchetMetaCleanupTest {

    @Test
    fun ratchetMetaKeysForContact_coversAllRatchetNamespaces() {
        val keys = ratchetMetaKeysForContact("abc")
        assertEquals(
            setOf(
                "dr/abc/text", "dr-rxc/abc", "dr-on/abc", "dr-intent/abc", "dr-rxseen/abc",
                "m2-chseen/abc", "ib-bound-seen/abc", "dr-rxlock/abc",
                // The pending read-cap rotation markers hold a LIVE capability
                // candidate, so EVERY inbound direction must be purged with the contact
                // — the group inbox's included, the moment DIR_INBOUND_GRP joined
                // OWNED_READ_DIRECTIONS.
                "cap-pend/abc/inbound", "cap-pend/abc/inbound-ctl", "cap-pend/abc/inbound-grp",
                // The consecutive-legacy-fallback counter.
                "dr-legacyfb/abc",
                // The peer's sealed-control capability latch
                // and the sealed-control commitment watermark — a re-paired peer must
                // start un-latched and un-armed.
                "dr-rxseen-ctlcap/abc", "dr-rxlock-ctlwm/abc",
                // …plus the text-lock grace owed after a CONTROL-armed lock, and the
                // deferred sealed-control wires (ratchet ciphertext — dies with the pairing).
                "dr-rxlock-grace/abc", "dr/abc/ctl-deferred", "dr-rxseen-ctlstep/abc",
                // The both-Alice detector and the
                // role-collision refusal latch. A re-pair is the documented way out of
                // a refusal, so neither may outlive the contact.
                "dr-rat-unacked/abc", "dr-refused/abc",
                // The two ratchet-ROLE inputs. A re-pair mints
                // brand-new pairing secrets, so an inherited order bit would be computed
                // against the wrong pair — and combined with the new pairing's parity it
                // could hand both devices the SAME role.
                "dr-roleord/abc", "dr-rolerv2/abc",
                // The group-inbox backfill throttle. A re-pair is one of
                // only TWO things that re-arm its budget (the other is the pairing
                // converging), so an inherited exhausted record would leave the
                // re-paired peer on the legacy group route for good.
                "grp-ann/abc",
            ),
            keys.toSet(),
        )
    }

    @Test
    fun deleteContact_purgesRatchetMeta_leavingUnrelatedMetaIntact() {
        val vault = InMemoryVault()
        val contactId = "gone"
        vault.insertContact(ContactRecord(contactId, "s".encodeToByteArray(), 1, "T", 0L))
        // Seed every ratchet-state key for this contact + one unrelated key.
        for (key in ratchetMetaKeysForContact(contactId)) vault.putMeta(key, "1")
        vault.putMeta("dr-on/other", "1")

        vault.deleteContact(contactId)

        for (key in ratchetMetaKeysForContact(contactId)) {
            assertNull(vault.getMeta(key), "ratchet meta $key must be purged on deleteContact")
        }
        assertEquals("1", vault.getMeta("dr-on/other"), "another contact's ratchet meta must survive")
        assertNull(vault.getContact(contactId), "contact row must be gone")
    }
}
