package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Pins the hoisted contact-edit read-modify-write. The regression this guards
 * is the EXACT drift that bit iOS — a mnemonic/alias edit that silently zeroed the
 * anti-replay counters/epoch because a hand-copy forgot a field. These
 * tests assert every non-edited field survives the round-trip.
 */
class ContactEditsTest {

    private fun fullContact(id: String = "c1") = ContactRecord(
        contactId = id,
        sharedSecret = ByteArray(32) { (it + 1).toByte() },
        trustLevel = 2,
        alias = "Original Alias",
        aliasLastRotated = 1_000L,
        mnemonic = "old note",
        outboundCounter = 41L,
        inboundCounter = 37L,
        inboundEpoch = "epoch-5",
        outboundCtlCounter = 9L,
        inboundCtlCounter = 8L,
        outboundGrpCounter = 6L,
        inboundGrpCounter = 5L,
        vouchedByContactId = "voucher-7",
        vouchedAt = 123_456L,
    )

    private fun assertAntiReplayPreserved(before: ContactRecord, after: ContactRecord) {
        assertTrue(before.sharedSecret.contentEquals(after.sharedSecret), "sharedSecret changed")
        assertEquals(before.trustLevel, after.trustLevel, "trustLevel changed")
        assertEquals(before.outboundCounter, after.outboundCounter, "outboundCounter reset")
        assertEquals(before.inboundCounter, after.inboundCounter, "inboundCounter reset")
        assertEquals(before.inboundEpoch, after.inboundEpoch, "inboundEpoch reset")
        assertEquals(before.outboundCtlCounter, after.outboundCtlCounter, "outboundCtlCounter reset")
        // v10: the group channel has its own counter space and the peer enforces
        // strict-monotonic per channel, so an edit that reset it would make every
        // later group message look like a replay to the peer — and be dropped.
        assertEquals(before.outboundGrpCounter, after.outboundGrpCounter, "outboundGrpCounter reset")
        assertEquals(before.inboundGrpCounter, after.inboundGrpCounter, "inboundGrpCounter reset")
        assertEquals(before.inboundCtlCounter, after.inboundCtlCounter, "inboundCtlCounter reset")
        assertEquals(before.vouchedByContactId, after.vouchedByContactId, "vouchedByContactId changed")
        assertEquals(before.vouchedAt, after.vouchedAt, "vouchedAt changed")
    }

    // ---- updateMnemonic ----

    @Test
    fun updateMnemonic_setsMnemonic_preservesEverythingElse() {
        val vault = InMemoryVault()
        val original = fullContact()
        vault.insertContact(original)

        ContactEdits.updateMnemonic(vault, "c1", "  fresh note  ")

        val after = vault.getContact("c1")!!
        assertEquals("fresh note", after.mnemonic, "mnemonic not trimmed/updated")
        assertEquals(original.alias, after.alias, "alias must not change on a mnemonic edit")
        assertEquals(original.aliasLastRotated, after.aliasLastRotated)
        assertAntiReplayPreserved(original, after)
    }

    @Test
    fun updateMnemonic_missingContact_isNoOp() {
        val vault = InMemoryVault()
        ContactEdits.updateMnemonic(vault, "nope", "x")
        assertNull(vault.getContact("nope"))
    }

    // ---- rollAlias ----

    @Test
    fun rollAlias_changesAlias_preservesAntiReplayAndMnemonic() {
        val vault = InMemoryVault()
        val original = fullContact()
        vault.insertContact(original)

        val returned = ContactEdits.rollAlias(vault, "c1")!!
        val persisted = vault.getContact("c1")!!

        // InMemoryVault.insertContact stores a defensive COPY of sharedSecret (mirrors
        // SQLCipher's copy-at-bind, so a caller can wipe its source array post-insert —
        // ReferralManager #15). ContactRecord is a data class whose ByteArray field
        // compares by REFERENCE, so normalise that one array instance before the
        // structural compare; the key CONTENT is asserted separately.
        assertTrue(returned.sharedSecret.contentEquals(persisted.sharedSecret),
            "returned record's key must match the persisted one")
        assertEquals(returned.copy(sharedSecret = persisted.sharedSecret), persisted,
            "returned record must equal the persisted one")
        assertNotEquals(original.alias, persisted.alias, "alias should be re-rolled")
        assertTrue(persisted.aliasLastRotated >= original.aliasLastRotated, "aliasLastRotated not advanced")
        assertEquals(original.mnemonic, persisted.mnemonic, "mnemonic must survive an alias roll")
        assertAntiReplayPreserved(original, persisted)
    }

    @Test
    fun rollAlias_producesGeneratorFormatAlias() {
        val vault = InMemoryVault()
        vault.insertContact(fullContact())
        val rolled = ContactEdits.rollAlias(vault, "c1")!!
        assertTrue(
            ContactAliasGenerator.matchesGeneratedFormat(rolled.alias),
            "rolled alias '${rolled.alias}' is not in the shared generator's format",
        )
    }

    @Test
    fun rollAlias_missingContact_returnsNull() {
        val vault = InMemoryVault()
        assertNull(ContactEdits.rollAlias(vault, "nope"))
    }

    // ---- The shared per-contact row lock ----

    @Test
    fun contactRowLock_isOneStableInstancePerContact() {
        // The whole point of hoisting the registry out of MessageManager: the edit
        // paths and the send/poll counter critical sections must end up on the SAME
        // mutex for a given contact (and must NOT serialise unrelated contacts).
        val a1 = ContactRowLocks.forContact("row-lock-a")
        val a2 = ContactRowLocks.forContact("row-lock-a")
        val b = ContactRowLocks.forContact("row-lock-b")
        assertTrue(a1 === a2, "the same contact must map to the same lock instance")
        assertTrue(a1 !== b, "different contacts must not share a lock")
    }

    @Test
    fun updateMnemonic_persistsTheCountersItReReads_notACallersStaleSnapshot() {
        // Directed (not concurrent): the UI hands us only a contactId, and the edit
        // re-reads inside the lock, so counters advanced after whatever snapshot the
        // screen is holding still survive the write. The genuinely CONCURRENT case —
        // a poll/send landing between this re-read and the write — is what the lock
        // adds and is covered by androidUnitTest's ContactEditCounterRaceTest (real
        // threads); it is not reproducible on this single-threaded double.
        val vault = InMemoryVault()
        vault.insertContact(fullContact())
        val uiSnapshot = vault.getContact("c1")!!

        // The background poll advances the row while the edit screen is open.
        vault.insertContact(uiSnapshot.copy(inboundCounter = 900L, inboundCtlCounter = 800L, outboundCounter = 700L))

        ContactEdits.updateMnemonic(vault, "c1", "note")

        val after = vault.getContact("c1")!!
        assertEquals("note", after.mnemonic)
        assertEquals(900L, after.inboundCounter, "inbound baseline rolled BACKWARD — replay window reopened")
        assertEquals(800L, after.inboundCtlCounter, "control inbound baseline rolled backward")
        assertEquals(700L, after.outboundCounter, "outbound counter reused — silent message loss")
    }

    @Test
    fun rollAlias_persistsTheCountersItReReads_notACallersStaleSnapshot() {
        val vault = InMemoryVault()
        vault.insertContact(fullContact())
        val uiSnapshot = vault.getContact("c1")!!

        vault.insertContact(uiSnapshot.copy(inboundCounter = 900L, outboundCtlCounter = 500L))

        val returned = ContactEdits.rollAlias(vault, "c1")!!

        val after = vault.getContact("c1")!!
        assertEquals(900L, after.inboundCounter)
        assertEquals(500L, after.outboundCtlCounter)
        assertEquals(900L, returned.inboundCounter, "the record handed back to the UI must match what was persisted")
    }
}
