package com.vg.run

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * 4D-1: locks down the secret-free projection ContactListScreen must use
 * instead of retaining a bare ContactRecord (which carries the raw 32-byte
 * sharedSecret) in Compose state.
 */
class ContactListItemTest {

    private fun sampleRecord(
        contactId: String = "contact-1",
        secret: ByteArray = byteArrayOf(1, 2, 3, 4, 5),
        vouchedByContactId: String? = "introducer-1",
    ) = ContactRecord(
        contactId = contactId,
        sharedSecret = secret,
        trustLevel = 3,
        alias = "Rune Fox",
        aliasLastRotated = 1_000L,
        mnemonic = "met at the meetup",
        outboundCounter = 7,
        inboundCounter = 9,
        inboundEpoch = "epoch-1",
        outboundCtlCounter = 2,
        inboundCtlCounter = 4,
        vouchedByContactId = vouchedByContactId,
        vouchedAt = 500L,
    )

    @Test
    fun toListItem_copiesOnlyTheNonSecretFields() {
        val record = sampleRecord()

        val item = record.toListItem()

        assertEquals(record.contactId, item.contactId)
        assertEquals(record.alias, item.alias)
        assertEquals(record.mnemonic, item.mnemonic)
        assertEquals(record.vouchedByContactId, item.vouchedByContactId)
    }

    @Test
    fun toListItem_preservesNullVouchedBy() {
        val record = sampleRecord(vouchedByContactId = null)

        val item = record.toListItem()

        assertNull(item.vouchedByContactId)
    }

    @Test
    fun sourceRecordSecretIsZeroedAfterProjection() {
        // Mirrors loadContactListSnapshot (ContactListEdits.kt):
        // project first, then wipe every source record's secret.
        val secret = byteArrayOf(9, 8, 7, 6, 5, 4, 3, 2, 1)
        val record = sampleRecord(secret = secret)

        val item = record.toListItem()
        record.sharedSecret.secureWipe()

        // The projection never referenced the secret in the first place...
        assertEquals("Rune Fox", item.alias)
        // ...and the ORIGINAL ByteArray backing the record is now all zeros —
        // proving the wipe actually reached the live buffer, not a copy.
        assertArrayEquals(ByteArray(secret.size), secret)
        assertArrayEquals(ByteArray(secret.size), record.sharedSecret)
    }

    @Test
    fun projectingAListWipesEverySourceSecretExactlyOnceEach() {
        val secrets = List(3) { i -> ByteArray(4) { (i + 1).toByte() } }
        val records = secrets.mapIndexed { i, s -> sampleRecord(contactId = "c$i", secret = s) }

        // Same shape as loadContactListSnapshot's projection.
        val projected = records.map { it.toListItem() }
        records.forEach { it.sharedSecret.secureWipe() }

        assertEquals(listOf("c0", "c1", "c2"), projected.map { it.contactId })
        records.forEach { r -> assertArrayEquals(ByteArray(4), r.sharedSecret) }
    }
}
