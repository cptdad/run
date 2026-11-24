package com.vg.run

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.lang.reflect.Proxy

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

    // --- RÚN-03: the pairing kind rides in the projection -----------------------------

    @Test
    fun toListItem_carriesThePairingKind_fromTheRowFlag() {
        assertEquals(ContactPairingKind.OLDER, sampleRecord().toListItem().pairingKind)
        assertEquals(
            ContactPairingKind.CURRENT,
            sampleRecord().copy(ratchetBootstrapV3 = true).toListItem().pairingKind,
        )
    }

    /**
     * A VaultDatabase answering only what the contact-list load reads (the interface
     * is large and androidApp's tests cannot see the commonTest InMemoryVault). Any
     * other call returns null / false / an empty list, i.e. "no inbox rows".
     */
    private fun fakeVault(records: () -> List<ContactRecord>, meta: MutableMap<String, String>): VaultDatabase =
        Proxy.newProxyInstance(VaultDatabase::class.java.classLoader, arrayOf(VaultDatabase::class.java)) { _, m, args ->
            when (m.name) {
                "getAllContacts" -> records()
                "getContact" -> records().firstOrNull { it.contactId == args?.get(0) }
                "getAllGroups" -> emptyList<GroupRecord>()
                "getMeta" -> meta[args?.get(0) as String]
                "putMeta" -> { meta[args?.get(0) as String] = args[1] as String; Unit }
                "insertContact" -> 1L
                "withTransaction" -> { @Suppress("UNCHECKED_CAST") (args?.get(0) as () -> Unit)(); Unit }
                else -> when (m.returnType) {
                    java.lang.Boolean.TYPE -> false
                    java.lang.Long.TYPE -> 0L
                    java.lang.Integer.TYPE -> 0
                    java.util.List::class.java -> emptyList<Any>()
                    else -> null
                }
            }
        } as VaultDatabase

    @Test
    fun loadContactListSnapshot_carriesEachKind_countsOlder_andWipesTheSecrets() {
        val secrets = List(3) { ByteArray(32) { 7 } }
        val records = listOf(
            sampleRecord(contactId = "old-1", secret = secrets[0]),
            sampleRecord(contactId = "new-1", secret = secrets[1]).copy(ratchetBootstrapV3 = true),
            sampleRecord(contactId = "old-2", secret = secrets[2]),
        )
        val meta = mutableMapOf<String, String>()
        val snap = loadContactListSnapshot(fakeVault({ records }, meta))

        assertEquals(
            listOf(ContactPairingKind.OLDER, ContactPairingKind.CURRENT, ContactPairingKind.OLDER),
            snap.contacts.map { it.pairingKind },
        )
        assertEquals(2, snap.olderPairingCount)
        assertFalse(snap.olderPairingBannerDismissed)
        assertTrue("the banner shows while an older pairing exists", snap.showOlderPairingBanner)
        secrets.forEach { assertArrayEquals("every source secret is wiped", ByteArray(32), it) }
    }

    @Test
    fun theBanner_staysDismissed_andNeverShowsWithoutAnOlderPairing() {
        val meta = mutableMapOf<String, String>()
        val older = listOf(sampleRecord())
        val vault = fakeVault({ older.map { it.copy(sharedSecret = ByteArray(32)) } }, meta)
        assertTrue(loadContactListSnapshot(vault).showOlderPairingBanner)
        assertTrue(dismissOlderPairingBanner(vault))
        val after = loadContactListSnapshot(vault)
        assertTrue(after.olderPairingBannerDismissed)
        assertFalse("closed stays closed across reloads", after.showOlderPairingBanner)
        assertEquals(1, after.olderPairingCount)

        val current = listOf(sampleRecord().copy(ratchetBootstrapV3 = true))
        assertFalse(
            "no older pairing, no banner",
            loadContactListSnapshot(fakeVault({ current.map { it.copy(sharedSecret = ByteArray(32)) } }, mutableMapOf()))
                .showOlderPairingBanner,
        )
        assertFalse("no vault, nothing written", dismissOlderPairingBanner(null))
    }

    @Test
    fun rollContactAlias_keepsThePairingKind() {
        var row = sampleRecord().copy(ratchetBootstrapV3 = true)
        val vault = Proxy.newProxyInstance(VaultDatabase::class.java.classLoader, arrayOf(VaultDatabase::class.java)) { _, m, args ->
            when (m.name) {
                "getContact" -> row.copy(sharedSecret = row.sharedSecret.copyOf())
                "insertContact" -> { row = args?.get(0) as ContactRecord; 1L }
                "withTransaction" -> { @Suppress("UNCHECKED_CAST") (args?.get(0) as () -> Unit)(); Unit }
                else -> when (m.returnType) {
                    java.lang.Boolean.TYPE -> false
                    java.lang.Long.TYPE -> 0L
                    java.lang.Integer.TYPE -> 0
                    java.util.List::class.java -> emptyList<Any>()
                    else -> null
                }
            }
        } as VaultDatabase
        val before = row.toListItem()
        val after = rollContactAlias(vault, before)
        assertTrue("the name really changed", after.alias != before.alias)
        assertEquals(ContactPairingKind.CURRENT, after.pairingKind)
    }
}
