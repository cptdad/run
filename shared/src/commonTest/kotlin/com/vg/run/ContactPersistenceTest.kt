package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ContactPersistenceTest {

    // Shared stub — see note in VaultWipeTest.createVault.
    private fun createVault(): VaultDatabase = InMemoryVault()

    @Test
    fun contactWithInboxes_persistsAcrossReads() {
        val vault = createVault()
        val secret = generateSecureRandom(32)
        val contactId = "test-contact"

        vault.insertContact(ContactRecord(contactId, secret, 1, "TestAlias", 1000))
        vault.insertInboxId(InboxIdRecord("inbox-out", contactId, 1000, 9999999, "outbound"))
        vault.insertInboxId(InboxIdRecord("inbox-in", contactId, 1000, 9999999, "inbound"))

        // Simulate "reopen" — read contacts fresh
        val contacts = vault.getAllContacts()
        assertEquals(1, contacts.size)
        assertEquals("TestAlias", contacts[0].alias)
        assertTrue(secret.contentEquals(contacts[0].sharedSecret), "Shared secret must persist")

        val outbox = vault.getInboxIdForContact(contactId, "outbound")
        val inbox = vault.getInboxIdForContact(contactId, "inbound")
        assertEquals("inbox-out", outbox?.inboxId)
        assertEquals("inbox-in", inbox?.inboxId)
    }

    @Test
    fun multipleContacts_allPersist() {
        val vault = createVault()
        for (i in 1..5) {
            vault.insertContact(ContactRecord("c$i", generateSecureRandom(32), 1, "Contact$i", 1000))
        }
        assertEquals(5, vault.getAllContacts().size)
    }

    @Test
    fun deleteContact_removesInboxes() {
        val vault = createVault()
        val contactId = "c1"
        vault.insertContact(ContactRecord(contactId, generateSecureRandom(32), 1, "Alice", 1000))
        vault.insertInboxId(InboxIdRecord("i1", contactId, 1000, 9999999, "inbound"))
        vault.insertInboxId(InboxIdRecord("i2", contactId, 1000, 9999999, "outbound"))

        vault.deleteContact(contactId)

        assertEquals(null, vault.getContact(contactId))
        assertEquals(null, vault.getInboxIdForContact(contactId, "inbound"))
        assertEquals(null, vault.getInboxIdForContact(contactId, "outbound"))
    }

    @Test
    fun wipe_clearsEverything_butDoesNotAffectOtherVault() {
        // Wiping one vault instance must not touch a separate vault instance.
        val vaultA = createVault()
        val vaultB = createVault()

        vaultA.insertContact(ContactRecord("a1", generateSecureRandom(32), 1, "Alice", 1000))
        vaultB.insertContact(ContactRecord("b1", generateSecureRandom(32), 1, "Bob", 1000))

        vaultA.wipeAllTables()

        assertEquals(0, vaultA.getAllContacts().size, "wiped vault must be empty")
        assertEquals(1, vaultB.getAllContacts().size, "other vault unaffected")
    }
}
