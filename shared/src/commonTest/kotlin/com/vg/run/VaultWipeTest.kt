package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals

class VaultWipeTest {

    // Reuse the shared InMemoryVault stub (support/InMemoryVault.kt) — it
    // covers the group methods too, so per-test anonymous stubs would only
    // drift from the interface.
    private fun createVault(): VaultDatabase = InMemoryVault()

    @Test
    fun wipeAllTables_clearsAllData() {
        val vault = createVault()
        val secret = generateSecureRandom(32)
        vault.insertContact(ContactRecord("c1", secret, 1, "Alice", 0))
        vault.insertInboxId(InboxIdRecord("i1", "c1", 1000, 9999999, "inbound"))

        assertEquals(1, vault.getAllContacts().size)

        vault.wipeAllTables()

        assertEquals(0, vault.getAllContacts().size)
        assertEquals(null, vault.getInboxId("i1"))
    }

    @Test
    fun deleteContact_removesContact() {
        val vault = createVault()
        val secret = generateSecureRandom(32)
        vault.insertContact(ContactRecord("c1", secret, 1, "Alice", 0))

        vault.deleteContact("c1")

        assertEquals(null, vault.getContact("c1"))
    }
}
