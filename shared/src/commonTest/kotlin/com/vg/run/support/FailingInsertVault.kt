package com.vg.run

// ---------------------------------------------------------------------------
// An [InMemoryVault] whose contact-row write can be made to fail on demand — the
// "vault not writable" case of the legacy replay-baseline persist.
//
// Models: `insertContact` throwing while [failInsertContact] is true (every other
// call is the plain in-memory vault), and a count of the contact writes that
// reached the vault. Does NOT model: partial writes or rollback.
// ---------------------------------------------------------------------------

internal class FailingInsertVault : InMemoryVault() {
    @kotlin.concurrent.Volatile var failInsertContact = false
    var insertContactCalls = 0
        private set

    override fun insertContact(contact: ContactRecord): Long {
        insertContactCalls++
        if (failInsertContact) throw RuntimeException("injected insertContact failure")
        return super.insertContact(contact)
    }
}
