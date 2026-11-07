package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * A contact-row EDIT (alias roll / mnemonic save) concurrent with a send or a
 * poll must never roll an anti-replay counter backward.
 *
 * All four counters (inbound/outbound × text/ctl) plus `inboundEpoch` live in ONE
 * `ContactRecord` row that `insertContact` upserts WHOLE, so an edit that reads the
 * row, is overtaken by a send/poll, and then writes its stale snapshot back reverts
 * that counter. The two outcomes are both security-relevant: a lowered INBOUND
 * baseline reopens the replay window (the counter is the entire replay defense —
 * messages are never persisted, so there is no secondary dedupe store), and a
 * lowered OUTBOUND counter makes the next send reuse a counter the peer drops as a
 * replay (silent message loss). The background control poll runs for the whole
 * unlocked session, so this race is a routine user action, not a corner case.
 *
 * `MessageManager.counterLock` covered send-vs-poll but was a private field, which
 * the edit paths structurally could not take; both now share
 * [ContactRowLocks.forContact]. Real threads + real Tink AES, so this lives here
 * rather than in commonTest — same reason as [ConcurrentSendSerializationTest].
 */
class ContactEditCounterRaceTest {

    private val inboundId  = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX"
    private val outboundId = "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"

    /** Always-200 relay: this test is about the vault write ordering, not the wire. */
    private val http = object : RelayHttp {
        override fun post(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int) =
            HttpResult(code = 200, body = null, isSuccess = true)
        override fun put(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int) =
            HttpResult(code = -1, body = "x", isSuccess = false)
        override fun get(url: String, headers: Map<String, String>, timeoutSeconds: Int) =
            HttpResult(code = 200, body = """{"blobs":[]}""", isSuccess = true)
    }

    private fun seed(vault: InMemoryVault, contactId: String) {
        vault.insertContact(ContactRecord(contactId, generateSecureRandom(32), 1, "T", 0L))
        vault.insertInboxId(InboxIdRecord(
            inboxId = inboundId, contactId = contactId,
            createdAt = 1L, expiresAt = Long.MAX_VALUE, direction = "inbound", cap = "A".repeat(43),
        ))
        vault.insertInboxId(InboxIdRecord(
            inboxId = outboundId, contactId = contactId,
            createdAt = 1L, expiresAt = Long.MAX_VALUE, direction = "outbound", cap = "B".repeat(43),
        ))
    }

    /**
     * Wraps [inner] so that ONE designated thread's `getContact` stalls after the
     * read — widening that caller's read→write window to something a scheduler
     * cannot accidentally close. Every other thread is untouched, so the send's own
     * locked re-read runs at full speed.
     */
    private class StallingReadVault(
        val inner: InMemoryVault,
        val stallFor: java.util.concurrent.atomic.AtomicReference<Thread?>,
        val hasRead: java.util.concurrent.CountDownLatch,
        val stallMs: Long,
    ) : VaultDatabase by inner {
        override fun getContact(contactId: String): ContactRecord? {
            val record = inner.getContact(contactId)
            if (Thread.currentThread() === stallFor.get()) {
                hasRead.countDown()
                Thread.sleep(stallMs)
            }
            return record
        }
    }

    @Test
    fun aliasRollConcurrentWithASend_neverRollsBackTheOutboundCounter() {
        val inner = InMemoryVault()
        val contactId = "c-edit-race"
        seed(inner, contactId)

        val editor = java.util.concurrent.atomic.AtomicReference<Thread?>(null)
        val editorHasRead = java.util.concurrent.CountDownLatch(1)
        val vault = StallingReadVault(inner, editor, editorHasRead, stallMs = 600)
        val mgr = MessageManager(vault, "http://relay.test", http as RelayHttp)

        val tEdit = Thread { ContactEdits.rollAlias(vault, contactId) }
        editor.set(tEdit)
        tEdit.start()
        // The edit has read the row; its write is ~600 ms away. Unlocked, the send
        // below slips in, bumps the counter, and the edit then overwrites it with 0.
        assertTrue(editorHasRead.await(5, java.util.concurrent.TimeUnit.SECONDS), "edit never read the row")

        val sent = java.util.concurrent.atomic.AtomicBoolean(false)
        val tSend = Thread { sent.set(mgr.sendMessage(contactId, "hello")) }
        tSend.start()
        tEdit.join(10_000); tSend.join(10_000)

        val after = inner.getContact(contactId)!!
        assertEquals(1L, after.outboundCounter,
            "the alias edit rolled the outbound counter back — the next send would REUSE counter 1 " +
                "and the peer would drop it as a replay (silent message loss)")
        assertTrue(sent.get(), "the send itself must still succeed")
        // The edit is not merely safe, it also survives: the send re-reads inside the
        // same lock, so it carries the new alias forward instead of clobbering it.
        assertTrue(ContactAliasGenerator.matchesGeneratedFormat(after.alias),
            "the rolled alias must survive the concurrent send (got '${after.alias}')")
    }

    @Test
    fun mnemonicSaveConcurrentWithAPoll_neverRollsBackTheInboundBaseline() {
        val inner = InMemoryVault()
        val contactId = "c-edit-race-2"
        seed(inner, contactId)
        // A baseline the poll is about to advance past.
        inner.insertContact(inner.getContact(contactId)!!.copy(
            inboundCounter = 5L, inboundEpoch = "e", outboundCounter = 3L,
        ))

        val editor = java.util.concurrent.atomic.AtomicReference<Thread?>(null)
        val editorHasRead = java.util.concurrent.CountDownLatch(1)
        val vault = StallingReadVault(inner, editor, editorHasRead, stallMs = 600)

        val tEdit = Thread { ContactEdits.updateMnemonic(vault, contactId, "a private note") }
        editor.set(tEdit)
        tEdit.start()
        assertTrue(editorHasRead.await(5, java.util.concurrent.TimeUnit.SECONDS), "edit never read the row")

        // Stand in for the poll's persist: exactly what pollChannel does — take the
        // shared per-contact row lock, re-read, advance THIS channel's baseline.
        val tPoll = Thread {
            ContactRowLocks.forContact(contactId).withLock {
                val fresh = vault.getContact(contactId)!!
                vault.insertContact(fresh.copy(inboundCounter = 9L, inboundEpoch = "e"))
            }
        }
        tPoll.start()
        tEdit.join(10_000); tPoll.join(10_000)

        val after = inner.getContact(contactId)!!
        assertEquals(9L, after.inboundCounter,
            "the mnemonic edit rolled the inbound replay baseline BACKWARD — a retaining relay could " +
                "re-serve counters 6..9 and they would decrypt and resurface")
        assertEquals("a private note", after.mnemonic, "the edit itself must survive")
    }
}
