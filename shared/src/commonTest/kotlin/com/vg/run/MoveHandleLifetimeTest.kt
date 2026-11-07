package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest

// ---------------------------------------------------------------------------
// Move-handle LIFETIME.
//
// `MoveExportState.Ready` is the only state that carries the one-time transfer
// CODE, and code + inbox read capability together are a full vault-export
// credential whose key is HKDF-derived independently of the vault — closing the
// vault does not reach it. So the rule this file pins is:
//
//   the code exists only while a live, unlocked session is displaying it.
//
// Both platforms cancel the export/import job on lock and on wipe and then call
// `scrubInMemory()`. Cancellation is COOPERATIVE, so neither half is sufficient
// alone; the three properties below are what make the pair safe:
//
//   1. `scrubInMemory` collapses `Ready` (proven freeze + proven upload, only the
//      RAM code is lost) to `FrozenNoCode`, and a half-run `Preparing` to `Idle`.
//      Without the second collapse a cancelled export leaves a status line with
//      no buttons under it for the life of the manager — `refreshFrozenState`
//      only ever moves `Idle -> FrozenNoCode`, and Android's in-process re-auth
//      lock keeps the very same MoveManager instance across the lock.
//   2. `Idle` is not a claim: the next unlock re-derives the truth from
//      `mig_frozen`, the durable authority, so the frozen phone still lands on
//      its "show again / wipe" screen.
//   3. An export that finishes its upload AFTER the session went away must not
//      publish the code at all. The bundle and its `mig_handle` survive, so the
//      user re-issues or cancels on the next unlock — nothing is destroyed and
//      no vault is touched. That is the brick-safe direction in both senses.
// ---------------------------------------------------------------------------

private const val MHL_INBOX  = "MoVeLiFeTiMe0000000000000000001x"                    // 32
private const val MHL_RCAP   = "LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL"        // 43
private const val MHL_WCAP   = "MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM"        // 43
private const val MHL_IN     = "MhLiNbOuNdTeXt000000000000000001"
private const val MHL_IN_CTL = "MhLiNbOuNdCtL0000000000000000001"
private const val MHL_CAP    = "nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn"

private class LifetimeTransport : MoveTransport {
    var mintThrows: Exception? = null
    var peekAnswer: Int? = 0
    val posts = mutableListOf<ByteArray>()
    val deleted = mutableListOf<String>()

    /** Fires after every successful chunk POST — the "the session died mid-upload" seam. */
    var onPosted: (() -> Unit)? = null

    override suspend fun mintTransferInbox(): MintedInbox {
        mintThrows?.let { throw it }
        return MintedInbox(MHL_INBOX, MHL_RCAP, MHL_WCAP, 0L)
    }

    override suspend fun postChunk(inboxId: String, writeCap: String, sealedChunk: ByteArray, ttlSeconds: Long) {
        posts.add(sealedChunk.copyOf())
        onPosted?.invoke()
    }

    override suspend fun peekPending(inboxId: String, readCap: String): Int? = peekAnswer
    override suspend fun drain(inboxId: String, readCap: String): List<ByteArray> = emptyList()
    override suspend fun deleteInbox(inboxId: String, readCap: String) { deleted.add(inboxId) }
    override suspend fun rotateReadCap(inboxId: String, currentReadCap: String): String = MHL_CAP
}

/** Session whose [quiesce] parks until [gate] completes — the mid-export freeze point. */
private class LifetimeSession(
    private val transport: MoveTransport?,
    private val gate: CompletableDeferred<Unit>? = null,
) : MoveSessionControl {
    override suspend fun unregisterPushBestEffort() {}
    override suspend fun quiesce() { gate?.await() }
    override suspend fun resume() {}
    override fun transport(): MoveTransport? = transport
}

private fun lifetimeVault(): MoveFakeVault {
    val vault = MoveFakeVault()
    vault.insertContact(
        ContactRecord(
            contactId = "contact-1", sharedSecret = ByteArray(32) { 9 }, trustLevel = 2,
            alias = "Alpha", aliasLastRotated = 10L, outboundCounter = 3L, outboundCtlCounter = 4L,
        )
    )
    vault.insertInboxId(InboxIdRecord(MHL_IN, "contact-1", 1L, 2L, "inbound", MHL_CAP))
    vault.insertInboxId(InboxIdRecord(MHL_IN_CTL, "contact-1", 1L, 2L, MessageManager.DIR_INBOUND_CTL, MHL_CAP))
    vault.putMeta("dr-on/contact-1", "1")
    return vault
}

class MoveHandleLifetimeTest {

    // -----------------------------------------------------------------------
    // scrubInMemory — what a lock/wipe teardown leaves behind
    // -----------------------------------------------------------------------

    /**
     * The pre-existing half, pinned so it cannot drift: `Ready` is the state that
     * holds the code, and a lock must drop it. `FrozenNoCode` rather than `Idle`
     * because here BOTH the freeze and the upload are proven — only the RAM-only
     * code is lost, exactly as after a process death.
     */
    @Test
    fun scrubInMemory_collapsesReady_soTheOneTimeCodeNeverOutlivesTheSession() = runTest {
        val vault = lifetimeVault()
        val transport = LifetimeTransport()
        val mgr = MoveManager({ vault }, LifetimeSession(transport), MigrationBundle.FROM_ANDROID, exportAuthGate = TestGrantedGate())

        mgr.beginExport()
        val ready = mgr.exportStateNow()
        assertTrue(ready is MoveExportState.Ready, "precondition: expected Ready, got $ready")
        assertEquals(MigrationSeal.CODE_SYMBOLS, ready.handle.code.length)

        mgr.scrubInMemory()

        assertEquals(
            MoveExportState.FrozenNoCode, mgr.exportStateNow(),
            "a lock must drop the one-time code; the vault stays frozen and the user re-issues",
        )
        // The durable half is untouched — the bundle is still on the relay and
        // still addressable, so nothing about the scrub is destructive.
        assertEquals("1", vault.getMeta(MoveMetaKeys.FROZEN))
        assertNotNull(MoveManager.decodeStoredHandle(vault.getMeta(MoveMetaKeys.HANDLE)))
    }

    /**
     * The "ship both halves together" half. The platform cancels
     * `moveOpJob` and then scrubs; cancellation is cooperative, so a half-run
     * export is genuinely reachable in `Preparing`. Collapsing it to `Idle` —
     * not to `FrozenNoCode` — is what lets the NEXT unlock re-derive the truth
     * from `mig_frozen` instead of the manager asserting a state it cannot know.
     *
     * Non-vacuousness: delete the `Preparing -> Idle` arm and the first assert
     * fails with `Preparing(FREEZE)`, i.e. the buttonless spinner.
     */
    @Test
    fun scrubInMemory_collapsesAHalfRunExport_andTheNextUnlockReDerivesFrozen() = runTest {
        val vault = lifetimeVault()
        val gate = CompletableDeferred<Unit>()
        val mgr = MoveManager({ vault }, LifetimeSession(LifetimeTransport(), gate), MigrationBundle.FROM_ANDROID, exportAuthGate = TestGrantedGate())

        val job = launch { mgr.beginExport() }
        advanceUntilIdle()

        // Parked inside quiesce: the durable freeze has landed, the mint has not.
        assertTrue(
            mgr.exportStateNow() is MoveExportState.Preparing,
            "precondition: expected Preparing, got ${mgr.exportStateNow()}",
        )
        assertEquals("1", vault.getMeta(MoveMetaKeys.FROZEN), "precondition: the freeze is durable")

        // The teardown, in the platform's order: cancel the job, then scrub.
        job.cancel()
        mgr.scrubInMemory()

        assertEquals(
            MoveExportState.Idle, mgr.exportStateNow(),
            "a cancelled export must not leave `Preparing` standing — both UIs render it as a " +
                "status line with no buttons, and refreshFrozenState only moves Idle -> FrozenNoCode",
        )

        // The next unlock (both platforms call this on every vault open).
        mgr.refreshFrozenState()
        assertEquals(
            MoveExportState.FrozenNoCode, mgr.exportStateNow(),
            "the frozen phone must still land on its show-again/wipe screen — the durable " +
                "`mig_frozen` row is the authority, not the cancelled operation's last step",
        )
    }

    /** Non-vacuousness for the two arms above: nothing else is collapsed. */
    @Test
    fun scrubInMemory_leavesTheStatesThatCarryNoSecretAlone() = runTest {
        val vault = lifetimeVault()
        val mgr = MoveManager(
            { vault },
            LifetimeSession(LifetimeTransport().apply { mintThrows = MoveTransportException("no relay") }),
            MigrationBundle.FROM_ANDROID,
            exportAuthGate = TestGrantedGate(),
        )

        // Idle, before anything ran.
        mgr.scrubInMemory()
        assertEquals(MoveExportState.Idle, mgr.exportStateNow())

        // Failed is informative and actionable (retry / wipe) and holds no code.
        mgr.beginExport()
        val failed = mgr.exportStateNow()
        assertTrue(failed is MoveExportState.Failed, "precondition: expected Failed, got $failed")
        mgr.scrubInMemory()
        assertEquals(failed, mgr.exportStateNow(), "a real failure must survive the scrub — it has buttons")
    }

    // -----------------------------------------------------------------------
    // The code is never published into a session that no longer exists
    // -----------------------------------------------------------------------

    /**
     * The third half. `moveOpJob?.cancel()` cannot cut a POST that is
     * already on the wire, so the upload can finish after the lock/wipe has
     * closed the vault and after `scrubMoveSecrets()` has already run. Publishing
     * `Ready` there would put the transfer code — and with it a full
     * vault-export credential — into a StateFlow that outlives the session.
     *
     * Everything durable survives, which is what keeps this brick-safe: the
     * bundle stays on the relay, `mig_handle` stays in `_meta` (so peek / cancel
     * / re-issue all still work), `mig_frozen` stays set, and no vault row is
     * touched or deleted.
     */
    @Test
    fun export_doesNotPublishTheCode_whenTheSessionDiedDuringTheUpload() = runTest {
        val vault = lifetimeVault()
        var sessionAlive = true
        val transport = LifetimeTransport()
        // The lock/wipe lands while the last chunk is in flight.
        transport.onPosted = { sessionAlive = false }
        val mgr = MoveManager(
            { if (sessionAlive) vault else null },
            LifetimeSession(transport),
            MigrationBundle.FROM_ANDROID,
            exportAuthGate = TestGrantedGate(),
        )

        mgr.beginExport()

        val state = mgr.exportStateNow()
        assertTrue(
            state !is MoveExportState.Ready,
            "the one-time code must never be published after the session is gone, got $state",
        )
        assertEquals(MoveExportState.FrozenNoCode, state)
        assertTrue(transport.posts.isNotEmpty(), "precondition: the upload really did happen")
        // Nothing destructive: the bundle is still addressable on the next unlock.
        assertTrue(transport.deleted.isEmpty(), "the uploaded bundle must NOT be destroyed")
        assertEquals("1", vault.getMeta(MoveMetaKeys.FROZEN))
        val stored = MoveManager.decodeStoredHandle(vault.getMeta(MoveMetaKeys.HANDLE))
        assertNotNull(stored, "mig_handle must survive so peek/cancel/re-issue still work")
        assertEquals(MHL_INBOX, stored.inboxId)
        // And the vault itself is intact — the old phone is still the only copy.
        assertNotNull(vault.getContact("contact-1"))
        assertNull(vault.getMeta(MoveMetaKeys.IMPORTED))
    }
}
