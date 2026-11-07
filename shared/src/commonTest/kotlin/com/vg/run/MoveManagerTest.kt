package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest

// ---------------------------------------------------------------------------
// MoveManager — "Move to new device" orchestration (docs/device-move.md, area 3).
//
// What these tests pin, and why each one is worth a test:
//
//  * ORDER. `mig_frozen` is written BEFORE the session is torn down and before
//    anything reaches the relay. Get that backwards and a poll cycle between the
//    snapshot and the freeze advances the Double Ratchet the new phone is about to
//    inherit (docs/device-move.md fact 5).
//  * NO FAILURE UNFREEZES, AND NO FAILURE ERASES. Every failed export leaves the
//    vault frozen and intact — the old phone is the user's only copy until they
//    wipe it themselves.
//  * CANCEL NEEDS POSITIVE PROOF. A drained (or unprovable) bundle must never
//    unfreeze a phone whose identity may already be live on another device.
//  * IMPORT IS DRAIN-THEN-COMMIT and guarded by `mig_imported`; the +10 000 counter
//    jump must be applied at most once.
//  * SECURING IS BEST-EFFORT. A rotation failure is deferred, never fatal, and a
//    referral-referenced inbox is never rotated out from under a pending handshake.
// ---------------------------------------------------------------------------

private const val TRANSFER_INBOX   = "MoVeInBoX0000000000000000000001x"  // 32 chars
private const val TRANSFER_RCAP    = "RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR"  // 43
private const val TRANSFER_WCAP    = "WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW"  // 43
private const val INBOUND_INBOX    = "InBoUnDtExT000000000000000000001"
private const val INBOUND_CTL_INBOX = "InBoUnDcTl0000000000000000000001"
private const val OUTBOUND_INBOX   = "OuTbOuNdTeXt00000000000000000001"
private const val REFERRAL_INBOX   = "ReFeRrAlMiNtEd000000000000000001"
private const val CAP_A            = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
private const val CAP_B            = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
private const val CAP_C            = "ccccccccccccccccccccccccccccccccccccccccccc"
private const val CAP_D            = "ddddddddddddddddddddddddddddddddddddddddddd"

/** [InMemoryVault] plus the unfiltered inbox enumeration the snapshot exporter needs. */
internal open class MoveFakeVault : InMemoryVault() {
    override fun getAllInboxIds(): List<InboxIdRecord> = inboxes.toList()
}

/** Records every vault write into a shared op log, so ORDER can be asserted. */
private class OpLogVault(private val ops: MutableList<String>) : MoveFakeVault() {
    override fun putMeta(key: String, value: String) {
        ops.add("put:$key")
        super.putMeta(key, value)
    }
    override fun deleteMeta(key: String) {
        ops.add("del:$key")
        super.deleteMeta(key)
    }
}

private class FakeMoveTransport(private val ops: MutableList<String> = mutableListOf()) : MoveTransport {
    var mintThrows: Exception? = null
    var minted = MintedInbox(TRANSFER_INBOX, TRANSFER_RCAP, TRANSFER_WCAP, 0L)
    var failPostAtIndex: Int? = null
    var peekThrows: Exception? = null
    /** null models a relay 404 (gone). */
    var peekAnswer: Int? = 0
    var drainThrows: Exception? = null
    var drainBlobs: List<ByteArray> = emptyList()
    var rotateFailures: Set<String> = emptySet()
    // Runs at the START of every rotation call, so a test can observe durable state then.
    var onRotate: ((String) -> Unit)? = null
    // Suspend points a cancellation test can park the import on.
    var drainSuspend: (suspend () -> Unit)? = null
    var rotateSuspend: (suspend () -> Unit)? = null

    val posts = mutableListOf<ByteArray>()
    val postTtls = mutableListOf<Long>()
    val deleted = mutableListOf<String>()
    val rotated = mutableListOf<String>()
    var mints = 0

    override suspend fun mintTransferInbox(): MintedInbox {
        ops.add("mint")
        mintThrows?.let { throw it }
        mints++
        return minted
    }

    override suspend fun postChunk(inboxId: String, writeCap: String, sealedChunk: ByteArray, ttlSeconds: Long) {
        ops.add("post")
        if (failPostAtIndex == posts.size) throw MoveTransportException("scripted upload failure")
        posts.add(sealedChunk.copyOf())
        postTtls.add(ttlSeconds)
    }

    override suspend fun peekPending(inboxId: String, readCap: String): Int? {
        ops.add("peek")
        peekThrows?.let { throw it }
        return peekAnswer
    }

    override suspend fun drain(inboxId: String, readCap: String): List<ByteArray> {
        ops.add("drain")
        drainSuspend?.invoke()
        drainThrows?.let { throw it }
        return drainBlobs
    }

    override suspend fun deleteInbox(inboxId: String, readCap: String) {
        ops.add("delete")
        deleted.add(inboxId)
    }

    override suspend fun rotateReadCap(inboxId: String, currentReadCap: String): String {
        ops.add("rotate")
        onRotate?.invoke(inboxId)
        rotateSuspend?.invoke()
        if (inboxId in rotateFailures) throw MoveTransportException("scripted rotation failure")
        rotated.add(inboxId)
        return CAP_D
    }
}

private class FakeSession(
    private val transport: MoveTransport?,
    private val ops: MutableList<String> = mutableListOf(),
) : MoveSessionControl {
    var quiesced = false
    var resumed = false
    override suspend fun unregisterPushBestEffort() { ops.add("unregister") }
    override suspend fun quiesce() { ops.add("quiesce"); quiesced = true }
    override suspend fun resume() { ops.add("resume"); resumed = true }
    override fun transport(): MoveTransport? = transport
}

private fun seededVault(vault: MoveFakeVault = MoveFakeVault()): MoveFakeVault {
    vault.insertContact(
        ContactRecord(
            contactId = "contact-1", sharedSecret = ByteArray(32) { 3 }, trustLevel = 2,
            alias = "Alpha", aliasLastRotated = 10L, outboundCounter = 5L, outboundCtlCounter = 7L,
        )
    )
    vault.insertInboxId(InboxIdRecord(INBOUND_INBOX, "contact-1", 1L, 2L, "inbound", CAP_A))
    vault.insertInboxId(InboxIdRecord(INBOUND_CTL_INBOX, "contact-1", 1L, 2L, MessageManager.DIR_INBOUND_CTL, CAP_B))
    vault.insertInboxId(InboxIdRecord(OUTBOUND_INBOX, "contact-1", 1L, 2L, "outbound", CAP_C))
    vault.putMeta("dr-on/contact-1", "1")
    return vault
}

private fun manager(
    vault: VaultDatabase?,
    session: MoveSessionControl,
    tag: String = MigrationBundle.FROM_ANDROID,
) = MoveManager({ vault }, session, tag, exportAuthGate = TestGrantedGate()) { 1_700_000_000_000L }

class MoveManagerTest {

    // ---- export ---------------------------------------------------------

    // ---- fresh-credential gate -------------------------

    @Test
    fun beginExport_withoutGrant_freezesNothingAndTouchesNoRelay() = runTest {
        val ops = mutableListOf<String>()
        val vault = seededVault(OpLogVault(ops))
        val session = FakeSession(FakeMoveTransport(ops), ops)
        val mgr = MoveManager({ vault }, session, MigrationBundle.FROM_ANDROID, MoveExportAuthGate()) { 1_700_000_000_000L }

        mgr.beginExport()

        assertTrue(mgr.exportState.value is MoveExportState.Failed, "expected Failed, got ${mgr.exportState.value}")
        assertNull(vault.getMeta(MoveMetaKeys.FROZEN), "no credential, no freeze")
        assertTrue(ops.none { it == "mint" || it == "quiesce" || it == "unregister" }, "nothing may run: $ops")
    }

    @Test
    fun beginExport_withGrant_runsAndSpendsTheToken() = runTest {
        val vault = seededVault()
        val gate = MoveExportAuthGate()
        val mgr = MoveManager({ vault }, FakeSession(FakeMoveTransport()), MigrationBundle.FROM_ANDROID, gate) { 1_700_000_000_000L }

        gate.grant()
        mgr.beginExport()

        assertTrue(mgr.exportState.value is MoveExportState.Ready, "got ${mgr.exportState.value}")
        assertFalse(gate.consume(), "the token must have been spent by the export")
    }

    @Test
    fun reissueExport_onAFrozenPhone_withoutAGrant_isRefusedAndUploadsNothing() = runTest {
        // "Show again" on a frozen phone mints a new inbox, uploads a new full-vault
        // bundle and shows a fresh code: whoever holds the unlocked frozen phone must
        // not get that without re-entering the credential.
        val vault = seededVault()
        vault.putMeta(MoveMetaKeys.FROZEN, "1")
        val transport = FakeMoveTransport()
        val gate = MoveExportAuthGate()
        val mgr = MoveManager({ vault }, FakeSession(transport), MigrationBundle.FROM_ANDROID, gate) { 1_700_000_000_000L }
        assertEquals(MoveExportState.FrozenNoCode, mgr.exportState.value)

        mgr.reissueExport()

        assertTrue(mgr.exportState.value is MoveExportState.Failed, "expected Failed, got ${mgr.exportState.value}")
        assertEquals(0, transport.mints, "no fresh credential, no new transfer inbox")
        assertTrue(transport.posts.isEmpty(), "no fresh credential, no bundle upload")
        assertEquals("1", vault.getMeta(MoveMetaKeys.FROZEN), "a refused re-issue leaves the phone frozen")

        gate.grant()
        mgr.reissueExport()

        assertTrue(mgr.exportState.value is MoveExportState.Ready, "a granted re-issue runs: ${mgr.exportState.value}")
        assertEquals(1, transport.mints)
        assertFalse(gate.consume(), "the re-issue must have spent the token")
    }

    @Test
    fun beginExport_writesFrozenBeforeQuiesceAndBeforeAnyRelayCall() = runTest {
        val ops = mutableListOf<String>()
        val vault = seededVault(OpLogVault(ops))
        val transport = FakeMoveTransport(ops)
        val session = FakeSession(transport, ops)

        manager(vault, session).beginExport()

        val frozenAt = ops.indexOf("put:${MoveMetaKeys.FROZEN}")
        assertTrue(frozenAt >= 0, "the freeze must be written: $ops")
        assertTrue(frozenAt < ops.indexOf("quiesce"), "freeze must precede the session teardown: $ops")
        assertTrue(frozenAt < ops.indexOf("mint"), "freeze must precede every relay call: $ops")
        // Push unregistration happens while the read caps are still ours.
        assertTrue(ops.indexOf("unregister") < frozenAt, "push unregistration comes first: $ops")
    }

    @Test
    fun beginExport_happyPath_uploadsWithTransferTtlAndPersistsTheHandle() = runTest {
        val vault = seededVault()
        val transport = FakeMoveTransport()
        val session = FakeSession(transport)
        val mgr = manager(vault, session)

        mgr.beginExport()

        val state = mgr.exportState.value
        assertTrue(state is MoveExportState.Ready, "expected Ready, got $state")
        assertEquals(transport.posts.size, state.chunkCount)
        assertTrue(transport.posts.isNotEmpty(), "the bundle must be uploaded")
        assertTrue(
            transport.postTtls.all { it == MoveConstants.TRANSFER_TTL_SECONDS },
            "every chunk must carry the 30-minute transfer TTL: ${transport.postTtls}",
        )
        assertEquals(MigrationSeal.CODE_SYMBOLS, state.handle.code.length)
        assertNotNull(MigrationSeal.decodeCode(state.handle.code), "the displayed code must decode")
        assertEquals(TRANSFER_INBOX, state.handle.inboxId)

        assertEquals("1", vault.getMeta(MoveMetaKeys.FROZEN))
        val stored = MoveManager.decodeStoredHandle(vault.getMeta(MoveMetaKeys.HANDLE))
        assertNotNull(stored, "mig_handle must be persisted and re-readable")
        assertEquals(TRANSFER_INBOX, stored.inboxId)
        assertEquals(TRANSFER_RCAP, stored.readCap)
        assertEquals(state.handle.bundleId, stored.bundleId)
        assertEquals(transport.posts.size, stored.chunkCount)
        assertTrue(session.quiesced, "the session must be torn down")
        assertTrue(transport.deleted.isEmpty(), "a successful export deletes nothing")
    }

    @Test
    fun beginExport_mintFailure_staysFrozenWithNoHandle() = runTest {
        val vault = seededVault()
        val transport = FakeMoveTransport().apply { mintThrows = MoveTransportException("no relay") }
        val mgr = manager(vault, FakeSession(transport))

        mgr.beginExport()

        val state = mgr.exportState.value
        assertTrue(state is MoveExportState.Failed, "expected Failed, got $state")
        assertEquals(MoveError.MINT_FAILED, state.error)
        assertTrue(state.retryable)
        assertEquals("1", vault.getMeta(MoveMetaKeys.FROZEN), "a failed export must leave the vault FROZEN")
        assertNull(vault.getMeta(MoveMetaKeys.HANDLE), "no handle may be recorded for a bundle that was never uploaded")
        // The vault itself is untouched — the old phone is still the only copy.
        assertNotNull(vault.getContact("contact-1"))
    }

    @Test
    fun beginExport_uploadFailure_destroysTheHalfFilledInbox() = runTest {
        val vault = seededVault()
        val transport = FakeMoveTransport().apply { failPostAtIndex = 0 }
        val mgr = manager(vault, FakeSession(transport))

        mgr.beginExport()

        val state = mgr.exportState.value
        assertTrue(state is MoveExportState.Failed, "expected Failed, got $state")
        assertEquals(MoveError.UPLOAD_FAILED, state.error)
        assertEquals(listOf(TRANSFER_INBOX), transport.deleted, "a half-filled transfer inbox must be deleted")
        assertNull(vault.getMeta(MoveMetaKeys.HANDLE))
        assertEquals("1", vault.getMeta(MoveMetaKeys.FROZEN))
    }

    @Test
    fun beginExport_withoutTransport_freezesAndReportsRelayUnreachable() = runTest {
        val vault = seededVault()
        val mgr = manager(vault, FakeSession(null))

        mgr.beginExport()

        val state = mgr.exportState.value
        assertTrue(state is MoveExportState.Failed, "expected Failed, got $state")
        assertEquals(MoveError.RELAY_UNREACHABLE, state.error)
        // The freeze still landed: whatever else failed, this device stops polling.
        assertEquals("1", vault.getMeta(MoveMetaKeys.FROZEN))
    }

    @Test
    fun beginExport_invalidPlatformTag_neverFreezes() = runTest {
        val vault = seededVault()
        val mgr = manager(vault, FakeSession(FakeMoveTransport()), tag = "symbian")

        mgr.beginExport()

        assertTrue(mgr.exportState.value is MoveExportState.Failed)
        assertNull(vault.getMeta(MoveMetaKeys.FROZEN), "a wiring bug must never strand a phone frozen")
    }

    @Test
    fun reissueExport_deletesTheOldInboxAndIssuesAFreshCodeAndBundleId() = runTest {
        val vault = seededVault()
        val transport = FakeMoveTransport()
        val mgr = manager(vault, FakeSession(transport))

        mgr.beginExport()
        val first = mgr.exportState.value as MoveExportState.Ready

        mgr.reissueExport()
        val second = mgr.exportState.value as MoveExportState.Ready

        assertEquals(2, transport.mints, "a re-issue mints a fresh transfer inbox")
        assertEquals(listOf(TRANSFER_INBOX), transport.deleted, "the previous transfer must be destroyed")
        assertTrue(first.handle.code != second.handle.code, "a re-issue must use a FRESH one-time code")
        assertTrue(first.handle.bundleId != second.handle.bundleId, "…and a fresh bundleId")
        assertEquals("1", vault.getMeta(MoveMetaKeys.FROZEN))
        assertEquals(second.handle.bundleId, MoveManager.decodeStoredHandle(vault.getMeta(MoveMetaKeys.HANDLE))?.bundleId)
    }

    @Test
    fun frozenVaultWithAHandle_constructsIntoFrozenNoCode() = runTest {
        val vault = seededVault()
        vault.putMeta(MoveMetaKeys.FROZEN, "1")
        vault.putMeta(
            MoveMetaKeys.HANDLE,
            MoveManager.encodeStoredHandle(TRANSFER_INBOX, TRANSFER_RCAP, MoveHandleCodec.newBundleId(), 1),
        )
        val mgr = manager(vault, FakeSession(FakeMoveTransport()))
        // The one-time code is RAM-only, so a re-launched frozen phone can only
        // re-issue or wipe — never show the old QR again.
        assertEquals(MoveExportState.FrozenNoCode, mgr.exportState.value)
        assertTrue(mgr.isFrozen())
    }

    // ---- waiting / cancel -------------------------------------------------

    @Test
    fun refreshTransferState_flipsToMovedOnDrainedAndOn404() = runTest {
        for (pending in listOf(0, null)) {
            val vault = seededVault()
            val transport = FakeMoveTransport()
            val mgr = manager(vault, FakeSession(transport))
            mgr.beginExport()
            transport.peekAnswer = pending

            mgr.refreshTransferState()

            assertEquals(MoveExportState.Moved, mgr.exportState.value, "pending=$pending must read as Moved")
            // Moved is DERIVED — nothing new is persisted.
            assertNotNull(vault.getMeta(MoveMetaKeys.HANDLE))
            assertEquals("1", vault.getMeta(MoveMetaKeys.FROZEN))
        }
    }

    @Test
    fun refreshTransferState_staysReadyWhilePendingAndWhenThePeekFails() = runTest {
        val vault = seededVault()
        val transport = FakeMoveTransport()
        val mgr = manager(vault, FakeSession(transport))
        mgr.beginExport()
        val chunks = (mgr.exportState.value as MoveExportState.Ready).chunkCount

        transport.peekAnswer = chunks
        mgr.refreshTransferState()
        assertTrue(mgr.exportState.value is MoveExportState.Ready, "a queued bundle stays Ready")

        // A transport failure is NOT evidence that the new phone has the bundle.
        transport.peekThrows = MoveTransportException("tor down")
        mgr.refreshTransferState()
        assertTrue(mgr.exportState.value is MoveExportState.Ready, "an unreachable relay must not read as Moved")
    }

    @Test
    fun cancelExport_beforeTheDrain_unfreezesResumesAndDeletesTheBundle() = runTest {
        val vault = seededVault()
        val transport = FakeMoveTransport()
        val session = FakeSession(transport)
        val mgr = manager(vault, session)
        mgr.beginExport()
        transport.peekAnswer = (mgr.exportState.value as MoveExportState.Ready).chunkCount

        assertTrue(mgr.cancelExport(), "a full queue proves the new phone has not drained it")

        assertEquals(listOf(TRANSFER_INBOX), transport.deleted)
        assertNull(vault.getMeta(MoveMetaKeys.FROZEN), "cancel must unfreeze")
        assertNull(vault.getMeta(MoveMetaKeys.HANDLE))
        assertTrue(session.resumed, "the session must be restarted")
        assertEquals(MoveExportState.Idle, mgr.exportState.value)
        assertFalse(mgr.isFrozen())
    }

    @Test
    fun cancelExport_afterTheDrain_isRefusedAndStaysFrozen() = runTest {
        val vault = seededVault()
        val transport = FakeMoveTransport()
        val session = FakeSession(transport)
        val mgr = manager(vault, session)
        mgr.beginExport()
        transport.peekAnswer = 0        // the new phone drained it

        assertFalse(mgr.cancelExport(), "a drained bundle must refuse the cancel")

        assertEquals("1", vault.getMeta(MoveMetaKeys.FROZEN), "a refused cancel must leave the phone frozen")
        assertNotNull(vault.getMeta(MoveMetaKeys.HANDLE))
        assertFalse(session.resumed, "the session must NOT resume — two live copies is the failure to avoid")
        assertEquals(MoveExportState.Moved, mgr.exportState.value)
    }

    @Test
    fun cancelExport_isRefusedWhenThePeekCannotProveAnything() = runTest {
        val vault = seededVault()
        val transport = FakeMoveTransport()
        val session = FakeSession(transport)
        val mgr = manager(vault, session)
        mgr.beginExport()
        transport.peekThrows = MoveTransportException("tor down")

        assertFalse(mgr.cancelExport(), "no proof, no unfreeze")
        assertEquals("1", vault.getMeta(MoveMetaKeys.FROZEN))
        assertFalse(session.resumed)
        assertTrue(mgr.exportState.value is MoveExportState.Ready, "the state must not move on an unknown peek")
    }

    // ---- import -----------------------------------------------------------

    @Test
    fun importFromHandle_happyPath_importsJumpsCountersDeletesAndRotates() = runTest {
        val source = seededVault()
        source.insertGroup(GroupRecord("GrOuP0000000000000000000000000001", "G", 3L, "aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb", 5L))
        // A pending referral whose freshly minted inbox must NOT be rotated: the
        // finalize writes the record's caps into inbox_ids verbatim.
        source.insertInboxId(InboxIdRecord(REFERRAL_INBOX, "contact-1", 1L, 2L, "inbound", CAP_A))
        source.putMeta("ref_p:intro1", """{"mi":"$REFERRAL_INBOX","mr":"$CAP_A"}""")

        val (handle, chunks) = sealSnapshot(VaultSnapshotIo.export(source))
        val target = MoveFakeVault()
        val transport = FakeMoveTransport().apply { drainBlobs = chunks }
        val mgr = manager(target, FakeSession(transport))
        val steps = mutableListOf<MoveImportStep>()

        val result = mgr.importFromHandle(handle) { steps.add(it) }

        assertTrue(result is MoveImportResult.Success, "expected Success, got $result")
        assertEquals(1, result.contacts)
        assertEquals(1, result.groups)
        assertEquals(listOf(MoveImportStep.FETCHING, MoveImportStep.IMPORTING, MoveImportStep.SECURING), steps)

        // Both outbound counters jumped, exactly once.
        val imported = target.getContact("contact-1")
        assertNotNull(imported)
        assertEquals(5L + MoveConstants.COUNTER_JUMP, imported.outboundCounter)
        assertEquals(7L + MoveConstants.COUNTER_JUMP, imported.outboundCtlCounter)
        assertEquals(handle.bundleId, target.getMeta(MoveMetaKeys.IMPORTED))
        assertEquals("1", target.getMeta("dr-on/contact-1"), "allowlisted ratchet meta must travel")

        // The relay copy is destroyed once the bundle is committed.
        assertEquals(listOf(TRANSFER_INBOX), transport.deleted)

        // Every inbound + inbound-ctl inbox rotated, EXCEPT the referral one;
        // outbound rows hold the PEER's write cap and are never touched.
        assertEquals(setOf(INBOUND_INBOX, INBOUND_CTL_INBOX), transport.rotated.toSet())
        assertEquals(CAP_D, target.getInboxId(INBOUND_INBOX)?.cap, "the new cap must be persisted")
        assertEquals(CAP_D, target.getInboxId(INBOUND_CTL_INBOX)?.cap)
        assertEquals(CAP_A, target.getInboxId(REFERRAL_INBOX)?.cap, "a referral-referenced inbox must keep its cap")
        assertEquals(CAP_C, target.getInboxId(OUTBOUND_INBOX)?.cap, "an outbound row is not ours to rotate")
        assertNull(target.getMeta(MoveManager.META_ROTATE_PENDING), "nothing deferred on a clean securing pass")
    }

    // ---- import cancellation: rethrow BEFORE the commit, swallow AFTER it --------

    @Test
    fun aCancelDuringTheTransferDrain_endsTheImportWithoutAResult_andWritesNothing() = runTest {
        val (handle, chunks) = sealSnapshot(VaultSnapshotIo.export(seededVault()))
        val target = MoveFakeVault()
        val transport = FakeMoveTransport().apply {
            drainBlobs = chunks
            drainSuspend = { awaitCancellation() }
        }
        val mgr = manager(target, FakeSession(transport))

        var result: MoveImportResult? = null
        val job = launch { result = mgr.importFromHandle(handle) {} }
        testScheduler.runCurrent()          // suspended inside the transfer drain
        job.cancel()
        job.join()

        assertTrue(job.isCancelled)
        assertNull(result, "a cancel before the commit ends the import — no result, got $result")
        assertNull(target.getMeta(MoveMetaKeys.IMPORTED), "nothing was imported")
        assertNull(target.getMeta(MoveManager.META_ROTATE_PENDING), "no rotation obligation was written")
        assertNull(target.getContact("contact-1"))

        // The op slot was released by the `finally`: a retry is admitted and lands.
        transport.drainSuspend = null
        assertTrue(mgr.importFromHandle(handle) {} is MoveImportResult.Success)
    }

    @Test
    fun aCancelAfterTheCommit_stillReturnsSuccess_andLeavesTheRotationsListed() = runTest {
        val (handle, chunks) = sealSnapshot(VaultSnapshotIo.export(seededVault()))
        val target = MoveFakeVault()
        val steps = mutableListOf<MoveImportStep>()
        val transport = FakeMoveTransport().apply {
            drainBlobs = chunks
            rotateSuspend = { awaitCancellation() }
        }
        val mgr = manager(target, FakeSession(transport))

        var result: MoveImportResult? = null
        val job = launch { result = mgr.importFromHandle(handle) { steps.add(it) } }
        testScheduler.runCurrent()          // suspended inside the first rotation (SECURING)
        assertEquals(MoveImportStep.SECURING, steps.last(), "precondition: the import committed")
        job.cancel()
        job.join()

        assertTrue(result is MoveImportResult.Success, "the identity is imported — expected Success, got $result")
        assertEquals(handle.bundleId, target.getMeta(MoveMetaKeys.IMPORTED))
        assertEquals(
            "$INBOUND_INBOX,$INBOUND_CTL_INBOX", target.getMeta(MoveManager.META_ROTATE_PENDING),
            "every unrotated inbox stays listed for the control sweep",
        )
        assertTrue(transport.rotated.isEmpty())
    }

    @Test
    fun importFromHandle_rotationFailure_isDeferredNeverFatal() = runTest {
        val source = seededVault()
        val (handle, chunks) = sealSnapshot(VaultSnapshotIo.export(source))
        val target = MoveFakeVault()
        val transport = FakeMoveTransport().apply {
            drainBlobs = chunks
            rotateFailures = setOf(INBOUND_CTL_INBOX)
        }
        val mgr = manager(target, FakeSession(transport))

        val result = mgr.importFromHandle(handle) {}

        assertTrue(result is MoveImportResult.Success, "a failed rotation must never fail the import: $result")
        assertEquals(INBOUND_CTL_INBOX, target.getMeta(MoveManager.META_ROTATE_PENDING))
        assertEquals(CAP_B, target.getInboxId(INBOUND_CTL_INBOX)?.cap, "the cap is unchanged until the retry lands")
        assertEquals(CAP_D, target.getInboxId(INBOUND_INBOX)?.cap, "the other inbox still rotated")
    }

    @Test
    fun importFromHandle_pendingListIsDurableBeforeTheFirstRotation_andShrinksPerSuccess() = runTest {
        val source = seededVault()
        source.insertInboxId(InboxIdRecord(REFERRAL_INBOX, "contact-1", 1L, 2L, "inbound", CAP_A))
        source.putMeta("ref_p:intro1", """{"mi":"$REFERRAL_INBOX","mr":"$CAP_A"}""")
        val (handle, chunks) = sealSnapshot(VaultSnapshotIo.export(source))
        val target = MoveFakeVault()
        val seenAtRotation = mutableListOf<String?>()
        val transport = FakeMoveTransport().apply {
            drainBlobs = chunks
            onRotate = { seenAtRotation.add(target.getMeta(MoveManager.META_ROTATE_PENDING)) }
        }
        val mgr = manager(target, FakeSession(transport))

        assertTrue(mgr.importFromHandle(handle) {} is MoveImportResult.Success)

        assertEquals(2, seenAtRotation.size, "two owned inboxes rotate: $seenAtRotation")
        // Before the FIRST rotation the whole obligation is already on disk…
        assertEquals("$INBOUND_INBOX,$INBOUND_CTL_INBOX", seenAtRotation[0])
        // …and each success prunes its own entry.
        assertEquals(INBOUND_CTL_INBOX, seenAtRotation[1])
        assertNull(target.getMeta(MoveManager.META_ROTATE_PENDING), "a clean pass leaves nothing listed")
        // A referral-referenced inbox is never listed (and never rotated).
        assertTrue(seenAtRotation.none { it != null && REFERRAL_INBOX in it }, "$seenAtRotation")
        assertFalse(REFERRAL_INBOX in transport.rotated)
    }

    @Test
    fun importFromHandle_aVaultClosedMidPass_leavesTheUnrotatedTailListed() = runTest {
        // A lock closes the vault while the securing pass is still running: every read
        // after that throws. The obligation for what did not rotate must survive.
        val source = seededVault()
        val (handle, chunks) = sealSnapshot(VaultSnapshotIo.export(source))
        var closed = false
        val target = object : MoveFakeVault() {
            override fun getInboxId(inboxId: String): InboxIdRecord? {
                if (closed) throw IllegalStateException("closed")
                return super.getInboxId(inboxId)
            }
        }
        val transport = FakeMoveTransport().apply {
            drainBlobs = chunks
            onRotate = { closed = true }    // the vault "closes" during the first rotation
        }
        val mgr = manager(target, FakeSession(transport))

        assertTrue(mgr.importFromHandle(handle) {} is MoveImportResult.Success)

        val listed = target.getMeta(MoveManager.META_ROTATE_PENDING)
        assertNotNull(listed, "the un-rotated inbox must stay listed for the sweep")
        assertTrue(INBOUND_CTL_INBOX in listed, listed)
    }

    @Test
    fun importFromHandle_referralScanFailure_listsEverythingAndRotatesNothing() = runTest {
        val source = seededVault()
        val (handle, chunks) = sealSnapshot(VaultSnapshotIo.export(source))
        val target = object : MoveFakeVault() {
            override fun metaKeys(): List<String> = throw RuntimeException("scan failed")
        }
        val transport = FakeMoveTransport().apply { drainBlobs = chunks }
        val mgr = manager(target, FakeSession(transport))

        assertTrue(mgr.importFromHandle(handle) {} is MoveImportResult.Success)

        assertTrue(transport.rotated.isEmpty(), "an unprovable rotation is deferred, never run")
        assertEquals(
            "$INBOUND_INBOX,$INBOUND_CTL_INBOX", target.getMeta(MoveManager.META_ROTATE_PENDING),
            "a failed referral scan must not lose the rotation obligation",
        )
    }

    @Test
    fun importFromHandle_refusesASecondImport() = runTest {
        val source = seededVault()
        val (handle, chunks) = sealSnapshot(VaultSnapshotIo.export(source))
        val target = MoveFakeVault()
        val transport = FakeMoveTransport().apply { drainBlobs = chunks }
        val mgr = manager(target, FakeSession(transport))

        assertTrue(mgr.importFromHandle(handle) {} is MoveImportResult.Success)
        val before = target.getContact("contact-1")?.outboundCounter

        val second = mgr.importFromHandle(handle) {}

        assertTrue(second is MoveImportResult.Failure)
        assertEquals(MoveError.ALREADY_IMPORTED, second.error)
        assertEquals(before, target.getContact("contact-1")?.outboundCounter, "the counter jump must not be re-applied")
    }

    @Test
    fun importFromHandle_emptyInboxIsBundleGone() = runTest {
        val target = MoveFakeVault()
        val mgr = manager(target, FakeSession(FakeMoveTransport()))
        val handle = MoveHandle(TRANSFER_INBOX, TRANSFER_RCAP, MigrationSeal.encodeCode(ByteArray(20) { 1 }), MoveHandleCodec.newBundleId())

        val result = mgr.importFromHandle(handle) {}

        assertTrue(result is MoveImportResult.Failure)
        assertEquals(MoveError.BUNDLE_GONE, result.error)
        assertNull(target.getMeta(MoveMetaKeys.IMPORTED), "nothing may be committed")
    }

    @Test
    fun importFromHandle_wrongCodeIsRejectedAndWritesNothing() = runTest {
        val source = seededVault()
        val (handle, chunks) = sealSnapshot(VaultSnapshotIo.export(source))
        val target = MoveFakeVault()
        val transport = FakeMoveTransport().apply { drainBlobs = chunks }
        val mgr = manager(target, FakeSession(transport))
        val wrong = handle.copy(code = MigrationSeal.encodeCode(ByteArray(MoveConstants.CODE_BYTES) { 9 }))

        val result = mgr.importFromHandle(wrong) {}

        assertTrue(result is MoveImportResult.Failure)
        assertEquals(MoveError.BAD_CODE, result.error)
        assertNull(target.getContact("contact-1"), "a failed unseal must not write a single row")
        assertNull(target.getMeta(MoveMetaKeys.IMPORTED))
    }

    @Test
    fun importFromHandle_refusesANewerSchema() = runTest {
        val source = seededVault()
        val (handle, chunks) = sealSnapshot(
            VaultSnapshotIo.export(source),
            schema = MigrationBundleCodec.CURRENT_SCHEMA + 1,
        )
        val target = MoveFakeVault()
        val transport = FakeMoveTransport().apply { drainBlobs = chunks }
        val mgr = manager(target, FakeSession(transport))

        val result = mgr.importFromHandle(handle) {}

        assertTrue(result is MoveImportResult.Failure)
        assertEquals(MoveError.SCHEMA_TOO_NEW, result.error)
        assertNull(target.getMeta(MoveMetaKeys.IMPORTED))
        assertNull(target.getContact("contact-1"))
    }

    @Test
    fun importFromHandle_toleratesADuplicateChunk() = runTest {
        // A POST whose response was lost is re-sent verbatim by the transient retry,
        // so the relay can hold one byte-identical extra copy. That must not fail an
        // import (the AEAD binds the chunk COUNT, so an un-deduped list would).
        val source = seededVault()
        val (handle, chunks) = sealSnapshot(VaultSnapshotIo.export(source))
        val target = MoveFakeVault()
        val transport = FakeMoveTransport().apply { drainBlobs = chunks + chunks.last().copyOf() }
        val mgr = manager(target, FakeSession(transport))

        val result = mgr.importFromHandle(handle) {}

        assertTrue(result is MoveImportResult.Success, "a duplicated blob must not break the import: $result")
    }

    // ---- deferred-rotation sweep -----------------------------------------

    @Test
    fun retryPendingMoveRotations_isANoOpWithoutATransportAndDropsDeadEntries() {
        val vault = MoveFakeVault()
        vault.putMeta(MoveManager.META_ROTATE_PENDING, INBOUND_INBOX)

        // No transport: the obligation must survive for a later sweep.
        retryPendingMoveRotations(vault, null)
        assertEquals(INBOUND_INBOX, vault.getMeta(MoveManager.META_ROTATE_PENDING))

        // The inbox row is gone (the contact was deleted): nothing to rotate ever
        // again, so the obligation is dropped rather than retried forever.
        retryPendingMoveRotations(vault, MessageManager(vault, "http://relay.test", RecordingRelayHttp()))
        assertNull(vault.getMeta(MoveManager.META_ROTATE_PENDING))
    }

    @Test
    fun retryPendingMoveRotations_neverRotatesAReferralReferencedEntry() {
        val vault = MoveFakeVault()
        vault.insertInboxId(InboxIdRecord(REFERRAL_INBOX, "contact-1", 1L, 2L, "inbound", CAP_A))
        vault.putMeta("ref_p:intro1", """{"mi":"$REFERRAL_INBOX","mr":"$CAP_A"}""")
        vault.putMeta(MoveManager.META_ROTATE_PENDING, REFERRAL_INBOX)
        val relay = RecordingRelayHttp()

        retryPendingMoveRotations(vault, MessageManager(vault, "http://relay.test", relay))

        assertTrue(relay.calls.none { REFERRAL_INBOX in it.url }, "a referral inbox must never be rotated")
        assertNull(vault.getMeta(MoveManager.META_ROTATE_PENDING), "the entry is dropped, exactly as at import")
        assertEquals(CAP_A, vault.getInboxId(REFERRAL_INBOX)?.cap)
    }

    @Test
    fun retryPendingMoveRotations_referralScanFailure_rotatesNothingAndKeepsTheList() {
        val vault = object : MoveFakeVault() {
            override fun metaKeys(): List<String> = throw RuntimeException("scan failed")
        }
        vault.insertInboxId(InboxIdRecord(INBOUND_INBOX, "contact-1", 1L, 2L, "inbound", CAP_A))
        vault.putMeta(MoveManager.META_ROTATE_PENDING, INBOUND_INBOX)
        val relay = RecordingRelayHttp()

        retryPendingMoveRotations(vault, MessageManager(vault, "http://relay.test", relay))

        assertTrue(relay.calls.none { INBOUND_INBOX in it.url }, "fail toward NOT rotating")
        assertEquals(INBOUND_INBOX, vault.getMeta(MoveManager.META_ROTATE_PENDING))
    }

    // ---- the freeze gate --------------------------------------------------

    @Test
    fun frozenVault_makesTheControlSweepAndEveryPollANoOp() {
        val vault = seededVault()
        val relay = RecordingRelayHttp()
        val managers = createSessionManagers(vault) { MessageManager(vault, "http://relay.test", relay) }

        // Not frozen: the sweep reaches the relay (it has contacts to drain).
        assertFalse(managers.groupManager.pollAllControls())
        val callsWhileLive = relay.calls.size
        assertTrue(callsWhileLive > 0, "a live session must actually poll")

        vault.putMeta(MoveMetaKeys.FROZEN, "1")
        relay.calls.clear()

        assertFalse(managers.groupManager.pollAllControls(), "a frozen phone must not sweep")
        managers.groupManager.pollGroup("GrOuP0000000000000000000000000001")
        managers.groupManager.pollDirect("contact-1")
        assertEquals(
            0, relay.calls.size,
            "a frozen phone must make NO relay call — one receive advances the ratchet the new phone inherited",
        )
    }

    @Test
    fun isMoveFrozen_failsTowardFrozenWhenTheVaultCannotBeRead() {
        val throwing = object : MoveFakeVault() {
            override fun getMeta(key: String): String? = throw RuntimeException("vault unavailable")
        }
        assertTrue(
            isMoveFrozen(throwing),
            "an unreadable vault must not be treated as 'safe to poll' — the fork hazard is one-way",
        )
    }

    // ---- wipe residue -----------------------------------------------------

    @Test
    fun migKeys_areVaultSingletonsNoPurgeMayMatchAndTheWipeClears() {
        // Same shape as MetaResiduePurgeTest's update_nudge / review_prompt pins: the
        // `mig_*` keys name no contact and no group, so no residue classifier may
        // match them — a contact delete must never silently UNFREEZE a phone that is
        // mid-move — and `wipeAllTables` (which clears `_meta` wholesale on both
        // actuals) is what erases them.
        val keys = listOf(
            MoveMetaKeys.FROZEN, MoveMetaKeys.HANDLE, MoveMetaKeys.IMPORTED, MoveManager.META_ROTATE_PENDING,
        )
        for (k in keys) {
            assertFalse(isGroupMetaResidueForGroup(k, "g"), k)
            assertFalse(isGroupMetaResidueForGroup(k, ""), k)
            assertFalse(isGroupMetaResidueForContact(k, "c"), k)
            assertFalse(isGroupMetaResidueForContact(k, ""), k)
            assertFalse(isScreenshotNoticeResidueForGroup(k, "g"), k)
            assertFalse(isScreenshotNoticeResidueForContact(k, "c"), k)
            assertFalse(isReferralMetaKey(k), k)
            assertFalse(k in ratchetMetaKeysForContact("c"), k)
            assertFalse(k in ratchetMetaKeysForContact(""), k)
            // And they can never be exported into a bundle.
            assertFalse(MoveMetaPolicy.isAllowedKey(k), "$k must never travel in a bundle")
        }

        val vault = seededVault()
        for (k in keys) vault.putMeta(k, "1")
        vault.deleteContact("contact-1")
        for (k in keys) assertNotNull(vault.getMeta(k), "$k must survive a contact delete")
        vault.wipeAllTables()
        for (k in keys) assertNull(vault.getMeta(k), "$k must be gone after a wipe")
    }
}

/**
 * Builds a real sealed bundle for the import tests: encode → seal, returning the
 * handle the new phone would have scanned plus the chunks the relay would hold.
 */
private fun sealSnapshot(
    snapshot: VaultSnapshot,
    schema: Int = MigrationBundleCodec.CURRENT_SCHEMA,
): Pair<MoveHandle, List<ByteArray>> {
    val bundleId = MoveHandleCodec.newBundleId()
    val plaintext = MigrationBundleCodec.encode(
        MigrationBundle(
            schema = schema,
            from = MigrationBundle.FROM_IOS,     // cross-platform by construction
            createdMs = 1_700_000_000_000L,
            bundleId = bundleId,
            snapshot = snapshot,
        )
    )
    val code = MigrationSeal.newCode()
    val chunks = MigrationSeal.seal(plaintext, code, TRANSFER_INBOX, bundleId)
    val handle = MoveHandle(TRANSFER_INBOX, TRANSFER_RCAP, MigrationSeal.encodeCode(code), bundleId)
    code.secureWipe()
    return handle to chunks
}

/**
 * [RelayMoveTransport] — the seam where a sealed chunk meets the relay. These pin
 * the two things that are invisible one layer up: that a chunk reaches the wire
 * VERBATIM, and that a relay answer is classified into evidence (404) vs
 * not-evidence (everything else that is not a success).
 */
class RelayMoveTransportTest {

    private fun transport(relay: RecordingRelayHttp) =
        RelayMoveTransport(MessageManager(MoveFakeVault(), "http://relay.test", relay))

    @Test
    fun postChunk_sendsTheSealedBytesUnchangedWithTheTtlAndNoPush() = runTest {
        val relay = RecordingRelayHttp()
        relay.script(HttpResult(code = 200, body = "{}", isSuccess = true))
        // Exactly what MigrationSeal emits: 12 IV + 60 000 + 16 tag.
        val chunk = ByteArray(MigrationSeal.SEALED_CHUNK_BYTES) { (it % 251).toByte() }

        transport(relay).postChunk(TRANSFER_INBOX, TRANSFER_WCAP, chunk, MoveConstants.TRANSFER_TTL_SECONDS)

        assertEquals(1, relay.calls.size)
        val call = relay.calls[0]
        assertEquals("POST", call.method)
        assertTrue(
            call.url.endsWith("/inbox/$TRANSFER_INBOX?ttl=${MoveConstants.TRANSFER_TTL_SECONDS}"),
            "the 30-minute transfer TTL must be on the URL: ${call.url}",
        )
        assertEquals(TRANSFER_WCAP, call.headers["X-Write-Capability"])
        assertEquals("1", call.headers["X-No-Push"], "a transfer chunk must never wake anyone")
        // THE POINT: no padMessage, no envelope, no second AES layer. A padded chunk
        // would land in the 65 536 bucket + 28 bytes of GCM overhead and every POST
        // would come back 413 (the relay's maxBlobBytes is 65 536).
        assertTrue(chunk.contentEquals(call.body), "the sealed chunk must reach the relay verbatim")
        assertTrue(call.body.size <= 65_536, "a chunk body must fit the relay ceiling: ${call.body.size}")
    }

    @Test
    fun postChunk_refusesAnOversizeChunkWithoutTouchingTheNetwork() = runTest {
        val relay = RecordingRelayHttp()
        val tooBig = ByteArray(65_537)
        var threw = false
        try {
            transport(relay).postChunk(TRANSFER_INBOX, TRANSFER_WCAP, tooBig, MoveConstants.TRANSFER_TTL_SECONDS)
        } catch (_: MoveTransportException) {
            threw = true
        }
        assertTrue(threw, "an oversize chunk must fail locally, not as a 413 mid-upload")
        assertEquals(0, relay.calls.size, "nothing may reach the relay")
    }

    @Test
    fun peekPending_readsTheCountOn200_nullOn404_andThrowsOnEverythingElse() = runTest {
        val ok = RecordingRelayHttp()
        ok.script(HttpResult(code = 200, body = """{"pending":3}""", isSuccess = true))
        assertEquals(3, transport(ok).peekPending(TRANSFER_INBOX, TRANSFER_RCAP))

        val gone = RecordingRelayHttp()
        gone.script(HttpResult(code = 404, body = """{"error":"request rejected"}""", isSuccess = false))
        assertNull(transport(gone).peekPending(TRANSFER_INBOX, TRANSFER_RCAP), "404 is the drained/gone evidence")

        // 429 / transport failure / an unreadable 200 must NOT masquerade as "gone" —
        // that is what would invite a user to wipe a phone whose bundle never arrived.
        for (reply in listOf(
            HttpResult(code = 429, body = """{"error":"rate limited"}""", isSuccess = false),
            HttpResult(code = -1, body = null, isSuccess = false),
            HttpResult(code = 200, body = """{"nope":1}""", isSuccess = true),
        )) {
            val relay = RecordingRelayHttp()
            relay.script(reply)
            var threw = false
            try {
                transport(relay).peekPending(TRANSFER_INBOX, TRANSFER_RCAP)
            } catch (_: MoveTransportException) {
                threw = true
            }
            assertTrue(threw, "code=${reply.code} must be reported as unknown, not as 'gone'")
        }
    }

    @Test
    fun drain_returnsRawBlobsOn200_emptyOn404_andThrowsOnAnythingElse() = runTest {
        val payload = ByteArray(64) { (it + 7).toByte() }
        val ok = RecordingRelayHttp()
        ok.script(HttpResult(code = 200, body = """{"blobs":["${encodeBase64(payload)}"]}""", isSuccess = true))
        val blobs = transport(ok).drain(TRANSFER_INBOX, TRANSFER_RCAP)
        assertEquals(1, blobs.size)
        assertTrue(payload.contentEquals(blobs[0]), "a drained blob must come back byte-for-byte")

        val gone = RecordingRelayHttp()
        gone.script(HttpResult(code = 404, body = """{"error":"request rejected"}""", isSuccess = false))
        assertTrue(transport(gone).drain(TRANSFER_INBOX, TRANSFER_RCAP).isEmpty())

        val down = RecordingRelayHttp()
        down.script(HttpResult(code = -1, body = null, isSuccess = false))
        var threw = false
        try {
            transport(down).drain(TRANSFER_INBOX, TRANSFER_RCAP)
        } catch (_: MoveTransportException) {
            threw = true
        }
        assertTrue(threw, "an unreachable relay must not read as an empty (gone) bundle")
    }

    @Test
    fun rotateReadCap_refusesAnInboxThisVaultDoesNotOwn() = runTest {
        val relay = RecordingRelayHttp()
        var threw = false
        try {
            // No such row in the vault: the rotation has nothing to authenticate
            // with, so it must refuse BEFORE any network call rather than issue a bare
            // PUT whose lost response would strand the inbox.
            transport(relay).rotateReadCap(INBOUND_INBOX, CAP_A)
        } catch (_: MoveTransportException) {
            threw = true
        }
        assertTrue(threw)
        assertEquals(0, relay.calls.size)
    }
}

/** Guards on re-entry: a second tap must not mint a second inbox. */
class MoveManagerReentryTest {

    @Test
    fun beginExport_twice_doesNotMintASecondTransfer() = runTest {
        val vault = seededVault()
        val transport = FakeMoveTransport()
        val mgr = manager(vault, FakeSession(transport))

        mgr.beginExport()
        val first = mgr.exportState.value as MoveExportState.Ready
        mgr.beginExport()
        val second = mgr.exportState.value as MoveExportState.Ready

        assertEquals(1, transport.mints, "a second tap on Continue must not orphan the first transfer")
        assertEquals(first.handle.code, second.handle.code, "the displayed code must not change under the user")
        assertTrue(transport.deleted.isEmpty())
    }

    @Test
    fun retryAfterAFailedExport_destroysTheSupersededTransfer() = runTest {
        val vault = seededVault()
        val transport = FakeMoveTransport()
        val mgr = manager(vault, FakeSession(transport))

        mgr.beginExport()                       // succeeds: handle persisted
        mgr.scrubInMemory()                     // process-death shape: the code is gone
        assertEquals(MoveExportState.FrozenNoCode, mgr.exportState.value)

        mgr.beginExport()                       // a retry from the frozen screen

        assertEquals(2, transport.mints)
        assertEquals(
            listOf(TRANSFER_INBOX), transport.deleted,
            "the superseded bundle must not be left live on the relay with no handle to delete it by",
        )
        assertTrue(mgr.exportState.value is MoveExportState.Ready)
    }
}
