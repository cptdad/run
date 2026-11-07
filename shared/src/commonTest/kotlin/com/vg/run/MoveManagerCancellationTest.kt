package com.vg.run

import kotlin.coroutines.cancellation.CancellationException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest

// ---------------------------------------------------------------------------
// MoveManager — a CANCELLED export ends; it is not reported as a failure and it
// does not run on. Both platforms cancel the export job on lock/background and
// then call scrubInMemory (Preparing → Idle). A broad `catch (e: Exception)`
// around a suspend call used to swallow that CancellationException:
//
//  * cancelled during push unregistration, the export went on to WRITE
//    `mig_frozen` for a session the user had already locked;
//  * cancelled during an upload, it published Failed(UPLOAD_FAILED, retryable)
//    over whatever the teardown had set.
//
// The third test pins the other half of the rule: a CancellationException that
// is NOT this job's (an inner timeout, job still active) is still the ordinary
// failure it always was.
// ---------------------------------------------------------------------------

private const val C_TRANSFER_INBOX = "MoVeCaNcEl000000000000000000001x"
private const val C_RCAP = "RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR"
private const val C_WCAP = "WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW"

private class CancelTransport(
    private val onPost: suspend () -> Unit = {},
) : MoveTransport {
    var posts = 0
    var mints = 0
    override suspend fun mintTransferInbox(): MintedInbox {
        mints++
        return MintedInbox(C_TRANSFER_INBOX, C_RCAP, C_WCAP, 0L)
    }
    override suspend fun postChunk(inboxId: String, writeCap: String, sealedChunk: ByteArray, ttlSeconds: Long) {
        posts++
        onPost()
    }
    override suspend fun peekPending(inboxId: String, readCap: String): Int? = 0
    override suspend fun drain(inboxId: String, readCap: String): List<ByteArray> = emptyList()
    override suspend fun deleteInbox(inboxId: String, readCap: String) {}
    override suspend fun rotateReadCap(inboxId: String, currentReadCap: String): String = currentReadCap
}

private class CancelSession(
    private val transport: MoveTransport?,
    private val onUnregister: suspend () -> Unit = {},
) : MoveSessionControl {
    override suspend fun unregisterPushBestEffort() = onUnregister()
    override suspend fun quiesce() {}
    override suspend fun resume() {}
    override fun transport(): MoveTransport? = transport
}

private fun cancelVault(): MoveFakeVault = MoveFakeVault().apply {
    insertContact(
        ContactRecord(
            contactId = "contact-1", sharedSecret = ByteArray(32) { 3 }, trustLevel = 2,
            alias = "Alpha", aliasLastRotated = 10L, outboundCounter = 5L, outboundCtlCounter = 7L,
        )
    )
    insertInboxId(
        InboxIdRecord(
            "InBoUnDcAnCeL000000000000000001x", "contact-1", 1L, 2L, "inbound",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
    )
}

class MoveManagerCancellationTest {

    @Test
    fun cancelDuringPushUnregistration_endsTheExportWithoutFreezing() = runTest {
        val vault = cancelVault()
        val transport = CancelTransport()
        val session = CancelSession(transport, onUnregister = { awaitCancellation() })
        val mgr = MoveManager({ vault }, session, MigrationBundle.FROM_ANDROID, TestGrantedGate()) { 1_700_000_000_000L }

        val job = launch { mgr.beginExport() }
        testScheduler.runCurrent()          // suspended inside unregisterPushBestEffort
        job.cancel()
        job.join()

        assertTrue(job.isCancelled, "the export job must end cancelled")
        assertNull(vault.getMeta(MoveMetaKeys.FROZEN), "a cancelled export must not freeze the phone afterwards")
        assertEquals(0, transport.mints, "nothing may reach the relay after the cancel")
        assertFalse(mgr.exportState.value is MoveExportState.Failed, "got ${mgr.exportState.value}")
    }

    @Test
    fun cancelDuringUpload_isNotReportedAsAnUploadFailure() = runTest {
        val vault = cancelVault()
        val transport = CancelTransport(onPost = { awaitCancellation() })
        val mgr = MoveManager({ vault }, CancelSession(transport), MigrationBundle.FROM_ANDROID, TestGrantedGate()) { 1_700_000_000_000L }

        val job = launch { mgr.beginExport() }
        testScheduler.runCurrent()          // suspended inside the first postChunk
        assertEquals(1, transport.posts, "precondition: the upload started")
        job.cancel()
        job.join()

        assertTrue(job.isCancelled, "the export job must end cancelled")
        assertFalse(mgr.exportState.value is MoveExportState.Failed, "got ${mgr.exportState.value}")
        // The freeze had already landed before the upload; the cancel does not undo it.
        assertEquals("1", vault.getMeta(MoveMetaKeys.FROZEN))
        // The teardown's scrub then settles the half-run export to Idle, as designed.
        mgr.scrubInMemory()
        assertEquals(MoveExportState.Idle, mgr.exportState.value)
    }

    @Test
    fun aForeignCancellationWithTheJobActive_isStillAnOrdinaryUploadFailure() = runTest {
        val vault = cancelVault()
        val transport = CancelTransport(onPost = { throw CancellationException("inner timeout") })
        val mgr = MoveManager({ vault }, CancelSession(transport), MigrationBundle.FROM_ANDROID, TestGrantedGate()) { 1_700_000_000_000L }

        mgr.beginExport()

        val state = mgr.exportState.value
        assertTrue(state is MoveExportState.Failed, "expected Failed, got $state")
        assertEquals(MoveError.UPLOAD_FAILED, state.error)
        assertTrue(state.retryable)
    }
}
