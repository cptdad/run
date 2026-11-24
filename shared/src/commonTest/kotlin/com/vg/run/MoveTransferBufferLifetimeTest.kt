package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest

// ---------------------------------------------------------------------------
// MoveManager: the owned plaintext transfer buffers are zero BEFORE anything
// slow happens (RÚN-04 part a).
//
// Export: the serialized bundle is wiped the moment `seal` returns or throws, so
// it is already zero at the first upload, at a failure-path inbox DELETE, inside
// a failing upload and inside an upload a cancel is waiting on.
// Import: the transfer code and the drained (sealed) chunks are wiped the moment
// `open` returns or throws, and the opened plaintext the moment `decode` returns
// or throws, so all three are zero at the transfer DELETE, at the first read-cap
// rotation and inside a rotation a cancel is waiting on.
//
// The seam (`bundleEncoder` / `bundleOpener`) hands the test the very array the
// manager owns. What this proves is the lifetime of THAT array only: it says
// nothing about the whole-bundle String inside the codec, GC copies, platform
// crypto buffers or swap.
// ---------------------------------------------------------------------------

private const val L_TRANSFER_INBOX = "MoVeLiFeTiMe00000000000000001xYz"   // 32 chars
private const val L_RCAP = "RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR"
private const val L_WCAP = "WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW"
private const val L_INBOUND = "InBoUnDlIfEtImE0000000000000001x"
private const val L_INBOUND_CTL = "InBoUnDcTlLiFe00000000000000001x"
private const val L_CAP_A = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
private const val L_CAP_B = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
private const val L_CAP_NEW = "ddddddddddddddddddddddddddddddddddddddddddd"

private fun ByteArray.isAllZero(): Boolean = all { it == 0.toByte() }

private class BufLifetimeTransport : MoveTransport {
    var minted = MintedInbox(L_TRANSFER_INBOX, L_RCAP, L_WCAP, 0L)
    var failPostAtIndex: Int? = null
    var drainBlobs: List<ByteArray> = emptyList()
    /** Runs at the START of every call of that kind, before any scripted failure or suspension. */
    var onPost: (() -> Unit)? = null
    var onDelete: (() -> Unit)? = null
    var onRotate: (() -> Unit)? = null
    var postSuspend: (suspend () -> Unit)? = null
    var rotateSuspend: (suspend () -> Unit)? = null

    var posts = 0
    val deleted = mutableListOf<String>()

    override suspend fun mintTransferInbox(): MintedInbox = minted

    override suspend fun postChunk(inboxId: String, writeCap: String, sealedChunk: ByteArray, ttlSeconds: Long) {
        onPost?.invoke()
        postSuspend?.invoke()
        if (failPostAtIndex == posts) throw MoveTransportException("scripted upload failure")
        posts++
    }

    override suspend fun peekPending(inboxId: String, readCap: String): Int? = 0

    override suspend fun drain(inboxId: String, readCap: String): List<ByteArray> = drainBlobs

    override suspend fun deleteInbox(inboxId: String, readCap: String) {
        onDelete?.invoke()
        deleted.add(inboxId)
    }

    override suspend fun rotateReadCap(inboxId: String, currentReadCap: String): String {
        onRotate?.invoke()
        rotateSuspend?.invoke()
        return L_CAP_NEW
    }
}

private class BufLifetimeSession(private val transport: MoveTransport?) : MoveSessionControl {
    override suspend fun unregisterPushBestEffort() {}
    override suspend fun quiesce() {}
    override suspend fun resume() {}
    override fun transport(): MoveTransport? = transport
}

private fun lifetimeVault(): MoveFakeVault = MoveFakeVault().apply {
    insertContact(
        ContactRecord(
            contactId = "contact-1", sharedSecret = ByteArray(32) { 3 }, trustLevel = 2,
            alias = "Alpha", aliasLastRotated = 10L, outboundCounter = 5L, outboundCtlCounter = 7L,
        )
    )
    insertInboxId(InboxIdRecord(L_INBOUND, "contact-1", 1L, 2L, "inbound", L_CAP_A))
    insertInboxId(InboxIdRecord(L_INBOUND_CTL, "contact-1", 1L, 2L, MessageManager.DIR_INBOUND_CTL, L_CAP_B))
}

/** Records every array the manager's encoder returned (the owned export plaintext). */
private class BufCapturingEncoder(
    private val produce: (MigrationBundle) -> ByteArray = MigrationBundleCodec::encode,
) : (MigrationBundle) -> ByteArray {
    val outputs = mutableListOf<ByteArray>()
    override fun invoke(b: MigrationBundle): ByteArray = produce(b).also { outputs.add(it) }
    fun last(): ByteArray = assertNotNull(outputs.lastOrNull(), "the encoder never ran")
}

/** Records the code, the chunks and the opened plaintext the manager passed through `open`. */
private class BufCapturingOpener(
    private val produce: (List<ByteArray>, ByteArray, String, String) -> ByteArray = MigrationSeal::open,
) : (List<ByteArray>, ByteArray, String, String) -> ByteArray {
    var code: ByteArray? = null
    var chunks: List<ByteArray> = emptyList()
    var plaintext: ByteArray? = null
    override fun invoke(chunks: List<ByteArray>, code: ByteArray, inboxId: String, bundleId: String): ByteArray {
        this.code = code
        this.chunks = chunks
        return produce(chunks, code, inboxId, bundleId).also { plaintext = it }
    }
    /** Every owned import buffer this opener saw is all zeros. */
    fun allZero(): Boolean =
        (code?.isAllZero() ?: true) && chunks.all { it.isAllZero() } && (plaintext?.isAllZero() ?: true)
}

private fun exportManager(vault: VaultDatabase, transport: MoveTransport, encoder: BufCapturingEncoder) =
    MoveManager(
        vault = { vault },
        session = BufLifetimeSession(transport),
        platformTag = MigrationBundle.FROM_ANDROID,
        exportAuthGate = TestGrantedGate(),
        bundleEncoder = encoder,
        nowMs = { 1_700_000_000_000L },
    )

private fun importManager(vault: VaultDatabase, transport: MoveTransport, opener: BufCapturingOpener) =
    MoveManager(
        vault = { vault },
        session = BufLifetimeSession(transport),
        platformTag = MigrationBundle.FROM_ANDROID,
        exportAuthGate = TestGrantedGate(),
        bundleOpener = opener,
        nowMs = { 1_700_000_000_000L },
    )

/** A real sealed bundle of [vault]: the handle the new phone scans plus the relay's chunks. */
private fun sealVault(vault: VaultDatabase): Pair<MoveHandle, List<ByteArray>> {
    val bundleId = MoveHandleCodec.newBundleId()
    val plaintext = MigrationBundleCodec.encode(
        MigrationBundle(
            schema = MigrationBundleCodec.CURRENT_SCHEMA,
            from = MigrationBundle.FROM_IOS,
            createdMs = 1_700_000_000_000L,
            bundleId = bundleId,
            snapshot = VaultSnapshotIo.export(vault),
        )
    )
    val code = MigrationSeal.newCode()
    val chunks = MigrationSeal.seal(plaintext, code, L_TRANSFER_INBOX, bundleId)
    val handle = MoveHandle(L_TRANSFER_INBOX, L_RCAP, MigrationSeal.encodeCode(code), bundleId)
    plaintext.secureWipe()
    code.secureWipe()
    return handle to chunks
}

class MoveTransferBufferLifetimeTest {

    // ---- export ---------------------------------------------------------------

    @Test
    fun export_plaintextIsZeroAtEveryUpload() = runTest {
        val transport = BufLifetimeTransport()
        val encoder = BufCapturingEncoder()
        val seenAtPost = mutableListOf<Boolean>()
        transport.onPost = { seenAtPost.add(encoder.last().isAllZero()) }
        val mgr = exportManager(lifetimeVault(), transport, encoder)

        mgr.beginExport()

        assertTrue(mgr.exportState.value is MoveExportState.Ready, "got ${mgr.exportState.value}")
        assertTrue(encoder.last().isNotEmpty(), "precondition: a real bundle was encoded")
        assertTrue(seenAtPost.isNotEmpty(), "precondition: the bundle was uploaded")
        assertTrue(seenAtPost.all { it }, "the plaintext must already be zero at every upload: $seenAtPost")
    }

    @Test
    fun export_uploadFailure_plaintextIsZeroInTheFailingUploadAndAtTheDelete() = runTest {
        val transport = BufLifetimeTransport().apply { failPostAtIndex = 0 }
        val encoder = BufCapturingEncoder()
        var zeroAtPost: Boolean? = null
        var zeroAtDelete: Boolean? = null
        transport.onPost = { zeroAtPost = encoder.last().isAllZero() }
        transport.onDelete = { zeroAtDelete = encoder.last().isAllZero() }
        val vault = lifetimeVault()
        val mgr = exportManager(vault, transport, encoder)

        mgr.beginExport()

        val state = mgr.exportState.value
        assertTrue(state is MoveExportState.Failed, "expected Failed, got $state")
        assertEquals(MoveError.UPLOAD_FAILED, state.error)
        assertEquals(listOf(L_TRANSFER_INBOX), transport.deleted, "the half-filled inbox is still deleted")
        assertEquals(true, zeroAtPost, "the plaintext must be zero inside the failing upload")
        assertEquals(true, zeroAtDelete, "the plaintext must be zero at the failure-path DELETE")
        assertEquals("1", vault.getMeta(MoveMetaKeys.FROZEN), "a failed export stays frozen")
    }

    @Test
    fun export_tooLarge_plaintextIsZeroAtTheDelete() = runTest {
        val transport = BufLifetimeTransport()
        // One byte more than MAX_CHUNKS chunks can carry (4-byte length prefix included).
        val oversize = MoveConstants.MAX_CHUNKS * MoveConstants.CHUNK_PLAINTEXT_BYTES - 4 + 1
        val encoder = BufCapturingEncoder { ByteArray(oversize) { 0x41 } }
        var zeroAtDelete: Boolean? = null
        transport.onDelete = { zeroAtDelete = encoder.last().isAllZero() }
        val mgr = exportManager(lifetimeVault(), transport, encoder)

        mgr.beginExport()

        val state = mgr.exportState.value
        assertTrue(state is MoveExportState.Failed, "expected Failed, got $state")
        assertEquals(MoveError.TOO_LARGE, state.error)
        assertEquals(0, transport.posts, "nothing is uploaded")
        assertEquals(true, zeroAtDelete, "the plaintext must be zero at the TOO_LARGE DELETE")
    }

    @Test
    fun export_sealFailure_plaintextIsZeroAtTheDelete() = runTest {
        // A minted inbox id the seal refuses: the generic seal-failure branch.
        val transport = BufLifetimeTransport().apply { minted = MintedInbox("short", L_RCAP, L_WCAP, 0L) }
        val encoder = BufCapturingEncoder()
        var zeroAtDelete: Boolean? = null
        transport.onDelete = { zeroAtDelete = encoder.last().isAllZero() }
        val mgr = exportManager(lifetimeVault(), transport, encoder)

        mgr.beginExport()

        val state = mgr.exportState.value
        assertTrue(state is MoveExportState.Failed, "expected Failed, got $state")
        assertEquals(MoveError.UPLOAD_FAILED, state.error)
        assertEquals(true, zeroAtDelete, "the plaintext must be zero at the seal-failure DELETE")
    }

    @Test
    fun export_cancelDuringAnUpload_plaintextIsAlreadyZero_andTheOpSlotIsReleased() = runTest {
        val transport = BufLifetimeTransport().apply { postSuspend = { awaitCancellation() } }
        val encoder = BufCapturingEncoder()
        var zeroWhileSuspended: Boolean? = null
        transport.onPost = { if (zeroWhileSuspended == null) zeroWhileSuspended = encoder.last().isAllZero() }
        val vault = lifetimeVault()
        val mgr = exportManager(vault, transport, encoder)

        val job = launch { mgr.beginExport() }
        testScheduler.runCurrent()          // parked inside the first upload
        assertEquals(true, zeroWhileSuspended, "the plaintext must be zero while an upload is in flight")
        job.cancel()
        job.join()

        assertTrue(job.isCancelled)
        assertTrue(encoder.last().isAllZero(), "still zero after the cancel unwound")
        assertEquals("1", vault.getMeta(MoveMetaKeys.FROZEN), "a cancelled export stays frozen")
        assertNull(vault.getMeta(MoveMetaKeys.HANDLE), "no handle for an upload that never finished")

        // The op slot was released: a re-issue is admitted and completes.
        transport.postSuspend = null
        mgr.reissueExport()
        assertTrue(mgr.exportState.value is MoveExportState.Ready, "got ${mgr.exportState.value}")
        assertTrue(encoder.last().isAllZero(), "the re-issued bundle's plaintext is zero too")
    }

    // ---- import ---------------------------------------------------------------

    @Test
    fun import_codeChunksAndPlaintextAreZeroAtTheTransferDeleteAndAtEveryRotation() = runTest {
        val (handle, chunks) = sealVault(lifetimeVault())
        val transport = BufLifetimeTransport().apply { drainBlobs = chunks }
        val opener = BufCapturingOpener()
        var zeroAtDelete: Boolean? = null
        val zeroAtRotate = mutableListOf<Boolean>()
        transport.onDelete = { zeroAtDelete = opener.allZero() }
        transport.onRotate = { zeroAtRotate.add(opener.allZero()) }
        val target = MoveFakeVault()
        val mgr = importManager(target, transport, opener)

        val result = mgr.importFromHandle(handle) {}
        // RÚN-01: the rotations run in the background pass the platform starts right
        // after the import returns, not inside it.
        mgr.secureImportedInboxes()

        assertTrue(result is MoveImportResult.Success, "expected Success, got $result")
        assertNotNull(opener.code, "precondition: open ran")
        assertNotNull(opener.plaintext)
        assertEquals(listOf(L_TRANSFER_INBOX), transport.deleted)
        assertEquals(true, zeroAtDelete, "code, chunks and plaintext must be zero at the transfer DELETE")
        assertEquals(2, zeroAtRotate.size, "both owned inboxes rotate: $zeroAtRotate")
        assertTrue(zeroAtRotate.all { it }, "code, chunks and plaintext must be zero at every rotation: $zeroAtRotate")
        // The decoded model is not backed by the wiped arrays: the import landed intact.
        val imported = assertNotNull(target.getContact("contact-1"))
        assertTrue(imported.sharedSecret.contentEquals(ByteArray(32) { 3 }), "the imported secret must be intact")
        assertEquals(5L + MoveConstants.COUNTER_JUMP, imported.outboundCounter)
    }

    @Test
    fun import_cancelAfterTheCommit_buffersAreAlreadyZeroInsideTheRotation() = runTest {
        val (handle, chunks) = sealVault(lifetimeVault())
        val transport = BufLifetimeTransport().apply {
            drainBlobs = chunks
            rotateSuspend = { awaitCancellation() }
        }
        val opener = BufCapturingOpener()
        var zeroWhileSuspended: Boolean? = null
        transport.onRotate = { if (zeroWhileSuspended == null) zeroWhileSuspended = opener.allZero() }
        val target = MoveFakeVault()
        val mgr = importManager(target, transport, opener)

        var result: MoveImportResult? = null
        // RÚN-01: the import returns once committed; the rotations run in the
        // background securing pass, which is where this test parks.
        val job = launch {
            result = mgr.importFromHandle(handle) {}
            mgr.secureImportedInboxes()
        }
        testScheduler.runCurrent()          // parked inside the first rotation
        assertEquals(true, zeroWhileSuspended, "the buffers must be zero while a rotation is in flight")
        job.cancel()
        job.join()

        assertTrue(result is MoveImportResult.Success, "a cancel after the commit still reports Success: $result")
        assertTrue(opener.allZero(), "still zero after the cancel")
        assertEquals(handle.bundleId, target.getMeta(MoveMetaKeys.IMPORTED))
    }

    @Test
    fun import_failedDecode_wipesThePlaintextAndWritesNothing() = runTest {
        val (handle, chunks) = sealVault(lifetimeVault())
        val transport = BufLifetimeTransport().apply { drainBlobs = chunks }
        // `open` "succeeds" with bytes that are not a bundle.
        val opener = BufCapturingOpener { _, _, _, _ -> "this is not a bundle".encodeToByteArray() }
        val target = MoveFakeVault()
        val mgr = importManager(target, transport, opener)

        val result = mgr.importFromHandle(handle) {}

        assertTrue(result is MoveImportResult.Failure)
        assertEquals(MoveError.BUNDLE_CORRUPT, result.error)
        assertTrue(opener.allZero(), "plaintext, code and chunks must be zero after a failed decode")
        assertNull(target.getMeta(MoveMetaKeys.IMPORTED))
        assertTrue(transport.deleted.isEmpty(), "nothing committed, so the relay copy is not deleted")
    }

    @Test
    fun import_wrongCode_wipesTheCodeAndTheChunks() = runTest {
        val (handle, chunks) = sealVault(lifetimeVault())
        val transport = BufLifetimeTransport().apply { drainBlobs = chunks }
        val opener = BufCapturingOpener()
        val target = MoveFakeVault()
        val mgr = importManager(target, transport, opener)
        val wrong = handle.copy(code = MigrationSeal.encodeCode(ByteArray(MoveConstants.CODE_BYTES) { 9 }))

        val result = mgr.importFromHandle(wrong) {}

        assertTrue(result is MoveImportResult.Failure)
        assertEquals(MoveError.BAD_CODE, result.error)
        assertNotNull(opener.code, "precondition: open ran and threw")
        assertNull(opener.plaintext)
        assertTrue(opener.allZero(), "the code and the chunks must be zero after a failed open")
        assertNull(target.getContact("contact-1"))
    }
}
