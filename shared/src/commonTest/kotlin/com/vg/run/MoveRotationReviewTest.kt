package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest

// ---------------------------------------------------------------------------
// RÚN-01 review follow-ups: the securing pass vs an EXPORT (no rotation may be in
// flight across the freeze and the snapshot), a freeze landing mid-pass, the
// background pass draining the whole list, and the iOS "empty answer on a query
// error" shape (a read that returns EMPTY, not one that throws).
// ---------------------------------------------------------------------------

/**
 * A [MoveTransport] that can both export (mint / post / peek) and rotate. A rotation
 * parks on [gate] (when set), then commits the new cap on the relay ([relayCaps]) and
 * onto the vault row, exactly as the production rotate does.
 */
private class ExportAndRotateTransport(private val vault: VaultDatabase) : MoveTransport {
    val relayCaps = mutableMapOf<String, String>()
    val chunks = mutableListOf<ByteArray>()
    val attempts = mutableListOf<String>()
    var gate: CompletableDeferred<Unit>? = null
    var onRotate: ((String) -> Unit)? = null

    override suspend fun mintTransferInbox(): MintedInbox =
        MintedInbox(ROT_TRANSFER_INBOX, ROT_TRANSFER_RCAP, rotCap("transfer-w"), 0L)
    override suspend fun postChunk(inboxId: String, writeCap: String, sealedChunk: ByteArray, ttlSeconds: Long) {
        chunks.add(sealedChunk.copyOf())
    }
    override suspend fun peekPending(inboxId: String, readCap: String): Int? = chunks.size
    override suspend fun drain(inboxId: String, readCap: String): List<ByteArray> = chunks.toList()
    override suspend fun deleteInbox(inboxId: String, readCap: String) {}
    override suspend fun rotateReadCap(inboxId: String, currentReadCap: String): String {
        attempts.add(inboxId)
        onRotate?.invoke(inboxId)
        gate?.await()
        val newCap = rotCap("r${attempts.size}$inboxId")
        relayCaps[inboxId] = newCap
        vault.getInboxId(inboxId)?.let { vault.insertInboxId(it.copy(cap = newCap)) }
        return newCap
    }
}

private fun movedVault(contacts: Int): Pair<RollbackMoveVault, List<String>> {
    val v = RollbackMoveVault()
    val owned = seedMoveContacts(v, contacts)
    v.putMeta(MoveMetaKeys.IMPORTED, "bundle-b")
    v.putMeta(MoveMetaKeys.ROTATE_VERSION, MoveRotation.VERSION)
    v.putMeta(MoveMetaKeys.ROTATE_PENDING, MoveRotation.encode(owned))
    return v to owned
}

class MoveRotationReviewTest {

    // ---- finding 1: an export never overlaps a rotation -------------------------

    @Test
    fun anExportStartedWhileARotationIsInFlight_waitsForIt_andTheBundleMatchesTheRelay() = runTest {
        val (vault, owned) = movedVault(2)
        val transport = ExportAndRotateTransport(vault).apply {
            for (id in owned) relayCaps[id] = rotCap(id)
            gate = CompletableDeferred()
        }
        val mgr = rotationTestManager(vault, transport)

        val pass = launch { mgr.secureImportedInboxes() }
        testScheduler.runCurrent()                       // parked inside the first rotation
        assertEquals(1, transport.attempts.size)

        val export = launch { mgr.beginExport() }
        testScheduler.runCurrent()
        assertNull(vault.getMeta(MoveMetaKeys.FROZEN), "the freeze must wait for the rotation in flight")

        transport.gate!!.complete(Unit)
        testScheduler.advanceUntilIdle()
        pass.join(); export.join()

        val ready = mgr.exportState.value
        assertTrue(ready is MoveExportState.Ready, "export finished: $ready")
        assertEquals("1", vault.getMeta(MoveMetaKeys.FROZEN))
        assertEquals(1, transport.attempts.size, "no rotation after the export asked for the slot")
        val code = MigrationSeal.decodeCode(ready.handle.code)!!
        val bundle = MigrationBundleCodec.decode(
            MigrationSeal.open(transport.chunks, code, ready.handle.inboxId, ready.handle.bundleId),
        )
        for (id in owned) {
            val inBundle = bundle.snapshot.inboxes.first { it.inboxId == id }.cap
            assertEquals(transport.relayCaps[id], inBundle, "the bundle carries the cap the relay honours: $id")
        }
    }

    @Test
    fun aFreezeLandingMidPass_stopsEveryFurtherRotation_inThePassAndInTheSweep() = runTest {
        val (vault, owned) = movedVault(2)
        val transport = ExportAndRotateTransport(vault).apply {
            onRotate = { vault.putMeta(MoveMetaKeys.FROZEN, "1") }
        }
        rotationTestManager(vault, transport).secureImportedInboxes()
        assertEquals(1, transport.attempts.size, "the pass re-checks the freeze before every rotation")

        val (vault2, _) = movedVault(2)
        var sweepAttempts = 0
        MoveRotation.runPassBlocking(vault2, MoveRotation.SWEEP_BUDGET) { id, _ ->
            sweepAttempts++
            vault2.putMeta(MoveMetaKeys.FROZEN, "1")
            rotCap("s$id")
        }
        assertEquals(1, sweepAttempts, "the sweep re-checks the freeze before every rotation")
        assertTrue(owned.isNotEmpty())
    }

    // ---- the status row does not depend on a screen having looked in time ----------

    @Test
    fun aPassThatFinishesBeforeAnyScreenLooked_stillLeavesTheRowAtDone() = runTest {
        // iOS reads the row only while its settings sheet is open, and the pass can
        // finish within a second of the import: the row was then never shown at all.
        val (vault, _) = movedVault(1)
        val mgr = rotationTestManager(vault, RotationTestTransport(emptyList()).apply {
            rotate = { id, _ -> rotCap("n$id") }
        })
        mgr.secureImportedInboxes()
        assertEquals(emptyList(), listedRotations(vault))
        assertEquals(MoveSecuringRow.DONE, mgr.securingRow(), "the first look after the pass says done")
        mgr.scrubInMemory()
        assertEquals(MoveSecuringRow.HIDDEN, mgr.securingRow(), "a later session of a finished move shows nothing")
    }

    @Test
    fun aPassThatLeavesAnEntry_keepsTheRowAtPending() = runTest {
        val (vault, owned) = movedVault(1)
        val failing = owned[0]
        val mgr = rotationTestManager(vault, RotationTestTransport(emptyList()).apply {
            rotate = { id, _ -> if (id == failing) null else rotCap("n$id") }
        })
        mgr.secureImportedInboxes()
        assertEquals(MoveSecuringRow.PENDING, mgr.securingRow(), "an unconfirmed rotation is never reported as done")
        mgr.scrubInMemory()
        assertEquals(MoveSecuringRow.PENDING, mgr.securingRow(), "and a later session still reads the list")
    }

    // ---- finding 3: the background pass drains the list ---------------------------

    @Test
    fun theBackgroundPass_drainsTheWholeList_andTriesAFailingEntryOnlyOnce() = runTest {
        val (vault, owned) = movedVault(50)                  // 150 owned inboxes
        val failing = owned[3]
        val transport = RotationTestTransport(emptyList()).apply {
            rotate = { id, _ -> if (id == failing) null else rotCap("n$id") }
        }
        rotationTestManager(vault, transport).secureImportedInboxes()

        assertEquals(listOf(failing), listedRotations(vault), "only the unconfirmed entry is left")
        assertEquals(1, transport.attempts.count { it == failing }, "one try per pass")
        assertEquals(150, transport.attempts.size)
    }

    // ---- findings 2, 4, 5: an EMPTY answer is not evidence -------------------------

    @Test
    fun theReRotationSeed_deferredOnAnEmptyInboxAnswer_thenSeedsInFull() {
        var emptyOnce = true
        val v = object : RollbackMoveVault() {
            override fun getAllInboxIds(): List<InboxIdRecord> =
                if (emptyOnce) { emptyOnce = false; emptyList() } else super.getAllInboxIds()
        }
        val owned = seedMoveContacts(v, 2)
        v.putMeta(MoveMetaKeys.IMPORTED, "bundle-old")

        assertFalse(MoveRotation.maybeReseedPreFixImport(v), "contacts exist but no owned row came back: not believable")
        assertNull(v.getMeta(MoveMetaKeys.ROTATE_VERSION), "the marker must not be written")
        assertNotEquals(MoveSecuringState.Complete, moveSecuringState(v))

        assertTrue(MoveRotation.maybeReseedPreFixImport(v))
        assertEquals(owned.toSet(), listedRotations(v).toSet())
    }

    @Test
    fun theReRotationSeed_deferredWhenAnExistingListReadsEmpty() {
        val v = object : RollbackMoveVault() {
            var hideList = true
            override fun getMeta(key: String): String? =
                if (hideList && key == MoveMetaKeys.ROTATE_PENDING) null else super.getMeta(key)
        }
        seedMoveContacts(v, 1)
        v.putMeta(MoveMetaKeys.IMPORTED, "bundle-old")
        v.putMeta(MoveMetaKeys.ROTATE_PENDING, rotId('T', 0))

        assertFalse(MoveRotation.maybeReseedPreFixImport(v))
        assertNull(v.getMeta(MoveMetaKeys.ROTATE_VERSION))
    }

    @Test
    fun anExistingListThatReadsEmpty_isNeverReportedComplete() {
        val v = object : RollbackMoveVault() {
            override fun getMeta(key: String): String? =
                if (key == MoveMetaKeys.ROTATE_PENDING) null else super.getMeta(key)
        }
        v.putMeta(MoveMetaKeys.IMPORTED, "b")
        v.putMeta(MoveMetaKeys.ROTATE_VERSION, MoveRotation.VERSION)
        v.putMeta(MoveMetaKeys.ROTATE_PENDING, rotId('T', 1))

        assertEquals(MoveSecuringState.Unknown, moveSecuringState(v), "the key exists, so an empty read is not 'nothing left'")
    }

    @Test
    fun anEmptyRowLookup_confinedToOneQuery_isNotProofTheRowIsGone() {
        val v = object : RollbackMoveVault() {
            override fun getInboxId(inboxId: String): InboxIdRecord? = null
        }
        val owned = seedMoveContacts(v, 1)
        v.putMeta(MoveMetaKeys.IMPORTED, "b")

        assertEquals(MoveRotationVerdict.KEEP_UNKNOWN, MoveRotation.classify(v, owned[0], emptySet()).first)
    }

    // ---- finding 6: never overwrite a cap committed by someone else -------------

    @Test
    fun aCapCommittedConcurrently_isNotOverwrittenByTheStaleRotationResult() = runTest {
        val (vault, owned) = movedVault(1)
        val concurrent = rotCap("concurrent-reset")
        val transport = RotationTestTransport(emptyList()).apply {
            rotate = { id, _ ->
                // A "Reset relay access" rotation commits its cap first; this transport
                // (unlike the production one) does not commit and just answers X.
                vault.getInboxId(id)?.let { vault.insertInboxId(it.copy(cap = concurrent)) }
                rotCap("x$id")
            }
        }
        rotationTestManager(vault, transport).secureImportedInboxes()
        assertEquals(concurrent, vault.getInboxId(owned[0])?.cap)
    }

    // ---- finding 7: a null operational lookup has a defined end ----------------

    @Test
    fun aNullOperationalLookup_fallsBackToTheFullRowSet() {
        val v = object : RollbackMoveVault() {
            override fun getInboxIdForContact(contactId: String, direction: String): InboxIdRecord? = null
        }
        val owned = seedMoveContacts(v, 1)
        v.putMeta(MoveMetaKeys.IMPORTED, "b")
        assertEquals(MoveRotationVerdict.ROTATE, MoveRotation.classify(v, owned[0], emptySet()).first)
    }
}
