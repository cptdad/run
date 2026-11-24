package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest

// ---------------------------------------------------------------------------
// MoveRotationObligations.kt — the obligation set, the classifier, the bounded
// pass, the shared-list concurrency rules, the securing state and the one-time
// re-rotation for phones that imported on an older build. Synthetic ids only.
// ---------------------------------------------------------------------------

/** A vault that can be "closed" the iOS way: reads then answer empty, writes throw. */
private class ClosableVault : RollbackMoveVault() {
    var open = true
    override val isOpen: Boolean get() = open
    override fun getInboxId(inboxId: String): InboxIdRecord? = if (open) super.getInboxId(inboxId) else null
    override fun getMeta(key: String): String? = if (open) super.getMeta(key) else null
    override fun putMeta(key: String, value: String) {
        if (!open) throw IllegalStateException("closed")
        super.putMeta(key, value)
    }
}

class MoveRotationObligationsTest {

    // ---- the obligation set -------------------------------------------------

    @Test
    fun obligations_zeroOneAndManyEligible_areExactlyTheOwnedRowsPlusReferralMints() {
        val empty = MoveFakeVault()
        assertEquals(emptyList(), moveRotationObligations(VaultSnapshotIo.export(empty)))

        val one = MoveFakeVault()
        one.insertContact(ContactRecord("c", ByteArray(32) { 3 }, 2, "C", 10L))
        val id = rotId('T', 1)
        one.insertInboxId(InboxIdRecord(id, "c", 1L, 2L, "inbound", rotCap(id)))
        one.insertInboxId(InboxIdRecord(rotId('O', 1), "c", 1L, 2L, "outbound", rotCap("o")))
        assertEquals(listOf(id), moveRotationObligations(VaultSnapshotIo.export(one)))

        val many = MoveFakeVault()
        val owned = seedMoveContacts(many, 300)
        val mi = rotId('M', 1); val ci = rotId('N', 1); val gi = rotId('P', 1)
        many.putMeta("ref_p:i1", pendingReferralRecord(mi, ci, gi))
        val got = moveRotationObligations(VaultSnapshotIo.export(many))
        assertEquals(903, got.size, "900 owned + 3 referral-minted, nothing truncated")
        assertEquals(owned.toSet() + setOf(mi, ci, gi), got.toSet())
        assertEquals(got, got.distinct(), "de-duplicated")
    }

    @Test
    fun theImportTransaction_writesTheListAndMarkerBeforeImported_inTheSameTransaction() {
        val source = MoveFakeVault()
        val owned = seedMoveContacts(source, 2)
        val snapshot = VaultSnapshotIo.export(source)
        val target = RollbackMoveVault()

        VaultSnapshotIo.import(target, snapshot, MoveConstants.COUNTER_JUMP, "bundle-1")

        val txOf: Map<String, Int> = target.metaWrites.associate { (tx, key) -> key to tx }
        val keys = target.metaWrites.map { it.second }
        assertTrue(txOf.getValue(MoveMetaKeys.ROTATE_PENDING) > 0, "written inside a transaction")
        assertEquals(txOf.getValue(MoveMetaKeys.IMPORTED), txOf.getValue(MoveMetaKeys.ROTATE_PENDING), "the SAME transaction as the import")
        assertEquals(txOf.getValue(MoveMetaKeys.IMPORTED), txOf.getValue(MoveMetaKeys.ROTATE_VERSION))
        assertTrue(keys.indexOf(MoveMetaKeys.ROTATE_PENDING) < keys.indexOf(MoveMetaKeys.IMPORTED))
        assertEquals(MoveMetaKeys.IMPORTED, keys.last(), "mig_imported stays the last write")
        assertEquals(owned, MoveRotation.decode(target.getMeta(MoveMetaKeys.ROTATE_PENDING)))
        assertEquals(MoveSecuringState.Pending(6), moveSecuringState(target))
    }

    @Test
    fun anImportWithNothingToRotate_isCompleteAtOnce() {
        val source = MoveFakeVault()
        source.insertContact(ContactRecord("c", ByteArray(32) { 3 }, 2, "C", 10L))
        val target = RollbackMoveVault()
        VaultSnapshotIo.import(target, VaultSnapshotIo.export(source), MoveConstants.COUNTER_JUMP, "bundle-0")
        assertEquals(MoveSecuringState.Complete, moveSecuringState(target))
    }

    // ---- the import does not hold the screen; securing runs after it ----------

    @Test
    fun importReturnsBeforeAnyRotation_andTheBackgroundPassThenDrainsTheList() = runTest {
        val source = MoveFakeVault()
        val owned = seedMoveContacts(source, 10)                 // 30 owned
        val (handle, chunks) = sealForRotationTest(VaultSnapshotIo.export(source))
        val target = RollbackMoveVault()
        val transport = RotationTestTransport(chunks).apply { rotate = { id, _ -> rotCap("new$id") } }
        val mgr = rotationTestManager(target, transport)
        val steps = mutableListOf<MoveImportStep>()

        val result = mgr.importFromHandle(handle) { steps.add(it) }

        assertTrue(result is MoveImportResult.Success, "$result")
        assertEquals(listOf(MoveImportStep.FETCHING, MoveImportStep.IMPORTING), steps, "no SECURING on the import screen")
        assertTrue(transport.attempts.isEmpty(), "the import itself spends no rotation")
        assertEquals(MoveSecuringState.Pending(30), mgr.securingState(), "imported is not secured")

        val after = mgr.secureImportedInboxes()

        // Batches of IMPORT_BUDGET, looped until nothing fresh is left (review finding 3).
        assertEquals(30, transport.attempts.size, "every entry tried once")
        assertEquals(owned, transport.attempts, "in list order")
        assertEquals(MoveSecuringState.Complete, after)
        for (id in transport.rotated) assertEquals(rotCap("new$id"), target.getInboxId(id)?.cap, "persisted: $id")
        assertNull(target.getMeta(MoveMetaKeys.ROTATE_PENDING))
    }

    @Test
    fun aCancelDuringTheBackgroundPass_leavesEveryUnconfirmedEntryListed() = runTest {
        val source = MoveFakeVault()
        val owned = seedMoveContacts(source, 2)
        val (handle, chunks) = sealForRotationTest(VaultSnapshotIo.export(source))
        val target = RollbackMoveVault()
        val transport = RotationTestTransport(chunks)
        val mgr = rotationTestManager(target, transport)
        assertTrue(mgr.importFromHandle(handle) {} is MoveImportResult.Success)
        transport.rotate = { _, _ -> awaitCancellation() }

        val job = launch { mgr.secureImportedInboxes() }
        testScheduler.runCurrent()
        job.cancel()
        job.join()

        assertEquals(owned, listedRotations(target), "nothing settled, nothing lost")
        // The pass slot was released: a later pass runs.
        transport.rotate = { id, _ -> rotCap("n$id") }
        mgr.secureImportedInboxes()
        assertNull(target.getMeta(MoveMetaKeys.ROTATE_PENDING))
        assertEquals(MoveSecuringState.Complete, mgr.securingState())
    }

    // ---- exclusions are verdicts of their own ---------------------------------

    @Test
    fun exclusions_areAccountedSeparately_andNeverCountedAsRotated() {
        val v = RollbackMoveVault()
        v.putMeta(MoveMetaKeys.IMPORTED, "b")
        v.putMeta(MoveMetaKeys.ROTATE_VERSION, MoveRotation.VERSION)
        v.insertContact(ContactRecord("c", ByteArray(32) { 3 }, 2, "C", 10L))
        val rotate = rotId('T', 1)
        val outbound = rotId('O', 1)
        val noCap = rotId('C', 1)
        val superseded = rotId('G', 1)
        val newerGrp = rotId('G', 2)
        val gone = rotId('T', 9)
        val deferred = rotId('M', 1)
        v.insertInboxId(InboxIdRecord(rotate, "c", 10L, 20L, "inbound", rotCap(rotate)))
        v.insertInboxId(InboxIdRecord(outbound, "c", 10L, 20L, "outbound", rotCap(outbound)))
        v.insertInboxId(InboxIdRecord(noCap, "c", 10L, 20L, MessageManager.DIR_INBOUND_CTL, null))
        v.insertInboxId(InboxIdRecord(superseded, "c", 5L, 20L, MessageManager.DIR_INBOUND_GRP, rotCap(superseded)))
        v.insertInboxId(InboxIdRecord(newerGrp, "c", 15L, 20L, MessageManager.DIR_INBOUND_GRP, rotCap(newerGrp)))
        v.putMeta("ref_p:i", pendingReferralRecord(deferred, rotId('N', 1), rotId('P', 1)))
        v.putMeta(
            MoveMetaKeys.ROTATE_PENDING,
            listOf(rotate, outbound, "not-an-inbox-id", noCap, superseded, gone, deferred).joinToString(","),
        )

        val report = MoveRotationPassReport()
        val candidates = MoveRotation.plan(v, budget = 64, report = report)

        assertEquals(listOf(rotate), candidates.map { it.inboxId })
        assertEquals(1, report.dropped[MoveRotationVerdict.DROP_NOT_OWNED])
        assertEquals(1, report.dropped[MoveRotationVerdict.DROP_INVALID])
        assertEquals(1, report.dropped[MoveRotationVerdict.DROP_NO_CAP])
        assertEquals(1, report.dropped[MoveRotationVerdict.DROP_SUPERSEDED])
        assertEquals(1, report.dropped[MoveRotationVerdict.DROP_NO_ROW])
        assertEquals(1, report.deferredReferral)
        assertEquals(0, report.rotated)
        assertEquals(listOf(rotate, deferred), listedRotations(v), "drops leave; the deferred entry stays (at the back)")
    }

    @Test
    fun anAbsentRowOnAClosedOrUnansweringVault_isNeverDropped() {
        val v = ClosableVault()
        v.putMeta(MoveMetaKeys.IMPORTED, "b")
        val id = rotId('T', 3)
        v.putMeta(MoveMetaKeys.ROTATE_PENDING, id)
        v.open = false

        val (verdict, _) = MoveRotation.classify(v, id, emptySet())
        assertEquals(MoveRotationVerdict.KEEP_UNKNOWN, verdict, "a closed iOS vault reads 'no rows' — not evidence")

        // Open, but the vault answers nothing at all (the iOS bridge's empty result on
        // a query error): no `mig_imported` witness ⇒ still not proof.
        val silent = object : RollbackMoveVault() {
            override fun getMeta(key: String): String? = null
        }
        assertEquals(MoveRotationVerdict.KEEP_UNKNOWN, MoveRotation.classify(silent, id, emptySet()).first)

        v.open = true
        assertEquals(MoveRotationVerdict.DROP_NO_ROW, MoveRotation.classify(v, id, emptySet()).first, "open + answering ⇒ positive absence")
    }

    @Test
    fun aFailedReferralScan_rotatesNothing_andKeepsEverything() {
        val v = object : RollbackMoveVault() {
            override fun metaKeys(): List<String> = throw RuntimeException("scan failed")
        }
        val owned = seedMoveContacts(v, 1)
        v.putMeta(MoveMetaKeys.IMPORTED, "b")
        v.putMeta(MoveMetaKeys.ROTATE_VERSION, MoveRotation.VERSION)
        v.putMeta(MoveMetaKeys.ROTATE_PENDING, MoveRotation.encode(owned))
        val relay = CapRotatingRelay().apply { adoptCapsFrom(v) }

        retryPendingMoveRotations(v, MessageManager(v, "http://relay.test", relay))

        assertTrue(relay.puts.isEmpty(), "fail toward NOT rotating")
        assertEquals(owned, listedRotations(v))
    }

    // ---- bounded work, nothing starved -----------------------------------------

    @Test
    fun aBoundedPass_neverSpendsMoreThanItsBudget_andAFailingHeadNeverStarvesTheTail() {
        val v = RollbackMoveVault()
        val owned = seedMoveContacts(v, 300)                   // 900 entries
        v.putMeta(MoveMetaKeys.IMPORTED, "b")
        v.putMeta(MoveMetaKeys.ROTATE_VERSION, MoveRotation.VERSION)
        v.putMeta(MoveMetaKeys.ROTATE_PENDING, MoveRotation.encode(owned))
        val alwaysFail = owned.take(MoveRotation.SWEEP_BUDGET).toSet()
        val attemptsPerPass = mutableListOf<Int>()
        val confirmed = mutableListOf<String>()

        var passes = 0
        while (passes < 2000) {
            var attempts = 0
            MoveRotation.runPassBlocking(v, MoveRotation.SWEEP_BUDGET) { id, _ ->
                attempts++
                if (id in alwaysFail) null else { confirmed.add(id); rotCap("n$id") }
            }
            attemptsPerPass.add(attempts)
            passes++
            if (listedRotations(v).toSet() == alwaysFail) break
        }

        assertTrue(attemptsPerPass.all { it <= MoveRotation.SWEEP_BUDGET }, "never more than the budget per pass")
        assertEquals(alwaysFail, listedRotations(v).toSet(), "every other entry completed despite a failing head")
        assertTrue(passes <= 900 / 2 + 10, "finishes in a bounded number of passes: $passes")
        assertEquals((owned - alwaysFail).sorted(), confirmed.sorted(), "each other entry confirmed exactly once")
    }

    // ---- the import-side pass and the sweep never overwrite each other ----------

    @Test
    fun theImportPassAndTheSweep_concurrently_loseNothing_andOverwriteNothing() = runTest {
        val source = MoveFakeVault()
        val owned = seedMoveContacts(source, 3)                  // 9 owned
        val (handle, chunks) = sealForRotationTest(VaultSnapshotIo.export(source))
        val target = RollbackMoveVault()
        val transport = RotationTestTransport(chunks)
        val mgr = rotationTestManager(target, transport)
        assertTrue(mgr.importFromHandle(handle) {} is MoveImportResult.Success)

        val relay = CapRotatingRelay().apply { adoptCapsFrom(target) }
        val sweepMm = MessageManager(target, "http://relay.test", relay)
        val lateId = rotId('T', 77)
        var first = true
        transport.rotate = { id, _ ->
            if (first) {
                first = false
                // The control sweep fires while the import-side pass is mid-flight…
                retryPendingMoveRotations(target, sweepMm)
                // …and another writer changes the stored list under it: one entry is
                // settled elsewhere and one new obligation is appended.
                MoveRotation.settleConfirmed(target, owned.last())
                target.insertInboxId(InboxIdRecord(lateId, "contact-late", 10L, 20L, "inbound", rotCap(lateId)))
                target.putMeta(MoveMetaKeys.ROTATE_PENDING, target.getMeta(MoveMetaKeys.ROTATE_PENDING) + ",$lateId")
            }
            rotCap("new$id")
        }

        mgr.secureImportedInboxes()

        assertTrue(relay.calls.isEmpty(), "the sweep skipped: one pass at a time")
        val listed = listedRotations(target)
        assertTrue(lateId in listed || lateId in transport.rotated, "an entry added mid-pass is not overwritten away: $listed")
        assertFalse(owned.last() in listed, "an entry settled elsewhere is not resurrected")
        val accounted = transport.rotated.toSet() + listed + owned.last()
        assertTrue(accounted.containsAll(owned), "every eligible entry is rotated or still listed")
    }

    // ---- securing state + the status row ---------------------------------------

    @Test
    fun securingState_projectsOnlyWhatTheVaultProves() {
        val v = ClosableVault()
        assertEquals(MoveSecuringState.NotMoved, moveSecuringState(v))

        v.putMeta(MoveMetaKeys.IMPORTED, "b")
        assertEquals(MoveSecuringState.Pending(0), moveSecuringState(v), "a pre-fix import is never Complete before its re-rotation")

        v.putMeta(MoveMetaKeys.ROTATE_VERSION, MoveRotation.VERSION)
        v.putMeta(MoveMetaKeys.ROTATE_PENDING, "${rotId('T', 1)},${rotId('T', 2)}")
        assertEquals(MoveSecuringState.Pending(2), moveSecuringState(v))

        v.deleteMeta(MoveMetaKeys.ROTATE_PENDING)
        assertEquals(MoveSecuringState.Complete, moveSecuringState(v))

        v.open = false
        assertEquals(MoveSecuringState.Unknown, moveSecuringState(v))

        val throwing = object : RollbackMoveVault() {
            override fun getMeta(key: String): String? = throw RuntimeException("read failed")
        }
        assertEquals(MoveSecuringState.Unknown, moveSecuringState(throwing))
    }

    @Test
    fun theStatusRow_saysDoneOnlyAfterThisSessionSawItPending() {
        val latch = MoveSecuringRowLatch()
        assertEquals(MoveSecuringRow.HIDDEN, latch.observe(MoveSecuringState.NotMoved))
        assertEquals(MoveSecuringRow.HIDDEN, latch.observe(MoveSecuringState.Complete), "a long-finished move shows nothing")
        assertEquals(MoveSecuringRow.PENDING, latch.observe(MoveSecuringState.Pending(3)))
        assertEquals(MoveSecuringRow.PENDING, latch.observe(MoveSecuringState.Unknown), "unknown claims nothing new")
        assertEquals(MoveSecuringRow.DONE, latch.observe(MoveSecuringState.Complete))
        latch.reset()
        assertEquals(MoveSecuringRow.HIDDEN, latch.observe(MoveSecuringState.Complete))
    }

    // ---- the one-time re-rotation for a pre-fix import --------------------------

    @Test
    fun theReRotationSeed_isAllOrNothing_skipsAmbiguousReads_andRunsOnce() {
        val v = RollbackMoveVault()
        val owned = seedMoveContacts(v, 2)
        v.putMeta(MoveMetaKeys.IMPORTED, "bundle-old")
        v.putMeta(MoveMetaKeys.ROTATE_PENDING, owned[2])
        val mi = rotId('M', 5); val ci = rotId('N', 5); val gi = rotId('P', 5)
        v.putMeta("ref_p:pending", pendingReferralRecord(mi, ci, gi))

        // A death inside the seed transaction: nothing of it lands.
        v.throwOnPutMetaKey = MoveMetaKeys.ROTATE_VERSION
        assertFalse(MoveRotation.maybeReseedPreFixImport(v))
        assertEquals(listOf(owned[2]), listedRotations(v), "rolled back to exactly what was there")
        assertNull(v.getMeta(MoveMetaKeys.ROTATE_VERSION))
        assertEquals(MoveSecuringState.Pending(1), moveSecuringState(v))

        // An unreadable enumeration: nothing written this sweep.
        val unreadable = object : RollbackMoveVault() {
            override fun getAllInboxIds(): List<InboxIdRecord> = throw RuntimeException("read failed")
        }
        unreadable.putMeta(MoveMetaKeys.IMPORTED, "bundle-old")
        assertFalse(MoveRotation.maybeReseedPreFixImport(unreadable))
        assertNull(unreadable.getMeta(MoveMetaKeys.ROTATE_VERSION))

        // The next sweep seeds: the old list first, then every owned row, then the
        // pending introduction's minted inboxes.
        v.throwOnPutMetaKey = null
        assertTrue(MoveRotation.maybeReseedPreFixImport(v))
        val seeded = listedRotations(v)
        assertEquals(owned[2], seeded.first())
        assertEquals((owned + listOf(mi, ci, gi)).toSet(), seeded.toSet())
        assertEquals(MoveRotation.VERSION, v.getMeta(MoveMetaKeys.ROTATE_VERSION))

        // Once only: a second call changes nothing, even after the list drained.
        v.deleteMeta(MoveMetaKeys.ROTATE_PENDING)
        assertFalse(MoveRotation.maybeReseedPreFixImport(v))
        assertNull(v.getMeta(MoveMetaKeys.ROTATE_PENDING))
        assertEquals(MoveSecuringState.Complete, moveSecuringState(v))
    }

    @Test
    fun aFrozenOldPhone_thatOnceImported_isNeverSeededOrRotated() {
        val v = RollbackMoveVault()
        seedMoveContacts(v, 1)
        v.putMeta(MoveMetaKeys.IMPORTED, "bundle-old")
        v.putMeta(MoveMetaKeys.FROZEN, "1")
        val relay = CapRotatingRelay().apply { adoptCapsFrom(v) }

        retryPendingMoveRotations(v, MessageManager(v, "http://relay.test", relay))

        assertNull(v.getMeta(MoveMetaKeys.ROTATE_VERSION), "nothing is written on a frozen phone")
        assertTrue(relay.calls.isEmpty())
    }

    @Test
    fun theBackgroundPass_refusesOnAFrozenVault() = runTest {
        val v = RollbackMoveVault()
        val owned = seedMoveContacts(v, 1)
        v.putMeta(MoveMetaKeys.IMPORTED, "b")
        v.putMeta(MoveMetaKeys.ROTATE_VERSION, MoveRotation.VERSION)
        v.putMeta(MoveMetaKeys.ROTATE_PENDING, MoveRotation.encode(owned))
        v.putMeta(MoveMetaKeys.FROZEN, "1")
        val transport = RotationTestTransport(emptyList()).apply { rotate = { id, _ -> rotCap("n$id") } }

        rotationTestManager(v, transport).secureImportedInboxes()

        assertTrue(transport.attempts.isEmpty(), "the old phone of a later move never rotates")
        assertEquals(owned, listedRotations(v))
    }

    @Test
    fun aNeverMovedVault_paysOneRead_andNothingElse() {
        var reads = 0
        val v = object : RollbackMoveVault() {
            override fun getMeta(key: String): String? { reads++; return super.getMeta(key) }
        }
        seedMoveContacts(v, 1)
        val relay = CapRotatingRelay()
        val mm = MessageManager(v, "http://relay.test", relay)
        reads = 0
        retryPendingMoveRotations(v, mm)
        assertEquals(1, reads)
        assertTrue(relay.calls.isEmpty())
        assertNotEquals(0, v.inboxes.size)
    }
}
