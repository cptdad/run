package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

// ---------------------------------------------------------------------------
// RÚN-01 — the post-import read-cap rotation obligations survive every
// interruption. These tests drive only the public move entry points
// (`importFromHandle`, the control-sweep `retryPendingMoveRotations`) against a
// vault with REAL transaction rollback (RollbackMoveVault), so they say what a
// store looks like "after a reopen" on each side of the import commit.
//
// The invariant: reopening the store yields EITHER no committed import OR a
// committed import together with EVERY eligible rotation obligation.
// ---------------------------------------------------------------------------

class MoveRotationBoundaryTest {

    private fun assertNothingOrEverything(vault: VaultDatabase, eligible: List<String>, why: String) {
        val imported = vault.getMeta(MoveMetaKeys.IMPORTED)
        if (imported.isNullOrEmpty()) {
            assertNull(vault.getMeta("mig_rotate_pending"), "$why: no committed import, so no obligations either")
            assertTrue(vault.getAllContacts().isEmpty(), "$why: no committed import, so no contact rows")
        } else {
            assertEquals(eligible.toSet(), listedRotations(vault).toSet(), "$why: a committed import carries EVERY obligation")
        }
    }

    // ---- zero / one / more than 256 ---------------------------------------

    @Test
    fun anImportOfMoreThan256OwnedInboxes_commitsEveryObligation_noneTruncated() = runTest {
        val source = MoveFakeVault()
        val owned = seedMoveContacts(source, 300)         // 900 owned inboxes
        val (handle, chunks) = sealForRotationTest(VaultSnapshotIo.export(source))
        val target = RollbackMoveVault()
        val transport = RotationTestTransport(chunks)     // every rotation unconfirmed

        val result = rotationTestManager(target, transport).importFromHandle(handle) {}

        assertTrue(result is MoveImportResult.Success, "$result")
        assertEquals(900, owned.size)
        assertEquals(owned.toSet(), listedRotations(target).toSet(), "all 900 obligations are durable — no 256 cap")
        assertTrue(listedRotations(target).none { it.startsWith("O") }, "outbound rows are never ours to rotate")
    }

    @Test
    fun anImportOfOneOwnedInbox_listsExactlyIt() = runTest {
        val source = MoveFakeVault()
        source.insertContact(ContactRecord("contact-x", ByteArray(32) { 3 }, 2, "X", 10L))
        val only = rotId('T', 7)
        source.insertInboxId(InboxIdRecord(only, "contact-x", 10L, 20L, "inbound", rotCap(only)))
        val out = rotId('O', 7)
        source.insertInboxId(InboxIdRecord(out, "contact-x", 10L, 20L, "outbound", rotCap(out)))
        val (handle, chunks) = sealForRotationTest(VaultSnapshotIo.export(source))
        val target = RollbackMoveVault()

        val result = rotationTestManager(target, RotationTestTransport(chunks)).importFromHandle(handle) {}

        assertTrue(result is MoveImportResult.Success, "$result")
        assertEquals(listOf(only), listedRotations(target))
    }

    @Test
    fun anImportWithNoOwnedInbox_listsNothing() = runTest {
        val source = MoveFakeVault()
        source.insertContact(ContactRecord("contact-x", ByteArray(32) { 3 }, 2, "X", 10L))
        val (handle, chunks) = sealForRotationTest(VaultSnapshotIo.export(source))
        val target = RollbackMoveVault()

        val result = rotationTestManager(target, RotationTestTransport(chunks)).importFromHandle(handle) {}

        assertTrue(result is MoveImportResult.Success, "$result")
        assertNull(target.getMeta("mig_rotate_pending"))
    }

    // ---- each side of the transaction boundary ------------------------------

    @Test
    fun aProcessDeathRightAfterTheImportCommit_leavesEveryObligationDurable() = runTest {
        val source = MoveFakeVault()
        val owned = seedMoveContacts(source, 3)
        val (handle, chunks) = sealForRotationTest(VaultSnapshotIo.export(source))
        val target = RollbackMoveVault().apply { dieAfterNextCommit = true }

        // The process "dies" the instant the import transaction commits: nothing
        // after it runs. The manager reports a failure; what matters is the store.
        rotationTestManager(target, RotationTestTransport(chunks)).importFromHandle(handle) {}

        assertTrue(!target.getMeta(MoveMetaKeys.IMPORTED).isNullOrEmpty(), "precondition: the import committed")
        assertNothingOrEverything(target, owned, "death after commit")
    }

    @Test
    fun aFailureInsideTheImport_ateverySide_leavesNothingOrEverything() = runTest {
        val source = MoveFakeVault()
        val owned = seedMoveContacts(source, 2)
        val (handle, chunks) = sealForRotationTest(VaultSnapshotIo.export(source))

        val injections: List<Pair<String, (RollbackMoveVault) -> Unit>> = listOf(
            "a contact insert" to { v -> v.throwOnInsertContact = true },
            "the obligation write" to { v -> v.throwOnPutMetaKey = "mig_rotate_pending" },
            "the imported marker" to { v -> v.throwOnPutMetaKey = MoveMetaKeys.IMPORTED },
        )
        for ((where, inject) in injections) {
            val target = RollbackMoveVault().also(inject)
            rotationTestManager(target, RotationTestTransport(chunks)).importFromHandle(handle) {}
            assertNothingOrEverything(target, owned, where)
        }
    }

    @Test
    fun aFailedObligationWrite_canNeverYieldASuccessfulImport() = runTest {
        val source = MoveFakeVault()
        seedMoveContacts(source, 2)
        val (handle, chunks) = sealForRotationTest(VaultSnapshotIo.export(source))
        val target = RollbackMoveVault().apply { throwOnPutMetaKey = "mig_rotate_pending" }

        val result = rotationTestManager(target, RotationTestTransport(chunks)).importFromHandle(handle) {}

        assertTrue(result is MoveImportResult.Failure, "an import whose obligations did not land must fail: $result")
        assertEquals(MoveError.IMPORT_FAILED, result.error)
        assertNull(target.getMeta(MoveMetaKeys.IMPORTED), "rolled back: the user retries from the old phone")
    }

    // ---- a realistic pending introduction ------------------------------------

    @Test
    fun aPendingIntroductionsMintedInboxes_areOwed_deferredUntilFinalize_thenRotated() = runTest {
        val source = MoveFakeVault()
        val owned = seedMoveContacts(source, 1)
        val mi = rotId('M', 900)
        val ci = rotId('N', 900)
        val gi = rotId('P', 900)
        // As production stores it: the minted inboxes live ONLY inside `ref_p`
        // until the introduction finalizes; there is no inbox row for them yet.
        source.putMeta("ref_p:intro-1", pendingReferralRecord(mi, ci, gi))
        val (handle, chunks) = sealForRotationTest(VaultSnapshotIo.export(source))
        val target = RollbackMoveVault()

        val result = rotationTestManager(target, RotationTestTransport(chunks)).importFromHandle(handle) {}
        assertTrue(result is MoveImportResult.Success, "$result")
        assertTrue(listedRotations(target).containsAll(listOf(mi, ci, gi)), "referral-minted inboxes are owed: ${listedRotations(target)}")
        assertTrue(listedRotations(target).containsAll(owned))

        val relay = CapRotatingRelay().apply { adoptCapsFrom(target) }
        val mm = MessageManager(target, "http://relay.test", relay)

        // While the introduction is pending: owned inboxes rotate, the minted ones wait.
        repeat(5) { retryPendingMoveRotations(target, mm) }
        assertTrue(relay.puts.none { it == mi || it == ci || it == gi }, "never rotated before finalize")
        assertEquals(setOf(mi, ci, gi), listedRotations(target).toSet(), "kept (deferred), not dropped")

        // Finalize, as ReferralManager does in one transaction: the rows appear with
        // the record's caps (which the old phone's copy also holds) and `ref_p` goes.
        target.withTransaction {
            target.insertContact(ContactRecord("contact-ref", ByteArray(32) { 5 }, 1, "Bee", 10L))
            target.insertInboxId(InboxIdRecord(mi, "contact-ref", 30L, 40L, "inbound", rotCap(mi)))
            target.insertInboxId(InboxIdRecord(ci, "contact-ref", 30L, 40L, MessageManager.DIR_INBOUND_CTL, rotCap(ci)))
            target.insertInboxId(InboxIdRecord(gi, "contact-ref", 30L, 40L, MessageManager.DIR_INBOUND_GRP, rotCap(gi)))
            target.deleteMeta("ref_p:intro-1")
        }
        relay.adoptCapsFrom(target)

        repeat(5) { retryPendingMoveRotations(target, mm) }
        for (id in listOf(mi, ci, gi)) {
            assertNotEquals(rotCap(id), target.getInboxId(id)?.cap, "rotated after finalize: $id")
            assertEquals(relay.caps[id], target.getInboxId(id)?.cap)
        }
        assertNull(target.getMeta("mig_rotate_pending"), "every obligation settled")
    }

    // ---- phones that imported on an older build ------------------------------

    @Test
    fun aPreFixImport_getsOneReRotationOfEveryOwnedInbox_onceAndOnlyOnce() {
        val vault = RollbackMoveVault()
        val owned = seedMoveContacts(vault, 3)
        // What an older build could leave: imported, a truncated / partial list, no marker.
        vault.putMeta(MoveMetaKeys.IMPORTED, "bundle-old")
        vault.putMeta("mig_rotate_pending", owned[4])
        val outbound = rotId('O', 1)
        val relay = CapRotatingRelay().apply { adoptCapsFrom(vault) }
        val mm = MessageManager(vault, "http://relay.test", relay)

        sweepUntilDrained(vault, mm)

        for (id in owned) {
            assertNotEquals(rotCap(id), vault.getInboxId(id)?.cap, "re-rotated: $id")
            assertEquals(relay.caps[id], vault.getInboxId(id)?.cap, "the vault holds the cap the relay honours: $id")
        }
        assertEquals(rotCap(outbound), vault.getInboxId(outbound)?.cap, "an outbound row is never touched")
        assertNull(vault.getMeta("mig_rotate_pending"))

        // Idempotent: later sweeps re-rotate nothing.
        val callsAfter = relay.calls.size
        repeat(3) { retryPendingMoveRotations(vault, mm) }
        assertEquals(callsAfter, relay.calls.size, "the one-time re-rotation never runs twice")
    }

    @Test
    fun anOldFormatList_isHonoured() {
        val vault = RollbackMoveVault()
        val owned = seedMoveContacts(vault, 2)
        vault.putMeta(MoveMetaKeys.IMPORTED, "bundle-old")
        // The exact grammar every build wrote: comma-separated ids, no marker.
        vault.putMeta("mig_rotate_pending", "${owned[0]},${owned[1]}")
        val relay = CapRotatingRelay().apply { adoptCapsFrom(vault) }
        val mm = MessageManager(vault, "http://relay.test", relay)

        sweepUntilDrained(vault, mm)

        assertNotEquals(rotCap(owned[0]), vault.getInboxId(owned[0])?.cap)
        assertNotEquals(rotCap(owned[1]), vault.getInboxId(owned[1])?.cap)
        assertNull(vault.getMeta("mig_rotate_pending"))
    }

    // ---- transient failure, duplicate retry ------------------------------------

    @Test
    fun aTransientFailure_thenDuplicateSweeps_keepConfirmedEntriesSettled_andTheRestCompletes() = runTest {
        val source = MoveFakeVault()
        val owned = seedMoveContacts(source, 4)               // 12 owned
        val (handle, chunks) = sealForRotationTest(VaultSnapshotIo.export(source))
        val target = RollbackMoveVault()
        assertTrue(rotationTestManager(target, RotationTestTransport(chunks)).importFromHandle(handle) {} is MoveImportResult.Success)

        val relay = CapRotatingRelay().apply {
            adoptCapsFrom(target)
            failPutsFor[owned[0]] = 3                            // the HEAD fails three times
        }
        val mm = MessageManager(target, "http://relay.test", relay)

        sweepUntilDrained(target, mm)
        repeat(3) { retryPendingMoveRotations(target, mm) }   // duplicate retries after completion

        for (id in owned) {
            assertEquals(relay.caps[id], target.getInboxId(id)?.cap, "settled on the relay's cap: $id")
            assertNotEquals(rotCap(id), target.getInboxId(id)?.cap)
        }
        // Each confirmed entry was rotated exactly once; only the failing one was retried.
        for (id in owned.drop(1)) assertEquals(1, relay.puts.count { it == id }, "rotated once: $id")
        assertEquals(4, relay.puts.count { it == owned[0] }, "three refused, the fourth confirmed")
        assertNull(target.getMeta("mig_rotate_pending"))
    }
}
