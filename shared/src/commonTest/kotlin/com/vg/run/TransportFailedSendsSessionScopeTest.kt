package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// "TransportFailedSends ledger survives lock/wipe when
// the MessageManager is null".
//
// The ledger is a process-wide static whose only clear used to be
// MessageManager.scrubInMemory(), reached on lock / wipe only through
// `messageManager?.scrubInMemory()`. But entries are recorded EXACTLY when the
// manager is null (the no-transport parking branch on both platforms), and
// Android nulls the manager on Tor Failed / Idle / restart without scrubbing —
// so a lock or wipe taken while Tor was down left the parked PLAINTEXTS in RAM
// past the session (and past a crypto-erase).
//
// The seam that fixes it is platform code (RunViewModel.lockSession /
// performEmergencyWipe, IosAppController.lock() / emergencyWipe()) and is pinned
// at source level by `TransportFailedSendsLockWiringSourceTest` (androidApp). This
// file pins the ledger-side contract that seam relies on: a `clear()` issued with
// NO MessageManager in existence empties the shared ledger completely, so nothing
// recorded in the no-manager state can be re-driven by a later session.
// ---------------------------------------------------------------------------
class TransportFailedSendsSessionScopeTest {

    @Test
    fun anEntryRecordedWithNoManager_isGoneAfterTheSeamsClear() {
        var clock = 1_000_000L
        val ledger = TransportFailedSends(clock = { clock })
        // No MessageManager anywhere: this is the exact state the parking branch
        // records in (Tor died between the tap and the send).
        ledger.record("bubble-1", "contact-a", "plaintext that must not outlive the session", noPush = false, onRedriven = null, sessionEpoch = ledger.sessionEpoch)
        assertEquals(1, ledger.size(), "precondition: the send is parked")

        // What lockSession / performEmergencyWipe / IosAppController.lock|emergencyWipe
        // now do, independent of any manager.
        ledger.clear()

        assertEquals(0, ledger.size(), "the seam's clear must empty the ledger with no manager involved")
        // A transport-back re-drive in the NEXT session finds nothing, even inside
        // the 15-minute window (so a re-drive can never ship a pre-lock plaintext).
        clock += 1_000L
        assertTrue(ledger.takeEligible().isEmpty(), "nothing parked before the lock may be re-driven after it")
    }

    @Test
    fun theSharedLedger_isTheOneTheSeamClears_andClearIsIdempotent() {
        val shared = TransportFailedSends.shared
        shared.clear()   // start from a known state (other tests may have parked)
        shared.record("t1", "c", "p", noPush = false, onRedriven = null, sessionEpoch = shared.sessionEpoch)
        shared.record("t2", "c", "q", noPush = true, onRedriven = null, sessionEpoch = shared.sessionEpoch)
        assertEquals(2, shared.size())

        shared.clear()
        assertEquals(0, shared.size(), "the platform seams call TransportFailedSends.shared.clear()")
        shared.clear()
        assertEquals(0, shared.size(), "a second clear (lock after wipe, onCleared after lock) is harmless")
        assertTrue(shared.takeEligible().isEmpty())
    }

    @Test
    fun aClearNeverTouchesALaterSessionsParkedSend() {
        // Order matters only in one direction: a clear must not be "sticky". A
        // send parked AFTER the clear (next unlocked session, Tor down again) is
        // a legitimate entry for that session's transport-back re-drive.
        val ledger = TransportFailedSends(clock = { 5_000L })
        ledger.record("old", "c", "pre-lock", noPush = false, onRedriven = null, sessionEpoch = ledger.sessionEpoch)
        ledger.clear()
        ledger.record("new", "c", "post-unlock", noPush = false, onRedriven = null, sessionEpoch = ledger.sessionEpoch)
        val taken = ledger.takeEligible()
        assertEquals(listOf("new"), taken.map { it.token })
    }

    // -----------------------------------------------------------------------
    // Session epoch: a send that started in one session and finished after its
    // lock (the POST is blocking; Tor dying under it is a TRANSPORT failure) must
    // not re-park its plaintext after the lock's clear.
    // -----------------------------------------------------------------------

    @Test
    fun aRecordAfterEndSession_isRefused() {
        val ledger = TransportFailedSends(clock = { 5_000L })
        ledger.beginSession()
        val epochAtSend = ledger.sessionEpoch
        ledger.endSession()   // lock / wipe while the send's POST is still blocked
        ledger.record("late", "c", "plaintext from the locked session", noPush = false, onRedriven = null, sessionEpoch = epochAtSend)
        assertEquals(0, ledger.size(), "a send that outlived its session must not re-park after endSession")
        assertTrue(ledger.takeEligible().isEmpty())
    }

    @Test
    fun aRecordWithAStaleEpoch_isRefused_andTheCurrentEpoch_isAccepted() {
        val ledger = TransportFailedSends(clock = { 5_000L })
        ledger.beginSession()
        val stale = ledger.sessionEpoch
        ledger.endSession()
        ledger.beginSession()   // the next unlock
        val current = ledger.sessionEpoch
        assertTrue(stale != current, "every session boundary moves the epoch")

        ledger.record("old", "c", "previous session", noPush = false, onRedriven = null, sessionEpoch = stale)
        assertEquals(0, ledger.size(), "a stale-epoch record must not land in the new session")

        ledger.record("new", "c", "this session", noPush = false, onRedriven = null, sessionEpoch = current)
        assertEquals(listOf("new"), ledger.takeEligible().map { it.token })
    }

    @Test
    fun beginAndEndSession_clearTheLedger() {
        val ledger = TransportFailedSends(clock = { 5_000L })
        ledger.record("a", "c", "p", noPush = false, onRedriven = null, sessionEpoch = ledger.sessionEpoch)
        assertEquals(1, ledger.size())
        ledger.endSession()
        assertEquals(0, ledger.size(), "endSession clears")
        ledger.record("b", "c", "p", noPush = false, onRedriven = null, sessionEpoch = ledger.sessionEpoch)
        ledger.beginSession()
        assertEquals(0, ledger.size(), "beginSession clears too")
        ledger.endSession()
        ledger.endSession()
        assertEquals(0, ledger.size(), "a second endSession (lock then the final post-Tor-stop call) is harmless")
    }

    @Test
    fun clear_doesNotMoveTheEpoch() {
        // iOS still uses clear() at its seams (epoch parity is a later step); a
        // clear must not invalidate the open session's in-flight sends.
        val ledger = TransportFailedSends(clock = { 5_000L })
        val epoch = ledger.sessionEpoch
        ledger.clear()
        assertEquals(epoch, ledger.sessionEpoch)
        ledger.record("x", "c", "p", noPush = false, onRedriven = null, sessionEpoch = epoch)
        assertEquals(1, ledger.size())
    }
}
