package com.vg.run

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.withContext
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The mint handling of [AddContactSessionViewModel] (G2 follow-up): one abort flag
 * PER mint (never re-armed), a mint bound to the transport it started on, and a
 * Ready mint that no transport change may replace.
 *
 * No relay: the minter is injected (production passes MessageManager.mintInboxPair)
 * and the session runs on an Unconfined scope, so a [CompletableDeferred] decides
 * exactly when each mint "returns". The fake minters wait under [NonCancellable],
 * like the real blocking PoW grind that `Job.cancel()` cannot stop — so the drop
 * rules are tested on their own, not via cancellation.
 */
class AddContactSessionMintTest {

    private fun session() = AddContactSessionViewModel(CoroutineScope(SupervisorJob() + Dispatchers.Unconfined))

    private class FakeMint {
        val result = CompletableDeferred<MintedInboxPair?>()
        var calls = 0
        var abort: PowAbort? = null
        val minter: suspend (PowAbort) -> MintedInboxPair? = { a ->
            calls++
            abort = a
            withContext(NonCancellable) { result.await() }
        }
    }

    private fun pair(tag: String) = MintedInboxPair(
        main = MintedInbox("$tag-main", "r", "w", 0L),
        ctl = MintedInbox("$tag-ctl", "r", "w", 0L),
        grp = MintedInbox("$tag-grp", "r", "w", 0L),
    )

    /** The screen's mapping, with the session's half. */
    private fun toState(half: ByteArray): (MintedInboxPair?) -> MintState = { r ->
        if (r != null) MintState.Ready(r.main, r.ctl, r.grp, half) else MintState.Failed("relay")
    }

    @Test
    fun aSecondStartWhileOneRunsOnTheSameManager_isRefused() {
        val vm = session()
        val half = vm.resumeOrStartNewSession()
        val manager = Any()
        val a = FakeMint()
        val b = FakeMint()
        assertTrue(vm.startMintIfIdle(manager, a.minter, toState(half)))
        assertFalse("same manager, mint running: re-attach, never a second grind",
            vm.startMintIfIdle(manager, b.minter, toState(half)))
        assertEquals(1, a.calls)
        assertEquals(0, b.calls)
        assertTrue(vm.mintState is MintState.Solving)
        assertFalse(a.abort!!.shouldAbort())
    }

    @Test
    fun aResultArrivingAfterEndSession_isDropped_andTheStateStaysReset() {
        val vm = session()
        val half = vm.resumeOrStartNewSession()
        val m = FakeMint()
        vm.startMintIfIdle(Any(), m.minter, toState(half))
        vm.step = AddStep.Show
        vm.endSession()
        assertTrue("endSession sets the running mint's own flag", m.abort!!.shouldAbort())

        m.result.complete(pair("late"))
        assertEquals(MintState.WaitingForRelay, vm.mintState)
        assertEquals(AddStep.Choice, vm.step)
        assertFalse(vm.isActive)
    }

    @Test
    fun theOldSessionsAbortFlagStaysSet_afterANewSessionStartsAMint() {
        val vm = session()
        val oldHalf = vm.resumeOrStartNewSession()
        val old = FakeMint()
        vm.startMintIfIdle(Any(), old.minter, toState(oldHalf))
        val oldFlag = vm.runningMintAbortFlag
        assertNotNull(oldFlag)
        vm.endSession()

        // Same nav entry, vault back: a new session in the same ViewModel.
        val newHalf = vm.resumeOrStartNewSession()
        val fresh = FakeMint()
        assertTrue(vm.startMintIfIdle(Any(), fresh.minter, toState(newHalf)))
        assertNotSame("each mint gets its own flag", oldFlag, vm.runningMintAbortFlag)
        assertTrue("the old grind must stay aborted", old.abort!!.shouldAbort())
        assertFalse(fresh.abort!!.shouldAbort())

        // The old grind finishing anyway must not land in the new session.
        old.result.complete(pair("old"))
        assertTrue(vm.mintState is MintState.Solving)
        fresh.result.complete(pair("new"))
        assertEquals("new-main", (vm.mintState as MintState.Ready).minted.inboxId)
    }

    @Test
    fun aManagerChangeDuringARunningMint_abortsIt_andRestartsWithTheSameHalf() {
        val vm = session()
        val half = vm.resumeOrStartNewSession()
        val dead = Any()
        val live = Any()
        val a = FakeMint()
        val b = FakeMint()
        vm.startMintIfIdle(dead, a.minter, toState(half))

        assertTrue("a different manager restarts the mint",
            vm.startMintIfIdle(live, b.minter, toState(half)))
        assertTrue("the superseded mint is aborted", a.abort!!.shouldAbort())
        assertFalse(b.abort!!.shouldAbort())
        assertSame("the secret half is untouched", half, vm.resumeOrStartNewSession())

        a.result.complete(pair("dead"))
        assertTrue("the superseded result is dropped", vm.mintState is MintState.Solving)
        b.result.complete(pair("live"))
        val ready = vm.mintState as MintState.Ready
        assertEquals("live-main", ready.minted.inboxId)
        assertSame("Ready carries the same half", half, ready.mySecret)
    }

    @Test
    fun theManagerGoingAway_parksARunningMint() {
        val vm = session()
        val half = vm.resumeOrStartNewSession()
        val owner = Any()
        val m = FakeMint()
        vm.startMintIfIdle(owner, m.minter, toState(half))

        vm.abandonMintIfTransportChanged(owner)
        assertTrue("same manager: nothing changes", vm.mintState is MintState.Solving)

        vm.abandonMintIfTransportChanged(null)
        assertEquals(MintState.WaitingForRelay, vm.mintState)
        assertTrue(m.abort!!.shouldAbort())
        m.result.complete(pair("late"))
        assertEquals(MintState.WaitingForRelay, vm.mintState)
    }

    @Test
    fun aReadyMintIsKeptAcrossAManagerChange() {
        val vm = session()
        val half = vm.resumeOrStartNewSession()
        val a = FakeMint()
        vm.startMintIfIdle(Any(), a.minter, toState(half))
        a.result.complete(pair("saved"))
        val ready = vm.mintState as MintState.Ready

        val b = FakeMint()
        assertFalse(vm.startMintIfIdle(Any(), b.minter, toState(half)))
        vm.abandonMintIfTransportChanged(null)
        vm.abandonMintIfTransportChanged(Any())
        assertEquals("a Ready mint is never replaced", 0, b.calls)
        assertSame(ready, vm.mintState)
    }

    /** Source pin: a Tor drop no longer resets a Ready mint (it used to). */
    @Test
    fun theScreenNoLongerResetsAReadyMintOnATorDrop() {
        val screen = SourcePins.stripped(SourcePins.ADD_CONTACT_SCREEN)
        assertFalse(
            "a bare `!is Solving` reset would throw away a Ready mint on every Tor drop",
            screen.contains("if (mintState !is MintState.Solving) mintState = MintState.WaitingForRelay"),
        )
        assertEquals(
            2,
            Regex("""mintState !is MintState\.Solving && mintState !is MintState\.Ready""")
                .findAll(screen).count(),
        )
        assertTrue(
            "the screen must re-check the transport under a running mint",
            screen.contains("session.abandonMintIfTransportChanged(null)") &&
                screen.contains("session.startMintIfIdle(current, toMintState)"),
        )
    }
}
