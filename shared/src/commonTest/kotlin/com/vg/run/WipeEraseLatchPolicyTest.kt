package com.vg.run

import com.vg.run.FakeWipeKeyStore.Companion.fail
import com.vg.run.FakeWipeKeyStore.Companion.ok
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

private fun WipeErasePolicy.refusesEverything(): Boolean =
    !mayMintDeviceKey() && !mayProvision() && !mayReplayJournal() && !mayOpenVault()

/**
 * RÚN-02: while a wipe's erase is unresolved the old vault stays closed and NOTHING
 * may mint a device key, replay the iOS write journal or start a fresh setup — and
 * every one of those is allowed again the moment the erase resolves. Plus the two
 * cross-launch rules: the fresh-setup purge (R3) and the post-wipe residue (R2), each
 * firing only on positive evidence.
 */
class WipeEraseLatchPolicyTest {

    @BeforeTest fun reset() = WipeEraseLatch.resetForTest()
    @AfterTest fun tearDown() = WipeEraseLatch.resetForTest()

    private fun allowedEverywhere(): Boolean =
        WipeErasePolicy.mayMintDeviceKey() && WipeErasePolicy.mayProvision() &&
            WipeErasePolicy.mayReplayJournal() && WipeErasePolicy.mayOpenVault()

    private fun refusedEverywhere(): Boolean =
        !WipeErasePolicy.mayMintDeviceKey() && !WipeErasePolicy.mayProvision() &&
            !WipeErasePolicy.mayReplayJournal() && !WipeErasePolicy.mayOpenVault()

    @Test
    fun aFreshProcess_isUnlatched() {
        assertFalse(WipeEraseLatch.unresolved)
        assertTrue(allowedEverywhere())
        assertNull(WipeEraseLatch.lastReport())
    }

    @Test
    fun aWipeInFlight_alreadyRefusesEverything() {
        WipeEraseLatch.begin()
        assertTrue(WipeEraseLatch.unresolved, "armed before the first delete, like ProcessWipeLatch")
        assertTrue(refusedEverywhere())
    }

    @Test
    fun anUnresolvedErase_refusesMintProvisionReplayAndOpen_untilItResolves() {
        val store = FakeWipeKeyStore()
        store.script(WipeItem.DEVICE_KEY, fail(), fail(), fail(), ok())
        WipeEraseLatch.finish(WipeEraseLatch.begin(), WipeEraser.run(store, WipeEraser.KEY_ITEMS))
        assertTrue(WipeEraseLatch.unresolved)
        assertTrue(refusedEverywhere())

        var dropped = 0
        assertTrue(WipeEraseRetry.retryIfPending(store) { dropped++ }, "the retry resolves it")
        assertFalse(WipeEraseLatch.unresolved)
        assertTrue(allowedEverywhere())
        assertEquals(1, dropped, "a resolution drops every cached copy of the old key")
    }

    @Test
    fun aCompleteErase_leavesNothingLatched_andRetryIsANoOp() {
        val store = FakeWipeKeyStore()
        WipeEraseLatch.finish(WipeEraseLatch.begin(), WipeEraser.run(store, WipeEraser.KEY_ITEMS))
        assertTrue(allowedEverywhere())
        store.calls.clear()
        var dropped = 0
        assertTrue(WipeEraseRetry.retryIfPending(store) { dropped++ })
        assertTrue(store.calls.isEmpty(), "nothing to retry ⇒ no delete at all")
        assertEquals(0, dropped)
    }

    @Test
    fun retryWhileAWipeIsStillInFlight_doesNothing() {
        val store = FakeWipeKeyStore()
        WipeEraseLatch.begin()
        assertFalse(WipeEraseRetry.retryIfPending(store) {})
        assertTrue(store.calls.isEmpty(), "a retry never races the wipe that is running")
    }

    // -- R3: the purge at the start of a fresh setup -------------------------

    @Test
    fun residualKeyPurge_onlyOnAProvablyEmptyInstall() {
        assertTrue(WipeErasePolicy.residualKeyPurgeAllowed(credentialPair = false, vaultFileAbsentAllDirs = true, journalConfirmedAbsent = true))
        for ((pair, file, journal) in listOf(
            Triple(true, true, true),      // configured
            Triple(null, true, true),      // ambiguous read (fail-toward-true territory)
            Triple(false, false, true),    // a vault file exists (or a dir is unresolved)
            Triple(false, true, false),    // a journal may replay credentials
        )) {
            assertFalse(
                WipeErasePolicy.residualKeyPurgeAllowed(pair, file, journal),
                "pair=$pair file-absent=$file journal-absent=$journal must not purge",
            )
        }
    }

    @Test
    fun freshProvisionGate_purgesAndDropsTheCache_thenProceeds() {
        val store = FakeWipeKeyStore()
        var dropped = 0
        assertTrue(FreshProvisionGate.prepare(store, false, true, true) { dropped++ })
        assertEquals(WipeEraser.KEY_ITEMS, store.calls, "only the two keys, nothing else")
        assertEquals(1, dropped)
        assertFalse(WipeEraseLatch.unresolved)
    }

    @Test
    fun freshProvisionGate_withoutEvidence_purgesNothing_butStillProceeds() {
        val store = FakeWipeKeyStore()
        var dropped = 0
        assertTrue(FreshProvisionGate.prepare(store, null, true, true) { dropped++ }, "today's behaviour")
        assertTrue(store.calls.isEmpty(), "ambiguity never deletes")
        assertEquals(1, dropped, "the cached key is dropped anyway, so the provision seals under the PERSISTED key")
    }

    @Test
    fun freshProvisionGate_anUnresolvedPurge_refusesTheSetup_andLatches() {
        val store = FakeWipeKeyStore()
        store.script(WipeItem.DEVICE_KEY, fail())
        assertFalse(FreshProvisionGate.prepare(store, false, true, true) {})
        assertTrue(WipeEraseLatch.unresolved, "the retry machinery takes it from here")
        assertEquals(setOf(WipeItem.DEVICE_KEY), WipeEraseLatch.lastReport()!!.unresolved)
    }

    @Test
    fun freshProvisionGate_refusesWhileAnEraseIsUnresolved_withoutTouchingAnything() {
        val store = FakeWipeKeyStore()
        WipeEraseLatch.begin()
        assertFalse(FreshProvisionGate.prepare(store, false, true, true) {})
        assertTrue(store.calls.isEmpty())
    }

    @Test
    fun freshProvisionGate_onAnInstallThatNeverWiped_failsPlainly_withoutLatching() {
        // Every fresh setup runs the purge. A delete that merely cannot be confirmed
        // (-34018, a locking keybag) while NOTHING was deleted is no evidence of a
        // leftover: refuse this attempt, but leave no erase state behind.
        val store = FakeWipeKeyStore()
        store.script(WipeItem.DEVICE_KEY, fail(-34018))
        store.script(WipeItem.HARDWARE_KEY, FakeWipeKeyStore.absent())
        assertFalse(FreshProvisionGate.prepare(store, false, true, true) {})
        assertFalse(WipeEraseLatch.unresolved, "no erase latch on an install with no evidence of a wipe")
        assertNull(WipeEraseLatch.lastReport())
    }

    // -- ownership of the in-flight guard ------------------------------------

    @Test
    fun onlyTheWipeThatBeganClearsTheGuard() {
        val token = WipeEraseLatch.begin()
        val done = WipeEraseReport(mapOf(WipeItem.DEVICE_KEY to EraseResult(EraseOutcome.DELETED, 0)))
        assertFalse(WipeEraseLatch.recordOutcome(done), "a retry / purge may not record mid-wipe")
        assertTrue(WipeEraseLatch.unresolved)
        assertFalse(WipeEraseLatch.finish(token + 1, done), "a foreign token changes nothing")
        assertFalse(WipeEraseLatch.finish(WipeEraseLatch.NO_TOKEN, done))
        assertTrue(WipeEraseLatch.wipeInFlight)
        assertEquals(token, WipeEraseLatch.begin(), "a second begin JOINS the wipe in flight")
        assertTrue(WipeEraseLatch.finish(token, done))
        assertFalse(WipeEraseLatch.unresolved)
        assertFalse(WipeEraseLatch.finish(token, done), "a token is single-use")
    }

    @Test
    fun aRetryOverlappingANewWipe_neverDropsTheWipesGuard() {
        // The retry's erase call is where another wipe begins (the interleaving the
        // old record() would have lost): its outcome must be discarded.
        val unresolved = WipeEraseReport(mapOf(WipeItem.KV_SWEEP to EraseResult(EraseOutcome.UNRESOLVED, -25308)))
        WipeEraseLatch.finish(WipeEraseLatch.begin(), unresolved)
        var newWipe = WipeEraseLatch.NO_TOKEN
        val racing = object : WipeKeyStore {
            override fun protectedDataAvailable() = true
            override fun erase(item: WipeItem): EraseResult {
                newWipe = WipeEraseLatch.begin()
                return EraseResult(EraseOutcome.DELETED, 0)
            }
        }
        var dropped = 0
        assertFalse(WipeEraseRetry.retryIfPending(racing) { dropped++ })
        assertTrue(WipeEraseLatch.wipeInFlight, "the new wipe's guard survived the retry")
        assertTrue(WipeErasePolicy.refusesEverything())
        assertEquals(0, dropped)
        assertTrue(WipeEraseLatch.finish(newWipe, unresolved))
    }

    @Test
    fun aPurgeOverlappingAWipe_recordsNothing() {
        val token = WipeEraseLatch.begin()
        val store = FakeWipeKeyStore()
        store.script(WipeItem.DEVICE_KEY, fail())
        // The gate refuses outright while a wipe is in flight (no deletes at all).
        assertFalse(FreshProvisionGate.prepare(store, false, true, true) {})
        assertTrue(store.calls.isEmpty())
        assertTrue(WipeEraseLatch.finish(token, WipeEraseReport(mapOf(WipeItem.DEVICE_KEY to EraseResult(EraseOutcome.DELETED, 0)))))
    }

    // -- R2: leftover credentials with no vault file at launch ----------------

    @Test
    fun postWipeResidue_onlyForProvenCredentialsOverAMissingFile() {
        assertTrue(WipeErasePolicy.postWipeResidue(credentialPair = true, vaultFileAbsentAllDirs = true, journalConfirmedAbsent = true))
        assertFalse(WipeErasePolicy.postWipeResidue(true, false, true), "a healthy vault has its file — never")
        assertFalse(WipeErasePolicy.postWipeResidue(false, true, true), "a fresh install has no credentials — never")
        assertFalse(WipeErasePolicy.postWipeResidue(null, true, true), "an ambiguous read — never")
        assertFalse(WipeErasePolicy.postWipeResidue(true, true, false), "a pending journal — never")
    }
}
