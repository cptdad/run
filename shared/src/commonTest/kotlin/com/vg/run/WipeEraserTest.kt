package com.vg.run

import com.vg.run.FakeWipeKeyStore.Companion.absent
import com.vg.run.FakeWipeKeyStore.Companion.boom
import com.vg.run.FakeWipeKeyStore.Companion.fail
import com.vg.run.FakeWipeKeyStore.Companion.ok
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * RÚN-02: [WipeEraser] — every deletion of a wipe reports DELETED, ALREADY_ABSENT or
 * UNRESOLVED; independent cleanup goes on when one item fails; crypto-erase-first
 * order is kept; absence is trusted only while protected data is available; retries
 * touch only what is still unresolved; a report is complete only when nothing is.
 */
class WipeEraserTest {

    private val all = listOf(
        WipeItem.DEVICE_KEY, WipeItem.HARDWARE_KEY, WipeItem.KV_SWEEP, WipeItem.BLOCK_LIST, WipeItem.VAULT_FILES,
    )

    @BeforeTest fun reset() = WipeEraseLatch.resetForTest()
    @AfterTest fun tearDown() = WipeEraseLatch.resetForTest()

    @Test
    fun everyItemIsAttemptedInCryptoEraseFirstOrder_completeOnlyWhenNothingIsUnresolved() {
        val variants = listOf(ok() to true, absent() to true, fail() to false, boom() to false)
        for (item in all) for ((step, resolves) in variants) {
            val store = FakeWipeKeyStore()
            store.script(item, step)
            val report = WipeEraser.run(store, all, passes = 1)
            assertEquals(all, store.calls, "$item/$step: every item once, in order")
            assertEquals(resolves, report.complete, "$item/$step: complete ⇔ nothing unresolved")
            assertEquals(if (resolves) emptySet() else setOf(item), report.unresolved)
        }
    }

    @Test
    fun deviceKeyHardwareKeyAndSweep_answerIndependently() {
        // Every combination of success / absence / error over the three items the
        // ticket names. The report must name exactly the failing ones.
        val steps = listOf(ok(), absent(), fail())
        for (dk in steps) for (hk in steps) for (kv in steps) {
            val store = FakeWipeKeyStore()
            store.script(WipeItem.DEVICE_KEY, dk)
            store.script(WipeItem.HARDWARE_KEY, hk)
            store.script(WipeItem.KV_SWEEP, kv)
            val report = WipeEraser.run(store, all, passes = 1)
            val expected = buildSet {
                if (dk == fail()) add(WipeItem.DEVICE_KEY)
                if (hk == fail()) add(WipeItem.HARDWARE_KEY)
                if (kv == fail()) add(WipeItem.KV_SWEEP)
            }
            assertEquals(expected, report.unresolved, "dk=$dk hk=$hk kv=$kv")
            assertEquals(all, store.calls, "a failure never short-circuits the rest")
            assertEquals(dk, FakeWipeKeyStore.Step.Answer(report.results.getValue(WipeItem.DEVICE_KEY)))
        }
    }

    @Test
    fun aDeviceKeyFailure_stillAttemptsTheRest_inOrder() {
        val store = FakeWipeKeyStore()
        store.script(WipeItem.DEVICE_KEY, fail())
        val report = WipeEraser.run(store, all, passes = 1)
        assertEquals(all, store.calls)
        assertEquals(setOf(WipeItem.DEVICE_KEY), report.unresolved)
        assertEquals(EraseOutcome.DELETED, report.results.getValue(WipeItem.VAULT_FILES).outcome)
    }

    @Test
    fun aThrowingAdapter_isUnresolved_andNeverPropagates() {
        val store = FakeWipeKeyStore()
        for (item in all) store.script(item, boom())
        val report = WipeEraser.run(store, all, passes = 1)
        assertEquals(all.toSet(), report.unresolved)
        assertEquals(EraseResult.STATUS_EXCEPTION, report.results.getValue(WipeItem.DEVICE_KEY).status)
    }

    @Test
    fun absenceWhileProtectedDataIsUnavailable_isNeverTrusted() {
        val store = FakeWipeKeyStore(protectedData = false)
        store.script(WipeItem.DEVICE_KEY, absent())
        store.script(WipeItem.HARDWARE_KEY, ok())
        store.script(WipeItem.KV_SWEEP, ok())
        store.script(WipeItem.VAULT_FILES, absent())
        val report = WipeEraser.run(store, all, passes = 1)
        assertTrue(WipeItem.DEVICE_KEY in report.unresolved, "'already absent' under a locked keybag can be a lie")
        assertTrue(WipeItem.VAULT_FILES in report.unresolved)
        assertTrue(WipeItem.KV_SWEEP in report.unresolved, "a bulk sweep's 'verified empty' cannot be trusted while locked")
        assertFalse(WipeItem.HARDWARE_KEY in report.unresolved, "a single-item delete that SUCCEEDED is positive evidence")
        assertFalse(report.complete, "no premature completion under a locked keybag")

        store.protectedData = true
        val retried = WipeEraser.retryUnresolved(store, report)
        assertTrue(retried.complete, "the same answers are trusted once protected data is available")
    }

    @Test
    fun immediatePasses_reAttemptOnlyTheUnresolved_andStopAtTheBudget() {
        val store = FakeWipeKeyStore()
        store.script(WipeItem.HARDWARE_KEY, fail())   // fails forever
        val report = WipeEraser.run(store, all)
        assertEquals(WipeEraser.IMMEDIATE_PASSES, store.callsFor(WipeItem.HARDWARE_KEY))
        assertEquals(1, store.callsFor(WipeItem.DEVICE_KEY), "a resolved item is never touched again")
        assertEquals(setOf(WipeItem.HARDWARE_KEY), report.unresolved)
    }

    @Test
    fun retry_touchesOnlyTheUnresolved_andACompleteReportCostsNothing() {
        val store = FakeWipeKeyStore()
        store.script(WipeItem.KV_SWEEP, fail(), ok())
        val first = WipeEraser.run(store, all, passes = 1)
        assertEquals(setOf(WipeItem.KV_SWEEP), first.unresolved)
        store.calls.clear()

        val second = WipeEraser.retryUnresolved(store, first)
        assertEquals(listOf(WipeItem.KV_SWEEP), store.calls, "only the unresolved item is retried")
        assertTrue(second.complete)
        assertEquals(EraseOutcome.DELETED, second.results.getValue(WipeItem.DEVICE_KEY).outcome, "earlier results kept")
        store.calls.clear()

        val third = WipeEraser.retryUnresolved(store, second)
        assertTrue(store.calls.isEmpty(), "idempotent: a complete report makes zero calls")
        assertTrue(third.complete)
    }

    @Test
    fun failFailThenSuccess_staysIncompleteUntilTheStoreResolves() {
        val store = FakeWipeKeyStore()
        store.script(WipeItem.DEVICE_KEY, fail(), fail(), fail(), fail(), ok())
        var report = WipeEraser.run(store, all)   // three passes: three failures
        assertFalse(report.complete)
        report = WipeEraser.retryUnresolved(store, report)   // fourth failure
        assertFalse(report.complete, "no premature completion")
        report = WipeEraser.retryUnresolved(store, report)   // success
        assertTrue(report.complete)
    }

    @Test
    fun anEmptyReport_isNotComplete() {
        // A report must prove something: no item attempted is not "all erased".
        assertFalse(WipeEraseReport(emptyMap()).complete)
    }

    @Test
    fun merge_laterResultsWin_andSummaryCarriesNumbersOnly() {
        val a = WipeEraseReport(mapOf(WipeItem.DEVICE_KEY to EraseResult(EraseOutcome.UNRESOLVED, -25308)))
        val b = WipeEraseReport(mapOf(WipeItem.DEVICE_KEY to EraseResult(EraseOutcome.DELETED, 0)))
        val merged = a.merge(b)
        assertTrue(merged.complete)
        assertEquals("DEVICE_KEY=DELETED(0)", merged.summary())
        assertEquals("DEVICE_KEY=UNRESOLVED(-25308)", a.summary())
    }

    @Test
    fun aliasDeleteOutcome_needsAReadBackProvingTheAliasGone() {
        assertEquals(EraseOutcome.DELETED, WipeErasePolicy.aliasDeleteOutcome(everPresent = true, goneAfter = true))
        assertEquals(EraseOutcome.ALREADY_ABSENT, WipeErasePolicy.aliasDeleteOutcome(everPresent = false, goneAfter = true))
        assertEquals(EraseOutcome.UNRESOLVED, WipeErasePolicy.aliasDeleteOutcome(everPresent = true, goneAfter = false))
        assertEquals(EraseOutcome.UNRESOLVED, WipeErasePolicy.aliasDeleteOutcome(everPresent = false, goneAfter = null))
        assertEquals(EraseOutcome.UNRESOLVED, WipeErasePolicy.aliasDeleteOutcome(everPresent = true, goneAfter = null))
    }
}
