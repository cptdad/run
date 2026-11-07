package com.vg.run

import kotlinx.coroutines.Job
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/** Runtime behaviour of the [SessionJobs] registry RunViewModel's teardowns rely on. */
class SessionJobsTest {

    private class Owner(jobs: SessionJobs) {
        var a: Job? by jobs.slot()
        var b: Job? by jobs.slot()
    }

    @Test
    fun slotsReadAndWriteLikePlainFields() {
        val jobs = SessionJobs()
        val owner = Owner(jobs)
        assertNull(owner.a)
        val j = Job()
        owner.a = j
        assertSame(j, owner.a)
        assertNull(owner.b)
        assertEquals(listOf("a", "b"), jobs.names)
    }

    @Test
    fun cancelAll_cancelsEverySlot_andIsIdempotent() {
        val jobs = SessionJobs()
        val owner = Owner(jobs)
        val a = Job()
        val b = Job()
        owner.a = a
        owner.b = b
        jobs.cancelAll()
        assertTrue(a.isCancelled)
        assertTrue(b.isCancelled)
        // The slot keeps the cancelled reference, as `x?.cancel()` on a field did.
        assertSame(a, owner.a)
        assertFalse(owner.a!!.isActive)
        jobs.cancelAll()
        assertTrue(a.isCancelled)
    }

    @Test
    fun cancelAll_skipsEmptySlots_andReachesAJobAssignedLater() {
        val jobs = SessionJobs()
        val owner = Owner(jobs)
        jobs.cancelAll()
        val late = Job()
        owner.b = late
        jobs.cancelAll()
        assertTrue(late.isCancelled)
    }

    @Test
    fun aJobOutsideTheRegistryIsNotCancelled() {
        val jobs = SessionJobs()
        val owner = Owner(jobs)
        owner.a = Job()
        val processScoped = Job()
        jobs.cancelAll()
        assertTrue(processScoped.isActive)
    }

    @Test(expected = IllegalStateException::class)
    fun aNameDeclaredTwiceIsRefused() {
        val jobs = SessionJobs()
        Owner(jobs)
        Owner(jobs)
    }
}
