package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// RollingWindow.admit is the arithmetic GroupManager.inviteAllowed and
// ReferralManager.offerAllowed share. The persisted string is a `_meta` value
// that existing vaults already hold, so its FORMAT is pinned byte for byte here:
// comma-joined stamps, input order kept, `now` appended on an allow only.
class RollingWindowTest {

    private val window = 3_600_000L

    @Test
    fun emptyOrAbsent_allowsAndRecordsNow() {
        assertEquals(RollingWindow.Admission(true, "1000"), RollingWindow.admit(null, 1000L, window, 8))
        assertEquals(RollingWindow.Admission(true, "1000"), RollingWindow.admit("", 1000L, window, 8))
    }

    @Test
    fun underTheCap_appendsNowAfterTheKeptStamps() {
        val a = RollingWindow.admit("10,20", 30L, window, 3)
        assertTrue(a.allowed)
        assertEquals("10,20,30", a.persist)
    }

    @Test
    fun atTheCap_deniesAndPersistsThePrunedListWithoutNow() {
        val now = window + 100L
        // 50 is out of the window, junk is dropped, the 3 in-window stamps fill the cap.
        val a = RollingWindow.admit("50,junk,200,300,400", now, window, 3)
        assertFalse(a.allowed)
        assertEquals("200,300,400", a.persist)
    }

    @Test
    fun aFutureStampIsDiscarded_soAClockStepBackCannotWedgeTheWindow() {
        val a = RollingWindow.admit("5000,6000,7000", 1000L, window, 3)
        assertTrue(a.allowed, "stamps in the future must not count toward the cap")
        assertEquals("1000", a.persist)
    }

    @Test
    fun theWindowEdgeIsInclusive() {
        val now = window + 10L
        val a = RollingWindow.admit("10", now, window, 1)
        assertFalse(a.allowed, "a stamp exactly windowMs old is still inside [now - windowMs, now]")
        assertEquals("10", a.persist)
    }

    @Test
    fun isSpent_isTrueExactlyWhenAdmitWouldIgnoreEveryStamp() {
        val now = 10_000_000L
        assertTrue(RollingWindow.isSpent(null, now, window))
        assertTrue(RollingWindow.isSpent("", now, window))
        assertTrue(RollingWindow.isSpent("${now - window - 1},junk", now, window), "every stamp aged out")
        assertTrue(RollingWindow.isSpent("${now + 5}", now, window), "a future stamp is ignored by admit too")
        assertFalse(RollingWindow.isSpent("${now - window - 1},${now - window}", now, window), "the window edge is live")
        assertFalse(RollingWindow.isSpent("$now", now, window))
        // Equivalence with admit: a spent row admits exactly like an absent one.
        for (row in listOf("${now - window - 1}", "${now + 5}", "x,${now - 2 * window}")) {
            assertTrue(RollingWindow.isSpent(row, now, window))
            assertEquals(RollingWindow.admit(null, now, window, 1), RollingWindow.admit(row, now, window, 1))
        }
    }
}
