package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// The early-NEWNYM session budget both platforms share ([EarlyNewnymLedger]).
class EarlyNewnymLedgerTest {

    @Test
    fun startsEmpty_withBudget() {
        val l = EarlyNewnymLedger()
        assertEquals(0, l.firedThisSession)
        assertEquals(0, l.coldFiresThisSession)
        assertTrue(l.hasBudget)
    }

    @Test
    fun aColdFireCountsBoth_anOtherFireOnlyTheCap() {
        val l = EarlyNewnymLedger()
        assertEquals(1, l.noteFired(cold = true))
        assertEquals(1, l.coldFiresThisSession)
        assertEquals(2, l.noteFired())
        assertEquals(2, l.firedThisSession)
        assertEquals(1, l.coldFiresThisSession)
    }

    @Test
    fun exhaust_spendsTheWholeCap() {
        val l = EarlyNewnymLedger()
        l.exhaust()
        assertFalse(l.hasBudget)
        assertEquals("NEWNYM ${MessageManager.EARLY_NEWNYM_MAX_FIRES}/${MessageManager.EARLY_NEWNYM_MAX_FIRES}", l.phrase())
    }

    @Test
    fun reset_startsTheSessionOver() {
        val l = EarlyNewnymLedger()
        l.noteFired(cold = true)
        l.exhaust()
        l.reset()
        assertEquals(0, l.firedThisSession)
        assertEquals(0, l.coldFiresThisSession)
        assertTrue(l.hasBudget)
    }

    @Test
    fun phrase_isTheSharedNewnymCountShape() {
        val l = EarlyNewnymLedger()
        l.noteFired()
        assertEquals("NEWNYM 1/${MessageManager.EARLY_NEWNYM_MAX_FIRES}", l.phrase())
    }
}
