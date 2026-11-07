package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals

/** `moveToFront` orders the control sweep: the awaited pairing peer first, everything else untouched. */
class MoveToFrontTest {
    @Test
    fun matchInTheMiddle_movesToIndexZero_restKeepsOrder() {
        val l = mutableListOf("a", "b", "c", "d")
        l.moveToFront { it == "c" }
        assertEquals(listOf("c", "a", "b", "d"), l)
    }

    @Test
    fun alreadyFirst_isANoOp() {
        val l = mutableListOf("a", "b", "c")
        l.moveToFront { it == "a" }
        assertEquals(listOf("a", "b", "c"), l)
    }

    @Test
    fun noMatch_isANoOp() {
        val l = mutableListOf("a", "b", "c")
        l.moveToFront { it == "zzz" }
        assertEquals(listOf("a", "b", "c"), l)
    }

    @Test
    fun emptyList_isANoOp() {
        val l = mutableListOf<String>()
        l.moveToFront { true }
        assertEquals(emptyList(), l)
    }
}
