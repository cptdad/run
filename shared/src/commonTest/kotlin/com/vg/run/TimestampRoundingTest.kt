package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class TimestampRoundingTest {

    @Test
    fun rounds_zero_unchanged() {
        assertEquals(0L, roundTimestampToMinute(0L))
    }

    @Test
    fun rounds_to_floor_of_minute() {
        assertEquals(60_000L, roundTimestampToMinute(60_000L))
        assertEquals(60_000L, roundTimestampToMinute(60_001L))
        assertEquals(60_000L, roundTimestampToMinute(119_999L))
        assertEquals(120_000L, roundTimestampToMinute(120_000L))
    }

    @Test
    fun strips_sub_minute_components() {
        val now = 1_713_364_823_456L
        val rounded = roundTimestampToMinute(now)
        assertEquals(0L, rounded % 60_000L)
        assertTrue(rounded <= now)
        assertTrue(now - rounded < 60_000L)
    }

    @Test
    fun two_timestamps_within_same_minute_collide() {
        val a = 1_713_364_800_001L
        val b = 1_713_364_859_999L
        assertEquals(roundTimestampToMinute(a), roundTimestampToMinute(b))
    }

    @Test
    fun two_timestamps_in_adjacent_minutes_differ() {
        val a = 1_713_364_859_999L
        val b = 1_713_364_860_000L
        assertEquals(60_000L, roundTimestampToMinute(b) - roundTimestampToMinute(a))
    }

    @Test
    fun parseTopLevelJson_readsScalarsAndTypes() {
        val o = parseTopLevelJson("""{"e":"abc","c":7,"t":60000,"m":"hi"}""")
        assertEquals("abc", o["e"]?.text); assertTrue(o["e"]?.isString == true)
        assertEquals("7", o["c"]?.text); assertTrue(o["c"]?.isString == false)
        assertEquals("60000", o["t"]?.text)
        assertEquals("hi", o["m"]?.text)
        assertNull(o["z"])                       // absent
    }

    @Test
    fun parseTopLevelJson_ignoresKeyEmbeddedInStringValue_decoyInsideStringValue() {
        // A malicious peer puts a decoy "c":999 inside the FIRST string value,
        // before the real top-level "c". Depth-1 parsing must surface only the
        // real top-level c (5), never the embedded decoy.
        val o = parseTopLevelJson("""{"m":"\"c\":999 hi","c":5}""")
        assertEquals(""""c":999 hi""", o["m"]?.text)   // m value unescaped, intact
        assertEquals("5", o["c"]?.text)                 // the REAL c, not 999
    }

    @Test
    fun parseTopLevelJson_ignoresKeysInNestedObject() {
        // A nested object value is skipped wholesale; its inner keys are not
        // surfaced, and the value itself is not exposed (envelope "b" is always
        // a quoted string in practice).
        val o = parseTopLevelJson("""{"b":{"c":999,"n":"x"},"c":5}""")
        assertNull(o["b"])             // nested object not surfaced as a scalar
        assertEquals("5", o["c"]?.text) // nested c:999 ignored; real c read
    }
}
