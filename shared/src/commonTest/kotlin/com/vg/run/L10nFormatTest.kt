package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals

class L10nFormatTest {

    @Test
    fun plainStringPassesThrough() {
        assertEquals("Add contact", formatPositional("Add contact", emptyArray()))
    }

    @Test
    fun androidStyleStringAndIntPlaceholders() {
        assertEquals(
            "Alice may have taken a screenshot · 12:30",
            formatPositional("%1\$s may have taken a screenshot · %2\$s", arrayOf("Alice", "12:30")),
        )
        assertEquals("3 members", formatPositional("%1\$d members", arrayOf(3)))
    }

    @Test
    fun iosStylePlaceholders() {
        assertEquals("Hi Bob", formatPositional("Hi %1\$@", arrayOf("Bob")))
        assertEquals("7 entries", formatPositional("%1\$lld entries", arrayOf(7L)))
        assertEquals("7 entries", formatPositional("%1\$ld entries", arrayOf(7)))
    }

    @Test
    fun positionalReorderAndReuse() {
        assertEquals("b a b", formatPositional("%2\$s %1\$s %2\$s", arrayOf("a", "b")))
    }

    @Test
    fun literalPercentAndUnknownConversionsAreVerbatim() {
        assertEquals("100% done", formatPositional("100%% done", emptyArray()))
        assertEquals("45%", formatPositional("%1\$d%%", arrayOf(45)))
        assertEquals("%x %1\$q %", formatPositional("%x %1\$q %", arrayOf("z")))
    }

    @Test
    fun missingArgumentRendersEmptyNotThrow() {
        assertEquals("Hello ", formatPositional("Hello %1\$s", emptyArray()))
        assertEquals("Hello ", formatPositional("Hello %2\$s", arrayOf("only-one")))
    }

    @Test
    fun overrideSeamWinsOverPlatformResolver() {
        platformStringOverride = { key, args -> "[$key:${args.joinToString(",")}]" }
        try {
            assertEquals("[about_welcome_title:]", platformString("about_welcome_title"))
            assertEquals("[x:1,y]", platformString("x", 1, "y"))
        } finally {
            platformStringOverride = null
        }
    }

    @Test
    fun unknownKeyFailsSoftToKey() {
        // No resolver installed in commonTest → the key itself comes back (never a throw).
        assertEquals("definitely_unknown_key", platformString("definitely_unknown_key"))
    }
}
