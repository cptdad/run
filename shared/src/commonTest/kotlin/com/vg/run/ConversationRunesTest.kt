package com.vg.run

import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Locks the shared conversation-status vocabulary + rules that all four conversation
 * screens (1:1/group × Android/iOS) now consume, so the 1:1↔group drift class
 * (the group scroll-gate drift, iOS whisper guard-drifts) can't re-open.
 *
 * LOCALIZATION: CONSULTING/WHISPER/etc. are now resource-key TOKENS (runes_* in
 * strings_shared.xml), not display text — [ConversationRunes.label] resolves a
 * token to text at render time. The equality/verdict/fade-rule tests below assert
 * on the TOKENS (what the render sites actually compare/store); the English-copy
 * lock installs a small platformStringOverride English map.
 */
class ConversationRunesTest {

    @AfterTest
    fun tearDown() {
        platformStringOverride = null
    }

    @Test
    fun verdict_reflectsWhetherMessagesArePresent() {
        assertEquals(ConversationRunes.WHISPER, ConversationRunes.verdict(hasMessages = true))
        assertEquals(ConversationRunes.SILENT, ConversationRunes.verdict(hasMessages = false))
    }

    @Test
    fun isTransientVerdict_coversEveryAutoFadingNotice_andNotThePersistentOnes() {
        // Auto-fade (the verdict).
        assertTrue(ConversationRunes.isTransientVerdict(ConversationRunes.WHISPER))
        assertTrue(ConversationRunes.isTransientVerdict(ConversationRunes.SILENT))
        // Persistent states must NOT auto-fade.
        assertFalse(ConversationRunes.isTransientVerdict(ConversationRunes.CONSULTING))
        assertFalse(ConversationRunes.isTransientVerdict(null))
    }

    @Test
    fun shouldAutoScrollToLatest_onlyWhenANewMessageWasAppendedToANonEmptyList() {
        // The auto-scroll rule: a relay re-serve (appendedNew = false) must NOT scroll,
        // even though the list is non-empty.
        assertFalse(ConversationRunes.shouldAutoScrollToLatest(appendedNew = false, hasMessages = true))
        assertFalse(ConversationRunes.shouldAutoScrollToLatest(appendedNew = true, hasMessages = false))
        assertFalse(ConversationRunes.shouldAutoScrollToLatest(appendedNew = false, hasMessages = false))
        assertTrue(ConversationRunes.shouldAutoScrollToLatest(appendedNew = true, hasMessages = true))
    }

    @Test
    fun shouldAutoScrollToLatest_asDrivenByTheMessageCountDelta() {
        // CONV-1: both Android screens now call the gate from an effect keyed on the
        // message COUNT (never from inside the poll loop, where a scroll cancelled by a
        // competing scroll would kill the drain), so `appendedNew` is the count delta.
        // Pin that mapping — it must stay equivalent to the rule above.
        fun scrolls(prevCount: Int, count: Int): Boolean =
            ConversationRunes.shouldAutoScrollToLatest(count > prevCount, count > 0)

        assertTrue(scrolls(0, 1))    // first message lands
        assertTrue(scrolls(2, 3))    // another append (sent or received)
        assertFalse(scrolls(3, 3))   // relay re-serve: deduped, count unchanged → no scroll
        assertFalse(scrolls(3, 2))   // a message was deleted → no scroll
        assertFalse(scrolls(0, 0))   // nothing to scroll to
    }

    @Test
    fun vocabulary_tokens_areStable() {
        // The tokens themselves are what render sites compare/store (equality,
        // LaunchedEffect keys, SwiftUI .id()) — pin them so a key rename can't
        // silently break that comparison across the four screens.
        assertEquals("runes_consulting", ConversationRunes.CONSULTING)
        assertEquals("runes_whisper", ConversationRunes.WHISPER)
        assertEquals("runes_silent", ConversationRunes.SILENT)
    }

    @Test
    fun label_resolvesTokensToEnglishCopy() {
        // The real English text now lives only in strings_shared.xml (locked
        // separately by a JVM resources test); here we install it via the test
        // seam and confirm `label` is the one true resolution path.
        platformStringOverride = { key, _ ->
            when (key) {
                "runes_consulting" -> "Consulting the runes…"
                "runes_whisper" -> "The runes whisper"
                "runes_silent" -> "The runes are silent"
                else -> key
            }
        }
        assertEquals("Consulting the runes…", ConversationRunes.label(ConversationRunes.CONSULTING))
        assertEquals("The runes whisper", ConversationRunes.label(ConversationRunes.WHISPER))
        assertEquals("The runes are silent", ConversationRunes.label(ConversationRunes.SILENT))
    }
}
