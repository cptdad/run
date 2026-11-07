package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class MessageDisplayCapTest {
    @Test
    fun capMessageForDisplay_capsPathologicalText() {
        // A short message is unchanged.
        assertEquals("hello", MessageManager.capMessageForDisplay("hello"))
        // An over-long message is truncated to the cap + ellipsis, bounding the
        // conversation-UI layout cost on both platforms.
        val huge = "x".repeat(MessageManager.MAX_DISPLAY_MESSAGE_CHARS + 5_000)
        val capped = MessageManager.capMessageForDisplay(huge)
        assertEquals(MessageManager.MAX_DISPLAY_MESSAGE_CHARS + 1, capped.length)
        assertTrue(capped.endsWith("…"))
    }
}
