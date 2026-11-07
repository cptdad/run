package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals

// The redactor ladder's EXECUTION order is load-bearing (DebugLogRedactor's
// LADDER comment lists why each pass precedes the next). Pinned here so a
// reorder is a deliberate, reviewed change rather than a silent one.
class DebugLogRedactorLadderOrderTest {

    @Test
    fun theLadderRunsInItsDocumentedOrder() {
        assertEquals(
            listOf("1a", "1b", "1c", "2", "3a", "3b", "3c", "3+4ab", "4c", "5", "7", "6"),
            DebugLogRedactor.LADDER.map { it.rule },
        )
    }

    @Test
    fun redactMessageIsExactlyTheFoldOfTheLadder() {
        val samples = listOf(
            "GET https://abc.onion/inbox/AbCdEfGh01234567 → 200",
            "peer 10.0.0.1:9001 said \"hello\" to contactId=aBcDeFgH",
            "sending 3072b to inbox aBcDeFgH... (17 contacts)",
        )
        for (s in samples) {
            var manual = s
            for (pass in DebugLogRedactor.LADDER) manual = pass.apply(manual)
            assertEquals(manual, DebugLogRedactor.redactMessage(s), s)
        }
    }
}
