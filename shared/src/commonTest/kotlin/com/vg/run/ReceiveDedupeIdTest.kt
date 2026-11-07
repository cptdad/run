package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Ratchet and legacy receive ids must not collide. */
class ReceiveDedupeIdTest {
    @Test
    fun ratchetAndLegacyIds_forTheSameCounter_neverCollide() {
        // On a fresh pairing both the legacy sender counter and the ratchet receive
        // counter start at 1; without namespacing the ratchet's first message keyed to
        // the same "rx-1" as the legacy bootstrap message and was silently dropped.
        for (n in 1..5L) {
            assertEquals("rx-$n", receiveDedupeId(ratchet = false, counter = n))
            assertEquals("dr-$n", receiveDedupeId(ratchet = true, counter = n))
            assertTrue(
                receiveDedupeId(ratchet = false, counter = n) != receiveDedupeId(ratchet = true, counter = n),
                "legacy and ratchet ids for counter $n must differ (T1)",
            )
        }
    }
}
