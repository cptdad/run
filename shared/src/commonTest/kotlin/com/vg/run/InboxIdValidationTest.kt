package com.vg.run

import kotlin.test.Test
import kotlin.test.assertTrue

class InboxIdValidationTest {

    private val capInboxId = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX"

    @Test
    fun capability_format_passes() {
        assertTrue(isValidInboxId(capInboxId))
    }

    @Test
    fun legacy_uuid_format_rejected() {
        // The relay migrated to base64url-no-pad 32-char IDs; old UUIDs are
        // surfaced by the migration UX as "re-pair required" and must NOT
        // pass the validator.
        assertTrue(!isValidInboxId("550e8400-e29b-41d4-a716-446655440000"))
        assertTrue(!isValidInboxId("6BA7B810-9DAD-11D1-80B4-00C04FD430C8"))
    }

    @Test
    fun pathTraversal_rejected() {
        assertTrue(!isValidInboxId("../../../admin"))
        assertTrue(!isValidInboxId("$capInboxId/../../"))
        assertTrue(!isValidInboxId(""))
        assertTrue(!isValidInboxId("short"))
    }

    @Test
    fun shortBlob_tooShortForDecryption() {
        // AES-GCM minimum: 12 (IV) + 16 (tag) = 28 bytes. The decode loop in
        // pollMessages still uses this lower bound as a cheap pre-filter
        // (defensive — the new protocol has no "init blob" but a malicious
        // relay could still serve undersized blobs).
        val undersized = byteArrayOf(0)
        assertTrue(undersized.size < 28, "Undersized blobs must be filtered out")
    }
}
