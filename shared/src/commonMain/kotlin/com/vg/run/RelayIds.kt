package com.vg.run

// ---------------------------------------------------------------------------
// Shape checks for relay-minted identifiers (inbox ids, capabilities, blob ids /
// lease tokens) and the locally generated group id. Pure; must stay in lock-step
// with the relay's formats. (Moved verbatim out of MessageManager.kt, 2026-11-06.)
// ---------------------------------------------------------------------------

/**
 * Inbox IDs are base64url-no-pad of 24 random bytes server-side — always
 * exactly 32 characters from `[A-Za-z0-9_-]`. The OLD format (canonical
 * hex UUIDs) is no longer valid; any record carrying a UUID-shaped ID is
 * from a pre-migration peering and must be re-paired.
 */
private val INBOX_ID_REGEX = Regex("^[A-Za-z0-9_\\-]{32}$")

/**
 * Validates that the given string is a syntactically well-formed inbox ID
 * for the new (capability) protocol. Used at QR/paste parse time to reject
 * malformed peer codes before they are stored — the same check is enforced
 * at every relay-call site, so an unvalidated value would brick the contact
 * entry on first send/poll.
 *
 * Migration note: an inbox ID that matches the OLD UUID format
 * `[0-9a-fA-F]{8}-…` will fail this regex and the calling code path should
 * surface a "re-pair required" UX rather than attempt a doomed send.
 */
fun isValidInboxId(s: String): Boolean = INBOX_ID_REGEX.matches(s)

/**
 * Capabilities are base64url-no-pad of 32 random bytes server-side — always
 * exactly 43 characters from `[A-Za-z0-9_-]` (same alphabet as inbox IDs;
 * [MessageManager.rotateReadCap] mints its new cap in the same shape). Shape-checked when
 * parsing a mint response so a malformed/truncated relay reply can't seed a
 * contact with an unusable cap. Must stay in lock-step with the relay's cap
 * format.
 */
private val CAPABILITY_REGEX = Regex("^[A-Za-z0-9_\\-]{43}$")

/** True iff [s] is a syntactically well-formed capability token. */
fun isValidCapability(s: String): Boolean = CAPABILITY_REGEX.matches(s)

/**
 * Group IDs are locally generated as base64url-no-pad of 24 random bytes —
 * the same 32-char shape as inbox IDs, so the same regex applies. Validated
 * on receive so a hostile peer can't smuggle structure into vault rows or
 * logs through the group routing field.
 */
fun isValidGroupId(s: String): Boolean = isValidInboxId(s)

// Retrieve-ack: a relay-minted blob id or lease token — 16 random bytes,
// base64url without padding (22 chars). Untrusted relay input is checked against
// this BEFORE it can enter an ack body. (Moved out of MessageManager.kt.)
internal fun isValidBlobRef(s: String): Boolean =
    s.length == 22 && s.all { it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_' }
