package com.vg.run

// ---------------------------------------------------------------------------
// "Screenshot taken" notice — the protocol-level courtesy signal a client sends
// after capturing a conversation.
//
// Shape and pathway are deliberately the EXISTING control-notice ones, not a
// parallel mechanism:
//
//   • 1:1   — a body-less DIRECT control message on the control channel
//             (MessageManager.CONTROL_KIND_SCREENSHOT), the same envelope the
//             referral handshake and the in-band inbox announce use.
//   • Group — a body-less GROUP control message fanned out per member exactly
//             like GroupManager.KIND_ACTIVITY, with the same shuffle + jitter
//             discipline and the same "sender must be a current, resolved
//             member" trust rule on receive.
//
// Both therefore inherit, unchanged: the AES-GCM/ratchet envelope, the
// per-contact monotonic counter + epoch anti-replay, the "ch" channel tag and
// "di" destination-inbox binding, and the power-of-two padding buckets. Nothing
// here adds a wire rule of its own — the persistence below is purely local
// RECEIVER semantics, so a new sender and an old receiver still interoperate
// (the old receiver just keeps the pre-2026-08-21 burn-on-read behaviour).
//
// PERSISTED for 24 h — this is NOT ephemeral any more (design
// docs/screenshot-notice-persistence-design.md §0). It used to live only in RAM,
// which meant the notice was lost forever unless the receiver happened to have
// that exact conversation open at the instant the DESTRUCTIVE background control
// sweep drained it — and both platforms tear the session down (and scrub those
// buffers) on every backgrounding. In production that condition is almost never
// met, so the feature effectively never reached the peer. A notice is now written
// to ONE `_meta` row on receipt (ScreenshotNoticeStore, `ssn:` namespace) and
// rendered for 24 h. Consequences that are load-bearing:
//
//   • It IS the first conversation-derived residue in the vault: a bounded set of
//     (conversationId, senderContactId, two timestamps) rows, ≤ 16 per
//     conversation, self-expiring after 24 h. No alias, no text, no wire bytes.
//   • It therefore has to be PURGED like every other per-contact/per-group `_meta`
//     class: isScreenshotNoticeResidueForContact / …ForGroup (ContactMetaPurge.kt,
//     beside GroupMetaKeys) are iterated by DatabaseManager.deleteContact/
//     deleteGroup, IosVaultDatabase.deleteContact/deleteGroup and the commonTest
//     InMemoryVault. It is deliberately NOT in ratchetMetaKeysForContact — that is
//     an EXACT-KEY list and these keys carry a variable receivedAt suffix.
//   • The RAM buffers (GroupManager.pendingScreenshotNotices,
//     MessageManager.pendingScreenshotNotices) still exist and are still dropped
//     on lock/wipe by scrubInMemory — they are now just the "arrived while you are
//     looking at it" fast path on top of the durable row.
//
// NO NOTIFICATION, unchanged: the notice is sent with X-No-Push, so it never
// wakes the peer's device and never raises a banner. Persisting it does not make
// it a message; it is a row the conversation renders when it is next opened.
//
// ATTRIBUTION is the pairwise channel, as everywhere else in this protocol:
// successful AEAD decryption under contact X's secret IS the proof it came from
// X. The notice carries no sender field a peer could forge.
//
// TWO TIMESTAMPS, and the split is the security property:
//
//   • receivedAt — OUR clock at receive. Authoritative for ORDERING and EXPIRY,
//     because it is the only one an attacker cannot touch. Expiry is anchored
//     here and NOT on the capture time: a sender-anchored expiry would let the
//     screenshotter backdate the envelope's "t" and make their own notice vanish
//     a minute after it landed.
//   • timestamp — the DISPLAY time, i.e. the sender's minute-rounded capture time
//     when it falls inside a sane window, else receivedAt (see
//     ScreenshotNoticeStore.clampTakenAt). Exactly the trust a received text
//     bubble already places in the peer's clock (ReceivedMessage.timestamp =
//     env.timestamp) — display only, never an input to expiry, ordering, unread
//     or any wipe/lock decision.
// ---------------------------------------------------------------------------

/**
 * One received "the other side took a screenshot" notice, ready for a
 * conversation UI to render as a non-message notice.
 *
 * @property conversationId the contactId for a 1:1 notice, the groupId for a
 *   group notice — i.e. the id of the conversation the UI should render it in.
 * @property isGroup true when [conversationId] is a groupId.
 * @property senderContactId the pairwise contact whose channel authenticated it.
 * @property senderAlias that contact's current alias, resolved at read time
 *   (never carried on the wire, never persisted).
 * @property timestamp the DISPLAY time — the sender's claimed, minute-rounded
 *   capture time when it is inside the accepted window, otherwise [receivedAt].
 *   Never used for expiry or ordering.
 * @property receivedAt LOCAL wall-clock ms at which this device received it —
 *   the ordering key and the expiry anchor.
 * @property expiresAt `receivedAt + SCREENSHOT_NOTICE_TTL_MS`; the UI drops a row
 *   whose [expiresAt] has passed without needing a vault read per poll tick.
 */
data class ScreenshotNotice(
    val conversationId: String,
    val isGroup: Boolean,
    val senderContactId: String,
    val senderAlias: String,
    val timestamp: Long,
    val receivedAt: Long = timestamp,
    val expiresAt: Long = receivedAt + SCREENSHOT_NOTICE_TTL_MS,
)

/**
 * A 1:1 notice as the TRANSPORT records it: contactId + local receive time +
 * the sender's CLAIMED capture time lifted verbatim from the envelope's "t",
 * and nothing else. The alias is resolved later, by the conversation layer, from
 * the vault — so MessageManager never holds a peer alias in RAM for this feature,
 * and [claimedTakenAt] is passed through UNVALIDATED (the clamp lives in
 * ScreenshotNoticeStore, one place for both the 1:1 and the group path).
 */
internal data class DirectScreenshotNotice(
    val contactId: String,
    val receivedAt: Long,
    val claimedTakenAt: Long,
)
