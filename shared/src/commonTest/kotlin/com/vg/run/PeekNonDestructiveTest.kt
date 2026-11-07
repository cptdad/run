package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals

// ---------------------------------------------------------------------------
// Regression guard for the iOS push-wake message-loss bug.
//
// The Tier-2 push wake (AppState.handleRemotePushWake) must decide whether to
// post a contentless "Notification" notification WITHOUT consuming the waiting
// message: texts are held in memory only, so a wake that DRAINED an inbox just
// to test "is anything here?" destroyed the message before its conversation was
// ever opened (the reported one-directional "silent drop"). The fix routes that
// decision through peekInbox (GET /inbox/{id}/peek), which the relay serves
// non-destructively. This test pins that property at the client boundary: a peek
// leaves the blob on the relay for the conversation poll to drain + display, and
// only a genuine retrieve consumes it. If peekInbox ever regressed to a draining
// GET, this would go red. (Android has no on-device background poll of its own
// anymore — notifications are FCM-only, matching iOS — so this is now the sole
// guard on peekInbox's non-destructive contract.)
// ---------------------------------------------------------------------------

/** Relay double that models the real drain semantics: `GET .../{id}/peek` is
 *  non-destructive and reports the queue depth; `GET .../{id}` (retrieve) drains. */
private class DrainAwareRelay : InboxQueueRelay(
    peek = true,
    postReply = HttpResult(code = 200, body = """{"ok":true}""", isSuccess = true),
    putReply = HttpResult(code = -1, body = "unused", isSuccess = false),
)

class PeekNonDestructiveTest {

    private val CID = "peer"
    private val INBOUND = "A".repeat(32)   // receiver's inbound text inbox
    private val CAP = "A".repeat(43)       // any header-valid read capability

    @Test
    fun peekInbox_isNonDestructive_soThePushWakeCannotEatTheMessage() {
        val relay = DrainAwareRelay()
        val vault = InMemoryVault()
        vault.insertContact(ContactRecord(CID, generateSecureRandom(32), 1, "T", 0L))
        vault.insertInboxId(InboxIdRecord(INBOUND, CID, 1L, Long.MAX_VALUE, "inbound", CAP))
        val mm = MessageManager(vault, "http://relay.test", relay as RelayHttp)

        // A message is waiting in the receiver's inbound inbox.
        relay.inject(INBOUND, ByteArray(64) { 7 })

        // The push-wake decision path: peek reports the waiting blob — and a SECOND
        // peek STILL reports it. This is the regression: a wake must be able to ask
        // "is anything here?" as many times as it likes without consuming it.
        assertEquals(1, mm.peekInbox(CID), "peek should report the waiting blob")
        assertEquals(1, mm.peekInbox(CID), "peek must NOT drain — the blob survives repeated peeks")

        // Only a genuine retrieve (the open conversation's poll) consumes it, after
        // which the inbox is empty. The message reaches the UI instead of being burned
        // by the notification check.
        relay.get("http://relay.test/inbox/$INBOUND", emptyMap(), 30)
        assertEquals(0, mm.peekInbox(CID), "after a genuine drain the inbox is empty")
    }
}
