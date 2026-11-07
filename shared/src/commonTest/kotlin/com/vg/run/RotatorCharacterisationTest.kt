package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// Characterisation of the read-cap rotator seams a move into its own class must
// keep: an interrupted rotation heals from the top of the drain (BEFORE the GET,
// so the drain already uses the new cap), and a committed rotation hands its inbox
// to `drainRotatedPushInboxIds` exactly once.
// ---------------------------------------------------------------------------

private val RC_INBOX = "RCinbox".padEnd(32, 'x')
private val RC_OLD_CAP = "O".repeat(43)
private val RC_NEW_CAP = "N".repeat(43)

class RotatorCharacterisationTest {

    // Q2 + Q1: a pending marker whose cap the relay already holds is committed by the
    // drain's prepare step, the drain's GET carries the NEW cap, and the inbox is
    // reported for push re-registration once.
    @Test
    fun anInterruptedRotation_healsBeforeTheGet_andReportsTheInboxForPushOnce() {
        val vault = InMemoryVault()
        val cid = "rc-1"
        vault.insertContact(ContactRecord(cid, generateSecureRandom(32), 0, "A", 0L))
        vault.insertInboxId(InboxIdRecord(RC_INBOX, cid, 1L, Long.MAX_VALUE, "inbound", RC_OLD_CAP))
        vault.putMeta(MessageManager.capPendingKey(cid, "inbound"), RC_NEW_CAP)
        val relay = FakeRelayHttp(onGet = { r ->
            if (r.url.substringBefore("?").endsWith("/peek")) {
                if (r.headers["X-Read-Capability"] == RC_NEW_CAP) HttpResult(200, """{"pending":0}""", true)
                else HttpResult(404, "", false)
            } else RELAY_EMPTY_DRAIN
        })
        val mgr = MessageManager(vault, "http://relay.test", relay)

        assertTrue(mgr.pollMessages(cid).isEmpty())
        val drainGet = relay.requestsOf("GET").last { !it.url.substringBefore("?").endsWith("/peek") }
        assertEquals(RC_NEW_CAP, drainGet.headers["X-Read-Capability"], "the drain already uses the committed cap")
        assertEquals(RC_NEW_CAP, vault.getInboxIdForContact(cid, "inbound")!!.cap)
        assertNull(vault.getMeta(MessageManager.capPendingKey(cid, "inbound")), "the marker is retired")
        assertEquals(setOf(RC_INBOX), mgr.drainRotatedPushInboxIds())
        assertEquals(emptySet<String>(), mgr.drainRotatedPushInboxIds(), "drained once")
    }
}
