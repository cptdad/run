package com.vg.run

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The display-payload keys the FCM SDK acts on are stripped; data keys survive. */
class FcmPayloadGuardTest {

    @Test
    fun displayNotificationKeys_areStripped() {
        for (k in listOf("gcm.n.e", "gcm.n.title", "gcm.n.body", "gcm.n.icon", "gcm.n.android_channel_id",
            "gcm.notification.e", "gcm.notification.title", "gcm.notification.body")) {
            assertTrue(k, FcmPayloadGuard.isNotificationExtraKey(k))
        }
    }

    @Test
    fun dataAndTransportKeys_survive() {
        for (k in listOf("type", "google.message_id", "google.sent_time", "google.ttl", "from",
            "collapse_key", "google.original_priority", "google.delivered_priority", "gcm", "gcm.n", "notification")) {
            assertFalse(k, FcmPayloadGuard.isNotificationExtraKey(k))
        }
    }

    @Test
    fun keysToStrip_returnsExactlyTheDisplayKeys_inOrder() {
        val extras = listOf("google.message_id", "gcm.n.e", "type", "gcm.notification.body", "from", "gcm.n.title")
        assertEquals(listOf("gcm.n.e", "gcm.notification.body", "gcm.n.title"), FcmPayloadGuard.keysToStrip(extras))
        assertEquals(emptyList<String>(), FcmPayloadGuard.keysToStrip(listOf("type", "from")))
    }
}
