package com.vg.run

import android.app.NotificationManager
import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Product decision 2026-08-05 — notifications must alert like an ordinary
 * messenger. Pins the SHAPE of the channel [NotificationHelper] creates, since
 * every regression here is silent by construction: a wrong importance or a
 * hidden lock screen looks identical to "no message arrived", which is exactly
 * the bug class the user reported.
 *
 * The `_v3` id is asserted deliberately and is NOT cosmetic. Android only ever
 * lets an app LOWER/DISABLE an existing channel's importance/badge behaviour
 * ([NotificationManager.createNotificationChannel]: settings change "only if
 * the new importance is LOWER than the current value" and only when the user
 * hasn't touched the channel), so reusing a retired id would leave every
 * install that ever notified stuck on the old channel's shape, with the code
 * looking correct. A future editor who changes these defaults must therefore
 * ALSO mint a new id — and update the manifest's
 * `com.google.firebase.messaging.default_notification_channel_id`, which must
 * stay byte-for-byte equal.
 *
 * What is deliberately NOT asserted: that these values still hold after the
 * user changes them. They are first-run defaults the OS hands to the user, and
 * [NotificationHelper.ensureChannel] never re-imposes them.
 *
 * INSTRUMENTED — it inspects a real system [NotificationManager]. Run with
 * `am instrument` and `-e class`, in the FOREGROUND user (a ComposeRule-free
 * test still needs the app's own user to own the channel).
 */
@RunWith(AndroidJUnit4::class)
class NotificationChannelShapeTest {

    /** `NotificationManager.VISIBILITY_NO_OVERRIDE` — @hide, so inlined. */
    private val VISIBILITY_NO_OVERRIDE = -1000

    private val context: Context
        get() = InstrumentationRegistry.getInstrumentation().targetContext

    private val nm: NotificationManager
        get() = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

    @After
    fun tearDown() {
        // Leave no channel behind: this test is the only thing that created it
        // on a device that may never have opted into notifications.
        NotificationHelper.deleteChannel(context)
    }

    @Test
    fun channel_alertsLikeAMessenger_andIsVisibleOnTheLockScreen() {
        NotificationHelper.showNewMessages(context)

        val channel = nm.getNotificationChannel("run_new_messages_v3")
        assertNotNull("the v3 channel must exist after a notification is posted", channel)
        requireNotNull(channel)

        assertEquals(
            "IMPORTANCE_HIGH is what produces sound + heads-up",
            NotificationManager.IMPORTANCE_HIGH,
            channel.importance,
        )
        assertNotNull("a notification sound must be set", channel.sound)
        assertTrue("vibration must be on", channel.shouldVibrate())
        assertTrue(
            "launcher badge must be a boolean 'something waiting' signal (design decision 2026-08-20)",
            channel.canShowBadge(),
        )

        // The platform STRIPS an app-set channel lockscreenVisibility and
        // stores VISIBILITY_NO_OVERRIDE (-1000) instead — verified here rather
        // than assumed, because it is the opposite of what the API shape
        // suggests. Consequence worth knowing: the channel value is advisory
        // at best, the USER's system setting owns the lock screen, and the
        // only lock-screen control the app really has is the per-notification
        // visibility asserted below. (The pre-2026-08-05 code set SECRET on
        // the channel too; that call did nothing — what actually hid the entry
        // was the notification-level SECRET.)
        assertEquals(
            "the OS owns channel lock-screen visibility; apps cannot set it",
            VISIBILITY_NO_OVERRIDE,
            channel.lockscreenVisibility,
        )

        val posted = nm.activeNotifications.firstOrNull { it.id == 1001 }
        assertNotNull("the notification must be posted", posted)
        assertEquals(
            "VISIBILITY_PUBLIC — the (contentless) entry shows on the lock screen",
            android.app.Notification.VISIBILITY_PUBLIC,
            posted!!.notification.visibility,
        )
        // The fixed contentless title (invariant I4). Pinned on-device because
        // the push e2e suite can only check it when FCM actually delivers, and
        // because the word is generic enough that a free-text grep of
        // `dumpsys notification` matches the dump's own boilerplate — see
        // Device.readAndroidNotificationBlock.
        assertEquals(
            "Notification",
            posted.notification.extras.getCharSequence(android.app.Notification.EXTRA_TITLE)?.toString(),
        )
    }

    @Test
    fun legacyChannels_areRetired() {
        // Simulate an install that skipped a version (v1 straight to v3, or
        // v2 straight to v3) — BOTH legacy ids must be cleaned up, not just
        // the immediately-prior one.
        @Suppress("DEPRECATION")
        nm.createNotificationChannel(
            android.app.NotificationChannel(
                "run_new_messages",
                "Messages",
                NotificationManager.IMPORTANCE_LOW,
            )
        )
        @Suppress("DEPRECATION")
        nm.createNotificationChannel(
            android.app.NotificationChannel(
                "run_new_messages_v2",
                "Messages",
                NotificationManager.IMPORTANCE_LOW,
            )
        )
        assertNotNull(nm.getNotificationChannel("run_new_messages"))
        assertNotNull(nm.getNotificationChannel("run_new_messages_v2"))

        NotificationHelper.showNewMessages(context)

        assertNull(
            "the retired v1 channel must not survive as an extra 'Messages' entry",
            nm.getNotificationChannel("run_new_messages"),
        )
        assertNull(
            "the retired v2 channel must not survive as an extra 'Messages' entry",
            nm.getNotificationChannel("run_new_messages_v2"),
        )
    }

    @Test
    fun deleteChannel_removesAllIds() {
        NotificationHelper.showNewMessages(context)
        @Suppress("DEPRECATION")
        nm.createNotificationChannel(
            android.app.NotificationChannel(
                "run_new_messages",
                "Messages",
                NotificationManager.IMPORTANCE_LOW,
            )
        )
        @Suppress("DEPRECATION")
        nm.createNotificationChannel(
            android.app.NotificationChannel(
                "run_new_messages_v2",
                "Messages",
                NotificationManager.IMPORTANCE_LOW,
            )
        )

        NotificationHelper.deleteChannel(context)

        // Wipe hygiene: a surviving channel is standalone proof the app
        // posted a notification, outliving the vault it must be deniable about.
        assertNull(nm.getNotificationChannel("run_new_messages_v3"))
        assertNull(nm.getNotificationChannel("run_new_messages_v2"))
        assertNull(nm.getNotificationChannel("run_new_messages"))
    }
}
