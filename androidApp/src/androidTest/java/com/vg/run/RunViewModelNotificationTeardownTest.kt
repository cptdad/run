package com.vg.run

import android.app.Application
import android.app.NotificationManager
import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Android never cleared delivered notifications on lock.
 *
 * Before this fix, [NotificationHelper.cancelAll]'s only production callers
 * were the wipe path ([WipeRoutine.wipePersistentState]) and the push
 * opt-OUT toggle. `RunViewModel.onCleared()` — the teardown that runs on
 * EVERY background/lock ([MainActivity.onStop]'s `finishAndRemoveTask()`
 * clears the ViewModel) — closed the vault, wiped the Tink keyset, and
 * stopped Tor, but left any delivered "Notification" notification posted. On
 * a seized AFU device the shade still showed "Rún — New messages" after the
 * app's own teardown had completed; `VISIBILITY_SECRET` only suppresses the
 * LOCK-SCREEN display, not the record itself. iOS ships the mirror-image
 * control on every `lock()`.
 *
 * `onCleared()` is `protected` (overriding `ViewModel.onCleared()`), so it is
 * invoked here via reflection — the same technique
 * [RunViewModelWipeTest.privateFlow] already uses for private fields in this
 * same class.
 *
 * INSTRUMENTED because it posts and inspects a real system
 * [NotificationManager] entry — not testable at the plain-JVM
 * `androidUnitTest` tier (no Robolectric). Run with:
 *   ./gradlew connectedAndroidTest --tests "*.RunViewModelNotificationTeardownTest"
 * or, against an already-provisioned device, `am instrument` with `-e class`.
 *
 * Non-vacuousness: reverting the `NotificationHelper.cancelAll(getApplication())`
 * line from `RunViewModel.onCleared()` makes
 * [onCleared_cancelsDeliveredNotification] fail (the posted notification would
 * still be active after the reflective `onCleared()` call) — PROVIDED the
 * environment actually grants POST_NOTIFICATIONS (see the `assumeTrue` guard
 * below); on an environment that doesn't, the test is skipped rather than
 * false-passing.
 */
@RunWith(AndroidJUnit4::class)
class RunViewModelNotificationTeardownTest {

    private val app: Application
        get() = InstrumentationRegistry.getInstrumentation()
            .targetContext.applicationContext as Application

    private fun notificationManager(): NotificationManager =
        app.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

    private fun callOnCleared(vm: RunViewModel) {
        val m = RunViewModel::class.java.getDeclaredMethod("onCleared")
        m.isAccessible = true
        m.invoke(vm)
    }

    @Before
    fun setUp() {
        // Best-effort programmatic grant so this doesn't depend on whatever the
        // device/emulator's default POST_NOTIFICATIONS state happens to be
        // (API 33+ requires the runtime grant before notify() has any effect).
        try {
            InstrumentationRegistry.getInstrumentation().uiAutomation
                .grantRuntimePermission(app.packageName, android.Manifest.permission.POST_NOTIFICATIONS)
        } catch (_: Exception) { /* pre-33 device, or already granted */ }
        NotificationHelper.cancelAll(app)
    }

    @After
    fun tearDown() {
        NotificationHelper.cancelAll(app)
    }

    @Test
    fun onCleared_cancelsDeliveredNotification() {
        val vm = RunViewModel(app)
        NotificationHelper.showNewMessages(app)

        val nm = notificationManager()
        // If this environment doesn't actually deliver the notification
        // (permission denied, notifications disabled system-wide, or a
        // non-default channel importance) there is nothing for `cancelAll` to
        // prove it cleared — skip rather than false-pass OR flake on the
        // environment instead of the fix under test.
        assumeTrue(
            "environment did not actually post the notification (permission/appearance) " +
                "— skipping rather than asserting on an untestable environment",
            nm.areNotificationsEnabled() && nm.activeNotifications.isNotEmpty(),
        )

        callOnCleared(vm)

        assertTrue(
            "RunViewModel.onCleared() must clear delivered notifications via " +
                "NotificationHelper.cancelAll",
            nm.activeNotifications.isEmpty(),
        )
    }
}
