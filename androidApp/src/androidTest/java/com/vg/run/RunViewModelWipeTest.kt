package com.vg.run

import android.app.Application
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.flow.MutableStateFlow
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The panic wipe keeps the process ALIVE
 * (the PIN screen renders a black Box; the change-PIN screen that can trigger the
 * daily-abuse-cap wipe stays up), so any per-contact / per-group identifier left in
 * a StateFlow is recoverable by a post-wipe RAM acquisition — proof of prior use plus
 * the user's contact ids. performEmergencyWipe() must therefore explicitly empty the
 * three identifier StateFlows populated by the background control poll.
 *
 * Run with: ./gradlew connectedAndroidTest
 */
@RunWith(AndroidJUnit4::class)
class RunViewModelWipeTest {

    private val app: Application
        get() = InstrumentationRegistry.getInstrumentation()
            .targetContext.applicationContext as Application

    @After
    fun tearDown() {
        // performEmergencyWipe already crypto-erases + deletes; belt-and-braces so a
        // leftover master key / prefs from this test can't affect neighbours.
        WipeRoutine.wipePersistentState(app)
        // The wipe above is DENIABLE (performEmergencyWipe's default), so it armed
        // the process-lifetime black cover. Instrumented tests share one process:
        // leaving it armed would black-screen every later Activity launch in the
        // run (MainActivityWipeCoverTest). Debug-only no-op in release, like the
        // ProcessWipeLatch reset the other wipe tests do.
        ProcessWipeCover.resetForTest()
    }

    @Suppress("UNCHECKED_CAST")
    private fun <T> RunViewModel.privateFlow(name: String): MutableStateFlow<T> {
        val f = RunViewModel::class.java.getDeclaredField(name)
        f.isAccessible = true
        return f.get(this) as MutableStateFlow<T>
    }

    @Test
    fun performEmergencyWipe_clearsInMemoryIdentifierMaps() {
        val vm = RunViewModel(app)

        // Populate the three id-bearing maps the control poll would fill while the
        // vault is open (no live vault/relay needed — set them directly).
        vm.privateFlow<Map<String, Int>>("_unreadCounts").value =
            mapOf("contact-alice" to 3, "contact-bob" to 1)
        vm.privateFlow<Map<String, Int>>("_groupUnreadCounts").value =
            mapOf("group-secret" to 5)
        vm.privateFlow<Set<String>>("_relayLostContacts").value =
            setOf("contact-carol", "contact-dave")

        // Sanity: the public flows now expose the contact ids.
        assertTrue("precondition: unread map populated", vm.unreadCounts.value.isNotEmpty())
        assertTrue("precondition: group unread map populated", vm.groupUnreadCounts.value.isNotEmpty())
        assertTrue("precondition: relay-lost set populated", vm.relayLostContacts.value.isNotEmpty())

        vm.performEmergencyWipe()

        // The wipe keeps the process/ViewModel alive, so these MUST be emptied.
        assertTrue("unread counts must be cleared on wipe", vm.unreadCounts.value.isEmpty())
        assertTrue("group unread counts must be cleared on wipe", vm.groupUnreadCounts.value.isEmpty())
        assertTrue("relay-lost set must be cleared on wipe", vm.relayLostContacts.value.isEmpty())
    }
}
