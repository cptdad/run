package com.vg.run

import kotlinx.coroutines.Job
import kotlin.properties.PropertyDelegateProvider
import kotlin.properties.ReadWriteProperty
import kotlin.reflect.KProperty

/**
 * The registry of every coroutine whose lifetime is ONE unlocked session.
 *
 * A session job is declared as `private var xJob: Job? by sessionJobs.slot()`.
 * It reads and writes like a plain field, but both teardowns
 * (`RunViewModel.lockSession` and `RunViewModel.performEmergencyWipe`) stop
 * every slot with one [cancelAll] call instead of a hand-kept list of names.
 * The two hand lists drifted before (the transport re-drive and both move jobs
 * were each missing from one of them for a while). With the registry a new
 * session job is cancelled by construction, and SessionJobsCoverageSourceTest
 * still fails until someone classifies it.
 *
 * Process-scoped jobs (the network-restore check, the lock-policy backstop
 * ticker) are deliberately NOT slots. Neither are two detached launches that
 * must outlive a teardown: the push-unregister DELETE burst
 * (`PushRegistrationCoordinator.unregisterPushBestEffort`) and lockSession's
 * re-auth debug-log flush. A `cancelAll` would kill them.
 *
 * Cancelling performs no I/O and no write: `cancel()` is O(1) per slot, so
 * [cancelAll] can sit before the vault close and the crypto-erase without ever
 * delaying the erase.
 *
 * Threading: slots are created while the owner is being constructed, so the slot
 * list never changes afterwards. Each slot's value is `@Volatile`, the same
 * visibility a plain field written on Main and read elsewhere had, plus a
 * guarantee that a cancel sees the latest assignment.
 */
internal class SessionJobs {

    private class Slot(val name: String) {
        @Volatile var job: Job? = null
    }

    private val slots = mutableListOf<Slot>()

    /** The slot names in declaration order (tests and diagnostics only). */
    val names: List<String> get() = slots.map { it.name }

    /** Declares one session job. Each property name may be declared once. */
    fun slot(): PropertyDelegateProvider<Any?, ReadWriteProperty<Any?, Job?>> =
        PropertyDelegateProvider { _, property ->
            val name = property.name
            check(slots.none { it.name == name }) { "session job `$name` declared twice" }
            val slot = Slot(name)
            slots += slot
            object : ReadWriteProperty<Any?, Job?> {
                override fun getValue(thisRef: Any?, property: KProperty<*>): Job? = slot.job
                override fun setValue(thisRef: Any?, property: KProperty<*>, value: Job?) {
                    slot.job = value
                }
            }
        }

    /**
     * Cancels every session job. Idempotent. The slots keep their (now
     * cancelled) Job references, exactly as `xJob?.cancel()` on a plain field
     * did, so an `isActive` check reads false afterwards.
     */
    fun cancelAll() {
        for (slot in slots) slot.job?.cancel()
    }
}
