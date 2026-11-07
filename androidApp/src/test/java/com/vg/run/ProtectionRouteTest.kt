package com.vg.run

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * `protectionRouteFor` is the ONE routing decision shared by the unlock path, the
 * forced route's dismissal and the contact-list entry.
 * Pin its three arms so a future "simplification" cannot re-open the split: a `null` floor read used to reach CONTACTS from the forced
 * route's exit while the unlock path sent the same state to the CHOOSER.
 */
class ProtectionRouteTest {

    @Test
    fun nullFloorRead_goesToTheChooser_notContacts() {
        // Legacy pre-slider vault OR a read that proves nothing (damaged blob,
        // device-key outage). Both must re-arm the gate via the chooser.
        for (lock in DeviceLockState.values()) {
            assertEquals("lock=$lock", "protection_setup", protectionRouteFor(null, lock))
        }
    }

    @Test
    fun belowTheFloorOnALockLessPhone_isForced() {
        assertEquals("protection_forced", protectionRouteFor(ProtectionLevel.CASUAL, DeviceLockState.Absent))
        assertEquals("protection_forced", protectionRouteFor(ProtectionLevel.PRIVATE, DeviceLockState.Absent))
    }

    @Test
    fun atOrAboveTheFloor_orLockPresent_goesToContacts() {
        assertEquals("contacts", protectionRouteFor(ProtectionLevel.MAXIMUM, DeviceLockState.Absent))
        for (level in ProtectionLevel.values()) {
            assertEquals("level=$level", "contacts", protectionRouteFor(level, DeviceLockState.Present))
        }
    }

    @Test
    fun matchesTheSharedPolicyExactly() {
        // The route is a pure projection of DeviceLockPolicy — no extra arm may
        // creep in on the Android side that iOS's needsForcedProtectionMigration
        // would not share.
        for (level in ProtectionLevel.values()) for (lock in DeviceLockState.values()) {
            val expected = if (DeviceLockPolicy.needsForcedMigration(level, lock)) "protection_forced" else "contacts"
            assertEquals("level=$level lock=$lock", expected, protectionRouteFor(level, lock))
        }
    }
}
