package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNull

/** The Group Info screen re-reads itself when [groupRosterStamp] changes: every roster
 *  change the screen displays must move the stamp, and nothing else may. */
class GroupRosterStampTest {
    private val gid = "g".repeat(32)
    private fun group(admin: String = "me", epoch: Long = 1, name: String = "Neighbours") =
        GroupRecord(gid, name, epoch, admin, "me", 0L)
    private fun member(id: String, contactId: String? = null) = GroupMemberRecord(gid, id, contactId, 0L)

    private fun vault(): InMemoryVault = InMemoryVault().apply {
        insertGroup(group())
        insertGroupMember(member("me"))
        insertGroupMember(member("m1", "c1"))
        insertGroupMember(member("m2"))
    }

    @Test fun unchangedRoster_keepsTheStamp() {
        val v = vault()
        assertEquals(groupRosterStamp(v, gid), groupRosterStamp(v, gid))
    }

    @Test fun adminHandover_movesTheStamp() {
        val v = vault()
        val before = groupRosterStamp(v, gid)
        v.deleteGroup(gid)
        v.insertGroup(group(admin = "m1", epoch = 2))
        listOf(member("me"), member("m1", "c1"), member("m2")).forEach { v.insertGroupMember(it) }
        assertNotEquals(before, groupRosterStamp(v, gid))
    }

    @Test fun memberAddedRemovedOrResolved_movesTheStamp() {
        val v = vault()
        val base = groupRosterStamp(v, gid)
        v.insertGroupMember(member("m3"))
        val added = groupRosterStamp(v, gid)
        assertNotEquals(base, added)
        v.deleteGroupMember(gid, "m3")
        assertEquals(base, groupRosterStamp(v, gid))
        v.deleteGroupMember(gid, "m2")
        v.insertGroupMember(member("m2", "c2"))
        assertNotEquals(base, groupRosterStamp(v, gid))
    }

    @Test fun memberOrder_doesNotMatter() {
        val a = vault()
        val b = InMemoryVault().apply {
            insertGroup(group())
            insertGroupMember(member("m2"))
            insertGroupMember(member("m1", "c1"))
            insertGroupMember(member("me"))
        }
        assertEquals(groupRosterStamp(a, gid), groupRosterStamp(b, gid))
    }

    @Test fun vanishedGroup_isNull_andAFailedRead_isUnavailable_notGone() {
        val v = vault()
        v.deleteGroup(gid)
        assertNull(groupRosterStamp(v, gid))
        val failing = object : VaultDatabase by vault() {
            override fun getGroup(groupId: String): GroupRecord? = throw IllegalStateException("vault closed")
        }
        assertEquals(ROSTER_STAMP_UNAVAILABLE, groupRosterStamp(failing, gid))
    }
}
