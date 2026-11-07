package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// ScreenshotNoticeStore — the durable, bounded, 24 h-expiring `_meta` namespace
// behind the persisted screenshot notices
// (docs/screenshot-notice-persistence-design.md §2.2–2.4, §7).
//
// Everything runs over [InMemoryVault] with an INJECTED clock, because every
// property that matters here is a time property: expiry is anchored on the LOCAL
// receive clock (never the sender's), and the display time is a clamp of the
// sender's claim. No migration exists and none is needed — an install with no
// `ssn:` rows simply has nothing to list.
// ---------------------------------------------------------------------------

private const val SSN_T0 = 1_700_000_000_000L   // a fixed, plausible wall clock
private const val SSN_C1 = "11111111-1111-1111-1111-111111111111"
private const val SSN_C2 = "22222222-2222-2222-2222-222222222222"
private const val SSN_G1 = "grpABC_def"

/** A store whose clock the test drives. */
private class SsnFixture {
    val vault = InMemoryVault()
    var now = SSN_T0
    val store = ScreenshotNoticeStore(vault) { now }
    fun ssnKeys() = vault.meta.keys.filter { it.startsWith(ScreenshotNoticeMetaKeys.PREFIX) }.sorted()
}

class ScreenshotNoticeStoreTest {

    // ---- round trip ------------------------------------------------------

    @Test
    fun record_roundTrips_asExactlyOneMetaRow() {
        val f = SsnFixture()
        val taken = roundTimestampToMinute(f.now - 45_000)
        val rec = f.store.record(SSN_C1, isGroup = false, senderContactId = SSN_C1, senderClaimedTakenAtMs = taken)

        assertNotNull(rec)
        assertEquals(SSN_C1, rec.conversationId)
        assertEquals(SSN_C1, rec.senderContactId)
        assertFalse(rec.isGroup)
        assertFalse(rec.seen)
        assertEquals(SSN_T0, rec.receivedAt, "receivedAt is OUR clock")
        assertEquals(taken, rec.takenAt, "an in-window claimed capture time is preserved")
        assertEquals(SSN_T0 + SCREENSHOT_NOTICE_TTL_MS, rec.expiresAt, "expiry is anchored on receivedAt")

        // One row, in the documented key/value shape and nothing else.
        assertEquals(listOf("ssn:$SSN_C1:$SSN_C1:$SSN_T0"), f.ssnKeys())
        assertEquals("$taken|0|0", f.vault.meta[f.ssnKeys().first()])

        val listed = f.store.list(SSN_C1)
        assertEquals(1, listed.size)
        assertEquals(rec, listed[0])
    }

    @Test
    fun record_storesNoAliasAndNoText() {
        // The vault row may name ids + timestamps and nothing else — the alias is
        // resolved at read time, from the contacts table, by GroupManager.
        val f = SsnFixture()
        f.vault.insertContact(ContactRecord(SSN_C1, ByteArray(32) { 3 }, 1, "Bob The Alias", 0L))
        f.store.record(SSN_C1, isGroup = false, senderContactId = SSN_C1, senderClaimedTakenAtMs = f.now)
        val row = f.ssnKeys().first() + "=" + f.vault.meta[f.ssnKeys().first()]
        assertFalse(row.contains("Bob"), "no alias may reach the vault row")
        assertFalse(row.contains("Alias"), "no alias may reach the vault row")
    }

    @Test
    fun aSecondStoreOverTheSameVault_seesTheSameState() {
        // The whole point of the feature: the notice must survive the session
        // teardown that follows every backgrounding, i.e. a brand-new store (and
        // GroupManager) over the same vault.
        val f = SsnFixture()
        f.store.record(SSN_C1, false, SSN_C1, f.now)
        f.store.markSeen(SSN_C1)

        val restarted = ScreenshotNoticeStore(f.vault) { f.now }
        val listed = restarted.list(SSN_C1)
        assertEquals(1, listed.size)
        assertTrue(listed[0].seen, "the seen flag is durable too")
        assertTrue(restarted.unseenCounts().isEmpty())
    }

    // ---- isolation + ordering -------------------------------------------

    @Test
    fun conversationsAreIsolated() {
        val f = SsnFixture()
        f.store.record(SSN_C1, false, SSN_C1, f.now)
        f.now += 10
        f.store.record(SSN_G1, true, SSN_C1, f.now)
        f.now += 10
        f.store.record(SSN_C2, false, SSN_C2, f.now)

        assertEquals(1, f.store.list(SSN_C1).size)
        assertEquals(1, f.store.list(SSN_G1).size)
        assertEquals(1, f.store.list(SSN_C2).size)
        assertEquals(0, f.store.list("nobody").size)
        assertEquals(SSN_G1, f.store.list(SSN_G1)[0].conversationId)
        assertTrue(f.store.list(SSN_G1)[0].isGroup)
        assertFalse(f.store.list(SSN_C1)[0].isGroup)
    }

    @Test
    fun listIsAscendingByReceivedAt() {
        val f = SsnFixture()
        val stamps = mutableListOf<Long>()
        repeat(5) {
            stamps.add(f.now)
            f.store.record(SSN_G1, true, SSN_C1, 0L)
            f.now += 1_000
        }
        assertEquals(stamps, f.store.list(SSN_G1).map { it.receivedAt })
    }

    @Test
    fun sameMillisecondBurst_getsDistinctRows_notAnOverwrite() {
        // Two notices inside one millisecond must not collapse onto one key; the
        // writer walks the receivedAt suffix forward instead.
        val f = SsnFixture()
        repeat(3) { f.store.record(SSN_G1, true, SSN_C1, 0L) }
        val listed = f.store.list(SSN_G1)
        assertEquals(3, listed.size)
        assertEquals(listOf(SSN_T0, SSN_T0 + 1, SSN_T0 + 2), listed.map { it.receivedAt })
    }

    // ---- caps ------------------------------------------------------------

    @Test
    fun capEvictsTheOldest_notTheNewest() {
        val f = SsnFixture()
        val flood = ScreenshotNoticeStore.MAX_PER_CONVERSATION + 8
        val stamps = mutableListOf<Long>()
        repeat(flood) {
            stamps.add(f.now)
            f.store.record(SSN_G1, true, SSN_C1, 0L)
            f.now += 1_000
        }
        val listed = f.store.list(SSN_G1)
        assertEquals(ScreenshotNoticeStore.MAX_PER_CONVERSATION, listed.size,
            "an authenticated member must not be able to grow the vault without bound")
        assertEquals(stamps.takeLast(ScreenshotNoticeStore.MAX_PER_CONVERSATION), listed.map { it.receivedAt },
            "the OLDEST rows are evicted, so the vault always holds the most recent notices")
        assertEquals(ScreenshotNoticeStore.MAX_PER_CONVERSATION, f.ssnKeys().size,
            "eviction deletes the keys, it does not merely hide them")
    }

    @Test
    fun capIsPerConversation() {
        val f = SsnFixture()
        repeat(ScreenshotNoticeStore.MAX_PER_CONVERSATION + 4) {
            f.store.record(SSN_G1, true, SSN_C1, 0L); f.now += 1
        }
        f.store.record(SSN_C2, false, SSN_C2, 0L)
        assertEquals(ScreenshotNoticeStore.MAX_PER_CONVERSATION, f.store.list(SSN_G1).size)
        assertEquals(1, f.store.list(SSN_C2).size, "one conversation's flood must not evict another's")
    }

    // ---- expiry ----------------------------------------------------------

    @Test
    fun expiryBoundary_isTtlAfterReceivedAt() {
        val f = SsnFixture()
        f.store.record(SSN_C1, false, SSN_C1, 0L)

        f.now = SSN_T0 + SCREENSHOT_NOTICE_TTL_MS - 1
        assertEquals(1, f.store.list(SSN_C1).size, "TTL - 1 ms is still visible")
        assertEquals(1, f.ssnKeys().size)

        f.now = SSN_T0 + SCREENSHOT_NOTICE_TTL_MS
        assertEquals(0, f.store.list(SSN_C1).size, "exactly TTL is gone")
        assertEquals(0, f.ssnKeys().size, "list() deletes the expired key, it does not just hide it")
    }

    @Test
    fun expiredRowsAreDeleted_byRecord_andByPruneExpired() {
        // record(): the write path prunes the conversation it touches.
        val a = SsnFixture()
        a.store.record(SSN_C1, false, SSN_C1, 0L)
        a.now = SSN_T0 + SCREENSHOT_NOTICE_TTL_MS + 1
        a.store.record(SSN_C1, false, SSN_C1, 0L)
        assertEquals(1, a.ssnKeys().size, "the expired row is gone, only the fresh one remains")
        assertEquals(a.now, a.store.list(SSN_C1)[0].receivedAt)

        // pruneExpired(): the sweep path, across ALL conversations.
        val b = SsnFixture()
        b.store.record(SSN_C1, false, SSN_C1, 0L)
        b.store.record(SSN_G1, true, SSN_C2, 0L)
        b.now = SSN_T0 + SCREENSHOT_NOTICE_TTL_MS
        b.store.pruneExpired()
        assertEquals(0, b.ssnKeys().size)
        assertTrue(b.store.unseenCounts().isEmpty())
    }

    @Test
    fun pruneExpired_leavesLiveRowsAndForeignNamespacesAlone() {
        val f = SsnFixture()
        f.vault.putMeta("dr/$SSN_C1/text", "state")
        f.vault.putMeta("group_admin:$SSN_G1", SSN_C1)
        f.store.record(SSN_C1, false, SSN_C1, 0L)
        f.now = SSN_T0 + 60_000
        f.store.pruneExpired()
        assertEquals(1, f.ssnKeys().size, "an unexpired notice must survive the sweep")
        assertNotNull(f.vault.getMeta("dr/$SSN_C1/text"), "the sweep touches nothing outside `ssn:`")
        assertNotNull(f.vault.getMeta("group_admin:$SSN_G1"))
    }

    // ---- the clamp (display time only) -----------------------------------

    @Test
    fun clamp_inWindowClaimIsPreserved_minuteRounded() {
        val received = SSN_T0
        val claimed = roundTimestampToMinute(received - 90_000)
        assertEquals(claimed, ScreenshotNoticeStore.clampTakenAt(claimed, received))
        assertEquals(0L, claimed % 60_000L, "the wire value is minute-rounded and stays that way")
    }

    @Test
    fun clamp_futureClaimFallsBackToReceivedAt() {
        val received = SSN_T0
        // Inside the skew tolerance but still ahead of us → clamped DOWN, never
        // rendered as a time this device has not reached.
        assertEquals(received, ScreenshotNoticeStore.clampTakenAt(received + 1, received))
        // Far in the future → a bogus clock; ignore it entirely.
        assertEquals(received, ScreenshotNoticeStore.clampTakenAt(received + 365L * 86_400_000, received))
    }

    @Test
    fun clamp_staleOrAbsentClaimFallsBackToReceivedAt() {
        val received = SSN_T0
        assertEquals(received, ScreenshotNoticeStore.clampTakenAt(0L, received), "no `t` on the wire")
        assertEquals(received, ScreenshotNoticeStore.clampTakenAt(-1L, received))
        assertEquals(received, ScreenshotNoticeStore.clampTakenAt(received - SCREENSHOT_NOTICE_TTL_MS - 1, received),
            "a claim older than the TTL itself is not believable")
        assertEquals(received - SCREENSHOT_NOTICE_TTL_MS,
            ScreenshotNoticeStore.clampTakenAt(received - SCREENSHOT_NOTICE_TTL_MS, received),
            "exactly TTL old is still inside the window")
    }

    @Test
    fun clampedClaim_neverMovesExpiryOrOrdering() {
        // The reason expiry is anchored on receivedAt: a screenshotter who backdates
        // "t" must not be able to make their own notice vanish early.
        val f = SsnFixture()
        val rec = f.store.record(SSN_C1, false, SSN_C1, SSN_T0 - SCREENSHOT_NOTICE_TTL_MS + 1_000)
        assertNotNull(rec)
        assertEquals(SSN_T0 + SCREENSHOT_NOTICE_TTL_MS, rec.expiresAt)
        f.now = SSN_T0 + SCREENSHOT_NOTICE_TTL_MS - 1
        assertEquals(1, f.store.list(SSN_C1).size, "a backdated claim does not expire the notice early")
    }

    // ---- seen / unseen ---------------------------------------------------

    @Test
    fun markSeen_zeroesTheUnseenCount_forThatConversationOnly() {
        val f = SsnFixture()
        f.store.record(SSN_C1, false, SSN_C1, 0L); f.now += 1
        f.store.record(SSN_C1, false, SSN_C1, 0L); f.now += 1
        f.store.record(SSN_G1, true, SSN_C1, 0L)

        assertEquals(mapOf(SSN_C1 to 2, SSN_G1 to 1), f.store.unseenCounts())
        assertEquals(mapOf(SSN_C1 to 2), f.store.unseenCounts(isGroup = false))
        assertEquals(mapOf(SSN_G1 to 1), f.store.unseenCounts(isGroup = true))

        f.store.markSeen(SSN_C1)

        assertEquals(mapOf(SSN_G1 to 1), f.store.unseenCounts())
        assertEquals(2, f.store.list(SSN_C1).size, "marking seen must not delete anything")
        assertTrue(f.store.list(SSN_C1).all { it.seen })
        assertFalse(f.store.list(SSN_G1)[0].seen)
    }

    @Test
    fun markSeen_isIdempotent_andWritesNothingOnceSeen() {
        val f = SsnFixture()
        f.store.record(SSN_C1, false, SSN_C1, 0L)
        f.store.markSeen(SSN_C1)
        val snapshot = f.vault.meta.toMap()
        f.store.markSeen(SSN_C1)
        f.store.markSeen(SSN_C1)
        assertEquals(snapshot, f.vault.meta.toMap(), "the steady-state poll tick must be a pure read")
    }

    @Test
    fun expiredNoticesDoNotCountAsUnseen() {
        val f = SsnFixture()
        f.store.record(SSN_C1, false, SSN_C1, 0L)
        f.now = SSN_T0 + SCREENSHOT_NOTICE_TTL_MS
        assertTrue(f.store.unseenCounts().isEmpty(), "an expired notice can't keep a dot lit")
    }

    // ---- lenient parsing / fail-soft -------------------------------------

    @Test
    fun corruptRowsAreDroppedOnLoad_notThrown() {
        val f = SsnFixture()
        // Every shape a hand-edited / partially-written row could take.
        f.vault.putMeta("ssn:$SSN_C1:$SSN_C1:notanumber", "1|0|0")
        f.vault.putMeta("ssn:$SSN_C1:$SSN_C1:${SSN_T0}", "")
        f.vault.putMeta("ssn:$SSN_C1:$SSN_C1:${SSN_T0 + 1}", "nope|0|0")
        f.vault.putMeta("ssn:$SSN_C1", "1|0|0")
        f.vault.putMeta("ssn:", "1|0|0")
        // …plus one good row.
        f.now = SSN_T0 + 5
        val good = f.store.record(SSN_C1, false, SSN_C1, 0L)

        assertNotNull(good)
        assertEquals(listOf(good), f.store.list(SSN_C1))
        assertTrue(f.store.unseenCounts().values.all { it == 1 })
        // list() GC'd the unreadable rows in that conversation…
        assertEquals(1, f.ssnKeys().count { it.startsWith("ssn:$SSN_C1:") })
        // …and pruneExpired GCs the rest of the namespace.
        f.store.pruneExpired()
        assertEquals(1, f.ssnKeys().size)
    }

    @Test
    fun idsThatWouldBreakTheKeyShape_areNotPersisted() {
        // The `:`-delimited key is what both purge classifiers parse, so an id that
        // could smuggle a separator is refused outright — the caller degrades to the
        // RAM-only path rather than writing an unpurgeable row.
        val f = SsnFixture()
        assertNull(f.store.record("has:colon", false, SSN_C1, 0L))
        assertNull(f.store.record(SSN_C1, false, "has:colon", 0L))
        assertNull(f.store.record("has|pipe", false, SSN_C1, 0L))
        assertNull(f.store.record("", false, SSN_C1, 0L))
        assertNull(f.store.record(SSN_C1, false, "", 0L))
        assertEquals(0, f.ssnKeys().size, "nothing may be written for a refused id")
        assertEquals(0, f.store.list("has:colon").size)
    }

    @Test
    fun aThrowingVaultIsFailSoft_neverFatal() {
        // iOS `putMeta` genuinely throws on a locked keybag mid-write. A screenshot
        // courtesy notice must degrade to "not durable", never take down a poll loop.
        val vault = object : InMemoryVault() {
            override fun putMeta(key: String, value: String) { throw RuntimeException("locked keybag") }
        }
        val store = ScreenshotNoticeStore(vault) { SSN_T0 }
        assertNull(store.record(SSN_C1, false, SSN_C1, 0L), "a refused write reports null, it does not throw")
        assertEquals(0, store.list(SSN_C1).size)
        store.markSeen(SSN_C1)     // must not throw either
        store.pruneExpired()
        assertTrue(store.unseenCounts().isEmpty())
    }

    @Test
    fun aThrowingRead_leavesTheNoticeRow_forTheNextRead() {
        // A transient read failure is ambiguous, not absent: the durable 24 h notice
        // must survive it on every path that GCs (list, markSeen, record, prune).
        var failReads = false
        val vault = object : InMemoryVault() {
            override fun getMeta(key: String): String? {
                if (failReads && key.startsWith(ScreenshotNoticeMetaKeys.PREFIX)) throw RuntimeException("transient")
                return super.getMeta(key)
            }
        }
        val store = ScreenshotNoticeStore(vault) { SSN_T0 }
        assertNotNull(store.record(SSN_C1, false, SSN_C1, SSN_T0))
        val key = vault.meta.keys.single { it.startsWith(ScreenshotNoticeMetaKeys.PREFIX) }
        val value = vault.meta[key]

        failReads = true
        assertEquals(0, store.list(SSN_C1).size, "an unreadable row is not shown")
        store.markSeen(SSN_C1)
        store.pruneExpired()
        assertNotNull(store.record(SSN_C1, false, SSN_C2, SSN_T0))
        assertTrue(store.unseenCounts()[SSN_C1] == null || store.unseenCounts()[SSN_C1] == 0)
        assertEquals(value, vault.meta[key], "the row must survive every read failure byte for byte")

        failReads = false
        val listed = store.list(SSN_C1)
        assertTrue(listed.any { it.senderContactId == SSN_C1 }, "the next read shows it again: $listed")
    }

    @Test
    fun aRowThatReadsButDoesNotDecode_isStillCollected() {
        val f = SsnFixture()
        f.vault.putMeta("ssn:$SSN_C1:$SSN_C1:$SSN_T0", "not-a-number|0|0")
        assertEquals(0, f.store.list(SSN_C1).size)
        assertEquals(0, f.ssnKeys().size, "a definite parse failure is residue and is deleted")
    }
}
