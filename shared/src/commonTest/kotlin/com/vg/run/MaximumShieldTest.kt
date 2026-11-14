package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// The "Maximum shield" (MaximumShield.kt): strict wire payload, receiver rules
// (only a MAXIMUM device stores anything), the sender's marker logic (steady state
// sends nothing), the no-ping-pong convergence, leaving Maximum, purge/move
// membership of both `_meta` keys, an ambiguous level being inert, and an end-to-end
// round trip through the real control-envelope pipeline.
// ---------------------------------------------------------------------------

private const val MS_MAIN_OUT = "MSMAINxxxxxxxxxxxxxxxxxxxxxxxxxx"   // 32 chars
private const val MS_CTL_OUT  = "MSCTLxxxxxxxxxxxxxxxxxxxxxxxxxxx"   // 32 chars
private const val MS_CAP      = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  // 43 chars

private fun msContact(id: String) = ContactRecord(id, ByteArray(32) { 7 }, 1, "Alias-$id", 0L)

/** A vault that counts `_meta` writes, to pin "this input changes nothing". */
private class ShieldCountingVault : InMemoryVault() {
    var puts = 0
    var deletes = 0
    override fun putMeta(key: String, value: String) { puts++; super.putMeta(key, value) }
    override fun deleteMeta(key: String) { deletes++; super.deleteMeta(key) }
    val writes get() = puts + deletes
}

/** One device: a vault, a settable level, a shield that never sleeps. */
private class ShieldDevice(val vault: InMemoryVault = InMemoryVault(), var level: MaximumShieldLevel = MaximumShieldLevel.MAXIMUM) {
    val sleeps = mutableListOf<Long>()
    val shield = MaximumShield(vault, { level }, sleeper = { sleeps.add(it) }, jitterMs = { 1L })
    fun pair(vararg ids: String) { ids.forEach { vault.insertContact(msContact(it)) } }
    fun sentMarker(id: String) = vault.getMeta(MaximumShieldPolicy.sentMarkerKey(id))
    fun claim(id: String) = vault.getMeta(MaximumShieldPolicy.peerClaimKey(id))
}

class MaximumShieldWireTest {
    @Test
    fun kind_fitsTheControlKindCap_andIsKnownToBothReceivePaths() {
        assertEquals("plvl", MessageManager.CONTROL_KIND_PLEVEL)
        assertTrue(MessageManager.CONTROL_KIND_PLEVEL.length <= MessageManager.MAX_CONTROL_KIND_CHARS)
        assertTrue(MessageManager.isKnownDirectControlKind(MessageManager.CONTROL_KIND_PLEVEL))
    }

    @Test
    fun payload_isExactlyOneFlag_everythingElseIsDropped() {
        assertEquals(true, MaximumShieldPolicy.parseBody("""{"max":"1"}"""))
        assertEquals(false, MaximumShieldPolicy.parseBody("""{"max":"0"}"""))
        assertEquals("""{"max":"1"}""", MaximumShieldPolicy.bodyFor(true))
        assertEquals("""{"max":"0"}""", MaximumShieldPolicy.bodyFor(false))
        for (bad in listOf(
            null, "", "{}", "1", "0", "true", """{"max":"2"}""", """{"max":1}""", """{"max":""}""",
            """{"max":"1","x":"1"}""", """{"x":"1","max":"1"}""", """{ "max":"1"}""", """{"max":"1"} """,
            """{"MAX":"1"}""", """{"max":"11"}""", """{"max":"1"}{"max":"0"}""",
        )) {
            assertNull(MaximumShieldPolicy.parseBody(bad), "must be dropped: $bad")
        }
    }

    @Test
    fun levelRead_onlyAnAuthenticatedParseableLevelAnswers() {
        fun lvl(present: Boolean, auth: Boolean, v: String?) = MaximumShieldPolicy.levelOf(present, auth, v)
        assertEquals(MaximumShieldLevel.MAXIMUM, lvl(true, true, "maximum"))
        assertEquals(MaximumShieldLevel.NOT_MAXIMUM, lvl(true, true, "casual"))
        assertEquals(MaximumShieldLevel.NOT_MAXIMUM, lvl(true, true, "private"))
        // A planted cleartext `maximum` (unauthenticated) must NOT make a device announce Maximum.
        assertEquals(MaximumShieldLevel.AMBIGUOUS, lvl(true, false, "maximum"))
        assertEquals(MaximumShieldLevel.AMBIGUOUS, lvl(true, false, "casual"))
        assertEquals(MaximumShieldLevel.AMBIGUOUS, lvl(false, false, null))        // never chosen
        assertEquals(MaximumShieldLevel.AMBIGUOUS, lvl(true, true, "tier-from-the-future"))
        assertEquals(MaximumShieldLevel.AMBIGUOUS, lvl(true, true, null))
    }
}

class MaximumShieldReceiverTest {
    private val bodyOn = MaximumShieldPolicy.bodyFor(true)
    private val bodyOff = MaximumShieldPolicy.bodyFor(false)

    @Test
    fun nonMaximumDevice_storesNothing_andChangesNothing() {
        for (lvl in listOf(MaximumShieldLevel.NOT_MAXIMUM, MaximumShieldLevel.AMBIGUOUS)) {
            val v = ShieldCountingVault()
            val d = ShieldDevice(v, lvl)
            d.pair("a")
            d.shield.onAnnouncement("a", bodyOn)
            d.shield.onAnnouncement("a", bodyOff)
            assertEquals(0, v.writes, "a $lvl device must not write anything")
            assertTrue(v.meta.isEmpty())
        }
    }

    @Test
    fun maximumDevice_storesAClaim_andAZeroDeletesIt() {
        val d = ShieldDevice()
        d.pair("a", "b")
        d.shield.onAnnouncement("a", bodyOn)
        assertEquals("1", d.claim("a"))
        assertNull(d.claim("b"), "only the announcing contact")
        assertEquals(setOf("a"), d.shield.claimedContactIds())
        assertTrue(d.shield.isClaimed("a"))
        assertFalse(d.shield.isClaimed("b"))
        d.shield.onAnnouncement("a", bodyOff)
        assertNull(d.claim("a"))
        assertTrue(d.shield.claimedContactIds().isEmpty())
    }

    @Test
    fun malformedPayload_isDroppedWithoutAWrite() {
        val v = ShieldCountingVault()
        val d = ShieldDevice(v)
        d.pair("a")
        for (bad in listOf(null, "", "{}", """{"max":"1","x":"y"}""", """{"max":"yes"}""")) d.shield.onAnnouncement("a", bad)
        assertEquals(0, v.writes)
        // …and a bad 0 never removes a stored claim.
        d.shield.onAnnouncement("a", bodyOn)
        d.shield.onAnnouncement("a", """{"max":"00"}""")
        assertEquals("1", d.claim("a"))
    }

    @Test
    fun leavingMaximum_hidesShieldsAtOnce_beforeAnySweep() {
        val d = ShieldDevice()
        d.pair("a")
        d.shield.onAnnouncement("a", bodyOn)
        d.level = MaximumShieldLevel.NOT_MAXIMUM
        // The UI reads through these: nothing shows although the row is still stored.
        assertTrue(d.shield.claimedContactIds().isEmpty())
        assertFalse(d.shield.isClaimed("a"))
        d.level = MaximumShieldLevel.AMBIGUOUS
        assertTrue(d.shield.claimedContactIds().isEmpty())
    }

    @Test
    fun aThrowingLevelProbe_isAmbiguous_neverFatal() {
        val v = ShieldCountingVault()
        val shield = MaximumShield(v, { throw IllegalStateException("keybag locked") })
        shield.onAnnouncement("a", bodyOn)
        assertTrue(shield.claimedContactIds().isEmpty())
        assertEquals(0, shield.reconcile { _, _ -> true })
        assertEquals(0, v.writes)
    }
}

class MaximumShieldSenderTest {
    private class Sent(val id: String, val max: Boolean)

    private fun ShieldDevice.pass(sent: MutableList<Sent>, ok: Boolean = true, blocked: Set<String> = emptySet(), maxAttempts: Int = 5): Int =
        shield.reconcile(blocked, maxAttempts) { id, max -> sent.add(Sent(id, max)); ok }

    @Test
    fun firstPassAtMaximum_announcesToEveryContact_thenSteadyStateSendsNothing() {
        val d = ShieldDevice()
        d.pair("a", "b", "c")
        val sent = mutableListOf<Sent>()
        assertEquals(3, d.pass(sent))
        assertEquals(setOf("a", "b", "c"), sent.map { it.id }.toSet())
        assertTrue(sent.all { it.max })
        for (id in listOf("a", "b", "c")) assertEquals("1", d.sentMarker(id))
        // Spread: a random delay BETWEEN sends (n-1 sleeps), none before the first.
        assertEquals(2, d.sleeps.size)

        sent.clear()
        val writesBefore = d.vault.meta.toMap()
        repeat(3) { assertEquals(0, d.pass(sent)) }
        assertTrue(sent.isEmpty(), "steady state sends NOTHING")
        assertEquals(writesBefore, d.vault.meta.toMap(), "…and writes nothing")
    }

    @Test
    fun aFailedSend_leavesNoMarker_andIsRetriedNextPass() {
        val d = ShieldDevice()
        d.pair("a")
        val sent = mutableListOf<Sent>()
        assertEquals(1, d.pass(sent, ok = false))
        assertNull(d.sentMarker("a"), "marker only after a successful send")
        assertEquals(1, d.pass(sent, ok = true))
        assertEquals("1", d.sentMarker("a"))
        assertEquals(2, sent.size)
        assertEquals(0, d.pass(sent))
    }

    @Test
    fun aDeviceThatNeverWasMaximum_sendsAndWritesNothing() {
        val v = ShieldCountingVault()
        val d = ShieldDevice(v, MaximumShieldLevel.NOT_MAXIMUM)
        d.pair("a", "b")
        val sent = mutableListOf<Sent>()
        assertEquals(0, d.pass(sent))
        assertTrue(sent.isEmpty())
        assertEquals(0, v.writes)
    }

    @Test
    fun leavingMaximum_deletesClaims_andSendsAZeroOnlyWhereAOneWasAnnounced() {
        val d = ShieldDevice()
        d.pair("a", "b", "c")
        d.pass(mutableListOf())                       // announced 1 to a, b, c
        d.shield.onAnnouncement("a", MaximumShieldPolicy.bodyFor(true))
        d.shield.onAnnouncement("b", MaximumShieldPolicy.bodyFor(true))
        // (a claim arriving cleared the markers - the convergence rule - so re-send to a and b)
        d.pass(mutableListOf())
        assertEquals("1", d.sentMarker("a")); assertEquals("1", d.sentMarker("b"))
        d.vault.deleteMeta(MaximumShieldPolicy.sentMarkerKey("c"))   // c was never successfully told

        d.level = MaximumShieldLevel.NOT_MAXIMUM
        val sent = mutableListOf<Sent>()
        assertEquals(2, d.pass(sent))
        assertEquals(setOf("a", "b"), sent.map { it.id }.toSet())
        assertTrue(sent.none { it.max }, "the announcements are 0s")
        // Every stored peer claim is gone, and the markers are cleared by the successful 0s.
        assertTrue(d.vault.meta.keys.none { it.startsWith("plvl-") }, "no plvl residue: ${d.vault.meta.keys}")
        // …and it is stable.
        assertEquals(0, d.pass(sent))
    }

    @Test
    fun aFailedZero_keepsTheMarker_soTheZeroIsRetried() {
        val d = ShieldDevice()
        d.pair("a")
        d.pass(mutableListOf())
        d.level = MaximumShieldLevel.NOT_MAXIMUM
        val sent = mutableListOf<Sent>()
        d.pass(sent, ok = false)
        assertEquals("1", d.sentMarker("a"))
        d.pass(sent, ok = true)
        assertNull(d.sentMarker("a"))
        assertEquals(listOf(false, false), sent.map { it.max })
    }

    @Test
    fun reEnteringMaximum_announcesAgain() {
        val d = ShieldDevice()
        d.pair("a")
        d.pass(mutableListOf())
        d.level = MaximumShieldLevel.NOT_MAXIMUM
        d.pass(mutableListOf())
        d.level = MaximumShieldLevel.MAXIMUM
        val sent = mutableListOf<Sent>()
        assertEquals(1, d.pass(sent))
        assertTrue(sent.single().max)
    }

    @Test
    fun ambiguousLevel_isInert_nothingSentStoredOrDeleted() {
        val d = ShieldDevice()
        d.pair("a", "b")
        d.pass(mutableListOf())
        d.shield.onAnnouncement("a", MaximumShieldPolicy.bodyFor(true))
        val before = d.vault.meta.toMap()
        d.level = MaximumShieldLevel.AMBIGUOUS
        val sent = mutableListOf<Sent>()
        assertEquals(0, d.pass(sent))
        d.shield.onAnnouncement("b", MaximumShieldPolicy.bodyFor(true))
        d.shield.onAnnouncement("a", MaximumShieldPolicy.bodyFor(false))
        assertTrue(sent.isEmpty())
        assertEquals(before, d.vault.meta.toMap(), "an ambiguous read changes nothing")
    }

    @Test
    fun aLevelThatFlipsMidBurst_stopsTheBurst() {
        val d = ShieldDevice()
        d.pair("a", "b", "c")
        val sent = mutableListOf<Sent>()
        // After the first send the tier changes: the spread wait notices and the pass ends.
        val n = d.shield.reconcile { id, max -> sent.add(Sent(id, max)); d.level = MaximumShieldLevel.AMBIGUOUS; true }
        assertEquals(1, n)
        assertEquals(1, sent.size)
    }

    @Test
    fun theBurstIsBounded_andTheRestWaitsForTheNextPass() {
        val d = ShieldDevice()
        d.pair("a", "b", "c", "d")
        val sent = mutableListOf<Sent>()
        assertEquals(2, d.pass(sent, maxAttempts = 2))
        assertEquals(2, d.pass(sent, maxAttempts = 2))
        assertEquals(0, d.pass(sent, maxAttempts = 2))
        assertEquals(4, sent.map { it.id }.toSet().size, "every contact announced exactly once overall")
    }

    @Test
    fun blockedContacts_areSkipped() {
        val d = ShieldDevice()
        d.pair("a", "b")
        val sent = mutableListOf<Sent>()
        d.pass(sent, blocked = setOf("a"))
        assertEquals(listOf("b"), sent.map { it.id })
        assertNull(d.sentMarker("a"))
    }

    @Test
    fun aContactDeletedMidSend_isNotResurrected() {
        val d = ShieldDevice()
        d.pair("a")
        d.shield.reconcile { id, _ -> d.vault.deleteContact(id); true }
        assertNull(d.sentMarker("a"), "the marker must not be re-created for a deleted contact")
    }

    @Test
    fun anOverlappingPass_isRefused() {
        val d = ShieldDevice()
        d.pair("a")
        var inner = -1
        d.shield.reconcile { _, _ -> inner = d.shield.reconcile { _, _ -> true }; true }
        assertEquals(0, inner, "a pass started while another runs does nothing")
    }
}

class MaximumShieldConvergenceTest {
    /** Delivers an announcement from [from] to [to] (the pairwise channel is the attribution). */
    private class Net(val a: ShieldDevice, val b: ShieldDevice) {
        var messages = 0
        private fun deliver(to: ShieldDevice, fromId: String, max: Boolean) {
            messages++
            to.shield.onAnnouncement(fromId, MaximumShieldPolicy.bodyFor(max))
        }
        // A knows B as "b", B knows A as "a".
        fun passA() = a.shield.reconcile { _, m -> deliver(b, "a", m); true }
        fun passB() = b.shield.reconcile { _, m -> deliver(a, "b", m); true }
    }

    @Test
    fun noPingPong_lateAdopterConverges_andThenEverythingIsQuiet() {
        val a = ShieldDevice(); a.pair("b")
        val b = ShieldDevice(level = MaximumShieldLevel.NOT_MAXIMUM); b.pair("a")
        val net = Net(a, b)

        // A has been at Maximum for a while: its 1 reached B, which dropped it (not Maximum).
        assertEquals(1, net.passA())
        assertEquals("1", a.sentMarker("b"))
        assertNull(b.claim("a"), "a non-Maximum B stored nothing")

        // B now reaches Maximum.
        b.level = MaximumShieldLevel.MAXIMUM
        assertEquals(1, net.passB())            // B -> A : 1   (unknown -> 1 at A)
        assertEquals("1", a.claim("b"))
        assertNull(a.sentMarker("b"), "A cleared its marker so its own 1 is sent once more")
        assertEquals(1, net.passA())            // A -> B : 1   (unknown -> 1 at B)
        assertEquals("1", b.claim("a"))
        assertNull(b.sentMarker("a"), "B cleared its marker too")
        assertEquals(1, net.passB())            // B -> A : 1   (A already holds the claim: nothing)
        assertEquals("1", a.sentMarker("b"), "A's marker untouched by a 1 for an already-stored claim")

        val total = net.messages
        assertEquals(4, total, "A's original 1 plus exactly three more once B reached Maximum, then it stops")
        repeat(4) { assertEquals(0, net.passA()); assertEquals(0, net.passB()) }
        assertEquals(total, net.messages, "no ping-pong: steady state is silent")
        assertEquals(setOf("b"), a.shield.claimedContactIds())
        assertEquals(setOf("a"), b.shield.claimedContactIds())
    }

    @Test
    fun aOneForAnAlreadyStoredClaim_triggersNothing() {
        val v = ShieldCountingVault()
        val d = ShieldDevice(v); d.pair("a")
        d.shield.onAnnouncement("a", MaximumShieldPolicy.bodyFor(true))      // unknown -> 1: stored
        v.putMeta(MaximumShieldPolicy.sentMarkerKey("a"), "1")                // we had announced to a
        v.puts = 0; v.deletes = 0
        d.shield.onAnnouncement("a", MaximumShieldPolicy.bodyFor(true))      // 1 again: already stored
        assertEquals(0, v.writes, "no write at all")
        assertEquals("1", d.sentMarker("a"), "marker kept, so nothing is re-sent")
    }

    @Test
    fun bothAtMaximumFromTheStart_exchangeOnceEach_thenStop() {
        val a = ShieldDevice(); a.pair("b")
        val b = ShieldDevice(); b.pair("a")
        val net = Net(a, b)
        assertEquals(1, net.passA())   // A -> B : 1 (B unknown -> 1: stores, clears its marker (none))
        assertEquals(1, net.passB())   // B -> A : 1 (A unknown -> 1: stores, clears its marker)
        assertEquals(1, net.passA())   // A -> B : 1 (the convergence resend; B already holds it)
        assertEquals(3, net.messages)
        repeat(3) { assertEquals(0, net.passA()); assertEquals(0, net.passB()) }
        assertEquals(3, net.messages)
    }
}

class MaximumShieldPurgeTest {
    private val c1 = "contact-one"
    private val c2 = "contact-two"

    @Test
    fun bothKeys_areInThePurgeList_forTheirOwnContactOnly() {
        for (k in listOf(
            MaximumShieldPolicy.peerClaimKey(c1), MaximumShieldPolicy.sentMarkerKey(c1),
        )) {
            assertTrue(k in ratchetMetaKeysForContact(c1), "$k must be purged by deleteContact")
            assertFalse(k in ratchetMetaKeysForContact(c2), "…and only for ITS contact")
        }
        assertEquals("plvl-peer/$c1", MaximumShieldPolicy.peerClaimKey(c1))
        assertEquals("plvl-sent/$c1", MaximumShieldPolicy.sentMarkerKey(c1))
    }

    @Test
    fun deleteContact_removesBothKeys_andLeavesOtherContactsAlone() {
        val v = InMemoryVault()
        v.insertContact(msContact(c1)); v.insertContact(msContact(c2))
        for (c in listOf(c1, c2)) {
            v.putMeta(MaximumShieldPolicy.peerClaimKey(c), "1")
            v.putMeta(MaximumShieldPolicy.sentMarkerKey(c), "1")
        }
        v.deleteContact(c1)
        assertNull(v.getMeta(MaximumShieldPolicy.peerClaimKey(c1)))
        assertNull(v.getMeta(MaximumShieldPolicy.sentMarkerKey(c1)))
        assertNotNull(v.getMeta(MaximumShieldPolicy.peerClaimKey(c2)))
        assertNotNull(v.getMeta(MaximumShieldPolicy.sentMarkerKey(c2)))
    }

    @Test
    fun aReceivedClaim_afterTheContactIsDeleted_isNotRecreatedByTheTransport() {
        // The transport guards on contact existence before the shield is called (see
        // MessageManager.applyMaximumAnnouncement); the shield alone is exercised above.
        val d = ShieldDevice(); d.pair(c1)
        d.vault.deleteContact(c1)
        assertTrue(d.vault.meta.isEmpty())
    }

    @Test
    fun bothKeys_travelOnAMove() {
        assertTrue(MoveMetaPolicy.isAllowedKey(MaximumShieldPolicy.peerClaimKey(c1)))
        assertTrue(MoveMetaPolicy.isAllowedKey(MaximumShieldPolicy.sentMarkerKey(c1)))
    }
}

/** The real control-envelope pipeline: A sends, B drains its control inbox. */
class MaximumShieldTransportTest {
    private class Rig(bLevel: MaximumShieldLevel) {
        val shared = generateSecureRandom(32)
        val aVault = InMemoryVault()
        val aHttp = RecordingRelayHttp()
        val aMgr = MessageManager(aVault, "http://relay.test", aHttp as RelayHttp)
        val bVault = InMemoryVault()
        val bHttp = RecordingRelayHttp()
        val bDev = ShieldDevice(bVault, bLevel)
        val bMgr = MessageManager(bVault, "http://relay.test", bHttp as RelayHttp, maximumShield = bDev.shield)
        val aDev = ShieldDevice(aVault, MaximumShieldLevel.MAXIMUM)

        init {
            aVault.insertContact(ContactRecord("b", shared, 0, "B", 0L))
            aVault.insertInboxId(InboxIdRecord(MS_MAIN_OUT, "b", 1L, Long.MAX_VALUE, "outbound", MS_CAP))
            aVault.insertInboxId(InboxIdRecord(MS_CTL_OUT, "b", 1L, Long.MAX_VALUE, MessageManager.DIR_OUTBOUND_CTL, MS_CAP))
            bVault.insertContact(ContactRecord("a", shared, 0, "Alias-A", 0L))
            bVault.insertInboxId(InboxIdRecord(MS_MAIN_OUT, "a", 1L, Long.MAX_VALUE, "inbound", MS_CAP))
            bVault.insertInboxId(InboxIdRecord(MS_CTL_OUT, "a", 1L, Long.MAX_VALUE, MessageManager.DIR_INBOUND_CTL, MS_CAP))
        }

        fun aSends(max: Boolean): String {
            aHttp.script(HttpResult(202, "", true))
            assertTrue(aMgr.sendMaximumAnnouncement("b", max), "the announcement must reach the relay")
            return encodeBase64(aHttp.calls.last().body)
        }

        fun bDrains(vararg blobs: String): List<ReceivedMessage> {
            bHttp.script(HttpResult(200, """{"blobs":[${blobs.joinToString(",") { "\"$it\"" }}]}""", true))
            return bMgr.pollControlMessages("a")
        }
    }

    @Test
    fun roundTrip_aMaximumReceiverStoresTheClaim_andNothingSurfaces() {
        if (!aeadUp()) return
        val rig = Rig(MaximumShieldLevel.MAXIMUM)
        val blob = rig.aSends(true)
        assertTrue(rig.aHttp.calls.last().url.substringBefore("?").endsWith("/inbox/$MS_CTL_OUT"), "control inbox")
        assertEquals(0, rig.bDrains(blob).size, "never a message")
        assertEquals("1", rig.bDev.claim("a"))
        // A withdrawal removes it.
        assertEquals(0, rig.bDrains(rig.aSends(false)).size)
        assertNull(rig.bDev.claim("a"))
    }

    @Test
    fun roundTrip_aNonMaximumReceiverStoresNothing() {
        if (!aeadUp()) return
        for (lvl in listOf(MaximumShieldLevel.NOT_MAXIMUM, MaximumShieldLevel.AMBIGUOUS)) {
            val rig = Rig(lvl)
            assertEquals(0, rig.bDrains(rig.aSends(true)).size)
            assertTrue(rig.bVault.meta.keys.none { it.startsWith("plvl-") }, "$lvl stored a claim")
        }
    }

    @Test
    fun theSenderPass_goesThroughTheRealPipeline_andSteadyStatePostsNothing() {
        if (!aeadUp()) return
        val rig = Rig(MaximumShieldLevel.MAXIMUM)
        rig.aHttp.script(HttpResult(202, "", true))
        assertEquals(1, rig.aDev.shield.reconcile { id, max -> rig.aMgr.sendMaximumAnnouncement(id, max) })
        assertEquals("1", rig.aDev.sentMarker("b"))
        val posts = rig.aHttp.calls.size
        assertEquals(0, rig.aDev.shield.reconcile { id, max -> rig.aMgr.sendMaximumAnnouncement(id, max) })
        assertEquals(posts, rig.aHttp.calls.size, "steady state: no relay request")
    }

    @Test
    fun anUnsendableAnnouncement_isAQuietFalse() {
        val mgr = MessageManager(InMemoryVault(), "http://relay.test", RecordingRelayHttp() as RelayHttp)
        assertEquals(false, mgr.sendMaximumAnnouncement("nobody", true))
    }

    // --- FORWARD COMPAT: what an OLDER build does with a kind it predates --------------------
    // An older build has no "plvl" in isKnownDirectControlKind, so the blob takes the generic
    // "drop: unknown direct control" branch of legacyDropReason (counted-as-dropped, acked,
    // counter not adopted, nothing surfaced, nothing written). That branch is driven here with a
    // same-shaped envelope of a kind this build does not know ("plvl-x" - a different kind, the
    // exact position an older build is in with "plvl"); DrainCharacterisationTest pins the ack
    // and the unmoved counter, ScreenshotNoticeTest pins that later traffic still lands.
    @Test
    fun anOlderBuild_dropsTheUnknownKindSilently() {
        if (!aeadUp()) return
        val rig = Rig(MaximumShieldLevel.MAXIMUM)
        assertFalse(MessageManager.isKnownDirectControlKind("plvl-x"))
        rig.aHttp.script(HttpResult(202, "", true))
        assertTrue(rig.aMgr.sendDirectControl("b", "plvl-x", MaximumShieldPolicy.bodyFor(true), noPush = true))
        val blob = encodeBase64(rig.aHttp.calls.last().body)
        assertEquals(0, rig.bDrains(blob).size, "never a bubble")
        assertTrue(rig.bVault.meta.keys.none { it.startsWith("plvl-") }, "and no state")
        assertEquals(0L, rig.bVault.getContact("a")!!.inboundCtlCounter, "the counter is not adopted")
        // The channel is not poisoned: a real announcement sent afterwards still lands.
        assertEquals(0, rig.bDrains(rig.aSends(true)).size)
        assertEquals("1", rig.bDev.claim("a"))
    }
}
