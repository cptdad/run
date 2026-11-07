package com.vg.run

import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

// ---------------------------------------------------------------------------
// DebugModeTest — the user-consented diagnostic log upload (2026-09-14).
//
// Five things are pinned here and must not drift:
//  1. The CONSENT FLAG: it persists, it drives LoggingState in BOTH directions
//     (including ON in a release build — that is the feature), turning it off
//     drops the buffer, and applyAtStartup never turns logging OFF (debug
//     builds enable it for their own reasons and must keep it).
//  2. The WIRE BODY: byte-exact, fixed key order, and the caps that bound it.
//  3. The CURSOR semantics: advance only on a confirmed 204, re-send the same
//     lines after a failure, drop the oldest when the backlog runs away, never
//     two flushes at once.
//  4. THE RELATIVE CLOCK. The uploaded lines carry `+SSSSS.mmm` offsets from a
//     per-process origin plus ONE minute-floored `t0`, never the device's
//     millisecond wall clock (a clock-skew/drift fingerprint at 1 Hz).
//  5. THE LEAK SWEEP. The product rule is "as much as possible, but nothing
//     that can identify the user or the device". `leakSweep_*` feeds the
//     redactor lines built from the REAL shapes this app emits — an 18-char
//     contact id, a 32-char inbox id, a 43-char capability, an alias, an onion
//     URL, IPv4/IPv6 literals, an epoch, a hex fingerprint, a sandbox path, a
//     Tor daemon phase line — and asserts that none of the sensitive
//     substrings survive while the prefix, the plain prose and the small
//     numbers do. `leakSweep_noTruncatedInboxPrefixSurvives` is the SIMULATION
//     half: 20 000 pseudo-random ids rendered the three ways this app actually
//     renders an 8-char prefix, asserting ZERO survivors — an all-letter
//     prefix is ≈ 19 % of them, so a rule that only catches mixed-case runs
//     would leak roughly one prefix in five. A failure here is a privacy bug,
//     not a formatting nit.
// ---------------------------------------------------------------------------

/** 43 characters — the on-the-wire length of an inbox capability. */
private const val CAP_43 = "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5bC7dE9f"

/** 18 characters — the length of a contact id. */
private const val CONTACT_ID_18 = "abcdEFGH1234567890"

/** 32 characters — the length of an inbox id. */
private const val INBOX_ID_32 = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"

/** 8 characters — a shortId as the UI renders it. */
private const val SHORT_ID_8 = "aB3dEfG7"

private const val FINGERPRINT_40 = "DEADBEEFCAFEBABE1234567890ABCDEF12345678"

private const val RELAY_BASE = "http://relay.test"

/** 12:34:56.789 as milliseconds-of-day — the clock every fixture line carries. */
private const val ORIGIN_MS_OF_DAY = 45_296_789

/** The same instant as epoch millis (2026-09-04T12:34:56.789Z). */
private const val ORIGIN_EPOCH_MS = 1_756_989_296_789L

/** [ORIGIN_EPOCH_MS] floored to a whole minute — the `t0` that ships with it. */
private const val ORIGIN_T0 = 1_756_989_240L

// `SeededLcg` / `b64Url` live in support/SeededLcg.kt, shared with
// DebugModeRedactorPropertyTest.

// The consent flag is a DEVICE-KEY AEAD blob now, so
// every seam call takes a cipher and every SEEDED "on" value has to be sealed.
// A bare "1" left in the store is precisely the plant the finding is about —
// `unauthenticatedOnValue_readsOff` below pins that it reads OFF.
private val debugCipher = FakeDeviceKeyCipher()

/** The stored form of an ON consent flag. */
private fun sealedDebugOn(): String = SealedPref.seal(debugCipher, DebugMode.SLOT, "1")

/** An in-memory [DebugModeStore]; optionally fails the way the iOS Keychain can. */
private class FakeDebugStore(
    private val throwOnGet: Boolean = false,
    private val throwOnPut: Boolean = false,
    /** SecItemDelete refused (locked keybag): the value SURVIVES and `false` is
     *  reported — the shape that used to leave consent armed for the next launch. */
    private val refuseRemove: Boolean = false,
    /** The store swallows the delete and reports success anyway. Read-back is
     *  then the only thing that can catch it. */
    private val silentlyIgnoreRemove: Boolean = false,
) : DebugModeStore {
    val values = mutableMapOf<String, String>()
    var removals = 0
    /** Ordered trace, so a test can pin that the PERSIST happens before the
     *  runtime switch is flipped (LoggingState is checked inside the fake). */
    val opsWhileLoggingOn = mutableListOf<String>()

    override fun get(key: String): String? {
        if (throwOnGet) throw KeyUnavailableException("keybag locked")
        return values[key]
    }

    override fun putSync(key: String, value: String) {
        if (throwOnPut) throw KeyUnavailableException("keybag locked")
        if (LoggingState.enabled) opsWhileLoggingOn.add("put=$value")
        values[key] = value
    }

    override fun remove(key: String): Boolean {
        removals++
        if (LoggingState.enabled) opsWhileLoggingOn.add("remove")
        if (refuseRemove) return false
        // Claims success while the value survives — only the read-back catches it.
        if (silentlyIgnoreRemove) return true
        values.remove(key)
        return true
    }
}

/** POST-only recorder; each request carries the `suppressLog` opt-out the uploader
 *  MUST ask for (RelayHttp.post's six-argument overload). */
private fun RecordingDebugRelay(
    scripted: HttpResult = HttpResult(204, null, true),
    throwOnPost: Boolean = false,
) = FakeRelayHttp.postOnly("the debug log") {
    if (throwOnPost) throw RuntimeException("transport down")
    scripted
}

private fun pending(vararg lines: Pair<Long, String>): List<DebugLogUploader.PendingLine> =
    lines.map { DebugLogUploader.PendingLine(it.first, it.second) }

/** `collect` that behaves like the real one: everything above the cursor. */
private fun source(all: List<DebugLogUploader.PendingLine>): (Long) -> List<DebugLogUploader.PendingLine> =
    { at -> all.filter { it.seq > at } }

class DebugModeTest {

    private var savedLogging = false

    @BeforeTest
    fun setUp() {
        savedLogging = LoggingState.enabled
        LoggingState.enabled = true
        LogBuffer.clear()
        ConnectionLog.clear()
        DebugLogUploader.setCursorForTest(0L)
        // The time origin is process-wide RAM state like the cursor: pin it, or
        // `t0` and every `+SSSSS.mmm` offset depend on which test ran first.
        DebugLogUploader.setOriginForTest(ORIGIN_MS_OF_DAY, ORIGIN_EPOCH_MS)
    }

    @AfterTest
    fun tearDown() {
        LogBuffer.clear()
        ConnectionLog.clear()
        LoggingState.enabled = savedLogging
        DebugLogUploader.setCursorForTest(0L)
        DebugLogUploader.clearOriginForTest()
    }

    // -- the consent flag ----------------------------------------------------

    @Test
    fun setEnabled_on_persistsAndTurnsLoggingOn() {
        val store = FakeDebugStore()
        LoggingState.enabled = false

        DebugMode.setEnabledIn(store, debugCipher, true)

        // A1-4: persisted as a DEVICE-KEY AEAD blob, never the literal "1".
        val stored = store.values[DebugMode.KEY]
        assertNotNull(stored)
        assertTrue(stored != "1", "the flag must not be persisted as plaintext")
        assertEquals("1", SealedPref.open(debugCipher, DebugMode.SLOT, stored).value)
        assertTrue(LoggingState.enabled, "turning Debug mode on must flip LoggingState, release build included")
        assertTrue(DebugMode.isEnabledIn(store, debugCipher))
    }

    @Test
    fun setEnabled_off_turnsLoggingOffClearsTheBufferAndForgetsTheKey() {
        val store = FakeDebugStore()
        DebugMode.setEnabledIn(store, debugCipher, true)
        LogBuffer.append("D", "Tag", "something the user no longer consents to")
        assertTrue(LogBuffer.getAll().isNotEmpty(), "precondition: the buffer holds a line")

        val nowOn = DebugMode.setEnabledIn(store, debugCipher, false)

        assertFalse(nowOn, "a clean revocation reports the flag as OFF")
        // OFF restores the build's baseline: a debug build keeps its own logging.
        assertEquals(isDebugBuild, LoggingState.enabled)
        assertTrue(LogBuffer.getAll().isEmpty(), "turning Debug mode off must drop what was buffered")
        assertNull(store.values[DebugMode.KEY], "the flag is removed, not set to \"0\"")
        assertEquals(1, store.removals)
        assertFalse(DebugMode.isEnabledIn(store, debugCipher))
    }

    // -- off must STICK ------------------------------------------------------
    //
    // The persist runs BEFORE the runtime switch is flipped, so a store that
    // refuses the delete can still be caught and overwritten with an explicit
    // "0" — otherwise a revoked consent silently came back on at the next
    // launch (the store still read "1"), with no way for either UI to know.

    @Test
    fun setEnabled_off_persistsBeforeItFlipsTheRuntimeSwitch() {
        val store = FakeDebugStore()
        DebugMode.setEnabledIn(store, debugCipher, true)
        store.opsWhileLoggingOn.clear()

        DebugMode.setEnabledIn(store, debugCipher, false)

        assertEquals(
            listOf("remove"),
            store.opsWhileLoggingOn,
            "the removal must happen while the flag is still on, not after the switch has been flipped",
        )
    }

    @Test
    fun setEnabled_off_writesAnExplicitZeroWhenTheStoreRefusesTheDelete() {
        val store = FakeDebugStore(refuseRemove = true)
        store.values[DebugMode.KEY] = sealedDebugOn()

        val nowOn = DebugMode.setEnabledIn(store, debugCipher, false)

        assertEquals("0", store.values[DebugMode.KEY], "a refused delete must be overwritten with an explicit off")
        assertFalse(DebugMode.isEnabledIn(store, debugCipher), "\"0\" reads as off")
        assertFalse(nowOn, "the flag IS off — it just took a write instead of a delete")
        assertEquals(isDebugBuild, LoggingState.enabled)
    }

    @Test
    fun setEnabled_off_writesAnExplicitZeroWhenTheDeleteIsSilentlyIgnored() {
        // The store claims the delete succeeded but the value survives — only
        // the read-back catches this one.
        val store = FakeDebugStore(silentlyIgnoreRemove = true)
        store.values[DebugMode.KEY] = sealedDebugOn()

        val nowOn = DebugMode.setEnabledIn(store, debugCipher, false)

        assertEquals("0", store.values[DebugMode.KEY])
        assertFalse(nowOn)
    }

    @Test
    fun setEnabled_off_reportsStillOnWhenNothingCouldBePersisted() {
        // Neither the delete nor the "0" write lands (locked keybag): the NEXT
        // launch will read consent again, so the UI must keep showing ON rather
        // than a revocation that quietly undoes itself.
        val store = FakeDebugStore(throwOnPut = true, refuseRemove = true)
        store.values[DebugMode.KEY] = sealedDebugOn()

        val nowOn = DebugMode.setEnabledIn(store, debugCipher, false)

        assertTrue(nowOn, "an unpersistable revocation must not be reported as off")
        assertEquals(isDebugBuild, LoggingState.enabled, "this session drops to the build baseline either way")
        assertTrue(LogBuffer.getAll().isEmpty())
    }

    @Test
    fun setEnabled_on_reportsOn() {
        val store = FakeDebugStore(throwOnPut = true)

        assertTrue(
            DebugMode.setEnabledIn(store, debugCipher, true),
            "ON reports on even when the write failed — the session IS on, and claiming off while uploading is the dangerous lie",
        )
    }

    @Test
    fun setEnabled_on_doesNotShipWhatWasBufferedBeforeConsent() {
        val store = FakeDebugStore()
        LoggingState.enabled = false
        ConnectionLog.append(ConnectionLog.Kind.SYSTEM, "recorded before the user consented")

        DebugMode.setEnabledIn(store, debugCipher, true)

        assertTrue(
            DebugLogUploader.collectPending(DebugLogUploader.cursorForTest()).isEmpty(),
            "consent is not retroactive — enabling must reset the cursor past everything already buffered",
        )
    }

    @Test
    fun applyAtStartup_turnsLoggingOnWhenTheFlagIsSetAndResetsTheCursor() {
        val store = FakeDebugStore()
        store.values[DebugMode.KEY] = sealedDebugOn()
        LoggingState.enabled = false
        ConnectionLog.append(ConnectionLog.Kind.SYSTEM, "from before this session's cursor")

        DebugMode.applyAtStartupIn(store, debugCipher)

        assertTrue(LoggingState.enabled)
        assertTrue(DebugLogUploader.collectPending(DebugLogUploader.cursorForTest()).isEmpty())
    }

    @Test
    fun applyAtStartup_neverTurnsLoggingOff() {
        // A DEBUG build flips LoggingState on at its own entry point. Startup
        // must leave that alone, or every debug build loses its log viewer.
        val store = FakeDebugStore()
        LoggingState.enabled = true

        DebugMode.applyAtStartupIn(store, debugCipher)

        assertTrue(LoggingState.enabled, "applyAtStartup must never write false")
    }

    @Test
    fun isEnabled_failsTowardOffOnATransientStoreError() {
        assertFalse(
            DebugMode.isEnabledIn(FakeDebugStore(throwOnGet = true), debugCipher),
            "a Keychain that cannot answer must never be read as consent",
        )
    }

    // -- A1-4: the flag is AUTHENTICATED, not merely stored --------------------

    @Test
    fun unauthenticatedOnValue_readsOff() {
        // THE FINDING. Before this, `debug_mode_prefs.xml` held the bare string
        // "1" and anyone able to write the app's files could start redacted log
        // uploads in a RELEASE build. A plant — and a legacy plaintext flag from
        // before the fix, which is byte-identical — must read OFF.
        for (planted in listOf("1", "0", "true", "MQ==", "not-base64!!")) {
            val store = FakeDebugStore().also { it.values[DebugMode.KEY] = planted }
            assertFalse(
                DebugMode.isEnabledIn(store, debugCipher),
                "an unauthenticated value (\"$planted\") must never read as consent",
            )
            assertEquals(
                DebugMode.PERSISTED_OFF,
                DebugMode.reapplyPersistedTriStateIn(store, debugCipher),
                "and it must be a DEFINITE off, so the iOS retry loop stops instead of spinning",
            )
        }
    }

    @Test
    fun aBlobSealedForAnotherSlotDoesNotOpenHere() {
        // Each consumer gets its OWN AEAD context so a blob cannot be lifted
        // between slots. The push consent proof says "vendor_push", not "1", but
        // the point is the context check, not the token.
        val foreign = SealedPref.seal(debugCipher, NotificationLevelStore.SLOT_CONSENT, "1")
        val store = FakeDebugStore().also { it.values[DebugMode.KEY] = foreign }
        assertFalse(DebugMode.isEnabledIn(store, debugCipher), "a blob from another slot is not consent")
    }

    @Test
    fun anUnreadableDeviceKeyIsDeferred_neverReadAsConsentAndNeverAsARevocation() {
        // KeyUnavailable = DEFER. The flag reads OFF (nothing is uploaded) but
        // the tri-state must say UNREADABLE so the retrying caller keeps trying
        // — an Android process started by a push wake on a LOCKED screen is in
        // exactly this state on every launch.
        val store = FakeDebugStore().also { it.values[DebugMode.KEY] = sealedDebugOn() }
        val locked = FakeDeviceKeyCipher(throwOnOpen = true)
        assertFalse(DebugMode.isEnabledIn(store, locked))
        assertEquals(DebugMode.PERSISTED_UNREADABLE, DebugMode.reapplyPersistedTriStateIn(store, locked))
        // …and the very same bytes read as ON the moment the key is usable.
        assertTrue(DebugMode.isEnabledIn(store, debugCipher))
    }

    @Test
    fun setEnabled_on_stillEnablesThisSessionWhenThePersistFails() {
        val store = FakeDebugStore(throwOnPut = true)
        LoggingState.enabled = false

        DebugMode.setEnabledIn(store, debugCipher, true)

        assertTrue(LoggingState.enabled, "a failed write must not leave the user's choice unapplied this session")
    }

    // -- the wire body -------------------------------------------------------

    @Test
    fun payload_isByteExactWithTheFixedKeyOrder() {
        assertEquals(
            "{\"v\":1,\"platform\":\"android\",\"app\":\"1.6.17\",\"reason\":\"periodic\"," +
                "\"session\":\"a1b2c3d4\",\"t0\":1756989240,\"lines\":[\"+00000.000 D/App: hello\",\"x\"]}",
            DebugLogUploader.payload(
                "android", "1.6.17", "periodic", "a1b2c3d4", ORIGIN_T0,
                listOf("+00000.000 D/App: hello", "x"),
            ),
        )
    }

    @Test
    fun payload_withNoLinesIsStillWellFormed() {
        assertEquals(
            "{\"v\":1,\"platform\":\"ios\",\"app\":\"1.6.17\",\"reason\":\"lock\",\"session\":\"00000000\"," +
                "\"t0\":0,\"lines\":[]}",
            DebugLogUploader.payload("ios", "1.6.17", "lock", "00000000", 0L, emptyList()),
        )
    }

    @Test
    fun payload_escapesEveryString() {
        val body = DebugLogUploader.payload("android", "1.6.17", "connect", "a1b2c3d4", ORIGIN_T0, listOf("a \"quoted\" \\ tab\there"))
        assertTrue(body.contains("\\\"quoted\\\""), body)
        assertTrue(body.contains("\\\\"), body)
        assertTrue(body.contains("\\t"), body)
    }

    @Test
    fun session_isEightLowercaseHexAndStableWithinTheProcess() {
        val s = DebugLogUploader.session
        assertEquals(DebugLogUploader.SESSION_CHARS, s.length, "the session tag is 8 characters")
        assertTrue(s.all { it in '0'..'9' || it in 'a'..'f' }, "lowercase hex only: $s")
        assertEquals(s, DebugLogUploader.session, "drawn once per process, never re-rolled")
    }

    // -- the caps ------------------------------------------------------------

    @Test
    fun buildBatch_sendsTheOldestBatchAndLeavesTheRestPending() {
        val all = (1..700).map { DebugLogUploader.PendingLine(it.toLong(), "12:34:56.789 D/T: mark $it") }

        val batch = DebugLogUploader.buildBatch("android", "1.6.17", "periodic", all)!!

        assertEquals(DebugLogUploader.MAX_LINES_PER_BATCH, batch.lineCount)
        assertEquals(500L, batch.lastSeq, "the cursor moves to the last line actually sent, not to the newest pending")
        assertTrue(batch.body.contains("mark 1\""), "the oldest line goes first")
        assertFalse(batch.body.contains("mark 501\""), "line 501 waits for the next tick")
    }

    @Test
    fun buildBatch_dropsTheOldestBeyondTheBacklogCeiling() {
        val all = (1..3000).map { DebugLogUploader.PendingLine(it.toLong(), "12:34:56.789 D/T: mark $it") }

        val batch = DebugLogUploader.buildBatch("android", "1.6.17", "periodic", all)!!

        // 3000 pending ⇒ keep the newest 2500 (seq 501..3000) ⇒ send the oldest
        // 500 of those (seq 501..1000).
        assertEquals(DebugLogUploader.MAX_LINES_PER_BATCH, batch.lineCount)
        assertEquals(1000L, batch.lastSeq)
        assertTrue(batch.body.contains("mark 501\""), "the backlog ceiling keeps the NEWEST 2500")
        assertFalse(batch.body.contains("mark 500\""), "everything older than the ceiling is dropped")
    }

    @Test
    fun buildBatch_truncatesALineAfterRedaction() {
        val long = "12:34:56.789 D/T: " + "xyzw ".repeat(300)
        val batch = DebugLogUploader.buildBatch("android", "1.6.17", "periodic", pending(1L to long))!!

        val expected = DebugLogUploader
            .toRelativeTime(DebugLogRedactor.redactLine(long), ORIGIN_MS_OF_DAY)
            .substring(0, DebugLogUploader.MAX_LINE_CHARS)
        assertEquals(DebugLogUploader.MAX_LINE_CHARS, expected.length)
        assertTrue(batch.body.contains(expected), "the clipped line is what ships")
        assertFalse(batch.body.contains(long), "the full-length line is not")
    }

    @Test
    fun buildBatch_dropsFromTheNEWESTEndUntilTheBodyFits() {
        // Each line clips to MAX_LINE_CHARS, so ~127 of them fill the 64 KiB
        // ceiling. Dropping must come off the NEW end: a dropped-newest line
        // stays above the cursor and ships next tick, whereas dropping the
        // oldest would lose it the moment the cursor moved past it.
        val body = "xyzw ".repeat(200)
        val all = (1..400).map { DebugLogUploader.PendingLine(it.toLong(), "12:34:56.789 D/T: $it $body") }

        val batch = DebugLogUploader.buildBatch("android", "1.6.17", "periodic", all)!!

        assertTrue(batch.body.encodeToByteArray().size <= DebugLogUploader.MAX_BODY_BYTES, "body ${batch.body.length}")
        assertTrue(batch.lineCount in 2 until DebugLogUploader.MAX_LINES_PER_BATCH, "lineCount=${batch.lineCount}")
        assertEquals(batch.lineCount.toLong(), batch.lastSeq, "the cursor stops at the last line that fit")
    }

    @Test
    fun buildBatch_returnsNullWhenNothingIsPending() {
        assertNull(DebugLogUploader.buildBatch("android", "1.6.17", "periodic", emptyList()))
    }

    @Test
    fun clipLine_replacesControlCharactersSoTheBodyStaysParseable() {
        // jsonEscapeString only knows \n, \r and \t — anything else below 0x20
        // would land raw inside a JSON string literal.
        assertEquals("a b c", DebugLogUploader.clipLine("a\u0000b\u0007c"))
    }

    // -- merge order ---------------------------------------------------------

    @Test
    fun collectPending_mergesBothBuffersIntoOneSeqOrderedStream() {
        DebugLogUploader.resetCursor()
        val at = DebugLogUploader.cursorForTest()

        LogBuffer.append("D", "A", "one")
        ConnectionLog.append(ConnectionLog.Kind.SYSTEM, "two")
        LogBuffer.append("D", "A", "three")
        ConnectionLog.append(ConnectionLog.Kind.RELAY, "four")

        val merged = DebugLogUploader.collectPending(at).sortedBy { it.seq }

        assertEquals(4, merged.size)
        assertTrue(merged[0].formatted.endsWith("D/A: one"), merged[0].formatted)
        assertTrue(merged[1].formatted.endsWith("SYSTEM two"), merged[1].formatted)
        assertTrue(merged[2].formatted.endsWith("D/A: three"), merged[2].formatted)
        assertTrue(merged[3].formatted.endsWith("RELAY four"), merged[3].formatted)
        assertTrue(merged[0].seq < merged[1].seq && merged[1].seq < merged[2].seq && merged[2].seq < merged[3].seq)
    }

    @Test
    fun resetCursor_pointsAtTheCurrentEndOfTheStream() {
        LogBuffer.append("D", "A", "before")
        ConnectionLog.append(ConnectionLog.Kind.SYSTEM, "before")

        DebugLogUploader.resetCursor()

        assertTrue(DebugLogUploader.collectPending(DebugLogUploader.cursorForTest()).isEmpty())
        LogBuffer.append("D", "A", "after")
        assertEquals(1, DebugLogUploader.collectPending(DebugLogUploader.cursorForTest()).size)
    }

    // -- the uploader's own footprint never feeds itself ---------------------
    //
    // TWO mechanisms, and NEITHER is a text filter (the old `isSelfLine`
    // matcher was removed 2026-09-14 — it also blanket-dropped real stuck-
    // stream diagnostics):
    //  1. The transport writes NO log line for the uploader's own POST
    //     (`suppressLog`), so the `POST /debuglog -> 204` echo never exists.
    //  2. The uploader does not WAKE UP for the only remaining echo: the
    //     STREAM_SENT/STREAM_OK narration of the Tor stream its own last POST
    //     opened. Those lines are not filtered — they simply do not justify a
    //     tick, and they ship with the next batch a real line triggers.

    @Test
    fun postBatch_asksTheTransportToSuppressItsOwnLogLine() {
        val relay = RecordingDebugRelay()

        assertTrue(DebugLogUploader.postBatch(relay, RELAY_BASE, "{}"))

        assertEquals(1, relay.requests.size)
        assertTrue(
            relay.requests[0].suppressLog,
            "the uploader's own POST must not be logged — that log line is what fed the 1 Hz loop",
        )
    }

    @Test
    fun relayTransport_forwardsTheLogOptOutThroughMessageManagersObserver() {
        // The uploader never talks to a PlatformHttpClient directly — it gets
        // `messageManager.relayTransport()`, which is MessageManager's own
        // update-nudge OBSERVER wrapper. RelayHttp's six-argument post has a
        // DEFAULT that drops to the five-argument one, so a wrapper that forgets
        // to override it silently discards `suppressLog` and the 1 Hz loop comes
        // back with no compile error anywhere. Pin it here.
        val relay = RecordingDebugRelay()
        val mgr = MessageManager(InMemoryVault(), RELAY_BASE, relay)

        assertTrue(DebugLogUploader.postBatch(mgr.relayTransport(), RELAY_BASE, "{}"))

        assertEquals(1, relay.requests.size)
        assertTrue(
            relay.requests[0].suppressLog,
            "MessageManager's observer wrapper must forward the log opt-out verbatim",
        )
    }

    @Test
    fun flush_skipsATickWhoseOnlyNewLinesNarrateItsOwnPost() = runTest {
        val relay = RecordingDebugRelay()
        // Exactly what one batch POST leaves behind now that the transport's own
        // line is suppressed: the control-event tap's narration of the single
        // Tor stream that POST opened.
        val onlyOwnStream = listOf(
            DebugLogUploader.PendingLine(1L, "12:34:56.789 TOR stream connecting", worthATick = false),
            DebugLogUploader.PendingLine(2L, "12:34:56.789 TOR stream connected", worthATick = false),
        )
        assertTrue(DebugLogUploader.flushTo(relay, RELAY_BASE, "android", "1.6.17", "periodic", source(onlyOwnStream)))
        assertEquals(0, relay.requests.size, "an idle app must POST nothing")

        // One real line makes the tick worth it — and the narration ships WITH
        // it, because nothing is filtered.
        val mixed = listOf(
            DebugLogUploader.PendingLine(3L, "12:34:56.789 TOR stream connecting", worthATick = false),
            DebugLogUploader.PendingLine(4L, "12:34:56.789 D/T: something real"),
            DebugLogUploader.PendingLine(5L, "12:34:56.789 TOR stream failed: TIMEOUT"),
        )
        assertTrue(DebugLogUploader.flushTo(relay, RELAY_BASE, "android", "1.6.17", "periodic", source(mixed)))
        assertEquals(1, relay.requests.size)
        val body = relay.requests[0].bodyText
        assertTrue(body.contains("something real"), body)
        assertTrue(body.contains("stream failed"), "a real stream failure must still ship: $body")
        assertTrue(body.contains("stream connecting"), "nothing is FILTERED — the narration ships too: $body")
    }

    @Test
    fun justifiesTick_onlyTheUploadersOwnStreamNarrationIsNotWorthATick() {
        assertFalse(DebugLogUploader.justifiesTick(ConnectionLog.Code.STREAM_SENT))
        assertFalse(DebugLogUploader.justifiesTick(ConnectionLog.Code.STREAM_OK))
        assertFalse(DebugLogUploader.justifiesTick(null), "uncoded panel narration does not wake the uploader")
        // The diagnostics the old text filter destroyed.
        assertTrue(DebugLogUploader.justifiesTick(ConnectionLog.Code.STREAM_FAILED))
        assertTrue(DebugLogUploader.justifiesTick(ConnectionLog.Code.HSDESC_FAILED))
        assertTrue(DebugLogUploader.justifiesTick(ConnectionLog.Code.APP_BACKGROUNDED))
    }

    @Test
    fun collectPending_marksOnlyTheOwnStreamNarrationAsNotWorthATick() {
        DebugLogUploader.resetCursor()
        val at = DebugLogUploader.cursorForTest()

        ConnectionLog.append(ConnectionLog.Kind.TOR, "stream connecting", ConnectionLog.Code.STREAM_SENT)
        ConnectionLog.append(ConnectionLog.Kind.TOR, "stream failed: TIMEOUT", ConnectionLog.Code.STREAM_FAILED)
        ConnectionLog.append(ConnectionLog.Kind.SYSTEM, "plain narration")
        LogBuffer.append("D", "A", "real work")

        val merged = DebugLogUploader.collectPending(at).sortedBy { it.seq }

        assertEquals(4, merged.size)
        assertFalse(merged[0].worthATick, "our own stream narration")
        assertTrue(merged[1].worthATick, "a stream FAILURE is the point of the feature")
        assertFalse(merged[2].worthATick, "uncoded narration alone does not wake the uploader")
        assertTrue(merged[3].worthATick, "every LogBuffer entry is real app activity")
    }

    // -- FIX 2b: an uneventful Tor stream is not worth UPLOADING --------------
    //
    // >90 % of the lines in the first real-device uploads were per-request
    // plumbing, and the biggest single share was the control-port tap narrating
    // every ordinary stream twice. The PANEL still shows every one of them —
    // the 2026-09-14 review removed the old blanket `isSelfLine` filter exactly
    // because it hid stuck streams from the one surface a stuck user can read.
    // What the uploader ships is now decided by the PAIR: fast ⇒ neither line,
    // slow or failed ⇒ both lines, and the SENT line is held (never dropped)
    // while its outcome is still in flight.

    private fun streamBatch(at: Long, nowMs: Long): DebugLogUploader.Batch? =
        DebugLogUploader.buildBatch(
            "android", "1.6.20", "periodic",
            DebugLogUploader.collectPending(at, nowMs),
        )

    @Test
    fun buildBatch_leavesAnUneventfulStreamPairOutOfTheUpload() {
        DebugLogUploader.resetCursor()
        val at = DebugLogUploader.cursorForTest()
        val t = ORIGIN_EPOCH_MS
        ConnectionLog.appendForTest(ConnectionLog.Kind.TOR, "stream connecting", ConnectionLog.Code.STREAM_SENT, 12L, t)
        ConnectionLog.appendForTest(ConnectionLog.Kind.TOR, "stream connected", ConnectionLog.Code.STREAM_OK, 12L, t + 400L)
        LogBuffer.append("D", "T", "something real")

        val batch = streamBatch(at, t + 500L)!!
        assertFalse(batch.body.contains("stream connecting"), batch.body)
        assertFalse(batch.body.contains("stream connected"), batch.body)
        assertTrue(batch.body.contains("something real"), batch.body)
        // The panel keeps BOTH — only the upload drops them.
        assertTrue(ConnectionLog.snapshotFormatted().any { it.endsWith("stream connecting") })
        assertTrue(ConnectionLog.snapshotFormatted().any { it.endsWith("stream connected") })
    }

    @Test
    fun buildBatch_shipsASlowStreamTOGETHERWithItsSentLine() {
        DebugLogUploader.resetCursor()
        val at = DebugLogUploader.cursorForTest()
        val t = ORIGIN_EPOCH_MS
        ConnectionLog.appendForTest(ConnectionLog.Kind.TOR, "stream connecting", ConnectionLog.Code.STREAM_SENT, 13L, t)
        ConnectionLog.appendForTest(
            ConnectionLog.Kind.TOR, "stream connected", ConnectionLog.Code.STREAM_OK, 13L,
            t + ConnectionLog.SLOW_STREAM_MS + 1L,
        )
        LogBuffer.append("D", "T", "something real")

        val batch = streamBatch(at, t + ConnectionLog.SLOW_STREAM_MS + 100L)!!
        assertTrue(batch.body.contains("stream connecting"), "the START is half the diagnosis: ${batch.body}")
        assertTrue(batch.body.contains("stream connected"), batch.body)
    }

    @Test
    fun buildBatch_shipsAFailedStreamTOGETHERWithItsSentLine() {
        DebugLogUploader.resetCursor()
        val at = DebugLogUploader.cursorForTest()
        val t = ORIGIN_EPOCH_MS
        ConnectionLog.appendForTest(ConnectionLog.Kind.TOR, "stream connecting", ConnectionLog.Code.STREAM_SENT, 14L, t)
        // FAST but FAILED — a failure is never plumbing, whatever it cost.
        ConnectionLog.appendForTest(
            ConnectionLog.Kind.TOR, "stream failed: TIMEOUT", ConnectionLog.Code.STREAM_FAILED, 14L, t + 200L,
        )

        // STREAM_FAILED justifies the tick on its own — no other line needed.
        val batch = streamBatch(at, t + 300L)!!
        assertTrue(batch.body.contains("stream connecting"), batch.body)
        assertTrue(batch.body.contains("stream failed"), batch.body)
    }

    @Test
    fun buildBatch_holdsTheCursorInFrontOfAStreamStillInFlight() {
        DebugLogUploader.resetCursor()
        val at = DebugLogUploader.cursorForTest()
        val t = ORIGIN_EPOCH_MS
        ConnectionLog.appendForTest(ConnectionLog.Kind.TOR, "stream connecting", ConnectionLog.Code.STREAM_SENT, 15L, t)
        LogBuffer.append("D", "T", "something real")

        // Outcome not in yet and the stream is young: undecided ⇒ the batch stops
        // in front of it, so the cursor cannot run past a SENT whose OK is about
        // to prove it worth shipping.
        assertNull(streamBatch(at, t + 100L), "an in-flight stream holds the batch")

        // …and the hold is BOUNDED: a stream still open past the threshold IS
        // the slow case, so it ships and the batch resumes even though no
        // outcome ever arrived.
        val batch = streamBatch(at, t + ConnectionLog.SLOW_STREAM_MS + 1L)!!
        assertTrue(batch.body.contains("stream connecting"), batch.body)
        assertTrue(batch.body.contains("something real"), batch.body)
    }

    @Test
    fun buildBatch_neverHoldsOnTheSessionsLastFlush() {
        // REASON_LOCK is the last flush of the session — the lines just before
        // the app goes away are the entire reason the uploader is incremental
        // rather than a snapshot, so there is no next tick to defer to.
        DebugLogUploader.resetCursor()
        val at = DebugLogUploader.cursorForTest()
        val t = ORIGIN_EPOCH_MS
        ConnectionLog.appendForTest(ConnectionLog.Kind.TOR, "stream connecting", ConnectionLog.Code.STREAM_SENT, 16L, t)
        LogBuffer.append("D", "T", "the last thing that happened")

        val pending = DebugLogUploader.collectPending(at, t + 100L)
        assertNull(
            DebugLogUploader.buildBatch("android", "1.6.20", "periodic", pending),
            "a periodic tick still holds in front of the in-flight stream",
        )
        val onLock = DebugLogUploader.buildBatch("android", "1.6.20", "lock", pending)!!
        assertTrue(onLock.body.contains("the last thing that happened"), onLock.body)
        assertTrue(onLock.body.contains("stream connecting"), onLock.body)
    }

    @Test
    fun streamDisposition_theWholeTable() {
        val t = ORIGIN_EPOCH_MS
        fun line(code: ConnectionLog.Code?, key: Long?, ship: Boolean?) =
            ConnectionLog.Line(t, ConnectionLog.Kind.TOR, "x", code, 1L, key, ship)

        // Not a stream line, or a FAILURE: always ships.
        assertEquals(DebugLogUploader.Disposition.SHIP, DebugLogUploader.streamDisposition(line(null, null, null), t))
        assertEquals(
            DebugLogUploader.Disposition.SHIP,
            DebugLogUploader.streamDisposition(line(ConnectionLog.Code.STREAM_FAILED, 1L, true), t),
        )
        // A stream line with NO pairing key keeps the pre-fix behaviour.
        assertEquals(
            DebugLogUploader.Disposition.SHIP,
            DebugLogUploader.streamDisposition(line(ConnectionLog.Code.STREAM_SENT, null, null), t),
        )
        // Resolved pairs.
        assertEquals(
            DebugLogUploader.Disposition.SKIP,
            DebugLogUploader.streamDisposition(line(ConnectionLog.Code.STREAM_OK, 1L, false), t),
        )
        assertEquals(
            DebugLogUploader.Disposition.SHIP,
            DebugLogUploader.streamDisposition(line(ConnectionLog.Code.STREAM_OK, 1L, true), t),
        )
        // An OK with no SENT partner carries no duration — it is pure plumbing.
        assertEquals(
            DebugLogUploader.Disposition.SKIP,
            DebugLogUploader.streamDisposition(line(ConnectionLog.Code.STREAM_OK, 1L, null), t),
        )
        // An undecided SENT: held while young, shipped once it is slow, and
        // shipped (never held) across a backwards clock step.
        val open = line(ConnectionLog.Code.STREAM_SENT, 1L, null)
        assertEquals(DebugLogUploader.Disposition.HOLD, DebugLogUploader.streamDisposition(open, t + 10L))
        assertEquals(
            DebugLogUploader.Disposition.SHIP,
            DebugLogUploader.streamDisposition(open, t + ConnectionLog.SLOW_STREAM_MS),
        )
        assertEquals(
            DebugLogUploader.Disposition.SHIP,
            DebugLogUploader.streamDisposition(open, t - 60_000L),
            "a backwards clock step must never stall the cursor",
        )
    }

    @Test
    fun streamPairing_keepsTheTorStreamIdOffThePanelAndOffTheWire() {
        DebugLogUploader.resetCursor()
        val at = DebugLogUploader.cursorForTest()
        val t = ORIGIN_EPOCH_MS
        val streamId = 987654321L
        ConnectionLog.appendForTest(ConnectionLog.Kind.TOR, "stream connecting", ConnectionLog.Code.STREAM_SENT, streamId, t)
        ConnectionLog.appendForTest(
            ConnectionLog.Kind.TOR, "stream failed: TIMEOUT", ConnectionLog.Code.STREAM_FAILED, streamId, t + 200L,
        )

        for (rendered in ConnectionLog.snapshotFormatted()) {
            assertFalse(rendered.contains("$streamId"), "the stream id must never reach the panel: $rendered")
        }
        val batch = streamBatch(at, t + 300L)!!
        assertFalse(batch.body.contains("$streamId"), "the stream id must never reach the wire: ${batch.body}")
        // The pairing itself still worked — both lines are in the batch.
        assertTrue(batch.body.contains("stream connecting"))
        assertTrue(batch.body.contains("stream failed"))
    }

    // -- the cursor / flush semantics ----------------------------------------

    @Test
    fun flush_postsTheBatchAndAdvancesTheCursorOn204() = runTest {
        val relay = RecordingDebugRelay()
        val lines = pending(1L to "12:34:56.789 D/T: one", 2L to "12:34:56.789 D/T: two", 3L to "12:34:56.789 D/T: three")

        val ok = DebugLogUploader.flushTo(relay, RELAY_BASE, "android", "1.6.17", "periodic", source(lines))

        assertTrue(ok)
        assertEquals(1, relay.requests.size)
        val call = relay.requests[0]
        assertEquals("$RELAY_BASE${DebugLogUploader.PATH}", call.url)
        assertEquals("application/json; charset=utf-8", call.contentType)
        assertEquals(emptyMap<String, String>(), call.headers, "no auth, no capability, no custom header — ever")
        assertEquals(DebugLogUploader.HTTP_TIMEOUT_SECONDS, call.timeoutSeconds)
        assertTrue(call.bodyText.startsWith("{\"v\":1,\"platform\":\"android\",\"app\":\"1.6.17\",\"reason\":\"periodic\","), call.bodyText)
        assertEquals(3L, DebugLogUploader.cursorForTest())

        // A second tick with nothing new must not post again.
        assertTrue(DebugLogUploader.flushTo(relay, RELAY_BASE, "android", "1.6.17", "periodic", source(lines)))
        assertEquals(1, relay.requests.size)
    }

    @Test
    fun flush_leavesTheCursorAndResendsTheSameLinesAfterAFailure() = runTest {
        val lines = pending(1L to "12:34:56.789 D/T: one", 2L to "12:34:56.789 D/T: two", 3L to "12:34:56.789 D/T: three")

        val failing = RecordingDebugRelay(scripted = HttpResult(500, null, false))
        assertFalse(DebugLogUploader.flushTo(failing, RELAY_BASE, "android", "1.6.17", "periodic", source(lines)))
        assertEquals(0L, DebugLogUploader.cursorForTest(), "a non-204 must not advance the cursor")

        // Each failed periodic POST arms the backoff (its own test below); the
        // seam disarms it so this test stays about the cursor.
        DebugLogUploader.setCursorForTest(0L)
        val throwing = RecordingDebugRelay(throwOnPost = true)
        assertFalse(DebugLogUploader.flushTo(throwing, RELAY_BASE, "android", "1.6.17", "periodic", source(lines)))
        assertEquals(0L, DebugLogUploader.cursorForTest(), "a transport failure must not advance the cursor either")

        DebugLogUploader.setCursorForTest(0L)
        val ok = RecordingDebugRelay()
        assertTrue(DebugLogUploader.flushTo(ok, RELAY_BASE, "android", "1.6.17", "periodic", source(lines)))
        assertEquals(failing.requests[0].bodyText, ok.requests[0].bodyText, "the same lines go again on the next tick")
        assertEquals(3L, DebugLogUploader.cursorForTest())
    }

    @Test
    fun flush_isANoOpWithNothingPending() = runTest {
        val relay = RecordingDebugRelay()
        assertTrue(DebugLogUploader.flushTo(relay, RELAY_BASE, "android", "1.6.17", "periodic") { emptyList() })
        assertEquals(0, relay.requests.size)
    }

    @Test
    fun flush_failsWithoutATransportOrARelayAndKeepsTheLinesPending() = runTest {
        val lines = pending(1L to "12:34:56.789 D/T: one")

        assertFalse(DebugLogUploader.flushTo(null, RELAY_BASE, "android", "1.6.17", "periodic", source(lines)))
        assertEquals(0L, DebugLogUploader.cursorForTest())

        val relay = RecordingDebugRelay()
        assertFalse(DebugLogUploader.flushTo(relay, "", "android", "1.6.17", "periodic", source(lines)))
        assertEquals(0, relay.requests.size)
        assertEquals(0L, DebugLogUploader.cursorForTest())
    }

    @Test
    fun flush_refusesAPlatformOrReasonOutsideTheClosedVocabulary() = runTest {
        val relay = RecordingDebugRelay()
        val lines = pending(1L to "12:34:56.789 D/T: one")

        assertFalse(DebugLogUploader.flushTo(relay, RELAY_BASE, "linux", "1.6.17", "periodic", source(lines)))
        assertFalse(DebugLogUploader.flushTo(relay, RELAY_BASE, "android", "1.6.17", "whatever", source(lines)))
        assertEquals(0, relay.requests.size)

        for (reason in listOf(DebugLogUploader.REASON_CONNECT, DebugLogUploader.REASON_PERIODIC, DebugLogUploader.REASON_LOCK)) {
            DebugLogUploader.setCursorForTest(0L)
            assertTrue(DebugLogUploader.flushTo(relay, RELAY_BASE, "ios", "1.6.17", reason, source(lines)))
        }
        assertEquals(3, relay.requests.size)
    }

    @Test
    fun flush_uploadsNothingWhileLoggingIsOff() = runTest {
        // In a RELEASE build LoggingState.enabled is true if and only if the
        // user consented, so this is the structural guard against a stray tick.
        LoggingState.enabled = false
        val relay = RecordingDebugRelay()
        val lines = pending(1L to "12:34:56.789 D/T: one")

        assertTrue(DebugLogUploader.flushTo(relay, RELAY_BASE, "android", "1.6.17", "periodic", source(lines)))

        assertEquals(0, relay.requests.size)
        assertEquals(0L, DebugLogUploader.cursorForTest())
    }

    @Test
    fun flush_neverRunsTwoAtOnce() = runTest {
        val relay = RecordingDebugRelay()
        val lines = pending(1L to "12:34:56.789 D/T: one")

        assertTrue(DebugLogUploader.tryBeginFlush(), "precondition: the latch is free")
        try {
            assertFalse(DebugLogUploader.tryBeginFlush(), "the latch is exclusive")
            assertTrue(
                DebugLogUploader.flushTo(relay, RELAY_BASE, "android", "1.6.17", "periodic", source(lines)),
                "a tick that finds a flush in flight returns immediately rather than queueing",
            )
            assertEquals(0, relay.requests.size)
            assertEquals(0L, DebugLogUploader.cursorForTest())
        } finally {
            DebugLogUploader.endFlush()
        }
        assertTrue(DebugLogUploader.flushTo(relay, RELAY_BASE, "android", "1.6.17", "periodic", source(lines)))
        assertEquals(1, relay.requests.size)
    }

    // -- the redactor --------------------------------------------------------

    @Test
    fun redactLine_keepsBothPrefixShapesVerbatim() {
        assertTrue(
            DebugLogRedactor.redactLine("12:34:56.789 D/MessageManager: envelope sealed").startsWith("12:34:56.789 D/MessageManager: "),
            "the LogBuffer prefix is kept as-is",
        )
        assertTrue(
            DebugLogRedactor.redactLine("12:34:56.789 TOR bootstrap continues").startsWith("12:34:56.789 TOR "),
            "the ConnectionLog prefix is kept as-is",
        )
        // A tag with digits must survive precisely BECAUSE the prefix is excluded.
        assertTrue(DebugLogRedactor.redactLine("12:34:56.789 W/Argon2id: cost pinned").startsWith("12:34:56.789 W/Argon2id: "))
    }

    @Test
    fun redactLine_keepsPureLetterClassNamesAndSmallNumbers() {
        val out = DebugLogRedactor.redactLine("12:34:56.789 D/App: MessageManager handed the envelope to RatchetManager in 3 ms")
        assertTrue(out.contains("MessageManager"), out)
        assertTrue(out.contains("RatchetManager"), out)
        assertTrue(out.contains("envelope"), out)
        assertTrue(out.contains(" 3 ms"), out)
    }

    @Test
    fun leakSweep_noIdentifyingSubstringSurvivesARealisticBatch() {
        val lines = listOf(
            "12:34:56.789 D/MessageManager: PeekTarget(contactId=$CONTACT_ID_18, inboxId=$INBOX_ID_32, readCap=$CAP_43)",
            "12:34:56.789 D/Contacts: contact added: \"Bob Andersson\" ($SHORT_ID_8)",
            "12:34:56.789 D/Relay: POST https://jtlc2qrstuvwxyzabcdefghijklmnop234567.onion/inbox/abc",
            "12:34:56.789 TOR Bootstrapped 45% (requesting_descriptors): Loading relay descriptors",
            "12:34:56.789 RELAY probe to 1.2.3.4:9001 failed",
            "12:34:56.789 RELAY probe to [2001:db8::1]:443 failed",
            "12:34:56.789 RELAY guard 2001:db8:85a3::8a2e:370:7334 dropped",
            "12:34:56.789 D/Sync: last opened at 1757000000000 ms",
            "12:34:56.789 D/Tor: guard fingerprint $FINGERPRINT_40",
            "12:34:56.789 D/Vault: db at /var/mobile/Containers/Data/Application/DEADBEEF-1234-5678-9ABC-DEF012345678/Documents/run.db",
            "12:34:56.789 D/Contacts: alias=Bob Andersson added to group",
            "12:34:56.789 D/Group: title='Family dinner' body='see you at 7'",
        )

        val redacted = lines.joinToString("\n") { DebugLogRedactor.redactLine(it) }

        val mustNotSurvive = listOf(
            CONTACT_ID_18,
            INBOX_ID_32,
            CAP_43,
            SHORT_ID_8,
            FINGERPRINT_40,
            "Bob",
            "Andersson",
            "Family",
            "dinner",
            "see you at",
            ".onion",
            "jtlc2",
            "https://",
            "1.2.3.4",
            "9001",
            "2001:db8",
            "443",
            "1757000000000",
            "/var/mobile",
            "Containers",
            "DEADBEEF",
            "run.db",
        )
        for (secret in mustNotSurvive) {
            assertFalse(redacted.contains(secret), "LEAK: \"$secret\" survived redaction\n$redacted")
        }

        val mustSurvive = listOf(
            "12:34:56.789 D/MessageManager: ",
            "12:34:56.789 TOR ",
            "PeekTarget",
            "contactId=",
            // Rule 3b deliberately eats the word after a BARE label token, so
            // `contact added:` reads `contact [id]:`. Losing a word of
            // narration is the price of catching `contact aB3dEfG7`.
            "contact [id]:",
            "Bootstrapped",
            "45%",
            "Loading relay descriptors",
            "probe to",
            "failed",
            "guard fingerprint",
            "last opened at",
            " ms",
            "alias=",
            "title=",
        )
        for (kept in mustSurvive) {
            assertTrue(redacted.contains(kept), "over-redacted: \"$kept\" was lost\n$redacted")
        }
    }

    @Test
    fun leakSweep_theShapesEachLandOnTheirOwnPlaceholder() {
        assertEquals(
            // inboxId lands on [id] via rule 3b (the LABEL), not on [hex] via
            // rule 4 — the label fires first and does not care what the value
            // looks like, which is the whole point of it.
            "12:34:56.789 D/M: PeekTarget(contactId=[id], inboxId=[id], readCap=[id])",
            DebugLogRedactor.redactLine("12:34:56.789 D/M: PeekTarget(contactId=$CONTACT_ID_18, inboxId=$INBOX_ID_32, readCap=$CAP_43)"),
        )
        assertEquals(
            "12:34:56.789 RELAY probe to [ip] failed",
            DebugLogRedactor.redactLine("12:34:56.789 RELAY probe to 1.2.3.4:9001 failed"),
        )
        assertEquals(
            "12:34:56.789 RELAY probe to [ip] failed",
            DebugLogRedactor.redactLine("12:34:56.789 RELAY probe to [2001:db8::1]:443 failed"),
        )
        assertEquals(
            "12:34:56.789 D/R: GET [url]",
            DebugLogRedactor.redactLine("12:34:56.789 D/R: GET https://abcdefghijklmnopqrstuvwxyz234567.onion/inbox"),
        )
        assertEquals(
            "12:34:56.789 D/R: host [onion] unreachable",
            DebugLogRedactor.redactLine("12:34:56.789 D/R: host abcdefghijklmnopqrstuvwxyz234567.onion unreachable"),
        )
        assertEquals(
            "12:34:56.789 D/S: last opened at [num] ms",
            DebugLogRedactor.redactLine("12:34:56.789 D/S: last opened at 1757000000000 ms"),
        )
        assertEquals(
            "12:34:56.789 D/V: db at [path]",
            DebugLogRedactor.redactLine("12:34:56.789 D/V: db at /var/mobile/Containers/Data/Application/DEADBEEF-1234/Documents/run.db"),
        )
        assertEquals(
            "12:34:56.789 D/C: alias=[str]",
            DebugLogRedactor.redactLine("12:34:56.789 D/C: alias=Bob Andersson added to group"),
        )
        assertEquals(
            "12:34:56.789 D/C: added [str] as a contact",
            DebugLogRedactor.redactLine("12:34:56.789 D/C: added \"Bob Andersson\" as a contact"),
        )
        assertEquals(
            "12:34:56.789 TOR Bootstrapped 45% ([id]): Loading relay descriptors",
            DebugLogRedactor.redactLine("12:34:56.789 TOR Bootstrapped 45% (requesting_descriptors): Loading relay descriptors"),
        )
    }

    // -- rule 3's Tor REASON passthrough (2026-10-23) -------------------------

    @Test
    fun torReasonKeywords_surviveRuleThree() {
        assertEquals(
            "12:34:56.789 TOR descriptor fetch failed: QUERY_NO_HSDIR",
            DebugLogRedactor.redactLine("12:34:56.789 TOR descriptor fetch failed: QUERY_NO_HSDIR"),
        )
        assertEquals(
            "12:34:56.789 TOR rendezvous circuit failed: CHANNEL_CLOSED",
            DebugLogRedactor.redactLine("12:34:56.789 TOR rendezvous circuit failed: CHANNEL_CLOSED"),
        )
        // Every keyword on the list, one by one, in a realistic panel line.
        for (word in TorReasonVocabulary.DEBUG_PASSTHROUGH) {
            val line = "12:34:56.789 TOR descriptor fetch failed: $word"
            assertEquals(line, DebugLogRedactor.redactLine(line), word)
        }
    }

    @Test
    fun torReasonPassthrough_stillStripsInboxIdsOnionsAndCapabilities() {
        // The same line shapes as above, carrying the identifiers the exception
        // must NEVER let through — beside a passing keyword, glued to one, and
        // in a raw Tor control event as debug mode could see it.
        val onion = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv.onion"
        val lines = listOf(
            "12:34:56.789 TOR descriptor fetch failed: QUERY_NO_HSDIR $INBOX_ID_32",
            "12:34:56.789 TOR descriptor fetch failed: NOT_FOUND $CAP_43",
            "12:34:56.789 TOR descriptor fetch failed: BAD_DESC $onion",
            "12:34:56.789 D/Tor: HS_DESC FAILED $onion NO_AUTH \$$FINGERPRINT_40~moria1 REASON=NOT_FOUND",
            // Glued: the run is maximal over [A-Za-z0-9_-], so these are NOT a keyword.
            "12:34:56.789 TOR descriptor fetch failed: NOT_FOUND_$INBOX_ID_32",
            "12:34:56.789 TOR descriptor fetch failed: ${CAP_43}_NOT_FOUND",
            "12:34:56.789 TOR descriptor fetch failed: QUERY_NO_HSDIR-$CONTACT_ID_18",
        )
        val secrets = listOf(INBOX_ID_32, CAP_43, onion, "abcdefghijklmnopqrstuvwxyz234567", FINGERPRINT_40, CONTACT_ID_18)
        for (line in lines) {
            val out = DebugLogRedactor.redactLine(line)
            for (secret in secrets) {
                assertFalse(out.contains(secret), "leaked $secret from: $line → $out")
            }
        }
        // The keyword next to a stripped id still reads; the id does not.
        assertEquals(
            "12:34:56.789 TOR descriptor fetch failed: QUERY_NO_HSDIR [hex]",
            DebugLogRedactor.redactLine("12:34:56.789 TOR descriptor fetch failed: QUERY_NO_HSDIR $INBOX_ID_32"),
        )
        assertEquals(
            "12:34:56.789 TOR descriptor fetch failed: [id]",
            DebugLogRedactor.redactLine("12:34:56.789 TOR descriptor fetch failed: NOT_FOUND_$INBOX_ID_32"),
        )
    }

    @Test
    fun torReasonPassthrough_isCaseSensitiveAndWholeWordOnly() {
        // A lower-case or partial look-alike is not a Tor keyword and keeps the
        // general rule's placeholder — the exception is an allowlist, not a shape.
        assertEquals(
            "12:34:56.789 D/X: [id] [id] [id]",
            DebugLogRedactor.redactLine("12:34:56.789 D/X: query_no_hsdir QUERY_NO_HSDIRS XQUERY_NO_HSDIR"),
        )
        // The pinned bootstrap-tag behaviour is unchanged (tags are NOT on the list).
        assertEquals(
            "12:34:56.789 TOR Bootstrapped 45% ([id]): Loading relay descriptors",
            DebugLogRedactor.redactLine("12:34:56.789 TOR Bootstrapped 45% (requesting_descriptors): Loading relay descriptors"),
        )
    }

    @Test
    fun redactLine_leavesAnApostropheAloneButNotAQuotedName() {
        val out = DebugLogRedactor.redactLine("12:34:56.789 D/T: the daemon's own phase line")
        assertTrue(out.contains("daemon's own phase line"), out)
        assertEquals(
            "12:34:56.789 D/T: group [str] renamed",
            DebugLogRedactor.redactLine("12:34:56.789 D/T: group 'Family dinner' renamed"),
        )
    }

    @Test
    fun redactLine_withNoClockPrefixRedactsTheWholeLine() {
        val out = DebugLogRedactor.redactLine("contactId=$CONTACT_ID_18")
        assertFalse(out.contains(CONTACT_ID_18), out)
    }

    // -- rules 3a/3b/3c: the truncated-prefix hole ---------------------------

    @Test
    fun leakSweep_noTruncatedInboxPrefixSurvives() {
        // THE FINDING (2026-09-14): ~25 producers log `${inboxId.take(8)}...`,
        // and rule 3 alone only takes a run that holds a digit or a `-`/`_`.
        // An 8-char base64url prefix is ALL LETTERS with probability
        // (52/64)^8 − (12/64)^8 ≈ 19 %, so roughly one prefix in five used to
        // ship verbatim. Rules 3a (the `...`/`…` truncation marker) and 3b (the
        // label) key on the CONTEXT instead of the contents, so the letters in
        // the prefix stop mattering. 20 000 ids × the three shapes this app
        // renders them in — zero survivors, or this is a privacy bug.
        val rng = SeededLcg(0x5EEDL)
        var allLetterPrefixes = 0
        var checked = 0
        for (n in 0 until 20_000) {
            val prefix = rng.b64Url(32).substring(0, 8)
            if (prefix.all { it in 'A'..'Z' || it in 'a'..'z' }) allLetterPrefixes++
            val lines = listOf(
                "12:34:56.789 D/MessageManager: sending 3072b to inbox $prefix...",
                "12:34:56.789 D/MessageManager: inbox=$prefix",
                "12:34:56.789 D/MessageManager: PeekTarget(contactId=$prefix\u2026, inboxId=$prefix\u2026, readCap=[redacted])",
            )
            for (line in lines) {
                val out = DebugLogRedactor.redactLine(line)
                assertFalse(out.contains(prefix), "LEAK: prefix \"$prefix\" survived\n  in: $line\n out: $out")
                checked++
            }
        }
        assertEquals(60_000, checked)
        // Sanity: the simulation really is exercising the hole. ~19 % of 20 000
        // is ≈ 3 800; anything in this window proves the generator is drawing
        // realistic base64url and that pure-letter prefixes are common, not rare.
        assertTrue(allLetterPrefixes in 3_000..4_600, "all-letter prefixes: $allLetterPrefixes of 20000")
    }

    @Test
    fun leakSweep_theTruncatedShapesLandOnTheirPlaceholder() {
        // The three shapes above, spelled out — so a regression says WHICH rule
        // broke instead of only "something leaked".
        assertEquals(
            "12:34:56.789 D/M: sending 3072b to inbox [id]...",
            DebugLogRedactor.redactLine("12:34:56.789 D/M: sending 3072b to inbox aBcDeFgH..."),
        )
        assertEquals(
            "12:34:56.789 D/M: inbox=[id]",
            DebugLogRedactor.redactLine("12:34:56.789 D/M: inbox=aBcDeFgH"),
        )
        assertEquals(
            "12:34:56.789 D/M: PeekTarget(contactId=[id]\u2026, inboxId=[id]\u2026, readCap=[redacted])",
            DebugLogRedactor.redactLine("12:34:56.789 D/M: PeekTarget(contactId=aBcDeFgH\u2026, inboxId=zYxWvUtS\u2026, readCap=[redacted])"),
        )
        // A bare, unmarked, unlabelled pure-letter prefix with 3+ lower→upper
        // transitions is still caught by rule 3c.
        assertEquals(
            "12:34:56.789 D/M: peek [id] done",
            DebugLogRedactor.redactLine("12:34:56.789 D/M: peek aBcDeFgH done"),
        )
    }

    @Test
    fun redactLine_keepsTheNamesTheLogsAreWrittenAround() {
        // Rule 3c must not mangle hand-written CamelCase: every name below has
        // at most 2 lower→upper transitions, random base64url letters far more.
        val names = listOf(
            "MessageManager", "ReferralManager", "GroupManager", "Bootstrapped",
            "PeekTarget", "KeychainHelper", "TorManager",
        )
        val out = DebugLogRedactor.redactLine("12:34:56.789 D/App: " + names.joinToString(" "))
        for (name in names) {
            assertTrue(out.contains(name), "over-redacted: \"$name\" was lost\n$out")
            assertTrue(
                DebugLogRedactor.lowerToUpperTransitions(name) < DebugLogRedactor.MIN_CASE_TRANSITIONS,
                "$name has ${DebugLogRedactor.lowerToUpperTransitions(name)} transitions",
            )
        }
        // `requesting_descriptors` (the Tor phase TAG) is untouched by the three
        // new rules — it is not ellipsis-marked, not label-preceded, and not a
        // pure-letter run — and keeps landing on [id] through rule 3's `_`, the
        // behaviour pinned since the redactor was written. The phase PROSE next
        // to it is what a developer reads, and that survives.
        assertEquals(
            "12:34:56.789 TOR Bootstrapped 45% ([id]): Loading relay descriptors",
            DebugLogRedactor.redactLine("12:34:56.789 TOR Bootstrapped 45% (requesting_descriptors): Loading relay descriptors"),
        )
    }

    // -- rule 7: contact-graph counts ----------------------------------------

    @Test
    fun redactLine_bucketsCountsOfContactsAndInboxes() {
        assertEquals(
            "12:34:56.789 D/C: control poll done: 6-20 contacts in 4.2 s",
            DebugLogRedactor.redactLine("12:34:56.789 D/C: control poll done: 17 contacts in 4.2 s"),
        )
        assertEquals(
            "12:34:56.789 D/G: 0 groups, 1-5 members, 6-20 peers, 20+ inboxes, 1-5 rows",
            DebugLogRedactor.redactLine("12:34:56.789 D/G: 0 groups, 3 members, 20 peers, 21 inboxes, 1 rows"),
        )
        // Only a count NOUN triggers it — timings, percentages and versions are
        // exactly the kind of number the logs are uploaded for.
        assertEquals(
            "12:34:56.789 TOR Bootstrapped 45% in 4.2 s after 3 probes",
            DebugLogRedactor.redactLine("12:34:56.789 TOR Bootstrapped 45% in 4.2 s after 3 probes"),
        )
    }

    // -- rule 7, FIX 1: a `key=` VALUE is never a count -----------------------
    //
    // THE BUG (found in the first real-device uploads, 2026-09-15): every batch
    // carried `poll → code=20+ inbox=[id]` and `send → code=20+ inbox=[id]`.
    // The real status was 200 / 202 — rule 7 rewrote it, because "200" is a
    // standalone digit run and the count noun `inbox` follows it with exactly
    // one space. It survived at all only because the (now removed, fix 2a)
    // duplicate `TorHttp: GET ← code=200` line still carried the status.

    @Test
    fun redactLine_keepsAnHttpStatusThatACountNounFollows() {
        for (code in listOf(200, 202, 404, 429, 500)) {
            assertEquals(
                "12:34:56.789 D/MessageManager: poll → code=$code inbox=[id]",
                DebugLogRedactor.redactLine("12:34:56.789 D/MessageManager: poll → code=$code inbox=$INBOX_ID_32"),
                "the HTTP status must survive rule 7",
            )
            assertEquals(
                "12:34:56.789 D/MessageManager: send → code=$code inbox=[id]",
                DebugLogRedactor.redactLine("12:34:56.789 D/MessageManager: send → code=$code inbox=${SHORT_ID_8}"),
            )
        }
        // Any `<word>=` label, not just `code=` — and the transport's own line,
        // which is the other place a status meets a redacted path.
        assertEquals(
            "12:34:56.789 D/H: status=404 inbox=[id]",
            DebugLogRedactor.redactLine("12:34:56.789 D/H: status=404 inbox=$INBOX_ID_32"),
        )
        assertEquals(
            "12:34:56.789 D/HttpClient: GET [path] → 200",
            DebugLogRedactor.redactLine("12:34:56.789 D/HttpClient: GET /inbox/$INBOX_ID_32/peek → 200"),
        )
    }

    @Test
    fun redactLine_stillBucketsARealCountOnTheSameLineAsAStatus() {
        // Both halves of the rule, in one line: the count noun's own number is
        // bucketed, the labelled status next to it is not.
        assertEquals(
            "12:34:56.789 D/G: sent 1-5 contacts code=200 inbox=x",
            DebugLogRedactor.redactLine("12:34:56.789 D/G: sent 3 contacts code=200 inbox=x"),
        )
        // The panel line the sweep actually writes — unchanged by fix 1.
        assertEquals(
            "12:34:56.789 RELAY control poll done: 6-20 contacts in 15.3 s",
            DebugLogRedactor.redactLine("12:34:56.789 RELAY control poll done: 17 contacts in 15.3 s"),
        )
        // `0` is still exact, and a bare `=` with no key is still ordinary.
        assertEquals(
            "12:34:56.789 D/G: 0 contacts",
            DebugLogRedactor.redactLine("12:34:56.789 D/G: 0 contacts"),
        )
        assertEquals(
            "12:34:56.789 D/G: = 6-20 contacts",
            DebugLogRedactor.redactLine("12:34:56.789 D/G: = 17 contacts"),
        )
    }

    @Test
    fun leakSweep_theStatusFixNarrowsRuleSevenAndNothingElse() {
        // Fix 1 only NARROWS what rule 7 buckets, so it cannot weaken any
        // identifier rule — but prove it rather than argue it: the same seeded
        // sweep, now with the `code=NNN inbox=<id>` shape that triggered the bug
        // added as a fourth rendering. 20 000 ids × 4 shapes, zero survivors.
        val rng = SeededLcg(0x5EEDL)
        var checked = 0
        for (n in 0 until 20_000) {
            val id = rng.b64Url(32)
            val prefix = id.substring(0, 8)
            val lines = listOf(
                "12:34:56.789 D/MessageManager: poll → code=200 inbox=$prefix ",
                "12:34:56.789 D/MessageManager: send → code=202 inbox=$id",
                "12:34:56.789 D/MessageManager: sending 3072b to inbox $prefix...",
                "12:34:56.789 D/MessageManager: peek 17 contacts inbox=$prefix\u2026",
            )
            for (line in lines) {
                val out = DebugLogRedactor.redactLine(line)
                assertFalse(out.contains(prefix), "LEAK: \"$prefix\" survived\n  in: $line\n out: $out")
                checked++
            }
        }
        assertEquals(80_000, checked)
    }

    // -- rule 4c: paths, not ratios ------------------------------------------

    @Test
    fun redactLine_keepsRatiosButStillEatsPaths() {
        // `digits/digits` is a ratio, not a path: no file name, no user name, no
        // container UUID — nothing in it to redact.
        assertEquals(
            "12:34:56.789 D/U: unread prime done: 3/3 answered in 61.0 s",
            DebugLogRedactor.redactLine("12:34:56.789 D/U: unread prime done: 3/3 answered in 61.0 s"),
        )
        assertEquals(
            "12:34:56.789 D/R: send failed, retry 1/4, backing off",
            DebugLogRedactor.redactLine("12:34:56.789 D/R: send failed, retry 1/4, backing off"),
        )
        // A real path still goes, by either of the two triggers.
        assertEquals(
            "12:34:56.789 D/V: db at [path]",
            DebugLogRedactor.redactLine("12:34:56.789 D/V: db at /data/user/0/com.vg.run/files/run.db"),
        )
        assertEquals(
            "12:34:56.789 D/V: log at [path]",
            DebugLogRedactor.redactLine("12:34:56.789 D/V: log at ~/Library/Logs/run.log"),
        )
    }

    // -- the relative clock --------------------------------------------------

    @Test
    fun toRelativeTime_rewritesBothPrefixShapes() {
        // "Now" is pinned next to the origin (an hour on): since 2026-10-26 a line's
        // time-of-day is resolved to the instant it names relative to now, so the
        // offset keeps counting past the origin's time-of-day on a multi-day process.
        val now = ORIGIN_EPOCH_MS + 3_600_000L
        assertEquals(
            "+00000.000 D/T: at the origin",
            DebugLogUploader.toRelativeTime("12:34:56.789 D/T: at the origin", ORIGIN_MS_OF_DAY, now),
        )
        assertEquals(
            "+00012.211 TOR bootstrap continues",
            DebugLogUploader.toRelativeTime("12:35:09.000 TOR bootstrap continues", ORIGIN_MS_OF_DAY, now),
        )
        assertEquals(
            "+03600.000 D/T: an hour later",
            DebugLogUploader.toRelativeTime("13:34:56.789 D/T: an hour later", ORIGIN_MS_OF_DAY, now),
        )
        // Not a clock prefix ⇒ untouched, which is the safe direction: nothing
        // is invented and nothing is cut.
        assertEquals("no clock here at all", DebugLogUploader.toRelativeTime("no clock here at all", ORIGIN_MS_OF_DAY, now))
        assertEquals("99:99:99.999 D/T: not a time", DebugLogUploader.toRelativeTime("99:99:99.999 D/T: not a time", ORIGIN_MS_OF_DAY, now))
        // No origin pinned yet ⇒ also untouched.
        assertEquals("12:34:56.789 D/T: x", DebugLogUploader.toRelativeTime("12:34:56.789 D/T: x", -1, now))
    }

    @Test
    fun toRelativeTime_treatsASmallerTimeOfDayAsTheNextDay() {
        // 23:59:59.000 origin, line at 00:00:01.000 ⇒ two seconds later, not
        // −86398. A negative offset would reorder the batch on the relay side.
        val origin = 23 * 3_600_000 + 59 * 60_000 + 59_000
        // The origin pin is (time-of-day, epoch) — keep the pair consistent (same UTC day
        // as ORIGIN_EPOCH_MS) and pin "now" two seconds after it.
        val originEpoch = ORIGIN_EPOCH_MS - ORIGIN_MS_OF_DAY + origin
        DebugLogUploader.setOriginForTest(origin, originEpoch)
        val now = originEpoch + 2_000L
        assertEquals("+00002.000 D/T: after midnight", DebugLogUploader.toRelativeTime("00:00:01.000 D/T: after midnight", origin, now))
        // A SMALL negative delta is NOT a wrap: the two buffers read their
        // clocks under different locks, so a line can carry a timestamp a few
        // ms older than a lower-seq line. That clamps to the origin instead of
        // rendering a day in the future.
        assertEquals("+00000.000 D/T: a hair early", DebugLogUploader.toRelativeTime("23:59:58.999 D/T: a hair early", origin, now))
        assertEquals("+00000.000 D/T: a minute early", DebugLogUploader.toRelativeTime("23:58:59.000 D/T: a minute early", origin, now))
        // Half a day on from a noon origin, the next midnight is +43199 s and a line
        // one second BEFORE that origin still clamps (it resolves to yesterday's
        // instant, 1 s before the origin — never a day in the future).
        val noonOrigin = 12 * 3_600_000 + 1_000
        val noonEpoch = ORIGIN_EPOCH_MS - ORIGIN_MS_OF_DAY + noonOrigin
        DebugLogUploader.setOriginForTest(noonOrigin, noonEpoch)
        val midnight = noonEpoch + 43_199_000L
        assertEquals("+43199.000 D/T: next midnight", DebugLogUploader.toRelativeTime("00:00:00.000 D/T: next midnight", noonOrigin, midnight))
        assertEquals("+00000.000 D/T: one second early", DebugLogUploader.toRelativeTime("12:00:00.000 D/T: one second early", noonOrigin, midnight))
    }

    @Test
    fun flush_periodicBacksOffAfterAFailedPostButOneShotsStillTry() = runTest {
        val relay = RecordingDebugRelay(scripted = HttpResult(502, null, false))
        val lines = pending(1L to "12:34:56.789 D/T: one")

        assertFalse(DebugLogUploader.flushTo(relay, RELAY_BASE, "android", "1.6.17", "periodic", source(lines)))
        assertEquals(1, relay.requests.size)
        assertTrue(DebugLogUploader.periodicRetryAtForTest() > 0L, "a failed periodic POST arms the backoff")

        // The very next tick is damped: no POST, no redaction pass.
        assertFalse(DebugLogUploader.flushTo(relay, RELAY_BASE, "android", "1.6.17", "periodic", source(lines)))
        assertEquals(1, relay.requests.size)

        // A connect or lock flush is a one-shot and is never damped.
        assertFalse(DebugLogUploader.flushTo(relay, RELAY_BASE, "android", "1.6.17", "lock", source(lines)))
        assertFalse(DebugLogUploader.flushTo(relay, RELAY_BASE, "android", "1.6.17", "connect", source(lines)))
        assertEquals(3, relay.requests.size)

        // A cursor reset (consent change / wipe / test seam) disarms it.
        DebugLogUploader.setCursorForTest(0L)
        assertEquals(0L, DebugLogUploader.periodicRetryAtForTest())
        assertFalse(DebugLogUploader.flushTo(relay, RELAY_BASE, "android", "1.6.17", "periodic", source(lines)))
        assertEquals(4, relay.requests.size)
    }

    @Test
    fun flush_aSuccessfulPostDisarmsThePeriodicBackoff() = runTest {
        val failing = RecordingDebugRelay(scripted = HttpResult(500, null, false))
        val lines = pending(1L to "12:34:56.789 D/T: one")
        assertFalse(DebugLogUploader.flushTo(failing, RELAY_BASE, "ios", "1.6.17", "periodic", source(lines)))
        assertTrue(DebugLogUploader.periodicRetryAtForTest() > 0L)

        // The lock flush (never damped) succeeds → backoff cleared, cursor moved.
        val ok = RecordingDebugRelay()
        assertTrue(DebugLogUploader.flushTo(ok, RELAY_BASE, "ios", "1.6.17", "lock", source(lines)))
        assertEquals(0L, DebugLogUploader.periodicRetryAtForTest())
        assertEquals(1L, DebugLogUploader.cursorForTest())
    }

    @Test
    fun buildBatch_shipsRelativeTimesAndNoWallClock() {
        val batch = DebugLogUploader.buildBatch(
            "android", "1.6.17", "periodic",
            pending(
                1L to "12:34:56.789 D/T: first",
                2L to "12:35:00.000 TOR second",
                3L to "no clock on this one",
            ),
            nowMs = ORIGIN_EPOCH_MS + 60_000L,
        )!!

        assertEquals(
            "{\"v\":1,\"platform\":\"android\",\"app\":\"1.6.17\",\"reason\":\"periodic\"," +
                "\"session\":\"${DebugLogUploader.session}\",\"t0\":$ORIGIN_T0,\"lines\":[" +
                "\"+00000.000 D/T: first\",\"+00003.211 TOR second\",\"no clock on this one\"]}",
            batch.body,
        )
        assertFalse(batch.body.contains("12:34:56"), "the device wall clock must not reach the wire\n${batch.body}")
        assertTrue(ORIGIN_T0 % DebugLogUploader.T0_GRANULARITY_SECONDS == 0L, "t0 is floored to a whole minute")
    }

    @Test
    fun buildBatch_pinsTheOriginToTheFirstLineItEverSees() {
        DebugLogUploader.clearOriginForTest()

        val first = DebugLogUploader.buildBatch(
            "android", "1.6.17", "periodic",
            pending(1L to "09:00:00.000 D/T: the very first line", 2L to "09:00:02.500 D/T: two and a half"),
        )!!
        assertTrue(first.body.contains("\"+00000.000 D/T: the very first line\""), first.body)
        assertTrue(first.body.contains("\"+00002.500 D/T: two and a half\""), first.body)

        // A LATER batch keeps the same origin — one time base per process, so
        // the offsets stay comparable across batches (and across a consent
        // toggle, which does not re-pin it).
        val later = DebugLogUploader.buildBatch(
            "android", "1.6.17", "periodic",
            pending(3L to "09:01:40.000 D/T: a hundred seconds in"),
        )!!
        assertTrue(later.body.contains("\"+00100.000 D/T: a hundred seconds in\""), later.body)

        val t0 = later.body.substringAfter("\"t0\":").substringBefore(',').toLong()
        assertTrue(t0 > 0L, "t0 is anchored: $t0")
        assertEquals(0L, t0 % DebugLogUploader.T0_GRANULARITY_SECONDS, "t0 is floored to a whole minute: $t0")
    }

    // -- reapplyPersisted (prod 2026-09-20: cold-start Keychain read fails) ----

    @Test
    fun reapplyPersisted_enablesLoggingWhenTheStartupReadHadFailed() {
        // Startup: the keybag is locked, the read throws, DebugMode reads OFF.
        val locked = FakeDebugStore(throwOnGet = true)
        locked.values[DebugMode.KEY] = sealedDebugOn()
        LoggingState.enabled = false
        DebugMode.applyAtStartupIn(locked, debugCipher)
        assertFalse(LoggingState.enabled, "a failed startup read must stay OFF (fails toward off)")
        // After unlock the same persisted (sealed, A1-4) ON is readable: the re-apply
        // turns logging on.
        val unlocked = FakeDebugStore()
        unlocked.values[DebugMode.KEY] = sealedDebugOn()
        assertTrue(DebugMode.reapplyPersistedIn(unlocked, debugCipher))
        assertTrue(LoggingState.enabled, "the persisted consent must win once the store is readable")
    }

    @Test
    fun reapplyPersisted_neverTurnsLoggingOff_andNeverResurrectsARevokedConsent() {
        // Explicit OFF ("0"), absent, and unreadable: none of them may change a running state.
        for (store in listOf(
            FakeDebugStore().also { it.values[DebugMode.KEY] = "0" },
            FakeDebugStore(),
            FakeDebugStore(throwOnGet = true).also { it.values[DebugMode.KEY] = sealedDebugOn() },
        )) {
            LoggingState.enabled = true
            assertFalse(DebugMode.reapplyPersistedIn(store, debugCipher))
            assertTrue(LoggingState.enabled, "reapply must never flip ON → OFF")
            LoggingState.enabled = false
            assertFalse(DebugMode.reapplyPersistedIn(store, debugCipher))
            assertFalse(LoggingState.enabled, "a revoked/absent/unreadable flag must not enable logging")
        }
    }

    @Test
    fun reapplyPersisted_isIdempotentWhenAlreadyOn() {
        val store = FakeDebugStore().also { it.values[DebugMode.KEY] = sealedDebugOn() }
        LoggingState.enabled = true
        DebugLogUploader.resetCursor()
        assertTrue(DebugMode.reapplyPersistedIn(store, debugCipher))
        assertTrue(DebugMode.reapplyPersistedIn(store, debugCipher))
        assertTrue(LoggingState.enabled)
    }


    // -- the in-flight latch survives a suspended flush (prod iPhone 2026-09-21) --

    @Test
    fun flushLatch_abandonedMidPost_isTakenOverAfterStaleWindow() {
        DebugLogUploader.endFlush()
        // A flush begins (the iOS lock flush) and never ends: the process was suspended mid-POST.
        assertTrue(DebugLogUploader.tryBeginFlush(nowMs = 1_000_000L))
        // Inside the stale window every later flush is (correctly) refused — nothing has proven it dead yet.
        assertFalse(DebugLogUploader.tryBeginFlush(nowMs = 1_000_000L + DebugLogUploader.STALE_FLUSH_MS - 1))
        // Past it the latch is abandoned and the next flush takes over — this is what
        // stopped every upload of the next session before the fix.
        assertTrue(DebugLogUploader.tryBeginFlush(nowMs = 1_000_000L + DebugLogUploader.STALE_FLUSH_MS))
        DebugLogUploader.endFlush()
    }

    @Test
    fun flushLatch_abandonFlush_releasesImmediately_andEndFlushStaysIdempotent() {
        DebugLogUploader.endFlush()
        assertTrue(DebugLogUploader.tryBeginFlush(nowMs = 5_000L))
        assertFalse(DebugLogUploader.tryBeginFlush(nowMs = 6_000L))
        // The iOS lock path gave up waiting: release now, no stale window.
        DebugLogUploader.abandonFlush()
        assertTrue(DebugLogUploader.tryBeginFlush(nowMs = 6_001L))
        // The abandoned flush's own endFlush arriving late is harmless.
        DebugLogUploader.endFlush()
        DebugLogUploader.endFlush()
        assertTrue(DebugLogUploader.tryBeginFlush(nowMs = 7_000L))
        DebugLogUploader.endFlush()
    }

    @Test
    fun flushLatch_backwardsClock_doesNotWedge() {
        DebugLogUploader.endFlush()
        assertTrue(DebugLogUploader.tryBeginFlush(nowMs = 9_000_000L))
        // A wall-clock step backwards must not turn a fresh latch into a permanent one.
        assertTrue(DebugLogUploader.tryBeginFlush(nowMs = 1_000L))
        DebugLogUploader.endFlush()
    }


    @Test
    fun reapplyPersistedTriState_distinguishesUnreadableFromOff() {
        LoggingState.enabled = false
        val unreadable = FakeDebugStore(throwOnGet = true).also { it.values[DebugMode.KEY] = sealedDebugOn() }
        assertEquals(DebugMode.PERSISTED_UNREADABLE, DebugMode.reapplyPersistedTriStateIn(unreadable, debugCipher))
        assertFalse(LoggingState.enabled)
        val off = FakeDebugStore().also { it.values[DebugMode.KEY] = "0" }
        assertEquals(DebugMode.PERSISTED_OFF, DebugMode.reapplyPersistedTriStateIn(off, debugCipher))
        assertEquals(DebugMode.PERSISTED_OFF, DebugMode.reapplyPersistedTriStateIn(FakeDebugStore(), debugCipher))
        assertFalse(LoggingState.enabled)
        val on = FakeDebugStore().also { it.values[DebugMode.KEY] = sealedDebugOn() }
        assertEquals(DebugMode.PERSISTED_ON, DebugMode.reapplyPersistedTriStateIn(on, debugCipher))
        assertTrue(LoggingState.enabled, "a readable ON enables logging, exactly like reapplyPersisted")
    }


    // -- the two-read split (prod iPhone with a passcode, 2026-09-22) ------------

    @Test
    fun startupReadFails_laterFlagReadSucceeds_reapplyTurnsLoggingOn() {
        // First instant of the process: applyAtStartup's read throws (locked keybag).
        LoggingState.enabled = false
        val locked = FakeDebugStore(throwOnGet = true).also { it.values[DebugMode.KEY] = sealedDebugOn() }
        DebugMode.applyAtStartupIn(locked, debugCipher)
        assertFalse(LoggingState.enabled, "a failed startup read leaves the master switch OFF")
        // Moments later AppState reads the SAME persisted "1" successfully → the
        // Settings row shows ON and the loop gates open, but logging is still off,
        // so every flush is a silent no-op — unless the loop re-applies.
        val readable = FakeDebugStore().also { it.values[DebugMode.KEY] = sealedDebugOn() }
        assertTrue(DebugMode.isEnabledIn(readable, debugCipher), "the flag read succeeds (Settings row ON)")
        assertFalse(LoggingState.enabled, "…while the master switch is still OFF: the two-read split")
        assertTrue(DebugMode.reapplyPersistedIn(readable, debugCipher))
        assertTrue(LoggingState.enabled, "re-apply must close the split by turning logging ON")
    }

}
