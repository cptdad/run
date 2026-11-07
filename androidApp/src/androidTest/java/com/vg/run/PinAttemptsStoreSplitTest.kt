package com.vg.run

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Regression guard for the transient-key-vs-tamper split. The iOS PIN screen used a bare Swift `catch` that could not
 * tell KeyUnavailableException (transient — DEFER) from a genuine AEAD failure
 * (tamper — WIPE) and wiped on both. The fix moves the discrimination into the
 * Kotlin boundary via [PinAttemptsStore.readOrNullOnTamper]:
 *   • returns the count on a normal read,
 *   • returns null ONLY on genuine AEAD tamper (caller wipes),
 *   • throws KeyUnavailableException on a transient key outage (caller defers).
 * These tests pin the first two behaviours with the real Android CryptoProvider
 * (the transient-throw branch is covered by CryptoProviderKeystoreClassifyTest,
 * which proves a Keystore-caused failure maps to KeyUnavailableException).
 *
 * Also covers [PinAttemptsStore.tryWrite], the best-effort write used by the
 * UnlockResult.Error rollback so a key outage there can never SIGABRT.
 *
 * Run with: ./gradlew connectedAndroidTest --tests "*.PinAttemptsStoreSplitTest"
 */
@RunWith(AndroidJUnit4::class)
class PinAttemptsStoreSplitTest {

    companion object {
        private const val ATTEMPTS_PREFS = "pin_attempts_prefs"
        // A DEDICATED test prefs for the fate-shared "established" marker (NOT
        // the real vault_selector_prefs, so a test device's real vault is untouched).
        private const val ANCHOR_PREFS = "pin_attempts_anchor_test_prefs"
        private val STORAGE_KEY = PinAttemptsStore.STORAGE_KEY
    }

    private lateinit var context: Context

    @Before
    fun setUp() {
        context = InstrumentationRegistry.getInstrumentation().targetContext
        context.deleteSharedPreferences(ATTEMPTS_PREFS)
        context.deleteSharedPreferences(ANCHOR_PREFS)
    }

    @After
    fun tearDown() {
        context.deleteSharedPreferences(ATTEMPTS_PREFS)
        context.deleteSharedPreferences(ANCHOR_PREFS)
    }

    /** Single-store form (anchor defaults to the counter store) — the iOS/test shape. */
    private fun newStore() =
        PinAttemptsStore(KeyValueStore(context, ATTEMPTS_PREFS), CryptoProvider(context))

    /** Two-store form mirroring production Android: counter + a SEPARATE anchor. */
    private fun twoStore() =
        PinAttemptsStore(
            KeyValueStore(context, ATTEMPTS_PREFS),
            CryptoProvider(context),
            KeyValueStore(context, ANCHOR_PREFS),
        )

    /** Two-store form with the vault CONFIGURED (DB-key wrap present) —
     *  the AND-gate the tamper/establish decisions now require. */
    private fun twoStoreConfigured() =
        PinAttemptsStore(
            KeyValueStore(context, ATTEMPTS_PREFS),
            CryptoProvider(context),
            KeyValueStore(context, ANCHOR_PREFS),
            dbKeyWrapPresent = { true },
        )

    /** A normally-written count round-trips through readOrNullOnTamper (never null). */
    @Test
    fun readOrNullOnTamper_normal_returnsCount() {
        val store = newStore()
        store.write(3)
        assertEquals("normal read must return the stored count", 3, store.readOrNullOnTamper())
    }

    /** No stored value reads as 0 (not null) — an absent counter is not tamper. */
    @Test
    fun readOrNullOnTamper_missing_returnsZero() {
        assertEquals("absent counter must read as 0", 0, newStore().readOrNullOnTamper())
    }

    /**
     * A genuinely tampered / undecryptable ciphertext (key present, AEAD fails)
     * returns null — the signal the caller uses to wipe. It must NOT throw
     * (throwing is reserved for the transient-key DEFER path).
     */
    @Test
    fun readOrNullOnTamper_tampered_returnsNull() {
        newStore().write(2)
        context.getSharedPreferences(ATTEMPTS_PREFS, Context.MODE_PRIVATE)
            .edit().putString(STORAGE_KEY, "not-valid-ciphertext").commit()
        assertNull("tampered ciphertext must return null (→ caller wipes), not throw",
            newStore().readOrNullOnTamper())
    }

    /** tryWrite persists like write and reports success when the key is available. */
    @Test
    fun tryWrite_normal_persistsAndReturnsTrue() {
        val store = newStore()
        assertTrue("tryWrite must report success with the key available", store.tryWrite(4))
        assertEquals("tryWrite must persist the count", 4, store.readOrNullOnTamper())
    }

    // -----------------------------------------------------------------------
    // Deleting the counter to reset the
    // throttle is detected as tamper ONLY on POSITIVE establishment evidence (the
    // surviving fate-shared marker) AND the vault configured. A legacy / unmigrated
    // / interrupted-provision vault (configured, no marker, no counter) ESTABLISHES
    // on read and is NEVER wiped — the round-1 brick fix.
    // -----------------------------------------------------------------------

    /**
     * The deletion attack: a normal write establishes the counter (+ the fate-shared
     * marker); deleting ONLY the counter store between guesses used to reset the
     * budget to 0. With the marker surviving in the separate anchor store AND the
     * vault still configured, the absent counter reads as tamper (→ null → wipe).
     */
    @Test
    fun deletedCounter_withSurvivingMarker_onConfiguredVault_isTamper() {
        twoStoreConfigured().write(3)                  // establishes counter + marker
        context.deleteSharedPreferences(ATTEMPTS_PREFS) // attack: delete counter only
        assertNull("counter deleted after establishment (marker + wrap survive) must be tamper (null)",
            twoStoreConfigured().readOrNullOnTamper())
    }

    /**
     * Control: with no marker ever set (a legacy install from before this marker)
     * AND nothing configured, an absent counter is NOT tamper — reads as 0.
     */
    @Test
    fun absentCounter_withoutMarker_isZero() {
        assertEquals("absent counter without a marker or configured vault must be 0 (not tamper)",
            0, twoStore().readOrNullOnTamper())
    }

    /**
     * Contract documentation for why Android passes vault_selector_prefs (not the
     * counter store) as the anchor: if the marker (mis)shares the counter store,
     * deleting that store clears the marker too, so the deletion is NOT detected and
     * falls back to 0. This is exactly the fate-sharing the two-store form prevents.
     */
    @Test
    fun deletedCounter_whenMarkerSharesCounterStore_resetsToZero() {
        newStore().write(3)                            // marker lands in the counter store
        context.deleteSharedPreferences(ATTEMPTS_PREFS) // clears counter AND marker
        assertEquals("a marker sharing the counter store cannot detect deletion",
            0, newStore().readOrNullOnTamper())
    }

    // -----------------------------------------------------------------------
    // iOS seam: on iOS the marker is a per-item-deletable Keychain item,
    // so production passes a DB-key-wrap presence probe as the "vault configured"
    // signal. Exercised here with lambda probes against the shared commonMain
    // wiring (the probe is platform-agnostic).
    // -----------------------------------------------------------------------

    /** BRICK FIX (findings #5/#7): a legacy / interrupted-provision vault — DB-key
     *  wrap present, but NO counter and NO marker — must ESTABLISH on read (return
     *  0 and arm the anchor), NEVER wipe. Round 1 wiped this exact state. */
    @Test
    fun legacyVault_wrapPresentNoMarker_establishesToZero_neverWipes() {
        val store = PinAttemptsStore(
            KeyValueStore(context, ATTEMPTS_PREFS), CryptoProvider(context),
            KeyValueStore(context, ANCHOR_PREFS),
            dbKeyWrapPresent = { true },
        )
        assertEquals("a legacy vault (wrap present, no marker) must establish-on-read to 0",
            0, store.readOrNullOnTamper())
        // Establish-on-read must have ARMED the anchor: the counter blob now exists
        // and the marker is set, so a later counter-only deletion is now tamper.
        assertTrue("establish-on-read must write the counter blob",
            context.getSharedPreferences(ATTEMPTS_PREFS, Context.MODE_PRIVATE).contains(STORAGE_KEY))
        assertTrue("establish-on-read must arm the fate-shared marker",
            context.getSharedPreferences(ANCHOR_PREFS, Context.MODE_PRIVATE)
                .contains(PinAttemptsStore.ESTABLISHED_KEY))
    }

    /** After establishment, deleting ONLY the counter (marker + wrap survive) is
     *  the deletion signature → tamper (→ null → wipe). */
    @Test
    fun counterOnlyDeletion_afterEstablishment_withWrapPresent_isTamper() {
        PinAttemptsStore(
            KeyValueStore(context, ATTEMPTS_PREFS), CryptoProvider(context),
            KeyValueStore(context, ANCHOR_PREFS),
            dbKeyWrapPresent = { true },
        ).write(3)                                      // establishes counter + marker
        context.deleteSharedPreferences(ATTEMPTS_PREFS) // delete counter only; marker survives
        assertNull("counter deleted while the marker + wrap survive must read as tamper",
            PinAttemptsStore(
                KeyValueStore(context, ATTEMPTS_PREFS), CryptoProvider(context),
                KeyValueStore(context, ANCHOR_PREFS),
                dbKeyWrapPresent = { true },
            ).readOrNullOnTamper())
    }

    /** Known limitation: deleting BOTH the counter and the (per-item-deletable iOS)
     *  marker while the wrap survives re-establishes to 0 — a bounded reset, not a
     *  brick and not a false wipe. Mitigated in depth by the Argon2id KDF cost. */
    @Test
    fun counterAndMarkerBothDeleted_withWrapPresent_isKnownLimitationReset() {
        PinAttemptsStore(
            KeyValueStore(context, ATTEMPTS_PREFS), CryptoProvider(context),
            KeyValueStore(context, ANCHOR_PREFS),
            dbKeyWrapPresent = { true },
        ).write(3)
        context.deleteSharedPreferences(ATTEMPTS_PREFS) // counter gone
        context.deleteSharedPreferences(ANCHOR_PREFS)   // marker gone (iOS per-item delete)
        assertEquals("delete-both is a known limitation → establish-on-read resets to 0",
            0, PinAttemptsStore(
                KeyValueStore(context, ATTEMPTS_PREFS), CryptoProvider(context),
                KeyValueStore(context, ANCHOR_PREFS),
                dbKeyWrapPresent = { true },
            ).readOrNullOnTamper())
    }

    /** Legit first run under the probe: nothing provisioned yet (wrap absent) → 0. */
    @Test
    fun absentCounter_withWrapAbsent_isZero() {
        val store = PinAttemptsStore(
            KeyValueStore(context, ATTEMPTS_PREFS), CryptoProvider(context),
            KeyValueStore(context, ANCHOR_PREFS),
            dbKeyWrapPresent = { false },
        )
        assertEquals("no wrap + no marker must read as 0 (fresh install)",
            0, store.readOrNullOnTamper())
    }

    /** A transiently-failing probe (iOS contains() throws KeyUnavailableException
     *  on a locked keybag) must DEFER to 0, never wipe. */
    @Test
    fun absentCounter_probeThrows_defersToZero() {
        val store = PinAttemptsStore(
            KeyValueStore(context, ATTEMPTS_PREFS), CryptoProvider(context),
            KeyValueStore(context, ANCHOR_PREFS),
            dbKeyWrapPresent = { throw KeyUnavailableException("keybag locked") },
        )
        assertEquals("a failing wrap probe must defer (0), not read as tamper",
            0, store.readOrNullOnTamper())
    }

    // -----------------------------------------------------------------------
    // The Android "configured" signal read
    // STRAIGHT from the fate-shared anchorStore via the DB-key wrap key — no lambda.
    // On Android the marker + wrap live in the SAME vault_selector_prefs FILE, so
    // deleting the counter file leaves both → tamper; a legacy vault (wrap present,
    // no marker) establishes-on-read instead of wiping. Wrap key is "vlt_c".
    // -----------------------------------------------------------------------

    private val wrapKey = "vlt_c" // VAULT_DBKEY_STORAGE_KEY

    /** BRICK FIX (#7): wrap present in the anchor but NO marker (legacy vault) must
     *  ESTABLISH on read to 0 and arm the marker, NEVER wipe. */
    @Test
    fun legacyVault_wrapKeyInAnchorNoMarker_establishesToZero() {
        val anchor = KeyValueStore(context, ANCHOR_PREFS)
        anchor.putStringSync(wrapKey, "wrapped-db-key-blob") // provisioned vault, no counter/marker
        val store = PinAttemptsStore(
            KeyValueStore(context, ATTEMPTS_PREFS), CryptoProvider(context),
            anchor, vaultWrapKeyInAnchorStore = wrapKey,
        )
        assertEquals("legacy vault (wrap in anchor, no marker) must establish to 0, not wipe",
            0, store.readOrNullOnTamper())
        assertTrue("marker must be armed in the fate-shared anchor store",
            context.getSharedPreferences(ANCHOR_PREFS, Context.MODE_PRIVATE)
                .contains(PinAttemptsStore.ESTABLISHED_KEY))
    }

    /** After establishment, deleting only the counter file (marker + wrap survive in
     *  the anchor file) is the deletion signature → tamper. */
    @Test
    fun counterOnlyDeletion_wrapKeyInAnchor_isTamper() {
        val anchor = KeyValueStore(context, ANCHOR_PREFS)
        anchor.putStringSync(wrapKey, "wrapped-db-key-blob")
        PinAttemptsStore(
            KeyValueStore(context, ATTEMPTS_PREFS), CryptoProvider(context),
            anchor, vaultWrapKeyInAnchorStore = wrapKey,
        ).write(3)                                      // establishes counter + marker (in the anchor file)
        context.deleteSharedPreferences(ATTEMPTS_PREFS) // delete counter file only
        assertNull("counter-only deletion with marker + wrap surviving must read as tamper",
            PinAttemptsStore(
                KeyValueStore(context, ATTEMPTS_PREFS), CryptoProvider(context),
                KeyValueStore(context, ANCHOR_PREFS), vaultWrapKeyInAnchorStore = wrapKey,
            ).readOrNullOnTamper())
    }

    @Test
    fun absentCounter_wrapKeyOptInButNothingProvisioned_isZero() {
        val store = PinAttemptsStore(
            KeyValueStore(context, ATTEMPTS_PREFS), CryptoProvider(context),
            KeyValueStore(context, ANCHOR_PREFS),
            vaultWrapKeyInAnchorStore = wrapKey, // opt-in, but no wrap written → fresh install
        )
        assertEquals("no wrap in the anchor store → fresh install must read 0, not wipe",
            0, store.readOrNullOnTamper())
    }

    // -----------------------------------------------------------------------
    // windowLimitReached() — the LAUNCH FAST-PATH.
    //
    // Test gap: this had ZERO tests on any platform, yet
    // both lock screens call it at launch and a `true` triggers an emergency
    // WIPE before any PIN is entered. A false positive destroys an honest user's
    // vault; a false negative silently removes the rolling-24h brute-force cap
    // that no successful unlock can reset (AND-SEC-1).
    // -----------------------------------------------------------------------

    @Test
    fun windowLimit_isNotReachedOnAFreshStore() {
        assertTrue("an untouched store must never report the daily cap reached",
            !newStore().windowLimitReached())
    }

    @Test
    fun windowLimit_isNotReachedBelowTheCap() {
        val store = newStore()
        repeat(PinAttemptsStore.MAX_WRONG_PER_DAY - 1) {
            store.recordWrongAttemptInWindowAndCheckLimit()
        }
        assertTrue("one short of the cap must NOT trip the launch-time wipe",
            !store.windowLimitReached())
    }

    @Test
    fun windowLimit_isReachedAtTheCap_andIsDurable() {
        val store = newStore()
        var reportedAtCap = false
        repeat(PinAttemptsStore.MAX_WRONG_PER_DAY) {
            reportedAtCap = store.recordWrongAttemptInWindowAndCheckLimit()
        }
        assertTrue("the cap-th wrong attempt must report the limit", reportedAtCap)
        assertTrue("windowLimitReached must agree with the recording path",
            store.windowLimitReached())
        // The whole point of the fast path: a relaunch (fresh store object over the
        // same persisted state) must still see it, so force-quitting cannot dodge
        // the wipe.
        assertTrue("the limit must survive a restart — it is read at launch",
            newStore().windowLimitReached())
    }

    @Test
    fun windowLimit_isReadOnly_andDoesNotRecordAttempts() {
        val store = newStore()
        repeat(3) { store.recordWrongAttemptInWindowAndCheckLimit() }
        repeat(10) { store.windowLimitReached() }
        // If the read path recorded, these extra calls would have advanced the
        // window count toward the cap.
        repeat(PinAttemptsStore.MAX_WRONG_PER_DAY - 4) {
            assertTrue("still below the cap while recording the remainder",
                !store.recordWrongAttemptInWindowAndCheckLimit())
        }
        assertTrue("the cap must be reached by RECORDED attempts only",
            store.recordWrongAttemptInWindowAndCheckLimit())
    }
}
