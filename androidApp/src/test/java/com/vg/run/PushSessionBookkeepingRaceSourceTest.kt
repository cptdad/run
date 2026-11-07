package com.vg.run

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The push session bookkeeping was mutated OFF the mutex that exists to serialise
 * it (adversarial review of dd5804a, 2026-08-09).
 *
 * `RunViewModel.unregisterPushBestEffort` emptied all four session fields —
 * `vendorPushRegisteredIds`, `vendorPushToken`, `unifiedPushRegisteredIds`,
 * `unifiedPushLastEndpoint` — without ever taking `pushRefreshMutex`, from three
 * call sites: the opt-out branch, the enable-failure branch and
 * `performEmergencyWipe`. The reachable interleaving: a toggle-ON fails and
 * releases the mutex; between `clearLevel(...)` and `unregisterPushInBackground()`
 * a control-poll cycle acquires the now-free mutex via `tryLock` and enters
 * `registerInboxesForCurrentSession`, which spends seconds in a Tor-routed PUT
 * loop calling `registeredIds.add(...)`, while the enable-failure coroutine — a
 * different `Dispatchers.IO` thread — runs `vendorPushRegisteredIds.clear()`.
 * Two threads, one plain `mutableSetOf()`, no synchronisation.
 *
 * THE FIX AND WHY IT LOOKS LIKE THIS. `unregisterPushBestEffort` cannot simply
 * take the mutex: it is non-suspend and reached from `performEmergencyWipe`,
 * which is non-suspend by design and must never make its crypto-erase contingent
 * on an unrelated 60 s Tor PUT releasing a lock. So instead
 *  - the fields themselves are thread-safe (`Collections.newSetFromMap(
 *    ConcurrentHashMap)` + `@Volatile`), which removes the data race, and
 *  - `pushTeardownEpoch` supplies the ordering the lock would have given:
 *    every teardown bumps it BEFORE emptying the fields, and a refresh pass that
 *    sees a changed epoch at exit discards its own bookkeeping.
 *
 * The direction is load-bearing and one-way: an over-cleared set merely
 * re-registers (`PushRegistration.register` is an idempotent relay upsert), while
 * a set left claiming an inbox whose relay push row the teardown just DELETEd
 * suppresses that inbox's registration for the rest of the session.
 *
 * SOURCE-LEVEL, for the reason this file's siblings state: `RunViewModel` is an
 * `AndroidViewModel` needing a real `Application` (`CryptoProvider`,
 * `KeyValueStore`, `VaultSelector`, `AndroidDbKeyProtector`, …) and this module's
 * unit-test tier has no Robolectric and no mocking framework, so the properties
 * are pinned where they are decidable — in the source. Same technique as
 * [PrefsApplySourceGuardTest] and [VendorPushOptOutTeardownSourceTest]; comments
 * are stripped before matching, so prose naming a call can neither satisfy nor
 * trip a guard.
 */
class PushSessionBookkeepingRaceSourceTest {

    /**
     * The constraint that shaped the whole fix. If someone "cleans this up" by
     * making the unregister suspend so it can take the mutex, the ripple lands in
     * `performEmergencyWipe` — a non-suspend, main-thread, crypto-erase-first path
     * that must not gain a suspension point (nor a `runBlocking`) on a lock a
     * 60 s Tor PUT can be holding.
     *
     * Non-vacuousness: adding `suspend` to the declaration fails this assertion —
     * and, before it, the compiler, since `performEmergencyWipe` is not a
     * coroutine. That compile error IS the property; this guard states it in the
     * one place where the reason is written down.
     */
    @Test
    fun unregisterPushBestEffort_staysNonSuspend_becauseTheWipePathCallsIt() {
        val src = strippedSource()

        assertTrue(
            "PushRegistrationCoordinator must declare `fun unregisterPushBestEffort(` — " +
                "non-suspend, because performEmergencyWipe (non-suspend, crypto-erase-first) calls it",
            Regex("""(?<!suspend )fun unregisterPushBestEffort\(""").containsMatchIn(src),
        )
        for ((name, file) in listOf("PushRegistrationCoordinator" to src, "RunViewModel" to strippedViewModel())) {
            assertFalse(
                "unregisterPushBestEffort must NOT become suspend ($name): performEmergencyWipe " +
                    "calls it synchronously while tearing the session down, and a suspension point " +
                    "there would make the crypto-erase wait on whatever holds pushRefreshMutex (a " +
                    "registration pass can sit on a 60 s Tor PUT).",
                file.contains("suspend fun unregisterPushBestEffort("),
            )
        }
        assertFalse(
            "the body moved to PushRegistrationCoordinator — no stale copy may stay in RunViewModel",
            strippedViewModel().contains("fun unregisterPushBestEffort("),
        )
        assertTrue(
            "performEmergencyWipe must still fire the best-effort push unregister — it needs " +
                "the vault refs and the transport that the lines below it destroy",
            functionBody(strippedViewModel(), "fun performEmergencyWipe(").contains("unregisterPushBestEffort("),
        )
    }

    /**
     * The unregister must not touch the four fields itself. Inline clears are
     * exactly what raced a concurrent `registeredIds.add(...)`, and an inline
     * clear also skips the epoch bump, which is what tells an in-flight pass to
     * throw its bookkeeping away.
     *
     * Non-vacuousness: putting `vendorPushRegisteredIds.clear()` back into that
     * function's body fails this.
     */
    @Test
    fun unregisterPushBestEffort_emptiesTheFieldsOnlyThroughTheSharedHelper() {
        val body = functionBody(strippedSource(), "fun unregisterPushBestEffort(")

        assertTrue(
            "unregisterPushBestEffort must route its session bookkeeping through " +
                "clearPushSessionBookkeeping() — the one place that bumps the teardown epoch. " +
                "Body was:\n$body",
            body.contains("clearPushSessionBookkeeping()"),
        )
        for (field in SESSION_FIELDS) {
            assertFalse(
                "unregisterPushBestEffort must not touch `$field` directly: it holds no lock " +
                    "(it cannot — the wipe path calls it), so an inline mutation races a " +
                    "registration pass mid-`add(...)` AND skips the epoch bump that would have " +
                    "invalidated that pass. Body was:\n$body",
                body.contains(field),
            )
        }
    }

    /**
     * Every teardown must go through the one helper. Pinned on the two ADDRESS
     * fields rather than the sets, because the sets are also legitimately cleared
     * under the mutex (`if (token != vendorPushToken) …clear()`), whereas nulling
     * an address is only ever a teardown.
     *
     * Non-vacuousness: re-adding the inline `vendorPushToken = null` /
     * `unifiedPushLastEndpoint = null` pair to either the opt-out or the
     * enable-failure branch fails this.
     */
    @Test
    fun theAddressFieldsAreEmptiedNowhereButTheTeardownHelper() {
        // Counted over BOTH files: the fields live in PushRegistrationCoordinator, and
        // RunViewModel (which hands the coordinator its dependencies) must hold none.
        val src = strippedSource() + "\n" + strippedViewModel()
        val helper = functionBody(strippedSource(), "fun clearPushSessionBookkeeping(")

        for (assignment in listOf("vendorPushToken = null", "unifiedPushLastEndpoint = null")) {
            assertEquals(
                "`$assignment` must not appear in RunViewModel at all",
                0,
                Regex(Regex.escape(assignment)).findAll(strippedViewModel()).count(),
            )
            assertEquals(
                "`$assignment` must appear exactly once in PushRegistrationCoordinator — inside " +
                    "clearPushSessionBookkeeping. A second, inline teardown would clear the " +
                    "fields without bumping pushTeardownEpoch, leaving an in-flight " +
                    "registration pass free to re-populate them behind it.",
                1,
                Regex(Regex.escape(assignment)).findAll(src).count(),
            )
            assertTrue(
                "`$assignment` must live in clearPushSessionBookkeeping. Helper body was:\n$helper",
                helper.contains(assignment),
            )
        }
    }

    /**
     * The bump must precede the clears. Clear-then-bump leaves a window in which
     * a pass reads the old epoch, the helper empties the fields, the pass
     * re-populates them, and the pass's own exit check still sees the pre-bump
     * value — the exact interleaving the epoch exists to catch.
     *
     * Non-vacuousness: moving `pushTeardownEpoch.incrementAndGet()` below the
     * first `clear()` fails this.
     */
    @Test
    fun clearPushSessionBookkeeping_bumpsTheEpochBeforeEmptyingTheFields() {
        val body = functionBody(strippedSource(), "fun clearPushSessionBookkeeping(")

        val bumpAt = body.indexOf("pushTeardownEpoch.incrementAndGet()")
        assertTrue(
            "the teardown helper must bump pushTeardownEpoch. Body was:\n$body",
            bumpAt >= 0,
        )
        val firstFieldAt = SESSION_FIELDS.map { body.indexOf(it) }.filter { it >= 0 }.minOrNull()
        assertTrue(
            "the teardown helper must actually empty the session fields. Body was:\n$body",
            firstFieldAt != null,
        )
        assertTrue(
            "ORDER: the epoch bump must come BEFORE the fields are emptied, so any teardown a " +
                "registration pass can outlive is preceded by an epoch change that pass is " +
                "guaranteed to observe at exit. Body was:\n$body",
            bumpAt < firstFieldAt!!,
        )
        // All four, not "the active transport's two": a teardown that leaves one
        // transport's set populated is the silent-skip shape the fields' own kdocs
        // warn about.
        for (field in SESSION_FIELDS) {
            assertTrue(
                "the teardown helper must empty `$field` too — DELETE /inbox/{id}/push is " +
                    "platform-agnostic, so both transports' bookkeeping goes stale together. " +
                    "Body was:\n$body",
                body.contains(field),
            )
        }
    }

    /**
     * A pass that STRADDLED a teardown must discard what it recorded: by the time
     * it finishes, the address it registered under has been destroyed and the
     * teardown's `DELETE /inbox/{id}/push` is on its way to removing the rows it
     * just created. Keeping those entries suppresses re-registration for the rest
     * of the session; dropping them costs one idempotent re-upsert.
     *
     * Non-vacuousness: deleting the epoch snapshot, the exit comparison, or the
     * discard call fails this.
     */
    @Test
    fun withPushRefreshTurn_discardsTheBookkeepingOfAPassATeardownStraddled() {
        val body = functionBody(strippedSource(), "private suspend fun withPushRefreshTurn(")

        val snapshotAt = body.indexOf("val epochAtEntry = pushTeardownEpoch.get()")
        val blockAt = body.indexOf("block()")
        val discardAt = body.indexOf("clearPushSessionBookkeeping()")
        val unlockAt = body.lastIndexOf("pushRefreshMutex.unlock()")

        assertTrue(
            "withPushRefreshTurn must snapshot pushTeardownEpoch. Body was:\n$body",
            snapshotAt >= 0,
        )
        assertTrue("withPushRefreshTurn must run the pass. Body was:\n$body", blockAt >= 0)
        assertTrue(
            "withPushRefreshTurn must discard the pass's bookkeeping when a teardown ran " +
                "during it. Body was:\n$body",
            discardAt >= 0,
        )
        assertTrue("withPushRefreshTurn must unlock. Body was:\n$body", unlockAt >= 0)
        assertTrue(
            "ORDER: the epoch must be snapshotted BEFORE the pass runs — a snapshot taken " +
                "afterwards can never differ from itself. Body was:\n$body",
            snapshotAt < blockAt,
        )
        assertTrue(
            "the discard must be GUARDED by a comparison against the entry snapshot: " +
                "unconditionally clearing would wipe the bookkeeping of every ordinary pass " +
                "and re-register every inbox on every control-poll cycle. Body was:\n$body",
            EPOCH_GUARDED_DISCARD.containsMatchIn(body),
        )
        assertTrue(
            "the discard must happen while the lock is still HELD, i.e. before unlock(). " +
                "Body was:\n$body",
            discardAt < unlockAt,
        )
    }

    /**
     * The memory-model half. `pushRefreshMutex` orders the refresh passes against
     * each other but not against the teardown, which by construction runs without
     * it — so the fields carry the synchronisation themselves.
     *
     * Non-vacuousness: reverting either set to `mutableSetOf()`, or dropping
     * either `@Volatile`, fails this.
     */
    @Test
    fun theSessionFieldsCarryTheirOwnThreadSafety() {
        val src = strippedSource()

        for (set in listOf("vendorPushRegisteredIds", "unifiedPushRegisteredIds")) {
            val decl = declaration(src, "private val $set")
            assertTrue(
                "`$set` must be a CONCURRENT set: the teardown clears it without " +
                    "pushRefreshMutex (it cannot take it — the wipe path is non-suspend) while " +
                    "a registration pass may be inside add(...). Concurrent add/clear on a " +
                    "plain HashSet is undefined. Declaration was:\n$decl",
                decl.contains("ConcurrentHashMap"),
            )
            assertFalse(
                "`$set` must not go back to a plain mutableSetOf(). Declaration was:\n$decl",
                decl.contains("mutableSetOf()"),
            )
        }

        for (field in SESSION_FIELDS) {
            assertFalse(
                "`$field` moved to PushRegistrationCoordinator — RunViewModel must not declare a copy",
                Regex("""(?:val|var) ${Regex.escape(field)}\b""").containsMatchIn(strippedViewModel()),
            )
        }

        for (address in listOf("vendorPushToken", "unifiedPushLastEndpoint")) {
            assertTrue(
                "`$address` must be @Volatile — it is written by a teardown on a different " +
                    "thread from the refresh pass that reads it, with no lock in common.",
                Regex("""@Volatile\s+private var ${Regex.escape(address)}\b""").containsMatchIn(src),
            )
        }
    }

    // -----------------------------------------------------------------------

    /**
     * PushRegistrationCoordinator's source with comments removed — the push
     * session bookkeeping moved there out of RunViewModel, verbatim.
     */
    private fun strippedSource(): String = stripped("PushRegistrationCoordinator.kt")

    /** RunViewModel's source with comments removed (the wipe path lives there). */
    private fun strippedViewModel(): String = stripped("RunViewModel.kt")

    private fun stripped(name: String): String = SourcePins.stripped("androidApp/src/main/java/com/vg/run/$name")

    /** A property declaration plus its initializer, up to the next declaration. */
    private fun declaration(src: String, prefix: String): String {
        val at = src.indexOf(prefix)
        assertTrue("PushRegistrationCoordinator.kt must declare `$prefix`", at >= 0)
        val next = src.indexOf("private ", at + prefix.length)
        return src.substring(at, if (next < 0) src.length else next)
    }

    companion object {
        /** The four session fields `pushRefreshMutex` exists to serialise. */
        private val SESSION_FIELDS = listOf(
            "vendorPushRegisteredIds",
            "vendorPushToken",
            "unifiedPushRegisteredIds",
            "unifiedPushLastEndpoint",
        )

        /**
         * `if (…epochAtEntry) { … clearPushSessionBookkeeping() … }`. Bounded by
         * `[^{}]` on both sides rather than `[^)]`, because the condition itself
         * contains parentheses (`pushTeardownEpoch.get()`).
         */
        private val EPOCH_GUARDED_DISCARD = Regex(
            """if\s*\([^{}]*epochAtEntry\s*\)\s*\{[^{}]*clearPushSessionBookkeeping\(\)""",
            RegexOption.DOT_MATCHES_ALL,
        )
    }
}
