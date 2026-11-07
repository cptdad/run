package com.vg.run

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The WIPE-path connector wedge (reproduced on hardware, 2026-08-11).
 *
 * `WipeRoutine.wipePersistentState` unlinked `databases/unifiedpush-connector`
 * out from under the open handle the connector caches in its private static
 * `DBStore.instance` singleton — always, deterministically, because the wipe's
 * own `destroyLocalPushIdentity` (one line earlier) constructs that singleton
 * to delete the connector's rows. The unlink pinned the handle in
 * `SQLITE_READONLY_DBMOVED` (extended result 1032), so every later
 * `saveDistributor` threw for the life of the process.
 *
 * That was "justified" by an invariant this defect disproved: "WipeRoutine is
 * a terminal path — nothing may survive it, and no retry follows it in this
 * process." Four of the five wipe entry points (the orphaned-vault "Erase and
 * start over", the launch-time inactivity wipe, the orphaned-credential
 * self-heal, and the debug TEST_WIPE hook) deliberately fall through to setup
 * in the SAME process — which additionally survives `finishAndRemoveTask()`
 * as a cached process — so wipe → re-onboard → enable notifications hit the
 * wedge, and the modal rendered "No notification distributor was selected.
 * Install ntfy from F-Droid…" while ntfy was installed and resolvable. On a
 * device without Play Services UnifiedPush is the ONLY transport: silently
 * dead notifications behind a lie, until real process death.
 *
 * The fix is three coupled pieces, and this class pins each at the tier that
 * runs on every `./gradlew test` (the behavioural proof — teardown, then
 * KEEP USING the connector in one process — is instrumented:
 * `UnifiedPushArtifactSweepTest.wipePathTeardown_leavesTheConnectorAbleToSelectADistributorAgain`):
 *  1. `sweepLocalArtifacts` closes the connector's cached handle BEFORE the
 *     unlink, so no dead handle ever exists;
 *  2. the close is reflective (the library exposes no reset), so release
 *     builds need `-keepnames` rules for the exact class/field names — the
 *     code and the rules must not drift apart, or the fix silently dies in
 *     RELEASE ONLY (debug is un-minified, so no test tier would notice);
 *  3. a failed distributor SELECTION is classified honestly: "install ntfy"
 *     only when no distributor is installed, never as the copy for a failure
 *     that is ours.
 *
 * Same source-scan technique as [VendorPushOptOutTeardownSourceTest] (the
 * property is a call site's presence/order, which the plain-JVM tier this
 * module's unit tests run at cannot exercise behaviourally).
 */
class UnifiedPushWipeWedgeSourceTest {

    // -----------------------------------------------------------------------
    // (1) close-before-unlink
    // -----------------------------------------------------------------------

    /**
     * The close must exist AND precede the unlink. Close-after would also drop
     * the singleton eventually, but close-BEFORE is the safe shape and is
     * pinned deliberately: it leaves no window in which a dead
     * (SQLITE_READONLY_DBMOVED) handle exists at all — a connector call
     * arriving between an unlink and a later close (the connector's receiver
     * runs on broadcasts from another app, on its own schedule) would grab the
     * dead handle and throw — and it lets `deleteDatabase` run against a
     * quiesced file instead of one whose -wal/-shm sidecars are still held
     * open.
     *
     * Non-vacuousness: deleting the `closeConnectorDbHandle()` call, or moving
     * it below the `deleteDatabase` line, fails this.
     */
    @Test
    fun sweepLocalArtifacts_closesTheConnectorHandleBeforeUnlinking() {
        val body = fileFunctionBody(
            SourcePins.UNIFIED_PUSH_SUPPORT,
            "fun sweepLocalArtifacts(",
        )

        val closeAt = body.indexOf("closeConnectorDbHandle()")
        val unlinkAt = body.indexOf("deleteDatabase")
        assertTrue(
            "sweepLocalArtifacts must close the connector's cached DB handle — unlinking " +
                "under the open handle wedges every later connector write for the life of the " +
                "process, and most wipe entry points keep running in that process. Body was:\n" +
                body,
            closeAt >= 0,
        )
        assertTrue("sweepLocalArtifacts must still unlink the connector database — the " +
            "wipe's destructive guarantee is non-negotiable. Body was:\n$body", unlinkAt >= 0)
        assertTrue(
            "ORDER: the close must run BEFORE the unlink — a close that runs after leaves " +
                "the already-dead handle cached. Body was:\n$body",
            closeAt < unlinkAt,
        )
    }

    // -----------------------------------------------------------------------
    // (2) the reflection names and the R8 rules cannot drift apart
    // -----------------------------------------------------------------------

    /**
     * `closeConnectorDbHandle` resolves `org.unifiedpush.android.connector
     * .internal.DBStore` and its `instance` field BY NAME at runtime. Release
     * builds minify (R8, `isMinifyEnabled = true`), so without matching
     * `-keepnames` rules the lookup fails, the close silently no-ops, and the
     * wedge returns IN RELEASE ONLY — the one variant no automated tier runs
     * against. This pins the code and the rules to each other; a connector
     * upgrade that renames the internals is caught separately and loudly by
     * `UnifiedPushArtifactSweepTest.resetConnectorStore` (no try/catch there).
     *
     * Non-vacuousness: renaming the class/field literal in either file, or
     * deleting either keep rule, fails this.
     */
    @Test
    fun reflectionNames_matchTheR8KeepRules() {
        val helper = fileFunctionBody(
            SourcePins.UNIFIED_PUSH_SUPPORT,
            "private fun closeConnectorDbHandle(",
        )
        assertTrue(
            "closeConnectorDbHandle must resolve the connector's DBStore class by its " +
                "verified name. Body was:\n$helper",
            helper.contains("\"org.unifiedpush.android.connector.internal.DBStore\""),
        )
        assertTrue(
            "closeConnectorDbHandle must resolve the singleton field by its verified name. " +
                "Body was:\n$helper",
            helper.contains("\"instance\""),
        )

        val rules = File(repoRoot(), "androidApp/proguard-rules.pro").readText()
        assertTrue(
            "proguard-rules.pro must -keepnames the connector's DBStore class — without it " +
                "R8 renames the class in release and the reflective close silently no-ops, " +
                "reintroducing the wipe wedge in the one build variant no test tier runs",
            rules.contains("-keepnames class org.unifiedpush.android.connector.internal.DBStore"),
        )
        assertTrue(
            "proguard-rules.pro must -keepclassmembernames the `instance` field for the same " +
                "reason",
            Regex(
                """-keepclassmembernames\s+class\s+org\.unifiedpush\.android\.connector\.internal\.DBStore\s*\{[^}]*\binstance\b[^}]*\}"""
            ).containsMatchIn(rules),
        )
    }

    /**
     * The close must be BEST-EFFORT: a wipe may never throw out of the sweep,
     * and the destructive unlink must not depend on the reflection succeeding
     * (a future connector rename must degrade to the old wedge — reported
     * honestly by the modal — never to a wipe that leaves the file behind).
     */
    @Test
    fun closeConnectorDbHandle_isBestEffortAndCreatesNothing() {
        val helper = fileFunctionBody(
            SourcePins.UNIFIED_PUSH_SUPPORT,
            "private fun closeConnectorDbHandle(",
        )
        assertTrue(
            "closeConnectorDbHandle must swallow every failure (catch Throwable: " +
                "Class.forName/NoSuchFieldException are not Exceptions' only shapes here, and " +
                "a wipe path may never throw). Body was:\n$helper",
            helper.contains("catch (_: Throwable)"),
        )
        assertFalse(
            "closeConnectorDbHandle must not construct a database or resolve a database " +
                "path — it is destructive-side only. Body was:\n$helper",
            helper.contains("getWritableDatabase") || helper.contains("getReadableDatabase") ||
                helper.contains("getDatabasePath"),
        )
    }

    // -----------------------------------------------------------------------
    // (3) the honest selection-failure classification
    // -----------------------------------------------------------------------

    /** The pure rule itself — plain-JVM (the enum has no Android deps). */
    @Test
    fun selectionFailure_isClassifiedHonestly() {
        assertEquals(
            "a failed selection WITH a distributor installed must never claim " +
                "NO_DISTRIBUTOR — 'install ntfy' sends the user to fix the one thing that " +
                "isn't broken",
            PushEnableFailure.DISTRIBUTOR_SELECTION,
            PushEnableFailure.forFailedDistributorSelection(distributorInstalled = true),
        )
        assertEquals(
            "with genuinely no distributor installed, NO_DISTRIBUTOR (and its install-ntfy " +
                "copy) is the honest answer",
            PushEnableFailure.NO_DISTRIBUTOR,
            PushEnableFailure.forFailedDistributorSelection(distributorInstalled = false),
        )
    }

    /**
     * …and the modal must actually WIRE it: the selection-failure callback used
     * to hardcode `errorCopyFor(PushEnableFailure.NO_DISTRIBUTOR)`, which is
     * exactly how the wedge surfaced as "Install ntfy from F-Droid" on a phone
     * with ntfy installed.
     *
     * Non-vacuousness: reverting the callback to the hardcoded constant fails
     * both assertions.
     */
    @Test
    fun modalSelectionFailure_usesTheHonestClassification() {
        val src = File(
            repoRoot(), "androidApp/src/main/java/com/vg/run/NotificationSettingsModal.kt",
        ).readText()

        assertTrue(
            "NotificationSettingsModal's selection-failure branch must classify through " +
                "PushEnableFailure.forFailedDistributorSelection (re-probing whether a " +
                "distributor is installed), not assume NO_DISTRIBUTOR",
            src.contains("PushEnableFailure.forFailedDistributorSelection("),
        )
        assertFalse(
            "the hardcoded errorCopyFor(PushEnableFailure.NO_DISTRIBUTOR) call must be gone " +
                "— it is the lie the 2026-08-11 defect surfaced behind",
            src.contains("errorCopyFor(PushEnableFailure.NO_DISTRIBUTOR)"),
        )
    }
}
