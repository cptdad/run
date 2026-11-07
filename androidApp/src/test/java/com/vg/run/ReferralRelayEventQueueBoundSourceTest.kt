package com.vg.run

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Guards the referral relay-event queue bound.
 *
 * `ReferralManager` (commonMain) bounds its own pre-hook event buffer at
 * `MAX_PENDING_RELAY_EVENTS = 8` (`ReferralManager.kt:174`, `private const val`,
 * not visible from either platform layer) because each entry pins two contact
 * aliases in RAM. Both platform sinks (`RunViewModel._referralRelayEvents`,
 * `AppState.referralRelayEvents`) used to append unboundedly, which defeated
 * that cap: `ReferralManager`'s success-only dedupe never arms while an
 * introduction's second leg stays unreachable, so every re-delivered accept
 * appended one more entry and queued one more modal, forever.
 *
 * SOURCE-LEVEL, same technique and same reason as
 * [ForwardSecrecyStalledNoticeSourceTest]: `RunViewModel` is an
 * `AndroidViewModel` needing a real `Application` and a live `ReferralManager`,
 * and `AppState` needs a live Kotlin/Native controller — this module's unit-test
 * tier has no Robolectric/mocking framework and cannot execute Swift at all, so
 * the bound/dedupe shape is checked structurally on both platforms' source.
 * Bodies are scanned with comments STRIPPED so prose that merely names a call
 * can neither satisfy nor trip a guard.
 *
 * No runtime Swift test is added: this module's test harness cannot execute
 * iOS/Swift code, so the AppState half of this fix is covered by this
 * source-level scan only (build + e2e are the Swift-side verification, per
 * project convention for SwiftUI/lifecycle changes).
 */
class ReferralRelayEventQueueBoundSourceTest {

    private val viewModel: String by lazy {
        SourcePins.stripped(SourcePins.RUN_VIEW_MODEL)
    }
    private val appState: String by lazy {
        stripComments(iosAppStateSources())
    }
    private val referralManager: String by lazy {
        stripComments(File(repoRoot(), "shared/src/commonMain/kotlin/com/vg/run/ReferralManager.kt").readText())
    }

    // -----------------------------------------------------------------------
    // 0. The commonMain constant this fix mirrors hasn't silently changed
    //    value out from under the platform-side literal duplicates.
    // -----------------------------------------------------------------------

    @Test
    fun referralManager_maxPendingRelayEventsIsStillEight() {
        assertTrue(
            "ReferralManager.MAX_PENDING_RELAY_EVENTS must still be 8 — both platform " +
                "mirrors below are hand-kept in lockstep with this literal",
            referralManager.contains("private const val MAX_PENDING_RELAY_EVENTS = 8"),
        )
    }

    // -----------------------------------------------------------------------
    // 1. Android: RunViewModel bounds + dedupes
    // -----------------------------------------------------------------------

    @Test
    fun runViewModel_mirrorsTheCommonMainBoundByValue() {
        assertTrue(
            "RunViewModel must mirror ReferralManager.MAX_PENDING_RELAY_EVENTS by value " +
                "(8) — see the kdoc naming ReferralManager.kt:174 as the source",
            viewModel.contains("private const val MAX_PENDING_REFERRAL_RELAY_EVENTS = 8"),
        )
    }

    @Test
    fun onIntroRelayed_routesThroughTheBoundedAppendHelper() {
        assertTrue(
            "the onIntroRelayed hook must route through appendReferralRelayEvent(event), " +
                "never append unboundedly via `it + event`",
            viewModel.contains("referralManager?.onIntroRelayed = { event -> appendReferralRelayEvent(event) }"),
        )
        assertFalse(
            "the old unbounded append pattern must be gone",
            viewModel.contains("_referralRelayEvents.update { it + event }"),
        )
    }

    @Test
    fun appendReferralRelayEvent_dedupesOnIntroIdBeforeAppending() {
        val fn = viewModel.functionBody("    private fun appendReferralRelayEvent(event: ReferralRelayEvent) {")
        assertTrue(
            "must dedupe the existing list on introId before adding the new event, so a " +
                "re-delivered accept for an already-queued intro replaces it in place instead " +
                "of adding a second entry. Body was:\n$fn",
            fn.contains("filterNot { it.introId == event.introId }"),
        )
        val dedupeAt = fn.indexOf("filterNot { it.introId == event.introId }")
        val appendAt = fn.indexOf("deduped + event")
        assertTrue("the dedupe must run BEFORE the new event is added", dedupeAt in 0 until appendAt)
    }

    /**
     * Non-vacuousness: bounding with `.take(MAX_PENDING_REFERRAL_RELAY_EVENTS)` instead of
     * `.drop(withNew.size - MAX_PENDING_REFERRAL_RELAY_EVENTS)` would silently flip the
     * eviction direction to "drop the NEWEST" — the exact defect class of an inverted
     * eviction. This pins "oldest dropped" specifically.
     */
    @Test
    fun appendReferralRelayEvent_dropsTheOldestEntryOnOverflow() {
        val fn = viewModel.functionBody("    private fun appendReferralRelayEvent(event: ReferralRelayEvent) {")
        assertTrue(
            "overflow must be bounded to MAX_PENDING_REFERRAL_RELAY_EVENTS by dropping from " +
                "the FRONT (oldest), not the back (newest). Body was:\n$fn",
            fn.contains("if (withNew.size > MAX_PENDING_REFERRAL_RELAY_EVENTS)") &&
                fn.contains("withNew.drop(withNew.size - MAX_PENDING_REFERRAL_RELAY_EVENTS)"),
        )
        assertFalse(
            "must never bound via .take(...), which would drop the newest arrival instead",
            fn.contains(".take(MAX_PENDING_REFERRAL_RELAY_EVENTS)"),
        )
    }

    // -----------------------------------------------------------------------
    // 2. iOS: AppState bounds + dedupes the same way (source-scanned only —
    //    no Swift execution available in this test harness)
    // -----------------------------------------------------------------------

    @Test
    fun appState_mirrorsTheCommonMainBoundByValue() {
        assertTrue(
            "AppState must mirror ReferralManager.MAX_PENDING_RELAY_EVENTS by value (8) — " +
                "see the doc comment naming ReferralManager.kt:174 as the source",
            appState.contains("private static let maxPendingReferralRelayEvents = 8"),
        )
    }

    @Test
    fun appState_bothOnIntroRelayedInstallsRouteThroughTheBoundedHelper() {
        // Both session-opening paths (didOpenVault() and recoverWithCode()) install
        // the hooks through ONE helper, so the one onIntroRelayed install inside it
        // is the only call site — and each path must still call the helper.
        val occurrences = Regex("self\\?\\.appendReferralRelayEvent\\(event\\)").findAll(appState).count()
        assertTrue(
            "the shared onIntroRelayed install (installReferralSessionHooks()) must call " +
                "appendReferralRelayEvent(event), not a bare .append(event) — found $occurrences " +
                "call site(s), need exactly 1",
            occurrences == 1,
        )
        val helper = appState.functionBody("    private func installReferralSessionHooks() {")
        assertTrue(
            "installReferralSessionHooks() must hold the onIntroRelayed install routing " +
                "through the bounded helper. Body was:\n$helper",
            helper.contains("onIntroRelayed = { [weak self] event in") &&
                helper.contains("self?.appendReferralRelayEvent(event)"),
        )
        for (signature in listOf(
            "    private func didOpenVault() {",
            "    func recoverWithCode(_ code: String, credential: String,",
        )) {
            assertTrue(
                "`$signature` must install the referral hooks via installReferralSessionHooks()",
                appState.functionBody(signature).contains("installReferralSessionHooks()"),
            )
        }
        assertFalse(
            "the old unbounded .append(event) pattern must be gone from both onIntroRelayed " +
                "installs",
            appState.contains("self?.referralRelayEvents.append(event)"),
        )
    }

    @Test
    fun appState_appendReferralRelayEvent_dedupesAndBoundsDroppingOldest() {
        val fn = appState.functionBody(
            "    private func appendReferralRelayEvent(_ event: ReferralRelayEvent) {",
            closingIndent = "    ",
        )
        assertTrue(
            "must dedupe the existing list on introId before appending the new event. Body " +
                "was:\n$fn",
            fn.contains("referralRelayEvents.removeAll { \$0.introId == event.introId }"),
        )
        val dedupeAt = fn.indexOf("removeAll { \$0.introId == event.introId }")
        val appendAt = fn.indexOf("referralRelayEvents.append(event)")
        assertTrue("the dedupe must run BEFORE the new event is appended", dedupeAt in 0 until appendAt)
        assertTrue(
            "overflow must be bounded by dropping the OLDEST entries via removeFirst(count), " +
                "never the newest. Body was:\n$fn",
            fn.contains("referralRelayEvents.removeFirst(referralRelayEvents.count - Self.maxPendingReferralRelayEvents)"),
        )
    }

    // -----------------------------------------------------------------------

    /** See [PeriodicReauthLockSourceTest] — same walk, same fail-loud contract. */
    private fun String.functionBody(signature: String, closingIndent: String? = null): String {
        val start = indexOf(signature)
        assertTrue("precondition: `$signature` must exist", start >= 0)
        val indent = closingIndent ?: signature.takeWhile { it == ' ' }
        val closer = "\n$indent}"
        val end = indexOf(closer, start)
        assertTrue("precondition: `$signature` must be closed", end > start)
        return substring(start, end)
    }
}
