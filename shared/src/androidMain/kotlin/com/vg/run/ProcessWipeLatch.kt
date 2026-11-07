package com.vg.run

/**
 * ProcessWipeLatch — a one-way, RAM-ONLY "a wipe has happened in this process"
 * flag. Set by `WipeRoutine.wipePersistentState`; honoured by anything that
 * could otherwise RE-CREATE an artifact the wipe just destroyed.
 *
 * WHY IT EXISTS (regression 2026-07-30). `WipeRoutine` crypto-erases a
 * subsystem's key surface and deletes its ciphertext — but ANY code that
 * constructs that subsystem afterwards silently REGENERATES the Keystore alias
 * and the wrapped Tink keyset (such an init creates both when absent) and can
 * then rewrite the blob. The concrete case was the warm-Tor-cache AEAD: the
 * result was a Keystore key, a keyset file and an encrypted Tor guard/consensus
 * blob all dated AFTER the wipe — standalone forensic proof Tor was used, on
 * paths that run while the user is absent and cannot re-wipe.
 *
 * The same primitive produced THREE separate bugs in one day — a post-wipe Tor
 * start in `InactivityWipe`, a push-woken background poller's `finally` (that
 * poller is since removed), and a manifest write. That is why the refusal lives
 * in the PRIMITIVE rather than at the call sites: patching the three that existed
 * would have left the fourth.
 *
 * WHY IT LIVES IN ITS OWN FILE. It began inside a since-removed warm-cache
 * AEAD file, which was its first consumer. Its SCOPE was always broader than that file —
 * `WipeRoutine` sets it as a general post-wipe-regeneration guard — and the
 * split proved itself: the warm cache was RETIRED on 2026-07-31 (see
 * [LegacyTorWarmCache]) and the latch survived the deletion untouched, instead
 * of a general safety mechanism vanishing as a side effect of removing one dead
 * feature. It is in `androidMain` because `:shared` cannot depend on
 * `:androidApp`, and `WipeRoutine` (in `:androidApp`) must be able to set it.
 *
 * WHAT IT DOES **NOT** BLOCK — the distinction is the whole design. Only a
 * consumer that explicitly asks is refused, and nothing load-bearing does. Tor
 * itself still starts, bootstraps and runs; a vault can be re-provisioned in the
 * same process; the relay and push registration are untouched. Consumers read
 * `wipedThisProcess` (UnifiedPushStateStore, the push-wake freshness check, the
 * Tor keep-alive service and RunViewModel among them);
 * [NotificationPollStore.purgeLegacyCapabilityMirror] skips its one prefs WRITE
 * post-wipe so a legacy-cleanup pass can never re-create the file the wipe just
 * deleted. (Its earlier consumer, the warm-Tor-cache AEAD, is
 * gone — nothing creates that key surface any more, so there is nothing left to
 * resurrect.)
 *
 * WHAT IT IS **NOT**: it is not "the app must stay black". The post-wipe black
 * deniability cover is a SEPARATE process-lifetime flag, `ProcessWipeCover` in
 * `:androidApp` (iOS sibling: `AppState.wipedThisSession`), armed only by a
 * DENIABLE in-session wipe. This latch is armed by EVERY wipe, including the
 * launch-time ones — inactivity, the orphaned-credential self-heal, the debug
 * test-wipe hook — that are designed to fall through to setup so the user can
 * re-provision in this same process. Gating the cover on THIS flag shipped a
 * permanent-black-screen regression over a healthy re-provisioned vault (2026-08-01,
 * fixed 2026-08-02): rotation recreates the Activity in the same process, and
 * nothing but a force-quit clears a process-lifetime flag. Keep the two distinct.
 *
 * A NEW CONSUMER should gate its key/keyset CREATION on [wipedThisProcess] (or
 * throw from its own init), not merely its writes — the regenerated Keystore
 * alias and keyset file are themselves the post-wipe artifacts, even if no
 * ciphertext is ever produced. This is the rule that matters when the next
 * background-capable subsystem is added; it is not specific to the feature that
 * motivated it.
 *
 * LIFETIME: RAM only, deliberately. Persisting it would itself be a post-wipe
 * artifact — the exact bug class it exists to prevent — so a fresh process
 * starts unlatched and the refusing subsystem works normally again from the next
 * launch. Within the process it is one-way: nothing but a DEBUG-build test reset
 * clears it, and its default (`false`) is only ever reached before a wipe, so
 * there is no ambiguous state in which a write could slip through.
 */
object ProcessWipeLatch {

    private val wiped = java.util.concurrent.atomic.AtomicBoolean(false)

    /**
     * True once [latch] has run in this process. Public so a WRITE site can gate
     * on it directly rather than relying on some owning primitive throwing first
     * — see the class kdoc's rule for a new consumer.
     */
    val wipedThisProcess: Boolean get() = wiped.get()

    /**
     * Called FIRST inside `WipeRoutine.wipePersistentState` — before the
     * crypto-erasures, so a write racing an erasure is refused too. Idempotent;
     * never cleared by any production path.
     */
    fun latch() {
        wiped.set(true)
    }

    /**
     * DEBUG-ONLY reset, and a **no-op in release builds** (`isDebugBuild` is
     * :shared's BuildConfig.DEBUG). Instrumented tests share one process, so a
     * wipe test would otherwise latch every later test class out of whatever
     * gates on it. Deliberately not usable in a shipped binary: the latch must be
     * one-way there.
     */
    fun resetForTest() {
        if (isDebugBuild) wiped.set(false)
    }
}
