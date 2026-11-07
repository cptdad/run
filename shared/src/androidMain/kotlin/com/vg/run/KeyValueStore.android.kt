package com.vg.run

import android.content.Context

/**
 * The SharedPreferences file of the vault-selector store (the "store" column of the
 * VaultStoreKeys table: `vlt_a`, `vlt_c`, `vlt_rc`, … plus the fate-shared
 * [INACTIVITY_ARMED_ANCHOR_KEY] and PinAttemptsStore anchors). WipeRoutine deletes it
 * whole. The value is the on-disk file name and must never change.
 */
const val VAULT_SELECTOR_PREFS_NAME = "vault_selector_prefs"

actual class KeyValueStore(context: Context, private val name: String) {
    // Resolve the SharedPreferences handle PER
    // CALL instead of caching it for the instance's lifetime. Context.getSharedPreferences
    // is backed by ContextImpl's own per-name cache, so this stays cheap — but caching it
    // HERE meant a store instance held past a deleteSharedPreferences() call (e.g. the
    // "Erase and start over" flow, which reuses the same Activity/ViewModel) kept
    // referencing the just-unlinked SharedPreferencesImpl. That instance still holds the
    // full pre-wipe in-memory map, and the FIRST write during re-provisioning would see
    // mFile.exists() == false and rewrite the ENTIRE stale map to disk — resurrecting the
    // destroyed vault's vlt_rc/vlt_a/vlt_c/vlt_abk. Resolving fresh here always lands on
    // the current on-disk (or freshly-recreated) file.
    //
    // Store applicationContext, not the passed Context: callers do pass Activity
    // contexts (e.g. MainActivity.kt, InactivityWipe.kt), and this instance can
    // outlive that Activity (held by a VaultSelector inside a longer-lived owner).
    // Retaining an Activity here would leak it. getSharedPreferences resolves to the
    // same on-disk file regardless of which Context in this process it's called on
    // (same package data dir), so this doesn't change which file is read/written —
    // it only drops the strong ref to the Activity. The per-call resolution above is
    // unaffected: every call still re-resolves via appCtx, so a post-wipe write still
    // can't resurrect a stale in-memory map.
    private val appCtx: Context = context.applicationContext
    private val prefs: android.content.SharedPreferences
        get() = appCtx.getSharedPreferences(name, Context.MODE_PRIVATE)

    actual fun getString(key: String): String? = prefs.getString(key, null)

    // ---------------------------------------------------------------------
    // EVERY WRITE BELOW USES commit(), NEVER apply() (2026-07-31).
    //
    // THE BUG apply() CAUSES. apply() SNAPSHOTS the whole in-memory map into
    // `MemoryCommitResult.mapToWriteToDisk` and hands it to a background
    // flush. `Context.deleteSharedPreferences` (WipeRoutine's deletion pass)
    // evicts the ContextImpl cache entry and unlinks the file, but it neither
    // cancels nor waits for that queued flush. When the flush then runs,
    // `SharedPreferencesImpl.writeToFile` only short-circuits the "nothing
    // changed" case WHEN THE FILE STILL EXISTS — so with the file gone it
    // takes the write branch and RE-CREATES vault_selector_prefs.xml from the
    // PRE-WIPE snapshot: vlt_a, vlt_c and vlt_rc all back on disk, dated after
    // the erasure. That is the exact residue class the wipe exists to remove
    // (and it can re-arm MainActivity's orphaned-credential wipe on the next
    // launch: both blobs present, key erased ⇒ unreadable ⇒ wipe again).
    // commit() writes on the calling thread before returning, so there is no
    // queued flush left to land after a wipe.
    //
    // WHY NOT [ProcessWipeLatch]. The latch is the right tool for a write
    // ISSUED after a wipe; this write is issued BEFORE it and merely LANDS
    // after, so a latch set during the wipe cannot retroactively cancel it —
    // it would close a different window. Worse, the writes it WOULD block are
    // the load-bearing ones: `provisionCredentialAndVault` persists the
    // credential verifier and the wrapped DB key through putString, and
    // re-provisioning in the same process after a wipe (the orphaned-credential
    // route lands straight on setup) is an explicitly supported flow. Gating it
    // would give Android the silent-write-failure mode iOS's locked-keybag
    // kvPut has — a vault file with no credential behind it. Do not add one.
    //
    // COST. The WRITING callers are rare and off the main thread: provisioning
    // (Dispatchers.IO, already running Argon2id 64 MiB × 3 and a SQLCipher
    // create) and the notification-level toggle (Dispatchers.IO).
    //
    // Two callers DO run on the main thread — stated explicitly because an
    // earlier version of this comment claimed "every caller" was off it, which
    // was wrong:
    //   • InactivityWipe.refreshMtimeProbe — every unlocked cold launch, via
    //     MainActivity.onCreate → checkAndWipeIfNeeded. One tiny XML value, and
    //     onCreate already does synchronous Keystore work (credentialsReadable)
    //     before reaching it, so the added latency is marginal — but it IS a
    //     main-thread commit() and should not be described otherwise.
    //   • VaultSelector's constructor purges (purgeDecoyArtifactsIfNeeded,
    //     migrateLegacyKeyNamesIfNeeded) — main thread at 2 of its 3
    //     construction sites. These are ZERO-I/O in steady state: the
    //     contains() guard in remove() below short-circuits before touching an
    //     editor, because those legacy keys are long absent on real installs.
    // Neither is a recomposition/per-message/loop path. If a future caller adds
    // one, it needs Dispatchers.IO, not a relaxation back to apply().
    // This also closes a real durability hole on the way past — the provision's
    // two credential blobs used to be async, so a power loss right after setup
    // could leave a vault FILE with no credential blobs, i.e. the orphaned-vault
    // dead end. iOS has always been synchronous here (SecItemAdd commits before
    // it returns), so this is parity, not a new contract.
    // ---------------------------------------------------------------------

    @android.annotation.SuppressLint("ApplySharedPref")
    actual fun putString(key: String, value: String) {
        prefs.edit().putString(key, value).commit()
    }

    @android.annotation.SuppressLint("ApplySharedPref")
    actual fun putStringSync(key: String, value: String) {
        // commit() (not apply()) so the write is durable before we return —
        // a force-quit during PIN evaluation must not discard the increment.
        // The blocking disk write is acceptable here: it runs
        // off the main thread (PinEntryScreen unlock path) and only for the
        // tiny pin-attempts counter.
        //
        // Identical to [putString]'s body; kept separate as a contract — see the
        // expect declaration (PinAttemptsStore's counter-then-anchor and
        // InactivityWipe's timestamp-then-marker orderings depend on it).
        prefs.edit().putString(key, value).commit()
    }

    @android.annotation.SuppressLint("ApplySharedPref")
    actual fun putStringsSync(values: Map<String, String>) {
        // Single editor + commit() → the whole batch is written atomically and
        // durably before returning. The change-PIN flow relies on this to swap
        // the credential verifier and the wrapped DB key as one unit; since
        // PROVISION-1 (2026-08-09) the first-run provision does too, instead of the
        // two independent putString calls that could tear.
        val editor = prefs.edit()
        for ((k, v) in values) editor.putString(k, v)
        // PROVISION-1: commit()'s Boolean was discarded. It stays non-fatal here for
        // the same reason the iOS actual does not throw (see its note) — a throw
        // would report change-PIN as FAILED — but a `false` is the
        // ONLY signal Android has that a batch did not reach disk, and callers cannot
        // see it themselves: `getString` reads the in-memory map the editor already
        // updated, so a read-back succeeds even when the disk write did not. Losing it
        // silently is what made an un-diagnosable half-state possible; log it loudly.
        if (!editor.commit()) {
            platformLogWarn(
                "KeyValueStore",
                "multi-key commit() returned false (${values.size} keys) — the batch is in memory " +
                    "but may not have reached disk; it will be gone after a process death"
            )
        }
    }

    actual fun contains(key: String): Boolean = prefs.contains(key)

    @android.annotation.SuppressLint("ApplySharedPref")
    actual fun remove(key: String): Boolean {
        // Absent key ⇒ do NOT touch the editor at all. This is not an
        // optimisation: `edit().remove(k)` on a key the map does not hold makes
        // NO change, and SharedPreferencesImpl only skips the disk write for a
        // no-change commit WHEN THE FILE ALREADY EXISTS — with the file missing
        // it MINTS an empty vault_selector_prefs.xml. That matters because
        // `VaultSelector.purgeDecoyArtifactsIfNeeded` issues FOUR unconditional
        // removes from the constructor, and a VaultSelector is constructed three
        // times per launch (InactivityWipe, MainActivity's orphan check,
        // RunViewModel) — including in the launch right after WipeRoutine deleted
        // the file, so the wipe was followed by a freshly dated prefs file it
        // never wrote. Same guard, same reason, as
        // NotificationPollStore.purgeLegacyCapabilityMirror's contains() check.
        // `prefs` is re-resolved per call (see the class note above), so a delete
        // racing between the two reads yields a FRESH empty instance rather than
        // a stale map — never a resurrection.
        //
        // A real removal then commits (see the putString note): removals here are
        // security-state transitions — dropping vlt_rc when Lever B is disabled
        // revokes a second, independent vault-decrypt path — and must not be
        // discardable by a process death, nor land after a wipe.
        // Absent ⇒ confirmed gone (see the expect's @return): there is nothing
        // to delete and nothing that could come back.
        if (!prefs.contains(key)) return true
        return prefs.edit().remove(key).commit()
    }
}
