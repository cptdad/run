package com.vg.run

import android.content.Context
import java.security.KeyStore

/**
 * NotificationPollStore — LEGACY ARTIFACT HOLDER ONLY, not a live opt-in flag.
 *
 * (2026-07-31) The vendor-push opt-in is no longer read/written
 * here. Android now persists it as a [NotificationLevel] through
 * [NotificationLevelStore] (its own prefs file, `notification_level_prefs` —
 * see `RunViewModel.NOTIFICATION_LEVEL_PREFS_NAME`/`notificationLevelStore`),
 * the single source of truth on both platforms, mirroring iOS's
 * `AppState.pushEnabled`. The `isEnabled`/`setEnabled`/`KEY_ENABLED` trio that
 * used to live here — writing plaintext boolean `bg_notifications_enabled`
 * into THIS file (`notif_manifest_prefs`) — is DELETED: Android used to persist
 * the opt-in TWICE (this file, and separately `NotificationLevelStore`, which
 * had zero Android call sites) and read the wrong one on every gate. There is
 * now exactly one persisted opt-in value.
 *
 * What's left in this object exists ONLY to name and destroy the REMOVED
 * capability-mirror artifacts — see [PREFS_NAME]'s own kdoc note below
 * and [LEGACY_KEYSET_PREFS_NAME]/[eraseLegacyManifestKeySurface]/
 * [purgeLegacyCapabilityMirror]. [PREFS_NAME] itself is kept as a constant
 * (not inlined) for two reasons: `WipeRoutine.PREFS_FILES` still deletes the
 * WHOLE `notif_manifest_prefs` file on every wipe — belt-and-suspenders for
 * any install that still carries a leftover `manifest_enc` blob the one-time
 * launch purge hasn't reached yet, AND for any install that ran a pre-2026-07-31
 * build and so still has a stray `bg_notifications_enabled` key sitting in
 * this file (a dead key now — nothing reads it — but its on-disk presence is
 * still a "this app was configured" tell a wipe must not leave behind).
 *
 * HISTORY — the reason this file used to hold a capability mirror at all. This store used to ALSO hold `manifest_enc`: a list of
 * (inboxId, relay READ capability) pairs, AEAD-sealed under a SEPARATE Keystore
 * key (`ManifestCrypto`, alias `run_manifest_master_key`) built deliberately
 * WITHOUT `setUnlockedDeviceRequired(true)` — the Android equivalent of iOS's
 * AfterFirstUnlock class — so a locked-device FCM token rotation could
 * re-register without an unlocked vault.
 *
 * The exposure bound signed off for that tradeoff ("learns inbox ids + READ
 * capabilities, can pull ciphertext, can NEVER send") was WRONG. Per the relay
 * wire contract (`MessageManager.kt` header) the read capability IS the inbox
 * OWNER capability: it authorises `GET /inbox/{id}` (drain every future inbound
 * ciphertext), `DELETE /inbox/{id}` (destroy the inbox, severing the contact),
 * and BOTH `PUT /inbox/{id}/read-capability` and `.../write-capability` —
 * rotation authenticates with the read-cap header alone
 * (`MessageManager.rotateWriteCapabilityNonDurable`). So an AFU forensic image of a
 * locked-but-powered device yielded, per inbound text inbox, a token letting the
 * examiner drain it, destroy it, lock the owner out permanently, and mint
 * themselves write access.
 *
 * The mirror is GONE — capability material now lives ONLY in the vault, under
 * the strict (unlocked-device-required / PIN) key. `ManifestCrypto` and its
 * Keystore alias are deleted; [purgeLegacyCapabilityMirror] destroys what
 * already-installed devices carry.
 *
 * ACCEPTED COST, deliberate, do not re-engineer around it: `RunFcmService
 * .onNewToken` can no longer re-register while the vault is locked — it has no
 * idea which inboxes exist. After an FCM token rotation, push wakes LAPSE until
 * the next unlock, at which point `PushRegistrationCoordinator.refreshVendorPushRegistration`
 * re-registers every inbound text inbox unconditionally (its "already
 * registered" set is session-scoped RAM, so a new session always re-registers —
 * nothing persisted has to be compared, and nothing can go stale). The canonical
 * rotation causes — reinstall, clear-app-data, restore-to-new-device — destroyed
 * this prefs file with the manifest anyway, so the only case actually lost is
 * FCM's own server-initiated refresh on an otherwise intact install, and
 * reading the messages requires opening the app regardless.
 *
 * EVERY WRITE HERE USES commit(), NEVER apply() (2026-07-30). Same durability
 * reasoning as `InactivityWipe.storeTimestamp`: apply() returns before the XML
 * reaches disk, so a write still queued when WipeRoutine deletes this prefs file
 * flushes AFTERWARDS and RE-CREATES notif_manifest_prefs.xml — a dated post-wipe
 * artifact, which is exactly what a wipe exists to prevent. commit() collapses
 * that window to the write itself. Free here: the (one remaining) write isn't
 * on a hot path.
 */
object NotificationPollStore {

    /**
     * Prefs file name; listed in WipeRoutine.PREFS_FILES.
     *
     * `bg_notifications_enabled` (a retired opt-in key) and
     * `manifest_enc` (the retired capability blob, [LEGACY_KEY_MANIFEST])
     * both lived — at different points in this app's history — inside THIS
     * file. Neither is written by any code path any more; this constant
     * exists only so the legacy-purge functions below and `WipeRoutine` can
     * still find and destroy either one by name on an install that predates
     * the migration that retired it.
     */
    const val PREFS_NAME = "notif_manifest_prefs"

    // -----------------------------------------------------------------------
    // Legacy artifacts of the REMOVED (inboxId, readCap) capability mirror.
    // Named here — the ONE place — so both the one-time upgrade purge and the
    // wipe paths destroy the identical set. `ManifestCrypto` is deleted, so
    // these names can no longer be reached through it; deleting them by name is
    // the only way an install provisioned before the removal gets cleaned up.
    // -----------------------------------------------------------------------

    /** Wrapped Tink keyset of the removed manifest AEAD. In WipeRoutine.PREFS_FILES. */
    const val LEGACY_KEYSET_PREFS_NAME = "run_manifest_keyset_prefs"

    /** Keystore alias of the removed manifest master key (the weak-gated one). */
    private const val LEGACY_MASTER_KEY_ALIAS = "run_manifest_master_key"

    /** The removed AEAD blob's key inside [PREFS_NAME]. */
    private const val LEGACY_KEY_MANIFEST = "manifest_enc"

    /**
     * Crypto-erasure of the REMOVED manifest key surface: the Keystore master
     * key first, then its wrapped Tink keyset. Purely destructive — it creates
     * nothing, writes nothing and never throws — so it is safe on the wipe path
     * (where any write after the erasure would re-create residue) and safe to
     * call on every launch.
     *
     * Idempotent and best-effort: the alias is normally already absent, and the
     * Keystore being unavailable (locked keybag on some OEMs, keystore daemon
     * hiccup) is not an error worth surfacing — the next launch retries.
     *
     * Called from BOTH [purgeLegacyCapabilityMirror] (the one-time upgrade
     * cleanup) and `WipeRoutine.wipePersistentState` (so an install that
     * predates the purge is still crypto-erased by any wipe, in the same
     * key-material-first position `ManifestCrypto.erase` used to occupy).
     */
    fun eraseLegacyManifestKeySurface(context: Context) {
        try {
            val ks = KeyStore.getInstance("AndroidKeyStore")
            ks.load(null)
            ks.deleteEntry(LEGACY_MASTER_KEY_ALIAS)
        } catch (_: Exception) { /* alias absent or Keystore unavailable */ }
        try {
            context.deleteSharedPreferences(LEGACY_KEYSET_PREFS_NAME)
        } catch (_: Exception) { /* best-effort */ }
    }

    /**
     * ONE-TIME (per install, effectively per launch and idempotent)
     * destruction of the removed capability mirror. Deleting the CODE is not
     * deleting the DATA — without this, every already-installed device would
     * keep an AFU-readable relay-owner-capability mirror on disk forever, and
     * the finding would stay live on exactly the population that already has it.
     *
     * Modelled on the codebase's other idempotent legacy purges (unconditional,
     * unflagged `store.remove` calls and by-name deletions). Deliberately NOT gated on a "did I
     * already purge" flag: such a flag is itself a persisted artifact that would
     * need its own wipe-list entry, and repeating three cheap deletions costs
     * less than getting that wrong.
     *
     * Runs regardless of whether push was ever enabled — the mirror could have
     * been written by any earlier build, and the caller (RunApplication.onCreate)
     * cannot know. Never throws: a failure here must never fail the app.
     *
     * ORDER: key material first (crypto-erase, so an interrupted purge still
     * leaves the blob undecryptable), THEN the ciphertext.
     */
    @android.annotation.SuppressLint("ApplySharedPref")
    fun purgeLegacyCapabilityMirror(context: Context) {
        try {
            eraseLegacyManifestKeySurface(context)

            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            // contains() FIRST, for a reason that is not cosmetic: an
            // edit().remove().commit() against a prefs file that does not exist
            // yet CREATES it (SharedPreferencesImpl.writeToFile only short-
            // circuits the no-change case when the file already exists). On a
            // fresh install that never opted into push, an unguarded purge would
            // therefore MINT notif_manifest_prefs.xml — manufacturing the very
            // "this app was configured" artifact the wipe paths exist to remove.
            if (!prefs.contains(LEGACY_KEY_MANIFEST)) return

            // The removal is a full XML rewrite, so it must never land after a
            // wipe: that would re-create notif_manifest_prefs.xml carrying the
            // wiped install's opt-in flag, dated after the erasure. This purge
            // runs from RunApplication.onCreate, which strictly precedes every
            // wipe trigger in the process (MainActivity.onCreate's inactivity /
            // orphaned-credential checks, the ViewModel's panic wipe), so the
            // ordering already holds; the latch is the structural guarantee that
            // it keeps holding if this is ever called from somewhere else.
            if (ProcessWipeLatch.wipedThisProcess) return

            // commit(), not apply() — see the class kdoc.
            prefs.edit().remove(LEGACY_KEY_MANIFEST).commit()
        } catch (_: Exception) {
            // Best-effort by contract: the next launch retries, and the key
            // surface erased above already made any surviving blob useless.
        }
    }
}
