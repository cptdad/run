package com.vg.run

import android.content.Context
import java.io.File
import java.security.KeyStore

/**
 * LegacyTorWarmCache — by-name destruction of the RETIRED warm-Tor-cache
 * artifacts. It holds no key material and creates nothing; it exists only
 * because the DATA outlives the CODE.
 *
 * WHAT THE FEATURE WAS. `TorWarmCacheCrypto` (deleted) sealed a snapshot of
 * Tor's `state` plus its cached consensus/microdescriptors into
 * `filesDir/tor_warm_cache.enc`, under a Tink AEAD whose AndroidKeystore master
 * key ([LEGACY_MASTER_KEY_ALIAS], wrapped keyset in
 * [LEGACY_KEYSET_PREFS_NAME]) was built deliberately WITHOUT
 * `setUnlockedDeviceRequired(true)` — the Android equivalent of iOS's
 * AfterFirstUnlock class — because the FCM-woken `NotificationPollRunner`
 * snapshotted and reloaded the cache while the phone was locked in a pocket.
 *
 * WHY IT IS GONE (2026-07-31). That runner was the ONLY production caller of
 * `TorManager(warmCache = true)` / `snapshotWarmCache()`, and it was deleted with
 * the poll-manifest removal: push wake no longer starts Tor at all (on
 * either transport, FCM or UnifiedPush). Its justification — "the background poll runs while
 * the phone is locked" — described no shipped path any more, so what was left was
 * a dormant weak-gated Keystore key, the same gating that made the poll manifest exploitable,
 * kept alive for a startup optimisation nothing asked for. A fresh install now
 * creates no alias, no keyset and no blob.
 *
 * WHY THIS FILE STILL EXISTS. An install that ran a warm-cache build carries all
 * three artifacts, and nothing else would remove them: the class that owned these
 * names is deleted, so deleting them by name here is the only cleanup path. The
 * blob sits at a TOP-LEVEL sibling of `tor_direct/`, outside the tree
 * `WipeRoutine` and `TorManager.stopAndDiscardState` sweep, so even a full wipe
 * would step around it. Left alone it would stay in `filesDir` forever as dated,
 * app-attributable proof Tor was used, with the key that decrypts it still in the
 * Keystore.
 *
 * Tor's working dirs are PERSISTENT (see `TorManager.dataDir`), which does not make
 * this redundant: the live `tor_direct/` tree is plain files that every wipe path
 * deletes, whereas this blob is sealed under a Keystore key built WITHOUT
 * `setUnlockedDeviceRequired(true)` — usable while the phone is locked, the poll
 * manifest's gating class — and is deleted by nothing but the two calls here.
 *
 * ORDER, at every entry point: Keystore alias FIRST (crypto-erase, so an
 * interrupted pass still leaves the blob undecryptable), then the wrapped keyset,
 * then the ciphertext. Same shape and same reasoning as
 * [NotificationPollStore.eraseLegacyManifestKeySurface].
 *
 * Every function here is idempotent, PURELY destructive (no write, no
 * `edit().commit()` — so unlike the manifest-mirror purge it can never MINT a prefs
 * file on an install that never had one) and never throws. That is what makes it
 * safe both on the wipe path, where any write after the erasure would re-create
 * residue, and on every launch.
 */
object LegacyTorWarmCache {

    /**
     * Wrapped Tink keyset of the removed warm-cache AEAD. Also listed in
     * `WipeRoutine.PREFS_FILES` — belt and braces, since
     * [eraseLegacyKeySurface] already deletes it in the crypto-erase-first
     * position.
     */
    const val LEGACY_KEYSET_PREFS_NAME = "run_torcache_keyset_prefs"

    /** Keystore alias of the removed warm-cache master key (the weak-gated one). */
    private const val LEGACY_MASTER_KEY_ALIAS = "run_torcache_master_key"

    /**
     * The removed AEAD blob. A TOP-LEVEL sibling of `tor_direct/`, deliberately
     * OUTSIDE the tree every Tor cleanup sweeps, which is exactly why it needs an
     * explicit deletion by name.
     */
    private const val LEGACY_BLOB_FILE_NAME = "tor_warm_cache.enc"

    /**
     * Crypto-erasure of the removed warm-cache key surface: the Keystore master
     * key first, then its wrapped Tink keyset. Creates nothing, writes nothing,
     * never throws.
     *
     * Idempotent and best-effort: the alias is normally already absent, and the
     * Keystore being unavailable (locked keybag on some OEMs, keystore daemon
     * hiccup) is not an error worth surfacing — the next launch retries, and a
     * surviving alias without the keyset still decrypts nothing.
     */
    fun eraseLegacyKeySurface(context: Context) {
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
     * Deletes the ciphertext blob and the `.tmp` an interrupted atomic write
     * could have stranded next to it. Called AFTER [eraseLegacyKeySurface] on
     * every path, never instead of it.
     */
    fun deleteLegacyBlob(context: Context) {
        try {
            File(context.filesDir, LEGACY_BLOB_FILE_NAME).delete()
            File(context.filesDir, "$LEGACY_BLOB_FILE_NAME.tmp").delete()
        } catch (_: Exception) { /* best-effort */ }
    }

    /**
     * ONE-TIME (per install, effectively per launch and idempotent) destruction of
     * every retired warm-cache artifact. Modelled on
     * [NotificationPollStore.purgeLegacyCapabilityMirror] and on the other
     * idempotent legacy purges: unconditional, unflagged, cheap.
     *
     * Deliberately NOT gated on a "did I already purge" flag — such a flag is
     * itself a persisted artifact that would need its own wipe-list entry, and
     * repeating four deletions that create nothing costs less than getting that
     * wrong. It is likewise NOT gated on [ProcessWipeLatch]: unlike the manifest-mirror
     * purge there is no write to suppress, and a deletion landing after a wipe is
     * simply a no-op.
     *
     * Runs regardless of whether background notifications were ever enabled — the
     * blob could have been written by any earlier build, and the caller cannot
     * know. Never throws: a failure here must never fail the app.
     */
    fun purgeLegacyWarmCache(context: Context) {
        eraseLegacyKeySurface(context)
        deleteLegacyBlob(context)
    }
}
