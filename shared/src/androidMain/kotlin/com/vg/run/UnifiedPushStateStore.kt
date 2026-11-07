package com.vg.run

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * UnifiedPushStateStore — the ONE new on-disk artifact the UnifiedPush tier
 * introduces: a SharedPreferences file (`unifiedpush_state_prefs`) holding this
 * device's WebPush *receiving address*.
 *
 * WHAT IT HOLDS
 * -------------
 *  - `up_endpoint` — the distributor's RFC 8030 endpoint URL, in CLEARTEXT (see
 *    "WHY THE ENDPOINT STAYS PLAINTEXT" below). The relay POSTs a contentless
 *    wake to it.
 *  - `up_keys_enc` — the RFC 8291 subscription's `p256dh` **and** `auth`, sealed
 *    together under an AES-256-GCM AndroidKeyStore key ([KEYSTORE_ALIAS]) with
 *    the endpoint bound in as associated data. NEVER cleartext since 2026-08-11;
 *    see "THE `auth` SECRET" and "MIGRATION" below.
 *  - `up_unregistered_notice_pending` — a bare presence marker so the settings
 *    modal can tell the user ONCE that their distributor dropped the
 *    registration.
 *  - `up_p256dh` / `up_auth` — LEGACY cleartext, written by builds before
 *    2026-08-11 and never written again. Read once, re-sealed into
 *    `up_keys_enc`, then removed.
 *
 * The matching WebPush PRIVATE key never comes near this file: the connector
 * library keeps it in its own `unifiedpush-connector` SQLite DB, AES-GCM sealed
 * under the AndroidKeyStore alias `UnifiedPush`.
 *
 * It holds **no inboxId and no capability**, and it must never be extended to.
 * That is not stylistic: it is the exact line the
 * design is drawn at. Read [NotificationPollStore]'s kdoc for the history — the
 * deleted `manifest_enc` mirror kept (inboxId, relay READ capability) pairs
 * under a deliberately weak, locked-device-readable key, and the read cap IS
 * the inbox OWNER capability (drain / delete-inbox / rotate both caps). An AFU
 * forensic image therefore handed an examiner the ability to drain and destroy
 * every inbound inbox. Nothing in THIS file grants any relay authority
 * whatsoever, and that has not changed.
 *
 * THE `auth` SECRET — the classification this file used to get WRONG
 * ------------------------------------------------------------------
 * Until 2026-08-11 this kdoc called `p256dh` and `auth` "the two keys … public
 * halves" and bounded their disclosure at "the same shape as the FCM
 * registration token". **`auth` is not public.** RFC 8291 §3.2 defines it as a
 * 16-octet *shared* authentication secret: it is mixed into the HKDF that
 * derives the content-encryption key, precisely so that knowing the
 * subscription's public key is NOT enough to encrypt to it. The pair
 * (`p256dh`, `auth`) is exactly the input an RFC 8291 sender needs.
 *
 * That matters here because of a gate this app owns:
 * `RunPushService.REQUIRE_ENCRYPTED_PUSH` drops any wake the connector could
 * not decrypt, and its whole security argument is "only the relay holds the
 * subscription keys, so an authenticated wake can only have come from the
 * relay". Anyone holding endpoint + `p256dh` + `auth` can RFC 8291-encrypt a
 * record, POST it to the endpoint, and make the handset display the generic
 * "Notification" banner ON DEMAND — enough to confirm a seized image belongs to
 * a watched handset, to confirm the app is still installed and opted in, or to
 * provoke the user into opening Rún under observation. FCM/APNs have no
 * equivalent: pushing to those tokens needs vendor credentials. Cleartext at
 * rest was justified by the wrong classification, so the fix is at rest.
 *
 * It leaks no message content and no vault authority — this is a
 * behaviour-oracle / nuisance vector, not a compromise — which is why the fix
 * is proportionate rather than vault-grade.
 *
 * WHY BOTH VALUES ARE SEALED, NOT JUST `auth`
 * -------------------------------------------
 * `p256dh` genuinely IS a public key (the relay holds it, and it is handed out
 * by the distributor), so sealing it is not what closes the finding — sealing
 * `auth` is. It rides along anyway because: forging needs BOTH, so an attacker
 * who recovers `auth` from somewhere else (the connector's own `keys` table —
 * see the caveat under [KEYSTORE_ALIAS]) still cannot proceed from this file;
 * they are written and read as one unit, so one blob is simpler and cannot tear
 * into a half-migrated pair; and nothing anywhere depends on reading `p256dh`
 * without `auth`.
 *
 * WHY THE ENDPOINT STAYS PLAINTEXT (and is nonetheless tamper-evident)
 * -------------------------------------------------------------------
 * Three reasons, in order of weight:
 *  1. It must stay readable independently of the Keystore. It is the address
 *    every teardown/unregister decision keys on, and it is the value
 *    `RunViewModel` compares to decide whether a rotated endpoint invalidates
 *    the session's "already registered" set.
 *  2. Sealing it would buy little. The endpoint is minted by, and stored by,
 *    the DISTRIBUTOR app — a whole-device image yields it from that app's data
 *    regardless of what we do, and the endpoint ALONE cannot forge a wake past
 *    `REQUIRE_ENCRYPTED_PUSH`.
 *  3. It would add a failure mode with no upside: a transient Keystore error
 *    would make the address unreadable, and this store cannot distinguish that
 *    from "no subscription yet".
 * It is not left unprotected, though: the endpoint is bound into the blob as
 * AEAD **associated data**, so swapping it (a malicious app-data restore
 * substituting an attacker-controlled push server, which the plausibility check
 * alone cannot catch) makes the keys fail to open and the whole subscription
 * read back as absent. Authenticated-but-not-encrypted is exactly the property
 * wanted here.
 *
 * Known limitation: the residual exposure IS real and is the cost of the tier: the file
 * proves this app was configured for push and names the push server host. That
 * is why it is on [WipeRoutine]'s deletion list, why [clear] uses `remove()`
 * rather than writing blanks, and why writes are latched (below).
 *
 * MIGRATION — read-old-write-new, never discard
 * ---------------------------------------------
 * Installs that opted in before 2026-08-11 carry `up_p256dh`/`up_auth` in
 * cleartext. [readSubscription] still reads them, RE-SEALS them into
 * `up_keys_enc`, and only then removes the cleartext (write-before-delete, with
 * a read-back gate). Discarding them instead was considered and REJECTED: a
 * distributor only ever re-announces an endpoint when asked, this store cannot
 * ask (the connector lives in `:androidApp`), and nothing else would — so a
 * discard would silently kill push for every existing opt-in until the user
 * happened to toggle the setting off and on. Never brick a live opt-in.
 *
 * The legacy path is one-shot and SELF-TIGHTENING: once [KEYSTORE_ALIAS] exists
 * (i.e. this install has sealed at least once) cleartext keys are ignored
 * outright, so an app-data restore cannot re-plant a subscription it controls —
 * a restore can write `shared_prefs`, but it cannot write the Keystore.
 *
 * ABSENCE-NOT-ARTIFACT
 * --------------------
 * [clear] REMOVES keys; it never writes an empty/sentinel value. A written
 * falsy value is itself proof the app was configured, an absent key is not —
 * the same rule [NotificationLevelStore.clearLevel] follows. Removal routes
 * through [KeyValueStore.remove], whose `contains()` guard means clearing a
 * store that was never written does not MINT the prefs file.
 *
 * WRITES ARE GATED ON [ProcessWipeLatch]
 * --------------------------------------
 * Per that class's rule for a new consumer. The wake path is asynchronous and
 * out-of-process: after [WipeRoutine] deletes this file, the distributor can
 * still deliver a `NEW_ENDPOINT` broadcast (our unregister is best-effort and
 * may not have landed), and an ungated write would re-create
 * `unifiedpush_state_prefs.xml` — carrying the push-server URL, dated AFTER the
 * erasure. That is precisely the post-wipe residue class the latch exists for.
 * The latch is checked BEFORE any Keystore work, so a post-wipe write cannot
 * re-mint [KEYSTORE_ALIAS] either.
 * ACCEPTED COST: if the user wipes and then re-provisions and re-enables
 * notifications inside the SAME process, the endpoint is not persisted, so the
 * toggle reports failure and reverts. Restarting the app fixes it, and Android
 * tears the whole session down on background anyway
 * (`MainActivity.onStop` → `finishAndRemoveTask`), so the window is narrow. A
 * silent post-wipe artifact is the worse of the two failures.
 *
 * Reads and removals are NOT gated — a read creates nothing (it never mints the
 * Keystore key either), and a removal is guarded against file creation as
 * described above. The migration RE-SEAL is a write and IS gated.
 *
 * THE LATCH IS NOT THE ONLY GATE, AND MUST NOT BE TREATED AS ONE. It is armed
 * exclusively by [WipeRoutine], so it says nothing about the two IN-SESSION
 * teardowns (the settings opt-out and the enable-FAILURE branch of
 * `RunViewModel.setBackgroundNotificationsEnabledAwaiting`), which delete this
 * file and then keep running. Those are covered on the CALLER side, by
 * `RunPushService` refusing to write once the persisted [NotificationLevel] no
 * longer reads UNIFIED_PUSH — every teardown clears the level first. A new
 * writer added here must be gated the same way, at its call site; the latch
 * alone would let a late distributor broadcast re-mint this file.
 */
class UnifiedPushStateStore(context: Context) {

    companion object {
        /** Prefs file name; listed in `WipeRoutine.PREFS_FILES`. */
        const val PREFS_NAME = "unifiedpush_state_prefs"

        /**
         * AndroidKeyStore alias of the AES-256-GCM key that seals [KEY_KEYS_ENC].
         *
         * PUBLIC because `UnifiedPushSupport.eraseKeySurface` must destroy it in
         * the crypto-erase-FIRST position, alongside the connector's own
         * `UnifiedPush` alias — one function, one call site per teardown path
         * (wipe, settings opt-out, failed enable), so the two aliases can never
         * drift apart. Naming it here rather than duplicating the literal is the
         * same single-source rule [NotificationPollStore.LEGACY_KEYSET_PREFS_NAME]
         * follows.
         *
         * WHY A KEY OF OUR OWN rather than the connector's `UnifiedPush` alias:
         * that alias belongs to a third-party AAR whose lifecycle we do not
         * control (it is created and may be re-minted during distributor
         * selection, and a version bump can rename it — the reason
         * `eraseKeySurface` is pinned by a test). Encrypting our data under it
         * would make our reads depend on a library's internal key management.
         *
         * WHY IT IS **NOT** `setUnlockedDeviceRequired(true)`, unlike the vault's
         * Tink master key: the writer is `RunPushService.onNewEndpoint`, an
         * out-of-process distributor broadcast that can land while the device is
         * locked. A locked-device-refusing key would silently drop a rotated
         * endpoint that nothing ever re-announces. That deliberately makes this
         * an AfterFirstUnlock-class key — the same gating that made the removed manifest mirror exploitable — and the
         * difference that makes it acceptable is what it protects: a push-wake
         * forgery input, not a relay OWNER capability. It stops the file-level
         * (AFU image / app-data restore) extraction this finding is about; it
         * does NOT stop an adversary who can execute as this app's UID on a live
         * device, and it is not claimed to.
         *
         * CAVEAT, verified by disassembling connector-3.3.5: the connector
         * encrypts only `privKey` in its own `keys` table — it reads `auth` back
         * in the CLEAR. So `auth` also exists, unsealed, inside
         * `databases/unifiedpush-connector` until a teardown deletes those rows.
         * That copy is out of our hands; this store owns only its own.
         */
        const val KEYSTORE_ALIAS = "run_up_state_key"

        private const val KEY_ENDPOINT = "up_endpoint"

        /** The sealed (`p256dh`, `auth`) pair. Written since 2026-08-11. */
        private const val KEY_KEYS_ENC = "up_keys_enc"

        /**
         * LEGACY cleartext key material. Read-only: never written again, removed
         * as soon as the sealed form is proven on disk. See "MIGRATION".
         */
        private const val LEGACY_KEY_P256DH = "up_p256dh"
        private const val LEGACY_KEY_AUTH = "up_auth"

        private const val KEY_UNREGISTERED_NOTICE = "up_unregistered_notice_pending"

        /** Bare presence marker — the value carries no information. */
        private const val MARKER = "1"
    }

    private val store = KeyValueStore(context, PREFS_NAME)

    /**
     * The current subscription, or null when any part is missing, unsealable, or
     * the stored endpoint no longer passes [isPlausibleUnifiedPushEndpoint].
     *
     * Re-validating on READ (not only on write) is deliberate: an examiner or a
     * malicious app-data restore can edit this file, and its endpoint ends up in
     * an HTTP body the relay acts on. Fail-CLOSED on every ambiguity — a
     * tampered value, a blob that will not open, or a Keystore that is
     * momentarily unavailable all yield "no subscription", which makes the next
     * registration pass ask the distributor for a fresh one rather than
     * forwarding attacker-chosen bytes. Never the reverse: a failed decrypt must
     * not fall back to any cleartext.
     *
     * Creates nothing. In particular it never mints [KEYSTORE_ALIAS] — only the
     * two write paths do.
     */
    fun readSubscription(): UnifiedPushSubscription? {
        val endpoint = store.getString(KEY_ENDPOINT) ?: return null
        if (!isPlausibleUnifiedPushEndpoint(endpoint)) return null

        val sealed = store.getString(KEY_KEYS_ENC)
        if (sealed != null) {
            // Sealed form wins outright: no cleartext fallback on a failed open,
            // or a file-write attacker could force the legacy path by corrupting
            // one byte.
            val opened = UnifiedPushStateCrypto.open(sealed, endpoint) ?: return null
            val (p256dh, auth) = opened
            if (p256dh.isEmpty() || auth.isEmpty()) return null
            // Self-heal a migration that wrote the blob but whose removals did
            // not land (two commits, not one editor — see [migrateLegacyKeys]).
            dropLegacyCleartextIfPresent()
            return UnifiedPushSubscription(endpoint, p256dh, auth)
        }

        // LEGACY read path (pre-2026-08-11 installs). Refused outright once this
        // install has ever sealed, so a restore that plants cleartext keys it
        // controls cannot be honoured — it can write shared_prefs, not the
        // Keystore. Fails toward ALLOWING on an unreadable Keystore: refusing
        // there would kill a real opt-in over a transient error, while allowing
        // it only restores the pre-fix behaviour for one read.
        if (UnifiedPushStateCrypto.hasSealedBefore()) return null
        val p256dh = store.getString(LEGACY_KEY_P256DH) ?: return null
        val auth = store.getString(LEGACY_KEY_AUTH) ?: return null
        if (p256dh.isEmpty() || auth.isEmpty()) return null
        migrateLegacyKeys(endpoint, p256dh, auth)
        return UnifiedPushSubscription(endpoint, p256dh, auth)
    }

    /**
     * Persists a subscription handed over by the distributor. Refuses an
     * implausible endpoint outright rather than storing something the relay
     * would reject anyway (and that a log/diagnostic could later echo), and
     * refuses key material that cannot be sealed.
     *
     * Returns whether it was stored — callers treat false as "no usable
     * endpoint yet", never as a hard error. That is why a Keystore failure
     * refuses the WHOLE save instead of degrading to cleartext: the three values
     * are only meaningful together, an endpoint with no openable keys reads back
     * as absent anyway, and writing one would mint the push-server-naming
     * artifact for nothing.
     */
    fun saveSubscription(endpoint: String, p256dh: String?, auth: String?): Boolean {
        // Latch FIRST — before any Keystore work, so a post-wipe broadcast can
        // neither write the file nor re-mint the alias.
        if (ProcessWipeLatch.wipedThisProcess) {
            return false
        }
        if (!isPlausibleUnifiedPushEndpoint(endpoint)) {
            return false
        }
        if (p256dh.isNullOrEmpty() || auth.isNullOrEmpty()) {
            return false
        }
        if (!UnifiedPushStateCrypto.isEncodable(p256dh) || !UnifiedPushStateCrypto.isEncodable(auth)) {
            return false
        }
        val sealed = UnifiedPushStateCrypto.seal(p256dh, auth, endpoint) ?: run {
            return false
        }
        // One editor, one commit — the endpoint and the sealed keys are only
        // meaningful together, and a torn write would leave a subscription that
        // can never be encrypted to (or, worse, a blob whose bound endpoint no
        // longer matches the stored one). [KeyValueStore.putStringsSync] is the
        // batching, durable primitive already used for coupled writes elsewhere.
        store.putStringsSync(
            mapOf(
                KEY_ENDPOINT to endpoint,
                KEY_KEYS_ENC to sealed,
            )
        )
        // A re-registration on a legacy install lands here before any read ever
        // migrated: drop the cleartext the old build left.
        dropLegacyCleartextIfPresent()
        return true
    }

    /**
     * Drops every value this store holds — the subscription (sealed AND legacy
     * cleartext) AND the pending notice. `remove()`, never a blank write (see
     * the class kdoc). Idempotent and safe on an install that never enabled the
     * tier.
     *
     * The Keystore key is NOT destroyed here: crypto-erasure is
     * `UnifiedPushSupport.eraseKeySurface`'s job, which every teardown path runs
     * FIRST, before this. Doing it in both places would be harmless but would
     * split the ownership of a purge list, which is the drift class this
     * codebase keeps closing.
     */
    fun clear() {
        store.remove(KEY_ENDPOINT)
        store.remove(KEY_KEYS_ENC)
        store.remove(LEGACY_KEY_P256DH)
        store.remove(LEGACY_KEY_AUTH)
        store.remove(KEY_UNREGISTERED_NOTICE)
    }

    /**
     * The distributor told us the registration is gone (app uninstalled, user
     * revoked, distributor reset). Recorded so the settings modal can say so
     * ONCE, the next time it opens — there is no vault or UI available in the
     * service callback that observes this.
     *
     * Deliberately NOT surfaced as a system notification: a notification the
     * user never earned by receiving a message is a use-artifact on a device
     * that may since have been seized, and it would advertise "this app is
     * installed and configured" on a lock screen. Same reasoning as
     * `RunFcmService.onNewToken`.
     */
    fun markUnregisteredNoticePending() {
        if (ProcessWipeLatch.wipedThisProcess) return
        store.putString(KEY_UNREGISTERED_NOTICE, MARKER)
    }

    /** True once, then clears — the notice is shown one time only. */
    fun consumeUnregisteredNotice(): Boolean {
        val pending = store.getString(KEY_UNREGISTERED_NOTICE) != null
        if (pending) store.remove(KEY_UNREGISTERED_NOTICE)
        return pending
    }

    /**
     * Re-seals a pre-2026-08-11 cleartext pair, then drops the cleartext.
     *
     * ORDER IS THE WHOLE POINT: write the sealed copy, prove it is readable,
     * and only then remove the originals. The reverse ordering (or an unproven
     * write) would destroy the only copy of a live subscription — the same
     * asymmetry `plainDbKeyReadBackProves` guards on the vault's recovery blob.
     * Two commits rather than one editor because [KeyValueStore] exposes no
     * combined put+remove, and widening that expect/actual for this would ripple
     * to iOS; the surviving interleaving (blob written, cleartext not removed)
     * is benign and self-heals on the next read via [dropLegacyCleartextIfPresent].
     *
     * Gated on [ProcessWipeLatch] like every other write here, and silently
     * abandoned when the Keystore is unavailable — the caller keeps the values
     * it already read, so the subscription keeps working and the next read
     * retries the migration.
     *
     * Android's read-back sees the in-memory map `commit()` already updated, so
     * it is weaker proof here than on iOS (the same caveat `storeWriteProven`
     * documents). It still catches the case that matters — a seal that never
     * reached the store at all — and the ordering, not the read-back, is what
     * makes an interrupted migration non-destructive.
     */
    private fun migrateLegacyKeys(endpoint: String, p256dh: String, auth: String) {
        if (ProcessWipeLatch.wipedThisProcess) return
        if (!UnifiedPushStateCrypto.isEncodable(p256dh) || !UnifiedPushStateCrypto.isEncodable(auth)) return
        val sealed = UnifiedPushStateCrypto.seal(p256dh, auth, endpoint) ?: return
        store.putStringsSync(mapOf(KEY_KEYS_ENC to sealed))
        if (store.getString(KEY_KEYS_ENC) != sealed) return
        dropLegacyCleartextIfPresent()
    }

    /**
     * Purely destructive, unlatched by the class rule (a removal creates
     * nothing, and [KeyValueStore.remove]'s `contains()` guard means it cannot
     * MINT the prefs file on an install that never had one).
     */
    private fun dropLegacyCleartextIfPresent() {
        store.remove(LEGACY_KEY_P256DH)
        store.remove(LEGACY_KEY_AUTH)
    }
}

/**
 * The AES-256-GCM seal over the RFC 8291 key pair, under an AndroidKeyStore key
 * this app owns ([UnifiedPushStateStore.KEYSTORE_ALIAS]).
 *
 * VAULT-INDEPENDENT ON PURPOSE. `RunPushService` runs on an out-of-process
 * distributor broadcast with no unlocked vault, so `CryptoProvider` /
 * `CryptoManager` (whose master key is `setUnlockedDeviceRequired(true)` and
 * whose keyset is a vault-lifecycle artifact) cannot be used here. A dedicated
 * key is the smallest thing that works; see the alias kdoc for the gating
 * tradeoff and its limits.
 *
 * Blob layout: `up1:` ‖ base64(IV(12) ‖ ciphertext ‖ GCM tag(16)). The version
 * prefix is not decoration — it makes "is this the sealed form?" a decision
 * about a KEY NAME plus an explicit tag, never a length heuristic over an
 * attacker-supplied string (the shape `readSelectorMeta` used to be exposed to).
 *
 * The endpoint is bound in as associated data, so the cleartext endpoint cannot
 * be swapped without the keys failing to open.
 *
 * Every entry point is total: it answers `null`/`false` instead of throwing, so
 * a Keystore hiccup degrades to "no subscription" rather than crashing a service
 * callback.
 */
private object UnifiedPushStateCrypto {

    private const val KEYSTORE = "AndroidKeyStore"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val BLOB_PREFIX = "up1:"
    private const val AAD_CONTEXT = "run-unifiedpush-subscription-v1|"
    private const val IV_BYTES = 12
    private const val TAG_BITS = 128

    /**
     * The two values are joined by a newline, so neither may contain one. Base64
     * / base64url — which is all RFC 8291/8292 permit for these fields — cannot,
     * so this can only reject material that was already unusable. Checked rather
     * than escaped: refusing a save is recoverable (the toggle reports "no
     * endpoint yet"), a mis-split pair silently is not.
     */
    private const val SEPARATOR = '\n'

    fun isEncodable(value: String): Boolean = !value.contains(SEPARATOR)

    /**
     * True only when this install has positively sealed at least once. Any
     * failure answers `false` — see the "fails toward allowing" note at the
     * legacy read path in [UnifiedPushStateStore.readSubscription].
     */
    fun hasSealedBefore(): Boolean = try {
        keyStore().containsAlias(UnifiedPushStateStore.KEYSTORE_ALIAS)
    } catch (_: Exception) {
        false
    }

    /** Seals the pair, minting the key if this install has none yet. */
    fun seal(p256dh: String, auth: String, endpoint: String): String? = try {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, ensureKey())
        cipher.updateAAD(aad(endpoint))
        val ct = cipher.doFinal("$p256dh$SEPARATOR$auth".toByteArray(Charsets.UTF_8))
        val iv = cipher.iv
        // AndroidKeyStore always generates a 12-byte GCM IV; refuse rather than
        // persist a blob the reader below could not frame.
        if (iv == null || iv.size != IV_BYTES) null
        else BLOB_PREFIX + Base64.encodeToString(iv + ct, Base64.NO_WRAP)
    } catch (_: Exception) {
        null
    }

    /** Opens a blob into `(p256dh, auth)`, or null on ANY doubt. */
    fun open(blob: String, endpoint: String): Pair<String, String>? = try {
        if (!blob.startsWith(BLOB_PREFIX)) {
            null
        } else {
            val raw = Base64.decode(blob.substring(BLOB_PREFIX.length), Base64.NO_WRAP)
            val key = loadKey()
            // IV + at least the 16-byte tag; an empty payload is not a subscription.
            if (key == null || raw.size <= IV_BYTES + 16) {
                null
            } else {
                val cipher = Cipher.getInstance(TRANSFORMATION)
                cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, raw, 0, IV_BYTES))
                cipher.updateAAD(aad(endpoint))
                val plain = String(
                    cipher.doFinal(raw, IV_BYTES, raw.size - IV_BYTES),
                    Charsets.UTF_8,
                )
                val at = plain.indexOf(SEPARATOR)
                if (at <= 0 || at == plain.length - 1) null
                else plain.substring(0, at) to plain.substring(at + 1)
            }
        }
    } catch (_: Exception) {
        null
    }

    private fun aad(endpoint: String): ByteArray =
        (AAD_CONTEXT + endpoint).toByteArray(Charsets.UTF_8)

    private fun keyStore(): KeyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }

    /** Existing key, or null — never mints one, so a READ creates no artifact. */
    private fun loadKey(): SecretKey? = try {
        keyStore().getKey(UnifiedPushStateStore.KEYSTORE_ALIAS, null) as? SecretKey
    } catch (_: Exception) {
        null
    }

    /**
     * Existing key, else a fresh one.
     *
     * No StrongBox request, deliberately: the barrier that matters here is
     * "non-exportable from a filesystem image", which the TEE already provides,
     * and `CryptoManager.ensureMasterKey` documents how ambiguous StrongBox
     * failures turn a one-shot creation into a permanent, unretryable downgrade.
     * That complexity is not worth carrying for a key protecting a wake-forgery
     * input.
     */
    private fun ensureKey(): SecretKey {
        val ks = keyStore()
        (ks.getKey(UnifiedPushStateStore.KEYSTORE_ALIAS, null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE).apply {
            init(
                KeyGenParameterSpec.Builder(
                    UnifiedPushStateStore.KEYSTORE_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .setRandomizedEncryptionRequired(true)
                    .build()
            )
        }.generateKey()
    }
}

/**
 * A WebPush subscription as the relay needs it: where to POST, and the RFC 8291
 * key material to encrypt the wake with. Carries no relay authority.
 *
 * [auth] is a SHARED SECRET (RFC 8291 §3.2), not a public half — it is one of
 * the two inputs needed to forge a wake this device would display. Treat it as
 * secret everywhere it travels: it is sealed at rest (see [UnifiedPushStateStore])
 * and it must never be logged.
 *
 * [toString] redacts: the endpoint names the user's push server (and, on a
 * self-hosted one, effectively the user), so it must never land in a log line
 * through a stray interpolation — the same discipline [InboundInboxRef] applies
 * to capabilities.
 */
data class UnifiedPushSubscription(
    val endpoint: String,
    val p256dh: String,
    val auth: String,
) {
    override fun toString() = "UnifiedPushSubscription(endpoint=[redacted], keys=[redacted])"
}
