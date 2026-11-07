package com.vg.run

import com.vg.run.VaultKdf.DBKEY_LENGTH

// ---------------------------------------------------------------------------
// DbKeyPayload — the INNER plaintext of every wrapped DB-key blob (`vlt_c`,
// `vlt_cn` and every auth-bound blob): the SQLCipher key R plus, after raw-key
// adoption, the adopted key K' and the mode tag. Plus the pure raw-key adoption
// decisions.
//
// RawKeyAdoptionDecisionTest and RawKeyAdoptionPayloadSealTest pin every length,
// tag byte and decision. The adoption RUNTIME (derive K',
// probe, rewrite `vlt_c`) stays in VaultSelector.
// ---------------------------------------------------------------------------

// --- Raw-key adoption: the SQLCipher KEY MODE carried in the DB-key payload ---
//
// 2026-10-07. Android opened SQLCipher in PASSPHRASE mode: the 32-byte dbKey
// goes through PBKDF2-HMAC-SHA512 × 256 000 on every open (2.08 s per unlock on
// a Samsung A13). Stretching a uniformly random 256-bit key adds no security,
// so an Android vault "adopts" raw-key mode: K' = the key that stretch produces
// for THIS file (PBKDF2(dbKey, file salt)) is computed once, proven to open the
// file, and stored next to dbKey; later unlocks open with `x'<K'>'` (5 ms). The
// file is byte-for-byte unchanged — no rekey, no page rewrite (androidTest
// `RawKeyAdoptionTest` proves both modes open the same file and read each
// other's pages). Security-neutral: K' is a deterministic function of dbKey,
// and it lives only where dbKey already lives — inside the same KEK-AEAD.
//
// WHERE THE MODE LIVES: inside the AEAD'd INNER plaintext — the bytes
// `aesGcmEncrypt(·, kek, VaultCryptoContexts.DBKEY_INNER)` seals, i.e. what every `vlt_c`,
// `vlt_cn` and `ab:` blob wraps. Never a separate store key (a separate key
// could be deleted/planted independently of the blob it describes) and never
// outside the KEK layer (the mode is useless without the key, and a tag an
// attacker can flip must not exist). The DB key itself (dbKey, "R") is ALWAYS
// kept, so every payload can always be opened in passphrase mode — that is
// what makes the unlock fallback possible and keeps `vlt_rc` (which wraps R and
// can never be migrated: the code is never persisted) valid forever.
//
//   32 bytes  R                     legacy, untagged ⇒ PASSPHRASE (establish-on-read)
//   33 bytes  R ‖ 0x01              PASSPHRASE, explicitly tagged
//   65 bytes  R ‖ 0x02 ‖ K'         RAW: open with K', fall back to R
//   anything else                   malformed ⇒ null ⇒ the unlock's neutral Error
//
// The lengths are disjoint, so the decode is unambiguous. iOS never ADOPTS (its
// VaultFactory keeps the defaults: it already opens raw with R itself), but it
// reads and writes the same payloads through this same code.

/** The SQLCipher key mode a DB-key payload selects. */
internal enum class DbKeyMode { PASSPHRASE, RAW }

/**
 * A decoded inner payload. [dbKey] is R (always present); [rawKey] is the
 * adopted K' and non-null exactly when [mode] is RAW; [tagged] is false only for
 * the legacy 32-byte form. Holds COPIES — the owner wipes them via [wipe].
 */
internal class DbKeyPayload(
    val dbKey: ByteArray,
    val mode: DbKeyMode,
    val rawKey: ByteArray?,
    val tagged: Boolean,
) {
    fun wipe() { dbKey.secureWipe(); rawKey?.secureWipe() }
}

internal object DbKeyPayloadCodec {
    internal const val DBKEY_MODE_TAG_PASSPHRASE: Byte = 0x01
    internal const val DBKEY_MODE_TAG_RAW: Byte = 0x02

    /**
     * Encode the inner payload: `R ‖ 0x01` without [rawKey], `R ‖ 0x02 ‖ K'` with
     * it. Every NEW write uses the tagged forms; only pre-2026-10-07 blobs are 32
     * bytes. The returned buffer is the caller's to wipe.
     */
    internal fun encodeDbKeyPayload(dbKey: ByteArray, rawKey: ByteArray?): ByteArray {
        require(dbKey.size == DBKEY_LENGTH) { "dbKey must be $DBKEY_LENGTH bytes" }
        if (rawKey == null) return dbKey + byteArrayOf(DBKEY_MODE_TAG_PASSPHRASE)
        require(rawKey.size == DBKEY_LENGTH) { "raw key must be $DBKEY_LENGTH bytes" }
        return dbKey + byteArrayOf(DBKEY_MODE_TAG_RAW) + rawKey
    }

    /** Re-encode a decoded payload byte-for-byte in its canonical (tagged) form. */
    internal fun encodeDbKeyPayload(payload: DbKeyPayload): ByteArray =
        encodeDbKeyPayload(payload.dbKey, payload.rawKey)

    /**
     * Decode an inner payload; null when malformed. A missing tag (the legacy
     * 32-byte form) is PASSPHRASE — establish-on-read, never an error and never
     * evidence of anything: every vault provisioned before raw-key adoption looks
     * exactly like this. An unknown tag byte or length is null, which every caller
     * treats exactly like a damaged `vlt_c` (the unlock's neutral, non-counting
     * Error — the credential already verified, so never Denied, never a wipe).
     */
    internal fun decodeDbKeyPayload(plain: ByteArray): DbKeyPayload? = when {
        plain.size == DBKEY_LENGTH ->
            DbKeyPayload(plain.copyOf(), DbKeyMode.PASSPHRASE, null, tagged = false)
        plain.size == DBKEY_LENGTH + 1 && plain[DBKEY_LENGTH] == DBKEY_MODE_TAG_PASSPHRASE ->
            DbKeyPayload(plain.copyOfRange(0, DBKEY_LENGTH), DbKeyMode.PASSPHRASE, null, tagged = true)
        plain.size == 2 * DBKEY_LENGTH + 1 && plain[DBKEY_LENGTH] == DBKEY_MODE_TAG_RAW ->
            DbKeyPayload(
                plain.copyOfRange(0, DBKEY_LENGTH), DbKeyMode.RAW,
                plain.copyOfRange(DBKEY_LENGTH + 1, plain.size), tagged = true,
            )
        else -> null
    }

    /**
     * The order in which an unlock tries the modes a payload offers: the TAGGED
     * mode first, then the other. A RAW payload carries both keys, so it falls
     * back to passphrase mode with R — a raw open that fails (stale K', transient
     * fault) never costs the unlock. A PASSPHRASE payload offers only passphrase
     * mode: it carries no K', and deriving one from an R that does not open the
     * file could not produce a key that does.
     */
    internal fun openModeOrder(mode: DbKeyMode): List<DbKeyMode> = when (mode) {
        DbKeyMode.RAW -> listOf(DbKeyMode.RAW, DbKeyMode.PASSPHRASE)
        DbKeyMode.PASSPHRASE -> listOf(DbKeyMode.PASSPHRASE)
    }
}

internal object RawKeyAdoptionPolicy {
    /**
     * May this unlock ADOPT raw-key mode (derive K', probe it, rewrite `vlt_c`)?
     *
     * Promotion is the only write this feature performs, and it fires ONLY on
     * positive evidence gathered in this very unlock — never on a guess, never on
     * an absence:
     *
     *  - [platformAdopts] — the VaultFactory can derive K' (Android). iOS: never.
     *  - [openedInPassphraseMode] — the vault ACTUALLY OPENED in passphrase mode
     *    with R just now. That open is the proof R is the file's key; K' is derived
     *    from it, so it is the precondition for a K' that can mean anything. (It
     *    also covers the self-heal case: a RAW payload whose K' failed and whose
     *    passphrase fallback opened re-adopts from the file's current salt.)
     *  - ![credentialBlobsMovedThisUnlock] — the KDF migration or the DB-key rotation
     *    reconcile rewrote `vlt_c`/`vlt_cn` in this unlock. The blob this unlock
     *    unwrapped is then no longer the stored one; defer one cycle.
     *  - [rotationPending] must be CONFIRMED `false` — a DB-key rotation record
     *    (`vlt_cn`) means the union {vlt_c, vlt_cn} is still the authority over
     *    which key the file is on, and adoption must never re-wrap `vlt_c` while
     *    that is unresolved. Unknown (`null`) refuses.
     *  - [journalPending] must be CONFIRMED `false` — a stale iOS write-ahead
     *    journal would replay an older `vlt_c` over a single-key write
     *    (see [VaultWriteProofs.singleKeyDbKeyWriteAllowed]).
     *    Unknown refuses.
     *  - an [authBound] (Lever B `ab:`) vault additionally needs
     *    [recoveryNetProven]: the re-wrap reuses the live auth-bound key with no
     *    second biometric prompt (the same unverified public-key re-wrap change-PIN
     *    and the KDF migration already perform), so a PROVEN `vlt_rc` must stand
     *    behind it, exactly like the legacy-key reconcile requires.
     *
     * Refusing is always safe: the vault simply stays in passphrase mode (slower,
     * never less openable). The commit itself is further gated by
     * [rawKeyAdoptionMayCommit].
     */
    internal fun rawKeyAdoptionAllowed(
        platformAdopts: Boolean,
        openedInPassphraseMode: Boolean,
        credentialBlobsMovedThisUnlock: Boolean,
        rotationPending: Boolean?,
        journalPending: Boolean?,
        authBound: Boolean,
        recoveryNetProven: Boolean,
    ): Boolean = platformAdopts && openedInPassphraseMode && !credentialBlobsMovedThisUnlock &&
        rotationPending == false && journalPending == false &&
        (!authBound || recoveryNetProven)

    /**
     * The commit gate, evaluated after K' exists. ALL must hold:
     *  - [rawProbeOpened]: `VaultFactory.probeRawKey(K')` OPENED the real vault
     *    file (non-empty `sqlite_master`). The derivation is a computation, the
     *    probe is the evidence; a K' that has not opened the file is never stored.
     *  - [storedBlobUnchanged]: `vlt_c` still holds exactly the blob this unlock
     *    unwrapped, so the rewrite replaces what was proven and nothing newer.
     *  - [roundTripOk]: the new blob was unwrapped + decrypted back to the exact
     *    payload before the write (`null` = not checkable without a biometric
     *    prompt, i.e. an auth-bound blob — allowed only because
     *    [rawKeyAdoptionAllowed] already demanded a PROVEN recovery net there).
     */
    internal fun rawKeyAdoptionMayCommit(
        rawProbeOpened: Boolean,
        storedBlobUnchanged: Boolean,
        roundTripOk: Boolean?,
    ): Boolean = rawProbeOpened && storedBlobUnchanged && roundTripOk != false
}
