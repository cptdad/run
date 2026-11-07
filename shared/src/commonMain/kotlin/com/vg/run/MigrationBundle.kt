package com.vg.run

// ---------------------------------------------------------------------------
// "Move to new device" — area 1: the PURE part (docs/device-move.md).
//
//   MigrationBundleCodec  the logical vault export ⇄ JSON bytes
//   MigrationSeal         HKDF-SHA256 + AES-256-GCM fixed-size chunk sealing
//   MoveHandleCodec       the QR / paste-text handle
//
// No I/O, no vault handle, no relay, no coroutines. It lives in commonMain
// because a move is Android↔iOS BY DESIGN: the same bytes are written by one
// platform and read by the other, so any per-platform divergence here is an
// unreadable transfer (the user's only copy of their identity), not a cosmetic
// bug. Everything below is therefore expressed over the SHARED primitives
// (`hkdfSha256`, `aesGcmEncrypt`, `Base32`, `jsonEscapeString`) that both
// actuals already agree on.
//
// The types this file operates on (VaultSnapshot, MoveHandle, MoveMetaPolicy,
// MoveConstants) are the shared contract in MoveContracts.kt — extend there,
// never redefine here.
//
// SECURITY NOTES that are load-bearing and easy to lose in a refactor:
//
//  • The one-time code is 160 bits of CSPRNG (MoveConstants.CODE_BYTES) and is
//    NOT stretched — same floor as the vault recovery code. It is a transfer
//    key with a 30-minute TTL on the relay, not a user-chosen credential.
//  • The HKDF info / AAD labels are DELIBERATELY distinct from the vault's
//    recovery labels ("vault:recovery-kek" / "vault-dbkey:recovery") and use a
//    different construction (HKDF vs sha256WithLabel), so a captured migration
//    chunk can never be mistaken for — or confused with — a `vlt_rc` blob.
//  • Nothing here logs key material, and nothing here persists anything. Key
//    hygiene: every derived key and every intermediate copy of the code is
//    wiped in `finally`. The CALLER owns the `code` array it passes in (the QR
//    screen still needs it) and must `secureWipe` it when the flow ends —
//    seal/open wipe only their own defensive copies.
// ---------------------------------------------------------------------------

/**
 * One export of everything that travels with the user (docs/device-move.md "What is
 * in the bundle"). The header fields are OUTSIDE the AEAD-protected snapshot only in
 * the sense that they are ordinary bundle fields — the whole serialized bundle is
 * sealed as one plaintext, so every field here is authenticated.
 *
 * [version] is the BUNDLE-FORMAT version (this codec); [schema] is the vault
 * DATABASE version the snapshot was taken from. They move independently.
 */
data class MigrationBundle(
    /** Bundle format version. See [MigrationBundleCodec.CURRENT_VERSION]; decode rejects anything else. */
    val version: Int = 1,
    /** Vault schema (`DatabaseManager.DATABASE_VERSION`) of the EXPORTING device. Surfaced, never enforced here. */
    val schema: Int,
    /** [MigrationBundle.FROM_ANDROID] / [MigrationBundle.FROM_IOS]. */
    val from: String,
    val createdMs: Long,
    /** 16 base64url chars — see [MoveHandleCodec.newBundleId]. Bound into every chunk's AAD. */
    val bundleId: String,
    val snapshot: VaultSnapshot,
) {
    companion object {
        const val FROM_ANDROID = "android"
        const val FROM_IOS = "ios"
    }
}

// ---------------------------------------------------------------------------
// Bundle codec
// ---------------------------------------------------------------------------

object MigrationBundleCodec {

    /** The only bundle format version this build can read. Decode REJECTS anything else. */
    const val CURRENT_VERSION = 1

    /**
     * The vault schema a bundle written by THIS build carries.
     *
     * COUPLING (no commonMain constant exists to derive it from): this must stay in
     * lock-step with `DatabaseManager.DATABASE_VERSION` (androidMain) — iOS's
     * `IosVaultDatabase` has no schema counter at all, it migrates additively, so
     * Android's number is the shared logical schema tag. `MigrationSchemaPinTest`
     * (androidUnitTest) fails the build if the two drift.
     *
     * Consumers: the IMPORTER compares the bundle's `schema` against this and refuses
     * a NEWER one ("update Rún on the new phone"). This codec never throws on it —
     * surfacing the number is deliberate so the caller can word the error.
     *
     * v9 (2026-09-15) is the `Messages`-table DROP. The bundle never carried
     * messages (the snapshot is contacts/inboxes/groups/members/`_meta`), so a v9
     * bundle is byte-compatible with a v8 importer — but the gate is deliberately
     * conservative and an older build will still answer SCHEMA_TOO_NEW, which is
     * non-destructive and tells the user to update the new phone.
     *
     * v10 (2026-09-24) adds the two GROUP-channel counters to the contact record.
     * Both are encoded and both are read back through `optLong(...) ?: 0L`, so a
     * **v9 bundle still imports** — its contacts simply arrive with the group
     * counters at 0, which is the same establish-on-read baseline the v9 → v10 DB
     * migration gives an existing row. The reverse (a v10 bundle into a v9
     * importer) still answers the conservative SCHEMA_TOO_NEW.
     */
    const val CURRENT_SCHEMA = 10

    /** Malformed / unsupported bundle bytes. Never carries any decoded content in its message. */
    class FormatException(message: String) : Exception(message)

    // Top-level keys.
    private const val K_VERSION = "v"
    private const val K_SCHEMA = "schema"
    private const val K_FROM = "from"
    private const val K_CREATED = "created"
    private const val K_BID = "bid"
    private const val K_CONTACTS = "contacts"
    private const val K_INBOXES = "inboxes"
    private const val K_GROUPS = "groups"
    private const val K_MEMBERS = "members"
    private const val K_META = "meta"

    /**
     * Per-array element cap, shared with the relay/control array scanner
     * ([MAX_PARSE_ARRAY_ELEMENTS] = 8192) so one number bounds every JSON array this
     * app parses. Far above any real vault (8192 contacts), and an OOM here is an
     * `Error` that would escape the callers' `Exception` catch.
     */
    private const val MAX_RECORDS = MAX_PARSE_ARRAY_ELEMENTS

    /** `_meta` row cap. Bounded well above a real vault; the plaintext itself is capped at ~12 MB by [MigrationSeal]. */
    private const val MAX_META_ROWS = 200_000

    private const val MAX_FROM_LEN = 16

    /**
     * Serializes [b] to the wire bytes that [MigrationSeal.seal] takes as plaintext.
     *
     * `_meta` is filtered through [MoveMetaPolicy.isAllowedKey] HERE too, not only in
     * the exporter: a `vlt_*` / `pin_*` / `mig_*` row must never leave the device even
     * inside ciphertext, and this is the last chokepoint before it would.
     *
     * The returned bytes are the CLEARTEXT of every shared secret and capability in the
     * vault. `secureWipe` them as soon as [MigrationSeal.seal] has consumed them.
     * Known limitation: the intermediate JSON is a Kotlin String, which is
     * immutable and cannot be wiped — it lives until GC. Unavoidable without a
     * byte-level serializer, bounded by the fact that this path runs only on an
     * unlocked device that is about to be frozen and wiped, and no worse than the
     * envelope building every message send already does.
     */
    fun encode(b: MigrationBundle): ByteArray = encodeToString(b).encodeToByteArray()

    internal fun encodeToString(b: MigrationBundle): String {
        if (b.version != CURRENT_VERSION) throw FormatException("refusing to encode bundle version ${b.version}")
        if (!isValidFrom(b.from)) throw FormatException("invalid 'from' tag")
        if (!MoveHandleCodec.isValidBundleId(b.bundleId)) throw FormatException("invalid bundleId")
        val s = b.snapshot
        if (s.contacts.size > MAX_RECORDS || s.inboxes.size > MAX_RECORDS ||
            s.groups.size > MAX_RECORDS || s.members.size > MAX_RECORDS
        ) throw FormatException("too many records to encode")
        if (s.meta.size > MAX_META_ROWS) throw FormatException("too many meta rows to encode")

        val sb = StringBuilder(4096)
        sb.append('{')
        sb.append("\"").append(K_VERSION).append("\":").append(b.version)
        sb.append(",\"").append(K_SCHEMA).append("\":").append(b.schema)
        sb.append(",\"").append(K_FROM).append("\":").append(jsonEscapeString(b.from))
        sb.append(",\"").append(K_CREATED).append("\":").append(b.createdMs)
        sb.append(",\"").append(K_BID).append("\":").append(jsonEscapeString(b.bundleId))

        sb.append(",\"").append(K_CONTACTS).append("\":[")
        s.contacts.forEachIndexed { i, c ->
            if (i > 0) sb.append(',')
            sb.append('{')
            str(sb, "contactId", c.contactId, first = true)
            str(sb, "sharedSecret", encodeBase64(c.sharedSecret))
            num(sb, "trustLevel", c.trustLevel.toLong())
            str(sb, "alias", c.alias)
            num(sb, "aliasLastRotated", c.aliasLastRotated)
            str(sb, "mnemonic", c.mnemonic)
            num(sb, "outboundCounter", c.outboundCounter)
            num(sb, "inboundCounter", c.inboundCounter)
            str(sb, "inboundEpoch", c.inboundEpoch)
            num(sb, "outboundCtlCounter", c.outboundCtlCounter)
            num(sb, "inboundCtlCounter", c.inboundCtlCounter)
            // v10 — the group channel's counter space. Emitted unconditionally
            // (numbers, never absent) so a v10 → v10 move carries the spent
            // outbound counter; the importer adds COUNTER_JUMP to it.
            num(sb, "outboundGrpCounter", c.outboundGrpCounter)
            num(sb, "inboundGrpCounter", c.inboundGrpCounter)
            // null is encoded by ABSENCE, so "" and null stay distinguishable.
            if (c.vouchedByContactId != null) str(sb, "vouchedByContactId", c.vouchedByContactId)
            num(sb, "vouchedAt", c.vouchedAt)
            sb.append('}')
        }
        sb.append(']')

        sb.append(",\"").append(K_INBOXES).append("\":[")
        s.inboxes.forEachIndexed { i, r ->
            if (i > 0) sb.append(',')
            sb.append('{')
            str(sb, "inboxId", r.inboxId, first = true)
            str(sb, "contactId", r.contactId)
            num(sb, "createdAt", r.createdAt)
            num(sb, "expiresAt", r.expiresAt)
            str(sb, "direction", r.direction)
            if (r.cap != null) str(sb, "cap", r.cap)
            sb.append('}')
        }
        sb.append(']')

        sb.append(",\"").append(K_GROUPS).append("\":[")
        s.groups.forEachIndexed { i, g ->
            if (i > 0) sb.append(',')
            sb.append('{')
            str(sb, "groupId", g.groupId, first = true)
            str(sb, "name", g.name)
            num(sb, "epoch", g.epoch)
            str(sb, "adminMemberId", g.adminMemberId)
            str(sb, "myMemberId", g.myMemberId)
            num(sb, "createdAt", g.createdAt)
            sb.append('}')
        }
        sb.append(']')

        sb.append(",\"").append(K_MEMBERS).append("\":[")
        s.members.forEachIndexed { i, m ->
            if (i > 0) sb.append(',')
            sb.append('{')
            str(sb, "groupId", m.groupId, first = true)
            str(sb, "memberId", m.memberId)
            if (m.contactId != null) str(sb, "contactId", m.contactId)
            num(sb, "addedAt", m.addedAt)
            str(sb, "tags", m.tags)
            sb.append('}')
        }
        sb.append(']')

        sb.append(",\"").append(K_META).append("\":{")
        var firstMeta = true
        for ((k, v) in s.meta) {
            if (!MoveMetaPolicy.isAllowedKey(k)) continue
            if (!firstMeta) sb.append(',')
            firstMeta = false
            sb.append(jsonEscapeString(k)).append(':').append(jsonEscapeString(v))
        }
        sb.append('}')

        sb.append('}')
        return sb.toString()
    }

    /**
     * Parses bundle bytes produced by [encode].
     *
     * Fails CLOSED with [FormatException] on: a version other than [CURRENT_VERSION],
     * malformed JSON, nesting inside records/meta, a missing required field, a non-string/non-numeric field
     * of the wrong kind, an invalid `from` tag or bundleId, a record with an empty
     * identity field, or an un-decodable base64 `sharedSecret`.
     *
     * Deliberately does NOT fail on a [MigrationBundle.schema] newer than
     * [CURRENT_SCHEMA] — that is the importer's decision and it needs the number to
     * word its error ("update Rún on the new phone").
     *
     * Defence in depth: `_meta` rows are re-filtered through
     * [MoveMetaPolicy.isAllowedKey] and disallowed ones are DROPPED (not rejected) —
     * an old or unpatched exporter, or a bundle assembled by anything but this build,
     * cannot smuggle a `vlt_*` / `pin_*` / `mig_*` row into the new vault.
     */
    fun decode(bytes: ByteArray): MigrationBundle = decodeFromString(bytes.decodeToString())

    internal fun decodeFromString(text: String): MigrationBundle {
        val doc = MigJson.parseBundleDocument(text) ?: throw FormatException("malformed bundle JSON")

        val version = doc.int(K_VERSION) ?: throw FormatException("missing bundle version")
        // Version FIRST: nothing else in the document may be interpreted under an
        // unknown format (a v2 field could mean something else entirely).
        if (version != CURRENT_VERSION) throw FormatException("unsupported bundle version $version")

        val schema = doc.int(K_SCHEMA) ?: throw FormatException("missing schema")
        val from = doc.string(K_FROM) ?: throw FormatException("missing 'from'")
        if (!isValidFrom(from)) throw FormatException("invalid 'from' tag")
        val created = doc.long(K_CREATED) ?: throw FormatException("missing 'created'")
        if (created < 0) throw FormatException("negative 'created'")
        val bid = doc.string(K_BID) ?: throw FormatException("missing bundleId")
        if (!MoveHandleCodec.isValidBundleId(bid)) throw FormatException("invalid bundleId")

        val contacts = doc.records(K_CONTACTS).map { o ->
            ContactRecord(
                contactId = o.req("contactId"),
                sharedSecret = o.reqBytes("sharedSecret"),
                trustLevel = o.reqInt("trustLevel"),
                alias = o.req("alias", allowEmpty = true),
                aliasLastRotated = o.reqLong("aliasLastRotated"),
                mnemonic = o.optString("mnemonic") ?: "",
                outboundCounter = o.optLong("outboundCounter") ?: 0L,
                inboundCounter = o.optLong("inboundCounter") ?: 0L,
                inboundEpoch = o.optString("inboundEpoch") ?: "",
                outboundCtlCounter = o.optLong("outboundCtlCounter") ?: 0L,
                inboundCtlCounter = o.optLong("inboundCtlCounter") ?: 0L,
                // OPTIONAL on purpose: a v9 (or older) bundle carries neither, and
                // must still import — 0 is the establish-on-read baseline.
                outboundGrpCounter = o.optLong("outboundGrpCounter") ?: 0L,
                inboundGrpCounter = o.optLong("inboundGrpCounter") ?: 0L,
                vouchedByContactId = o.optString("vouchedByContactId"),
                vouchedAt = o.optLong("vouchedAt") ?: 0L,
            )
        }

        val inboxes = doc.records(K_INBOXES).map { o ->
            InboxIdRecord(
                inboxId = o.req("inboxId"),
                contactId = o.req("contactId"),
                createdAt = o.reqLong("createdAt"),
                expiresAt = o.reqLong("expiresAt"),
                direction = o.req("direction"),
                cap = o.optString("cap"),
            )
        }

        val groups = doc.records(K_GROUPS).map { o ->
            GroupRecord(
                groupId = o.req("groupId"),
                name = o.req("name", allowEmpty = true),
                epoch = o.reqLong("epoch"),
                adminMemberId = o.req("adminMemberId"),
                myMemberId = o.req("myMemberId"),
                createdAt = o.reqLong("createdAt"),
            )
        }

        val members = doc.records(K_MEMBERS).map { o ->
            GroupMemberRecord(
                groupId = o.req("groupId"),
                memberId = o.req("memberId"),
                contactId = o.optString("contactId"),
                addedAt = o.reqLong("addedAt"),
                tags = o.optString("tags") ?: "",
            )
        }

        val meta = LinkedHashMap<String, String>()
        for ((k, v) in doc.meta) {
            if (MoveMetaPolicy.isAllowedKey(k)) meta[k] = v
        }

        return MigrationBundle(
            version = version,
            schema = schema,
            from = from,
            createdMs = created,
            bundleId = bid,
            snapshot = VaultSnapshot(contacts, inboxes, groups, members, meta),
        )
    }

    /** `android` / `ios` today; kept as a bounded lowercase token so a future platform needs no codec change. */
    private fun isValidFrom(s: String): Boolean =
        s.isNotEmpty() && s.length <= MAX_FROM_LEN &&
            s.all { it in 'a'..'z' || it in '0'..'9' || it == '_' || it == '-' }

    private fun str(sb: StringBuilder, key: String, value: String, first: Boolean = false) {
        if (!first) sb.append(',')
        sb.append('"').append(key).append("\":").append(jsonEscapeString(value))
    }

    private fun num(sb: StringBuilder, key: String, value: Long) {
        sb.append(",\"").append(key).append("\":").append(value)
    }
}

// ---------------------------------------------------------------------------
// Sealing (D6 of docs/device-move.md)
// ---------------------------------------------------------------------------

/**
 * Fixed-size chunk sealing for the transfer bundle.
 *
 * Key:  `HKDF-SHA256(ikm = code, salt = inboxIdBytes, info = "run:migrate:v1", 32)`.
 * Chunk: `AES-256-GCM(chunkPlaintext, key, aad)` where the platform primitive
 *        prepends a FRESH random 12-byte IV — layout `IV(12) ‖ ct ‖ tag(16)`.
 * AAD:  `inboxId ‖ bundleId ‖ index(4 BE) ‖ count(4 BE) ‖ "run:migrate:chunk:v1"`.
 *
 * The AAD concatenation is unambiguous because `inboxId` is validated to the fixed
 * 32-char relay format and `bundleId` to a fixed 16 chars before it is built, so no
 * two distinct (inboxId, bundleId) pairs can produce the same AAD bytes.
 *
 * Binding index+count into the AAD is what makes the transport tamper-evident
 * without any plaintext header: a relay that REORDERS chunks, DROPS one (count
 * changes), DUPLICATES one, or splices in a chunk from another bundle produces an
 * AEAD failure, not a subtly wrong bundle. Only the chunk COUNT (i.e. a size bucket)
 * and the timing leak.
 *
 * ON-WIRE SIZE — every sealed chunk is exactly
 *   12 (IV) + 60 000 (MoveConstants.CHUNK_PLAINTEXT_BYTES) + 16 (GCM tag) = **60 028 bytes**,
 * identical for every chunk of every bundle (the last chunk is random-padded, never
 * short). That is what a `POST /inbox/{id}` body must carry, and it is under the
 * relay's 64 KiB `maxBlobBytes` with 5 508 bytes of headroom.
 *
 * TRANSPORT RULE THAT FOLLOWS FROM THAT NUMBER (area 3, `MoveTransport.postChunk`):
 * post the sealed chunk **raw**. Do NOT route it through the message path's
 * `padMessage` + `aesGcmEncrypt` envelope — that pads to the next power-of-two bucket
 * (`PlatformCrypto.kt` PAD_MIN 256 … PAD_MAX 131072), so 60 028 bytes would land in
 * the 65 536 bucket and post 12 + 65 536 + 16 = **65 564 bytes, 28 over the 64 KiB
 * limit**, and every chunk would be rejected. The chunk is already AEAD-sealed under
 * a key the relay cannot have, and every chunk is the same size, so the message
 * envelope's confidentiality and length-hiding add nothing here.
 */
object MigrationSeal {

    /** Canonical Base32 length of a [MoveConstants.CODE_BYTES]-byte code: 20 B = 160 bits = 32 symbols. */
    const val CODE_SYMBOLS = 32

    private const val GCM_IV_BYTES = 12
    private const val GCM_TAG_BYTES = 16

    /** AEAD expansion of one chunk: IV + tag. */
    const val CHUNK_OVERHEAD_BYTES = GCM_IV_BYTES + GCM_TAG_BYTES

    /** Exact size of one sealed chunk on the wire (see the class KDoc): 60 028 bytes. */
    const val SEALED_CHUNK_BYTES = MoveConstants.CHUNK_PLAINTEXT_BYTES + CHUNK_OVERHEAD_BYTES

    /** Largest plaintext that fits in [MoveConstants.MAX_CHUNKS] chunks (4-byte length prefix included). */
    const val MAX_PLAINTEXT_BYTES = MoveConstants.MAX_CHUNKS * MoveConstants.CHUNK_PLAINTEXT_BYTES - 4

    /**
     * Sealing/opening failed. Message never contains key, code or plaintext material —
     * it is safe to log and safe to show a code for.
     */
    class SealException(message: String) : Exception(message)

    /** The bundle needs more than [MoveConstants.MAX_CHUNKS] chunks. Distinct type ⇒ `MoveError.TOO_LARGE`. */
    class TooLargeException(message: String) : Exception(message)

    /** A fresh 160-bit one-time transfer code. The CALLER owns it and must [secureWipe] it when the move ends. */
    fun newCode(): ByteArray = generateSecureRandom(MoveConstants.CODE_BYTES)

    /** Canonical (uppercase, ungrouped) Crockford Base32 of [code]. Use `Base32.formatGrouped` for display. */
    fun encodeCode(code: ByteArray): String {
        require(code.size == MoveConstants.CODE_BYTES) { "transfer code must be ${MoveConstants.CODE_BYTES} bytes" }
        return Base32.encode(code)
    }

    /**
     * Parses a transfer code. Accepts any case and tolerates the `-` / space grouping a
     * user may retype, folds the Crockford look-alikes (O→0, I/L→1) — but requires
     * EXACTLY [CODE_SYMBOLS] surviving symbols, so a truncated or over-long code fails
     * closed instead of silently decoding to 20 bytes of something else (33 symbols
     * also yield 20 bytes; the surviving-symbol count is the check that catches it).
     *
     * Returns null on anything else. Never throws.
     */
    fun decodeCode(text: String): ByteArray? {
        var symbols = 0
        for (c in text) {
            when (c) {
                ' ', '-', '\t', '\n', '\r' -> {}
                else -> symbols++
            }
        }
        if (symbols != CODE_SYMBOLS) return null
        val bytes = Base32.decode(text) ?: return null
        if (bytes.size != MoveConstants.CODE_BYTES) {
            bytes.secureWipe()
            return null
        }
        return bytes
    }

    /**
     * Pads [plaintext] to a whole number of [MoveConstants.CHUNK_PLAINTEXT_BYTES] chunks
     * (4-byte big-endian length prefix + CSPRNG fill, the same shape as `padMessage`)
     * and seals each chunk. Returns the chunks in index order — the order they must be
     * POSTed and the order the relay returns them.
     *
     * @throws TooLargeException  above [MoveConstants.MAX_CHUNKS] chunks (~12 MB).
     * @throws SealException      on an invalid code / inbox id / bundle id, or a crypto failure.
     */
    fun seal(plaintext: ByteArray, code: ByteArray, inboxId: String, bundleId: String): List<ByteArray> {
        validateSealInputs(code, inboxId, bundleId)
        val chunkPlain = MoveConstants.CHUNK_PLAINTEXT_BYTES
        // 4-byte length prefix + payload, rounded UP to whole chunks (min 1).
        val total = 4L + plaintext.size
        val count = ((total + chunkPlain - 1) / chunkPlain).toInt().coerceAtLeast(1)
        if (count > MoveConstants.MAX_CHUNKS) {
            throw TooLargeException("bundle needs $count chunks (max ${MoveConstants.MAX_CHUNKS})")
        }

        val padded = ByteArray(count * chunkPlain)
        padded[0] = (plaintext.size shr 24).toByte()
        padded[1] = (plaintext.size shr 16).toByte()
        padded[2] = (plaintext.size shr 8).toByte()
        padded[3] = (plaintext.size).toByte()
        plaintext.copyInto(padded, destinationOffset = 4)
        val fill = generateSecureRandom(padded.size - 4 - plaintext.size)
        fill.copyInto(padded, destinationOffset = 4 + plaintext.size)
        fill.secureWipe()

        // Defensive COPY of the code: the caller still needs its array (the QR screen
        // shows the code), so we wipe ours, never theirs.
        val ikm = code.copyOf()
        val key = try {
            hkdfSha256(ikm, inboxId.encodeToByteArray(), MoveConstants.HKDF_INFO.encodeToByteArray(), 32)
        } catch (e: Exception) {
            ikm.secureWipe(); padded.secureWipe(); throw SealException("key derivation failed")
        }
        try {
            val out = ArrayList<ByteArray>(count)
            for (i in 0 until count) {
                val chunk = padded.copyOfRange(i * chunkPlain, (i + 1) * chunkPlain)
                try {
                    out.add(aesGcmEncrypt(chunk, key, chunkAad(inboxId, bundleId, i, count)))
                } catch (e: Exception) {
                    throw SealException("chunk seal failed")
                } finally {
                    chunk.secureWipe()
                }
            }
            return out
        } finally {
            key.secureWipe()
            ikm.secureWipe()
            padded.secureWipe()
        }
    }

    /**
     * Reverses [seal]. [chunks] must be the complete set, in relay order.
     *
     * Verified before anything is decrypted: 1..[MoveConstants.MAX_CHUNKS] chunks, all
     * of IDENTICAL size, each large enough to hold the AEAD overhead and no larger than
     * [SEALED_CHUNK_BYTES]. The count and each index are verified CRYPTOGRAPHICALLY —
     * they are AAD, so "every index present exactly once, in order" and "no chunk
     * missing" are enforced by the AEAD rather than by a header a relay could rewrite:
     * a swap, a drop (count changes), a duplicate or a splice all fail authentication.
     *
     * ALL-OR-NOTHING: on any failure the assembled buffer is wiped and nothing is
     * returned, so a caller can never import a half-decrypted bundle.
     *
     * The returned plaintext is the whole bundle in the clear — the caller owns it and
     * must `secureWipe` it once [MigrationBundleCodec.decode] has consumed it.
     *
     * (A smaller-than-current chunk size is accepted so a bundle written by a build
     * with a smaller CHUNK_PLAINTEXT_BYTES still opens; the total is still bounded by
     * MAX_CHUNKS × CHUNK_PLAINTEXT_BYTES.)
     *
     * @throws SealException on any structural or authentication failure.
     */
    fun open(chunks: List<ByteArray>, code: ByteArray, inboxId: String, bundleId: String): ByteArray {
        if (code.size != MoveConstants.CODE_BYTES) throw SealException("bad transfer code length")
        if (!isValidInboxId(inboxId)) throw SealException("bad transfer inbox id")
        if (!MoveHandleCodec.isValidBundleId(bundleId)) throw SealException("bad bundle id")

        val count = chunks.size
        if (count < 1) throw SealException("no chunks")
        if (count > MoveConstants.MAX_CHUNKS) throw SealException("too many chunks: $count")
        val sealedSize = chunks[0].size
        for (c in chunks) if (c.size != sealedSize) throw SealException("chunks are not all the same size")
        val chunkPlain = sealedSize - CHUNK_OVERHEAD_BYTES
        if (chunkPlain < 1 || chunkPlain > MoveConstants.CHUNK_PLAINTEXT_BYTES) {
            throw SealException("implausible chunk size: $sealedSize")
        }

        val ikm = code.copyOf()
        val padded = ByteArray(count * chunkPlain)
        val key = try {
            hkdfSha256(ikm, inboxId.encodeToByteArray(), MoveConstants.HKDF_INFO.encodeToByteArray(), 32)
        } catch (e: Exception) {
            ikm.secureWipe(); throw SealException("key derivation failed")
        }
        try {
            for (i in 0 until count) {
                val pt = try {
                    aesGcmDecrypt(chunks[i], key, chunkAad(inboxId, bundleId, i, count))
                } catch (e: Exception) {
                    // Wrong code, tampered/reordered/dropped chunk, foreign bundle — all
                    // indistinguishable and all equally fatal. No detail leaks.
                    throw SealException("chunk authentication failed")
                }
                try {
                    if (pt.size != chunkPlain) throw SealException("chunk plaintext size mismatch")
                    pt.copyInto(padded, destinationOffset = i * chunkPlain)
                } finally {
                    pt.secureWipe()
                }
            }
            return try {
                unpadMessage(padded)
            } catch (e: Exception) {
                throw SealException("bundle padding invalid")
            }
        } finally {
            key.secureWipe()
            ikm.secureWipe()
            // unpadMessage returns a fresh copy, so the assembled buffer is always dead here.
            padded.secureWipe()
        }
    }

    private fun validateSealInputs(code: ByteArray, inboxId: String, bundleId: String) {
        if (code.size != MoveConstants.CODE_BYTES) throw SealException("bad transfer code length")
        if (!isValidInboxId(inboxId)) throw SealException("bad transfer inbox id")
        if (!MoveHandleCodec.isValidBundleId(bundleId)) throw SealException("bad bundle id")
    }

    private fun chunkAad(inboxId: String, bundleId: String, index: Int, count: Int): ByteArray =
        inboxId.encodeToByteArray() +
            bundleId.encodeToByteArray() +
            be32(index) +
            be32(count) +
            MoveConstants.CHUNK_AAD_LABEL.encodeToByteArray()

    private fun be32(v: Int): ByteArray = byteArrayOf(
        (v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte()
    )
}

// ---------------------------------------------------------------------------
// The QR / paste handle (D7 of docs/device-move.md)
// ---------------------------------------------------------------------------

/**
 * The move handle codec — depth-1, all-string JSON, exactly the discipline
 * [PairingPayload] uses for the pairing QR, and validated with the SAME primitives
 * ([isValidInboxId], [PairingPayload.isValidCap], the hardened [parseTopLevelJson]).
 *
 *   `{"v":"1","inbox":<32-char inbox id>,"rcap":<43-char read cap>,"code":<32-symbol Base32>,"bid":<16-char bundle id>}`
 *
 * The handle IS the secret (read cap + one-time code). Same exposure as the
 * pairing QR: a photograph of A's screen can drain the bundle first — the UI screens
 * inherit window-level screenshot protection, and B's drain then 404s visibly.
 */
object MoveHandleCodec {

    /** Canonical bundle id: 16 base64url chars (12 CSPRNG bytes). */
    const val BUNDLE_ID_LENGTH = 16

    private const val MAX_TEXT_LENGTH = 1024

    /** A fresh bundle id. THE generator for the value that goes in the AAD of every chunk. */
    fun newBundleId(): String = encodeBase64Url(generateSecureRandom(12))

    fun isValidBundleId(s: String): Boolean =
        s.length == BUNDLE_ID_LENGTH && s.all {
            it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_'
        }

    /**
     * Renders [h] as the QR / "Show as text" payload. Never throws (it is called from
     * UI paths on both platforms); a malformed handle simply produces text that [parse]
     * rejects — pinned by a test. The code is normalised to its canonical 32-symbol
     * uppercase form when it parses, so the QR never carries a grouped/lowercased one.
     */
    fun toQrText(h: MoveHandle): String {
        val canonicalCode = MigrationSeal.decodeCode(h.code)?.let { b ->
            try { MigrationSeal.encodeCode(b) } finally { b.secureWipe() }
        } ?: h.code
        return "{\"v\":${jsonEscapeString(MoveConstants.QR_VERSION)}," +
            "\"inbox\":${jsonEscapeString(h.inboxId)}," +
            "\"rcap\":${jsonEscapeString(h.readCap)}," +
            "\"code\":${jsonEscapeString(canonicalCode)}," +
            "\"bid\":${jsonEscapeString(h.bundleId)}}"
    }

    /**
     * Parses a scanned or pasted handle. Returns null on: surrounding junk (only
     * whitespace is tolerated), a non-object, an over-long payload, a missing or
     * non-string field, a version other than [MoveConstants.QR_VERSION], a malformed
     * inbox id / read capability / bundle id, or a code that is not exactly 32 Base32
     * symbols. Never throws.
     *
     * The returned [MoveHandle.code] is the CANONICAL uppercase, ungrouped form, so
     * every downstream consumer sees one representation.
     *
     * Unknown extra keys are ignored (forward compatibility — a future field is gated
     * by `v`, which this build rejects outright).
     */
    fun parse(text: String): MoveHandle? {
        return try {
            val t = text.trim()
            if (t.length > MAX_TEXT_LENGTH) return null
            if (!t.startsWith("{") || !t.endsWith("}")) return null
            val json = parseTopLevelJson(t)
            fun strField(key: String): String? = json[key]?.let { if (it.isString) it.text else null }

            if (strField("v") != MoveConstants.QR_VERSION) return null
            val inbox = strField("inbox") ?: return null
            val rcap = strField("rcap") ?: return null
            val code = strField("code") ?: return null
            val bid = strField("bid") ?: return null

            if (!isValidInboxId(inbox)) return null
            if (!PairingPayload.isValidCap(rcap)) return null
            if (!isValidBundleId(bid)) return null
            // Decoded only to validate the shape; the bytes are wiped immediately and
            // the CALLER re-decodes from the canonical string when it needs the key
            // (same ownership rule PairingPayload uses for the pairing secret).
            val codeBytes = MigrationSeal.decodeCode(code) ?: return null
            val canonical = try { MigrationSeal.encodeCode(codeBytes) } finally { codeBytes.secureWipe() }

            MoveHandle(inboxId = inbox, readCap = rcap, code = canonical, bundleId = bid)
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Log-safe rendering of a handle: every field redacted. No id fragment is ever
     * rendered (not even a prefix — log lines carry class names and counts only);
     * [MoveHandle.toString] follows the same rule.
     */
    @Suppress("UNUSED_PARAMETER")
    fun redact(h: MoveHandle): String =
        "MoveHandle(inbox=[redacted], bid=[redacted], rcap=[redacted], code=[redacted])"
}

// ---------------------------------------------------------------------------
// Bundle JSON reader — iterative, depth-bounded, no recursion.
//
// The bundle document is NOT depth-1 (it carries arrays of flat records and one
// flat meta object), so parseTopLevelJson cannot read it. This reader handles
// EXACTLY that shape and nothing else: a top-level object whose values are
// scalars, arrays of FLAT objects, or one flat object. Nesting inside records and
// the meta object is rejected; UNKNOWN top-level structured values are skipped
// (depth-counted, iterative — see skipValue).
//
// Regex-free and recursion-free for the same reason every other parser in this
// codebase is (Kotlin/Native's regex engine matches recursively and overflows the
// native stack on long values; a recursive descent parser would overflow on deep
// input). Depth is structurally bounded to 2 inside known fields by the grammar itself.
//
// Input reaches this only AFTER AES-GCM authentication under a 160-bit code, so it
// is not an open attack surface — but it is still parsed defensively, because the
// alternative to defensive parsing here is corrupting a freshly provisioned vault.
// ---------------------------------------------------------------------------

internal class MigRecord(private val fields: Map<String, JsonScalar>) {

    fun req(key: String, allowEmpty: Boolean = false): String {
        val v = fields[key] ?: throw MigrationBundleCodec.FormatException("missing field '$key'")
        if (!v.isString) throw MigrationBundleCodec.FormatException("field '$key' is not a string")
        if (!allowEmpty && v.text.isEmpty()) throw MigrationBundleCodec.FormatException("empty field '$key'")
        return v.text
    }

    fun optString(key: String): String? {
        val v = fields[key] ?: return null
        if (!v.isString) throw MigrationBundleCodec.FormatException("field '$key' is not a string")
        return v.text
    }

    fun reqBytes(key: String): ByteArray {
        val b64 = req(key, allowEmpty = true)
        return try {
            decodeBase64(b64)
        } catch (e: Exception) {
            throw MigrationBundleCodec.FormatException("field '$key' is not valid base64")
        }
    }

    fun reqLong(key: String): Long =
        optLong(key) ?: throw MigrationBundleCodec.FormatException("missing numeric field '$key'")

    fun optLong(key: String): Long? {
        val v = fields[key] ?: return null
        if (v.isString) throw MigrationBundleCodec.FormatException("field '$key' is not a number")
        return MigJson.strictLong(v.text)
            ?: throw MigrationBundleCodec.FormatException("field '$key' is not a valid number")
    }

    fun reqInt(key: String): Int {
        val l = reqLong(key)
        if (l < Int.MIN_VALUE.toLong() || l > Int.MAX_VALUE.toLong()) {
            throw MigrationBundleCodec.FormatException("field '$key' out of Int range")
        }
        return l.toInt()
    }
}

internal class MigDocument(
    private val scalars: Map<String, JsonScalar>,
    private val arrays: Map<String, List<Map<String, JsonScalar>>>,
    val meta: Map<String, String>,
) {
    fun string(key: String): String? = scalars[key]?.let { if (it.isString) it.text else null }
    fun long(key: String): Long? = scalars[key]?.let { if (it.isString) null else MigJson.strictLong(it.text) }
    fun int(key: String): Int? = long(key)?.let { if (it in Int.MIN_VALUE.toLong()..Int.MAX_VALUE.toLong()) it.toInt() else null }
    fun records(key: String): List<MigRecord> = (arrays[key] ?: emptyList()).map { MigRecord(it) }
}

internal object MigJson {

    private val ARRAY_KEYS = setOf("contacts", "inboxes", "groups", "members")
    private const val MAX_ELEMENTS = MAX_PARSE_ARRAY_ELEMENTS
    private const val MAX_META_ROWS = 200_000

    /**
     * Strict ASCII decimal parse with an explicit overflow guard.
     *
     * Deliberately NOT `toLongOrNull`: the stdlib accepts Unicode digits and a leading
     * `+`, which would let two different texts denote the same counter — the same rule
     * the relay version parser follows.
     */
    fun strictLong(text: String): Long? {
        if (text.isEmpty()) return null
        var i = 0
        val negative = text[0] == '-'
        if (negative) i = 1
        if (i >= text.length) return null
        var acc = 0L
        while (i < text.length) {
            val c = text[i]
            if (c < '0' || c > '9') return null
            val d = (c - '0').toLong()
            if (acc > (Long.MAX_VALUE - d) / 10) return null   // overflow
            acc = acc * 10 + d
            i++
        }
        return if (negative) -acc else acc
    }

    /** Parses the bundle document, or null if it is not exactly the expected shape. */
    fun parseBundleDocument(body: String): MigDocument? {
        val s = body
        var i = 0
        fun skipWs() { while (i < s.length && s[i].isWhitespace()) i++ }

        // ---- a JSON string starting at s[i] == '"' ----
        fun readString(): String? {
            if (i >= s.length || s[i] != '"') return null
            i++
            val sb = StringBuilder()
            while (i < s.length) {
                val c = s[i]
                when {
                    c == '\\' -> {
                        if (i + 1 >= s.length) return null
                        sb.append(c).append(s[i + 1]); i += 2
                    }
                    c == '"' -> { i++; return jsonUnescapeString(sb.toString()) }
                    else -> { sb.append(c); i++ }
                }
            }
            return null
        }

        // ---- a bare scalar token (number / true / false / null) ----
        fun readBareScalar(): String? {
            val start = i
            while (i < s.length && s[i] != ',' && s[i] != '}' && s[i] != ']' && !s[i].isWhitespace()) i++
            return if (i > start) s.substring(start, i) else null
        }

        // ---- a FLAT object: {"k":<string|scalar>, …}. Any nesting inside ⇒ reject. ----
        fun readFlatObject(limit: Int): Map<String, JsonScalar>? {
            skipWs()
            if (i >= s.length || s[i] != '{') return null
            i++
            val out = LinkedHashMap<String, JsonScalar>()
            skipWs()
            if (i < s.length && s[i] == '}') { i++; return out }
            while (i < s.length) {
                skipWs()
                if (i >= s.length || s[i] != '"') return null
                val key = readString() ?: return null
                skipWs()
                if (i >= s.length || s[i] != ':') return null
                i++
                skipWs()
                if (i >= s.length) return null
                val value: JsonScalar = when (s[i]) {
                    '"' -> JsonScalar(readString() ?: return null, true)
                    '{', '[' -> return null           // no nesting inside a record / meta
                    else -> JsonScalar(readBareScalar() ?: return null, false)
                }
                // Duplicate keys: FIRST wins, matching parseTopLevelJson — a later
                // duplicate must never be able to override an earlier field.
                if (!out.containsKey(key)) out[key] = value
                if (out.size > limit) return null
                skipWs()
                if (i >= s.length) return null
                when (s[i]) {
                    ',' -> { i++; continue }
                    '}' -> { i++; return out }
                    else -> return null
                }
            }
            return null
        }

        // ---- an array of flat objects ----
        fun readObjectArray(): List<Map<String, JsonScalar>>? {
            skipWs()
            if (i >= s.length || s[i] != '[') return null
            i++
            val out = ArrayList<Map<String, JsonScalar>>()
            skipWs()
            if (i < s.length && s[i] == ']') { i++; return out }
            while (i < s.length) {
                val obj = readFlatObject(MAX_ELEMENTS) ?: return null
                out.add(obj)
                if (out.size > MAX_ELEMENTS) return null
                skipWs()
                if (i >= s.length) return null
                when (s[i]) {
                    ',' -> { i++; continue }
                    ']' -> { i++; return out }
                    else -> return null
                }
            }
            return null
        }

        // ---- skip an unknown value (forward compatibility), iteratively ----
        fun skipValue(): Boolean {
            skipWs()
            if (i >= s.length) return false
            when (s[i]) {
                '"' -> return readString() != null
                '{', '[' -> {
                    var depth = 0
                    while (i < s.length) {
                        when (s[i]) {
                            '"' -> { if (readString() == null) return false }
                            '{', '[' -> { depth++; i++ }
                            '}', ']' -> { depth--; i++; if (depth == 0) return true }
                            else -> i++
                        }
                    }
                    return false
                }
                else -> return readBareScalar() != null
            }
        }

        skipWs()
        if (i >= s.length || s[i] != '{') return null
        i++
        val scalars = LinkedHashMap<String, JsonScalar>()
        val arrays = LinkedHashMap<String, List<Map<String, JsonScalar>>>()
        var meta: Map<String, String> = emptyMap()
        var metaSeen = false
        skipWs()
        if (i < s.length && s[i] == '}') {
            i++
            return MigDocument(scalars, arrays, meta)
        }
        while (i < s.length) {
            skipWs()
            if (i >= s.length || s[i] != '"') return null
            val key = readString() ?: return null
            skipWs()
            if (i >= s.length || s[i] != ':') return null
            i++
            skipWs()
            if (i >= s.length) return null
            when {
                key in ARRAY_KEYS -> {
                    if (arrays.containsKey(key)) return null       // duplicate top-level array
                    arrays[key] = readObjectArray() ?: return null
                }
                key == "meta" -> {
                    if (metaSeen) return null
                    metaSeen = true
                    val flat = readFlatObject(MAX_META_ROWS) ?: return null
                    val m = LinkedHashMap<String, String>(flat.size)
                    for ((k, v) in flat) {
                        if (!v.isString) return null                // meta values are always strings
                        m[k] = v.text
                    }
                    meta = m
                }
                s[i] == '"' -> {
                    val v = readString() ?: return null
                    if (!scalars.containsKey(key)) scalars[key] = JsonScalar(v, true)
                }
                s[i] == '{' || s[i] == '[' -> { if (!skipValue()) return null }   // unknown structured field
                else -> {
                    val v = readBareScalar() ?: return null
                    if (!scalars.containsKey(key)) scalars[key] = JsonScalar(v, false)
                }
            }
            skipWs()
            if (i >= s.length) return null
            when (s[i]) {
                ',' -> { i++; continue }
                '}' -> { i++; return MigDocument(scalars, arrays, meta) }
                else -> return null
            }
        }
        return null
    }
}
