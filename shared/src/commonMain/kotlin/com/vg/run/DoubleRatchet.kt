package com.vg.run

// ---------------------------------------------------------------------------
// DoubleRatchet — forward secrecy + post-compromise security for 1:1 messages.
//
// WHY A SYMMETRIC RATCHET ALONE IS NOT ENOUGH HERE
// ------------------------------------------------
// Forward secrecy means a device compromised at time T cannot decrypt messages
// from before T. A pure hash ratchet (CK_{n+1} = KDF(CK_n)) only delivers that
// if the chain ORIGIN is unrecoverable. In Rún the per-pairing `sharedSecret`
// is retained in the vault (it seeds the message epoch, group pair-tags, and the
// referral bootstrap), so an attacker who seizes the vault could recompute
// CK_0 = KDF(sharedSecret) and ratchet forward to EVERY past key. A symmetric
// ratchet seeded from a retained secret is therefore security theatre.
//
// The Double Ratchet fixes this by mixing fresh X25519 entropy into the root on
// every direction change. The ephemeral DH PRIVATE keys are wiped after use and
// never persisted, so once the chain has moved past a DH step the keys from
// before it cannot be reconstructed from `sharedSecret` (or from any later
// state). This gives:
//   * forward secrecy   — past message keys are gone after the chain advances;
//   * post-compromise   — a future DH step the attacker didn't observe heals
//                         the channel (Signal's "break-in recovery").
// The very first batch of messages (before the first DH step) is still
// recoverable from `sharedSecret` — that is the unavoidable bootstrap cost of a
// symmetric pairing with no online handshake.
//
// This file is the PURE, transport-agnostic ratchet primitive. It performs no
// I/O and touches no vault — it is exercised end to end by DoubleRatchetTest.
// It is wired into the live path via RatchetManager (MessageManager envelope
// + per-contact `dr/{id}/{channel}` persistence); the text channel gains forward
// secrecy once the ratchet engages.
//
// Algorithm: Signal's Double Ratchet (Perrin/Marlinspike), with HKDF-SHA256 for
// KDF_RK and HMAC-SHA256 for KDF_CK, AES-256-GCM for the message AEAD, and the
// header (sender ratchet pubkey ‖ PN ‖ N) bound as additional authenticated data.
// ---------------------------------------------------------------------------

private fun writeIntBE(buf: ByteArray, off: Int, v: Int) {
    buf[off] = (v ushr 24).toByte(); buf[off + 1] = (v ushr 16).toByte()
    buf[off + 2] = (v ushr 8).toByte(); buf[off + 3] = v.toByte()
}

private fun readIntBE(buf: ByteArray, off: Int): Int =
    ((buf[off].toInt() and 0xFF) shl 24) or ((buf[off + 1].toInt() and 0xFF) shl 16) or
        ((buf[off + 2].toInt() and 0xFF) shl 8) or (buf[off + 3].toInt() and 0xFF)

private fun int4(v: Int): ByteArray = ByteArray(4).also { writeIntBE(it, 0, v) }

private fun writeLongBE(buf: ByteArray, off: Int, v: Long) {
    for (i in 0 until 8) buf[off + i] = (v ushr (56 - 8 * i)).toByte()
}

private fun readLongBE(buf: ByteArray, off: Int): Long {
    var v = 0L
    for (i in 0 until 8) v = (v shl 8) or (buf[off + i].toLong() and 0xFF)
    return v
}

private fun long8(v: Long): ByteArray = ByteArray(8).also { writeLongBE(it, 0, v) }

private fun hexToBytes(s: String): ByteArray {
    val out = ByteArray(s.length / 2)
    for (i in out.indices) out[i] = s.substring(i * 2, i * 2 + 2).toInt(16).toByte()
    return out
}

/** A ratchet message header, sent in the clear alongside the ciphertext (and bound as AAD). */
internal data class RatchetHeader(
    val dhPub: ByteArray,   // sender's current ratchet public key (32 bytes)
    val pn: Int,            // number of messages in the sender's PREVIOUS sending chain
    val n: Int,             // message index in the sender's CURRENT sending chain
) {
    /** Canonical wire/AAD encoding: dhPub(32) ‖ pn(4, big-endian) ‖ n(4, big-endian). */
    fun encode(): ByteArray {
        require(dhPub.size == 32) { "ratchet pubkey must be 32 bytes" }
        val out = ByteArray(40)
        dhPub.copyInto(out, 0)
        writeIntBE(out, 32, pn)
        writeIntBE(out, 36, n)
        return out
    }

    companion object {
        fun decode(bytes: ByteArray): RatchetHeader {
            require(bytes.size == 40) { "ratchet header must be 40 bytes" }
            return RatchetHeader(bytes.copyOfRange(0, 32), readIntBE(bytes, 32), readIntBE(bytes, 36))
        }
    }
}

/** Output of [DoubleRatchet.encrypt]: the cleartext header plus the AEAD ciphertext (IV‖ct‖tag). */
internal data class RatchetMessage(val header: RatchetHeader, val ciphertext: ByteArray) {
    /** Self-describing relay blob: header(40) ‖ ciphertext. Base64 this onto the wire. */
    fun encodeWire(): ByteArray = header.encode() + ciphertext
}

/** Parse a [RatchetMessage.encodeWire] blob back into header + ciphertext. */
internal fun decodeRatchetWire(bytes: ByteArray): RatchetMessage {
    require(bytes.size >= 40 + 28) { "ratchet wire blob too short" }   // 40 header + 12 IV + 16 tag min
    return RatchetMessage(RatchetHeader.decode(bytes.copyOfRange(0, 40)), bytes.copyOfRange(40, bytes.size))
}

/**
 * LEGACY role rule (`rv:1`) — retained for every pairing that has no proof the
 * peer runs the v2 rule below, and for every ratchet blob already on disk.
 *
 * Both peers share a secret but have no online handshake, so the responder role
 * ("Bob", who holds the secret-derived initial ratchet key) is assigned
 * deterministically from the pairing's two inbox IDs — each peer computes the
 * same answer. Returns true if THIS device is Bob.
 *
 * [myInboundInboxId] is the inbox we minted and read; [myOutboundInboxId] is the
 * peer's inbox we write to. The peer sees these two ids swapped, so comparing
 * them yields opposite roles on the two devices — exactly one Bob.
 *
 * Known limitation of this legacy rule: [myOutboundInboxId] is **the id the PEER declared**
 * (QR payload or in-band `inbox` announce), so this rule lets the peer choose the
 * victim's role, and the value is MUTABLE after pairing (an announce rewrites the
 * outbound row; a post-[onCorruptReinit] re-init recomputes from whatever it then
 * holds). [ratchetSelfIsBobFromRoleOrder] is the replacement; this one stays
 * because agreement, not strength, is what a role rule needs — two builds using
 * different rules land in exactly the collision being fixed, so v2 applies only
 * where the peer has PROVEN it runs v2 too (`rv:2`, see
 * `MessageManager.drPeerRoleRuleV2Key`).
 */
internal fun ratchetSelfIsBob(myInboundInboxId: String, myOutboundInboxId: String): Boolean {
    require(myInboundInboxId != myOutboundInboxId) { "inbox ids must differ" }
    return myInboundInboxId < myOutboundInboxId
}

/** HKDF info for the v2 role parity bit. Part of the wire contract: both
 *  devices must derive the same bit from the same pairing secret. */
private val INFO_ROLE = "run-dr-role-v1".encodeToByteArray()

/**
 * The wire field and value by which a build announces
 * that it runs the v2 (secret-order) role rule. Optional everywhere it appears —
 * the QR pairing payload, the in-band `inbox` announce body and the referral
 * accept body — and every parser predates it, so an old peer simply omits it and
 * the pairing keeps the id-order rule on BOTH sides. Carried as a JSON STRING
 * because all three of those parsers (`parseTopLevelJson` + `isString`,
 * `firstStringFieldAnywhere`) only ever read string values; a numeric `2` would read as
 * absent, which is the safe direction but would make the marker inert.
 */
internal const val ROLE_RULE_FIELD = "rv"
internal const val ROLE_RULE_V2 = "2"

/**
 * The IMMUTABLE half of the v2 role rule — "does MY pairing
 * contribution sort before the peer's?".
 *
 * Fed with the two 32-byte pairing-secret halves on the QR/paste path, and with
 * the two ephemeral X25519 PUBLIC keys on the referral path (which has no
 * symmetric halves at all). Both are fixed at pairing and can never be moved
 * afterwards by an inbox announce, an inbox rotation or a re-init — which is the
 * entire point: [ratchetSelfIsBob]'s inputs can be.
 *
 * The comparison is over the SHA-256 of each input, exactly like
 * [deriveSharedSecret]'s canonical ordering, so (a) the pairing code has one
 * notion of "order" rather than two, and (b) the order is not a direct statement
 * about the raw bytes. Any total order works as long as both devices compute the
 * same one; they do, because each sees the same unordered pair.
 *
 * Returns **null** when the two inputs are identical — no ordering exists, so
 * there is nothing to persist and the pairing must keep the id-order rule.
 * (`PairingPayload.parse` already rejects a reflected copy of our own secret and
 * two X25519 keypairs never collide, so this is a can't-happen guarded anyway:
 * silently answering `false` on both devices would hand them the SAME role, i.e.
 * manufacture the very collision this change exists to remove.)
 */
internal fun ratchetRoleOrderBit(mine: ByteArray, peer: ByteArray): Boolean? {
    val hm = sha256(mine)
    val hp = sha256(peer)
    try {
        for (i in hm.indices) {
            val d = (hm[i].toInt() and 0xFF) - (hp[i].toInt() and 0xFF)
            if (d != 0) return d < 0
        }
        return null
    } finally {
        // Not reversible, but they are one-way images of pairing material and the
        // callers hand us the real thing — leave nothing behind, same discipline as
        // every other derived buffer in this file.
        hm.secureWipe(); hp.secureWipe()
    }
}

/**
 * The v2 role — `parity(HKDF(sharedSecret, "run-dr-role-v1", 1)) XOR
 * mineSortsFirst`. Returns true if THIS device is Bob.
 *
 * Both devices derive the SAME parity bit from the SAME pairing secret, so the
 * parity alone would give both of them the same role; [mineSortsFirst] is what
 * breaks the tie, and it is the one input that is genuinely opposite on the two
 * devices. The parity is not security — it exists so the role is not a pure,
 * publicly-computable function of the two halves.
 *
 * What this buys (and does not): the role can no longer be MOVED after pairing,
 * which kills the "freeze the victim's role at a moment of the peer's choosing"
 * primitive and both honest-path hazards (a later announce / an
 * `onCorruptReinit` re-init). It does NOT make the role unchoosable — a modified
 * client can regenerate its own half and grind the bit in ~2 tries, and can
 * simply act as the wrong role regardless (known limitation). That is why the
 * detect-and-refuse gate is the load-bearing half.
 */
internal fun ratchetSelfIsBobFromRoleOrder(sharedSecret: ByteArray, mineSortsFirst: Boolean): Boolean {
    val out = hkdfSha256(ikm = sharedSecret, salt = ByteArray(32), info = INFO_ROLE, length = 1)
    val parityIsOne = (out[0].toInt() and 1) == 1
    out.secureWipe()
    return parityIsOne xor mineSortsFirst
}

/** Raised when a message cannot be decrypted (bad key, tampered, or beyond the skip bound). */
internal class RatchetException(message: String) : Exception(message)

/**
 * An AGGREGATE ceiling on the ratchet work ONE
 * drain may spend on blobs that never authenticate.
 *
 * WHY THIS SHAPE, AND NOT "CHECK THE TAG FIRST". [DoubleRatchet.decrypt] cannot
 * verify the AEAD tag before deriving a key — in the Signal design the message key
 * is what the skip loop and the DH step PRODUCE, so the derivation is unavoidably
 * paid before the rejection. [DoubleRatchet.MAX_SKIP] bounds ONE decrypt (up to
 * 2 x 256 chain-key derivations = 1024 HMAC, plus 2 ECDH + 1 keygen when the
 * header carries a new ratchet key); nothing bounded the SUM across a drain, while
 * `RatchetManager.decryptBatch` rolls the state back after every failure — so each
 * of up to `MessageManager.MAX_BLOBS_PER_POLL` forged 72-byte blobs repeated the
 * full price. This is the same shape of aggregate guard as
 * `MessageManager.MINT_TOTAL_POW_BUDGET_MS` for the PoW path.
 *
 * WHY CHARGES ARE REFUNDED ON SUCCESS — and why that is not a loophole. The budget
 * has to be INVISIBLE to honest traffic: a week-long backlog is hundreds of real
 * messages that all authenticate, and a drain contains at most one receiving DH
 * step. So [beginAttempt]/[refundAttempt] make the ceiling apply to
 * WASTED work only — a decrypt that produced a verified plaintext hands its charges
 * back. Nothing is given away by that: work that ends in a valid GCM tag required
 * the genuine message keys, i.e. it is work an attacker cannot ask for. What stays
 * charged is exactly the work that ended in a rejection.
 *
 * Not thread-safe, and deliberately so — it is constructed per drain and used under
 * the [RatchetManager] lock that already serializes the drain.
 */
internal class RatchetWorkBudget(
    private val maxDhSteps: Int = MAX_FAILED_DH_STEPS,
    private val maxChainDerivations: Int = MAX_FAILED_CHAIN_DERIVATIONS,
) {
    companion object {
        /**
         * A real drain contains AT MOST ONE receiving DH step, and that is a
         * structural property, not an estimate: the peer's ratchet key only changes
         * when the peer RECEIVES from us, and our own key only changes when we
         * decrypt a new peer key — so while we are not draining, the peer can ratchet
         * exactly once. 8 leaves a wide margin for re-pairing / recovery oddities.
         */
        const val MAX_FAILED_DH_STEPS = 8

        /**
         * 2048 wasted chain-key derivations = 4096 HMAC-SHA256, i.e. single-digit
         * milliseconds even on the slowest supported handset, against the ~2.1 M HMAC
         * a full `MAX_BLOBS_PER_POLL` junk drain used to cost. Sized as 8 x MAX_SKIP:
         * enough that a rejected blob at the per-decrypt ceiling is still processed
         * several times over before the drain stops paying.
         */
        const val MAX_FAILED_CHAIN_DERIVATIONS = 8 * DoubleRatchet.MAX_SKIP
    }

    private var dhSteps = 0
    private var chainDerivations = 0
    // Retrieve-ack: how many charges this budget REFUSED. A blob refused by the
    // budget (not by the AEAD) was not really processed — the caller leaves it for
    // the next drain instead of acking it (RatchetManager.decryptBatch).
    private var refused = 0

    /** Retrieve-ack: refusals so far (monotonic). */
    fun refusals(): Int = refused
    private var attemptDhSteps = 0
    private var attemptChainDerivations = 0

    /** Mark the start of one decrypt attempt, so [refundAttempt] can undo its charges. */
    fun beginAttempt() {
        attemptDhSteps = dhSteps
        attemptChainDerivations = chainDerivations
    }

    /** The attempt authenticated: give its charges back (see the class note). */
    fun refundAttempt() {
        dhSteps = attemptDhSteps
        chainDerivations = attemptChainDerivations
    }

    /**
     * Charge one DH ratchet step (2 ECDH + 1 keypair generation).
     *
     * Refuses BEFORE incrementing, so the counters never run past their ceiling: an
     * exhausted budget must make every further blob cost nothing, not keep tallying.
     */
    fun chargeDhStep() {
        if (dhSteps >= maxDhSteps) {
            refused += 1
            throw RatchetException("ratchet work budget: $maxDhSteps failed DH steps in one drain")
        }
        dhSteps += 1
    }

    /** Charge [count] chain-key derivations (2 HMAC-SHA256 each). Same refuse-first rule. */
    fun chargeChainDerivations(count: Int) {
        if (count <= 0) return
        if (chainDerivations + count > maxChainDerivations) {
            refused += 1
            throw RatchetException("ratchet work budget: $maxChainDerivations failed chain derivations in one drain")
        }
        chainDerivations += count
    }

    /** Diagnostics only (logging / tests): what this drain has spent on rejected blobs. */
    fun spentDhSteps(): Int = dhSteps
    fun spentChainDerivations(): Int = chainDerivations
}

internal class DoubleRatchet private constructor(
    private var rootKey: ByteArray,
    private var dhSelfPriv: ByteArray,
    private var dhSelfPub: ByteArray,
    private var dhRemotePub: ByteArray?,
    private var sendChain: ByteArray?,
    private var recvChain: ByteArray?,
    private var sendN: Int,
    private var recvN: Int,
    private var prevSendN: Int,
    // Skipped message keys: (remoteRatchetPubHex, n) -> messageKey + creation
    // stamp, for out-of-order delivery. The stamp exists
    // because these are the ONE place the ratchet keeps a key capable of opening a
    // message it has already ratcheted past — a hostile relay picks which ones by
    // choosing what to withhold — so they age out (see [SKIPPED_KEY_TTL_MS]).
    private val skipped: MutableMap<SkippedKeyId, SkippedKey>,
    // Count of RECEIVING DH ratchet steps. Used to
    // gate dr-rxlock arming past the bootstrap window. Not an unforgeability
    // guarantee — see the known-limitation note on hasRatchetedPastBootstrap()
    // and drRecvLockKey.
    private var dhRecvSteps: Int = 0,
    // Injectable wall clock, ONLY for skipped-key stamping + age-out. Production
    // never passes anything but the real clock; the seam exists so a 24 h TTL can be
    // driven in a unit test without real waits (same shape/rationale as
    // ReferralManager.clockMs / MessageManager.relayLostClockMs). RatchetManager
    // forwards its own [RatchetManager.clockMs] here on every load/init.
    private val nowMs: () -> Long = { currentTimeMillis() },
) {
    private data class SkippedKeyId(val dhPubHex: String, val n: Int)

    /**
     * A cached skipped message key plus the wall-clock ms it was DERIVED at.
     * The stamp is what makes the cache expirable; it is persisted alongside the key
     * (SER_VERSION 3) so the window survives a lock/relaunch, and entries restored
     * from a pre-v3 blob are stamped at LOAD time (see [deserialize]) — tolerant, so
     * an existing vault keeps working and simply starts its window now.
     */
    private class SkippedKey(val mk: ByteArray, val createdAtMs: Long)

    /**
     * Set by [deserialize] when the load-time age-out (or the legacy-cap trim)
     * actually dropped entries, so [RatchetManager] can re-persist the pruned state
     * and take those keys OFF DISK instead of only out of RAM. Transient — never
     * serialized, never part of the wire.
     */
    private var droppedSkippedAtLoad = false

    /** See [droppedSkippedAtLoad]: true iff this load dropped expired/over-cap keys. */
    fun droppedExpiredSkippedOnLoad(): Boolean = droppedSkippedAtLoad

    /**
     * Optional per-DRAIN work meter (see
     * [RatchetWorkBudget]). Null — the default, and what every single-message path
     * uses — means "no aggregate ceiling", which is exactly the original behaviour
     * and is safe there because [MAX_SKIP] already bounds ONE decrypt.
     *
     * It is a settable field rather than a constructor argument on purpose:
     * [RatchetManager.decryptBatch] re-creates the ratchet from its rollback snapshot
     * after every rejected blob, and the ceiling must survive those re-creations —
     * a constructor parameter would have to be threaded through [deserialize],
     * [initAsAlice] and [initAsBob] for one caller. NEVER serialized: it is a
     * property of the drain, not of the ratchet.
     */
    internal var workBudget: RatchetWorkBudget? = null

    /**
     * Zero the transient SECRET key material this
     * ratchet holds — used on a DISCARD path (e.g. a rolled-back poisoned state
     * in RatchetManager.decryptBatch). After this the object MUST NOT be used
     * again. Public halves (dhSelfPub/dhRemotePub/header pub) are not secret and
     * are left. Overwrites in place so the bytes leave RAM without waiting for GC.
     */
    fun wipe() {
        rootKey.secureWipe()
        dhSelfPriv.secureWipe()
        sendChain?.secureWipe()
        recvChain?.secureWipe()
        skipped.values.forEach { it.mk.secureWipe() }
        skipped.clear()
    }

    companion object {
        // Defence-in-depth bounds. A hostile/buggy peer claiming a huge N must not
        // make us grind unbounded HMACs or hold unbounded keys in memory.
        const val MAX_SKIP = 256              // most messages skippable within one chain per decrypt
        // Lowered 1024 -> 128. Every cached entry is a key
        // that reopens a message the chain has already ratcheted past, and a hostile
        // relay chooses which ones exist by choosing what to withhold, so the worst
        // case AT REST must be small. 128 still covers any realistic Tor reordering
        // burst (MAX_SKIP, the per-decrypt bound, is deliberately unchanged at 256).
        const val MAX_SKIPPED_STORE = 128     // most cached skipped keys before least-needed are evicted
        // …but a blob written by a PREVIOUS build may legitimately carry up to the old
        // bound. Read up to this many (then trim to MAX_SKIPPED_STORE and re-persist on
        // the next write) — rejecting them instead would fail deserialize on a real
        // vault, which RatchetManager turns into a full ratchet re-init.
        const val MAX_SKIPPED_STORE_LEGACY = 1024
        /**
         * How long a skipped (out-of-order) message key may live. Evaluated on
         * every load and on every decrypt; expired keys are zeroed and dropped, so a
         * blob the relay withheld past the window is simply undecryptable — exactly
         * what forward secrecy is supposed to mean. 24 h is deliberately generous
         * against Tor reordering and an offline peer (minutes would cover real
         * delivery); the point is that "forever" becomes "bounded".
         */
        const val SKIPPED_KEY_TTL_MS = 24L * 60L * 60L * 1000L
        const val SER_VERSION: Byte = 3       // persisted-state format version (2 adds dhRecvSteps, 3 adds skipped-key stamps)

        // The serialized flags byte: which optional 32-byte fields follow the
        // three fixed keys. Every other bit is rejected on read.
        private const val FLAG_HAS_REMOTE = 0x1
        private const val FLAG_HAS_SEND_CHAIN = 0x2
        private const val FLAG_HAS_RECV_CHAIN = 0x4
        private const val KNOWN_FLAGS = FLAG_HAS_REMOTE or FLAG_HAS_SEND_CHAIN or FLAG_HAS_RECV_CHAIN
        // One skipped-key entry: 32 (pub) + 4 (n) + 32 (mk), plus the 8-byte
        // creation stamp from SER_VERSION 3 onward.
        private const val SKIPPED_ENTRY_BYTES_V1V2 = 32 + 4 + 32
        private const val SKIPPED_ENTRY_STAMP_BYTES = 8

        /** Restore a ratchet persisted by [serialize]. Throws on a malformed/old blob. */
        fun deserialize(bytes: ByteArray, nowMs: () -> Long = { currentTimeMillis() }): DoubleRatchet {
            // Accept v1 (no dhRecvSteps) AND v2 (with it) so the
            // SER_VERSION bump doesn't force every existing ratchet to re-bootstrap.
            // v3 additionally stamps each skipped key; v1/v2
            // entries carry no stamp and are stamped at LOAD time below, so an existing
            // vault reads back unchanged and simply starts its age-out window now.
            val ver = if (bytes.isNotEmpty()) bytes[0].toInt() else -1
            require(bytes.size >= 2 && ver >= 1 && ver <= SER_VERSION.toInt()) { "bad ratchet blob version" }
            val flags = bytes[1].toInt() and 0xFF
            // Reject UNKNOWN flag bits — only 0x1/0x2/0x4 are defined — so a
            // malformed or forward-versioned record fails loudly instead of being
            // silently reinterpreted.
            require(flags and KNOWN_FLAGS.inv() == 0) { "unknown ratchet flags: $flags" }
            var o = 2
            // Bounds-check EVERY read: a corrupt/truncated vault record must fail
            // as a clean IllegalArgumentException (caught + re-inited by
            // RatchetManager) rather than an IndexOutOfBounds — the latter is an
            // uncaught Kotlin exception that SIGABRTs iOS. Also reject negative
            // counters and trailing garbage so a malformed record can't yield
            // nonsensical-but-accepted state.
            fun need(n: Int) = require(n >= 0 && o + n <= bytes.size) {
                "ratchet blob truncated (need $n at $o of ${bytes.size})"
            }
            fun take(n: Int): ByteArray { need(n); val r = bytes.copyOfRange(o, o + n); o += n; return r }
            fun int(): Int { need(4); val v = readIntBE(bytes, o); o += 4; return v }
            fun long(): Long { need(8); val v = readLongBE(bytes, o); o += 8; return v }
            val root = take(32); val selfPriv = take(32); val selfPub = take(32)
            val remote = if (flags and FLAG_HAS_REMOTE != 0) take(32) else null
            val sendCk = if (flags and FLAG_HAS_SEND_CHAIN != 0) take(32) else null
            val recvCk = if (flags and FLAG_HAS_RECV_CHAIN != 0) take(32) else null
            val sN = int(); val rN = int(); val pN = int()
            require(sN >= 0 && rN >= 0 && pN >= 0) { "negative ratchet counter" }
            val skCount = int()
            // Read bound = the LEGACY cap (a blob written by an older build may hold
            // up to 1024); the CURRENT cap is enforced right after, by trimming.
            require(skCount in 0..MAX_SKIPPED_STORE_LEGACY) { "skipped count out of range" }
            // 32 (pub) + 4 (n) + 32 (mk) [+ 8 (createdAt), v3 onward] per entry.
            val skEntryBytes =
                if (ver >= 3) SKIPPED_ENTRY_BYTES_V1V2 + SKIPPED_ENTRY_STAMP_BYTES else SKIPPED_ENTRY_BYTES_V1V2
            need(skCount * skEntryBytes)   // all must fit
            val loadedAt = nowMs()
            val sk = mutableMapOf<SkippedKeyId, SkippedKey>()
            repeat(skCount) {
                val pub = take(32); val n = int(); val mk = take(32)
                // v1/v2 entries predate the stamp: give them "now", so they age out from
                // this load rather than being dropped (or kept forever) on upgrade.
                val createdAt = if (ver >= 3) long() else loadedAt
                require(n >= 0) { "negative skipped-key index" }
                sk[SkippedKeyId(bytesToHex(pub), n)] = SkippedKey(mk, createdAt)
            }
            // v2 appends the receiving-DH-step counter. A v1 blob
            // predates it — default to 2 (an already-persisted ratchet was an
            // established, past-bootstrap conversation), so existing pairings keep
            // arming semantics rather than being treated as mid-bootstrap.
            val dhRecvSteps = if (ver >= 2) int().also { require(it >= 0) { "negative dhRecvSteps" } } else 2
            require(o == bytes.size) { "trailing bytes in ratchet blob (${bytes.size - o} extra)" }
            return DoubleRatchet(
                root, selfPriv, selfPub, remote, sendCk, recvCk, sN, rN, pN, sk, dhRecvSteps, nowMs,
            ).also {
                // The age-out is evaluated on EVERY load (this is the only place
                // persisted state enters the process, so it costs no extra I/O), and an
                // over-cap legacy store is trimmed to the current bound here. Both zero
                // the keys they drop. Neither can fail a load: a dropped skipped key
                // only makes one withheld message undecryptable — never a brick.
                val before = it.skipped.size
                it.pruneExpiredSkipped()
                it.enforceSkippedCap()
                it.droppedSkippedAtLoad = it.skipped.size != before
            }
        }

        private val INFO_INIT = "run-dr-init-v1".encodeToByteArray()
        private val INFO_BOBKEY = "run-dr-bob-key-v1".encodeToByteArray()
        private val INFO_ROOT = "run-dr-root-v1".encodeToByteArray()
        private val INFO_MSG = "run-dr-msg-v1".encodeToByteArray()
        private val ZERO_SALT = ByteArray(32)
        private val BASEPOINT = ByteArray(32).also { it[0] = 9 }   // X25519 generator u=9

        /**
         * Both peers share `sharedSecret` but have no online handshake, so roles are
         * assigned deterministically by the caller (see `ratchetSelfIsBob` /
         * `ratchetSelfIsBobFromRoleOrder` in RatchetManager) and the responder ("Bob") uses a ratchet key DERIVED from the secret
         * so the initiator ("Alice") can DH against it on her first send.
         */
        fun initAsBob(sharedSecret: ByteArray, nowMs: () -> Long = { currentTimeMillis() }): DoubleRatchet {
            val rk = hkdfSha256(sharedSecret, ZERO_SALT, INFO_INIT, 32)
            val (priv, pub) = bobRatchetKey(sharedSecret)
            return DoubleRatchet(
                rootKey = rk, dhSelfPriv = priv, dhSelfPub = pub, dhRemotePub = null,
                sendChain = null, recvChain = null, sendN = 0, recvN = 0, prevSendN = 0,
                skipped = mutableMapOf(), nowMs = nowMs,
            )
        }

        fun initAsAlice(sharedSecret: ByteArray, nowMs: () -> Long = { currentTimeMillis() }): DoubleRatchet {
            val rk0 = hkdfSha256(sharedSecret, ZERO_SALT, INFO_INIT, 32)
            val (_, bobPub) = bobRatchetKey(sharedSecret)
            val self = x25519GenerateKeypair()
            // Alice performs the first DH step immediately so she can send first.
            val (rk1, ck) = kdfRk(rk0, x25519EcdhChecked(self.privateKey, bobPub))
            rk0.secureWipe()
            return DoubleRatchet(
                rootKey = rk1, dhSelfPriv = self.privateKey, dhSelfPub = self.publicKey,
                dhRemotePub = bobPub, sendChain = ck, recvChain = null,
                sendN = 0, recvN = 0, prevSendN = 0, skipped = mutableMapOf(), nowMs = nowMs,
            )
        }

        /** Bob's deterministic initial ratchet keypair: priv from the secret, pub = X25519(priv, 9). */
        private fun bobRatchetKey(sharedSecret: ByteArray): Pair<ByteArray, ByteArray> {
            val priv = hkdfSha256(sharedSecret, ZERO_SALT, INFO_BOBKEY, 32)
            val pub = x25519Ecdh(priv, BASEPOINT)   // scalar-mult by the basepoint = public key
            return priv to pub
        }

        // KDF_RK: HKDF(salt=rootKey, ikm=dhOut) -> new 32-byte root key + 32-byte chain key.
        // `internal` (not private) purely so DoubleRatchetTest can assert the dhOut wipe
        // below directly — still module-scoped, not public API.
        internal fun kdfRk(rootKey: ByteArray, dhOut: ByteArray): Pair<ByteArray, ByteArray> {
            try {
                val out = hkdfSha256(ikm = dhOut, salt = rootKey, info = INFO_ROOT, length = 64)
                val newRoot = out.copyOfRange(0, 32)
                val chain = out.copyOfRange(32, 64)
                out.secureWipe()
                return newRoot to chain
            } finally {
                // Zero the raw X25519 ECDH shared output.
                // Every caller passes a FRESH transient — x25519EcdhChecked(...) computed
                // inline at the call site (initAsAlice + both dhRatchet steps) — that is
                // retained nowhere else, so wiping the consumed ikm here removes the last
                // live copy of the DH secret from RAM without disturbing any alias. In
                // `finally` so it runs even if hkdfSha256 throws; strictly AFTER the HKDF
                // read, so the derivation is unaffected. (rootKey, the salt, is NOT wiped
                // here — every caller reuses/rewrites it right after and owns its teardown.)
                dhOut.secureWipe()
            }
        }

        // KDF_CK: ratchet a chain key, yielding the next chain key + this message key.
        private fun kdfCk(chainKey: ByteArray): Pair<ByteArray, ByteArray> {
            val mk = hmacSha256(chainKey, byteArrayOf(0x01))
            val nextCk = hmacSha256(chainKey, byteArrayOf(0x02))
            return nextCk to mk
        }

    }

    /** True once a sending chain exists — Alice from init, Bob after his first receive. */
    fun canSend(): Boolean = sendChain != null

    /** Encrypt [plaintext]; advances the sending chain and wipes the consumed message key. */
    fun encrypt(plaintext: ByteArray): RatchetMessage {
        val ck = sendChain ?: throw RatchetException("no sending chain (responder must receive first)")
        val (nextCk, mk) = kdfCk(ck)
        ck.secureWipe()
        sendChain = nextCk
        val header = RatchetHeader(dhSelfPub.copyOf(), prevSendN, sendN)
        sendN += 1
        val encKey = hkdfSha256(mk, ZERO_SALT, INFO_MSG, 32)
        mk.secureWipe()
        try {
            val ct = aesGcmEncrypt(plaintext = plaintext, key = encKey, associatedData = header.encode())
            return RatchetMessage(header, ct)
        } finally {
            encKey.secureWipe()
        }
    }

    /** Decrypt a message; performs a DH step on a new ratchet key and caches skipped keys. */
    fun decrypt(header: RatchetHeader, ciphertext: ByteArray): ByteArray {
        // 0. Age out cached skipped keys FIRST, so an expired one can never open
        //    a message. Also covers a long-lived instance (RatchetManager reloads per
        //    op, but decryptBatch drives a whole drain through one object).
        pruneExpiredSkipped()

        // 1. A skipped (out-of-order) message we already derived a key for.
        trySkipped(header, ciphertext)?.let { return it }

        // 2. A new remote ratchet key → symmetric-key skip in the old chain, then DH ratchet.
        if (dhRemotePub == null || !header.dhPub.contentEquals(dhRemotePub)) {
            // HOISTED BOUND, not a new rule. [dhRatchet] resets
            // recvN to 0, so the skipMessageKeys(header.n) two lines below would reject
            // exactly `n !in 0..MAX_SKIP` — after having already paid the pn-skip, 2 ECDH
            // and a keypair generation. Checking it here rejects the same set of headers
            // for ZERO crypto. It is deliberately scoped to the NEW-key branch: within an
            // established chain `n` is bounded RELATIVE to recvN, and an absolute bound
            // there would refuse a legitimate message from any chain longer than MAX_SKIP.
            // (A negative n is only reachable from a forged header — RatchetHeader.decode
            // reads a raw big-endian Int off the wire — and cost a full DH step before.)
            if (header.n < 0 || header.n > MAX_SKIP) {
                throw RatchetException("ratchet n out of range for a new chain: ${header.n}")
            }
            skipMessageKeys(header.pn)
            dhRatchet(header)
        }

        // 3. Skip within the current receiving chain up to this message's index, then derive.
        skipMessageKeys(header.n)
        val ck = recvChain ?: throw RatchetException("no receiving chain")
        val (nextCk, mk) = kdfCk(ck)
        ck.secureWipe()
        recvChain = nextCk
        recvN += 1
        return openWith(mk, header, ciphertext)
    }

    private fun trySkipped(header: RatchetHeader, ciphertext: ByteArray): ByteArray? {
        val id = SkippedKeyId(bytesToHex(header.dhPub), header.n)
        val entry = skipped[id] ?: return null
        // openWith wipes the message key it consumes, so drop the (now-zeroed) entry
        // on the throw path too — a failed AEAD must not leave a dead key cached.
        val plain = try {
            openWith(entry.mk, header, ciphertext)   // throws on AEAD failure → caller sees tamper
        } catch (e: Exception) {
            skipped.remove(id)?.mk?.secureWipe()
            throw e
        }
        skipped.remove(id)?.mk?.secureWipe()
        return plain
    }

    private fun openWith(mk: ByteArray, header: RatchetHeader, ciphertext: ByteArray): ByteArray {
        val encKey = hkdfSha256(mk, ZERO_SALT, INFO_MSG, 32)
        mk.secureWipe()
        try {
            return aesGcmDecrypt(ciphertext = ciphertext, key = encKey, associatedData = header.encode())
        } catch (e: Exception) {
            // Class name only: this message reaches log lines upstream.
            throw RatchetException("AEAD decrypt failed: ${e::class.simpleName}")
        } finally {
            encKey.secureWipe()
        }
    }

    /** Cache message keys for indices [recvN, until) in the current receiving chain. */
    private fun skipMessageKeys(until: Int) {
        val ck = recvChain ?: return
        if (until - recvN > MAX_SKIP) throw RatchetException("skip $recvN→$until exceeds MAX_SKIP")
        val remote = dhRemotePub ?: return
        // Charge the whole burst BEFORE deriving any of it, so a drain whose
        // budget is already spent costs nothing further. The MAX_SKIP check above
        // bounds the charge, so it cannot overflow.
        workBudget?.chargeChainDerivations(until - recvN)
        val remoteHex = bytesToHex(remote)
        val stamp = nowMs()   // one clock read for the whole burst
        var cur = ck
        while (recvN < until) {
            val (nextCk, mk) = kdfCk(cur)
            cur.secureWipe()
            cur = nextCk
            // Bound the cache before inserting (see [enforceSkippedCap] for the
            // least-likely-needed order). Keys are one-shot and wiped on eviction.
            if (skipped.size >= MAX_SKIPPED_STORE) enforceSkippedCap(MAX_SKIPPED_STORE - 1)
            skipped[SkippedKeyId(remoteHex, recvN)] = SkippedKey(mk, stamp)
            recvN += 1
        }
        recvChain = cur
    }

    /**
     * Drop (and ZERO) every skipped key older than [SKIPPED_KEY_TTL_MS].
     * A stamp in the FUTURE (the user's clock stepped backwards) is never treated as
     * expired — the age-out is a hygiene bound, so it must fail toward keeping a key
     * the peer may still legitimately deliver rather than toward silent message loss.
     */
    private fun pruneExpiredSkipped() {
        if (skipped.isEmpty()) return
        val now = nowMs()
        val stale = skipped.entries
            .filter { now - it.value.createdAtMs >= SKIPPED_KEY_TTL_MS }
            .map { it.key }
        for (id in stale) skipped.remove(id)?.mk?.secureWipe()
    }

    /**
     * Evict (and ZERO) skipped keys until at most [target] remain. Prefers a key from
     * a PRIOR DH chain (dhPubHex != the current remote) — those follow a completed
     * ratchet step and are least likely to still arrive — and within that the lowest
     * message number. Better than insertion-order FIFO, which could drop a still-needed
     * current-chain key ahead of a stale prior-chain one.
     */
    private fun enforceSkippedCap(target: Int = MAX_SKIPPED_STORE) {
        if (skipped.size <= target) return
        val remoteHex = dhRemotePub?.let { bytesToHex(it) }
        while (skipped.size > target) {
            val victim = skipped.keys.minWithOrNull(
                compareBy({ it.dhPubHex == remoteHex }, { it.n })
            ) ?: return
            skipped.remove(victim)?.mk?.secureWipe()
        }
    }

    /**
     * True once the ratchet has processed >= 2 RECEIVING DH steps.
     * Used to gate dr-rxlock arming so a SINGLE forged bootstrap message (step 1)
     * does not arm the sticky lock.
     *
     * Known limitation — this is NOT an unforgeability check. Reaching step 2 needs
     * only Bob's fresh PUBLIC ratchet key, which is sent in the CLEARTEXT header; an
     * attacker with sharedSecret + write-cap who OBSERVES headers (the in-scope
     * malicious relay) can forge the second inbound too — dh(A2priv, B1pub) equals
     * dh(B1priv, A2pub), so no Bob private key is required. The counter raises the
     * attacker's cost (2 forged blobs + 1 observed header) but cannot prevent
     * malicious arming under full compromise. See drRecvLockKey for the full scope.
     */
    fun hasRatchetedPastBootstrap(): Boolean = dhRecvSteps >= 2

    /** How many skipped message keys are cached (no key material leaves). */
    internal fun skippedKeyCount(): Int = skipped.size

    /** How many RECEIVING DH steps this ratchet has taken — a monotonic ordinal of
     *  the peer's sending chains as we first received them (serialized since v2). */
    internal fun receivingStepCount(): Int = dhRecvSteps

    /** Would [header] open an already-cached skipped key (an out-of-order /
     *  withheld message) rather than the current in-order path? */
    internal fun hasSkippedKeyFor(header: RatchetHeader): Boolean =
        skipped.containsKey(SkippedKeyId(bytesToHex(header.dhPub), header.n))

    /** Why [wouldDamageSkippedKeys] wants a wire deferred. */
    internal enum class SkipDamage {
        /** Fine to decrypt. */
        NONE,
        /** A skip AHEAD in the current chain past MAX_SKIP / the skipped-key cap:
         *  the positions it would cache or evict are messages not yet received. */
        BACKLOG,
        /** A receiving DH step that would flush cached keys of an OLDER chain. */
        OLD_CHAIN,
    }

    /**
     * READ-ONLY prediction of whether decrypting a message with
     * [header] would DESTROY or REFUSE something the receive path still needs —
     * used to DEFER a ratchet-sealed control blob drained by the background control
     * sweep ahead of an undrained text backlog on the same chain. [SkipDamage.BACKLOG]
     * when the decrypt would be refused for skipping more than [MAX_SKIP] or would
     * push the skipped-key cache past [MAX_SKIPPED_STORE] (evicting the oldest cached
     * keys); [SkipDamage.OLD_CHAIN] when it would perform a receiving DH step while
     * skipped keys from a chain OLDER than the current remote one exist ([dhRatchet]
     * flushes those). NONE for a header that opens an existing skipped key, and for a
     * header [decrypt] would reject outright anyway (out-of-range `n` on a new key):
     * deferring a blob that can never decrypt would only park junk. Mutates nothing.
     */
    internal fun wouldDamageSkippedKeys(header: RatchetHeader): SkipDamage {
        if (hasSkippedKeyFor(header)) return SkipDamage.NONE
        val remote = dhRemotePub
        if (remote != null && header.dhPub.contentEquals(remote)) {
            if (recvChain == null) return SkipDamage.NONE
            val add = header.n - recvN
            if (add > MAX_SKIP) return SkipDamage.BACKLOG
            return if (add > 0 && skipped.size + add > MAX_SKIPPED_STORE) SkipDamage.BACKLOG else SkipDamage.NONE
        }
        // A NEW remote ratchet key → pn-skip in the current chain, then a DH step.
        if (header.n < 0 || header.n > MAX_SKIP) return SkipDamage.NONE
        val addOld = if (remote != null && recvChain != null) maxOf(0, header.pn - recvN) else 0
        if (addOld > MAX_SKIP) return SkipDamage.BACKLOG
        val remoteHex = remote?.let { bytesToHex(it) }
        val incomingHex = bytesToHex(header.dhPub)
        if (skipped.keys.any { it.dhPubHex != remoteHex && it.dhPubHex != incomingHex }) return SkipDamage.OLD_CHAIN
        return if (skipped.size + addOld + header.n > MAX_SKIPPED_STORE) SkipDamage.BACKLOG else SkipDamage.NONE
    }

    /**
     * True iff at least [n] messages have been sent on
     * the CURRENT sending chain. [dhRatchet] resets `sendN` to 0 on every receiving DH
     * step, so this reads as "ratchet blobs we have sent since the peer's ratchet last
     * provably answered" — which is exactly the precondition
     * `MessageManager.noteRatchetUnackedReceive` needs before an inbound drain without
     * a decryptable ratchet blob counts as evidence of a role collision.
     *
     * Deliberately a predicate, not a getter: nothing outside needs the raw counter,
     * and `sendN` is also a (weak) traffic-volume fact about this pairing.
     */
    fun hasSentAtLeast(n: Int): Boolean = sendN >= n

    /** A DH ratchet step on receiving a header with a new remote ratchet public key. */
    private fun dhRatchet(header: RatchetHeader) {
        // Charge the step BEFORE any of its work (2 ECDH + 1 keypair generation
        // are the single most expensive thing a forged blob can buy). Honest drains
        // never notice — see [RatchetWorkBudget]: a step that ends in a verified tag
        // is refunded, and a real drain holds at most one step to begin with.
        workBudget?.chargeDhStep()
        // This step retires the CURRENT receiving chain. Skipped keys from the
        // chain retired by the PREVIOUS step (and anything older) are now two or more
        // DH steps behind: the peer cannot still be sending in them (it has ratcheted
        // twice since), so they are dead weight that only a forensic reader benefits
        // from. Flush + zero them. Kept: the chain being retired right now (its
        // PN-skipped messages may still be in flight — skipMessageKeys(header.pn) just
        // ran for exactly that) and the incoming chain.
        val retiringHex = dhRemotePub?.let { bytesToHex(it) }
        val incomingHex = bytesToHex(header.dhPub)
        val twoStepsBack = skipped.keys.filter { it.dhPubHex != retiringHex && it.dhPubHex != incomingHex }
        for (id in twoStepsBack) skipped.remove(id)?.mk?.secureWipe()

        dhRecvSteps += 1
        prevSendN = sendN
        sendN = 0
        recvN = 0
        dhRemotePub = header.dhPub.copyOf()
        // Receiving chain from a DH against our CURRENT key.
        val (rk1, recvCk) = kdfRk(rootKey, x25519EcdhChecked(dhSelfPriv, dhRemotePub!!))
        rootKey.secureWipe(); rootKey = rk1
        recvChain?.secureWipe(); recvChain = recvCk
        // New self ratchet key, then sending chain from a DH against the new remote key.
        dhSelfPriv.secureWipe()
        val fresh = x25519GenerateKeypair()
        dhSelfPriv = fresh.privateKey
        dhSelfPub = fresh.publicKey
        val (rk2, sendCk) = kdfRk(rootKey, x25519EcdhChecked(dhSelfPriv, dhRemotePub!!))
        rootKey.secureWipe(); rootKey = rk2
        sendChain?.secureWipe(); sendChain = sendCk
    }

    /**
     * Serialize the full ratchet state for vault persistence (binary, versioned).
     * Holds key material — the caller must store it only inside the encrypted vault
     * and [secureWipe] the returned array after writing it.
     */
    fun serialize(): ByteArray {
        var flags = 0
        if (dhRemotePub != null) flags = flags or FLAG_HAS_REMOTE
        if (sendChain != null) flags = flags or FLAG_HAS_SEND_CHAIN
        if (recvChain != null) flags = flags or FLAG_HAS_RECV_CHAIN
        val parts = ArrayList<ByteArray>()
        parts.add(byteArrayOf(SER_VERSION, flags.toByte()))
        parts.add(rootKey); parts.add(dhSelfPriv); parts.add(dhSelfPub)
        dhRemotePub?.let { parts.add(it) }
        sendChain?.let { parts.add(it) }
        recvChain?.let { parts.add(it) }
        parts.add(int4(sendN)); parts.add(int4(recvN)); parts.add(int4(prevSendN))
        parts.add(int4(skipped.size))
        for ((id, sk) in skipped) {
            // SER_VERSION 3 appends the 8-byte creation stamp per entry, so the
            // age-out window survives a lock/relaunch instead of restarting on every
            // load. A v1/v2 blob has no stamps and is read tolerantly (see deserialize);
            // this write is the migrate-on-write half.
            parts.add(hexToBytes(id.dhPubHex)); parts.add(int4(id.n)); parts.add(sk.mk)
            parts.add(long8(sk.createdAtMs))
        }
        // SER_VERSION 2 appends the receiving-DH-step counter after
        // the skipped-key block. A v1 blob (no counter) deserializes with a safe
        // default (see deserialize) so existing ratchets aren't force-re-bootstrapped.
        parts.add(int4(dhRecvSteps))
        val total = parts.sumOf { it.size }
        val out = ByteArray(total)
        var o = 0
        for (p in parts) { p.copyInto(out, o); o += p.size }
        return out
    }
}
