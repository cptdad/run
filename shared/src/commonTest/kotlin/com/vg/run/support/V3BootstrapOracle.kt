package com.vg.run

/**
 * The DERIVATION ORACLE for the v3 ratchet bootstrap (docs/ratchet-bootstrap-plan.md §7):
 * the attacker's program, written from the protocol description and the public state
 * format — it never calls the victim's [DoubleRatchet] or [RatchetBootstrapV3]. It
 * extends [LegacyBootstrapAttacker] (wire parsing, KDF_RK / KDF_CK, opening) with every
 * further key and label the code uses.
 *
 * Inputs = everything the attacker holds after seizing both phones and recording the relay:
 *  - every serialized ratchet state found in either vault (parsed by the documented
 *    `SER_VERSION` layout: root, self priv/pub, remote pub, both chains, skipped keys),
 *  - every contact-row secret (`ss'` for a v3 pairing, `ss` for a legacy one) plus any
 *    other leaked 32-byte value a control case chooses to add,
 *  - both QR codes: the two secret halves and the two one-time public keys,
 *  - every recorded relay body (ratchet wires carry their cleartext header).
 *
 * The program, step by step:
 *  1. secrets = all of the above + `ss_halves` recomputed from the halves; every secret is
 *     also tried as an X25519 scalar, and as a legacy root / legacy responder key
 *     (HKDF with "run-dr-init-v1" / "run-dr-bob-key-v1");
 *  1b. referral (when the snapshot names an introId): every secret, and every DH of a
 *     held scalar with one of the two one-time keys, expanded under "run-referral-v1|introId"
 *     and "run-referral-drboot-v3|introId"; both results join the secrets, and each pair
 *     from one ikm is tried as (ikm = S_ref, salt = ss_ref) in step 3;
 *  2. public keys = QR keys + state keys + every header key; X25519(every scalar, every key);
 *  3. v3 candidates: for every possible S (each DH output and each raw secret) and every
 *     plausible salt (zero, `ss_halves`, each half, each stored secret), the four v3 labels
 *     bound to the QR transcript T → candidate (rk0, rB_seed, CK_pre, ss');
 *  4. chains: KDF_RK(root, DH) for every root candidate (stored roots, legacy roots, v3 rk0)
 *     against every DH output that involves a recorded key; every v3 output as a chain
 *     origin; EVERY secret (stored, QR, legacy-derived) walked forward as a chain key at each
 *     wire's index and at every offset; each secret as a raw message key / AES key;
 *  5. a root whose chain OPENED a wire is confirmed and ratcheted one more step, to a fixed
 *     point (this is how the attacker walks past the first DH step when it can);
 *  6. AES-GCM-open every recorded wire with its real 40-byte header as AAD.
 *
 * Every label is a literal here, on purpose (same rule as [LegacyBootstrapAttacker]).
 */
internal object V3BootstrapOracle {

    const val LABEL_V3_DOMAIN = "run-dr-boot-v3"
    val LABELS_V3 = listOf("root", "bob-key", "pre-chain", "pairing-secret")

    private val ZERO = ByteArray(32)
    private val BASEPOINT = ByteArray(32).also { it[0] = 9 }
    private const val MAX_OFFSET = 8

    /** Every referral label the code uses (`ReferralManager`), as literals: the contact
     *  secret `ss_ref` and the one-time bootstrap's ikm `S_ref`, each `label|introId`. */
    val LABELS_REFERRAL = listOf("run-referral-v1", "run-referral-drboot-v3")

    class Snapshot(
        val ratchetBlobs: List<ByteArray>,
        val storedSecrets: List<ByteArray>,
        val qrHalves: List<ByteArray>,
        /** The two one-time public keys: from the QR codes, or (referral) the `pk` of the
         *  two accepts the introducer relayed. They are the transcript T in both cases. */
        val qrPublicKeys: List<ByteArray>,
        val bodies: List<ByteArray>,
        /** A referral's introId (on the wire in the offer and both accepts). Non-null ⇒
         *  step 1b runs the referral derivations. */
        val referralIntroId: String? = null,
    )

    /** One parsed ratchet state (public layout, `DoubleRatchet.serialize`). */
    /** [end] = the offset where the documented layout ends; anything after it is an
     *  unknown extra field, which [open] still mines (every 32-byte window). */
    class ParsedState(val secrets: List<ByteArray>, val publics: List<ByteArray>, val remote: ByteArray?, val selfPub: ByteArray, val end: Int = 0)

    private fun readInt(b: ByteArray, o: Int): Int =
        ((b[o].toInt() and 0xFF) shl 24) or ((b[o + 1].toInt() and 0xFF) shl 16) or
            ((b[o + 2].toInt() and 0xFF) shl 8) or (b[o + 3].toInt() and 0xFF)

    fun parseState(blob: ByteArray): ParsedState {
        val ver = blob[0].toInt()
        val flags = blob[1].toInt() and 0xFF
        var o = 2
        fun take(): ByteArray = blob.copyOfRange(o, o + 32).also { o += 32 }
        val secrets = mutableListOf<ByteArray>()
        val publics = mutableListOf<ByteArray>()
        secrets += take()                       // root
        secrets += take()                       // self priv
        val selfPub = take().also { publics += it }
        val remote = if (flags and 0x1 != 0) take().also { publics += it } else null
        if (flags and 0x2 != 0) secrets += take()   // sending chain
        if (flags and 0x4 != 0) secrets += take()   // receiving chain
        o += 12                                 // sendN, recvN, prevSendN
        val sk = readInt(blob, o); o += 4
        repeat(sk) {
            publics += take(); o += 4; secrets += take()
            if (ver >= 3) o += 8
        }
        return ParsedState(secrets, publics, remote, selfPub, o)
    }

    private class Key(val bytes: ByteArray) {
        override fun equals(other: Any?) = other is Key && other.bytes.contentEquals(bytes)
        override fun hashCode() = bytes.contentHashCode()
    }

    private fun MutableSet<Key>.addKey(b: ByteArray?) { if (b != null && b.size == 32) add(Key(b)) }

    private fun dh(priv: ByteArray, pub: ByteArray): ByteArray? = try {
        x25519Ecdh(priv, pub).takeIf { out -> out.any { it.toInt() != 0 } }
    } catch (_: Exception) {
        null
    }

    private fun hkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray) = hkdfSha256(ikm, salt, info, 32)

    private fun cmp(a: ByteArray, b: ByteArray): Int {
        for (i in a.indices) {
            val d = (a[i].toInt() and 0xFF) - (b[i].toInt() and 0xFF)
            if (d != 0) return d
        }
        return 0
    }

    /** `label -> T ‖ label` for the transcript of the two QR one-time keys (min/max, unsigned). */
    private fun transcriptInfos(k1: ByteArray, k2: ByteArray): Map<String, ByteArray> {
        val (lo, hi) = if (cmp(k1, k2) <= 0) k1 to k2 else k2 to k1
        val t = LABEL_V3_DOMAIN.encodeToByteArray() + lo + hi
        return LABELS_V3.associateWith { t + it.encodeToByteArray() }
    }

    /**
     * The attacker's own v3 derivation (§3.2, labels as literals): for a candidate S and
     * salt, `label -> HKDF(S, salt, T ‖ label)` for all four labels. Used by the controls
     * to pin that what the oracle recovers IS what production derived.
     */
    fun deriveV3(s: ByteArray, salt: ByteArray, qrPublicKeys: List<ByteArray>): Map<String, ByteArray> =
        transcriptInfos(qrPublicKeys[0], qrPublicKeys[1]).mapValues { (_, info) -> hkdf(s, salt, info) }

    /** Returns every text the attacker opened (wire order, each wire at most once). */
    fun open(snapshot: Snapshot): List<String> {
        val wires = snapshot.bodies.mapNotNull { LegacyBootstrapAttacker.parseRatchetBody(it) }
        val opened = arrayOfNulls<String>(wires.size)

        // Returns whether [mk] opens wire [i] — also when it was already opened by another
        // route, so a root that reaches it still counts as confirmed (step 5).
        fun tryMessageKey(mk: ByteArray, i: Int): Boolean {
            val w = wires[i]
            val text = LegacyBootstrapAttacker.openRatchetWire(mk, w) ?: try {
                LegacyBootstrapAttacker.envelopeText(aesGcmDecrypt(w.sealed, mk, w.header))
            } catch (_: Exception) {
                null
            }
            if (text != null && opened[i] == null) opened[i] = text
            return text != null
        }

        /** A chain ORIGIN (index 0) tried on the given wires at their own header index. */
        fun tryChain(ck: ByteArray, targets: List<Int>): Boolean {
            var any = false
            for (i in targets) if (tryMessageKey(LegacyBootstrapAttacker.messageKeyAt(ck, wires[i].n), i)) any = true
            return any
        }

        // --- 1. secrets ----------------------------------------------------------
        val secrets = LinkedHashSet<Key>()
        val publics = LinkedHashSet<Key>()
        val storedChains = LinkedHashSet<Key>()
        for (blob in snapshot.ratchetBlobs) {
            val p = parseState(blob)
            p.secrets.forEach { secrets.addKey(it); storedChains.addKey(it) }
            p.publics.forEach { publics.addKey(it) }
            // Any bytes past the documented layout: every 32-byte window is a candidate secret.
            for (off in p.end..blob.size - 32) secrets.addKey(blob.copyOfRange(off, off + 32))
        }
        snapshot.storedSecrets.forEach { secrets.addKey(it) }
        snapshot.qrHalves.forEach { secrets.addKey(it) }
        val ssHalves = if (snapshot.qrHalves.size == 2) deriveSharedSecret(snapshot.qrHalves[0], snapshot.qrHalves[1]) else null
        secrets.addKey(ssHalves)
        snapshot.qrPublicKeys.forEach { publics.addKey(it) }
        wires.forEach { publics.addKey(it.senderRatchetPub) }

        // --- 1b. referral (plan §4.2): every raw secret and every DH between a held
        // scalar (e.g. a `ref_p` private key) and one of the two one-time keys, expanded
        // under BOTH referral labels bound to the introId → candidate `ss_ref` / `S_ref`.
        // Both join the secrets (so every later step tries them: as legacy roots, chain
        // keys, raw keys, v3 ikm with the stored salts), and each (S_ref, ss_ref) pair from
        // ONE ikm is also tried as (ikm, salt) in step 3 — what production derives.
        val referralPairs = mutableListOf<Pair<ByteArray, ByteArray>>()
        snapshot.referralIntroId?.let { introId ->
            val ikms = LinkedHashSet<Key>().apply { addAll(secrets) }
            for (q in secrets.toList()) for (p in snapshot.qrPublicKeys) dh(q.bytes, p)?.let { ikms.add(Key(it)) }
            for (x in ikms) {
                val (labelSs, labelBoot) = LABELS_REFERRAL
                val ssRef = hkdf(x.bytes, ByteArray(0), "$labelSs|$introId".encodeToByteArray())
                val sRef = hkdf(x.bytes, ByteArray(0), "$labelBoot|$introId".encodeToByteArray())
                referralPairs += sRef to ssRef
            }
            referralPairs.forEach { (a, b) -> secrets.addKey(a); secrets.addKey(b) }
        }

        val legacyRoots = secrets.map { Key(LegacyBootstrapAttacker.legacyRootKey(it.bytes)) }
        val legacyBobPrivs = secrets.map { Key(LegacyBootstrapAttacker.legacyResponderRatchetPriv(it.bytes)) }
        val privs = LinkedHashSet<Key>().apply { addAll(secrets); addAll(legacyBobPrivs) }
        val pubOf = privs.associateWith { k -> dh(k.bytes, BASEPOINT)?.let { Key(it) } }

        // --- 2. every DH between a scalar we hold and a key we saw -------------------
        class DhOut(val value: ByteArray, val keys: Set<Key>)   // keys = the public keys this DH involves
        val dhOuts = mutableListOf<DhOut>()
        for (q in privs) for (p in publics) {
            val out = dh(q.bytes, p.bytes) ?: continue
            dhOuts += DhOut(out, setOfNotNull(p, pubOf[q]))
        }

        val wireIdx = wires.indices.toList()
        fun wiresFor(keys: Set<Key>): List<Int> = wireIdx.filter { Key(wires[it].senderRatchetPub) in keys }

        // --- 6 (direct). every secret as a raw message key, and walked forward as a
        // chain key: at each wire's own index n (a chain ORIGIN) and at every offset up to
        // the longest recorded chain (a stored, already-advanced chain). Every secret —
        // not only the chain slots of a parsed state — so a production slip that keys a
        // chain with ss', a half, ss_halves or a legacy derivation is caught here.
        for (k in secrets) for (i in wireIdx) tryMessageKey(k.bytes, i)
        val maxOffset = maxOf(MAX_OFFSET, wires.maxOfOrNull { it.n } ?: 0)
        val chainWalk = LinkedHashSet<Key>().apply {
            addAll(storedChains); addAll(secrets); addAll(legacyRoots); addAll(legacyBobPrivs)
        }
        for (c in chainWalk) {
            tryChain(c.bytes, wireIdx)
            var ck = c.bytes
            repeat(maxOffset + 1) {
                val (next, mk) = LegacyBootstrapAttacker.kdfCk(ck)
                for (i in wireIdx) tryMessageKey(mk, i)
                ck = next
            }
        }

        // --- 4/5. KDF_RK from a root, then confirmed roots ratchet on ----------------
        val confirmed = ArrayDeque<ByteArray>()
        val seenRoots = LinkedHashSet<Key>()
        fun stepRoot(root: ByteArray, dhValue: ByteArray, keys: Set<Key>) {
            val (next, ck) = LegacyBootstrapAttacker.kdfRk(root, dhValue)
            if (tryChain(ck, wiresFor(keys)) && seenRoots.add(Key(next))) confirmed.addLast(next)
        }
        val freeRoots = LinkedHashSet<Key>().apply { addAll(secrets); addAll(legacyRoots) }
        for (r in freeRoots) for (d in dhOuts) stepRoot(r.bytes, d.value, d.keys)

        // --- 3. v3 candidates from every S × salt, bound to the QR transcript -------------
        val qr = snapshot.qrPublicKeys
        if (qr.size == 2) {
            val info = transcriptInfos(qr[0], qr[1])
            val sCandidates = LinkedHashSet<Key>().apply { dhOuts.forEach { add(Key(it.value)) }; addAll(secrets) }
            val salts = LinkedHashSet<Key>().apply {
                add(Key(ZERO)); addKey(ssHalves)
                snapshot.qrHalves.forEach { addKey(it) }; snapshot.storedSecrets.forEach { addKey(it) }
            }
            fun tryV3(s: ByteArray, salt: ByteArray) {
                val rk0 = hkdf(s, salt, info.getValue("root"))
                val seed = hkdf(s, salt, info.getValue("bob-key"))
                val pre = hkdf(s, salt, info.getValue("pre-chain"))
                val ssPrime = hkdf(s, salt, info.getValue("pairing-secret"))
                // Every output, not only CK_pre, as a chain origin and as a raw key.
                for (out in listOf(pre, ssPrime, rk0, seed)) {
                    tryChain(out, wireIdx)
                    for (i in wireIdx) tryMessageKey(out, i)
                }
                val seedPub = dh(seed, BASEPOINT)?.let { Key(it) }
                for (p in publics) {
                    val out = dh(seed, p.bytes) ?: continue
                    stepRoot(rk0, out, setOfNotNull(p, seedPub))
                }
            }
            for (s in sCandidates) for (salt in salts) tryV3(s.bytes, salt.bytes)
            for ((sRef, ssRef) in referralPairs) tryV3(sRef, ssRef)
        }

        // Confirmed roots: one more KDF_RK against every DH, to a fixed point.
        while (confirmed.isNotEmpty()) {
            val r = confirmed.removeFirst()
            for (d in dhOuts) stepRoot(r, d.value, d.keys)
        }

        return opened.filterNotNull()
    }

    // --- the stored-value scan, encoding-independent ---------------------------------------

    private fun decode32(s: String): List<ByteArray> {
        val out = mutableListOf<ByteArray>()
        fun keep(b: ByteArray?) { if (b != null && b.size == 32) out += b }
        keep(try { decodeBase64(s) } catch (_: Exception) { null })
        keep(try {
            val std = s.replace('-', '+').replace('_', '/')
            decodeBase64(std + "=".repeat((4 - std.length % 4) % 4))
        } catch (_: Exception) { null })
        if (s.length == 64 && s.all { it in "0123456789abcdefABCDEF" }) {
            keep(ByteArray(32) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() })
        }
        return out
    }

    /** The value itself and every double-quoted segment inside it (JSON records). No regex:
     *  Kotlin/Native's engine recurses on long inputs. */
    private fun candidateStrings(v: String): List<String> = listOf(v) + v.split('"').filterIndexed { i, _ -> i % 2 == 1 }

    /**
     * Every 32-byte value an attacker can read out of [vault] as stored, whatever the
     * encoding: each `_meta` value (and each quoted field inside it) decoded as base64,
     * base64url and hex; every string field of every contact row the same way, plus the
     * raw shared secret. [exclude] = keys handed to the oracle separately (ratchet states).
     */
    fun secretsAtRest(vault: InMemoryVault, exclude: Set<String> = emptySet()): List<ByteArray> {
        val out = mutableListOf<ByteArray>()
        for (c in vault.contacts.values) {
            out += c.sharedSecret
            for (f in listOfNotNull(c.contactId, c.alias, c.mnemonic, c.inboundEpoch, c.vouchedByContactId)) {
                candidateStrings(f).forEach { out += decode32(it) }
            }
        }
        for ((k, v) in vault.meta) {
            if (k in exclude) continue
            candidateStrings(v).forEach { out += decode32(it) }
        }
        return out
    }
}
