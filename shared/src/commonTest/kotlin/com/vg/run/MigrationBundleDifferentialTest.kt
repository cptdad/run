package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

// ---------------------------------------------------------------------------
// RÚN-04 part (b): seeded differential test of the byte-oriented bundle codec against
// the frozen String-based reference (LegacyMigrationBundleCodec).
//
//  1. Random bundles (control chars, escapes, Unicode whitespace, non-BMP text, LONE
//     SURROGATES, extreme numbers, optional fields on/off, allowed + denied meta):
//       encode-new == encode-reference, byte for byte (or the same refusal), and
//       decode-new(encode-reference) == decode-reference(encode-new) == the source bundle
//       (both directions: what an old exporter wrote is read by the new importer the
//       same way, and vice versa).
//  2. Random byte-level mutations of those documents (truncation, deletion,
//     duplication, structural bytes, Unicode whitespace, invalid UTF-8, encoded
//     surrogates, '+', nesting): decode-new and decode-reference must give the same
//     model or the same exception class + message.
//
// Deterministic: SEED is fixed and the generator is a local SplitMix64, identical on
// every platform. Runs on the JVM and Kotlin/Native (iosSimulatorArm64Test); lone
// surrogates and invalid UTF-8 encode/decode differently per platform (D4), so the
// reference on the SAME platform is always the expectation.
// ---------------------------------------------------------------------------
class MigrationBundleDifferentialTest {

    private class Rng(private var state: Long) {
        fun next(): Long {
            state += -0x61c8864680b583ebL
            var z = state
            z = (z xor (z ushr 30)) * -0x40a7b892e31b1a47L
            z = (z xor (z ushr 27)) * -0x6b2fb644ecceee15L
            return z xor (z ushr 31)
        }
        fun int(bound: Int): Int = ((next() ushr 1) % bound).toInt()
        fun chance(oneIn: Int) = int(oneIn) == 0
        fun <T> pick(xs: List<T>): T = xs[int(xs.size)]
    }

    private val atoms: List<String> = listOf(
        "a", "Z", "0", "9", " ", "-", "_", ":", "/", ",", "{", "}", "[", "]", "\"", "\\", "\\u0041", "\\n",
        "\u0000", "\u0001", "\u001f", "\n", "\r", "\t", "\u000b", "\u000c", "\u007f",
        "\u0080", "\u0085", " ", "é", " ", " ", "　", " ", "​", "﻿", "�", "￿",
        "ᚱᚢᚾ", "中", "ا", "é",
        "🦊", "𝕽", "􏿿", "𐀀",
        // lone surrogates — each platform keeps its own replacement (D4)
        "\ud800", "\udc00", "\ud83d", "\ude00",
    )

    private fun text(r: Rng, maxAtoms: Int = 8): String {
        val n = r.int(maxAtoms + 1)
        if (n == 0) return ""
        val sb = StringBuilder()
        repeat(n) { sb.append(if (r.chance(3)) r.pick(atoms) else ('a' + r.int(26)).toString()) }
        return sb.toString()
    }

    // Long.MIN_VALUE encodes but never decodes (strictLong's overflow guard, kept as is),
    // so it is rare enough that most bundles still round-trip.
    private fun num(r: Rng): Long = when (r.int(48)) {
        0, 5, 6 -> 0L
        1 -> Long.MAX_VALUE
        2 -> Long.MIN_VALUE
        3 -> -1L
        4 -> Long.MIN_VALUE + 1
        else -> r.next() shr r.int(64)
    }

    private val metaPrefixes = listOf(
        "dr/", "dr-rxc/", "dr-on", "dr-lost/", "dr-kc/", "cap-pend/", "grp_", "grp-ann/", "ref_p:", "ref_x", "plvl-peer/",
        "group_admin:", "m2-chseen", "ib-bound-seen/",
        // denied / not allowed
        "vlt_", "pin_", "mig_", "ssn:", "grp-unread/", "locale", "older_pairing_banner_v1", "",
    )

    private fun bundle(r: Rng): MigrationBundle {
        val contacts = List(r.int(4)) {
            val id = if (r.chance(40)) "" else "c" + text(r, 3)
            ContactRecord(
                contactId = id,
                sharedSecret = ByteArray(if (r.chance(8)) r.int(3) else 32) { r.next().toByte() },
                trustLevel = when (r.int(4)) { 0 -> Int.MIN_VALUE; 1 -> Int.MAX_VALUE; else -> r.int(5) - 1 },
                alias = text(r),
                aliasLastRotated = num(r),
                mnemonic = text(r),
                outboundCounter = num(r),
                inboundCounter = num(r),
                inboundEpoch = text(r, 3),
                outboundCtlCounter = num(r),
                inboundCtlCounter = num(r),
                outboundGrpCounter = num(r),
                inboundGrpCounter = num(r),
                vouchedByContactId = when (r.int(3)) { 0 -> null; 1 -> ""; else -> text(r, 3) },
                vouchedAt = num(r),
                ratchetBootstrapV3 = r.chance(6),
            )
        }
        val inboxes = List(r.int(4)) {
            InboxIdRecord(
                if (r.chance(40)) "" else "i" + text(r, 3), if (r.chance(40)) "" else "c" + text(r, 2), num(r), num(r),
                if (r.chance(40)) "" else r.pick(listOf("inbound", "outbound", "inbound-ctl", "outbound-ctl", "inbound-grp", "outbound-grp")),
                when (r.int(3)) { 0 -> null; 1 -> ""; else -> text(r, 4) },
            )
        }
        val groups = List(r.int(3)) { GroupRecord("g" + text(r, 2), text(r), num(r), "a" + text(r, 2), "m" + text(r, 2), num(r)) }
        val members = List(r.int(3)) {
            GroupMemberRecord("g" + text(r, 2), "m" + text(r, 2), when (r.int(3)) { 0 -> null; 1 -> ""; else -> text(r, 2) }, num(r), text(r, 3))
        }
        val meta = LinkedHashMap<String, String>()
        repeat(r.int(6)) {
            val key = r.pick(metaPrefixes) + text(r, 3)
            meta[key] = if (key.startsWith("ref_p:") && r.chance(3)) "{\"bv\":\"3\"}" else text(r)
        }
        // Most v3 contacts get their state, so the round trip is exercised, not only the refusal.
        for (c in contacts) if (c.ratchetBootstrapV3 && !r.chance(5)) meta["dr/${c.contactId}/text"] = "s" + text(r, 2)
        val schema = when (r.int(6)) { 0 -> 11; 1 -> 10; 2 -> r.int(12); 3 -> Int.MAX_VALUE; 4 -> -1; else -> MigrationBundleCodec.exportSchemaFor(
            VaultSnapshot(contacts, inboxes, groups, members, meta)) }
        val from = when (r.int(10)) { 0 -> ""; 1 -> "Android"; 2 -> "abcdefghijklmnopq"; 3 -> "abcdefghij_-0189"; 4 -> "ios"; else -> "android" }
        val bid = if (r.chance(15)) "short" else MIG_FIX_BID
        return MigrationBundle(
            version = if (r.chance(40)) 2 else 1,
            schema = schema, from = from, createdMs = if (r.chance(10)) -5 else num(r).let { if (it < 0) -it - 1 else it },
            bundleId = bid, snapshot = VaultSnapshot(contacts, inboxes, groups, members, meta),
        )
    }

    private val insertions: List<IntArray> = listOf(
        intArrayOf(0x22), intArrayOf(0x5c), intArrayOf(0x2c), intArrayOf(0x3a), intArrayOf(0x7b), intArrayOf(0x7d),
        intArrayOf(0x5b), intArrayOf(0x5d), intArrayOf(0x20), intArrayOf(0x09), intArrayOf(0x0a), intArrayOf(0x1f),
        intArrayOf(0x2b), intArrayOf(0x2d), intArrayOf(0x30), intArrayOf(0x31), intArrayOf(0x00), intArrayOf(0x7f),
        intArrayOf(0xc2, 0xa0), intArrayOf(0xe2, 0x80, 0xa8), intArrayOf(0xe3, 0x80, 0x80), intArrayOf(0xe1, 0x9a, 0x80),
        intArrayOf(0xc2, 0x85), intArrayOf(0xef, 0xbb, 0xbf), intArrayOf(0xe2, 0x80, 0x8b),
        intArrayOf(0x80), intArrayOf(0xbf), intArrayOf(0xc3), intArrayOf(0xe2), intArrayOf(0xe2, 0x80), intArrayOf(0xf0, 0x9f),
        intArrayOf(0xf0, 0x9f, 0xa6), intArrayOf(0xc0, 0xaf), intArrayOf(0xed, 0xa0, 0x80), intArrayOf(0xf4, 0x90, 0x80, 0x80),
        intArrayOf(0xff), intArrayOf(0xfe), intArrayOf(0xf0, 0x9f, 0xa6, 0x8a),
        "\\u00".encodeToByteArray().map { it.toInt() }.toIntArray(),
        "{\"x\":1}".encodeToByteArray().map { it.toInt() }.toIntArray(),
        "[1,{}]".encodeToByteArray().map { it.toInt() }.toIntArray(),
        ",\"v\":2".encodeToByteArray().map { it.toInt() }.toIntArray(),
        "true".encodeToByteArray().map { it.toInt() }.toIntArray(),
    )

    private fun mutate(r: Rng, src: ByteArray): ByteArray {
        var d = src
        repeat(1 + r.int(3)) {
            if (d.isEmpty()) return d
            val p = r.int(d.size + 1)
            d = when (r.int(7)) {
                0 -> d.copyOf(p)                                                    // truncate
                1 -> if (p < d.size) d.copyOfRange(0, p) + d.copyOfRange(p + 1, d.size) else d   // delete a byte
                2, 3 -> {                                                            // insert
                    val ins = r.pick(insertions).map { it.toByte() }.toByteArray()
                    d.copyOfRange(0, p) + ins + d.copyOfRange(p, d.size)
                }
                4 -> {                                                               // duplicate a slice
                    val q = (p + r.int(40)).coerceAtMost(d.size)
                    d.copyOfRange(0, q) + d.copyOfRange(p, q) + d.copyOfRange(q, d.size)
                }
                5 -> if (p < d.size) d.copyOf().also { it[p] = r.pick(insertions)[0].toByte() } else d  // overwrite
                else -> {                                                            // a digit becomes '+' / a quote becomes a space
                    val c = d.copyOf()
                    val at = (0 until c.size).firstOrNull { idx -> idx >= p && (c[idx] in '0'.code.toByte()..'9'.code.toByte() || c[idx] == 0x22.toByte()) }
                    if (at != null) c[at] = if (c[at] == 0x22.toByte()) 0x20 else '+'.code.toByte()
                    c
                }
            }
        }
        return d
    }

    @Test
    fun randomBundles_andRandomMutations_behaveExactlyLikeTheReference() {
        val r = Rng(SEED)
        var encoded = 0
        var refusedEncodes = 0
        var roundTrips = 0
        var mutations = 0
        var mutationsAccepted = 0
        val failures = ArrayList<String>()
        fun record(msg: String) { if (failures.size < 20) failures += msg }

        repeat(BUNDLES) { idx ->
            val b = bundle(r)
            val encNew = migEncodeOutcome { MigrationBundleCodec.encode(b) }
            val encRef = migEncodeOutcome { LegacyMigrationBundleCodec.encode(b) }
            if (encNew != encRef) { record("bundle #$idx: encode new=${encNew.take(200)} reference=${encRef.take(200)}"); return@repeat }
            if (encNew.startsWith("ERR:")) { refusedEncodes++; return@repeat }
            encoded++
            val bytes = migFixUnhex(encNew)

            // Both directions across the codec boundary.
            val newReadsOld = migOutcome { MigrationBundleCodec.decode(LegacyMigrationBundleCodec.encode(b)) }
            val oldReadsNew = migOutcome { LegacyMigrationBundleCodec.decode(MigrationBundleCodec.encode(b)) }
            if (newReadsOld != oldReadsNew) record("bundle #$idx: new-reads-old=$newReadsOld old-reads-new=$oldReadsNew")
            if (!newReadsOld.startsWith("ERR:")) roundTrips++

            repeat(MUTATIONS_PER_BUNDLE) { m ->
                val mutated = mutate(r, bytes)
                mutations++
                val a = migOutcome { MigrationBundleCodec.decode(mutated) }
                val c = migOutcome { LegacyMigrationBundleCodec.decode(mutated) }
                if (a != c) record("bundle #$idx mutation #$m (${migFixHex(mutated).take(400)}): new=${a.take(200)} reference=${c.take(200)}")
                if (!a.startsWith("ERR:")) mutationsAccepted++
            }
        }
        if (failures.isNotEmpty()) fail("seed=$SEED: ${failures.size}+ divergences\n" + failures.joinToString("\n"))
        println(
            "RUN04-DIFF seed=$SEED bundles=$BUNDLES encoded=$encoded refusedEncodes=$refusedEncodes " +
                "roundTrips=$roundTrips mutations=$mutations mutationsAccepted=$mutationsAccepted",
        )
        // The generator must actually exercise all three paths, or the comparison is hollow.
        assertTrue(encoded > BUNDLES / 3, "too few encodable bundles: $encoded")
        assertTrue(refusedEncodes > 50, "too few refused encodes: $refusedEncodes")
        assertTrue(roundTrips > BUNDLES / 4, "too few round trips: $roundTrips")
        assertTrue(mutationsAccepted > 100, "too few accepted mutations: $mutationsAccepted")
        assertTrue(mutations - mutationsAccepted > 1000, "too few rejected mutations")
    }

    @Test
    fun randomDecodableBundles_roundTripToTheirSource() {
        // The reference is not the only yardstick: a well-formed bundle (no lone
        // surrogate, no refused shape) must come back exactly, on every platform.
        val r = Rng(SEED + 1)
        var checked = 0
        repeat(BUNDLES) {
            val b = bundle(r)
            val src = migExpectedAfterDecode(b)
            val bytes = try { MigrationBundleCodec.encode(b) } catch (_: MigrationBundleCodec.FormatException) { return@repeat }
            val out = migOutcome { MigrationBundleCodec.decode(bytes) }
            if (out.startsWith("ERR:")) return@repeat
            // (the rendering covers every decoded field, allowed meta keys included)
            if (hasLoneSurrogate(renderMigBundle(src))) return@repeat
            assertEquals(renderMigBundle(src), out)
            checked++
        }
        assertTrue(checked > 200, "too few checked: $checked")
    }

    private fun hasLoneSurrogate(rendered: String): Boolean {
        // renderMigBundle writes every non-ASCII unit as \uXXXX; look for an unpaired one.
        var i = 0
        val units = ArrayList<Int>()
        while (i < rendered.length) {
            if (rendered.startsWith("\\u", i) && i + 6 <= rendered.length) {
                units += rendered.substring(i + 2, i + 6).toInt(16); i += 6
            } else { units += -1; i++ }
        }
        for (j in units.indices) {
            val u = units[j]
            if (u in 0xd800..0xdbff && (j + 1 >= units.size || units[j + 1] !in 0xdc00..0xdfff)) return true
            if (u in 0xdc00..0xdfff && (j == 0 || units[j - 1] !in 0xd800..0xdbff)) return true
        }
        return false
    }

    private companion object {
        const val SEED = 0x52554E04L
        const val BUNDLES = 3000
        const val MUTATIONS_PER_BUNDLE = 3
    }
}
