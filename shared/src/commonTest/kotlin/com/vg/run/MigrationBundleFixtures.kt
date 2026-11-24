package com.vg.run

// ---------------------------------------------------------------------------
// Device-move bundle FIXTURES (RÚN-04 part b). Self-contained on purpose: nothing
// here reuses MigrationBundleTest's builders, so editing those can never silently
// change what the golden bytes in MigrationBundleGoldenData describe.
//
//   migGoldenBundles()     the bundles whose encoded bytes are pinned
//   migDecodeDocuments()   hand-made documents (historic layouts, whitespace,
//                          duplicates, unknown fields, escapes, malformed input)
//                          whose decode OUTCOME is pinned
//   migLargeBundle()       a deterministic bundle near the seal's size limit with
//                          exactly MAX_RECORDS rows in every array
//   renderMigBundle /      a canonical text form of a decoded bundle (or of the
//   migOutcome             exception) so two decodes can be compared exactly
//
// Every string below is either ASCII or written with \u escapes, so the source
// file's own encoding cannot change a fixture.
// ---------------------------------------------------------------------------

internal const val MIG_FIX_BID = "AbCdEfGhIjKl-_09"

internal fun migFixHex(b: ByteArray): String {
    val digits = "0123456789abcdef"
    val sb = StringBuilder(b.size * 2)
    for (x in b) {
        val v = x.toInt() and 0xff
        sb.append(digits[v ushr 4]).append(digits[v and 0xf])
    }
    return sb.toString()
}

internal fun migFixUnhex(s: String): ByteArray {
    require(s.length % 2 == 0)
    return ByteArray(s.length / 2) { i -> s.substring(2 * i, 2 * i + 2).toInt(16).toByte() }
}

/** Escapes every char outside printable ASCII (and the backslash) as \uXXXX, so a rendering is plain ASCII. */
internal fun migFixQuote(s: String?): String {
    if (s == null) return "null"
    val sb = StringBuilder("\"")
    for (c in s) {
        val code = c.code
        if (code in 0x20..0x7e && c != '\\' && c != '"') sb.append(c)
        else {
            val h = code.toString(16)
            sb.append("\\u").append("0".repeat(4 - h.length)).append(h)
        }
    }
    return sb.append('"').toString()
}

/** Canonical text of every field of [b]; two bundles render equal iff every field (and the meta ORDER) is equal. */
internal fun renderMigBundle(b: MigrationBundle): String = buildString {
    append("v=").append(b.version).append(" schema=").append(b.schema)
    append(" from=").append(migFixQuote(b.from)).append(" created=").append(b.createdMs)
    append(" bid=").append(migFixQuote(b.bundleId)).append('\n')
    val s = b.snapshot
    for (c in s.contacts) {
        append("C ").append(migFixQuote(c.contactId)).append(" secret=").append(migFixHex(c.sharedSecret))
        append(" trust=").append(c.trustLevel).append(" alias=").append(migFixQuote(c.alias))
        append(" aliasRot=").append(c.aliasLastRotated).append(" mn=").append(migFixQuote(c.mnemonic))
        append(" out=").append(c.outboundCounter).append(" in=").append(c.inboundCounter)
        append(" ep=").append(migFixQuote(c.inboundEpoch))
        append(" octl=").append(c.outboundCtlCounter).append(" ictl=").append(c.inboundCtlCounter)
        append(" ogrp=").append(c.outboundGrpCounter).append(" igrp=").append(c.inboundGrpCounter)
        append(" vby=").append(migFixQuote(c.vouchedByContactId)).append(" vat=").append(c.vouchedAt)
        append(" v3=").append(c.ratchetBootstrapV3).append('\n')
    }
    for (r in s.inboxes) {
        append("I ").append(migFixQuote(r.inboxId)).append(' ').append(migFixQuote(r.contactId))
        append(' ').append(r.createdAt).append(' ').append(r.expiresAt)
        append(' ').append(migFixQuote(r.direction)).append(" cap=").append(migFixQuote(r.cap)).append('\n')
    }
    for (g in s.groups) {
        append("G ").append(migFixQuote(g.groupId)).append(' ').append(migFixQuote(g.name)).append(' ').append(g.epoch)
        append(' ').append(migFixQuote(g.adminMemberId)).append(' ').append(migFixQuote(g.myMemberId))
        append(' ').append(g.createdAt).append('\n')
    }
    for (m in s.members) {
        append("M ").append(migFixQuote(m.groupId)).append(' ').append(migFixQuote(m.memberId))
        append(' ').append(migFixQuote(m.contactId)).append(' ').append(m.addedAt)
        append(' ').append(migFixQuote(m.tags)).append('\n')
    }
    for ((k, v) in s.meta) append("K ").append(migFixQuote(k)).append('=').append(migFixQuote(v)).append('\n')
}

/** The decoded rendering, or `ERR:<exception class>:<message>`. Only [Exception] is caught; an Error fails the test. */
internal fun migOutcome(block: () -> MigrationBundle): String =
    try {
        renderMigBundle(block())
    } catch (e: Exception) {
        "ERR:" + e::class.simpleName + ":" + e.message
    }

/** The encoder's outcome as hex, or `ERR:<exception class>:<message>`. */
internal fun migEncodeOutcome(block: () -> ByteArray): String =
    try {
        migFixHex(block())
    } catch (e: Exception) {
        "ERR:" + e::class.simpleName + ":" + e.message
    }

/** What a decoder may return for an encoded [b]: the same bundle with the denied `_meta` rows dropped. */
internal fun migExpectedAfterDecode(b: MigrationBundle): MigrationBundle =
    b.copy(snapshot = b.snapshot.copy(meta = b.snapshot.meta.filterKeys { MoveMetaPolicy.isAllowedKey(it) }))

// ---------------------------------------------------------------------------
// Encoder fixtures
// ---------------------------------------------------------------------------

private fun fixInbox(n: Int) = "inbox-" + n.toString().padStart(26, '0')
private fun fixCap(n: Int) = "cap-" + n.toString().padStart(39, '0')
private fun fixSecret(seed: Int, size: Int = 32) = ByteArray(size) { (it * 31 + seed * 7 + 3).toByte() }

private fun fixRichSnapshot(): VaultSnapshot {
    val contacts = listOf(
        ContactRecord(
            contactId = "c-one",
            sharedSecret = fixSecret(1),
            trustLevel = 2,
            alias = "Silent \"Fox\"\nwith\\slash \u16b1\u16a2\u16be",
            aliasLastRotated = 1_725_000_000_000L,
            mnemonic = "met at the caf\u00e9 \u2014 tab\there",
            outboundCounter = 41,
            inboundCounter = 39,
            inboundEpoch = "a1b2c3d4e5f6",
            outboundCtlCounter = 7,
            inboundCtlCounter = 6,
            outboundGrpCounter = 5,
            inboundGrpCounter = 4,
            vouchedByContactId = "c-two",
            vouchedAt = 1_724_000_000_000L,
        ),
        ContactRecord(contactId = "c-two", sharedSecret = ByteArray(32), trustLevel = 0, alias = "", aliasLastRotated = 0),
        ContactRecord(
            contactId = "c-three",
            sharedSecret = byteArrayOf(0, -1, 0, -1, 127, -128, 1, 2),
            trustLevel = -1,
            alias = "\u03a9",
            aliasLastRotated = Long.MAX_VALUE,
            outboundCounter = Long.MAX_VALUE,
            inboundCounter = Long.MAX_VALUE - 1,
            inboundEpoch = "ffffffffffff",
            outboundCtlCounter = 9_007_199_254_740_993L,
            inboundCtlCounter = 1,
            outboundGrpCounter = 9_007_199_254_740_995L,
            inboundGrpCounter = Long.MAX_VALUE - 2,
        ),
    )
    val inboxes = listOf(
        InboxIdRecord(fixInbox(1), "c-one", 1_000, 2_000, "inbound", fixCap(1)),
        InboxIdRecord(fixInbox(2), "c-one", 1_001, 2_001, "outbound", fixCap(2)),
        InboxIdRecord(fixInbox(3), "c-one", 1_002, 2_002, "inbound-ctl", fixCap(3)),
        InboxIdRecord(fixInbox(4), "c-two", 1_003, 2_003, "outbound-ctl", null),
        InboxIdRecord(fixInbox(5), "c-one", 1_004, 2_004, "inbound-grp", fixCap(5)),
        InboxIdRecord(fixInbox(6), "c-one", 1_005, 2_005, "outbound-grp", fixCap(6)),
    )
    val groups = listOf(
        GroupRecord("g-one", "Kitchen \"table\"", 4, "0123456789abcdef", "0123456789abcdef", 1_700_000_000_000L),
    )
    val members = listOf(
        GroupMemberRecord("g-one", "0123456789abcdef", null, 1_700_000_000_000L, ""),
        GroupMemberRecord("g-one", "fedcba9876543210", "c-one", 1_700_000_001_000L, "aa:bb;cc:dd"),
    )
    val meta = linkedMapOf(
        "dr/c-one/text" to "v3:AAAA/BBBB+CC==",
        "vlt_c" to "DENIED-wrapped-db-key",
        "dr-rxc/c-one" to "17",
        "pin_attempts" to "DENIED-pin",
        "cap-pend/c-one/inbound" to fixCap(9),
        "grp_ctl_pend:g-one:c-one" to "roster|4|abcdef|2|1725000000000",
        "ssn:conv-1:c-one:1725000000123" to "DENIED-screenshot-notice",
        "ref_p:offer-1" to "{\"k\":\"v\"}",
        "mig_frozen" to "DENIED-frozen",
        "locale" to "DENIED-locale",
        "grp-ann/c-one" to "3|1725000000000",
        "group_admin:g-one" to "c-one",
    )
    return VaultSnapshot(contacts, inboxes, groups, members, meta)
}

private fun fixBundle(snapshot: VaultSnapshot, schema: Int, from: String = MigrationBundle.FROM_ANDROID, created: Long = 1_725_500_000_000L) =
    MigrationBundle(schema = schema, from = from, createdMs = created, bundleId = MIG_FIX_BID, snapshot = snapshot)

private val EMPTY_SNAPSHOT = VaultSnapshot(emptyList(), emptyList(), emptyList(), emptyList(), emptyMap())

/** Every control char, quotes, backslash, slash, line/paragraph separators, NBSP, BOM, NEL, DEL, emoji and other non-BMP text. */
internal const val MIG_FIX_WEIRD: String =
    "\u0000\u0001\u0002\u0003\u0004\u0005\u0006\u0007\u0008\u0009\u000a\u000b\u000c\u000d\u000e\u000f" +
        "\u0010\u0011\u0012\u0013\u0014\u0015\u0016\u0017\u0018\u0019\u001a\u001b\u001c\u001d\u001e\u001f" +
        " \"\\/'<>&\u007f\u0080\u0085\u00a0\u00ad\u2028\u2029\u200b\u200d\ufeff\ufffd\uffff" +
        "\ud83e\udd8a\ud835\udd7d\ud83d\udc68\u200d\ud83d\udc69\u200d\ud83d\udc67 e\u0301 \u4e2d\u6587 \u0627\u0644\u0639\u0631\u0628\u064a\u0629 \u16b1\u16a2\u16be" +
        " \\n \\u0041 \\\" end"

private fun fixSpecialSnapshot(): VaultSnapshot {
    val w = MIG_FIX_WEIRD
    val contacts = listOf(
        ContactRecord(
            contactId = "c weird \ud83e\udd8a \"q\"",
            sharedSecret = fixSecret(9, 64),
            trustLevel = 1,
            alias = w,
            aliasLastRotated = 5,
            mnemonic = "\\\\\\\"\"\"\n\r\t",
            inboundEpoch = "\u2028\u2029",
            vouchedByContactId = "\ud83d\ude00",
        ),
    )
    val inboxes = listOf(InboxIdRecord("in \t box", "c weird", -1, 0, "dir\u00e9\ud83d\ude00", "cap \"x\" \\ /"))
    val groups = listOf(GroupRecord("g\u0000id", w, 0, "adm\u2028", "me\u00a0", -9))
    val members = listOf(GroupMemberRecord("g\u0000id", "m\ud83d\ude00", "c weird", 1, w))
    val meta = linkedMapOf(
        "dr/\ud83e\udd8a/text" to w,
        "ref_p:\"quoted\\key\"" to "{\"bv\":\"2\",\"x\":\"\\u0041\"}",
        "grp_\u2028\n" to "",
        "dr-on\u0000" to "\u0000",
    )
    return VaultSnapshot(contacts, inboxes, groups, members, meta)
}

private fun fixOptionalVariants(): VaultSnapshot = VaultSnapshot(
    contacts = listOf(
        ContactRecord("a", ByteArray(0), Int.MIN_VALUE, "x", Long.MIN_VALUE + 1, vouchedByContactId = null, vouchedAt = -1),
        ContactRecord("b", ByteArray(1) { 7 }, Int.MAX_VALUE, "", 0, vouchedByContactId = "", vouchedAt = Long.MAX_VALUE),
    ),
    inboxes = listOf(
        InboxIdRecord("i1", "a", 0, 0, "inbound", null),
        InboxIdRecord("i2", "a", Long.MAX_VALUE, Long.MIN_VALUE + 1, "inbound", ""),
    ),
    groups = listOf(GroupRecord("g", "", Long.MIN_VALUE + 1, "x", "y", 0)),
    members = listOf(
        GroupMemberRecord("g", "m1", null, 1, ""),
        GroupMemberRecord("g", "m2", "", 1, ""),
    ),
    meta = emptyMap(),
)

private fun fixV3Snapshot(): VaultSnapshot = VaultSnapshot(
    contacts = listOf(
        ContactRecord("legacy", fixSecret(2), 1, "L", 10, outboundCounter = 3),
        ContactRecord("fresh", fixSecret(3), 1, "F", 11, ratchetBootstrapV3 = true),
    ),
    inboxes = listOf(InboxIdRecord(fixInbox(7), "fresh", 1, 2, "inbound", fixCap(7))),
    groups = emptyList(),
    members = emptyList(),
    meta = linkedMapOf(
        "dr/fresh/text" to "v3:" + encodeBase64(fixSecret(4, 120)),
        "dr-kc/fresh" to "1",
        "dr-lost/legacy" to "1",
    ),
)

private fun fixRefBvSnapshot(): VaultSnapshot = VaultSnapshot(
    contacts = listOf(ContactRecord("c", fixSecret(5), 0, "c", 1)),
    inboxes = emptyList(), groups = emptyList(), members = emptyList(),
    meta = linkedMapOf("ref_p:offer-9" to "{\"ic\":\"x\",\"bv\":\"3\"}"),
)

/**
 * The bundles whose encoding is pinned in [MigrationBundleGoldenData]. The name is the
 * key into the golden tables. All are well-formed UTF-16 (the lone-surrogate case is
 * [migLoneSurrogateBundle], whose bytes differ per platform by design — D4).
 */
internal fun migGoldenBundles(): LinkedHashMap<String, MigrationBundle> = linkedMapOf(
    // schema 10: what every build writes for a vault without a v3 contact.
    "schema10_rich" to fixBundle(fixRichSnapshot(), 10),
    // schema 11 with a v3 contact and its ratchet state.
    "schema11_v3_contact" to fixBundle(fixV3Snapshot(), 11, from = MigrationBundle.FROM_IOS),
    // schema 11 forced only by a v3-capable pending introduction.
    "schema11_ref_bv" to fixBundle(fixRefBvSnapshot(), 11),
    // historic schema numbers through today's encoder (the importer accepts <= 11).
    "schema8_rich" to fixBundle(fixRichSnapshot(), 8),
    "schema9_rich" to fixBundle(fixRichSnapshot(), 9),
    "schema_extremes" to fixBundle(fixOptionalVariants(), Int.MAX_VALUE, from = "abcdefghij_-0189", created = 0),
    "schema_negative" to fixBundle(EMPTY_SNAPSHOT, -3, from = "a", created = Long.MAX_VALUE),
    "empty_all" to fixBundle(EMPTY_SNAPSHOT, 10, from = MigrationBundle.FROM_IOS),
    "meta_all_denied" to fixBundle(
        VaultSnapshot(emptyList(), emptyList(), emptyList(), emptyList(), linkedMapOf("vlt_c" to "x", "pin_attempts" to "3", "locale" to "sv")),
        10,
    ),
    "only_contacts" to fixBundle(fixRichSnapshot().copy(inboxes = emptyList(), groups = emptyList(), members = emptyList(), meta = emptyMap()), 10),
    "only_meta" to fixBundle(fixRichSnapshot().copy(contacts = emptyList(), inboxes = emptyList(), groups = emptyList(), members = emptyList()), 10),
    "special_chars" to fixBundle(fixSpecialSnapshot(), 10),
    "optional_variants" to fixBundle(fixOptionalVariants(), 10),
    // Encodes; the DECODER refuses it (empty identity) — pinned on both sides.
    "empty_identity" to fixBundle(
        VaultSnapshot(listOf(ContactRecord("", ByteArray(32), 0, "", 0)), emptyList(), emptyList(), emptyList(), emptyMap()), 10,
    ),
    // Encodes; Long.MIN_VALUE does not decode (strictLong's overflow guard) — pinned as is.
    "long_min_value" to fixBundle(
        VaultSnapshot(listOf(ContactRecord("c", ByteArray(32), 0, "", 0, outboundCounter = Long.MIN_VALUE)), emptyList(), emptyList(), emptyList(), emptyMap()), 10,
    ),
)

/** Bundles too large for a hex constant: their bytes are pinned by length + SHA-256. */
internal fun migDigestBundles(): LinkedHashMap<String, MigrationBundle> {
    val longAlias = buildString { while (length < 70_000) append("ab\"\\\n\u00e9\u2028\ud83e\udd8a\u0000 ") }
    val longValue = buildString { while (length < 200_000) append("v3:QUJDREVGR0g=/+") }
    return linkedMapOf(
        "long_fields" to fixBundle(
            VaultSnapshot(
                contacts = listOf(ContactRecord("c", fixSecret(6, 4096), 1, longAlias, 1, mnemonic = longAlias)),
                inboxes = emptyList(), groups = emptyList(), members = emptyList(),
                meta = linkedMapOf("dr/c/text" to longValue, "ref_p:" + "k".repeat(10_000) to longValue),
            ),
            10,
        ),
    )
}

/** Lone surrogates in every kind of string position. JVM writes `?` for each, Kotlin/Native EF BF BD (D4: kept as is). */
internal fun migLoneSurrogateBundle(): MigrationBundle = fixBundle(
    VaultSnapshot(
        contacts = listOf(ContactRecord("c\ud800", ByteArray(32), 0, "\udc00", 0, mnemonic = "a\ud83d", inboundEpoch = "\ude00b")),
        inboxes = emptyList(),
        groups = listOf(GroupRecord("g", "\ude0a\ud83d", 0, "x", "y", 0)),
        members = emptyList(),
        meta = linkedMapOf("dr/\udbff/text" to "\ud83d\ud83d\ude00\ude00"),
    ),
    10,
)

/** True on a platform whose UTF-8 encoder writes `?` for a lone surrogate (the JVM). */
internal fun migPlatformWritesQuestionMarkForLoneSurrogate(): Boolean =
    "\ud800".encodeToByteArray().contentEquals(byteArrayOf('?'.code.toByte()))

// ---------------------------------------------------------------------------
// The large bundle: exactly 8192 rows in every array (MAX_RECORDS, accepted on both
// sides), meta rows filling the plaintext to just under MigrationSeal.MAX_PLAINTEXT_BYTES.
// Deterministic (own SplitMix64), so its bytes are pinned by digest.
// ---------------------------------------------------------------------------

private class FixRng(private var state: Long) {
    fun next(): Long {
        state += -0x61c8864680b583ebL
        var z = state
        z = (z xor (z ushr 30)) * -0x40a7b892e31b1a47L
        z = (z xor (z ushr 27)) * -0x6b2fb644ecceee15L
        return z xor (z ushr 31)
    }
    fun nextInt(bound: Int): Int = ((next() ushr 1) % bound).toInt()
    fun bytes(n: Int) = ByteArray(n) { next().toByte() }
}

internal const val MIG_LARGE_RECORDS = 8192
internal const val MIG_LARGE_META_ROWS = 5_300

internal fun migLargeBundle(): MigrationBundle {
    val rng = FixRng(0x5eed_0004L)
    val words = listOf("Ann", "Bj\u00f6rn", "\u00c5sa", "\u16b1\u16a2\u16be", "\ud83e\udd8a", "Kitchen", "\"Q\"", "a\\b", "line\nbreak", "\u4e2d")
    fun text(n: Int) = buildString { repeat(n) { if (it > 0) append(' '); append(words[rng.nextInt(words.size)]) } }
    val contacts = (0 until MIG_LARGE_RECORDS).map { i ->
        ContactRecord(
            contactId = "contact-$i-" + migFixHex(rng.bytes(8)),
            sharedSecret = rng.bytes(32),
            trustLevel = rng.nextInt(3),
            alias = text(3),
            aliasLastRotated = 1_700_000_000_000L + rng.nextInt(1_000_000_000),
            mnemonic = text(4),
            outboundCounter = rng.next() ushr 1,
            inboundCounter = rng.next() ushr 1,
            inboundEpoch = migFixHex(rng.bytes(6)),
            outboundCtlCounter = rng.nextInt(100_000).toLong(),
            inboundCtlCounter = rng.nextInt(100_000).toLong(),
            outboundGrpCounter = rng.nextInt(100_000).toLong(),
            inboundGrpCounter = rng.nextInt(100_000).toLong(),
            vouchedByContactId = if (rng.nextInt(4) == 0) "contact-${rng.nextInt(MIG_LARGE_RECORDS)}" else null,
            vouchedAt = rng.nextInt(1_000_000).toLong(),
        )
    }
    val dirs = listOf("inbound", "outbound", "inbound-ctl", "outbound-ctl", "inbound-grp", "outbound-grp")
    val inboxes = (0 until MIG_LARGE_RECORDS).map { i ->
        InboxIdRecord(
            encodeBase64Url(rng.bytes(24)), contacts[i].contactId, rng.nextInt(1_000_000).toLong(), rng.nextInt(1_000_000).toLong(),
            dirs[i % dirs.size], if (i % 17 == 0) null else encodeBase64Url(rng.bytes(32)),
        )
    }
    val groups = (0 until MIG_LARGE_RECORDS).map { i ->
        GroupRecord("group-$i-" + migFixHex(rng.bytes(8)), text(2), rng.nextInt(50).toLong(), migFixHex(rng.bytes(8)), migFixHex(rng.bytes(8)), rng.nextInt(1_000_000).toLong())
    }
    val members = (0 until MIG_LARGE_RECORDS).map { i ->
        GroupMemberRecord(groups[i].groupId, migFixHex(rng.bytes(8)), if (i % 3 == 0) null else contacts[i].contactId, rng.nextInt(1_000_000).toLong(), "t:" + rng.nextInt(9))
    }
    val meta = LinkedHashMap<String, String>()
    for (i in 0 until MIG_LARGE_META_ROWS) {
        val c = contacts[i % MIG_LARGE_RECORDS].contactId
        meta["dr/$c/text"] = "v3:" + encodeBase64(rng.bytes(540))
    }
    return MigrationBundle(schema = 10, from = MigrationBundle.FROM_ANDROID, createdMs = 1_725_500_000_000L, bundleId = MIG_FIX_BID,
        snapshot = VaultSnapshot(contacts, inboxes, groups, members, meta))
}

// ---------------------------------------------------------------------------
// Decode-only documents. Key = name, value = the exact UTF-8 text. Their outcomes
// are pinned in MigrationBundleGoldenData.DECODE_OUTCOMES.
// ---------------------------------------------------------------------------

private const val B64_32_ZERO = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

private const val HDR = "\"v\":1,\"schema\":10,\"from\":\"android\",\"created\":5,\"bid\":\"$MIG_FIX_BID\""
private const val C_MIN = "{\"contactId\":\"c\",\"sharedSecret\":\"$B64_32_ZERO\",\"trustLevel\":1,\"alias\":\"a\",\"aliasLastRotated\":9}"
private const val TAIL = "\"inboxes\":[],\"groups\":[],\"members\":[],\"meta\":{}"

private fun doc(contacts: String = C_MIN, meta: String = "{}", hdr: String = HDR, extra: String = "") =
    "{$hdr$extra,\"contacts\":[$contacts],\"inboxes\":[],\"groups\":[],\"members\":[],\"meta\":$meta}"

/** The pre-v10 encoder (aa6516e8 / cd55cf44) wrote no group counters and no v3 flag: its exact layout. */
private fun historicDoc(schema: Int) =
    "{\"v\":1,\"schema\":$schema,\"from\":\"ios\",\"created\":1725500000000,\"bid\":\"$MIG_FIX_BID\"," +
        "\"contacts\":[{\"contactId\":\"c-one\",\"sharedSecret\":\"$B64_32_ZERO\",\"trustLevel\":2,\"alias\":\"Fox \\\"x\\\"\\n\"," +
        "\"aliasLastRotated\":1725000000000,\"mnemonic\":\"caf\u00e9\",\"outboundCounter\":41,\"inboundCounter\":39," +
        "\"inboundEpoch\":\"a1b2\",\"outboundCtlCounter\":7,\"inboundCtlCounter\":6,\"vouchedByContactId\":\"c-two\",\"vouchedAt\":17}," +
        "{\"contactId\":\"c-two\",\"sharedSecret\":\"$B64_32_ZERO\",\"trustLevel\":0,\"alias\":\"\",\"aliasLastRotated\":0," +
        "\"mnemonic\":\"\",\"outboundCounter\":0,\"inboundCounter\":0,\"inboundEpoch\":\"\",\"outboundCtlCounter\":0,\"inboundCtlCounter\":0,\"vouchedAt\":0}]," +
        "\"inboxes\":[{\"inboxId\":\"i1\",\"contactId\":\"c-one\",\"createdAt\":1,\"expiresAt\":2,\"direction\":\"inbound\",\"cap\":\"k1\"}," +
        "{\"inboxId\":\"i2\",\"contactId\":\"c-one\",\"createdAt\":1,\"expiresAt\":2,\"direction\":\"outbound-ctl\"}]," +
        "\"groups\":[{\"groupId\":\"g\",\"name\":\"N\",\"epoch\":4,\"adminMemberId\":\"a\",\"myMemberId\":\"b\",\"createdAt\":3}]," +
        "\"members\":[{\"groupId\":\"g\",\"memberId\":\"a\",\"addedAt\":3,\"tags\":\"\"},{\"groupId\":\"g\",\"memberId\":\"b\",\"contactId\":\"c-one\",\"addedAt\":3,\"tags\":\"t\"}]," +
        "\"meta\":{\"dr/c-one/text\":\"v1:AAAA\",\"ib-bound-seen/c-one\":\"1\",\"vlt_c\":\"x\"}}"

internal fun migDecodeDocuments(): LinkedHashMap<String, String> = linkedMapOf(
    // ---- historic layouts ----
    "hist_schema8" to historicDoc(8),
    "hist_schema9" to historicDoc(9),
    "hist_schema7_minimal" to "{\"v\":1,\"schema\":7,\"from\":\"ios\",\"created\":5,\"bid\":\"$MIG_FIX_BID\"," +
        "\"contacts\":[$C_MIN],\"inboxes\":[{\"inboxId\":\"i\",\"contactId\":\"c\",\"createdAt\":1,\"expiresAt\":2,\"direction\":\"inbound\"}]," +
        "\"groups\":[],\"members\":[],\"meta\":{}}",
    "minimal_no_arrays" to "{$HDR}",
    "empty_object" to "{}",
    // ---- whitespace ----
    "ws_ascii_pretty" to "\n\t {\r\n  \"v\" : 1 ,\n \"schema\"\t:\t10, \"from\" :\"android\" , \"created\": 5 ,\"bid\":\"$MIG_FIX_BID\" ,\n" +
        " \"contacts\" : [ \n { \"contactId\" : \"c\" , \"sharedSecret\":\"$B64_32_ZERO\", \"trustLevel\" : 1 , \"alias\":\"a\",\"aliasLastRotated\" : 9 } \n ] ,\n" +
        " \"inboxes\" : [ ] , \"groups\":[\t], \"members\" :[\n],\"meta\" : { \"dr/c/text\" : \"s\" , \"grp_x\" :\"y\" } \n} \n",
    "ws_unicode_nbsp" to "\u00a0{\u00a0\"v\"\u00a0:\u00a01\u00a0,$HDR\u00a0,\"contacts\":[\u00a0$C_MIN\u00a0],$TAIL\u00a0}",
    "ws_unicode_seps" to "\u2028{\u3000\"v\"\u1680:\u20001\u2029,$HDR\u205f,\"contacts\":[\u2009$C_MIN\u200a],$TAIL\u3000}",
    "ws_ascii_ctrl" to "{\u001c\"v\"\u001d:\u001e1\u001f,$HDR\u000b,\"contacts\":[\u000c$C_MIN],$TAIL}",
    "ws_nel" to "{\u0085\"v\":1,$HDR,\"contacts\":[$C_MIN],$TAIL}",
    "ws_zwsp" to "{\u200b\"v\":1,$HDR,\"contacts\":[$C_MIN],$TAIL}",
    "ws_nnbsp_figure" to "{\u202f\"v\":1\u2007,$HDR,\"contacts\":[$C_MIN],$TAIL}",
    "ws_mvs" to "{\u180e\"v\":1,$HDR,\"contacts\":[$C_MIN],$TAIL}",
    "bom_prefix" to "\ufeff{$HDR,\"contacts\":[$C_MIN],$TAIL}",
    "trailing_junk" to "{$HDR,\"contacts\":[$C_MIN],$TAIL}xyz\u0000\"",
    "trailing_ws_after_number" to "{$HDR,\"x\":12\u3000,\"contacts\":[$C_MIN],$TAIL}",
    // ---- duplicates ----
    "dup_top_scalar" to "{\"v\":1,\"schema\":10,\"schema\":99,\"v\":2,\"from\":\"android\",\"from\":\"ios\",\"created\":5,\"bid\":\"$MIG_FIX_BID\",\"contacts\":[$C_MIN],$TAIL}",
    "dup_record_key" to doc(contacts = C_MIN.dropLast(1) + ",\"trustLevel\":2,\"alias\":\"b\"}"),
    "dup_meta_key" to doc(meta = "{\"dr/c/text\":\"first\",\"dr/c/text\":\"second\"}"),
    "dup_array" to "{$HDR,\"contacts\":[],\"contacts\":[$C_MIN],$TAIL}",
    "dup_meta_object" to "{$HDR,\"meta\":{},\"contacts\":[$C_MIN],$TAIL}",
    "array_key_as_scalar_first" to "{$HDR,\"contacts\":\"x\",$TAIL}",
    "unknown_then_meta_scalar" to "{$HDR,\"meta\":1,\"contacts\":[]}",
    // ---- unknown fields (forward compatibility) ----
    "unknown_fields" to "{\"future\":{\"a\":[1,2,{\"b\":\"}]\\\"{[\"}],\"c\":{}},\"f2\":\"str\\\"\",\"f3\":true,\"f4\":null,\"f5\":[],\"f6\":-1.5e3,$HDR,\"contacts\":[$C_MIN],$TAIL}",
    "unknown_unbalanced" to "{$HDR,\"future\":[1,{],\"contacts\":[$C_MIN],$TAIL}",
    "unknown_unterminated" to "{$HDR,\"future\":[1,2,\"x\"",
    "unknown_nonascii_scalar" to "{$HDR,\"x\":\u00e9\ud83e\udd8a\u4e2d,\"contacts\":[$C_MIN],$TAIL}",
    "unknown_scalar_with_quote" to "{$HDR,\"x\":ab\"c,\"contacts\":[$C_MIN],$TAIL}",
    "unknown_scalar_nbsp_end" to "{$HDR,\"x\":ab\u00a0,\"contacts\":[$C_MIN],$TAIL}",
    "unknown_record_field" to doc(contacts = C_MIN.dropLast(1) + ",\"future\":\"x\",\"n\":true}"),
    // ---- escapes ----
    "escapes_alias" to doc(contacts = C_MIN.replace("\"alias\":\"a\"", "\"alias\":\"\\u0041\\/\\b\\f\\q\\u12\\uD83D\\uDE00\\uDC00\\u00e9\\uZZZZ\\\\\\\"\"")),
    "escape_u_at_end" to doc(contacts = C_MIN.replace("\"alias\":\"a\"", "\"alias\":\"x\\u12\"")),
    "escaped_quote_in_key" to doc(meta = "{\"dr/\\\"q\\\"/text\":\"v\",\"grp_\\u0041\":\"w\"}"),
    "raw_controls_in_string" to doc(contacts = C_MIN.replace("\"alias\":\"a\"", "\"alias\":\"\u0000\u0001\n\t\u001f\u007f\"")),
    // ---- numbers ----
    "num_plus" to doc(contacts = C_MIN.replace("\"trustLevel\":1", "\"trustLevel\":+1")),
    "num_exp" to doc(contacts = C_MIN.replace("\"trustLevel\":1", "\"trustLevel\":1e3")),
    "num_minus_only" to doc(contacts = C_MIN.replace("\"trustLevel\":1", "\"trustLevel\":-")),
    "num_leading_zero" to doc(contacts = C_MIN.replace("\"trustLevel\":1", "\"trustLevel\":007")),
    "num_neg_zero" to doc(contacts = C_MIN.replace("\"trustLevel\":1", "\"trustLevel\":-0")),
    "num_long_overflow" to doc(contacts = C_MIN.replace("\"aliasLastRotated\":9", "\"aliasLastRotated\":9223372036854775808")),
    "num_long_max" to doc(contacts = C_MIN.replace("\"aliasLastRotated\":9", "\"aliasLastRotated\":9223372036854775807")),
    "num_long_min" to doc(contacts = C_MIN.replace("\"aliasLastRotated\":9", "\"aliasLastRotated\":-9223372036854775808")),
    "num_int_overflow" to doc(contacts = C_MIN.replace("\"trustLevel\":1", "\"trustLevel\":2147483648")),
    "num_arabic_digit" to doc(contacts = C_MIN.replace("\"trustLevel\":1", "\"trustLevel\":\u0661")),
    "num_fullwidth_digit" to "{\"v\":\uff11,\"schema\":10,\"from\":\"android\",\"created\":5,\"bid\":\"$MIG_FIX_BID\",$TAIL}",
    "num_true_literal" to doc(contacts = C_MIN.replace("\"trustLevel\":1", "\"trustLevel\":true")),
    "num_as_string" to doc(contacts = C_MIN.replace("\"trustLevel\":1", "\"trustLevel\":\"1\"")),
    "string_as_number" to doc(contacts = C_MIN.replace("\"alias\":\"a\"", "\"alias\":7")),
    "version_string" to "{\"v\":\"1\",\"schema\":10,\"from\":\"android\",\"created\":5,\"bid\":\"$MIG_FIX_BID\",$TAIL}",
    "version_2" to "{\"v\":2,\"schema\":10,\"from\":\"android\",\"created\":5,\"bid\":\"$MIG_FIX_BID\",$TAIL}",
    "version_float" to "{\"v\":1.0,\"schema\":10,\"from\":\"android\",\"created\":5,\"bid\":\"$MIG_FIX_BID\",$TAIL}",
    "schema_out_of_int" to "{\"v\":1,\"schema\":2147483648,\"from\":\"android\",\"created\":5,\"bid\":\"$MIG_FIX_BID\",$TAIL}",
    "schema_missing" to "{\"v\":1,\"from\":\"android\",\"created\":5,\"bid\":\"$MIG_FIX_BID\",$TAIL}",
    "created_negative" to "{\"v\":1,\"schema\":10,\"from\":\"android\",\"created\":-1,\"bid\":\"$MIG_FIX_BID\",$TAIL}",
    "from_invalid" to "{\"v\":1,\"schema\":10,\"from\":\"Android\",\"created\":5,\"bid\":\"$MIG_FIX_BID\",$TAIL}",
    "from_too_long" to "{\"v\":1,\"schema\":10,\"from\":\"abcdefghijklmnopq\",\"created\":5,\"bid\":\"$MIG_FIX_BID\",$TAIL}",
    "bid_invalid" to "{\"v\":1,\"schema\":10,\"from\":\"android\",\"created\":5,\"bid\":\"AbCdEfGhIjKl-_0=\",$TAIL}",
    // ---- record content ----
    "bad_base64" to doc(contacts = C_MIN.replace(B64_32_ZERO, "!!!")),
    "empty_base64" to doc(contacts = C_MIN.replace(B64_32_ZERO, "")),
    "v3_flag_2" to doc(contacts = C_MIN.dropLast(1) + ",\"ratchetV3\":2}"),
    "v3_flag_0" to doc(contacts = C_MIN.dropLast(1) + ",\"ratchetV3\":0}"),
    "v3_without_state" to doc(contacts = C_MIN.dropLast(1) + ",\"ratchetV3\":1}"),
    "v3_with_state" to doc(contacts = C_MIN.dropLast(1) + ",\"ratchetV3\":1}", meta = "{\"dr/c/text\":\"s\"}"),
    "missing_alias" to doc(contacts = C_MIN.replace(",\"alias\":\"a\"", "")),
    "empty_contact_id" to doc(contacts = C_MIN.replace("\"contactId\":\"c\"", "\"contactId\":\"\"")),
    "member_contact_number" to "{$HDR,\"contacts\":[],\"inboxes\":[],\"groups\":[],\"members\":[{\"groupId\":\"g\",\"memberId\":\"m\",\"contactId\":5,\"addedAt\":1}],\"meta\":{}}",
    "empty_record" to doc(contacts = "{}"),
    // ---- structure ----
    "nested_in_record" to doc(contacts = C_MIN.replace("\"trustLevel\":1", "\"trustLevel\":{\"x\":1}")),
    "nested_array_in_record" to doc(contacts = C_MIN.replace("\"trustLevel\":1", "\"trustLevel\":[1]")),
    "nested_in_meta" to doc(meta = "{\"dr/c/text\":{}}"),
    "meta_number_value" to doc(meta = "{\"dr/c/text\":1}"),
    "array_of_numbers" to doc(contacts = "1,2"),
    "array_trailing_comma" to doc(contacts = "$C_MIN,"),
    "object_trailing_comma" to "{$HDR,\"contacts\":[$C_MIN],$TAIL,}",
    "record_trailing_comma" to doc(contacts = C_MIN.dropLast(1) + ",}"),
    "missing_colon" to "{\"v\" 1}",
    "missing_comma" to "{\"v\":1 \"schema\":10}",
    "unterminated_string" to "{\"v\":1,\"from\":\"andr",
    "dangling_backslash" to "{\"v\":1,\"from\":\"andr\\",
    "key_not_string" to "{v:1}",
    "empty_doc" to "",
    "ws_only" to " \n\t ",
    "top_array" to "[]",
    "junk" to "not json at all",
    "truncated" to doc().dropLast(1),
    "deep_unknown" to "{$HDR," + "\"d\":" + "[".repeat(500) + "]".repeat(500) + ",\"contacts\":[$C_MIN],$TAIL}",
)

/**
 * Raw byte documents (invalid UTF-8, encoded lone surrogates, truncated sequences) —
 * their decode differs per platform BY DESIGN (D4), so their outcomes are not pinned
 * as text; they are compared against [LegacyMigrationBundleCodec] on each platform.
 */
internal fun migRawByteDocuments(): LinkedHashMap<String, ByteArray> {
    fun b(vararg parts: Any): ByteArray {
        val out = ArrayList<Byte>()
        for (p in parts) when (p) {
            is String -> out.addAll(p.encodeToByteArray().toList())
            is IntArray -> p.forEach { out.add(it.toByte()) }
            else -> error("bad part")
        }
        return out.toByteArray()
    }
    val pre = "{$HDR,\"contacts\":[{\"contactId\":\"c\",\"sharedSecret\":\"$B64_32_ZERO\",\"trustLevel\":1,\"aliasLastRotated\":9,\"alias\":\""
    val post = "\"}],$TAIL}"
    val pairs = linkedMapOf(
        "lone_cont" to intArrayOf(0x80),
        "lone_cont_run" to intArrayOf(0x80, 0xbf, 0x80),
        "trunc2" to intArrayOf(0xc3),
        "trunc3a" to intArrayOf(0xe2),
        "trunc3b" to intArrayOf(0xe2, 0x80),
        "trunc4" to intArrayOf(0xf0, 0x9f, 0xa6),
        "overlong2" to intArrayOf(0xc0, 0xaf),
        "overlong3" to intArrayOf(0xe0, 0x80, 0xaf),
        "surrogate_enc" to intArrayOf(0xed, 0xa0, 0x80),
        "surrogate_pair_enc" to intArrayOf(0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80),
        "above_max" to intArrayOf(0xf4, 0x90, 0x80, 0x80),
        "f5" to intArrayOf(0xf5, 0x80, 0x80, 0x80),
        "ff" to intArrayOf(0xff),
        "fe_ff" to intArrayOf(0xfe, 0xff),
        "mixed" to intArrayOf(0x61, 0xe2, 0x80, 0x62, 0xf0, 0x9f, 0x98, 0x80, 0xc3),
    )
    val out = LinkedHashMap<String, ByteArray>()
    for ((name, bytes) in pairs) {
        out["str_$name"] = b(pre, bytes, post)
        // the bad sequence right before the closing quote / a backslash
        out["strq_$name"] = b(pre, "x\\", bytes, post)
        // outside a string: between tokens, inside an unknown scalar, inside an unknown structure
        out["ws_$name"] = b("{", bytes, HDR, ",\"contacts\":[],$TAIL}")
        out["afterval_$name"] = b("{$HDR,\"x\":1", bytes, ",\"contacts\":[],$TAIL}")
        out["scalar_$name"] = b("{$HDR,\"x\":ab", bytes, "cd,\"contacts\":[],$TAIL}")
        out["scalar_ws_$name"] = b("{$HDR,\"x\":ab", bytes, intArrayOf(0xc2, 0xa0), ",\"contacts\":[],$TAIL}")
        out["skip_$name"] = b("{$HDR,\"x\":[1,", bytes, ",{\"a\":\"", bytes, "\"}],\"contacts\":[],$TAIL}")
        out["key_$name"] = b("{$HDR,\"contacts\":[],\"inboxes\":[],\"groups\":[],\"members\":[],\"meta\":{\"dr/", bytes, "/text\":\"v\"}}")
        out["ws_before_nbsp_$name"] = b("{$HDR,", bytes, intArrayOf(0xc2, 0xa0), "\"contacts\":[],$TAIL}")
        out["end_$name"] = b("{$HDR,\"contacts\":[],$TAIL}", bytes)
        out["trunc_doc_$name"] = b("{$HDR,\"x\":\"", bytes)
    }
    out["nbsp_then_trunc"] = b("{", intArrayOf(0xc2, 0xa0, 0xc2), HDR, "}")
    out["seps_run"] = b("{", intArrayOf(0xe2, 0x80, 0xa8, 0xe3, 0x80, 0x80, 0xc2, 0xa0), HDR, "}")
    out["seps_run_bad_mid"] = b("{", intArrayOf(0xe2, 0x80, 0xa8, 0xe3, 0x80, 0xc2, 0xa0), HDR, "}")
    out["seps_run_then_scalar"] = b("{$HDR,\"x\":", intArrayOf(0xe2, 0x80, 0xa8, 0xc3, 0xa9, 0xe2, 0x80, 0xa8), "1,\"contacts\":[],$TAIL}")
    return out
}
