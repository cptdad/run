package com.vg.run

// ---------------------------------------------------------------------------
// REFERENCE ORACLE — a frozen copy of the String-based device-move bundle codec
// exactly as it shipped up to 1.6.75 (MigrationBundle.kt at 0550f276:
// MigrationBundleCodec.encodeToString / decodeFromString, MigRecord, MigDocument,
// MigJson.parseBundleDocument / strictLong, plus RelayJson's jsonEscapeString /
// jsonUnescapeString).
//
// RÚN-04 part (b) replaced the production codec with a byte-oriented one that must
// keep the wire format byte for byte. This copy is what "the same" means: the golden
// fixtures (MigrationBundleGoldenTest) and the seeded differential test
// (MigrationBundleDifferentialTest) compare the production codec against it, in
// both directions, on the JVM and on Kotlin/Native.
//
// DO NOT EDIT to follow a production change. A change here is a change of the
// reference, which is a wire-format decision of its own.
//
// What is deliberately NOT copied (policy, not format, and shared by both sides):
// MoveMetaPolicy.isAllowedKey, MigrationBundleCodec.needsCurrentSchema,
// VaultSnapshotIo.v3ContactsMissingRatchetState, MoveHandleCodec.isValidBundleId,
// and the platform base64 actuals.
// ---------------------------------------------------------------------------
internal object LegacyMigrationBundleCodec {

    private const val CURRENT_VERSION = 1
    private const val CURRENT_SCHEMA = 11
    private const val K_CONTACT_V3 = "ratchetV3"
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
    private const val MAX_RECORDS = 8192
    private const val MAX_META_ROWS = 200_000
    private const val MAX_FROM_LEN = 16

    private fun fail(message: String): Nothing = throw MigrationBundleCodec.FormatException(message)

    fun encode(b: MigrationBundle): ByteArray = encodeToString(b).encodeToByteArray()

    fun decode(bytes: ByteArray): MigrationBundle = decodeFromString(bytes.decodeToString())

    fun encodeToString(b: MigrationBundle): String {
        if (b.version != CURRENT_VERSION) fail("refusing to encode bundle version ${b.version}")
        if (!isValidFrom(b.from)) fail("invalid 'from' tag")
        if (!MoveHandleCodec.isValidBundleId(b.bundleId)) fail("invalid bundleId")
        val s = b.snapshot
        if (s.contacts.size > MAX_RECORDS || s.inboxes.size > MAX_RECORDS ||
            s.groups.size > MAX_RECORDS || s.members.size > MAX_RECORDS
        ) fail("too many records to encode")
        if (s.meta.size > MAX_META_ROWS) fail("too many meta rows to encode")
        if (b.schema < CURRENT_SCHEMA && MigrationBundleCodec.needsCurrentSchema(s)) {
            fail("a v3 contact or a v3 introduction needs bundle schema $CURRENT_SCHEMA")
        }
        if (VaultSnapshotIo.v3ContactsMissingRatchetState(s)) {
            fail("a v3 contact without its ratchet state")
        }

        val sb = StringBuilder(4096)
        sb.append('{')
        sb.append("\"").append(K_VERSION).append("\":").append(b.version)
        sb.append(",\"").append(K_SCHEMA).append("\":").append(b.schema)
        sb.append(",\"").append(K_FROM).append("\":").append(esc(b.from))
        sb.append(",\"").append(K_CREATED).append("\":").append(b.createdMs)
        sb.append(",\"").append(K_BID).append("\":").append(esc(b.bundleId))

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
            num(sb, "outboundGrpCounter", c.outboundGrpCounter)
            num(sb, "inboundGrpCounter", c.inboundGrpCounter)
            if (c.vouchedByContactId != null) str(sb, "vouchedByContactId", c.vouchedByContactId)
            num(sb, "vouchedAt", c.vouchedAt)
            if (c.ratchetBootstrapV3) num(sb, K_CONTACT_V3, 1L)
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
            sb.append(esc(k)).append(':').append(esc(v))
        }
        sb.append('}')

        sb.append('}')
        return sb.toString()
    }

    fun decodeFromString(text: String): MigrationBundle {
        val doc = parseBundleDocument(text) ?: fail("malformed bundle JSON")

        val version = doc.int(K_VERSION) ?: fail("missing bundle version")
        if (version != CURRENT_VERSION) fail("unsupported bundle version $version")

        val schema = doc.int(K_SCHEMA) ?: fail("missing schema")
        val from = doc.string(K_FROM) ?: fail("missing 'from'")
        if (!isValidFrom(from)) fail("invalid 'from' tag")
        val created = doc.long(K_CREATED) ?: fail("missing 'created'")
        if (created < 0) fail("negative 'created'")
        val bid = doc.string(K_BID) ?: fail("missing bundleId")
        if (!MoveHandleCodec.isValidBundleId(bid)) fail("invalid bundleId")

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
                outboundGrpCounter = o.optLong("outboundGrpCounter") ?: 0L,
                inboundGrpCounter = o.optLong("inboundGrpCounter") ?: 0L,
                vouchedByContactId = o.optString("vouchedByContactId"),
                vouchedAt = o.optLong("vouchedAt") ?: 0L,
                ratchetBootstrapV3 = when (o.optLong(K_CONTACT_V3)) {
                    null, 0L -> false
                    1L -> true
                    else -> fail("malformed contact flag")
                },
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

        val snapshot = VaultSnapshot(contacts, inboxes, groups, members, meta)
        if (VaultSnapshotIo.v3ContactsMissingRatchetState(snapshot)) {
            fail("a v3 contact without its ratchet state")
        }
        return MigrationBundle(
            version = version,
            schema = schema,
            from = from,
            createdMs = created,
            bundleId = bid,
            snapshot = snapshot,
        )
    }

    private fun isValidFrom(s: String): Boolean =
        s.isNotEmpty() && s.length <= MAX_FROM_LEN &&
            s.all { it in 'a'..'z' || it in '0'..'9' || it == '_' || it == '-' }

    private fun str(sb: StringBuilder, key: String, value: String, first: Boolean = false) {
        if (!first) sb.append(',')
        sb.append('"').append(key).append("\":").append(esc(value))
    }

    private fun num(sb: StringBuilder, key: String, value: Long) {
        sb.append(",\"").append(key).append("\":").append(value)
    }

    // ---- RelayJson.jsonEscapeString / jsonUnescapeString, frozen ----

    private fun esc(s: String): String {
        val sb = StringBuilder("\"")
        for (c in s) {
            when (c) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                else -> sb.append(c)
            }
        }
        sb.append('"')
        return sb.toString()
    }

    private fun unesc(s: String): String {
        val sb = StringBuilder(s.length)
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (c == '\\' && i + 1 < s.length) {
                when (val n = s[i + 1]) {
                    '"' -> { sb.append('"'); i += 2 }
                    '\\' -> { sb.append('\\'); i += 2 }
                    '/' -> { sb.append('/'); i += 2 }
                    'n' -> { sb.append('\n'); i += 2 }
                    'r' -> { sb.append('\r'); i += 2 }
                    't' -> { sb.append('\t'); i += 2 }
                    'b' -> { sb.append(8.toChar()); i += 2 }
                    'f' -> { sb.append(12.toChar()); i += 2 }
                    'u' -> {
                        val hex = if (i + 6 <= s.length) s.substring(i + 2, i + 6) else null
                        val code = hex?.toIntOrNull(16)
                        if (code != null) { sb.append(code.toChar()); i += 6 }
                        else { sb.append(c); i += 1 }
                    }
                    else -> { sb.append(n); i += 2 }
                }
            } else {
                sb.append(c); i += 1
            }
        }
        return sb.toString()
    }

    // ---- MigRecord / MigDocument, frozen ----

    private class Rec(private val fields: Map<String, JsonScalar>) {
        fun req(key: String, allowEmpty: Boolean = false): String {
            val v = fields[key] ?: fail("missing field '$key'")
            if (!v.isString) fail("field '$key' is not a string")
            if (!allowEmpty && v.text.isEmpty()) fail("empty field '$key'")
            return v.text
        }

        fun optString(key: String): String? {
            val v = fields[key] ?: return null
            if (!v.isString) fail("field '$key' is not a string")
            return v.text
        }

        fun reqBytes(key: String): ByteArray {
            val b64 = req(key, allowEmpty = true)
            return try {
                decodeBase64(b64)
            } catch (e: Exception) {
                fail("field '$key' is not valid base64")
            }
        }

        fun reqLong(key: String): Long = optLong(key) ?: fail("missing numeric field '$key'")

        fun optLong(key: String): Long? {
            val v = fields[key] ?: return null
            if (v.isString) fail("field '$key' is not a number")
            return strictLong(v.text) ?: fail("field '$key' is not a valid number")
        }

        fun reqInt(key: String): Int {
            val l = reqLong(key)
            if (l < Int.MIN_VALUE.toLong() || l > Int.MAX_VALUE.toLong()) fail("field '$key' out of Int range")
            return l.toInt()
        }
    }

    private class Doc(
        private val scalars: Map<String, JsonScalar>,
        private val arrays: Map<String, List<Map<String, JsonScalar>>>,
        val meta: Map<String, String>,
    ) {
        fun string(key: String): String? = scalars[key]?.let { if (it.isString) it.text else null }
        fun long(key: String): Long? = scalars[key]?.let { if (it.isString) null else strictLong(it.text) }
        fun int(key: String): Int? = long(key)?.let { if (it in Int.MIN_VALUE.toLong()..Int.MAX_VALUE.toLong()) it.toInt() else null }
        fun records(key: String): List<Rec> = (arrays[key] ?: emptyList()).map { Rec(it) }
    }

    // ---- MigJson, frozen ----

    private val ARRAY_KEYS = setOf("contacts", "inboxes", "groups", "members")
    private const val MAX_ELEMENTS = 8192

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
            if (acc > (Long.MAX_VALUE - d) / 10) return null
            acc = acc * 10 + d
            i++
        }
        return if (negative) -acc else acc
    }

    private fun parseBundleDocument(body: String): Doc? {
        val s = body
        var i = 0
        fun skipWs() { while (i < s.length && s[i].isWhitespace()) i++ }

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
                    c == '"' -> { i++; return unesc(sb.toString()) }
                    else -> { sb.append(c); i++ }
                }
            }
            return null
        }

        fun readBareScalar(): String? {
            val start = i
            while (i < s.length && s[i] != ',' && s[i] != '}' && s[i] != ']' && !s[i].isWhitespace()) i++
            return if (i > start) s.substring(start, i) else null
        }

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
                    '{', '[' -> return null
                    else -> JsonScalar(readBareScalar() ?: return null, false)
                }
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
            return Doc(scalars, arrays, meta)
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
                    if (arrays.containsKey(key)) return null
                    arrays[key] = readObjectArray() ?: return null
                }
                key == "meta" -> {
                    if (metaSeen) return null
                    metaSeen = true
                    val flat = readFlatObject(MAX_META_ROWS) ?: return null
                    val m = LinkedHashMap<String, String>(flat.size)
                    for ((k, v) in flat) {
                        if (!v.isString) return null
                        m[k] = v.text
                    }
                    meta = m
                }
                s[i] == '"' -> {
                    val v = readString() ?: return null
                    if (!scalars.containsKey(key)) scalars[key] = JsonScalar(v, true)
                }
                s[i] == '{' || s[i] == '[' -> { if (!skipValue()) return null }
                else -> {
                    val v = readBareScalar() ?: return null
                    if (!scalars.containsKey(key)) scalars[key] = JsonScalar(v, false)
                }
            }
            skipWs()
            if (i >= s.length) return null
            when (s[i]) {
                ',' -> { i++; continue }
                '}' -> { i++; return Doc(scalars, arrays, meta) }
                else -> return null
            }
        }
        return null
    }
}
