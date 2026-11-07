package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// MigrationBundleCodec — "Move to new device", area 1 (docs/device-move.md).
//
// The bundle is the user's WHOLE identity in transit: contacts (shared secrets),
// the four inbox directions with their capabilities, groups, and the ratchet /
// referral `_meta` rows. A field that silently fails to round-trip is a contact
// that stops decrypting on the new phone; a `_meta` key that slips past the
// allowlist is credential material leaving the device. Both are pinned here.
// ---------------------------------------------------------------------------

/** 24 bytes → exactly the relay's 32-char base64url inbox id. */
internal fun migTestInboxId(seed: Int): String = encodeBase64Url(ByteArray(24) { (it * 7 + seed).toByte() })

/** 32 bytes → exactly the relay's 43-char base64url capability. */
internal fun migTestCap(seed: Int): String = encodeBase64Url(ByteArray(32) { (it * 11 + seed).toByte() })

/** 12 bytes → exactly the 16-char bundle id. */
internal fun migTestBundleId(seed: Int): String = encodeBase64Url(ByteArray(12) { (it * 13 + seed).toByte() })

/** Every allowed `_meta` prefix (MoveMetaPolicy.allowedPrefixes), one row each. */
internal val migAllowedMeta: Map<String, String> = linkedMapOf(
    "dr/c-one/text" to "v3:AAAA/BBBB+CC==",
    "dr-rxc/c-one" to "17",
    "dr-on/c-one" to "1",
    "dr-intent/c-one" to "1",
    "dr-rxseen/c-one" to "1",
    "dr-rxlock/c-one" to "1",
    "dr-legacyfb/c-one" to "3",
    // The role-collision detectors travel with the ratchet state they
    // describe — the new phone imports the same role, so it inherits the same verdict.
    "dr-rat-unacked/c-one" to "2",
    "dr-refused/c-one" to "1",
    // The role INPUTS travel with the ratchet state too — without them
    // the new phone would fall back to the id-order rule on its first re-init and
    // could land the opposite role from the peer.
    "dr-roleord/c-one" to "1",
    "dr-rolerv2/c-one" to "1",
    "m2-chseen/c-one" to "m",
    "cap-pend/c-one/inbound" to migTestCap(9),
    "grp_ctl_pend:g-one:c-one" to "roster|4|abcdef|2|1725000000000",
    "ref_p:offer-1" to "{\"k\":\"v\"}",
    "ssn:conv-1:c-one:1725000000123" to "1",
)

/** Keys that must NEVER travel — every denied prefix plus an unlisted key. */
internal val migDeniedMeta: Map<String, String> = linkedMapOf(
    // Values are distinctive sentinels so a test can assert the VALUE never appears
    // in the serialized bundle either (a "1" would match by accident).
    "vlt_c" to "DENIED-wrapped-db-key",
    "vlt_rc" to "DENIED-recovery-blob",
    "vlt_txn_journal" to "DENIED-journal",
    "pin_attempts" to "DENIED-pin-attempts",
    "inactivity_armed_v1" to "DENIED-inactivity-anchor",
    "change_pin_pending" to "DENIED-change-pin",
    "run.crypto.provider.key" to "DENIED-keyset",
    "review_prompt_v1" to "DENIED-review",
    "update_nudge_v1" to "DENIED-nudge",
    "onboard_push_prompt_v1" to "DENIED-push-prompt",
    MoveMetaKeys.FROZEN to "DENIED-frozen",
    MoveMetaKeys.IMPORTED to "DENIED-imported",
    "locale" to "DENIED-locale",
)

internal fun migRichSnapshot(): VaultSnapshot {
    val contacts = listOf(
        ContactRecord(
            contactId = "c-one",
            sharedSecret = ByteArray(32) { (it * 3 + 1).toByte() },
            trustLevel = 2,
            alias = "Silent \"Fox\"\nwith\\slash ᚱᚢᚾ",
            aliasLastRotated = 1_725_000_000_000L,
            mnemonic = "met at the café — tab\there",
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
        // Defaults everywhere: null vouchedBy, empty mnemonic/epoch, zero counters.
        ContactRecord(
            contactId = "c-two",
            sharedSecret = ByteArray(32) { 0 },
            trustLevel = 0,
            alias = "",
            aliasLastRotated = 0,
        ),
        // Extremes: 0x00/0xFF secret bytes and a saturated counter.
        ContactRecord(
            contactId = "c-three",
            sharedSecret = byteArrayOf(0, -1, 0, -1, 127, -128, 1, 2),
            trustLevel = -1,
            alias = "Ω",
            aliasLastRotated = Long.MAX_VALUE,
            mnemonic = "",
            outboundCounter = Long.MAX_VALUE,
            inboundCounter = Long.MAX_VALUE - 1,
            inboundEpoch = "ffffffffffff",
            outboundCtlCounter = 9_007_199_254_740_993L,
            inboundCtlCounter = 1,
            // Beyond 2^53: proves the group counters ride the same strict-decimal
            // Long path as their siblings and never a lossy double.
            outboundGrpCounter = 9_007_199_254_740_995L,
            inboundGrpCounter = Long.MAX_VALUE - 2,
            vouchedByContactId = null,
            vouchedAt = 0,
        ),
    )
    val inboxes = listOf(
        InboxIdRecord(migTestInboxId(1), "c-one", 1_000, 2_000, "inbound", migTestCap(1)),
        InboxIdRecord(migTestInboxId(2), "c-one", 1_001, 2_001, "outbound", migTestCap(2)),
        InboxIdRecord(migTestInboxId(3), "c-one", 1_002, 2_002, "inbound-ctl", migTestCap(3)),
        // A legacy pre-capability row: cap == null must stay null, not "".
        InboxIdRecord(migTestInboxId(4), "c-two", 1_003, 2_003, "outbound-ctl", null),
        // v10 — the THIRD pairwise pair (group text). Nothing in the codec knows
        // the direction vocabulary (it is a plain string), which is exactly why
        // these rows travel for free; pinned so that stays true.
        InboxIdRecord(migTestInboxId(5), "c-one", 1_004, 2_004, MessageManager.DIR_INBOUND_GRP, migTestCap(5)),
        InboxIdRecord(migTestInboxId(6), "c-one", 1_005, 2_005, MessageManager.DIR_OUTBOUND_GRP, migTestCap(6)),
    )
    val groups = listOf(
        GroupRecord(
            groupId = "g-one",
            name = "Kitchen \"table\"",
            epoch = 4,
            adminMemberId = "0123456789abcdef",
            myMemberId = "0123456789abcdef",
            createdAt = 1_700_000_000_000L,
        ),
    )
    val members = listOf(
        GroupMemberRecord("g-one", "0123456789abcdef", null, 1_700_000_000_000L, ""),
        GroupMemberRecord("g-one", "fedcba9876543210", "c-one", 1_700_000_001_000L, "aa:bb;cc:dd"),
    )
    val meta = LinkedHashMap<String, String>()
    meta.putAll(migAllowedMeta)
    meta.putAll(migDeniedMeta)
    return VaultSnapshot(contacts, inboxes, groups, members, meta)
}

internal fun migBundle(
    snapshot: VaultSnapshot = migRichSnapshot(),
    schema: Int = MigrationBundleCodec.CURRENT_SCHEMA,
    from: String = MigrationBundle.FROM_ANDROID,
): MigrationBundle = MigrationBundle(
    schema = schema,
    from = from,
    createdMs = 1_725_500_000_000L,
    bundleId = migTestBundleId(5),
    snapshot = snapshot,
)

private fun assertContactEquals(expected: ContactRecord, actual: ContactRecord) {
    assertEquals(expected.contactId, actual.contactId, "contactId")
    assertTrue(expected.sharedSecret.contentEquals(actual.sharedSecret), "sharedSecret bytes")
    assertEquals(expected.trustLevel, actual.trustLevel, "trustLevel")
    assertEquals(expected.alias, actual.alias, "alias")
    assertEquals(expected.aliasLastRotated, actual.aliasLastRotated, "aliasLastRotated")
    assertEquals(expected.mnemonic, actual.mnemonic, "mnemonic")
    assertEquals(expected.outboundCounter, actual.outboundCounter, "outboundCounter")
    assertEquals(expected.inboundCounter, actual.inboundCounter, "inboundCounter")
    assertEquals(expected.inboundEpoch, actual.inboundEpoch, "inboundEpoch")
    assertEquals(expected.outboundCtlCounter, actual.outboundCtlCounter, "outboundCtlCounter")
    assertEquals(expected.inboundCtlCounter, actual.inboundCtlCounter, "inboundCtlCounter")
    assertEquals(expected.outboundGrpCounter, actual.outboundGrpCounter, "outboundGrpCounter")
    assertEquals(expected.inboundGrpCounter, actual.inboundGrpCounter, "inboundGrpCounter")
    assertEquals(expected.vouchedByContactId, actual.vouchedByContactId, "vouchedByContactId")
    assertEquals(expected.vouchedAt, actual.vouchedAt, "vouchedAt")
}

class MigrationBundleTest {

    @Test
    fun richSnapshot_roundTripsEveryField() {
        val original = migBundle()
        val decoded = MigrationBundleCodec.decode(MigrationBundleCodec.encode(original))

        assertEquals(1, decoded.version)
        assertEquals(original.schema, decoded.schema)
        assertEquals(original.from, decoded.from)
        assertEquals(original.createdMs, decoded.createdMs)
        assertEquals(original.bundleId, decoded.bundleId)

        assertEquals(3, decoded.snapshot.contacts.size)
        original.snapshot.contacts.forEachIndexed { i, c ->
            assertContactEquals(c, decoded.snapshot.contacts[i])
        }
        // The remaining record types have no ByteArray field, so data-class equality
        // is a full field-by-field comparison.
        assertEquals(original.snapshot.inboxes, decoded.snapshot.inboxes)
        assertEquals(original.snapshot.groups, decoded.snapshot.groups)
        assertEquals(original.snapshot.members, decoded.snapshot.members)
    }

    @Test
    fun allSixInboxDirections_andNullCap_survive() {
        val decoded = MigrationBundleCodec.decode(MigrationBundleCodec.encode(migBundle()))
        assertEquals(
            listOf(
                "inbound", "outbound", "inbound-ctl", "outbound-ctl",
                MessageManager.DIR_INBOUND_GRP, MessageManager.DIR_OUTBOUND_GRP,
            ),
            decoded.snapshot.inboxes.map { it.direction },
        )
        // null cap must NOT come back as "" — the UI keys "re-pair required" off null.
        assertNull(decoded.snapshot.inboxes[3].cap)
        assertEquals(migTestCap(1), decoded.snapshot.inboxes.first().cap)
        // The group pair carries LIVE capability material like every other row; a
        // dropped cap here would be a group channel the new phone cannot use.
        assertEquals(migTestCap(5), decoded.snapshot.inboxes[4].cap)
        assertEquals(migTestCap(6), decoded.snapshot.inboxes[5].cap)
    }

    @Test
    fun nullAndEmptyString_stayDistinguishable() {
        val snap = VaultSnapshot(
            contacts = listOf(
                ContactRecord("a", ByteArray(32), 0, "x", 0, vouchedByContactId = null),
                ContactRecord("b", ByteArray(32), 0, "x", 0, vouchedByContactId = ""),
            ),
            inboxes = emptyList(), groups = emptyList(), members = emptyList(), meta = emptyMap(),
        )
        val decoded = MigrationBundleCodec.decode(MigrationBundleCodec.encode(migBundle(snap)))
        assertNull(decoded.snapshot.contacts[0].vouchedByContactId)
        assertEquals("", decoded.snapshot.contacts[1].vouchedByContactId)

        val members = VaultSnapshot(
            emptyList(), emptyList(), emptyList(),
            listOf(
                GroupMemberRecord("g", "m1", null, 1, ""),
                GroupMemberRecord("g", "m2", "", 1, ""),
            ),
            emptyMap(),
        )
        val d2 = MigrationBundleCodec.decode(MigrationBundleCodec.encode(migBundle(members)))
        assertNull(d2.snapshot.members[0].contactId)
        assertEquals("", d2.snapshot.members[1].contactId)
    }

    @Test
    fun emptySnapshot_roundTrips() {
        val empty = VaultSnapshot(emptyList(), emptyList(), emptyList(), emptyList(), emptyMap())
        val decoded = MigrationBundleCodec.decode(MigrationBundleCodec.encode(migBundle(empty)))
        assertTrue(decoded.snapshot.contacts.isEmpty())
        assertTrue(decoded.snapshot.inboxes.isEmpty())
        assertTrue(decoded.snapshot.groups.isEmpty())
        assertTrue(decoded.snapshot.members.isEmpty())
        assertTrue(decoded.snapshot.meta.isEmpty())
    }

    // -----------------------------------------------------------------------
    // `_meta` allowlist / denylist — the whole point of MoveMetaPolicy.
    // -----------------------------------------------------------------------

    @Test
    fun everyAllowedMetaPrefix_survivesTheRoundTrip() {
        val decoded = MigrationBundleCodec.decode(MigrationBundleCodec.encode(migBundle()))
        for ((k, v) in migAllowedMeta) {
            assertEquals(v, decoded.snapshot.meta[k], "allowed meta key '$k' must travel")
        }
        assertEquals(migAllowedMeta.size, decoded.snapshot.meta.size, "no extra meta rows")
    }

    @Test
    fun deniedMetaKeys_neverEnterTheEncodedBundle() {
        val json = MigrationBundleCodec.encodeToString(migBundle())
        for (k in migDeniedMeta.keys) {
            assertFalse(json.contains("\"$k\""), "denied meta key '$k' must not be serialized")
        }
        for (v in migDeniedMeta.values) {
            assertFalse(json.contains(v), "denied meta VALUE for a dropped key leaked into the bundle")
        }
    }

    @Test
    fun deniedMetaKeys_areDroppedOnDecodeToo() {
        // Defence in depth: a bundle built by anything but this build (an older
        // exporter, a tampered-with-but-correctly-sealed bundle) must not be able to
        // plant credential material into the new vault's _meta table.
        val handMade = buildString {
            append("{\"v\":1,\"schema\":8,\"from\":\"ios\",\"created\":1,\"bid\":\"${migTestBundleId(5)}\",")
            append("\"contacts\":[],\"inboxes\":[],\"groups\":[],\"members\":[],\"meta\":{")
            append("\"dr/c1/text\":\"keep-me\"")
            for ((k, v) in migDeniedMeta) append(",${jsonEscapeString(k)}:${jsonEscapeString(v)}")
            append("}}")
        }
        val decoded = MigrationBundleCodec.decodeFromString(handMade)
        assertEquals(mapOf("dr/c1/text" to "keep-me"), decoded.snapshot.meta)
    }

    // -----------------------------------------------------------------------
    // Version / schema
    // -----------------------------------------------------------------------

    @Test
    fun unknownVersion_isRejected() {
        for (v in listOf(0, 2, 99, -1)) {
            val json = MigrationBundleCodec.encodeToString(migBundle()).replaceFirst("\"v\":1", "\"v\":$v")
            assertFailsWith<MigrationBundleCodec.FormatException>("version $v must be rejected") {
                MigrationBundleCodec.decodeFromString(json)
            }
        }
    }

    @Test
    fun missingVersion_isRejected() {
        val json = MigrationBundleCodec.encodeToString(migBundle()).replaceFirst("\"v\":1,", "")
        assertFailsWith<MigrationBundleCodec.FormatException> { MigrationBundleCodec.decodeFromString(json) }
    }

    @Test
    fun newerSchema_isSurfacedNotThrown() {
        // "update Rún on the new phone" is the IMPORTER's decision; the codec must
        // hand it the number rather than making the bundle unreadable.
        val newer = MigrationBundleCodec.CURRENT_SCHEMA + 3
        val decoded = MigrationBundleCodec.decode(MigrationBundleCodec.encode(migBundle(schema = newer)))
        assertEquals(newer, decoded.schema)
        val older = MigrationBundleCodec.decode(MigrationBundleCodec.encode(migBundle(schema = 1)))
        assertEquals(1, older.schema)
    }

    @Test
    fun currentSchema_matchesTheShippedVaultSchema() {
        // Pinned against DatabaseManager.DATABASE_VERSION in MigrationSchemaPinTest
        // (androidUnitTest); this only catches an accidental edit to a nonsense value.
        // 10 is the group-counter migration — going below it would make a bundle
        // claim a schema that predates the columns it carries.
        assertTrue(MigrationBundleCodec.CURRENT_SCHEMA >= 10)
    }

    @Test
    fun aV9Bundle_withNoGroupCounters_importsWithThemAtZero() {
        // The pre-v10 exporter wrote no `outboundGrpCounter`/`inboundGrpCounter`.
        // Such a bundle must still decode — losing it would strand a user mid-move
        // on an older phone — and its contacts must arrive at the establish-on-read
        // baseline, exactly what the v9 → v10 DB migration gives an existing row.
        val json = "{\"v\":1,\"schema\":9,\"from\":\"android\",\"created\":5,\"bid\":\"${migTestBundleId(1)}\"," +
            "\"contacts\":[{\"contactId\":\"c\",\"sharedSecret\":\"${encodeBase64(ByteArray(32))}\"," +
            "\"trustLevel\":1,\"alias\":\"a\",\"aliasLastRotated\":9," +
            "\"outboundCounter\":31,\"inboundCounter\":29,\"inboundEpoch\":\"ep\"," +
            "\"outboundCtlCounter\":11,\"inboundCtlCounter\":10}]," +
            "\"inboxes\":[],\"groups\":[],\"members\":[],\"meta\":{}}"
        val d = MigrationBundleCodec.decodeFromString(json)
        assertEquals(9, d.schema)
        val c = d.snapshot.contacts.single()
        assertEquals(0L, c.outboundGrpCounter, "a v9 bundle must import with the group counter at 0")
        assertEquals(0L, c.inboundGrpCounter)
        // …and the counters it DID carry are untouched by the new fields.
        assertEquals(31L, c.outboundCounter)
        assertEquals(11L, c.outboundCtlCounter)
    }

    @Test
    fun bothPlatformTags_roundTrip() {
        for (from in listOf(MigrationBundle.FROM_ANDROID, MigrationBundle.FROM_IOS)) {
            assertEquals(from, MigrationBundleCodec.decode(MigrationBundleCodec.encode(migBundle(from = from))).from)
        }
    }

    // -----------------------------------------------------------------------
    // Malformed input
    // -----------------------------------------------------------------------

    @Test
    fun malformedDocuments_areRejected() {
        val good = MigrationBundleCodec.encodeToString(migBundle())
        val bad = listOf(
            "",
            "   ",
            "not json at all",
            "[]",
            good.dropLast(1),                                   // truncated
            good.replaceFirst("\"schema\":${MigrationBundleCodec.CURRENT_SCHEMA}", "\"schema\":\"${MigrationBundleCodec.CURRENT_SCHEMA}\""),   // number as string
            good.replaceFirst("\"created\":", "\"created\":+"),      // non-ASCII-strict number
            good.replaceFirst("\"contacts\":[", "\"contacts\":\""),  // array replaced by a string
            good.replaceFirst("\"from\":\"android\"", "\"from\":\"ANDROID!\""),
            good.replaceFirst("\"bid\":\"", "\"bid\":\"x"),          // 17-char bundle id
        )
        for (b in bad) {
            assertFailsWith<MigrationBundleCodec.FormatException>("must reject: ${b.take(40)}") {
                MigrationBundleCodec.decodeFromString(b)
            }
        }
    }

    @Test
    fun nestedObjectInsideARecord_isRejected() {
        val json = MigrationBundleCodec.encodeToString(migBundle())
            .replaceFirst("\"trustLevel\":2", "\"trustLevel\":{\"x\":1}")
        assertFailsWith<MigrationBundleCodec.FormatException> { MigrationBundleCodec.decodeFromString(json) }
    }

    @Test
    fun missingRequiredRecordField_isRejected() {
        val json = MigrationBundleCodec.encodeToString(migBundle())
            .replaceFirst("\"sharedSecret\":", "\"sharedSecretX\":")
        assertFailsWith<MigrationBundleCodec.FormatException> { MigrationBundleCodec.decodeFromString(json) }
    }

    @Test
    fun emptyIdentityField_isRejected() {
        val json = MigrationBundleCodec.encodeToString(migBundle())
            .replaceFirst("\"contactId\":\"c-one\"", "\"contactId\":\"\"")
        assertFailsWith<MigrationBundleCodec.FormatException> { MigrationBundleCodec.decodeFromString(json) }
    }

    @Test
    fun badBase64SharedSecret_isRejected() {
        val json = MigrationBundleCodec.encodeToString(migBundle())
            .replaceFirst("\"sharedSecret\":\"", "\"sharedSecret\":\"!!!")
        assertFailsWith<MigrationBundleCodec.FormatException> { MigrationBundleCodec.decodeFromString(json) }
    }

    @Test
    fun optionalFieldsAbsent_fallBackToTheDataClassDefaults() {
        // A bundle from an older exporter that never wrote the control counters must
        // import with the same defaults the DB migration would have applied.
        val json = "{\"v\":1,\"schema\":7,\"from\":\"ios\",\"created\":5,\"bid\":\"${migTestBundleId(1)}\"," +
            "\"contacts\":[{\"contactId\":\"c\",\"sharedSecret\":\"${encodeBase64(ByteArray(32))}\"," +
            "\"trustLevel\":1,\"alias\":\"a\",\"aliasLastRotated\":9}]," +
            "\"inboxes\":[{\"inboxId\":\"${migTestInboxId(1)}\",\"contactId\":\"c\",\"createdAt\":1," +
            "\"expiresAt\":2,\"direction\":\"inbound\"}]," +
            "\"groups\":[],\"members\":[],\"meta\":{}}"
        val d = MigrationBundleCodec.decodeFromString(json)
        val c = d.snapshot.contacts.single()
        assertEquals("", c.mnemonic)
        assertEquals(0L, c.outboundCounter)
        assertEquals(0L, c.inboundCtlCounter)
        assertEquals(0L, c.outboundGrpCounter)
        assertEquals(0L, c.inboundGrpCounter)
        assertEquals("", c.inboundEpoch)
        assertNull(c.vouchedByContactId)
        assertEquals(0L, c.vouchedAt)
        assertNull(d.snapshot.inboxes.single().cap)
    }

    @Test
    fun unknownTopLevelFields_areIgnored_forwardCompat() {
        val json = MigrationBundleCodec.encodeToString(migBundle())
            .replaceFirst("{\"v\":1", "{\"future\":{\"a\":[1,2,{\"b\":\"c\"}]},\"v\":1")
        val decoded = MigrationBundleCodec.decodeFromString(json)
        assertEquals(3, decoded.snapshot.contacts.size)
    }

    @Test
    fun encodeRefusesANonCurrentVersion() {
        assertFailsWith<MigrationBundleCodec.FormatException> {
            MigrationBundleCodec.encodeToString(migBundle().copy(version = 2))
        }
    }

    @Test
    fun encodeRefusesAnInvalidBundleId() {
        assertFailsWith<MigrationBundleCodec.FormatException> {
            MigrationBundleCodec.encodeToString(migBundle().copy(bundleId = "short"))
        }
    }

    @Test
    fun duplicateKeysInARecord_keepTheFirstOccurrence() {
        // A later duplicate must never be able to override an earlier field — the same
        // rule parseTopLevelJson enforces for the message envelope.
        val json = MigrationBundleCodec.encodeToString(migBundle())
            .replaceFirst("\"trustLevel\":2", "\"trustLevel\":2,\"trustLevel\":9")
        assertEquals(2, MigrationBundleCodec.decodeFromString(json).snapshot.contacts.first().trustLevel)
    }
}
