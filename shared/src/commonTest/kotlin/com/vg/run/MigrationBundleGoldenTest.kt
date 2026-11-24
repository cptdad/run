package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

// ---------------------------------------------------------------------------
// RÚN-04 part (b): the device-move bundle's WIRE FORMAT, pinned byte for byte.
//
// MigrationBundleGoldenData was generated from the String-based codec as it shipped
// (0550f276) BEFORE the byte-oriented rewrite, and this test passed against that
// codec unmodified. Every assertion here is therefore "the codec still does exactly
// what the shipped one did":
//
//   - encode(fixture) == the pinned bytes          → an older importer sees identical bytes
//   - decode(pinned bytes) == the pinned model      → a bundle an older exporter wrote still imports
//   - decode(hand-made / historic documents) gives the pinned model or the pinned
//     FormatException message (schema 7/8/9 layouts, whitespace, duplicates,
//     unknown fields, escapes, malformed input)
//   - the record and meta-row limits sit exactly where they were
//
// Each case is also run through LegacyMigrationBundleCodec (the frozen reference),
// so a drift of the pinned data from the reference is visible too.
//
// Runs on the JVM (testDebugUnitTest) AND Kotlin/Native (iosSimulatorArm64Test):
// String ⇄ UTF-8 conversion differs between them for malformed text (D4), and the
// lone-surrogate case is pinned per platform.
// ---------------------------------------------------------------------------
class MigrationBundleGoldenTest {

    @Test
    fun everyGoldenBundle_encodesToThePinnedBytes() {
        val bundles = migGoldenBundles()
        assertEquals(MigrationBundleGoldenData.ENCODED_HEX.keys, bundles.keys, "fixture list and pinned data drifted")
        for ((name, b) in bundles) {
            val pinned = MigrationBundleGoldenData.ENCODED_HEX.getValue(name)
            assertEquals(pinned, migFixHex(MigrationBundleCodec.encode(b)), "encode($name) changed the wire bytes")
            assertEquals(pinned, migFixHex(LegacyMigrationBundleCodec.encode(b)), "reference encode($name) != pinned")
        }
    }

    @Test
    fun everyPinnedEncoding_decodesToThePinnedModel() {
        for ((name, hex) in MigrationBundleGoldenData.ENCODED_HEX) {
            val pinned = MigrationBundleGoldenData.ENCODED_DECODE_OUTCOMES.getValue(name)
            assertEquals(pinned, migOutcome { MigrationBundleCodec.decode(migFixUnhex(hex)) }, "decode($name)")
            assertEquals(pinned, migOutcome { LegacyMigrationBundleCodec.decode(migFixUnhex(hex)) }, "reference decode($name)")
        }
    }

    @Test
    fun theDecodablePinnedEncodings_areExactlyTheirSourceBundle() {
        // Ties the pinned outcome to MEANING: the decode is the source bundle minus the
        // denied `_meta` rows — except the two shapes this codec encodes but refuses.
        val refused = setOf("empty_identity", "long_min_value")
        for ((name, b) in migGoldenBundles()) {
            val pinned = MigrationBundleGoldenData.ENCODED_DECODE_OUTCOMES.getValue(name)
            if (name in refused) {
                assertTrue(pinned.startsWith("ERR:FormatException:"), "$name: $pinned")
            } else {
                assertEquals(renderMigBundle(migExpectedAfterDecode(b)), pinned, "$name does not round-trip")
            }
        }
    }

    @Test
    fun theLargeBundles_encodeToThePinnedDigest() {
        val all = LinkedHashMap(migDigestBundles())
        all["large_near_limit"] = migLargeBundle()
        assertEquals(MigrationBundleGoldenData.ENCODED_DIGESTS.keys, all.keys)
        for ((name, b) in all) {
            val (len, sha) = MigrationBundleGoldenData.ENCODED_DIGESTS.getValue(name)
            val bytes = MigrationBundleCodec.encode(b)
            assertEquals(len, bytes.size, "encode($name) length")
            assertEquals(sha, migFixHex(sha256(bytes)), "encode($name) bytes")
            val ref = LegacyMigrationBundleCodec.encode(b)
            assertEquals(sha, migFixHex(sha256(ref)), "reference encode($name) bytes")
        }
    }

    @Test
    fun theLargeBundle_isNearTheSealLimit_withEveryArrayAtMaxRecords_andDecodesToThePinnedModel() {
        val b = migLargeBundle()
        val bytes = MigrationBundleCodec.encode(b)
        assertTrue(bytes.size <= MigrationSeal.MAX_PLAINTEXT_BYTES, "must still fit the seal")
        assertTrue(bytes.size >= MigrationSeal.MAX_PLAINTEXT_BYTES - 200_000, "must be near the seal limit: ${bytes.size}")
        assertEquals(MIG_LARGE_RECORDS, b.snapshot.contacts.size)
        assertEquals(MIG_LARGE_RECORDS, b.snapshot.inboxes.size)
        assertEquals(MIG_LARGE_RECORDS, b.snapshot.groups.size)
        assertEquals(MIG_LARGE_RECORDS, b.snapshot.members.size)

        val render = migOutcome { MigrationBundleCodec.decode(bytes) }
        assertEquals(MigrationBundleGoldenData.LARGE_DECODE_RENDER_SHA256, migFixHex(sha256(render.encodeToByteArray())))
        assertEquals(renderMigBundle(b), render, "the large bundle must round-trip")
        val ref = migOutcome { LegacyMigrationBundleCodec.decode(bytes) }
        assertEquals(render, ref, "reference decode of the large bundle")

        val long = MigrationBundleCodec.encode(migDigestBundles().getValue("long_fields"))
        val longRender = migOutcome { MigrationBundleCodec.decode(long) }
        assertEquals(MigrationBundleGoldenData.LONG_FIELDS_DECODE_RENDER_SHA256, migFixHex(sha256(longRender.encodeToByteArray())))
    }

    @Test
    fun loneSurrogates_keepThisPlatformsReplacement() {
        // D4: not normalised. The JVM writes '?' per lone surrogate, Kotlin/Native EF BF BD.
        val jvm = migPlatformWritesQuestionMarkForLoneSurrogate()
        val pinnedHex = if (jvm) MigrationBundleGoldenData.LONE_SURROGATE_HEX_JVM else MigrationBundleGoldenData.LONE_SURROGATE_HEX_NATIVE
        val pinnedDecode = if (jvm) MigrationBundleGoldenData.LONE_SURROGATE_DECODE_JVM else MigrationBundleGoldenData.LONE_SURROGATE_DECODE_NATIVE
        val b = migLoneSurrogateBundle()
        assertEquals(pinnedHex, migFixHex(MigrationBundleCodec.encode(b)))
        assertEquals(pinnedHex, migFixHex(LegacyMigrationBundleCodec.encode(b)))
        assertEquals(pinnedDecode, migOutcome { MigrationBundleCodec.decode(migFixUnhex(pinnedHex)) })
        assertEquals(pinnedDecode, migOutcome { LegacyMigrationBundleCodec.decode(migFixUnhex(pinnedHex)) })
        // Bytes the OTHER platform writes still decode the way this platform always decoded them.
        for (hex in listOf(MigrationBundleGoldenData.LONE_SURROGATE_HEX_JVM, MigrationBundleGoldenData.LONE_SURROGATE_HEX_NATIVE)) {
            assertEquals(
                migOutcome { LegacyMigrationBundleCodec.decode(migFixUnhex(hex)) },
                migOutcome { MigrationBundleCodec.decode(migFixUnhex(hex)) },
            )
        }
    }

    @Test
    fun everyHandMadeDocument_decodesToThePinnedOutcome() {
        val docs = migDecodeDocuments()
        assertEquals(MigrationBundleGoldenData.DECODE_OUTCOMES.keys, docs.keys, "document list and pinned data drifted")
        val failures = ArrayList<String>()
        for ((name, text) in docs) {
            val pinned = MigrationBundleGoldenData.DECODE_OUTCOMES.getValue(name)
            val bytes = text.encodeToByteArray()
            val now = migOutcome { MigrationBundleCodec.decode(bytes) }
            val ref = migOutcome { LegacyMigrationBundleCodec.decode(bytes) }
            if (now != pinned) failures += "$name: decode=$now pinned=$pinned"
            if (ref != pinned) failures += "$name: reference=$ref pinned=$pinned"
        }
        if (failures.isNotEmpty()) fail(failures.joinToString("\n"))
    }

    @Test
    fun rawByteDocuments_decodeExactlyLikeTheReferenceOnThisPlatform() {
        // Invalid UTF-8 / encoded surrogates / truncated sequences inside strings, between
        // tokens, in unknown scalars and structures, at the end. The outcome is platform
        // specific (D4), so the reference on THIS platform is the expectation.
        val failures = ArrayList<String>()
        for ((name, bytes) in migRawByteDocuments()) {
            val now = migOutcome { MigrationBundleCodec.decode(bytes) }
            val ref = migOutcome { LegacyMigrationBundleCodec.decode(bytes) }
            if (now != ref) failures += "$name: decode=$now reference=$ref"
        }
        if (failures.isNotEmpty()) fail(failures.joinToString("\n"))
    }

    // -----------------------------------------------------------------------
    // Limits: MAX_RECORDS (8192) per array and MAX_META_ROWS (200 000), encode and decode.
    // -----------------------------------------------------------------------

    private fun limitBundle(contacts: Int = 0, inboxes: Int = 0, groups: Int = 0, members: Int = 0, meta: Int = 0) = MigrationBundle(
        schema = 10, from = "android", createdMs = 1, bundleId = MIG_FIX_BID,
        snapshot = VaultSnapshot(
            contacts = List(contacts) { ContactRecord("c$it", ByteArray(32), 0, "", 0) },
            inboxes = List(inboxes) { InboxIdRecord("i$it", "c", 1, 2, "inbound", null) },
            groups = List(groups) { GroupRecord("g$it", "", 0, "a", "b", 0) },
            members = List(members) { GroupMemberRecord("g", "m$it", null, 0, "") },
            meta = LinkedHashMap<String, String>().also { m -> for (i in 0 until meta) m["dr/$i/text"] = "v" },
        ),
    )

    @Test
    fun recordLimits_sitExactlyAt8192_onEncodeAndDecode() {
        for (shape in listOf("contacts", "inboxes", "groups", "members")) {
            fun of(n: Int) = when (shape) {
                "contacts" -> limitBundle(contacts = n)
                "inboxes" -> limitBundle(inboxes = n)
                "groups" -> limitBundle(groups = n)
                else -> limitBundle(members = n)
            }
            val atLimit = MigrationBundleCodec.encode(of(8192))
            assertEquals(migFixHex(LegacyMigrationBundleCodec.encode(of(8192))), migFixHex(atLimit), shape)
            assertEquals(renderMigBundle(of(8192)), migOutcome { MigrationBundleCodec.decode(atLimit) }, "$shape: 8192 must decode")

            assertEquals("ERR:FormatException:too many records to encode", migEncodeOutcome { MigrationBundleCodec.encode(of(8193)) })
            assertEquals("ERR:FormatException:too many records to encode", migEncodeOutcome { LegacyMigrationBundleCodec.encode(of(8193)) })

            // 8193 elements on the wire (an encoder without the cap): refused as malformed.
            val text = atLimit.decodeToString()
            val open = "\"$shape\":["
            val start = text.indexOf(open) + open.length
            val firstEnd = text.indexOf('}', start) + 1
            val over = (text.substring(0, start) + text.substring(start, firstEnd) + "," + text.substring(start)).encodeToByteArray()
            assertEquals("ERR:FormatException:malformed bundle JSON", migOutcome { MigrationBundleCodec.decode(over) }, "$shape: 8193 on decode")
            assertEquals("ERR:FormatException:malformed bundle JSON", migOutcome { LegacyMigrationBundleCodec.decode(over) })
        }
    }

    @Test
    fun metaRowLimit_sitsExactlyAt200000_onEncodeAndDecode() {
        val atLimit = MigrationBundleCodec.encode(limitBundle(meta = 200_000))
        assertEquals(migFixHex(sha256(LegacyMigrationBundleCodec.encode(limitBundle(meta = 200_000)))), migFixHex(sha256(atLimit)))
        assertEquals(200_000, MigrationBundleCodec.decode(atLimit).snapshot.meta.size)

        assertEquals("ERR:FormatException:too many meta rows to encode", migEncodeOutcome { MigrationBundleCodec.encode(limitBundle(meta = 200_001)) })
        assertEquals("ERR:FormatException:too many meta rows to encode", migEncodeOutcome { LegacyMigrationBundleCodec.encode(limitBundle(meta = 200_001)) })

        val text = atLimit.decodeToString()
        val over = (text.dropLast(2) + ",\"dr/x/text\":\"v\"}}").encodeToByteArray()
        assertEquals("ERR:FormatException:malformed bundle JSON", migOutcome { MigrationBundleCodec.decode(over) })
        assertEquals("ERR:FormatException:malformed bundle JSON", migOutcome { LegacyMigrationBundleCodec.decode(over) })
        // A duplicate key does not count toward the limit (first wins, nothing added).
        val dup = (text.dropLast(2) + ",\"dr/0/text\":\"w\"}}").encodeToByteArray()
        assertEquals(200_000, MigrationBundleCodec.decode(dup).snapshot.meta.size)
        assertEquals("v", MigrationBundleCodec.decode(dup).snapshot.meta["dr/0/text"])
    }

    @Test
    fun encoderRefusals_areUnchanged() {
        val good = limitBundle(contacts = 1)
        val cases = linkedMapOf(
            "version" to good.copy(version = 2),
            "from_empty" to good.copy(from = ""),
            "from_upper" to good.copy(from = "Android"),
            "from_17" to good.copy(from = "abcdefghijklmnopq"),
            "bid" to good.copy(bundleId = "short"),
            "v3_needs_11" to good.copy(snapshot = good.snapshot.copy(
                contacts = listOf(ContactRecord("c", ByteArray(32), 0, "", 0, ratchetBootstrapV3 = true)),
                meta = mapOf("dr/c/text" to "s"))),
            "v3_without_state" to good.copy(schema = 11, snapshot = good.snapshot.copy(
                contacts = listOf(ContactRecord("c", ByteArray(32), 0, "", 0, ratchetBootstrapV3 = true)))),
            "ref_bv_needs_11" to good.copy(snapshot = good.snapshot.copy(meta = mapOf("ref_p:x" to "{\"bv\":\"3\"}"))),
        )
        val expected = linkedMapOf(
            "version" to "ERR:FormatException:refusing to encode bundle version 2",
            "from_empty" to "ERR:FormatException:invalid 'from' tag",
            "from_upper" to "ERR:FormatException:invalid 'from' tag",
            "from_17" to "ERR:FormatException:invalid 'from' tag",
            "bid" to "ERR:FormatException:invalid bundleId",
            "v3_needs_11" to "ERR:FormatException:a v3 contact or a v3 introduction needs bundle schema 11",
            "v3_without_state" to "ERR:FormatException:a v3 contact without its ratchet state",
            "ref_bv_needs_11" to "ERR:FormatException:a v3 contact or a v3 introduction needs bundle schema 11",
        )
        for ((name, b) in cases) {
            assertEquals(expected.getValue(name), migEncodeOutcome { MigrationBundleCodec.encode(b) }, name)
            assertEquals(expected.getValue(name), migEncodeOutcome { LegacyMigrationBundleCodec.encode(b) }, "reference $name")
        }
    }
}
