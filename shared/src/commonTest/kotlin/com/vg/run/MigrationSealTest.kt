package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// MigrationSeal — the transfer's confidentiality AND its integrity.
//
// The relay holds every chunk of a user's whole identity for 30 minutes. It can
// reorder, drop, duplicate, truncate or splice blobs at will, and nothing in the
// transport carries a plaintext header it could not also rewrite. The ONLY thing
// standing between that and a silently-wrong import is the AEAD binding of
// (inboxId, bundleId, index, count) — so every one of those manipulations is
// pinned here as a hard failure, not a "returns something odd".
// ---------------------------------------------------------------------------
class MigrationSealTest {

    private val inbox = migTestInboxId(21)
    private val otherInbox = migTestInboxId(22)
    private val bid = migTestBundleId(23)
    private val otherBid = migTestBundleId(24)

    private fun code(seed: Int) = ByteArray(MoveConstants.CODE_BYTES) { (it * 5 + seed).toByte() }

    // -----------------------------------------------------------------------
    // Round trip + wire shape
    // -----------------------------------------------------------------------

    @Test
    fun oneChunk_roundTrips() {
        val c = code(1)
        val pt = "the whole bundle fits in one chunk".encodeToByteArray()
        val chunks = MigrationSeal.seal(pt, c, inbox, bid)
        assertEquals(1, chunks.size)
        assertTrue(MigrationSeal.open(chunks, c, inbox, bid).contentEquals(pt))
    }

    @Test
    fun threeChunks_roundTrip() {
        val c = code(2)
        // 2 × CHUNK_PLAINTEXT_BYTES of payload + the 4-byte length prefix ⇒ 3 chunks.
        val pt = ByteArray(2 * MoveConstants.CHUNK_PLAINTEXT_BYTES) { (it % 251).toByte() }
        val chunks = MigrationSeal.seal(pt, c, inbox, bid)
        assertEquals(3, chunks.size)
        assertTrue(MigrationSeal.open(chunks, c, inbox, bid).contentEquals(pt))
    }

    @Test
    fun emptyPlaintext_roundTrips() {
        val c = code(3)
        val chunks = MigrationSeal.seal(ByteArray(0), c, inbox, bid)
        assertEquals(1, chunks.size)
        assertEquals(0, MigrationSeal.open(chunks, c, inbox, bid).size)
    }

    @Test
    fun everyChunkIsTheSameSizeAndFitsTheRelayBlobLimit() {
        val c = code(4)
        // A deliberately ragged payload: the LAST chunk must still be full-size
        // (random-padded), or the chunk count would leak the exact bundle length.
        val pt = ByteArray(MoveConstants.CHUNK_PLAINTEXT_BYTES + 7) { 42 }
        val chunks = MigrationSeal.seal(pt, c, inbox, bid)
        assertEquals(2, chunks.size)
        for (ch in chunks) {
            assertEquals(MigrationSeal.SEALED_CHUNK_BYTES, ch.size, "every chunk must be the same fixed size")
        }
        // The number this whole design hangs on: 12 (IV) + 60 000 + 16 (tag).
        assertEquals(60_028, MigrationSeal.SEALED_CHUNK_BYTES)
        assertTrue(MigrationSeal.SEALED_CHUNK_BYTES <= 65_536, "must fit the relay's 64 KiB maxBlobBytes")
    }

    @Test
    fun chunksOfTheSamePlaintextDifferEveryTime() {
        // Fresh 12-byte IV per chunk (the platform AEAD prepends one), so an observer
        // cannot tell that A re-issued the SAME bundle after a process death.
        val c = code(5)
        val pt = ByteArray(1000) { 7 }
        val a = MigrationSeal.seal(pt, c, inbox, bid).single()
        val b = MigrationSeal.seal(pt, c, inbox, bid).single()
        assertNotEquals(a.toList(), b.toList())
    }

    // -----------------------------------------------------------------------
    // Every relay-side manipulation must fail
    // -----------------------------------------------------------------------

    @Test
    fun wrongCode_fails() {
        val chunks = MigrationSeal.seal("secret".encodeToByteArray(), code(6), inbox, bid)
        assertFailsWith<MigrationSeal.SealException> { MigrationSeal.open(chunks, code(7), inbox, bid) }
    }

    @Test
    fun oneBitOffInTheCode_fails() {
        val good = code(8)
        val chunks = MigrationSeal.seal("secret".encodeToByteArray(), good, inbox, bid)
        val nearly = good.copyOf().also { it[19] = (it[19].toInt() xor 1).toByte() }
        assertFailsWith<MigrationSeal.SealException> { MigrationSeal.open(chunks, nearly, inbox, bid) }
    }

    @Test
    fun swappedChunkOrder_fails() {
        val c = code(9)
        val pt = ByteArray(2 * MoveConstants.CHUNK_PLAINTEXT_BYTES) { (it % 97).toByte() }
        val chunks = MigrationSeal.seal(pt, c, inbox, bid).toMutableList()
        assertEquals(3, chunks.size)
        val tmp = chunks[0]; chunks[0] = chunks[2]; chunks[2] = tmp
        assertFailsWith<MigrationSeal.SealException> { MigrationSeal.open(chunks, c, inbox, bid) }
    }

    @Test
    fun droppedChunk_fails() {
        val c = code(10)
        val pt = ByteArray(2 * MoveConstants.CHUNK_PLAINTEXT_BYTES) { 3 }
        val chunks = MigrationSeal.seal(pt, c, inbox, bid)
        // count is AAD, so 2-of-3 cannot authenticate even though each blob is intact.
        assertFailsWith<MigrationSeal.SealException> { MigrationSeal.open(chunks.dropLast(1), c, inbox, bid) }
        assertFailsWith<MigrationSeal.SealException> { MigrationSeal.open(chunks.drop(1), c, inbox, bid) }
    }

    @Test
    fun duplicatedChunk_fails() {
        val c = code(11)
        val pt = ByteArray(MoveConstants.CHUNK_PLAINTEXT_BYTES) { 5 }
        val chunks = MigrationSeal.seal(pt, c, inbox, bid)
        assertEquals(2, chunks.size)
        assertFailsWith<MigrationSeal.SealException> {
            MigrationSeal.open(listOf(chunks[0], chunks[0]), c, inbox, bid)
        }
    }

    @Test
    fun differentInboxId_fails() {
        // Binds the bundle to the transfer inbox: both the HKDF salt and the AAD change.
        val c = code(12)
        val chunks = MigrationSeal.seal("x".encodeToByteArray(), c, inbox, bid)
        assertFailsWith<MigrationSeal.SealException> { MigrationSeal.open(chunks, c, otherInbox, bid) }
    }

    @Test
    fun differentBundleId_fails() {
        // Defeats splicing a chunk from an earlier re-issued bundle into this one.
        val c = code(13)
        val chunks = MigrationSeal.seal("x".encodeToByteArray(), c, inbox, bid)
        assertFailsWith<MigrationSeal.SealException> { MigrationSeal.open(chunks, c, inbox, otherBid) }
    }

    @Test
    fun splicedChunkFromAnotherBundle_fails() {
        val c = code(14)
        val pt = ByteArray(MoveConstants.CHUNK_PLAINTEXT_BYTES) { 1 }
        val mine = MigrationSeal.seal(pt, c, inbox, bid)
        val theirs = MigrationSeal.seal(pt, c, inbox, otherBid)
        assertFailsWith<MigrationSeal.SealException> {
            MigrationSeal.open(listOf(mine[0], theirs[1]), c, inbox, bid)
        }
    }

    @Test
    fun flippedCiphertextBit_fails() {
        val c = code(15)
        val chunks = MigrationSeal.seal("payload".encodeToByteArray(), c, inbox, bid).toMutableList()
        val tampered = chunks[0].copyOf()
        tampered[tampered.size - 1] = (tampered[tampered.size - 1].toInt() xor 0x01).toByte()
        assertFailsWith<MigrationSeal.SealException> { MigrationSeal.open(listOf(tampered), c, inbox, bid) }
    }

    @Test
    fun mixedChunkSizes_areRejectedBeforeAnyDecrypt() {
        val c = code(16)
        val pt = ByteArray(MoveConstants.CHUNK_PLAINTEXT_BYTES) { 2 }
        val chunks = MigrationSeal.seal(pt, c, inbox, bid)
        val ragged = listOf(chunks[0], chunks[1].copyOfRange(0, chunks[1].size - 1))
        assertFailsWith<MigrationSeal.SealException> { MigrationSeal.open(ragged, c, inbox, bid) }
    }

    @Test
    fun noChunks_isRejected() {
        assertFailsWith<MigrationSeal.SealException> { MigrationSeal.open(emptyList(), code(17), inbox, bid) }
    }

    @Test
    fun implausibleChunkSize_isRejected() {
        val c = code(18)
        // Too short to even hold IV+tag, and (separately) larger than a real chunk.
        assertFailsWith<MigrationSeal.SealException> { MigrationSeal.open(listOf(ByteArray(20)), c, inbox, bid) }
        assertFailsWith<MigrationSeal.SealException> {
            MigrationSeal.open(listOf(ByteArray(MigrationSeal.SEALED_CHUNK_BYTES + 1)), c, inbox, bid)
        }
    }

    @Test
    fun tooManyChunksOnOpen_isRejected() {
        val c = code(19)
        val one = MigrationSeal.seal("x".encodeToByteArray(), c, inbox, bid).single()
        val flood = List(MoveConstants.MAX_CHUNKS + 1) { one }
        assertFailsWith<MigrationSeal.SealException> { MigrationSeal.open(flood, c, inbox, bid) }
    }

    @Test
    fun malformedInputsToSeal_areRejected() {
        val c = code(20)
        assertFailsWith<MigrationSeal.SealException> { MigrationSeal.seal(ByteArray(1), ByteArray(19), inbox, bid) }
        assertFailsWith<MigrationSeal.SealException> { MigrationSeal.seal(ByteArray(1), c, "short-inbox", bid) }
        assertFailsWith<MigrationSeal.SealException> { MigrationSeal.seal(ByteArray(1), c, inbox, "nope") }
    }

    // -----------------------------------------------------------------------
    // Size cap
    // -----------------------------------------------------------------------

    @Test
    fun aboveMaxChunks_throwsTooLarge() {
        val c = code(21)
        // One byte more than MAX_CHUNKS chunks can hold (the 4-byte prefix counts).
        val tooBig = ByteArray(MigrationSeal.MAX_PLAINTEXT_BYTES + 1)
        assertFailsWith<MigrationSeal.TooLargeException> { MigrationSeal.seal(tooBig, c, inbox, bid) }
    }

    @Test
    fun exactlyMaxChunks_sealsAndOpens() {
        val c = code(22)
        val pt = ByteArray(MigrationSeal.MAX_PLAINTEXT_BYTES) { (it % 253).toByte() }
        val chunks = MigrationSeal.seal(pt, c, inbox, bid)
        assertEquals(MoveConstants.MAX_CHUNKS, chunks.size)
        for (ch in chunks) assertEquals(MigrationSeal.SEALED_CHUNK_BYTES, ch.size)
        assertTrue(MigrationSeal.open(chunks, c, inbox, bid).contentEquals(pt))
    }

    // -----------------------------------------------------------------------
    // Code handling + hygiene
    // -----------------------------------------------------------------------

    @Test
    fun newCode_is160BitsAndFresh() {
        val a = MigrationSeal.newCode()
        val b = MigrationSeal.newCode()
        assertEquals(20, a.size)
        assertEquals(MoveConstants.CODE_BYTES, a.size)
        assertNotEquals(a.toList(), b.toList())
    }

    @Test
    fun encodeCode_isExactly32Symbols() {
        val text = MigrationSeal.encodeCode(MigrationSeal.newCode())
        assertEquals(MigrationSeal.CODE_SYMBOLS, text.length)
        assertTrue(text.all { it in '0'..'9' || it in 'A'..'Z' })
    }

    @Test
    fun decodeCode_normalisesCaseGroupingAndLookAlikes() {
        val raw = MigrationSeal.newCode()
        val canonical = MigrationSeal.encodeCode(raw)
        val variants = listOf(
            canonical,
            canonical.lowercase(),
            Base32.formatGrouped(canonical, 4, "-"),
            "  " + Base32.formatGrouped(canonical.lowercase(), 8, " ") + "  ",
        )
        for (v in variants) {
            val decoded = MigrationSeal.decodeCode(v)
            assertTrue(decoded != null && decoded.contentEquals(raw), "variant failed to normalise: $v")
        }
        // Crockford look-alikes fold back to the canonical symbol.
        val folded = MigrationSeal.decodeCode(canonical.replace('0', 'O').replace('1', 'L'))
        assertTrue(folded != null && folded.contentEquals(raw))
    }

    @Test
    fun decodeCode_rejectsWrongLengthAndBadSymbols() {
        val canonical = MigrationSeal.encodeCode(MigrationSeal.newCode())
        assertNull(MigrationSeal.decodeCode(canonical.dropLast(1)), "31 symbols must fail closed")
        // 33 symbols still decode to 20 bytes in Base32 — the SYMBOL COUNT is the check.
        assertNull(MigrationSeal.decodeCode(canonical + "Z"), "33 symbols must fail closed")
        assertNull(MigrationSeal.decodeCode(canonical.dropLast(1) + "U"), "U is not a Crockford symbol")
        assertNull(MigrationSeal.decodeCode(""))
    }

    @Test
    fun sealAndOpen_doNotWipeTheCallersCode() {
        // The QR screen still needs the code after seal(), and a failed open must be
        // retryable; only our own defensive copies are wiped.
        val c = MigrationSeal.newCode()
        val snapshot = c.copyOf()
        val chunks = MigrationSeal.seal("x".encodeToByteArray(), c, inbox, bid)
        assertTrue(c.contentEquals(snapshot), "seal must not wipe the caller's code")
        MigrationSeal.open(chunks, c, inbox, bid)
        assertTrue(c.contentEquals(snapshot), "open must not wipe the caller's code")
    }

    @Test
    fun sealedChunksLookNothingLikeThePlaintext() {
        val c = MigrationSeal.newCode()
        val marker = "SHARED-SECRET-MARKER-9137"
        val chunks = MigrationSeal.seal(marker.encodeToByteArray(), c, inbox, bid)
        val asText = chunks.single().decodeToString()
        assertTrue(!asText.contains(marker))
    }

    // -----------------------------------------------------------------------
    // End to end with the real bundle codec
    // -----------------------------------------------------------------------

    @Test
    fun bundleSurvivesEncodeSealOpenDecode() {
        val c = MigrationSeal.newCode()
        val bundle = migBundle()
        val chunks = MigrationSeal.seal(MigrationBundleCodec.encode(bundle), c, inbox, bundle.bundleId)
        val decoded = MigrationBundleCodec.decode(MigrationSeal.open(chunks, c, inbox, bundle.bundleId))
        assertEquals(bundle.snapshot.contacts.size, decoded.snapshot.contacts.size)
        assertEquals(bundle.snapshot.inboxes, decoded.snapshot.inboxes)
        assertEquals(migAllowedMeta.size, decoded.snapshot.meta.size)
        assertTrue(
            bundle.snapshot.contacts[0].sharedSecret.contentEquals(decoded.snapshot.contacts[0].sharedSecret)
        )
    }
}
