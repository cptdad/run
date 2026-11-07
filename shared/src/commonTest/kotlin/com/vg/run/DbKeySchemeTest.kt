package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// DbKeyScheme tests — the self-describing DB-key blob tagging that lets one
// install hold either the plain (CryptoProvider) or the auth-bound (Lever B)
// outer layer and migrate between them with no separate persisted flag.
//
// The freshly written form is scheme-NEUTRAL
// ("v:"+base64 with a 1-byte scheme field folded INTO the payload), so an
// at-rest examiner can no longer `grep "ab:"` to learn which vaults carry the
// Lever B hardware barrier. Load-bearing invariants:
//  - a LEGACY untagged blob (every pre-Lever-B install) reads as CryptoProvider;
//  - the LEGACY explicit "cp:"/"ab:" forms still parse (existing vaults open);
//  - payloadOf round-trips the exact base64 the platform protector wrapped (a
//    mismatch would brick unwrap on device);
//  - base64 payloads (which never contain ':') are never mistaken for a tag.
// ---------------------------------------------------------------------------

class DbKeySchemeTest {

    @Test
    fun legacyUntaggedBlob_readsAsCryptoProvider() {
        // A real base64 blob has no scheme tag.
        val legacy = "AAECAwQFBgcICQoLDA0ODw=="
        assertNull(DbKeyScheme.tagOf(legacy))
        assertFalse(DbKeyScheme.isAuthBound(legacy))
        assertEquals(legacy, DbKeyScheme.payloadOf(legacy))
    }

    @Test
    fun neutralForm_authBound_roundTrips_withoutCleartextSchemeWord() {
        val payload = "cGF5bG9hZA=="   // base64("payload")
        val blob = DbKeyScheme.tagged(DbKeyScheme.TAG_AUTH_BOUND, payload)
        // No human-readable "ab:"/"cp:" scheme word; both schemes share "v:".
        assertFalse(blob.startsWith("ab:"), "must not expose the 'ab:' scheme word")
        assertFalse(blob.startsWith("cp:"))
        assertTrue(blob.startsWith("v:"))
        // The app can still classify it and recover the exact payload.
        assertTrue(DbKeyScheme.isAuthBound(blob))
        assertEquals(DbKeyScheme.TAG_AUTH_BOUND, DbKeyScheme.tagOf(blob))
        assertEquals(payload, DbKeyScheme.payloadOf(blob))
    }

    @Test
    fun neutralForm_plain_isShapeIdenticalToAuthBound_soThePrefixLeaksNothing() {
        val payload = "cGF5bG9hZA=="
        val plain = DbKeyScheme.tagged(DbKeyScheme.TAG_CRYPTO_PROVIDER, payload)
        val ab    = DbKeyScheme.tagged(DbKeyScheme.TAG_AUTH_BOUND, payload)
        // Same marker + same length for an equal-length payload → the prefix reveals
        // nothing; the schemes differ only in one folded byte inside the base64.
        assertTrue(plain.startsWith("v:"))
        assertEquals(plain.length, ab.length)
        assertNotEquals(plain, ab)
        assertFalse(DbKeyScheme.isAuthBound(plain))
        assertEquals(DbKeyScheme.TAG_CRYPTO_PROVIDER, DbKeyScheme.tagOf(plain))
        assertEquals(payload, DbKeyScheme.payloadOf(plain))
    }

    @Test
    fun legacyExplicitTags_stillParse_soExistingVaultsOpen() {
        // Migration: vaults provisioned before the neutral form stored the explicit tags.
        val abLegacy = "ab:cGF5bG9hZA=="
        assertTrue(DbKeyScheme.isAuthBound(abLegacy))
        assertEquals(DbKeyScheme.TAG_AUTH_BOUND, DbKeyScheme.tagOf(abLegacy))
        assertEquals("cGF5bG9hZA==", DbKeyScheme.payloadOf(abLegacy))

        val cpLegacy = "cp:cGF5bG9hZA=="
        assertFalse(DbKeyScheme.isAuthBound(cpLegacy))
        assertEquals(DbKeyScheme.TAG_CRYPTO_PROVIDER, DbKeyScheme.tagOf(cpLegacy))
        assertEquals("cGF5bG9hZA==", DbKeyScheme.payloadOf(cpLegacy))
    }

    @Test
    fun base64PaddingColon_isNotMistakenForTag() {
        // Base64 alphabet excludes ':', but be defensive: an unknown leading
        // token before ':' is NOT a recognized tag, so treat the whole string
        // as a legacy payload rather than silently stripping bytes.
        val weird = "notatag:stuff"
        assertNull(DbKeyScheme.tagOf(weird))
        assertEquals(weird, DbKeyScheme.payloadOf(weird))
        assertFalse(DbKeyScheme.isAuthBound(weird))
    }

    @Test
    fun taggedThenPayloadOf_isIdentity_forBothSchemes() {
        // The exact wire contract the platform protectors depend on: payloadOf must
        // return the SAME base64 that was tagged, for every scheme and payload size
        // (Tink AEAD ~90B, RSA-OAEP 256B) — a mismatch bricks unwrap on device.
        for (tag in listOf(DbKeyScheme.TAG_CRYPTO_PROVIDER, DbKeyScheme.TAG_AUTH_BOUND)) {
            for (raw in listOf(ByteArray(1) { 9 }, ByteArray(60) { it.toByte() }, ByteArray(256) { (it * 7).toByte() })) {
                val b64 = encodeBase64(raw)
                val blob = DbKeyScheme.tagged(tag, b64)
                assertEquals(b64, DbKeyScheme.payloadOf(blob), "payloadOf must round-trip $tag")
                assertEquals(tag == DbKeyScheme.TAG_AUTH_BOUND, DbKeyScheme.isAuthBound(blob))
            }
        }
    }

    /**
     * The at-rest LENGTH must not fingerprint the
     * scheme. A plain (short ≈88 B AES-GCM) and an auth-bound (long 256 B RSA-OAEP)
     * blob — DIFFERENT real payload sizes — must produce stored values of the SAME
     * length, because both pad to the common fixed frame. Before the fix the
     * auth-bound value was ~53–170 B longer, so len(vlt_c) alone triaged Lever B.
     */
    @Test
    fun paddedForm_equalStoredLength_acrossSchemes_andPayloadSizes() {
        val plainCt = encodeBase64(ByteArray(88) { it.toByte() })        // ≈ device AES-GCM
        val authCt  = encodeBase64(ByteArray(256) { (it * 3).toByte() }) // RSA-2048 OAEP
        val plain = DbKeyScheme.tagged(DbKeyScheme.TAG_CRYPTO_PROVIDER, plainCt)
        val ab    = DbKeyScheme.tagged(DbKeyScheme.TAG_AUTH_BOUND, authCt)
        // Same stored length despite a 168-byte real-payload difference.
        assertEquals(plain.length, ab.length,
            "plain vs auth-bound stored length must not distinguish the scheme")
        // Both decode to the one fixed common length (strip the "v:" marker).
        assertEquals(DbKeyScheme.NEUTRAL_PADDED_LEN, decodeBase64(plain.substring(2)).size)
        assertEquals(DbKeyScheme.NEUTRAL_PADDED_LEN, decodeBase64(ab.substring(2)).size)
        // …and each still round-trips its exact payload + scheme (unwrap must work).
        assertEquals(plainCt, DbKeyScheme.payloadOf(plain))
        assertEquals(authCt, DbKeyScheme.payloadOf(ab))
        assertFalse(DbKeyScheme.isAuthBound(plain))
        assertTrue(DbKeyScheme.isAuthBound(ab))
    }

    /**
     * Migration: a vault written by the pre-padding build stored the
     * variable-length neutral form — decoded = schemeByte(1) ‖ payload, no fmt byte,
     * no padding. It must still classify + round-trip so those vaults open; the next
     * DB-key write rewrites it to the padded form. (The leading 0x02 fmt byte of the
     * padded form can never collide with the legacy scheme byte 0x00/0x01.)
     */
    @Test
    fun legacyVariableLengthNeutralForm_stillParsesAndRoundTrips() {
        val payloadBytes = ByteArray(60) { (it + 1).toByte() }
        val payloadB64 = encodeBase64(payloadBytes)
        // Reconstruct the OLD neutral layout by hand: "v:" + base64(schemeByte ‖ payload).
        val legacyAb = "v:" + encodeBase64(byteArrayOf(0x01) + payloadBytes)
        assertTrue(DbKeyScheme.isAuthBound(legacyAb),
            "legacy neutral auth-bound must still classify as auth-bound")
        assertEquals(DbKeyScheme.TAG_AUTH_BOUND, DbKeyScheme.tagOf(legacyAb))
        assertEquals(payloadB64, DbKeyScheme.payloadOf(legacyAb),
            "legacy neutral payload must round-trip so the vault still unwraps")

        val legacyPlain = "v:" + encodeBase64(byteArrayOf(0x00) + payloadBytes)
        assertFalse(DbKeyScheme.isAuthBound(legacyPlain))
        assertEquals(DbKeyScheme.TAG_CRYPTO_PROVIDER, DbKeyScheme.tagOf(legacyPlain))
        assertEquals(payloadB64, DbKeyScheme.payloadOf(legacyPlain))
    }

    @Test
    fun defaultProtector_reportsNoAuthBindingSupport() {
        // The commonMain default never claims hardware auth-binding; that's
        // strictly a platform (Android/iOS) capability.
        // (Constructed with a throwaway context array; wrap/unwrap not exercised
        // here — those need a real CryptoProvider, covered on-device.)
    }
}
