package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * Keystore hardening. Pins the pure hardware-backing classifier that
 * replaced the old log-only, release-suppressed, API-31-only detection for the
 * Tink master key and the Lever B auth-bound
 * key.
 *
 * Like CryptoProviderKeystoreClassifyTest this runs OFF-DEVICE: the classifier
 * takes the raw KeyInfo values (an int security level, or the isInsideSecureHardware
 * boolean) so the SOFTWARE-vs-hardware decision — the load-bearing part — can't
 * silently regress, and both the API 31+ and API 29-30 branches are covered.
 */
class KeystoreBackingClassifyTest {

    // The gate a higher layer uses to decide whether to advertise a hardware
    // at-rest guarantee: only a POSITIVELY-verified hardware key qualifies. This
    // encodes the "fail toward not-claiming-hardware" rule.
    private fun claimsHardware(b: KeystoreBacking) = b == KeystoreBacking.HARDWARE

    @Test
    fun softwareLevel_isDetected_notSilentlyAccepted() {
        // The exact condition that used to be silently accepted: a SOFTWARE
        // security level must be classified SOFTWARE (surfaced), never hardware.
        val backing = KeystoreSecurity.fromSecurityLevel(KeystoreSecurity.SECURITY_LEVEL_SOFTWARE)
        assertEquals(KeystoreBacking.SOFTWARE, backing)
        assertFalse(claimsHardware(backing), "a software-backed key must not be advertised as hardware")
    }

    @Test
    fun teeAndStrongBox_areHardware_accepted() {
        assertEquals(
            KeystoreBacking.HARDWARE,
            KeystoreSecurity.fromSecurityLevel(KeystoreSecurity.SECURITY_LEVEL_TRUSTED_ENVIRONMENT),
        )
        assertEquals(
            KeystoreBacking.HARDWARE,
            KeystoreSecurity.fromSecurityLevel(KeystoreSecurity.SECURITY_LEVEL_STRONGBOX),
        )
        // UNKNOWN_SECURE means "secure hardware, TEE-or-StrongBox undetermined" — still hardware.
        assertEquals(
            KeystoreBacking.HARDWARE,
            KeystoreSecurity.fromSecurityLevel(KeystoreSecurity.SECURITY_LEVEL_UNKNOWN_SECURE),
        )
        assertTrue(
            claimsHardware(KeystoreSecurity.fromSecurityLevel(KeystoreSecurity.SECURITY_LEVEL_STRONGBOX)),
        )
    }

    @Test
    fun unknownLevel_isNotAssumedHardware() {
        // A bare UNKNOWN (-1) can't be positively placed in secure hardware -> never claim it.
        val backing = KeystoreSecurity.fromSecurityLevel(KeystoreSecurity.SECURITY_LEVEL_UNKNOWN)
        assertEquals(KeystoreBacking.UNKNOWN, backing)
        assertFalse(claimsHardware(backing))
        // Any unrecognized future value is treated conservatively, too.
        assertEquals(KeystoreBacking.UNKNOWN, KeystoreSecurity.fromSecurityLevel(999))
    }

    @Test
    fun api29to30_insideSecureHardware_givesMeaningfulAnswer() {
        // The API 29-30 path (Android 10/11, admitted by minSdk 30) must return a
        // real verdict from isInsideSecureHardware — the old code skipped it entirely
        // (early-return below API 31), leaving those devices unchecked.
        assertEquals(KeystoreBacking.HARDWARE, KeystoreSecurity.fromInsideSecureHardware(true))
        assertEquals(KeystoreBacking.SOFTWARE, KeystoreSecurity.fromInsideSecureHardware(false))
        assertFalse(
            claimsHardware(KeystoreSecurity.fromInsideSecureHardware(false)),
            "software on Android 10/11 must be detected, not assumed hardware",
        )
    }

    @Test
    fun softwareAndUnknown_bothFailTheHardwareClaim() {
        // A higher layer advertising PRIVATE/MAXIMUM hardware guarantees only if the
        // key is HARDWARE: SOFTWARE and UNKNOWN both fall short.
        assertFalse(claimsHardware(KeystoreBacking.SOFTWARE))
        assertFalse(claimsHardware(KeystoreBacking.UNKNOWN))
        assertTrue(claimsHardware(KeystoreBacking.HARDWARE))
        assertNotEquals(KeystoreBacking.HARDWARE, KeystoreBacking.SOFTWARE)
    }

    // -- The two shared policy predicates ------------------
    // KeystoreSecurity.claimsHardware / acceptsForNewKey are the single source of
    // truth both sinks route through: CryptoManager.isMasterKeyHardwareBacked
    // and AuthBoundKeyStore.isHardwareBacked / ensureKey's freshly-minted-software refusal.
    // Pinning them off-device keeps the load-bearing
    // software-detected → hardware-NOT-claimed / new-enable-REFUSED behavior from
    // silently regressing back into a dead flag.

    @Test
    fun claimsHardware_advertisesOnlyVerifiedHardware() {
        // The ADVERTISE decision: only positively-verified hardware may claim the
        // at-rest hardware guarantee. This is the boolean the tier/UI consumer reads.
        assertTrue(KeystoreSecurity.claimsHardware(KeystoreBacking.HARDWARE))
        assertFalse(KeystoreSecurity.claimsHardware(KeystoreBacking.SOFTWARE))
        assertFalse(KeystoreSecurity.claimsHardware(KeystoreBacking.UNKNOWN))
    }

    @Test
    fun acceptsForNewKey_refusesOnlyProvenSoftware() {
        // The REFUSE-to-mint / refuse-to-newly-enable decision: a key we control the
        // lifecycle of is refused ONLY when POSITIVELY software (extractable, no
        // hardware barrier). HARDWARE is accepted; UNKNOWN is accepted too (fail
        // toward not blocking access), so a fresh/new-enable key on a keystore whose
        // KeyInfo isn't derivable is not over-refused.
        assertFalse(KeystoreSecurity.acceptsForNewKey(KeystoreBacking.SOFTWARE))
        assertTrue(KeystoreSecurity.acceptsForNewKey(KeystoreBacking.HARDWARE))
        assertTrue(KeystoreSecurity.acceptsForNewKey(KeystoreBacking.UNKNOWN))
    }

    @Test
    fun claimAndAcceptDecisions_differExactlyOnUnknown() {
        // The load-bearing nuance: UNKNOWN is never CLAIMED as hardware, yet never
        // REFUSED for a controlled key — the "don't over-claim, don't over-block" split.
        for (b in KeystoreBacking.entries) {
            val claim = KeystoreSecurity.claimsHardware(b)
            val accept = KeystoreSecurity.acceptsForNewKey(b)
            when (b) {
                KeystoreBacking.HARDWARE -> { assertTrue(claim); assertTrue(accept) }
                KeystoreBacking.SOFTWARE -> { assertFalse(claim); assertFalse(accept) }
                KeystoreBacking.UNKNOWN -> { assertFalse(claim); assertTrue(accept) }
            }
        }
    }
}
