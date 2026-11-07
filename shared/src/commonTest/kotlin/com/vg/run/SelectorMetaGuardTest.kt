package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// Selector-meta hardening tests. CryptoProvider and
// KeyValueStore are expect classes with no common fake seam, so these pin the
// two extracted decision units directly; the end-to-end wiring (real AEAD blob
// round-trip, damaged-blob behavior of isPassphraseMode/protectionLevel*) is
// covered by the instrumented androidApp VaultSelectorTest.
//
//  - isSelectorMetaBlobShaped: a stored value that base64-decodes to at least
//    IV(12)+tag(16) bytes is provably one of our AEAD blobs — a decrypt failure
//    on it is a DAMAGED blob, never legacy cleartext, and must not be returned
//    as a value (it rendered the wrong entry UI / fed garbage level parses).
//  - selectorWriteGuard: selector WRITES reachable from non-@Throws Swift
//    callers and Compose click handlers map a transient KeyUnavailableException
//    to `false` instead of letting it cross the bridge (SIGABRT).
//  - The same classifier is what makes a planted
//    cleartext tier readable, so the fail-secure DESTINATION for an
//    unauthenticated value is pinned here too.
// ---------------------------------------------------------------------------

class SelectorMetaGuardTest {

    // -- Damaged-blob vs legacy-cleartext classifier ---------------------------

    @Test
    fun legacyCleartextTokens_areNotBlobShaped() {
        // Every token a pre-tier install could have stored in vlt_m / vlt_lvl.
        for (legacy in listOf("pin", "phrase", "casual", "private", "maximum", "hardened")) {
            assertFalse(
                SelectorMetaPolicy.isSelectorMetaBlobShaped(legacy),
                "legacy token '$legacy' must classify as cleartext, not a blob",
            )
        }
    }

    @Test
    fun base64AtOrAboveIvPlusTag_isBlobShaped() {
        // IV(12) + tag(16) = 28 raw bytes is the smallest possible AEAD blob.
        assertTrue(SelectorMetaPolicy.isSelectorMetaBlobShaped(encodeBase64(ByteArray(28))))
        // A real mode/level blob (IV + ct + tag) is comfortably larger.
        assertTrue(SelectorMetaPolicy.isSelectorMetaBlobShaped(encodeBase64(ByteArray(40) { it.toByte() })))
    }

    @Test
    fun shortOrInvalidBase64_isNotBlobShaped() {
        assertFalse(SelectorMetaPolicy.isSelectorMetaBlobShaped(encodeBase64(ByteArray(27))))
        assertFalse(SelectorMetaPolicy.isSelectorMetaBlobShaped(""))
        assertFalse(SelectorMetaPolicy.isSelectorMetaBlobShaped("!!!not-base64###"))
    }

    // -- Bridge-safe write guard ----------------------------------------------

    @Test
    fun guard_success_returnsTrue() {
        var ran = false
        assertTrue(selectorWriteGuard("test") { ran = true })
        assertTrue(ran)
    }

    @Test
    fun guard_keyUnavailable_returnsFalseInsteadOfThrowing() {
        // The contract: setProtectionLevel / the level-aware provision
        // route their crypto.encrypt through this guard, so a transient device-key
        // outage surfaces as `false` — never as an exception across the
        // non-@Throws Swift bridge or a Compose click handler.
        assertFalse(selectorWriteGuard("test") { throw KeyUnavailableException("keybag locked") })
    }

    @Test
    fun guard_otherExceptions_stillPropagate() {
        // Only the transient-outage type is a defer signal; a genuine storage /
        // programming fault must stay visible.
        assertFailsWith<IllegalStateException> {
            selectorWriteGuard("test") { throw IllegalStateException("boom") }
        }
    }

    @Test
    fun smallestRealBlobIsAboveTheLegacyTokens() {
        // Guard the classifier's premise: the longest legacy token ("hardened",
        // 8 chars) decodes to 6 raw bytes — far below the 28-byte blob floor.
        assertEquals(6, decodeBase64("hardened").size)
    }

    // -- An unauthenticated vlt_lvl must never LOOSEN -----
    //
    // The classifier above is exactly what makes the attack cheap: writing the six
    // ASCII bytes `casual` into vault_selector_prefs.xml (or the iOS NSUserDefaults
    // slot KeyValueStore falls back to) decodes to 4 bytes, so it is classified as
    // legacy cleartext and returned as the value. That is unavoidable — a cleartext
    // fallback has no tag to check — so the fix is on the CONSUMER side:
    // protectionLevelForEnforcement now flags the read's provenance and routes any
    // unauthenticated value to Present(MAXIMUM). These pin the property that makes
    // that destination correct. (The end-to-end wiring — real AEAD blob, real store,
    // legacy-cleartext-still-reads-for-display — is covered by the instrumented
    // androidApp VaultSelectorTest.)

    @Test
    fun attackerControlledTierTokens_areAllClassifiedAsUnauthenticatedCleartext() {
        // Every tier name an attacker could plant, incl. the gentlest one (CASUAL:
        // 180-day self-wipe, 10-try budget, 15-min auto-lock).
        for (level in ProtectionLevel.entries) {
            assertFalse(
                SelectorMetaPolicy.isSelectorMetaBlobShaped(level.storageValue),
                "planted tier '${level.storageValue}' must classify as cleartext (unauthenticated)",
            )
        }
    }

    @Test
    fun failSecureTierCannotLoosenAnyEnforcementDecision() {
        // The fail-secure destination for an unauthenticated (or unrecognized)
        // token is MAXIMUM. Pin that it really is the strictest tier on every
        // decision an attacker would want to relax, so the route can never
        // become a downgrade by a later tier-constant edit.
        val failSecure = ProtectionLevelRead.Present(ProtectionLevel.MAXIMUM)
        for (level in ProtectionLevel.entries) {
            val chosen = ProtectionLevelRead.Present(level)
            assertTrue(
                InactivityPolicy.thresholdMsOrNull(failSecure)!! <=
                    InactivityPolicy.thresholdMsOrNull(chosen)!!,
                "fail-secure inactivity window must not exceed $level's",
            )
            assertTrue(
                CredentialPolicy.maxConsecutiveAttempts(failSecure) <=
                    CredentialPolicy.maxConsecutiveAttempts(chosen),
                "fail-secure attempt budget must not exceed $level's",
            )
            assertTrue(
                CredentialPolicy.autoLockTimeoutMs(failSecure) <=
                    CredentialPolicy.autoLockTimeoutMs(chosen),
                "fail-secure auto-lock must not exceed $level's",
            )
            // The periodic re-auth's tier gate is a
            // fourth enforcement decision sharing this fail-secure destination.
            // "Looser" here means DISABLED (not a larger number) — so the property
            // is the fail-secure tier must never be OFF when the legitimately
            // chosen tier would have turned it ON.
            if (ReauthPolicy.appliesTo(chosen)) {
                assertTrue(
                    ReauthPolicy.appliesTo(failSecure),
                    "fail-secure must not DISABLE the periodic re-auth when $level would enable it",
                )
            }
        }
        // …and it must not be gentler than what a pre-slider (Absent) vault has
        // always enforced either — that is what makes it safe for a genuine
        // pre-tier cleartext install, which simply reverts to the legacy behaviour
        // until its next tier write re-persists an authenticated blob.
        assertTrue(
            InactivityPolicy.thresholdMsOrNull(failSecure)!! <=
                InactivityPolicy.thresholdMsOrNull(ProtectionLevelRead.Absent)!!,
        )
        assertTrue(
            CredentialPolicy.maxConsecutiveAttempts(failSecure) <=
                CredentialPolicy.maxConsecutiveAttempts(ProtectionLevelRead.Absent),
        )
    }

    // -- An unauthenticated vlt_lvl must never SATISFY ---
    //    the Lever A credential FLOOR either.
    //
    // The rule above fixed the LOOSENING direction — an unauthenticated tier can no
    // longer stretch a timer, a budget or an auto-lock, because those all fail
    // secure to MAXIMUM. The floor gate asks the OPPOSITE question ("is this vault
    // AT OR ABOVE the tier this device requires?"), so MAXIMUM is fail-OPEN there:
    // planting the seven ASCII bytes `maximum` (5 decoded bytes — under the
    // 28-byte blob floor, so it is read back verbatim as legacy cleartext)
    // permanently suppressed DeviceLockPolicy's forced migration on a phone with
    // no lock screen, where CR-1 has already collapsed to a ~20-bit PIN.
    //
    // SelectorMetaPolicy.provenProtectionLevel is the floor-side reader's decision unit
    // (the store/CryptoProvider have no common fake seam, so the end-to-end wiring
    // is covered by the instrumented androidApp VaultSelectorTest).

    @Test
    fun plantedCleartextMaximum_doesNotSatisfyTheFloor() {
        // Premise: `maximum` really does take the legacy-cleartext branch.
        assertFalse(SelectorMetaPolicy.isSelectorMetaBlobShaped(ProtectionLevel.MAXIMUM.storageValue))
        assertEquals(5, decodeBase64(ProtectionLevel.MAXIMUM.storageValue).size)

        val proven = SelectorMetaPolicy.provenProtectionLevel(
            storedLevel = ProtectionLevel.MAXIMUM,   // it PARSES — that was the whole trick
            present = true,
            authenticated = false,                   // …but it proves nothing
        )
        assertEquals(SelectorMetaPolicy.UNPROVEN_LEVEL, proven)
        assertTrue(
            DeviceLockPolicy.needsForcedMigration(proven, DeviceLockState.Absent),
            "an unauthenticated tier must NOT be able to skip the forced migration",
        )
        // The regression this closes, stated as the pre-fix behaviour: the lenient
        // read handed the planted tier straight through, and the gate went quiet.
        assertFalse(
            DeviceLockPolicy.needsForcedMigration(ProtectionLevel.MAXIMUM, DeviceLockState.Absent),
            "pre-fix path: honouring the planted token disarms the gate",
        )
    }

    @Test
    fun everyPlantableTierToken_isUnprovenAtTheFloor() {
        for (level in ProtectionLevel.entries) {
            val proven = SelectorMetaPolicy.provenProtectionLevel(level, present = true, authenticated = false)
            assertEquals(SelectorMetaPolicy.UNPROVEN_LEVEL, proven, "planted '${level.storageValue}'")
            assertTrue(DeviceLockPolicy.needsForcedMigration(proven, DeviceLockState.Absent))
        }
        // …and the weakest tier is what makes that true: it satisfies no floor.
        for (level in ProtectionLevel.entries) {
            assertTrue(
                SelectorMetaPolicy.UNPROVEN_LEVEL.ordinal <= level.ordinal,
                "UNPROVEN_LEVEL must be the weakest tier, not $level",
            )
        }
    }

    @Test
    fun aSealedMaximum_isProven_andIsLeftAlone() {
        // The mirror case: a tier that came out of a SUCCESSFUL device-key AEAD
        // decrypt is the vault's real tier and must be honoured in full — the fix
        // costs a legitimate Maximum user nothing (no forced screen, no loop).
        val proven = SelectorMetaPolicy.provenProtectionLevel(
            storedLevel = ProtectionLevel.MAXIMUM, present = true, authenticated = true,
        )
        assertEquals(ProtectionLevel.MAXIMUM, proven)
        assertFalse(DeviceLockPolicy.needsForcedMigration(proven, DeviceLockState.Absent))
    }

    @Test
    fun aSealedSubFloorTier_stillForces() {
        // The case DeviceLockPolicy was written for (Android CASUAL, lock screen
        // removed after provisioning) is untouched by the provenance rule.
        for (level in listOf(ProtectionLevel.CASUAL, ProtectionLevel.PRIVATE)) {
            val proven = SelectorMetaPolicy.provenProtectionLevel(level, present = true, authenticated = true)
            assertEquals(level, proven)
            assertTrue(DeviceLockPolicy.needsForcedMigration(proven, DeviceLockState.Absent))
        }
    }

    @Test
    fun neverChosenAndUnparseable_areNull_notBelowTheFloor() {
        // BRICK-SAFETY / no-loop: "nothing stored" is a legacy pre-slider vault and
        // "authenticated but unparseable" is a tier written by a NEWER binary.
        // Neither is evidence of being under the floor, and both already route to
        // the one-time chooser, which is itself gated by isSelectable (nothing
        // below MAXIMUM is selectable without a lock screen) and whose write
        // self-heals the slot. Forcing them instead would fight over the screen.
        assertNull(SelectorMetaPolicy.provenProtectionLevel(null, present = false, authenticated = false))
        assertNull(SelectorMetaPolicy.provenProtectionLevel(null, present = true, authenticated = true))
        assertFalse(
            DeviceLockPolicy.needsForcedMigration(
                SelectorMetaPolicy.provenProtectionLevel(null, present = false, authenticated = false),
                DeviceLockState.Absent,
            ),
        )
    }

    @Test
    fun theFloorReadNeverForcesOnADeviceThatHasALockScreen() {
        // The 99.99% case: whatever the provenance says, a phone WITH a lock screen
        // is never dragged through a credential migration by this change.
        for (level in ProtectionLevel.entries) {
            for (authenticated in listOf(true, false)) {
                val proven = SelectorMetaPolicy.provenProtectionLevel(level, present = true, authenticated = authenticated)
                assertFalse(
                    DeviceLockPolicy.needsForcedMigration(proven, DeviceLockState.Present),
                    "$level (authenticated=$authenticated) must not force on a locked device",
                )
                assertFalse(
                    DeviceLockPolicy.needsForcedMigration(proven, DeviceLockState.Unknown),
                    "$level (authenticated=$authenticated) must not force on an AMBIGUOUS probe",
                )
            }
        }
    }

    @Test
    fun theEnforcementReadWouldHaveBeenFailOpenHere() {
        // Why the two readers of the SAME slot cannot be merged: the fail-secure
        // destination for an unauthenticated value is Present(MAXIMUM), which is
        // exactly the answer that satisfies the floor. Opposite questions, opposite
        // fail directions — pin it so a later "cleanup" doesn't collapse them.
        val enforcementAnswer = ProtectionLevel.MAXIMUM      // protectionLevelForEnforcement
        val floorAnswer = SelectorMetaPolicy.provenProtectionLevel(
            storedLevel = ProtectionLevel.MAXIMUM, present = true, authenticated = false,
        )                                                    // protectionLevelForFloorCheck
        assertFalse(DeviceLockPolicy.needsForcedMigration(enforcementAnswer, DeviceLockState.Absent))
        assertTrue(DeviceLockPolicy.needsForcedMigration(floorAnswer, DeviceLockState.Absent))
    }

    // -- Fixed-length padding of selector-meta plaintext -------------
    //
    // vlt_m ("pin"/"phrase") and vlt_lvl ("casual"/"private"/"maximum") are
    // NUL-padded to one fixed plaintext length BEFORE the length-preserving AEAD,
    // so the on-disk ciphertext length no longer distinguishes credential mode
    // or protection tier. The end-to-end constant
    // ciphertext length is asserted with a real CryptoProvider in the instrumented
    // androidApp VaultSelectorTest; here we pin the pure pad/unpad units.

    @Test
    fun selectorMetaPadding_isConstantLength_acrossEveryModeAndTierToken() {
        val lengths = listOf("pin", "phrase", "casual", "private", "maximum")
            .map { SelectorMetaPolicy.padSelectorMetaPlaintext(it).size }
            .toSet()
        assertEquals(
            setOf(SelectorMetaPolicy.SELECTOR_META_PADDED_LEN), lengths,
            "every mode/tier token must pad to the same fixed plaintext length",
        )
    }

    @Test
    fun selectorMetaPadding_roundTrips() {
        for (t in listOf("pin", "phrase", "casual", "private", "maximum")) {
            assertEquals(
                t,
                SelectorMetaPolicy.unpadSelectorMetaPlaintext(SelectorMetaPolicy.padSelectorMetaPlaintext(t)),
            )
        }
    }

    @Test
    fun selectorMetaUnpad_isNoOpOnLegacyUnpaddedPlaintext() {
        // A blob from before the NUL padding decrypts to the raw token with NO trailing NUL — unpad
        // must return it unchanged so the migration is lossless.
        for (t in listOf("pin", "phrase", "casual", "private", "maximum", "hardened")) {
            assertEquals(t, SelectorMetaPolicy.unpadSelectorMetaPlaintext(t.encodeToByteArray()))
        }
    }
}
