package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// a TIER UPGRADE may skip the credential
// rotation only on PROOF that the credential is already a passphrase.
//
// The bug: all four tier screens (Settings + the one-time chooser, on both
// platforms) asked `VaultSelector.isPassphraseMode()`, which fails OPEN to
// `true` for anything it cannot authenticate — correct for its own job (it picks
// the ENTRY WIDGET, and the digit keypad hard-locks a passphrase user out),
// fatal here. Writing ≥28 bytes of base64 garbage into `vlt_m` (a DAMAGED blob —
// see SelectorMetaGuardTest for the same classifier used there) therefore
// turned "upgrade to Maximum" into a pure metadata write: an AEAD-AUTHENTICATED
// `vlt_lvl = maximum` persisted over an UNCHANGED 6-digit PIN. That permanently
// satisfies DeviceLockPolicy.needsForcedMigration — the lock-less floor
// The lock-less floor exists for — and a later, image-only attacker grinds the
// ~20-bit PIN the UI now claims is a ≥70-bit passphrase.
//
// CryptoProvider/KeyValueStore are expect classes with no common fake seam, so
// (exactly as SelectorMetaGuardTest does) these pin the two pure
// decision units the accessor and all four consumers are built from:
// SelectorMetaPolicy.credentialKindProvenFromRead and ProtectionUpgradePlan. The
// end-to-end damaged-blob wiring of the accessor itself is the instrumented
// androidApp VaultSelectorTest's territory; the classifier premise that makes
// the damaged case reach the accessor's `null` branch is pinned below.
// ---------------------------------------------------------------------------

class ProtectionUpgradePlanTest {

    // -- The tri-state read ----------------------------------------------------

    @Test
    fun authenticatedPassphrase_isPROVEN() {
        assertEquals(
            true,
            SelectorMetaPolicy.credentialKindProvenFromRead(SelectorMetaPolicy.MODE_PASSPHRASE, authenticated = true),
        )
    }

    @Test
    fun authenticatedPin_isPROVEN_pin() {
        assertEquals(
            false,
            SelectorMetaPolicy.credentialKindProvenFromRead(SelectorMetaPolicy.MODE_PIN, authenticated = true),
        )
    }

    @Test
    fun absentMode_provesPIN_becauseSuchAVaultPredatesPassphraseMode() {
        // `vlt_m` is ALWAYS written now (MODE_PIN included), so a missing
        // value is a pre-claim install — not a claim anyone wrote — and its
        // credential really is a 6-digit PIN. It is also the SAFE answer either
        // way: `false` and `null` both require the rotation below.
        assertEquals(false, SelectorMetaPolicy.credentialKindProvenFromRead(null, authenticated = false))
        assertEquals(false, SelectorMetaPolicy.credentialKindProvenFromRead(null, authenticated = true))
    }

    @Test
    fun unauthenticatedValue_provesNOTHING_whateverItClaims() {
        // Legacy cleartext and an attacker's plant are indistinguishable by
        // construction (the fallback carries no tag), so neither may be believed.
        for (planted in listOf(SelectorMetaPolicy.MODE_PASSPHRASE, SelectorMetaPolicy.MODE_PIN, "maximum", "", "zzz")) {
            assertNull(
                SelectorMetaPolicy.credentialKindProvenFromRead(planted, authenticated = false),
                "unauthenticated '$planted' must prove nothing",
            )
        }
    }

    @Test
    fun authenticatedButUnknownToken_provesNOTHING() {
        // A mode written by a NEWER binary: authenticated, so not a forgery, but
        // this build cannot say what it means. One extra rotation is the safe cost.
        assertNull(SelectorMetaPolicy.credentialKindProvenFromRead("phrase-v2", authenticated = true))
    }

    @Test
    fun aDamagedModeBlob_reachesTheUnprovenBranch() {
        // The accessor maps SelectorMetaDamagedException to `null`; this pins the
        // premise that the plant PRODUCES that exception rather than being read
        // back as a value: readSelectorMetaRaw throws Damaged for any value that
        // is blob-SHAPED (≥ IV(12)+tag(16) decoded bytes) and fails AEAD.
        val plantedBlob = encodeBase64(ByteArray(28) { 0x41 })
        assertTrue(
            SelectorMetaPolicy.isSelectorMetaBlobShaped(plantedBlob),
            "the A1-2 plant must classify as a DAMAGED blob, not legacy cleartext",
        )
        // …and `null` is what must not skip the rotation.
        assertTrue(ProtectionUpgradePlan.needsCredentialChange(ProtectionLevel.MAXIMUM, null))
    }

    @Test
    fun theWidgetReaderAndTheProofReaderFailInOPPOSITEDirections() {
        // Why the two readers of the SAME slot cannot be merged (the `vlt_m` twin
        // of SelectorMetaGuardTest.theEnforcementReadWouldHaveBeenFailOpenHere):
        // The widget answer for an unauthenticated/damaged value is `true` (the
        // free-text field — a PIN user can still type six digits, the keypad
        // hard-locks a passphrase user out), and `true` is exactly the answer that
        // SKIPS the rotation. Opposite questions, opposite fail directions.
        val plantedWidget = SelectorMetaPolicy.passphraseModeFromRead("pin", authenticated = false)
        val plantedProof = SelectorMetaPolicy.credentialKindProvenFromRead("pin", authenticated = false)
        assertTrue(plantedWidget, "the widget reader must keep failing OPEN")
        assertNull(plantedProof, "the tier reader must not inherit that fail-open")
        assertTrue(ProtectionUpgradePlan.needsCredentialChange(ProtectionLevel.MAXIMUM, plantedProof))
    }

    // -- The upgrade decision --------------------------------------------------

    @Test
    fun onlyAPROVENPassphraseSkipsTheCredentialChange() {
        assertFalse(ProtectionUpgradePlan.needsCredentialChange(ProtectionLevel.MAXIMUM, true))
        for (unproven in listOf(false, null)) {
            assertTrue(
                ProtectionUpgradePlan.needsCredentialChange(ProtectionLevel.MAXIMUM, unproven),
                "proven=$unproven must NOT skip the credential change",
            )
        }
    }

    @Test
    fun aTierThatDoesNotUseAPassphraseNeverDemandsOne() {
        // CASUAL / PRIVATE keep the PIN, so this decision is not theirs — including
        // for the DOWNGRADE direction, which each platform still resolves with the
        // fail-open widget reader (there "cannot tell" already means "rotate").
        for (level in ProtectionLevel.entries.filter { !it.usesPassphrase }) {
            for (proven in listOf(true, false, null)) {
                assertFalse(
                    ProtectionUpgradePlan.needsCredentialChange(level, proven),
                    "$level (proven=$proven)",
                )
            }
        }
    }

    @Test
    fun anUnknownTargetTokenBehavesExactlyLikeThePreFixPlatformCode() {
        // Both platforms derived `usesPassphrase` from an exact match on
        // "maximum"; a token this build cannot parse implies no passphrase.
        assertFalse(ProtectionUpgradePlan.needsCredentialChange(null, null))
        assertFalse(ProtectionUpgradePlan.needsCredentialChangeForStorage("nonsense", null))
        assertFalse(ProtectionUpgradePlan.needsCredentialChangeForStorage(null, null))
    }

    @Test
    fun theStorageOverloadMatchesTheTypedOne_forEveryTierToken() {
        // The Swift call sites carry the tier as a String; they must not drift.
        for (level in ProtectionLevel.entries) {
            for (proven in listOf(true, false, null)) {
                assertEquals(
                    ProtectionUpgradePlan.needsCredentialChange(level, proven),
                    ProtectionUpgradePlan.needsCredentialChangeForStorage(level.storageValue, proven),
                    "${level.storageValue} (proven=$proven)",
                )
            }
        }
        // The retired "hardened" token maps forward to PRIVATE (a PIN tier).
        assertFalse(ProtectionUpgradePlan.needsCredentialChangeForStorage("hardened", null))
    }

    // -- The property the four consumers exist to preserve ---------------------

    @Test
    fun anUnprovenUpgradeCanNeverRetireTheLockLessFloor() {
        // End to end, at the decision level: on a lock-less phone
        // the ONLY escape from DeviceLockPolicy's forced migration is a tier at or
        // above MAXIMUM. Every unproven state now demands the credential rotation
        // first, and the honest tier the screens fall back to meanwhile (CASUAL)
        // keeps the gate armed for the next unlock.
        for (unproven in listOf(false, null)) {
            assertTrue(ProtectionUpgradePlan.needsCredentialChange(ProtectionLevel.MAXIMUM, unproven))
            assertTrue(
                DeviceLockPolicy.needsForcedMigration(ProtectionLevel.CASUAL, DeviceLockState.Absent),
                "the fallback tier must still fail the floor",
            )
        }
        // The pre-fix behaviour, stated: believing the fail-open widget reader
        // ("a passphrase is already set") skipped the rotation and let an
        // AUTHENTICATED maximum land over the untouched PIN — which satisfies the
        // floor forever.
        assertFalse(DeviceLockPolicy.needsForcedMigration(ProtectionLevel.MAXIMUM, DeviceLockState.Absent))
    }

    @Test
    fun aGenuineMaximumVaultIsNotDraggedThroughAnotherRotation() {
        // The fix must cost an honest passphrase user nothing: an AUTHENTICATED
        // `phrase` still skips the chain, and the migration chooser's
        // `passphraseAlreadySet` (the negation of this answer for a passphrase
        // tier) still persists the chosen MAXIMUM rather than the CASUAL fallback.
        val proven = SelectorMetaPolicy.credentialKindProvenFromRead(
            SelectorMetaPolicy.MODE_PASSPHRASE, authenticated = true,
        )
        assertFalse(ProtectionUpgradePlan.needsCredentialChange(ProtectionLevel.MAXIMUM, proven))
        assertFalse(DeviceLockPolicy.needsForcedMigration(ProtectionLevel.MAXIMUM, DeviceLockState.Absent))
    }

    // -- The one-time chooser's finish-note rule ------------

    @Test
    fun theFinishNoteIsOwedExactlyWhenSomethingWasLeftUndone() {
        // Nothing left to do: what was persisted IS what was chosen and no
        // credential rotation is outstanding.
        assertFalse(
            ProtectionUpgradePlan.needsFinishInSettings(
                ProtectionLevel.CASUAL, ProtectionLevel.CASUAL, mustRotateCredential = false,
            ),
        )
        // The credential half: MAXIMUM was chosen, CASUAL persisted, rotation owed.
        assertTrue(
            ProtectionUpgradePlan.needsFinishInSettings(
                ProtectionLevel.MAXIMUM, ProtectionLevel.CASUAL, mustRotateCredential = true,
            ),
        )
        // The Lever-B half: PRIVATE chosen, CASUAL persisted (the key is plain), no
        // credential rotation involved — the note is still owed.
        assertTrue(
            ProtectionUpgradePlan.needsFinishInSettings(
                ProtectionLevel.PRIVATE, ProtectionLevel.CASUAL, mustRotateCredential = false,
            ),
        )
        assertFalse(
            ProtectionUpgradePlan.needsFinishInSettings(
                ProtectionLevel.PRIVATE, ProtectionLevel.PRIVATE, mustRotateCredential = false,
            ),
        )
    }

    @Test
    fun aPassphraseVaultPickingAPinTierIsOwedNoNote() {
        // The disjunct iOS carried and Android never did: `!usesPassphrase &&
        // isPassphraseMode()`. A passphrase vault picking CASUAL keeps its
        // credential and persists exactly the tier it chose, so there is nothing to
        // "finish in Settings" — and the reader that answered it fails OPEN, which
        // is why it must not be consulted here at all. (Under-claiming a passphrase
        // as CASUAL is the safe direction; the tier only relaxes timers.)
        assertFalse(
            ProtectionUpgradePlan.needsFinishInSettings(
                ProtectionLevel.CASUAL, ProtectionLevel.CASUAL, mustRotateCredential = false,
            ),
        )
    }

    @Test
    fun theFinishNoteStorageOverloadMatchesTheTypedOne() {
        // The Swift chooser carries both tiers as Strings.
        for (chosen in ProtectionLevel.entries) {
            for (persisted in ProtectionLevel.entries) {
                for (rotate in listOf(true, false)) {
                    assertEquals(
                        ProtectionUpgradePlan.needsFinishInSettings(chosen, persisted, rotate),
                        ProtectionUpgradePlan.needsFinishInSettingsForStorage(
                            chosen.storageValue, persisted.storageValue, rotate,
                        ),
                        "${chosen.storageValue}/${persisted.storageValue} (rotate=$rotate)",
                    )
                }
            }
        }
    }

    @Test
    fun theFinishNoteAndTheUpgradePlanAgreeOnTheHonestFallback() {
        // End to end for the case this turns on: an unproven `vlt_m` forces the
        // rotation, the chooser can therefore only persist the honest CASUAL, and
        // BOTH halves of the note rule fire — so the user is told, and the
        // lock-less floor stays armed for the next unlock.
        val mustRotate = ProtectionUpgradePlan.needsCredentialChange(ProtectionLevel.MAXIMUM, null)
        assertTrue(mustRotate)
        assertTrue(
            ProtectionUpgradePlan.needsFinishInSettings(
                ProtectionLevel.MAXIMUM, ProtectionLevel.CASUAL, mustRotate,
            ),
        )
        assertTrue(DeviceLockPolicy.needsForcedMigration(ProtectionLevel.CASUAL, DeviceLockState.Absent))
    }

    // -- Short-circuiting the proof read -------------------

    @Test
    fun aNonPassphraseTargetNeedsNoProofReadAtAll() {
        // Both platforms now guard the accessor with `level.usesPassphrase &&`, so
        // a PIN tier never decrypts `vlt_m` twice per apply. That is safe ONLY
        // because the plan's answer for such a target is `false` regardless of what
        // the proof would have said — pinned here so the short-circuit can never
        // change a decision.
        for (level in ProtectionLevel.entries.filter { !it.usesPassphrase }) {
            for (proven in listOf(true, false, null)) {
                assertEquals(
                    false,
                    ProtectionUpgradePlan.needsCredentialChange(level, proven),
                    "$level (proven=$proven) must not depend on the proof read",
                )
            }
        }
    }

    @Test
    fun everyLegacyAndTransientStateRoutesThroughTheRotation_neverIntoARefusal() {
        // BRICK-SAFETY / no dead end: the plan only ever answers "run a credential
        // change", which is recoverable and re-writes `vlt_m` as an authenticated
        // blob on the way. There is no state in which it refuses the upgrade, and
        // nothing here can wipe.
        for (proven in listOf(true, false, null)) {
            val answer = ProtectionUpgradePlan.needsCredentialChange(ProtectionLevel.MAXIMUM, proven)
            assertEquals(proven != true, answer)
        }
    }
}
