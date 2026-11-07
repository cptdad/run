package com.vg.run

import com.vg.run.RecoveryBlobPolicy.RecoveryBlobState
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// `vlt_rc` is PROVEN, never merely PRESENT.
//
// THE PROBLEM. Every consumer asked `store.contains(VaultStoreKeys.RECOVERY_BLOB)`. That
// slot is writable by anyone who can write the app's files (Android
// `vault_selector_prefs.xml`, the iOS NSUserDefaults fallback), so one planted
// byte did two things at once:
//
//   • permanently VETOED the re-key, so the archived weak-era `vlt_c` plus a
//     grindable PIN plus the still-current device key kept opening today's
//     vault — the exact exposure the re-key exists to retire; and
//   • minted a PHANTOM recovery path: the unlock screen offered "use your
//     recovery code" for a vault that has none, and every attempt against a blob
//     that can never decrypt was counted as a wrong-code guess against the
//     emergency-wipe budget.
//
// THE RULE, and it is DIRECTIONAL — the three predicates do NOT agree, and that
// is the point:
//
//   state        rotation veto   recovery path offered   usable as a Lever-B net
//   PROVEN       yes             yes                     yes
//   UNREADABLE   yes             yes                     NO
//   ABSENT       no              no                      no
//   FORGED       no              no                      no
//
// UNREADABLE is where the asymmetry lives. It keeps the rotation veto and keeps
// the escape hatch on screen (both "change nothing"), but it is NOT a safety net
// for a path that is about to make the DB key auth-bound — that one has to be
// proof or nothing, because after it the code is the only way back.
//
// Scope note, the same one DbKeyRotationTest carries: `VaultSelector`'s store is
// the concrete `expect class KeyValueStore`, so commonTest asserts the PURE
// decision units the implementation calls. The wiring (which site consumes which
// predicate) is pinned by the androidTest `VaultSelectorTest` against a real
// store.
// ---------------------------------------------------------------------------

private const val REAL_BLOB = "dGhpcy1sb29rcy1saWtlLWEtYmxvYg=="

class RecoveryBlobProvenanceTest {

    // -- the classifier --------------------------------------------------------

    @Test
    fun absentWhenNothingIsStored() {
        assertEquals(RecoveryBlobState.ABSENT, RecoveryBlobPolicy.classifyRecoveryBlob(null) { true })
    }

    @Test
    fun provenWhenTheDeviceKeyOpensIt() {
        assertEquals(RecoveryBlobState.PROVEN, RecoveryBlobPolicy.classifyRecoveryBlob(REAL_BLOB) { true })
    }

    @Test
    fun forgedWhenTheOpenFails() {
        // A plant, or a blob damaged past use. Both are equally unable to
        // recover anything, so both release the rotation veto.
        assertEquals(RecoveryBlobState.FORGED, RecoveryBlobPolicy.classifyRecoveryBlob("plausible") { false })
        assertEquals(
            RecoveryBlobState.FORGED,
            RecoveryBlobPolicy.classifyRecoveryBlob("plausible") { throw IllegalArgumentException("bad base64") },
        )
    }

    @Test
    fun unreadableWhenTheDeviceKeyIsUnavailable() {
        // KeyUnavailable = DEFER. Misreading this as FORGED would let a locked
        // keybag or an Android Keystore hiccup authorise a re-key that orphans a
        // recovery code the user has written down.
        assertEquals(
            RecoveryBlobState.UNREADABLE,
            RecoveryBlobPolicy.classifyRecoveryBlob(REAL_BLOB) { throw KeyUnavailableException("locked keybag") },
        )
        assertEquals(
            RecoveryBlobState.UNREADABLE,
            RecoveryBlobPolicy.classifyRecoveryBlob(REAL_BLOB) { throw KeyPermanentlyInvalidException("key gone") },
        )
    }

    // -- the rotation veto -----------------------------------------------------

    @Test
    fun onlyProvenAbsentOrProvenForgedReleasesTheRotationVeto() {
        assertTrue(RecoveryBlobPolicy.recoveryBlobVetoesRotation(RecoveryBlobState.PROVEN))
        assertTrue(
            RecoveryBlobPolicy.recoveryBlobVetoesRotation(RecoveryBlobState.UNREADABLE),
            "a transient outage must never enable a re-key that would orphan a real recovery blob",
        )
        assertFalse(RecoveryBlobPolicy.recoveryBlobVetoesRotation(RecoveryBlobState.ABSENT))
        assertFalse(
            RecoveryBlobPolicy.recoveryBlobVetoesRotation(RecoveryBlobState.FORGED),
            "a blob that cannot be opened could never have recovered anything — rotating over it destroys nothing",
        )
    }

    @Test
    fun aPlantedRecoveryBlobNoLongerVetoesTheTierUpgradeRekey() {
        // End to end through the eligibility gate: the planted-slot case is the
        // problem, and it now rotates exactly like a vault with no slot at all.
        val planted = RecoveryBlobPolicy.recoveryBlobVetoesRotation(RecoveryBlobPolicy.classifyRecoveryBlob("vlt_rc") { false })
        assertTrue(
            DbKeyRotationPolicy.mayRotateDbKey(
                tierUpgrade = true,
                recoveryBlobVetoes = planted,
                dbKeyAuthBound = false,
                hasVaultHandle = true,
                rotationAlreadyPending = false,
            ),
        )
    }

    @Test
    fun aRealRecoveryBlobStillVetoesIt_andSoDoesAnOutage() {
        for (state in listOf(RecoveryBlobState.PROVEN, RecoveryBlobState.UNREADABLE)) {
            assertFalse(
                DbKeyRotationPolicy.mayRotateDbKey(
                    tierUpgrade = true,
                    recoveryBlobVetoes = RecoveryBlobPolicy.recoveryBlobVetoesRotation(state),
                    dbKeyAuthBound = false,
                    hasVaultHandle = true,
                    rotationAlreadyPending = false,
                ),
                "$state must keep the absolute recovery-code veto was built around",
            )
        }
    }

    // -- the recovery ENTRY path ------------------------------------------------

    @Test
    fun theRecoveryPathIsHiddenOnlyWhenTheSlotIsProvenUseless() {
        assertTrue(RecoveryBlobPolicy.recoveryPathOffered(RecoveryBlobState.PROVEN))
        assertTrue(
            RecoveryBlobPolicy.recoveryPathOffered(RecoveryBlobState.UNREADABLE),
            "hiding the escape hatch from a user whose hardware key just died IS the brick",
        )
        assertFalse(RecoveryBlobPolicy.recoveryPathOffered(RecoveryBlobState.ABSENT))
        assertFalse(
            RecoveryBlobPolicy.recoveryPathOffered(RecoveryBlobState.FORGED),
            "a phantom recovery screen spends the emergency-wipe budget one attempt at a time",
        )
    }

    // -- arming Lever B ---------------------------------------------------------

    @Test
    fun onlyAProvenBlobIsASafetyNetForArmingLeverB() {
        assertTrue(RecoveryBlobPolicy.recoveryBlobUsableAsNet(RecoveryBlobState.PROVEN))
        for (state in listOf(RecoveryBlobState.ABSENT, RecoveryBlobState.FORGED, RecoveryBlobState.UNREADABLE)) {
            assertFalse(
                RecoveryBlobPolicy.recoveryBlobUsableAsNet(state),
                "$state is not a net — binding the DB key to hardware over it is the brick this gate prevents",
            )
        }
    }

    @Test
    fun theNetPredicateIsStrictlyStrongerThanTheVetoPredicate() {
        // Non-vacuousness: collapsing the two (the obvious "just use one
        // helper" refactor) either arms Lever B over an unreadable slot or
        // releases the rotation veto on one. Both are regressions.
        for (state in RecoveryBlobState.entries) {
            if (RecoveryBlobPolicy.recoveryBlobUsableAsNet(state)) {
                assertTrue(RecoveryBlobPolicy.recoveryBlobVetoesRotation(state), "$state")
            }
        }
        assertTrue(RecoveryBlobPolicy.recoveryBlobVetoesRotation(RecoveryBlobState.UNREADABLE))
        assertFalse(RecoveryBlobPolicy.recoveryBlobUsableAsNet(RecoveryBlobState.UNREADABLE))
    }
}
