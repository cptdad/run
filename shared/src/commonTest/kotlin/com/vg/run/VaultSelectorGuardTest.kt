package com.vg.run

import com.vg.run.RecoveryBlobPolicy.AbandonedEnableAction
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// VaultSelector write/read guards.
//
// KeyValueStore and CryptoProvider are expect classes with no common fake seam,
// so — exactly as SelectorMetaGuardTest and VaultKdfTest already do — these pin
// the extracted PURE decision units, which is where the whole bug surface of
// each fix lives. End-to-end wiring (real AEAD blob, real store, real rotation)
// stays in the instrumented androidApp VaultSelectorTest.
//
//  - passphraseModeFromRead: an UNAUTHENTICATED vlt_m must not be allowed to
//        select the 6-digit keypad. On a MAXIMUM/passphrase vault the keypad
//        guarantees wrong entries, each one durably counted, and MAXIMUM's budget
//        of 5 fires an emergency wipe with no recovery code to fall back on — so
//        three planted cleartext bytes ("pin") destroyed the vault.
//  - resolveChangeCredentialMode: the sibling that keeps that fail-open
//        brick-safe. With the entry UI on free text for an unauthenticated mode,
//        a rotation must not re-persist the untrusted token AUTHENTICATED.
//  - plainDbKeyReadBackProves: the recovery blob — the ONLY way back into an
//        auth-bound vault whose hardware key died — may be deleted only on
//        positive proof the replacement plain blob landed.
//  - credentialWriteRefuted: a change-PIN batch may be reported as failed only
//        on positive evidence it did not persist. Both wrong answers are
//        destructive here, so ambiguity refutes nothing.
//  - abandonedEnableAction: an orphan recovery code left by a Lever B enable the
//        user abandoned may be revoked only on an ARMED, AUTHENTICATED marker over a
//        DB-key blob that is still PLAIN. Every other read does nothing.
// ---------------------------------------------------------------------------

class VaultSelectorGuardTest {

    // -- Which entry widget a stored credential-mode read selects ----------

    @Test
    fun unauthenticatedModeMarker_failsOpenToThePassphraseField() {
        // The attack: 3 cleartext bytes in vault_selector_prefs.xml (or the iOS
        // NSUserDefaults slot KeyValueStore falls back to). Unauthenticated by
        // construction — a cleartext fallback has no tag to check — so the fix is
        // on the consumer side: never let it pick the widget that can only produce
        // wrong entries.
        assertTrue(
            SelectorMetaPolicy.passphraseModeFromRead(SelectorMetaPolicy.MODE_PIN, authenticated = false),
            "a planted cleartext 'pin' must NOT render the digit keypad",
        )
        assertTrue(
            SelectorMetaPolicy.passphraseModeFromRead(SelectorMetaPolicy.MODE_PASSPHRASE, authenticated = false),
            "an unauthenticated 'phrase' also fails open to the text field",
        )
        assertTrue(
            SelectorMetaPolicy.passphraseModeFromRead("garbage", authenticated = false),
            "any unauthenticated token fails open — the value is not trusted at all",
        )
    }

    @Test
    fun authenticatedModeMarker_isHonouredExactly() {
        // No false positives: a healthy vault still gets the widget it asked for.
        assertTrue(
            SelectorMetaPolicy.passphraseModeFromRead(SelectorMetaPolicy.MODE_PASSPHRASE, authenticated = true),
        )
        assertFalse(
            SelectorMetaPolicy.passphraseModeFromRead(SelectorMetaPolicy.MODE_PIN, authenticated = true),
            "an AEAD-authenticated 'pin' is the vault's real mode — keypad, as chosen",
        )
        assertFalse(
            SelectorMetaPolicy.passphraseModeFromRead("hardened", authenticated = true),
            "an authenticated but unrecognized token is not the passphrase token",
        )
    }

    @Test
    fun absentModeMarker_staysOnThePinKeypad() {
        // Pre-claim legacy install: nobody ever wrote a claim, and the credential
        // really is a 6-digit PIN. Absence is not tamper (same rule as vlt_lvl).
        assertFalse(SelectorMetaPolicy.passphraseModeFromRead(null, authenticated = false))
        assertFalse(SelectorMetaPolicy.passphraseModeFromRead(null, authenticated = true))
    }

    // -- Sibling: mode resolution inside a mode-preserving rotation ---------

    private fun resolve(
        stored: String?,
        authenticated: Boolean,
        damaged: Boolean = false,
        newCredential: String,
    ) = SelectorMetaPolicy.resolveChangeCredentialMode(
        storedMode = stored,
        storedAuthenticated = authenticated,
        storedDamaged = damaged,
        newCredentialIsPinShaped = CredentialPolicy.isPinShaped(newCredential),
    )

    @Test
    fun rotation_authenticatedMode_isPreservedVerbatim() {
        val phrase = resolve(SelectorMetaPolicy.MODE_PASSPHRASE, authenticated = true, newCredential = "correct horse battery staple")
        assertEquals(SelectorMetaPolicy.MODE_PASSPHRASE, phrase.modeToWrite)
        assertTrue(phrase.resultingPassphrase, "a passphrase vault keeps the Lever A floor")

        val pin = resolve(SelectorMetaPolicy.MODE_PIN, authenticated = true, newCredential = "246810")
        assertEquals(SelectorMetaPolicy.MODE_PIN, pin.modeToWrite)
        assertFalse(pin.resultingPassphrase, "a PIN vault's rotation is not floored")
    }

    @Test
    fun rotation_absentMode_migratesToAnExplicitPinBlob() {
        // vlt_m is ALWAYS written, so its presence/absence can't leak the
        // mode. A legacy absent value must therefore be persisted, not left absent.
        val d = resolve(null, authenticated = false, newCredential = "135790")
        assertEquals(SelectorMetaPolicy.MODE_PIN, d.modeToWrite)
        assertFalse(d.resultingPassphrase)
    }

    @Test
    fun rotation_damagedMode_derivesFromTheNewCredentialShape() {
        // Unchanged by the mode guard: a damaged blob must not hold a 6-digit
        // PIN to the passphrase floor (that blocked PIN rotation forever).
        val toPin = resolve(null, authenticated = false, damaged = true, newCredential = "112233")
        assertEquals(SelectorMetaPolicy.MODE_PIN, toPin.modeToWrite)
        assertFalse(toPin.resultingPassphrase)

        val toPhrase = resolve(null, authenticated = false, damaged = true, newCredential = "runes harbor violet stapler")
        assertEquals(SelectorMetaPolicy.MODE_PASSPHRASE, toPhrase.modeToWrite)
        assertTrue(toPhrase.resultingPassphrase)
    }

    @Test
    fun rotation_plantedPinMarker_isHealedFromTheCredentialShape_notBlessed() {
        // The laundering path: plant `pin` on a MAXIMUM vault, wait for the user
        // to change their passphrase. Trusting the token here would write an
        // AUTHENTICATED 'pin' over a vault whose credential is a passphrase —
        // pinning the keypad permanently and re-arming the same wipe the guard closes.
        val d = resolve(SelectorMetaPolicy.MODE_PIN, authenticated = false, newCredential = "runes harbor violet stapler mountain")
        assertEquals(
            SelectorMetaPolicy.MODE_PASSPHRASE, d.modeToWrite,
            "an untrusted 'pin' must never be promoted to an authenticated blob over a passphrase",
        )
        assertTrue(d.resultingPassphrase, "the resulting passphrase is still held to the floor")
    }

    @Test
    fun rotation_legacyCleartextPin_stillRotatesAPinWithoutTheFloor() {
        // The no-false-positive control for the case above: a GENUINE pre-tier
        // cleartext 'pin' install rotating a 6-digit PIN must behave exactly as it
        // does today — no floor, healed to an authenticated PIN blob.
        val d = resolve(SelectorMetaPolicy.MODE_PIN, authenticated = false, newCredential = "998877")
        assertEquals(SelectorMetaPolicy.MODE_PIN, d.modeToWrite)
        assertFalse(d.resultingPassphrase, "a 6-digit rotation must not be gated on the ≥70-bit floor")
    }

    @Test
    fun rotation_untrustedPhraseMarker_cannotRelaxTheLeverAFloor() {
        // The untrusted token still gets a vote in the TIGHTENING direction only:
        // today a cleartext 'phrase' vault rotating to 6 digits is denied
        // (WEAK_CREDENTIAL), and shape-derivation alone would have silently turned
        // that into a Lever A downgrade path.
        val d = resolve(SelectorMetaPolicy.MODE_PASSPHRASE, authenticated = false, newCredential = "000111")
        assertTrue(
            d.resultingPassphrase,
            "a claimed-passphrase vault must still be floored, so the 6-digit 'rotation' is refused",
        )
    }

    // -- Deleting the recovery blob needs positive proof -------------------

    private val authBound: (String) -> Boolean = { it.startsWith("ab:") }

    @Test
    fun recoveryBlob_isDroppedOnlyWhenThePlainBlobReadsBack() {
        assertTrue(
            VaultWriteProofs.plainDbKeyReadBackProves("plain-blob", authBound),
            "a confirmed plain blob is the one state where revoking recovery is safe",
        )
    }

    @Test
    fun recoveryBlob_isKeptWhenTheWriteSilentlyDidNothing() {
        // iOS: kvPut returns WITHOUT writing on a locked keybag, while kvRemove (a
        // bare SecItemDelete, no class key needed) still succeeds. The blob is still
        // the ab: one, wrapped by a hardware key that may already be dead.
        assertFalse(
            VaultWriteProofs.plainDbKeyReadBackProves("ab:still-the-old-one", authBound),
            "an auth-bound read-back means the plain write never landed — keep the recovery code",
        )
    }

    @Test
    fun recoveryBlob_isKeptWhenTheReadBackCannotDecide() {
        // getString → null: absent, or a read that could not decide. Either way there
        // is no proof, and deleting the only recovery path is irreversible.
        assertFalse(VaultWriteProofs.plainDbKeyReadBackProves(null, authBound))
    }

    // -- Reporting a credential change as failed needs positive evidence --

    private val batch = mapOf("vlt_a" to "new-cred-blob", "vlt_c" to "new-dbkey-blob")

    @Test
    fun changeCredential_healthyStore_isNotRefuted() {
        // No false positives: a real rotation still reports SUCCESS.
        assertFalse(VaultWriteProofs.credentialWriteRefuted(batch) { batch[it] })
    }

    @Test
    fun changeCredential_silentlyDroppedBatch_isRefuted() {
        // The store still holds the OLD credential: the app would otherwise tell the
        // user their PIN changed while only the old one opens the vault — and every
        // entry of the NEW one then counts toward the emergency-wipe budget.
        val old = mapOf("vlt_a" to "old-cred-blob", "vlt_c" to "old-dbkey-blob")
        assertTrue(VaultWriteProofs.credentialWriteRefuted(batch) { old[it] })
    }

    @Test
    fun changeCredential_tornBatch_isRefuted() {
        // Only one half landed (iOS has no Keychain transaction; the journal is what
        // eventually repairs this). Claiming SUCCESS over a torn write is the one
        // thing that must not happen.
        val torn = mapOf("vlt_a" to "new-cred-blob", "vlt_c" to "old-dbkey-blob")
        assertTrue(VaultWriteProofs.credentialWriteRefuted(batch) { torn[it] })
    }

    @Test
    fun changeCredential_absentValue_isRefuted() {
        assertTrue(VaultWriteProofs.credentialWriteRefuted(batch) { null })
    }

    @Test
    fun changeCredential_ambiguousReadBack_refutesNothing() {
        // The mirror hazard: a false FAILURE is just as destructive as a false
        // success — the user keeps entering the OLD credential, which by then may no
        // longer open the vault, and those attempts count too. So a transient outage
        // keeps the earlier report rather than inventing a failure.
        assertFalse(
            VaultWriteProofs.credentialWriteRefuted(batch) { throw KeyUnavailableException("keybag locked") },
        )
        assertFalse(
            VaultWriteProofs.credentialWriteRefuted(batch) { throw IllegalStateException("store fault") },
        )
    }

    @Test
    fun changeCredential_emptyBatch_isNotRefuted() {
        // Degenerate guard: nothing expected, nothing to refute.
        assertFalse(VaultWriteProofs.credentialWriteRefuted(emptyMap()) { null })
    }

    // -- Revoking the orphan code of an ABANDONED Lever B enable ----------

    private fun action(
        marker: String?,
        authenticated: Boolean = true,
        dbKeyBlob: String?,
    ) = RecoveryBlobPolicy.abandonedEnableAction(
        markerValue = marker,
        markerAuthenticated = authenticated,
        dbKeyBlob = dbKeyBlob,
        isAuthBound = authBound,
    )

    @Test
    fun abandonedEnable_armedMarkerOverAPlainVault_revokesTheOrphanCode() {
        // The bug: phase one commits + verifies `vlt_rc` and then holds the
        // auth-bound blob in RAM until the user acknowledges the displayed code. A back
        // press (that screen has no back handler), an auto-lock mid-transcription or a
        // process death abandons the flow — and the vault stays PLAIN while the recovery
        // blob lives on disk forever as a second, live decrypt path the user believes
        // was never created. A later PIN change drops the RAM blob, so it can never be
        // finalized either.
        assertEquals(
            AbandonedEnableAction.PURGE_RECOVERY,
            action(RecoveryBlobPolicy.RECOVERY_PENDING_ARMED, dbKeyBlob = "plain-blob"),
        )
    }

    @Test
    fun abandonedEnable_armedMarkerOverAnAuthBoundVault_onlyClearsTheMarker() {
        // THE brick-safety branch. finalize commits the ab: blob and only then disarms
        // the marker, so a crash between those two steps leaves an armed marker over a
        // LIVE Lever B vault. Revoking `vlt_rc` there would delete the ONLY way back in
        // once the hardware key invalidates (biometric re-enrol / passcode change) —
        // i.e. the fix for a mental-model mismatch would have become a brick. The
        // recovery blob must not be touched at all.
        assertEquals(
            AbandonedEnableAction.CLEAR_MARKER_ONLY,
            action(RecoveryBlobPolicy.RECOVERY_PENDING_ARMED, dbKeyBlob = "ab:live-lever-b-blob"),
        )
    }

    @Test
    fun abandonedEnable_armedMarkerWithNoDbKeyBlob_doesNothing() {
        // Absent (or an unreadable) wrapped DB key: nothing can be concluded about the
        // vault, and deleting a recovery blob is irreversible.
        assertEquals(
            AbandonedEnableAction.NONE,
            action(RecoveryBlobPolicy.RECOVERY_PENDING_ARMED, dbKeyBlob = null),
        )
    }

    @Test
    fun abandonedEnable_absentMarker_doesNothing() {
        // Negative control, and the reason the fix is PROSPECTIVE ONLY: an
        // install that abandoned an enable before this marker existed keeps its orphan
        // rather than having a live recovery code revoked on a guess. Absence is never
        // evidence (the -v2 rule), and a hand-planted `vlt_rc` is never purged.
        assertEquals(AbandonedEnableAction.NONE, action(null, dbKeyBlob = "plain-blob"))
        assertEquals(AbandonedEnableAction.NONE, action(null, dbKeyBlob = "ab:blob"))
    }

    @Test
    fun abandonedEnable_unauthenticatedMarker_doesNothing() {
        // Negative control (the class): the selector-meta reader
        // tolerates a LEGACY CLEARTEXT value, which carries no tag — so anyone who can
        // write vault_selector_prefs.xml (or the iOS NSUserDefaults fallback slot) could
        // otherwise plant one byte and revoke a user's recovery code. Only an
        // AUTHENTICATED read — a value THIS app device-key-sealed — counts.
        assertEquals(
            AbandonedEnableAction.NONE,
            action(RecoveryBlobPolicy.RECOVERY_PENDING_ARMED, authenticated = false, dbKeyBlob = "plain-blob"),
        )
        assertEquals(
            AbandonedEnableAction.NONE,
            action("anything-else", authenticated = true, dbKeyBlob = "plain-blob"),
        )
    }

    @Test
    fun abandonedEnable_damagedOrPlantedMarker_isStoppedByTheAUTHENTICATIONCheck() {
        // Negative control, and the one that has to be stated carefully.
        // A blob-SHAPED value that fails AEAD makes readSelectorMetaRaw THROW
        // (SelectorMetaDamagedException) and the caller's catch does nothing at all;
        // what reaches THIS function from any such read is "not authenticated".
        //
        // So the input must be the ARMED token — i.e. a value that WOULD be
        // actionable if it were authenticated — or the test proves nothing: an
        // unrecognized token exits on the `markerValue != RECOVERY_PENDING_ARMED`
        // branch and would survive the removal of the authentication check entirely.
        // The positive control below is what makes that visible.
        assertEquals(
            AbandonedEnableAction.NONE,
            action(RecoveryBlobPolicy.RECOVERY_PENDING_ARMED, authenticated = false, dbKeyBlob = "plain-blob"),
            "an unauthenticated (damaged / planted) armed marker must never revoke a recovery code",
        )
        assertEquals(
            AbandonedEnableAction.PURGE_RECOVERY,
            action(RecoveryBlobPolicy.RECOVERY_PENDING_ARMED, authenticated = true, dbKeyBlob = "plain-blob"),
            "control: the SAME inputs are actionable when authenticated — so the assertion " +
                "above is pinning the authentication check and nothing else",
        )
    }

    // -- a stale iOS write-ahead journal blocks a SINGLE-KEY vlt_c write --

    @Test
    fun singleKeyDbKeyWrite_isAllowedOnlyWhenTheJournalIsCONFIRMEDAbsent() {
        // The bug this pins: `putStringSync(vlt_c, plain)` reads back (the Keychain
        // item really did change) and therefore passes plainDbKeyReadBackProves — but
        // a journal left by an earlier TORN putStringsSync replays ITS vlt_c at the
        // next KeyValueStore construction and silently reverts it. Both callers of
        // that read-back have already deleted vlt_rc by then, so the replay restores
        // an ab: blob whose hardware key may be dead with no recovery path: a brick.
        assertTrue(
            VaultWriteProofs.singleKeyDbKeyWriteAllowed(journalPending = false),
            "a confirmed-absent journal is the only state in which the write is durable",
        )
        assertFalse(
            VaultWriteProofs.singleKeyDbKeyWriteAllowed(journalPending = true),
            "a pending journal can replay over the write — refuse, keep the recovery blob",
        )
    }

    @Test
    fun singleKeyDbKeyWrite_unreadableJournalRefuses_neverAssumesAbsent() {
        // The fail direction, and it is the same one plainDbKeyReadBackProves uses:
        // `null` is "the store could not tell" (a transient KeyUnavailableException
        // from contains(), which throws there precisely because `false` drives
        // destructive decisions). "Could not tell" must never authorise the
        // irreversible vlt_rc delete that follows.
        assertFalse(
            VaultWriteProofs.singleKeyDbKeyWriteAllowed(journalPending = null),
            "an unreadable store must not be read as 'no journal pending'",
        )
    }

    @Test
    fun singleKeyDbKeyWrite_refusalIsBrickSafe_itIsAPureRefusal() {
        // Brick-safety in one assertion: the guard's ONLY output is permission to
        // write. There is no input combination that returns something other than a
        // boolean gate — no wipe, no delete, no "repair" branch — so a refusal can
        // only ever mean "changed nothing", which leaves the vault exactly as
        // openable as it was (ab: blob + live recovery blob). It is also self-healing:
        // recoverPendingBatch clears the journal at the next construction once the
        // keybag is unlocked, so the refusal cannot become permanent.
        val outcomes = listOf(true, false, null).map { VaultWriteProofs.singleKeyDbKeyWriteAllowed(it) }
        assertEquals(listOf(false, true, false), outcomes)
    }
}
