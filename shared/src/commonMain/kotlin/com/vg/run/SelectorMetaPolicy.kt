package com.vg.run

// ---------------------------------------------------------------------------
// SelectorMetaPolicy — the selector-metadata plaintext tokens, their fixed-length
// padding, the blob-shape classifier, and the PURE read-policy decisions over
// `vlt_m` / `vlt_lvl`.
//
// "Selector metadata" is every small device-key-AEAD'd token VaultSelector
// keeps next to the credential: `vlt_m` (mode), `vlt_lvl` (tier), `vlt_rp`
// (recovery-enable pending) and `vlt_abk` (auth-bound key scheme) — see
// [VaultStoreKeys]. All four are sealed under the per-key context
// `VaultCryptoContexts.SELECTOR_META_PREFIX + key` by VaultSelector's
// selector-meta IO, which stays in VaultSelector (it needs the instance's
// store and device key).
//
// Pure so commonTest can pin every branch: KeyValueStore and CryptoProvider are expect classes with
// no common fake. Two readers here have OPPOSITE fail directions on purpose —
// [passphraseModeFromRead] (entry widget, fails OPEN to the passphrase field) and
// [credentialKindProvenFromRead] (tier upgrade, fails CLOSED to "unproven"). The
// internals doc forbids merging them.
// ---------------------------------------------------------------------------

internal object SelectorMetaPolicy {
    /** `vlt_m` token: 6-digit PIN keypad. */
    const val MODE_PIN = "pin"

    /** `vlt_m` token: free-text passphrase (Lever A). */
    const val MODE_PASSPHRASE = "phrase"

    /** `vlt_abk` token: the current auth-bound blob is wrapped by the strict (biometric-only) key. */
    const val AUTHBOUND_SCHEME_STRICT = "2"

    // Selector-meta plaintext (vlt_m mode, vlt_lvl tier) is NUL-padded
    // to this FIXED length before the device-key AEAD, so the (length-preserving)
    // AES-GCM ciphertext is a CONSTANT length across every credential mode and
    // protection tier. That closes the at-rest length side-channel that
    // distinguished "pin" from "phrase" and CASUAL from
    // PRIVATE/MAXIMUM with no device key and no decryption. Every
    // real token is short ASCII (≤ "hardened" = 8 bytes) and never contains a NUL,
    // so the padding is unambiguous and reversible.
    const val SELECTOR_META_PADDED_LEN = 16

    /** NUL-pad a selector-meta token to [SELECTOR_META_PADDED_LEN]. */
    internal fun padSelectorMetaPlaintext(value: String): ByteArray {
        val raw = value.encodeToByteArray()
        check(raw.size <= SELECTOR_META_PADDED_LEN) { "selector-meta token too long to pad" }
        return raw + ByteArray(SELECTOR_META_PADDED_LEN - raw.size)
    }

    /**
     * Strip the trailing NUL padding [padSelectorMetaPlaintext] adds. Also a
     * transparent no-op on LEGACY unpadded plaintext (installs provisioned before
     * the padding) — those tokens carry no trailing NUL — so the migration is lossless.
     */
    internal fun unpadSelectorMetaPlaintext(bytes: ByteArray): String {
        var end = bytes.size
        while (end > 0 && bytes[end - 1] == 0.toByte()) end--
        return bytes.copyOfRange(0, end).decodeToString()
    }

    /**
     * True when a stored selector-meta value is SHAPED like one of our
     * device-key AEAD blobs: base64 that decodes to at least IV(12)+tag(16)
     * bytes. The legacy cleartext tokens ("pin"/"phrase"/level names) all
     * decode to ≤ 6 bytes (or fail to decode), so a value this shape that
     * fails decrypt is provably a DAMAGED blob, never legacy cleartext —
     * see [VaultSelector.readSelectorMeta]. Internal so commonTest can pin the classifier
     * (the expect-class CryptoProvider has no common fake seam).
     */
    internal fun isSelectorMetaBlobShaped(raw: String): Boolean = try {
        decodeBase64(raw).size >= 12 + 16
    } catch (_: Exception) {
        false
    }

    /**
     * Threshold for the LAUNCH-TIME "interrupted wipe" re-trigger — the check
     * all four pre-unlock credential screens run at COMPOSITION time against
     * the already-accumulated durable counter, before the user has entered
     * anything. Extracted pure so one commonTest pins the rule for both
     * platforms; consumed through [VaultSelector.maxConsecutiveAttemptsForInterruptedWipe].
     *
     * It is deliberately NOT [CredentialPolicy.maxConsecutiveAttempts]. That
     * budget governs a NEW attempt and is allowed to TIGHTEN retroactively —
     * an unauthenticated tier routes to MAXIMUM's 5, and so does a damaged
     * blob. Comparing an ALREADY-ACCUMULATED counter against a
     * budget that shrank after those failures were recorded destroys a vault
     * whose owner entered nothing wrong: a genuine pre-encryption legacy-cleartext
     * CASUAL vault can sit at 5–9 stranded failures (its budget was 10, and
     * only a successful unlock clears the counter) and would be wiped the
     * moment the app is opened after upgrading.
     *
     * So the re-trigger uses the tier budget ONLY where the read proves the
     * budget cannot have shrunk underneath the counter:
     *  - nothing stored ([present] false) — a pre-slider vault, whose budget
     *    has always been [CredentialPolicy.MAX_CONSECUTIVE_ATTEMPTS];
     *  - an AUTHENTICATED, parseable tier — that tier's own budget. A tier
     *    change only happens while UNLOCKED and a successful unlock resets
     *    the counter to 0, so an authenticated tier can never be tighter than
     *    the budget the stranded failures were counted under;
     *  - everything else — unauthenticated legacy cleartext, an authenticated
     *    but UNPARSEABLE token (a newer binary's tier, whose budget is
     *    unknown), a damaged blob or a device-key outage (both handled by the
     *    caller's catch) — [ProtectionLevel.MOST_LENIENT_MAX_ATTEMPTS], the
     *    largest budget any tier ever had.
     *
     * The result is therefore never SMALLER than the new-attempt budget, and
     * never larger than [ProtectionLevel.MOST_LENIENT_MAX_ATTEMPTS]: this can
     * only ever DELAY a re-trigger, never fire one early. A genuinely
     * interrupted wipe still completes — the counter is durably at/over the
     * budget in force, so the very next wrong entry trips
     * `attempt >= maxAttempts` and re-fires the wipe even in the lenient
     * branches, and the 24h window cap (checked at launch too, unchanged) is
     * untouched by this relaxation.
     */
    internal fun interruptedWipeAttemptThreshold(
        storedLevel: ProtectionLevel?,
        present: Boolean,
        authenticated: Boolean,
    ): Int = when {
        !present -> CredentialPolicy.MAX_CONSECUTIVE_ATTEMPTS
        !authenticated || storedLevel == null -> ProtectionLevel.MOST_LENIENT_MAX_ATTEMPTS
        else -> storedLevel.maxConsecutiveAttempts
    }

    /**
     * The tier an UNPROVEN `vlt_lvl` claim is worth: the LOWEST one, so it can
     * never satisfy a floor. Declaration order in [ProtectionLevel] IS the
     * strength order every floor comparison uses (`level.ordinal < floor.ordinal`
     * — [DeviceLockPolicy.needsForcedMigration] / [DeviceLockPolicy.isSelectable]),
     * so "weakest" is `entries.first()` rather than a hardcoded tier name.
     */
    internal val UNPROVEN_LEVEL: ProtectionLevel = ProtectionLevel.entries.first()

    /**
     * The tier a `vlt_lvl` read PROVES this vault is
     * at — for the Lever A CREDENTIAL FLOOR decision only.
     *
     * The provenance change gave `vlt_lvl` a provenance flag and routed every
     * DESTRUCTIVE-ENFORCEMENT read of an unauthenticated value to
     * `Present(MAXIMUM)` ([VaultSelector.protectionLevelForEnforcement]). That is fail-SECURE
     * for a timer, a budget and an auto-lock — the shorter/tighter number is
     * always the safe answer there — and it is fail-OPEN for the one decision
     * that asks the opposite question: "is this vault AT OR ABOVE the floor its
     * device requires?" (`MAXIMUM.ordinal < MAXIMUM.ordinal` is false ⇒ no
     * migration). So the same slot needs two readers with OPPOSITE fail
     * directions, and this is the floor one:
     *
     *  - [present] false — nothing was ever chosen. NOT "below the floor":
     *    that is a legacy pre-slider vault and the one-time CHOOSER owns it,
     *    which is itself gated by [DeviceLockPolicy.isSelectable] (nothing
     *    below MAXIMUM is selectable on a lock-less device) and whose write
     *    self-heals the slot to an authenticated blob. `null`.
     *  - [authenticated] false — LEGACY CLEARTEXT, or an attacker's forgery,
     *    indistinguishable by construction (the fallback has no tag to check).
     *    Planting the seven ASCII bytes `maximum` in vault_selector_prefs.xml
     *    (or the iOS NSUserDefaults slot `KeyValueStore` falls back to) decodes
     *    to 5 bytes — under [isSelectorMetaBlobShaped]'s 28-byte floor — so it
     *    is read back verbatim, and it used to satisfy the floor forever on a
     *    phone with no lock screen, i.e. it silently disarmed the ONE control
     *    written for that device class (CR-1 collapsed to a ~20-bit PIN). An
     *    unauthenticated value therefore proves NOTHING and is worth
     *    [UNPROVEN_LEVEL] — the weakest tier, which satisfies no floor.
     *  - authenticated but UNPARSEABLE ([storedLevel] null) — a tier written by
     *    a NEWER binary. Authenticated, so not a forgery, but its strength is
     *    unknown to this build; `null` routes it to the same gated chooser as
     *    "never chosen" rather than forcing an irreversible credential change on
     *    a tier that may well already be above the floor.
     *
     * A DAMAGED blob and a device-key OUTAGE are mapped to `null` by the caller
     * for the same reason as the first bullet — see [VaultSelector.protectionLevelForFloorCheck].
     *
     * BRICK-SAFETY: nothing downstream of this can wipe. Its consumers are the
     * forced-tier route (a credential-change flow) and the honest DISPLAY
     * ([VaultSelector.currentProtectionLevel]); the strictest thing a wrong answer can cost
     * is one pass through a screen that sets a passphrase.
     */
    internal fun provenProtectionLevel(
        storedLevel: ProtectionLevel?,
        present: Boolean,
        authenticated: Boolean,
    ): ProtectionLevel? = when {
        !present -> null
        !authenticated -> UNPROVEN_LEVEL
        else -> storedLevel
    }

    /**
     * Which ENTRY WIDGET a stored `vlt_m` read selects.
     *
     * `vlt_m` has the same legacy-cleartext
     * fallback `vlt_lvl` has, so the same three ASCII bytes a filesystem-write
     * attacker can plant (`pin`) were returned verbatim — and, unlike `vlt_lvl`,
     * this reader discarded the provenance flag entirely. On a MAXIMUM /
     * passphrase vault the plant renders the 6-DIGIT KEYPAD: Lever A's ≥70-bit
     * floor guarantees the real credential is not six digits, every 6-digit
     * entry auto-submits and DURABLY counts, and MAXIMUM's budget of 5 fires an
     * emergency wipe with no confirmation and no recovery code (that is tied to
     * Lever B / PRIVATE). A three-byte unauthenticated write therefore destroyed
     * the vault.
     *
     * So an UNAUTHENTICATED value fails OPEN to the passphrase field — the exact
     * destination, and the exact reason, the damaged-blob branch of
     * [VaultSelector.isPassphraseMode] already documents: the unlock path is
     * input-widget-agnostic (both widgets hand `evalCredential` a String), so a
     * PIN user can still type six digits into a text field, while the keypad
     * hard-locks a passphrase user out. Cost is a cosmetic mislabel on a genuine
     * pre-encryption cleartext install; benefit is that no forgeable byte can pick the
     * widget that guarantees wrong entries.
     *
     * ABSENT stays PIN: that is a legacy install from before `vlt_m` was always written, not a claim anyone
     * wrote, and its credential really is a 6-digit PIN.
     */
    internal fun passphraseModeFromRead(value: String?, authenticated: Boolean): Boolean = when {
        value == null -> false
        !authenticated -> true
        else -> value == MODE_PASSPHRASE
    }

    /**
     * What a `vlt_m` read PROVES about the
     * credential's KIND — the TIER-UPGRADE reader, three-state on purpose.
     *
     * [passphraseModeFromRead] above answers "which entry widget?" and fails
     * OPEN to the passphrase field for anything it cannot authenticate, because
     * the digit keypad hard-locks a passphrase user out. That direction is
     * correct there and catastrophic here: the tier screens read it as "a
     * passphrase is already set", so ≥28 bytes of base64 garbage planted in
     * `vlt_m` (a DAMAGED blob — [isSelectorMetaBlobShaped]) turned "upgrade to
     * MAXIMUM" into a pure metadata write. That persists an AEAD-AUTHENTICATED
     * `vlt_lvl = maximum` over an UNCHANGED 6-digit PIN, which permanently
     * satisfies [DeviceLockPolicy.needsForcedMigration] — the whole lock-less
     * floor — and is inherited by a later, lower-capability attacker who only
     * needs to image and grind.
     *
     *  - `true`  — an AUTHENTICATED `phrase`: proof of a Lever A passphrase.
     *  - `false` — an AUTHENTICATED `pin`, or a genuinely ABSENT value. Absence
     *    is a legacy install (`vlt_m` is now ALWAYS written, PIN
     *    included), i.e. a vault old enough to predate passphrase mode; it is
     *    not a claim anyone wrote, and its credential really is a PIN. Proven
     *    PIN and proven-nothing lead to the same (safe) place anyway — both
     *    require the rotation — so this costs nothing either way.
     *  - `null`  — proves NOTHING: unauthenticated legacy cleartext or a plant
     *    (indistinguishable by construction), or an authenticated token this
     *    build does not recognise (written by a NEWER binary). The DAMAGED-blob
     *    and device-key-OUTAGE cases map here too, in the caller's catch.
     *
     * Never a wipe input and never a refusal: everything unproven simply routes
     * the user through the credential change, which re-writes `vlt_m` as an
     * authenticated blob on the way — so a genuine legacy install self-heals
     * instead of being punished.
     */
    internal fun credentialKindProvenFromRead(value: String?, authenticated: Boolean): Boolean? = when {
        value == null -> false
        !authenticated -> null
        value == MODE_PASSPHRASE -> true
        value == MODE_PIN -> false
        else -> null
    }

    /** Result of [resolveChangeCredentialMode]: what to persist, and what floor to apply. */
    internal class ChangeModeDecision(
        val modeToWrite: String?,
        val resultingPassphrase: Boolean,
    )

    /**
     * Resolve a MODE-PRESERVING rotation's outcome: the `vlt_m` value to persist
     * in the atomic swap, and whether the NEW credential must clear the Lever A
     * passphrase floor. (An explicit PIN↔passphrase switch never reaches here —
     * `newMode` decides both.)
     *
     * Three inputs, because a stored mode has three trust levels:
     *  - AUTHENTICATED (or genuinely absent) — the vault's real mode. Honour it,
     *    and re-persist it so a legacy absent/unpadded value migrates.
     *  - DAMAGED (2026-07-14) — derive the resulting mode from the NEW
     *    credential's own shape, so a damaged blob can't hold every 6-digit PIN
     *    to the passphrase floor (which blocked PIN rotation forever, with no
     *    write to heal the damage).
     *  - UNAUTHENTICATED — legacy cleartext, or a
     *    plant, and indistinguishable by construction. This one is load-bearing
     *    for the entry-widget rule: once [passphraseModeFromRead] fails open, ChangePinScreen /
     *    ChangePinView render the free-text field for such an install, so trusting
     *    the token would write an AUTHENTICATED `pin` over a vault whose credential
     *    is now a passphrase — laundering the plant into a permanent keypad and the
     *    very wipe that rule closes. Derive the persisted mode from the new credential's
     *    SHAPE, exactly like the damaged case.
     *
     * The floor is the one place the untrusted token still gets a vote, and only
     * in the TIGHTENING direction: `derived || claims-passphrase`. That keeps
     * today's denial of a 6-digit "rotation" of a cleartext-`phrase` vault
     * (WEAK_CREDENTIAL) intact — this must never become a silent Lever A
     * downgrade path — while a passphrase-shaped credential still heals the mode.
     */
    internal fun resolveChangeCredentialMode(
        storedMode: String?,
        storedAuthenticated: Boolean,
        storedDamaged: Boolean,
        newCredentialIsPinShaped: Boolean,
    ): ChangeModeDecision {
        if (!storedDamaged && (storedMode == null || storedAuthenticated)) {
            val passphrase = storedMode == MODE_PASSPHRASE
            return ChangeModeDecision(
                modeToWrite = if (passphrase) MODE_PASSPHRASE else MODE_PIN,
                resultingPassphrase = passphrase,
            )
        }
        val derivedPassphrase = !newCredentialIsPinShaped
        return ChangeModeDecision(
            modeToWrite = if (derivedPassphrase) MODE_PASSPHRASE else MODE_PIN,
            resultingPassphrase = derivedPassphrase || storedMode == MODE_PASSPHRASE,
        )
    }
}
