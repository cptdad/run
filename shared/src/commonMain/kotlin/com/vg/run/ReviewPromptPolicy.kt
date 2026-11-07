package com.vg.run

// ---------------------------------------------------------------------------
// ReviewPromptPolicy — pure decision function for the privacy-respecting
// in-app store-review nudge (Android Play In-App Review /
// `ReviewManagerFactory`; iOS `@Environment(\.requestReview)` /
// `AppStore.requestReview(in:)`).
//
// VAULT-BACKED. Previously
// the counters this policy reasons about (first-unlock timestamp, unlock
// count, a one-shot "already asked" latch) lived OUTSIDE the vault — Android
// `SecurePrefs` (`review_*` keys), iOS `UserDefaults` (`ReviewPromptStore`) —
// on the theory that they were non-sensitive usage telemetry, same treatment
// as the push-deregistration pending flag. It turned out that "non-
// sensitive" is not "free": an AFU (filesystem-image) extraction could read
// the first-unlock wall-clock timestamp and the total unlock count straight
// off disk, without the vault credential, and correlate that timeline against
// other evidence — exactly the class of leak the vault exists to prevent, and
// an inconsistency with the directly comparable throttle (`UpdateNudge`),
// which was already vault-`_meta`. The counters now live in ONE packed vault
// singleton, `review_prompt_v1` (see [readReviewPromptState] /
// [recordReviewPromptUnlock] / [markReviewPromptShown] below) — same shape as
// `update_nudge_v1`: names no contact/group, so it needs no purge-list entry
// and is erased with the vault on wipe. Platform layers migrate an existing
// pre-fix legacy value into the vault the first time a vault opens after this
// change and then delete the legacy keys (see the vault-store section below).
//
// This [ReviewPromptPolicy] object itself still does NO I/O — it stays a pure
// function of its arguments, so it needs no [VaultDatabase] fixture to test.
// Platform layers call the vault-store functions below to read/persist the
// counters, [afterUnlock] once per successful unlock to compute what to
// persist, [shouldPrompt] to decide whether to ask, and — if it returns true
// — actually invoke the OS review sheet and persist `alreadyPrompted = true`
// the moment the request is MADE (the OS alone decides whether it is actually
// rendered; on a debug/TestFlight build Apple always shows it, which is
// exactly why callers must gate [isDebugBuild] on the SAME build-flag
// mechanism [VaultSelector] uses for the Argon2id KDF cost — see
// [isDebugBuildPublic] in BuildFlags.kt — so an e2e/debug build can never see
// this prompt).
// ---------------------------------------------------------------------------

/** Minimum successful unlocks before an established user is eligible. */
// REVIEW_PROMPT_TEST_THRESHOLDS is generated at build time (shared/build.gradle.kts,
// REVIEW_PROMPT_TEST=1): a device-test-only override so a release-configuration
// build can prove the OS review-sheet wiring without waiting 3 days and pairing
// a contact. It is false in every shipping build; the real thresholds follow.
internal val REVIEW_PROMPT_MIN_UNLOCKS: Int = if (REVIEW_PROMPT_TEST_THRESHOLDS) 2 else 5

/** Minimum paired contacts before an established user is eligible — a
 *  contact-less install has nothing to review the app FOR yet. */
internal val REVIEW_PROMPT_MIN_CONTACTS: Int = if (REVIEW_PROMPT_TEST_THRESHOLDS) 0 else 1

/** Minimum elapsed time since the first unlock, in milliseconds (3 days). */
internal val REVIEW_PROMPT_MIN_AGE_MS: Long = if (REVIEW_PROMPT_TEST_THRESHOLDS) 0L else 3L * 24 * 60 * 60 * 1000

/**
 * The (firstUnlockAt, unlockCount) counters to persist after a successful
 * unlock — see [ReviewPromptPolicy.afterUnlock].
 */
data class ReviewPromptCounters(
    val firstUnlockAt: Long,
    val unlockCount: Int,
)

object ReviewPromptPolicy {

    /**
     * True only when EVERY gate passes:
     *  - [isDebugBuild] is false — never in a debug/e2e build, regardless of
     *    the other counters;
     *  - [alreadyPrompted] is false — a strict one-shot per install; once the
     *    OS request has been MADE this never re-arms (there is no "ask again
     *    later" path, by design — a repeated ask is the opposite of privacy-
     *    respecting);
     *  - [unlockCount] is at least [REVIEW_PROMPT_MIN_UNLOCKS];
     *  - [contactCount] is at least [REVIEW_PROMPT_MIN_CONTACTS];
     *  - [firstUnlockAt] is non-null and at least [REVIEW_PROMPT_MIN_AGE_MS]
     *    has elapsed since it, measured against [now].
     *
     * A null [firstUnlockAt] (never recorded, e.g. a fresh install that
     * hasn't gone through [afterUnlock] yet) always answers false rather than
     * throwing — the fail direction is always "don't ask".
     *
     * Never throws: pure arithmetic/comparison over its arguments.
     */
    fun shouldPrompt(
        now: Long,
        firstUnlockAt: Long?,
        unlockCount: Int,
        contactCount: Int,
        alreadyPrompted: Boolean,
        isDebugBuild: Boolean,
    ): Boolean {
        if (isDebugBuild) return false
        if (alreadyPrompted) return false
        if (unlockCount < REVIEW_PROMPT_MIN_UNLOCKS) return false
        if (contactCount < REVIEW_PROMPT_MIN_CONTACTS) return false
        val first = firstUnlockAt ?: return false
        return now - first >= REVIEW_PROMPT_MIN_AGE_MS
    }

    /**
     * The counters to persist after a successful unlock lands. [firstUnlockAt]
     * latches to [now] the first time this is called with a null stored value
     * and never moves again afterwards (a caller re-passing the freshly
     * returned, now non-null value on every later unlock is what keeps it
     * pinned — see the platform callers); [unlockCount] always increments by
     * exactly one.
     *
     * Never throws: pure arithmetic over its arguments.
     */
    fun afterUnlock(
        now: Long,
        firstUnlockAt: Long?,
        unlockCount: Int,
    ): ReviewPromptCounters =
        ReviewPromptCounters(
            firstUnlockAt = firstUnlockAt ?: now,
            unlockCount = unlockCount + 1,
        )
}

// ---------------------------------------------------------------------------
// Vault-backed storage. Exactly the `UpdateNudge.kt` shape: one
// packed string under one `_meta` key, read/written through [VaultDatabase]
// only, `@Throws`-safe on both platforms (iOS `putMeta` genuinely throws on a
// locked keybag mid-write; every entry point here swallows it and fails
// toward "don't ask" / "don't lose data" as documented per function below).
//
// `review_prompt_v1` = "<firstUnlockAtMs, or empty for null>|<unlockCount>|<alreadyPrompted 0/1>"
// ---------------------------------------------------------------------------

/** Encrypted per-vault meta key holding the packed review-prompt counters. */
internal const val REVIEW_PROMPT_META_KEY = "review_prompt_v1"

/** Separator between the three packed fields — same character as [UpdateNudge]. */
private const val REVIEW_PROMPT_SEPARATOR = '|'

/**
 * Vault round-trip snapshot of the review-prompt counters — the same fields
 * [ReviewPromptPolicy.shouldPrompt] takes, plus the one-shot latch.
 */
data class ReviewPromptVaultState(
    val firstUnlockAt: Long?,
    val unlockCount: Int,
    val alreadyPrompted: Boolean,
)

/** Fresh-install defaults — also what a missing or unparseable vault row reads as. */
private val REVIEW_PROMPT_DEFAULT_STATE =
    ReviewPromptVaultState(firstUnlockAt = null, unlockCount = 0, alreadyPrompted = false)

private fun packReviewPromptState(state: ReviewPromptVaultState): String {
    val first = state.firstUnlockAt?.toString() ?: ""
    return "$first$REVIEW_PROMPT_SEPARATOR${state.unlockCount}$REVIEW_PROMPT_SEPARATOR${if (state.alreadyPrompted) 1 else 0}"
}

/** Strict 3-field parse; any unrecognised shape returns null (treated exactly
 *  like "no key" by every caller — never a suppression, only a possible re-ask). */
private fun unpackReviewPromptState(raw: String): ReviewPromptVaultState? {
    val fields = raw.split(REVIEW_PROMPT_SEPARATOR)
    if (fields.size != 3) return null
    val firstUnlockAt = if (fields[0].isEmpty()) null else (fields[0].toLongOrNull() ?: return null)
    val unlockCount = fields[1].toIntOrNull() ?: return null
    val alreadyPrompted = when (fields[2]) {
        "0" -> false
        "1" -> true
        else -> return null
    }
    return ReviewPromptVaultState(firstUnlockAt, unlockCount, alreadyPrompted)
}

/**
 * Current vault-backed review-prompt state. Never throws: a vault whose
 * `getMeta` fails, or a row that doesn't parse, reads as the fresh-install
 * defaults — same fail-toward-"don't ask" direction as
 * [ReviewPromptPolicy.shouldPrompt]. Read-only; never migrates or writes (see
 * [recordReviewPromptUnlock] for the one path that does).
 */
fun readReviewPromptState(vault: VaultDatabase): ReviewPromptVaultState =
    try {
        vault.getMeta(REVIEW_PROMPT_META_KEY)?.let(::unpackReviewPromptState) ?: REVIEW_PROMPT_DEFAULT_STATE
    } catch (_: Exception) {
        REVIEW_PROMPT_DEFAULT_STATE
    }

/**
 * Records a successful unlock into the vault: reads the current row (falling
 * back to [legacyFallback] — a platform-supplied pre-fix snapshot from its own
 * legacy store — ONLY when the vault has no `review_prompt_v1` row yet, so an
 * upgrading install's real history is preserved rather than restarted),
 * applies [ReviewPromptPolicy.afterUnlock] on top of it, and writes the packed
 * result back. `alreadyPrompted` is carried through untouched — only
 * [markReviewPromptShown] ever latches it.
 *
 * The read, the policy application, and the write are ONE try block: if the
 * read throws, nothing is written — a transient failure must never overwrite
 * real counters with defaults. Returns true iff the write is confirmed to
 * have landed; platform callers must only delete their legacy pre-fix keys
 * after a `true` result (never delete unread-back state — the same
 * never-lose-the-only-copy discipline `putStringsSync` enforces on iOS's
 * Keychain writes).
 */
fun recordReviewPromptUnlock(
    vault: VaultDatabase,
    now: Long,
    legacyFallback: ReviewPromptVaultState? = null,
): Boolean =
    try {
        val stored = vault.getMeta(REVIEW_PROMPT_META_KEY)
        val current = stored?.let(::unpackReviewPromptState) ?: legacyFallback ?: REVIEW_PROMPT_DEFAULT_STATE
        val updated = ReviewPromptPolicy.afterUnlock(
            now = now,
            firstUnlockAt = current.firstUnlockAt,
            unlockCount = current.unlockCount,
        )
        vault.putMeta(
            REVIEW_PROMPT_META_KEY,
            packReviewPromptState(
                ReviewPromptVaultState(
                    firstUnlockAt = updated.firstUnlockAt,
                    unlockCount = updated.unlockCount,
                    alreadyPrompted = current.alreadyPrompted,
                ),
            ),
        )
        true
    } catch (_: Exception) {
        false
    }

/**
 * Marks the OS review request as MADE — a one-shot latch, WRITE ON ASK (same
 * "write on show" discipline as [markUpdateNudgeShown]) so a same-turn
 * teardown between the call and the OS sheet actually rendering can never
 * re-ask on the next unlock. Preserves the current firstUnlockAt/unlockCount
 * untouched. The read and the write are ONE try block, same reasoning as
 * [recordReviewPromptUnlock]: a read failure aborts the whole call rather
 * than writing `alreadyPrompted = true` over defaulted (potentially wrong)
 * counters. Never throws: a lost write only costs one extra ask attempt this
 * session, bounded by the RAM-only once-per-session latch both platforms already
 * keep (`reviewPromptEvaluated`), never a crash.
 */
fun markReviewPromptShown(vault: VaultDatabase) {
    try {
        val stored = vault.getMeta(REVIEW_PROMPT_META_KEY)
        val current = stored?.let(::unpackReviewPromptState) ?: REVIEW_PROMPT_DEFAULT_STATE
        vault.putMeta(REVIEW_PROMPT_META_KEY, packReviewPromptState(current.copy(alreadyPrompted = true)))
    } catch (_: Exception) {
        // Cosmetic — see kdoc.
    }
}
