package com.vg.run

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// The group-text isolation rule, AS A SOURCE GUARD: **no group-inbox signal may reach a contact row.**
//
// `GroupTextNeverOnContactTest` (commonTest) pins the behaviour across the whole
// rollout matrix. This pins the SHAPE, and the two are not the same claim: a
// behavioural test can only cover the states that exist today, which is exactly
// how "just one more term" gets added to the contact count later. The property
// is "nowhere", not "not in these cases".
//
// It scans the BODIES of the only two functions that ever compute a contact's
// unread number — `GroupUnreadTally.contactCountsFrom` (the steady-state sweep's
// arithmetic) and `GroupUnreadTally.primeUnreadCountFor` (the connect-time
// prime's) — plus the public entry point `GroupManager.contactUnreadCounts`, with
// comments stripped so the prose ABOUT the invariant cannot satisfy or trip it.
// It searches GroupManager.kt and GroupUnreadTally.kt together.
//
// It lives in androidUnitTest because that is the only JVM test source set with a
// filesystem, the same reason `LegacyMessageTableRemovalTest` and
// `MigrationSchemaPinTest` do.
// ---------------------------------------------------------------------------
class GroupTextNeverOnContactSourceGuardTest {

    @Test
    fun theContactCountDerivationNamesNoGroupInboxSymbol() {
        for (fn in GUARDED_FUNCTIONS) {
            val body = bodyOf(fn)
            assertTrue(
                body.length > 40,
                "$fn was not found in GroupManager.kt / GroupUnreadTally.kt (or is empty) — a guard that silently " +
                    "scans nothing passes forever. If it was renamed, rename it here too.",
            )
            for (symbol in FORBIDDEN) {
                assertFalse(
                    body.contains(symbol),
                    "R8 VIOLATION: `$fn` references `$symbol`. A group message must NEVER put " +
                        "the unread bubble on the contact name, and the contact count is " +
                        "derived from the TEXT inbox, the LEGACY compensator and screenshot " +
                        "notices — nothing else. If you need group state here, you are about " +
                        "to reintroduce the 2026-09-05 production bug.",
                )
            }
        }
    }

    /**
     * Each guarded signature occurs EXACTLY ONCE across the two scanned files.
     *
     * [bodyOf] takes the FIRST match and then the next `{`. A same-name delegate
     * (say an expression-body `private fun primeUnreadCountFor(…) = tally.…` in
     * GroupManager) has no `{` of its own, so the guard would scan the NEXT
     * function's body instead and could pass vacuously. Exactly one declaration
     * per signature keeps the scanned body the real one.
     */
    @Test
    fun eachGuardedSignatureOccursExactlyOnce() {
        val src = scanned()
        for (fn in GUARDED_FUNCTIONS) {
            val n = Regex(Regex.escape(fn) + "\\b").findAll(src).count()
            assertEquals(
                1, n,
                "`$fn` must be declared exactly once across GroupManager.kt and " +
                    "GroupUnreadTally.kt (found $n) — a same-name delegate would make " +
                    "the guard scan the wrong body.",
            )
        }
    }

    /**
     * EVERY forbidden symbol must still EXIST in the file it is forbidden from.
     *
     * Without this the guard decays silently: rename `grpNoticedByContact` and the
     * entry below stops matching anything, the "does the contact path mention it?"
     * test keeps passing, and the rule is no longer enforced for that symbol at all. A
     * rename must therefore fail HERE — loudly, with the new name in hand — rather
     * than quietly delete a rule. Same discipline the guarded-function list gets
     * from its `body.length > 40` assertion.
     */
    @Test
    fun everyForbiddenSymbolStillExistsSomewhereInTheSource() {
        // The union of the files that own the group-inbox mechanism: some of
        // these symbols are GroupUnreadTally's RAM state, some GroupManager's
        // orchestration, some MessageManager's wire/peek surface, and a rename in
        // any of them must fail here.
        val src = scanned() + source(MESSAGE_MANAGER)
        for (symbol in FORBIDDEN) {
            assertTrue(
                src.contains(symbol),
                "`$symbol` no longer appears in GroupManager.kt, GroupUnreadTally.kt or MessageManager.kt, so " +
                    "forbidding it from the contact-count path enforces NOTHING. If it was " +
                    "renamed, update FORBIDDEN with the new name; if it was deleted, delete the " +
                    "entry — do not leave a rule that cannot fire.",
            )
        }
    }

    /**
     * The GROUP dot, conversely, MUST read them — otherwise the guard above could
     * be satisfied by deleting the whole mechanism, which is the classic way a
     * source guard turns into decoration.
     */
    @Test
    fun theGroupDotReallyDoesReadTheGroupInboxState() {
        val unattributed = bodyOf("fun unattributedContacts")
        assertTrue(unattributed.contains("groupInboxPendingByContact"), "the presence bump reads the depth")
        assertTrue(unattributed.contains("grpNoticedByContact"), "…minus what a `gi` notice already attributed")
        assertTrue(
            bodyOf("private fun presenceBumpedGroups").contains("unattributedContacts"),
            "the presence bump is driven by the unattributed set",
        )
        assertTrue(
            bodyOf("fun groupUnreadCounts").contains("presenceBumpedGroups"),
            "the group dot must actually apply the bump",
        )
    }

    /** The detector must be able to fire. (Fabricated source.) */
    @Test
    fun theDetectorActuallyDetects() {
        val bad = "val pending = unreadLock.withLock { groupInboxPendingByContact[contactId] ?: 0 }"
        assertTrue(FORBIDDEN.any { bad.contains(it) }, "detector missed the obvious violation")
        // …and does not false-positive on the LEGACY compensator, which is a
        // TEXT-inbox term and legitimately belongs in the contact count.
        val good = "val pending = unreadLock.withLock { groupPendingByContact[contactId] ?: 0 }"
        assertTrue(FORBIDDEN.none { good.contains(it) }, "detector false-positived on the legacy compensator")
    }

    @Test
    fun theSharedPurgeListCarriesTheBackfillThrottle() {
        // Cross-file coupling that only bites at delete/re-pair time: `grp-ann/` is
        // per contact and must be in the ONE list both actuals iterate.
        assertTrue(
            MessageManager.groupBackfillKey("x") in ratchetMetaKeysForContact("x"),
            "the group-inbox backfill throttle must be purged with its contact",
        )
        assertEquals("grp-ann/x", MessageManager.groupBackfillKey("x"))
    }

    // -----------------------------------------------------------------------

    /**
     * The body of the first declaration matching [signature], comments stripped,
     * by brace counting from the opening `{`. Crude on purpose: it must not depend
     * on a Kotlin parser, and any drift makes the body EMPTY, which the length
     * assertion above turns into a loud failure rather than a silent pass.
     */
    private fun bodyOf(signature: String): String {
        val src = scanned()
        val at = src.indexOf(signature)
        if (at < 0) return ""
        var i = src.indexOf('{', at)
        if (i < 0) return ""
        var depth = 0
        val start = i
        while (i < src.length) {
            when (src[i]) {
                '{' -> depth++
                '}' -> { depth--; if (depth == 0) return src.substring(start, i + 1) }
            }
            i++
        }
        return ""
    }

    /** GroupManager.kt + GroupUnreadTally.kt, comments stripped. */
    private fun scanned(): String = source(GROUP_MANAGER) + "\n" + source(GROUP_UNREAD_TALLY)

    private fun source(path: String = GROUP_MANAGER): String {
        val f = File(repoRoot(), path)
        assertTrue(f.isFile, "scanned source is missing: $path")
        return f.readText().replace(BLOCK_COMMENT, " ").replace(LINE_COMMENT, " ")
    }

    /** Walks up to the directory holding `settings.gradle.kts`; fails loudly. */
    private fun repoRoot(): File {
        var d: File? = File("").absoluteFile
        while (d != null) {
            if (File(d, "settings.gradle.kts").isFile) return d
            d = d.parentFile
        }
        throw AssertionError(
            "repo root not found above ${File("").absoluteFile} — this guard must never " +
                "silently scan nothing",
        )
    }

    private companion object {
        const val GROUP_MANAGER = "shared/src/commonMain/kotlin/com/vg/run/GroupManager.kt"
        const val MESSAGE_MANAGER = "shared/src/commonMain/kotlin/com/vg/run/MessageManager.kt"
        const val GROUP_UNREAD_TALLY = "shared/src/commonMain/kotlin/com/vg/run/GroupUnreadTally.kt"

        val BLOCK_COMMENT = Regex("""/\*.*?\*/""", RegexOption.DOT_MATCHES_ALL)
        val LINE_COMMENT = Regex("""//[^\n]*""")

        /** Every function that computes, or returns, a CONTACT unread number. */
        val GUARDED_FUNCTIONS = listOf(
            "fun contactUnreadCounts",
            "fun contactCountsFrom",
            "fun primeUnreadCountFor",
        )

        /**
         * Group-inbox symbols. Deliberately NOT including `groupPendingByContact`:
         * that is the LEGACY compensator for a group text sitting on the contact's
         * own TEXT inbox (rollout cells 2/3/4), so it is a text-inbox
         * term and belongs in the contact count until it is deleted in N+2.
         */
        val FORBIDDEN = listOf(
            "groupInboxPendingByContact",
            "grpNoticedByContact",
            "presenceBumpedGroups",
            "notePeekedGroupInboxDepths",
            "peekGroupInboxPending",
            "inboundGroupPeekTargets",
            "groupUnread",
            "DIR_INBOUND_GRP",
            "CHANNEL_TAG_GRP",
            "Chan.GRP",
            "fromGroupInbox",
            "ACTIVITY_FIELD_GROUP_INBOX",
            // The presence bump's notice grace (2026-11-13) — group-dot state only.
            "unattributedSinceMs",
            "noticeCheckedAfterGrace",
            "controlInboxChecked",
        )
    }
}
