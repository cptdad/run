package com.vg.run

/**
 * Single source of truth for the conversation "rune whisper" status vocabulary, the
 * first-fetch verdict, the transient-fade rule, and the auto-scroll gate.
 *
 * These strings + rules were previously duplicated as LITERALS across four screens —
 * ConversationScreen / GroupConversationScreen (Android) and ConversationView /
 * GroupViews (iOS) — and compared by string EQUALITY across files. That duplication is
 * the standing bug incubator: the group scroll-gate drift
 * and several iOS whisper/verdict guard-drifts all came from the 1:1 and group
 * screens diverging. Centralizing here in commonMain — so BOTH platforms and BOTH screen
 * types call the same code (iOS via `ConversationRunes.shared`) — removes the drift at
 * its root: the reference (1:1) behaviour and the group behaviour are now literally the
 * same definitions.
 *
 * LOCALIZATION: the `CONSULTING`/`WHISPER`/etc. constants are now resource-key TOKENS,
 * not display text — the four render sites compare/store these tokens (equality,
 * `LaunchedEffect(runeWhisper)` keys, SwiftUI `.id(whisper)`) exactly as before, and
 * call [label] only at the point of display to resolve the token to localized text via
 * [platformString]. Every token below MUST exist as a key in
 * `androidApp/src/main/res/values/strings_shared.xml` (runes_* group).
 */
object ConversationRunes {
    /** On open, while the first poll is in flight (only shown when the relay is up). */
    const val CONSULTING = "runes_consulting"

    /** First-fetch verdict — at least one message present. */
    const val WHISPER = "runes_whisper"

    /** First-fetch verdict — no messages. */
    const val SILENT = "runes_silent"

    /** Minimum time to hold [CONSULTING] before revealing the verdict (mystic pacing). */
    const val VERDICT_MIN_HOLD_MS = 1600L

    /** The first-fetch verdict TOKEN (resolve via [label] to display it). */
    fun verdict(hasMessages: Boolean): String = if (hasMessages) WHISPER else SILENT

    /** Resolves a rune-whisper TOKEN (one of the constants above) to localized display
     *  text. Render sites must call this instead of showing [runeWhisper] directly. */
    fun label(state: String): String = platformString(state)

    /**
     * True if [whisper] is a transient verdict/notice that should auto-fade — as opposed
     * to the persistent [CONSULTING] state. Replaces the per-file
     * string-equality checks the fade effects duplicated (and drifted on).
     */
    fun isTransientVerdict(whisper: String?): Boolean =
        whisper == WHISPER || whisper == SILENT

    /**
     * Whether a conversation list should auto-scroll to the latest message: ONLY when a
     * message was actually appended (not on a relay re-serve of already-known blobs) and
     * the list is non-empty. Centralizes the 1:1 fix (M8) and its group sibling (AND-3) so
     * they cannot diverge again.
     *
     * NOTE: called by both ANDROID conversation screens — from an effect keyed on the
     * message COUNT, never from inside the poll loop (CONV-1: a scroll cancelled by a
     * competing scroll through LazyListState's MutatorMutex would otherwise cancel — and
     * kill — the poll coroutine, silently stalling the drain). [appendedNew] is therefore
     * the count delta. The iOS screens encode the SAME rule structurally via
     * `.onChange(of: messages.count)` — the count changes only when a genuinely new message
     * is appended (dedup keeps it stable on a re-serve), so they do not call this function.
     * (The vocabulary + verdict
     * + fade rule below ARE shared with iOS via `.shared`; this scroll gate is the one
     * member iOS mirrors rather than calls.)
     */
    fun shouldAutoScrollToLatest(appendedNew: Boolean, hasMessages: Boolean): Boolean =
        appendedNew && hasMessages
}
