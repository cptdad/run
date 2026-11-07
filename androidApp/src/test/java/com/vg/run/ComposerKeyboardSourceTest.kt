package com.vg.run

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Guards "keyboard privacy scales with the protection tier" (product decision
 * 2026-09-20; shared decision = [ComposerKeyboardPolicy]).
 *
 * Before this feature, BOTH message composers hardcoded
 * `KeyboardType.Password` unconditionally — private/no-suggestions, but
 * Gboard/Samsung Keyboard both drop the emoji key in password mode, so
 * Android users had NO emoji at all regardless of the chosen protection
 * tier. This wires a per-tier branch into `RunViewModel` and both composer
 * screens, mirroring exactly how [PeriodicReauthLockSourceTest] guards the
 * re-auth wiring: `RunViewModel`/`ConversationScreen`/`GroupConversationScreen`
 * need a live vault this module's unit-test tier can't provide (no
 * Robolectric, no mocking framework here), so the decision is checked
 * structurally. Bodies are scanned with comments STRIPPED so prose that
 * merely names a call can neither satisfy nor trip a guard.
 *
 * The strict branch MUST stay exactly `KeyboardType.Password` on both
 * composers — that is the one behavior this change must never regress,
 * since it is the only thing that stops the IME's on-device dictionary
 * (which lives outside the app sandbox and survives a wipe) from learning
 * plaintext message words at MAXIMUM.
 */
class ComposerKeyboardSourceTest {

    private val viewModel: String by lazy {
        SourcePins.stripped(SourcePins.RUN_VIEW_MODEL)
    }
    private val conversationScreen: String by lazy {
        SourcePins.stripped(SourcePins.CONVERSATION_SCREEN)
    }
    private val groupConversationScreen: String by lazy {
        SourcePins.stripped(SourcePins.GROUP_CONVERSATION_SCREEN)
    }
    private val conversationView: String by lazy {
        stripComments(File(repoRoot(), "iosApp/iosApp/ConversationView.swift").readText())
    }
    private val groupViews: String by lazy {
        stripComments(File(repoRoot(), "iosApp/iosApp/GroupViews.swift").readText())
    }
    private val uiComponents: String by lazy {
        stripComments(File(repoRoot(), "iosApp/iosApp/UIComponents.swift").readText())
    }

    // -----------------------------------------------------------------------
    // 1. Android: RunViewModel exposes the flag and (re)computes it through
    //    the shared policy on every unlock
    // -----------------------------------------------------------------------

    @Test
    fun runViewModel_exposesTheFlagDefaultingStrict() {
        assertTrue(
            "RunViewModel must expose strictComposerKeyboard as a Boolean, defaulting true " +
                "(fail toward strict before the first onVaultOpened runs)",
            viewModel.contains("var strictComposerKeyboard: Boolean = true"),
        )
    }

    @Test
    fun onVaultOpened_recomputesThroughTheSharedPolicy() {
        // The tier decisions moved into onVaultOpened's applySessionPolicy() (R5 it3).
        assertTrue(
            "onVaultOpened must apply the session policy",
            viewModel.functionBody("    fun onVaultOpened(openedVault: VaultDatabase) {").contains("applySessionPolicy()"),
        )
        val fn = viewModel.functionBody("    private fun applySessionPolicy() {")
        assertTrue(
            "onVaultOpened must route through ComposerKeyboardPolicy.isStrict(...) reading " +
                "vaultSelector.protectionLevelForEnforcement() — the same tamper-aware accessor " +
                "ReauthPolicy.isEnabled uses just above it. Body was:\n$fn",
            fn.contains(
                "strictComposerKeyboard =",
            ) && fn.contains(
                "ComposerKeyboardPolicy.isStrict(vaultSelector.protectionLevelForEnforcement())",
            ),
        )
    }

    // -----------------------------------------------------------------------
    // 2. Android: both composers branch on the shared flag, and the strict
    //    branch is UNCHANGED (still exactly KeyboardType.Password)
    // -----------------------------------------------------------------------

    @Test
    fun conversationScreen_branchesOnTheSharedFlag() {
        assertTrue(
            "ConversationScreen must read viewModel.strictComposerKeyboard",
            conversationScreen.contains("val strictKeyboard = viewModel.strictComposerKeyboard"),
        )
        assertTrue(
            "the strict branch must stay exactly KeyboardType.Password — the one behavior " +
                "that must never regress",
            conversationScreen.contains("KeyboardOptions(keyboardType = KeyboardType.Password)"),
        )
        assertTrue(
            "the non-strict branch must use KeyboardType.Text with autocorrect off (the " +
                "no-learning flags come from the NoPersonalizedLearning wrapper, pinned by " +
                "NoPersonalizedLearningSourceTest)",
            conversationScreen.contains(
                "KeyboardOptions(keyboardType = KeyboardType.Text, autoCorrectEnabled = false)",
            ),
        )
        assertTrue(
            "message_input must stay masked-never (text visible in both branches) — the a11y " +
                "test tag itself must be unchanged",
            conversationScreen.contains(".testTag(\"message_input\")"),
        )
    }

    @Test
    fun groupConversationScreen_branchesOnTheSharedFlagIdentically() {
        assertTrue(
            "GroupConversationScreen must read viewModel.strictComposerKeyboard, mirroring " +
                "the 1:1 composer",
            groupConversationScreen.contains("val strictKeyboard = viewModel.strictComposerKeyboard"),
        )
        assertTrue(
            "the strict branch must stay exactly KeyboardType.Password",
            groupConversationScreen.contains("KeyboardOptions(keyboardType = KeyboardType.Password)"),
        )
        assertTrue(
            "the non-strict branch must use KeyboardType.Text with autocorrect off, identical " +
                "to the 1:1 composer",
            groupConversationScreen.contains(
                "KeyboardOptions(keyboardType = KeyboardType.Text, autoCorrectEnabled = false)",
            ),
        )
        assertTrue(
            "group_message_input a11y test tag must be unchanged",
            groupConversationScreen.contains(".testTag(\"group_message_input\")"),
        )
    }

    // -----------------------------------------------------------------------
    // 3. iOS: NO tier branch — the no-learning composer at every tier (user
    //    decision 2026-09-21, reverting the 2026-09-20 split for iOS only).
    //    .textContentType(.password) is the only modifier that keeps the field
    //    out of QuickType learning, and iOS keeps its emoji key in that mode,
    //    so there is nothing to trade. Both composers must be UNCONDITIONAL.
    // -----------------------------------------------------------------------

    @Test
    fun conversationView_isUnconditionalPasswordModeAtEveryTier() {
        val fn = conversationView.functionBody("    private var inputBar: some View {")
        assertFalse(
            "ConversationView.inputBar must NOT read strictComposerKeyboard() — iOS has no tier branch. Body was:\n$fn",
            fn.contains("strictComposerKeyboard()"),
        )
        assertTrue(
            "ConversationView.inputBar's message_input must apply the shared no-learning " +
                "composer style. Body was:\n$fn",
            fn.contains(".noLearningComposerStyle()\n                .onSubmit { sendMessage() }\n" +
                "                .accessibilityIdentifier(\"message_input\")"),
        )
        assertNoLearningComposerStyleIsUnconditional()
    }

    @Test
    fun groupViews_isUnconditionalPasswordModeAtEveryTier() {
        val fn = groupViews.functionBody("    private var inputBar: some View {")
        assertFalse(fn.contains("strictComposerKeyboard()"))
        assertTrue(
            "GroupViews.inputBar's group_message_input must apply the shared no-learning " +
                "composer style. Body was:\n$fn",
            fn.contains(".noLearningComposerStyle()\n                    .onSubmit { sendMessage() }\n" +
                "                    .accessibilityIdentifier(\"group_message_input\")"),
        )
        assertNoLearningComposerStyleIsUnconditional()
    }

    /**
     * Both composers get the password content type through the shared
     * `noLearningComposerStyle()` helper: it must carry all three no-learning
     * modifiers and must NOT branch on the tier flag.
     */
    private fun assertNoLearningComposerStyleIsUnconditional() {
        val style = uiComponents.functionBody("    func noLearningComposerStyle() -> some View {")
        assertFalse(
            "noLearningComposerStyle must NOT read strictComposerKeyboard — iOS has no tier branch. Body was:\n$style",
            style.contains("strictComposerKeyboard"),
        )
        assertFalse(
            "noLearningComposerStyle must be unconditional (no if/? branch). Body was:\n$style",
            style.contains(" if ") || style.contains(" ? "),
        )
        assertTrue(style.contains(".textContentType(.password)"))
        assertTrue(style.contains(".textInputAutocapitalization(.never)"))
        assertTrue(style.contains(".autocorrectionDisabled(true)"))
    }

    /**
     * The create-group name field (`group_name_input`) is a secret-style
     * field, not a message composer, and must be left unconditional — only
     * the two message-input fields get the tier branch. Scoped to a window
     * ending at its own a11y identifier (rather than a whole-function-body
     * walk) since it sits inline in `CreateGroupView.body`, not its own
     * computed property.
     */
    @Test
    fun createGroupNameField_stillUnconditionalNeverReferencesTheFlag() {
        val idAt = groupViews.indexOf(".accessibilityIdentifier(\"group_name_input\")")
        assertTrue("precondition: group_name_input must still exist", idAt >= 0)
        val windowStart = maxOf(0, idAt - 600)
        val window = groupViews.substring(windowStart, idAt)
        assertTrue(
            "precondition: the create-group name field must stay a plain unconditional " +
                ".textContentType(.password) — it names a real circle, but is not a message " +
                "composer, so it is out of scope for this tier split. Window was:\n$window",
            window.contains(".textContentType(.password)"),
        )
        assertTrue(
            "the create-group name field must NOT reference strictComposerKeyboard — that " +
                "gate is for message composers only. Window was:\n$window",
            !window.contains("strictComposerKeyboard"),
        )
    }

    // -----------------------------------------------------------------------

    /** See [PeriodicReauthLockSourceTest] — same walk, same fail-loud contract. */
    private fun String.functionBody(signature: String): String {
        val start = indexOf(signature)
        assertTrue("precondition: `$signature` must exist", start >= 0)
        val indent = signature.takeWhile { it == ' ' }
        val closer = "\n$indent}"
        val end = indexOf(closer, start)
        assertTrue("precondition: `$signature` must be closed", end > start)
        return substring(start, end)
    }
}
