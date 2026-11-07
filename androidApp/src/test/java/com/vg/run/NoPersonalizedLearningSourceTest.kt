package com.vg.run

import android.text.InputType
import android.view.inputmethod.EditorInfo
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Keyboard-learning parity with iOS (which refuses third-party keyboards outright):
 * Android cannot refuse an IME, so every field that takes private text asks the IME
 * not to learn it, through the [NoPersonalizedLearning] wrapper.
 *
 * SOURCE-LEVEL for the wiring (the screens need a live vault this JVM tier cannot
 * build): each listed field's call must sit INSIDE a `NoPersonalizedLearning { … }`
 * block. Comments are stripped first so prose cannot satisfy the guard. The flag
 * arithmetic itself is pure and tested directly.
 *
 * The SWEEP test is the backstop for the list: every text field anywhere in
 * androidApp/src/main must be wrapped, or use a password keyboard type (which the
 * IME already treats as no-learning), so a new field cannot be added unguarded.
 */
class NoPersonalizedLearningSourceTest {

    private companion object {
        /** Today's count of text-field calls under androidApp/src/main (2026-11). */
        const val MIN_TEXT_FIELDS = 13
        val NON_PASSWORD_TYPE = Regex("""KeyboardType\.(Text|Ascii|Uri|Email)\b""")
    }

    /** (file, a string unique to the field's call, the field's call token). */
    private val wrappedFields = listOf(
        Triple("ConversationScreen.kt", ".testTag(\"message_input\")", "BasicTextField("),
        Triple("GroupConversationScreen.kt", ".testTag(\"group_message_input\")", "BasicTextField("),
        Triple("CreateGroupScreen.kt", ".testTag(\"group_name_input\")", "BasicTextField("),
        Triple("AddContactScreen.kt", "testTag(\"add_done_mnemonic\")", "BasicTextField("),
        Triple("AddContactScreen.kt", "testTag(\"scan_inject_field\")", "BasicTextField("),
        Triple("AddContactScreen.kt", ".testTag(\"debug_code_input\")", "BasicTextField("),
        Triple("ContactListScreen.kt", ".testTag(\"report_bug_text_field\")", "BasicTextField("),
        Triple("ContactListScreen.kt", ".testTag(\"mnemonic_edit_input\")", "BasicTextField("),
        Triple("MoveFromDeviceScreen.kt", ".testTag(\"move_paste_field\")", "BasicTextField("),
        Triple("RecoveryEntryScreen.kt", "R.string.protection_recovery_code_placeholder", "OutlinedTextField("),
        Triple("ExternalProxySettingsModal.kt", "KeyboardOptions(keyboardType = keyboardType, autoCorrectEnabled = false)", "BasicTextField("),
    )

    /** The message composers: no learning, but suggestions + glide typing kept. */
    private val composerAnchors = setOf(".testTag(\"message_input\")", ".testTag(\"group_message_input\")")

    /** A wrapper opening: `NoPersonalizedLearning {` or `NoPersonalizedLearning(…) {`. */
    private val wrapperOpen = Regex("""NoPersonalizedLearning\s*(\(([^()]*)\))?\s*\{""")

    /** The innermost wrapper whose block still encloses [at], or null. */
    private fun enclosingWrapper(src: String, at: Int): MatchResult? =
        wrapperOpen.findAll(src).filter { it.range.first < at }.lastOrNull { m ->
            var depth = 0
            for (i in m.range.last until at) {
                when (src[i]) {
                    '{' -> depth++
                    '}' -> depth--
                }
                if (depth <= 0 && i > m.range.last) return@lastOrNull false
            }
            depth >= 1
        }

    @Test
    fun everyPrivateTextField_sitsInsideTheWrapper() {
        for ((file, anchor, call) in wrappedFields) {
            val src = stripComments(File(repoRoot(), "androidApp/src/main/java/com/vg/run/$file").readText())
            val anchorAt = src.indexOf(anchor)
            assertTrue("$file: anchor `$anchor` must exist", anchorAt >= 0)
            assertEquals("$file: anchor `$anchor` must be unique", anchorAt, src.lastIndexOf(anchor))
            val callAt = src.lastIndexOf(call, anchorAt)
            val wrap = enclosingWrapper(src, anchorAt)
            assertTrue("$file: the field `$anchor` must be wrapped in NoPersonalizedLearning { }", wrap != null)
            assertTrue("$file: the wrapper must open BEFORE the field's $call", wrap!!.range.first < callAt)
            val keepsSuggestions = wrap.groupValues[2].contains("keepSuggestions = true")
            if (anchor in composerAnchors) {
                assertTrue(
                    "$file: the message composer keeps suggestions (only the learning flag)",
                    keepsSuggestions,
                )
            } else {
                assertTrue(
                    "$file: a secret field (`$anchor`) must also drop suggestions — no keepSuggestions",
                    wrap.groupValues[2].isBlank(),
                )
            }
        }
    }

    /**
     * Every text field in the app is either inside the wrapper or uses a password
     * keyboard type (KeyboardType.Password / NumberPassword: the IME already treats
     * those as no-learning, no-suggestion). A new field that is neither fails here.
     */
    @Test
    fun sweep_everyTextFieldIsWrappedOrPasswordTyped() {
        val call = Regex("""\b(BasicTextField|OutlinedTextField|TextField|BasicSecureTextField|OutlinedSecureTextField|SecureTextField)\(""")
        val mainDir = File(repoRoot(), "androidApp/src/main/java")
        val offenders = mutableListOf<String>()
        var seen = 0
        mainDir.walkTopDown().filter { it.isFile && it.extension == "kt" }.forEach { f ->
            val src = stripComments(f.readText())
            for (m in call.findAll(src)) {
                seen++
                val open = m.range.last
                var depth = 0
                var close = open
                for (i in open until src.length) {
                    when (src[i]) {
                        '(' -> depth++
                        ')' -> depth--
                    }
                    if (depth == 0) { close = i; break }
                }
                val args = src.substring(open, close + 1)
                // A conditional type (`if (strict) KeyboardType.Password else
                // KeyboardType.Text`, as the composers do) is NOT password-typed: the
                // field can run with a learning keyboard, so it must be wrapped.
                val passwordTyped =
                    (args.contains("KeyboardType.Password") || args.contains("KeyboardType.NumberPassword")) &&
                        !NON_PASSWORD_TYPE.containsMatchIn(args)
                if (enclosingWrapper(src, m.range.first) == null && !passwordTyped) {
                    val line = src.substring(0, m.range.first).count { it == '\n' } + 1
                    offenders += "${f.name}:$line ${m.value}"
                }
            }
        }
        assertTrue("the sweep must see the app's text fields (saw $seen, expected >= $MIN_TEXT_FIELDS)", seen >= MIN_TEXT_FIELDS)
        assertTrue(
            "every text field must sit inside NoPersonalizedLearning { } or use a password " +
                "keyboard type. Unguarded: $offenders",
            offenders.isEmpty(),
        )
    }

    /**
     * keepSuggestions = true is the composers' exemption only. A secret field placed
     * inside such a wrapper would pass [everyPrivateTextField_sitsInsideTheWrapper]
     * (it checks only the listed anchors) and the sweep (it only asks for SOME
     * wrapper), so the exemption is pinned to exactly the two composer anchors.
     */
    @Test
    fun keepSuggestions_wrapsOnlyTheTwoComposers() {
        val mainDir = File(repoRoot(), "androidApp/src/main/java")
        val opens = mutableListOf<String>()
        mainDir.walkTopDown().filter { it.isFile && it.extension == "kt" }.forEach { f ->
            val src = stripComments(f.readText())
            for (m in wrapperOpen.findAll(src)) {
                if (!m.groupValues[2].contains("keepSuggestions = true")) continue
                val anchor = composerAnchors.firstOrNull { a ->
                    val at = src.indexOf(a, m.range.last)
                    at >= 0 && enclosingWrapper(src, at)?.range?.first == m.range.first
                }
                opens += "${f.name}:${anchor ?: "NOT-A-COMPOSER"}"
            }
        }
        assertEquals(
            "exactly two NoPersonalizedLearning(keepSuggestions = true) blocks, one per composer",
            listOf("ConversationScreen.kt:.testTag(\"message_input\")", "GroupConversationScreen.kt:.testTag(\"group_message_input\")"),
            opens.sorted(),
        )
    }

    @Test
    fun theWrapper_usesThePlatformInterceptor() {
        val src = stripComments(File(repoRoot(), "androidApp/src/main/java/com/vg/run/NoPersonalizedLearning.kt").readText())
        assertTrue(src.contains("InterceptPlatformTextInput(interceptor, content)"))
        assertTrue(src.contains("request.createInputConnection(outAttributes)"))
        assertTrue(src.contains("outAttributes.imeOptions = noLearningImeOptions(outAttributes.imeOptions)"))
        assertTrue(src.contains("outAttributes.inputType = noSuggestionsInputType(outAttributes.inputType)"))
        // NO_SUGGESTIONS is skipped only for keepSuggestions (the composers); the
        // learning flag is unconditional.
        assertTrue(src.contains("if (!keepSuggestions) {"))
        assertTrue(
            src.indexOf("if (!keepSuggestions) {") <
                src.indexOf("outAttributes.inputType = noSuggestionsInputType("),
        )
        assertTrue(
            src.indexOf("outAttributes.imeOptions = noLearningImeOptions(") <
                src.indexOf("if (!keepSuggestions) {"),
        )
        assertTrue(src.contains("fun NoPersonalizedLearning(keepSuggestions: Boolean = false,"))
        // The attributes are amended AFTER the field filled them in, or the field's
        // own write would overwrite ours.
        assertTrue(
            src.indexOf("request.createInputConnection(outAttributes)") <
                src.indexOf("outAttributes.imeOptions = "),
        )
    }

    @Test
    fun imeOptions_gainTheNoLearningFlag_andKeepTheRest() {
        val base = EditorInfo.IME_ACTION_SEND
        val out = noLearningImeOptions(base)
        assertEquals(EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING, out and EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING)
        assertEquals(base, out and EditorInfo.IME_MASK_ACTION)
    }

    @Test
    fun plainText_gainsNoSuggestions_passwordAndNumbersDoNot() {
        val text = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE
        assertEquals(text or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS, noSuggestionsInputType(text))
        val password = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        assertEquals(password, noSuggestionsInputType(password))
        val visiblePassword = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
        assertEquals(visiblePassword, noSuggestionsInputType(visiblePassword))
        val number = InputType.TYPE_CLASS_NUMBER
        assertEquals(number, noSuggestionsInputType(number))
    }
}
