package com.vg.run

import java.io.File
import java.util.concurrent.ConcurrentHashMap

/**
 * Shared helpers of the `*SourceTest` guards (tests that read production source
 * text and assert on its shape). Test-only; one copy instead of one per file.
 *
 * Every guard uses these; a private `repoRoot()` / `stripComments()` /
 * `functionBody()` copy in a test file would shadow them, so do not add one.
 */

private val BLOCK_COMMENT = Regex("""/\*.*?\*/""", RegexOption.DOT_MATCHES_ALL)
private val LINE_COMMENT = Regex("""//[^\n]*""")
// `(?<!:)` keeps `http://` inside string literals intact.
private val LINE_COMMENT_KEEP_URLS = Regex("""(?<!:)//[^\n]*""")

/**
 * Walks up from the JVM working directory (Gradle sets it to the module dir) to
 * the directory holding `settings.gradle.kts`. Fails loudly rather than
 * returning a default: a guard that silently scans nothing passes forever.
 */
internal fun repoRoot(): File {
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

/**
 * So prose that merely NAMES a call cannot satisfy (or trip) a shape guard.
 * [keepUrls] = true leaves a `//` preceded by `:` alone, so `http://` inside a
 * string literal survives (the Tor parity guards scan string literals).
 */
internal fun stripComments(src: String, keepUrls: Boolean = false): String =
    src.replace(BLOCK_COMMENT, " ").replace(if (keepUrls) LINE_COMMENT_KEEP_URLS else LINE_COMMENT, " ")

/**
 * The brace-matched block whose `{` is at [open], up to its matching `}`.
 * [includeBraces] = true returns the braces too; false only the text between them.
 */
internal fun braceBody(src: String, open: Int, includeBraces: Boolean = true): String {
    if (open < 0 || open >= src.length || src[open] != '{') throw AssertionError("no opening brace at $open")
    var depth = 0
    for (i in open until src.length) {
        when (src[i]) {
            '{' -> depth++
            '}' -> {
                depth--
                if (depth == 0) return if (includeBraces) src.substring(open, i + 1) else src.substring(open + 1, i)
            }
        }
    }
    throw AssertionError("unbalanced braces from $open")
}

/**
 * The brace-matched body of the first function whose declaration contains
 * [signature] in [src], so a scan cannot wander into a neighbouring function.
 * [label] names the source in the failure message.
 */
internal fun functionBody(
    src: String,
    signature: String,
    label: String = "the source",
    includeBraces: Boolean = true,
): String {
    val fnStart = src.indexOf(signature)
    if (fnStart < 0) throw AssertionError("$label must declare `$signature`")
    val open = src.indexOf('{', fnStart)
    if (open < 0) throw AssertionError("`$signature` must have a body")
    return braceBody(src, open, includeBraces)
}

/** [functionBody] of the raw (comments kept) repo-relative file [relativePath]. */
internal fun fileFunctionBody(relativePath: String, signature: String): String =
    functionBody(SourcePins.text(relativePath), signature, label = relativePath)

/**
 * The production files many guards pin, spelled once. A guard reads them through
 * [text] / [stripped], which read (and strip) each file once per test JVM, so a
 * file split changes one constant here instead of every guard.
 */
internal object SourcePins {
    private const val MAIN = "androidApp/src/main/java/com/vg/run/"
    /** The `google` distribution flavour's source set (FCM, Play Billing, Play Review). */
    private const val GOOGLE = "androidApp/src/google/kotlin/com/vg/run/"
    const val RUN_VIEW_MODEL = MAIN + "RunViewModel.kt"
    const val WIPE_ROUTINE = MAIN + "WipeRoutine.kt"
    const val MAIN_ACTIVITY = MAIN + "MainActivity.kt"
    const val UNIFIED_PUSH_SUPPORT = MAIN + "UnifiedPushSupport.kt"
    const val GROUP_CONVERSATION_SCREEN = MAIN + "GroupConversationScreen.kt"
    const val CONVERSATION_SCREEN = MAIN + "ConversationScreen.kt"
    const val CONTACT_LIST_SCREEN = MAIN + "ContactListScreen.kt"
    const val VENDOR_PUSH = GOOGLE + "VendorPush.kt"
    const val PUSH_REGISTRATION_COORDINATOR = MAIN + "PushRegistrationCoordinator.kt"
    const val RUN_FCM_SERVICE = GOOGLE + "RunFcmService.kt"
    const val MOVE_TO_NEW_DEVICE_SCREEN = MAIN + "MoveToNewDeviceScreen.kt"
    const val GROUP_INFO_SCREEN = MAIN + "GroupInfoScreen.kt"
    const val CONNECT_TELEMETRY_RECORDER = MAIN + "ConnectTelemetryRecorder.kt"
    const val ADD_CONTACT_SCREEN = MAIN + "AddContactScreen.kt"

    private val texts = ConcurrentHashMap<String, String>()
    private val strippedTexts = ConcurrentHashMap<String, String>()

    /** The raw text of the repo-relative file [rel] (read once per JVM). */
    fun text(rel: String): String = texts.computeIfAbsent(rel) { File(repoRoot(), it).readText() }

    /** [text] with [stripComments] applied (the default, URL-eating form). */
    fun stripped(rel: String): String = strippedTexts.computeIfAbsent(rel) { stripComments(text(it)) }
}

/**
 * The Swift `AppState` as ONE text: `iosApp/iosApp/AppState.swift` FIRST, then every
 * `AppState+*.swift` extension file of the same directory in name order, joined by
 * newlines. The AppState source guards read this instead of `AppState.swift` alone
 * so that whole-file `contains` / regex / count checks — and above all the NEGATIVE
 * ones — keep covering code that moves into an extension file. A function body
 * stays in one file, so `functionBody`-style slicing and in-body ordering are
 * unaffected by the join.
 *
 * Raw text (no comment stripping): callers strip with their own stripper as before.
 */
internal fun iosAppStateSources(): String {
    val dir = File(repoRoot(), "iosApp/iosApp")
    val main = File(dir, "AppState.swift")
    check(main.isFile) { "iosAppStateSources: $main not found — this guard must never silently scan nothing" }
    val extensions = dir.listFiles { f ->
        f.isFile && f.name.startsWith("AppState+") && f.name.endsWith(".swift")
    }!!.sortedBy { it.name }
    return (listOf(main) + extensions).joinToString("\n") { it.readText() }
}

/**
 * Where [body] (a teardown function of RunViewModel) cancels the session job
 * [job]: the index of a by-name `job?.cancel()` if one is there, otherwise, when
 * [viewModelSource] declares [job] as a `SessionJobs` slot
 * (`var job: Job? by sessionJobs.slot()`), the index of the body's
 * `sessionJobs.cancelAll()` — the one call that cancels every slot. -1 when the
 * body cancels the job neither way. Lets an ordering guard keep pinning "job X is
 * cancelled before Y" across the registry refactor.
 */
internal fun sessionJobCancelIndex(viewModelSource: String, body: String, job: String): Int {
    val byName = body.indexOf("$job?.cancel()")
    if (byName >= 0) return byName
    val isSlot = Regex("""var\s+$job\s*:\s*Job\?\s+by\s+sessionJobs\.slot\(\)""").containsMatchIn(viewModelSource)
    return if (isSlot) body.indexOf("sessionJobs.cancelAll()") else -1
}
