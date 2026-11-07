package com.vg.run

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * "Show again" (frozen page) and "Retry" (failed page) re-issue the transfer bundle
 * under a fresh code, which is as sensitive as the first export. Both must run the
 * SAME credential prompt the first export uses ([MoveCredentialPage], which calls
 * RunViewModel.verifyMoveExportAuth -> MoveExportAuth.verifyAndGrant) before
 * reissueMoveExport() is called; the buttons keep their `move_error_retry` tag.
 *
 * SOURCE-LEVEL (the screen needs a live vault this JVM tier cannot build);
 * comments are stripped so prose cannot satisfy the guard.
 */
class MoveReissueCredentialSourceTest {

    private val screen = SourcePins.stripped(SourcePins.MOVE_TO_NEW_DEVICE_SCREEN)

    @Test
    fun reissueIsCalledOnlyAfterTheCredentialPromptVerifies() {
        assertEquals(
            "reissueMoveExport() must have exactly one call site in the screen",
            1, Regex("""viewModel\.reissueMoveExport\(\)""").findAll(screen).count(),
        )
        val callAt = screen.indexOf("viewModel.reissueMoveExport()")
        val promptAt = screen.lastIndexOf("MoveCredentialPage(", callAt)
        val verifiedAt = screen.lastIndexOf("onVerified = {", callAt)
        assertTrue("the call must sit in a MoveCredentialPage's onVerified", promptAt in 0 until verifiedAt)
        // …and that MoveCredentialPage is the re-issue one, not the first export's.
        assertTrue(
            "the re-issue prompt is gated on its own flag",
            screen.substring(screen.lastIndexOf("if (", promptAt), promptAt).contains("askingReissueCredential"),
        )
    }

    @Test
    fun theCredentialPageStillVerifiesThroughTheSharedGate() {
        val page = screen.functionBody("private fun MoveCredentialPage(")
        assertTrue(page.contains("viewModel.verifyMoveExportAuth(credential)"))
        assertTrue(page.contains("MoveExportAuth.Outcome.OK -> {"))
        val vm = SourcePins.text(SourcePins.RUN_VIEW_MODEL)
        assertTrue(vm.contains("MoveExportAuth.verifyAndGrant(credential, vaultSelector, changePinAttempts, moveExportAuthGate)"))
    }

    @Test
    fun theFrozenAndFailedButtonsAskFirstAndKeepTheirTag() {
        for (sig in listOf("private fun MoveFrozenPage(", "private fun MoveFailedPage(")) {
            val body = screen.functionBody(sig)
            assertFalse("$sig must not re-issue directly", body.contains("reissueMoveExport"))
            val tagAt = body.indexOf("testTag = \"move_error_retry\",")
            assertTrue("$sig keeps move_error_retry", tagAt >= 0)
            val click = body.substring(tagAt, body.indexOf(")", tagAt))
            assertTrue("$sig: the retry button's click is onReissue", click.contains("onClick = onReissue"))
        }
    }

    // ---- iOS half (MoveToNewDeviceView.swift) — the same property. ----

    private val swift by lazy { SourcePins.stripped("iosApp/iosApp/MoveToNewDeviceView.swift") }

    @Test
    fun ios_theThreeRetryButtonsAskFirstAndNeverReissueDirectly() {
        val tag = "id: \"move_error_retry\""
        val sites = Regex(Regex.escape(tag)).findAll(swift).map { it.range.first }.toList()
        assertEquals("the frozen/failed pages keep three move_error_retry buttons", 3, sites.size)
        for (at in sites) {
            val action = braceBody(swift, swift.indexOf('{', at), includeBraces = false)
            assertEquals("a move_error_retry button's action is exactly requestReissue()",
                "requestReissue()", action.trim())
        }
        assertFalse("nothing may start a re-issue export directly",
            Regex("""startExport\(\s*reissue:\s*true\s*\)""").containsMatchIn(swift))
    }

    @Test
    fun ios_reissueStartsOnlyOnAVerifiedCredential() {
        assertEquals("startExport(reissue: reissue) must have exactly one call site", 1,
            Regex("""startExport\(reissue: reissue\)""").findAll(swift).count())
        assertEquals("startExport( must be called from one place only (plus its declaration)", 1,
            Regex("""(?<!func )startExport\(""").findAll(swift).count())
        val submit = functionBody(swift, "private func submitCredential(", "MoveToNewDeviceView.swift")
        assertTrue("the gate is the shared verifyMoveExportAuth", submit.contains("appState.verifyMoveExportAuth(credential)"))
        val ok = submit.indexOf("case \"ok\":")
        val wipe = submit.indexOf("case \"wipe\":")
        val call = submit.indexOf("startExport(reissue: reissue)")
        assertTrue("startExport(reissue: reissue) sits in the \"ok\" case", ok in 0 until call && call < wipe)
    }

    @Test
    fun ios_requestReissueOpensTheSameCredentialPromptAsTheFirstExport() {
        val request = functionBody(swift, "private func requestReissue(", "MoveToNewDeviceView.swift")
        assertTrue(request.contains("guard !busy, !credVerifying else { return }"))
        assertTrue(request.contains("openCredentialPrompt(reissue: true)"))
        val open = functionBody(swift, "private func openCredentialPrompt(reissue: Bool)", "MoveToNewDeviceView.swift")
        assertTrue("the prompt records which export to start", open.contains("credForReissue = reissue"))
        assertTrue("the prompt is the credentialBody gate", open.contains("askingCredential = true"))
        assertTrue("the first export opens the same prompt", swift.contains("openCredentialPrompt(reissue: false)"))
    }

    private fun String.functionBody(signature: String): String {
        val start = indexOf(signature)
        assertTrue("precondition: `$signature` must exist", start >= 0)
        val end = indexOf("\n}", start)
        assertTrue("precondition: `$signature` must be closed", end > start)
        return substring(start, end)
    }
}
