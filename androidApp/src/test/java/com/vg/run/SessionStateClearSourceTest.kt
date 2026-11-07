package com.vg.run

import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * RunViewModel-side guards for the contact-list / consent state moved out of
 * ContactListScreen (R5 it3 T2/T3/T6) and for the import-path cancellation (T4).
 * Comment-stripped source.
 */
class SessionStateClearSourceTest {

    private val vm: String by lazy { SourcePins.stripped(SourcePins.RUN_VIEW_MODEL) }

    @Test
    fun clearInMemoryIdentifierMaps_dropsTheContactListAndThePendingConsent() {
        val body = vm.bodyOf("    private fun clearInMemoryIdentifierMaps() {")
        assertTrue("the contact-list snapshot holds aliases: null it on lock/wipe", body.contains("_contactList.value = null"))
        assertTrue(
            "pending offers carry introducer/peer aliases: clear them on lock/wipe",
            body.contains("_pendingConsent.value = PendingConsent(null, null)"),
        )
        for (sig in listOf("    private fun lockSession(stopTor: Boolean) {", "    fun performEmergencyWipe(deniable: Boolean = true) {")) {
            assertTrue("$sig must call clearInMemoryIdentifierMaps()", vm.bodyOf(sig).contains("clearInMemoryIdentifierMaps()"))
        }
    }

    @Test
    fun theLoaderIsASessionJob_onIo_andEpochGated() {
        val body = vm.bodyOf("    private fun startContactListLoader() {")
        assertTrue(body.contains("withContext(Dispatchers.IO)"))
        assertTrue(body.contains("loadContactListSnapshot("))
        assertTrue("a load straddling a lock must not re-publish", body.contains("sessionStillCurrent(epoch)"))
        assertTrue(vm.contains("private var contactListJob: Job? by sessionJobs.slot()"))
        assertTrue(vm.contains("private var consentTickJob: Job? by sessionJobs.slot()"))
        val opened = vm.bodyOf("    fun onVaultOpened(openedVault: VaultDatabase) {")
        for (call in listOf("startContactListLoader()", "refreshPendingConsent()", "startConsentTick()")) {
            assertTrue("onVaultOpened must call $call", opened.contains(call))
        }
    }

    @Test
    fun theConsentStateIsRefreshedAfterEveryControlCycle_andThePrime() {
        assertTrue(vm.bodyOf("    private fun startControlPoll() {").contains("refreshPendingConsent()"))
        assertTrue(vm.bodyOf("    private fun startUnreadPrime() {").contains("refreshPendingConsent()"))
    }

    @Test
    fun theScreensVaultWritesRunOffMain() {
        for (sig in listOf(
            "    fun declineReferralOfferInBackground(",
            "    fun saveContactMnemonicInBackground(",
            "    fun rollContactAliasInBackground(",
        )) {
            assertTrue("$sig must run on IO", vm.bodyOf(sig).contains("viewModelScope.launch(Dispatchers.IO)"))
        }
        val decline = vm.bodyOf("    fun declineReferralOfferInBackground(")
        assertTrue(
            "the decline refreshes the consent state BEFORE the screen's onDone, so the dialog " +
                "cannot re-present the just-declined offer",
            decline.indexOf("refreshPendingConsent()") in 0 until decline.indexOf("onDone()"),
        )
    }

    /**
     * T4: a teardown cancelling moveOpJob (or MoveManager rethrowing a
     * cancellation) must not leave the import screen on Running forever.
     */
    @Test
    fun theImportCatchesCancellationFirst_goesIdle_andRethrows() {
        val body = vm.bodyOf("    fun startPendingMoveImport() {")
        val cancelAt = body.indexOf("catch (e: CancellationException)").let {
            if (it >= 0) it else body.indexOf("catch (e: kotlinx.coroutines.CancellationException)")
        }
        val otherAt = body.indexOf("catch (e: Exception)")
        assertTrue("startPendingMoveImport must catch CancellationException. Body was:\n$body", cancelAt >= 0)
        assertTrue("…BEFORE the Exception catch (CancellationException is an Exception)", otherAt > cancelAt)
        val cancelBlock = body.substring(cancelAt, otherAt)
        assertTrue("the cancel branch sets Idle", cancelBlock.contains("MoveImportUiState.Idle"))
        assertTrue("the cancel branch rethrows", cancelBlock.contains("throw e"))
        assertTrue(
            "any other throw maps to IMPORT_FAILED",
            body.substring(otherAt).contains("MoveImportResult.Failure(MoveError.IMPORT_FAILED)"),
        )
    }

    private fun String.bodyOf(signature: String): String {
        val start = indexOf(signature)
        assertTrue("precondition: `$signature` must exist", start >= 0)
        val open = indexOf('{', start)
        var depth = 0
        var i = open
        while (i < length) {
            when (this[i]) {
                '{' -> depth++
                '}' -> { depth--; if (depth == 0) break }
            }
            i++
        }
        return substring(open, i + 1)
    }
}
