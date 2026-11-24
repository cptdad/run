package com.vg.run

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * RÚN-02 — key deletion during a wipe is CHECKED, on both platforms.
 *
 * The behaviour itself is pinned by commonTest (`WipeEraserTest`,
 * `WipeEraseLatchPolicyTest`, `WipeRetryNeverTargetsNewKeyTest`), androidUnitTest
 * (`WipeEraseVaultSelectorGateTest`) and iosTest (`IosWipeKeyStoreTest`). This guard
 * pins the WIRING those tests cannot see: which call runs first, which result is
 * consumed, which call precedes which, and that the latch leaves nothing on disk.
 */
class WipeEraseCheckedSourceTest {

    private fun ios(rel: String): String = stripComments(File(repoRoot(), "iosApp/iosApp/$rel").readText())
    private fun shared(rel: String): String = stripComments(File(repoRoot(), "shared/src/$rel").readText())
    private val appState: String by lazy { stripComments(iosAppStateSources()) }
    private val controller: String by lazy { shared("iosMain/kotlin/com/vg/run/IosAppController.kt") }

    @Test
    fun iosPanicWipe_firstDestructiveActIsTheCheckedKeyErase() {
        val body = functionBody(appState, "    func emergencyWipe(deniable: Bool = true) {", "AppState")
        val eraseAt = body.indexOf("controller.eraseKeyMaterialFirst(")
        assertTrue("AppState.emergencyWipe must start with the checked key erase. Body:\n$body", eraseAt >= 0)
        for (later in listOf(
            "inactivityCrypto.wipeKey()",
            "unregisterCurrentInboxesBestEffort()",
            "TorManager.shared.stop(discardingState: true)",
            "controller.emergencyWipe()",
        )) {
            val at = body.indexOf(later)
            assertTrue("`$later` must exist in AppState.emergencyWipe", at >= 0)
            assertTrue("`$later` must come AFTER the checked key erase (crypto-erase-first)", eraseAt < at)
        }
        assertFalse(
            "the unchecked direct deletes are gone — the status must reach the report",
            body.contains("KeychainHelper.shared.deleteKey()") || body.contains("SecureEnclaveHelper.shared.deleteKey()"),
        )
    }

    @Test
    fun iosWipeLogLine_claimsOnlyWhatWasConfirmed() {
        assertFalse(
            "the unconditional 'all data destroyed' line must not come back",
            appState.contains("all data destroyed"),
        )
        val body = functionBody(appState, "    func emergencyWipe(deniable: Bool = true) {", "AppState")
        assertTrue(
            "the completion line must be decided by the controller's erase report",
            body.contains("controller.wipeEraseComplete()"),
        )
    }

    @Test
    fun swiftDeleteHelpers_neverDiscardTheStatus() {
        val keychain = ios("KeychainHelper.swift")
        for (sig in listOf(
            "public func deleteKeyChecked() -> KeychainDeleteResult {",
            "public func kvDeleteAllChecked() -> KeychainDeleteResult {",
            "public func deleteBlockListChecked() -> KeychainDeleteResult {",
        )) {
            val fn = functionBody(keychain, sig, "KeychainHelper.swift")
            assertTrue("$sig must keep the SecItemDelete status", Regex("""let \w+ = SecItemDelete\(""").containsMatchIn(fn))
            assertTrue("$sig must classify through the verify probe", fn.contains("classifyDelete("))
        }
        for ((sig, checked) in listOf(
            "public func deleteKey() {" to "deleteKeyChecked()",
            "public func kvDeleteAll() {" to "kvDeleteAllChecked()",
        )) {
            val fn = functionBody(keychain, sig, "KeychainHelper.swift")
            assertTrue("$sig must delegate to $checked", fn.contains(checked))
            assertFalse("$sig must not issue its own unchecked SecItemDelete", fn.contains("SecItemDelete("))
        }
        val se = ios("SecureEnclaveHelper.swift")
        val seChecked = functionBody(se, "public func deleteKeyChecked() -> KeychainDeleteResult {", "SecureEnclaveHelper.swift")
        assertTrue(Regex("""let \w+ = SecItemDelete\(""").containsMatchIn(seChecked))
        assertFalse(
            "the SE probe must never ask for a usable key reference",
            seChecked.contains("kSecReturnRef"),
        )
        val seDelete = functionBody(se, "public func deleteKey() {", "SecureEnclaveHelper.swift")
        assertTrue(seDelete.contains("deleteKeyChecked()") && !seDelete.contains("SecItemDelete("))
        val blockClear = functionBody(ios("UserSafety.swift"), "static func clear() {", "UserSafety.swift")
        assertTrue(blockClear.contains("deleteBlockListChecked()") && !blockClear.contains("SecItemDelete("))
    }

    @Test
    fun iosProvision_dropsTheCachedInactivityKeyBeforeTheControllerCall() {
        val body = functionBody(appState, "    func setRealCredentialWithLevel(", "AppState")
        val wipeAt = body.indexOf("inactivityCrypto.wipeKey()")
        val callAt = body.indexOf("controller.setRealCredentialWithLevel(")
        assertTrue("setRealCredentialWithLevel must drop inactivityCrypto's cached key", wipeAt >= 0)
        assertTrue("…BEFORE the controller provisions (no stamp sealed under a purged key)", wipeAt < callAt)
    }

    @Test
    fun iosController_freshProvisionGateRunsBeforeTheFirstSeal() {
        for (sig in listOf(
            "    fun setRealCredentialWithLevel(credential: String, passphraseMode: Boolean, level: String): Boolean",
            "    fun setRealCredential(credential: String) {",
        )) {
            val body = functionBody(controller, sig, "IosAppController")
            val gateAt = body.indexOf("prepareFreshProvision()")
            val sealAt = body.indexOf("pinAttempts.establishVerified()")
            assertTrue("$sig must run the fresh-provision gate", gateAt >= 0)
            assertTrue("$sig: the gate must precede the first seal (the first possible mint)", gateAt in 0 until sealAt)
        }
        // Expression body: from the declaration to the next blank line.
        val gateAt = controller.indexOf("    private fun prepareFreshProvision(): Boolean")
        assertTrue("IosAppController must declare prepareFreshProvision", gateAt >= 0)
        val gate = controller.substring(gateAt, controller.indexOf("\n\n", gateAt))
        assertTrue(gate.contains("FreshProvisionGate.prepare("))
        assertTrue("the gate must drop the cached device key", gate.contains("crypto.wipeKey()"))
    }

    @Test
    fun iosLaunchChecks_postWipeResidueRule_sitsBetweenTheOrphanAndInactivityChecks() {
        val body = functionBody(appState, "    private func runLaunchSecurityChecks() {", "AppState")
        val orphanAt = body.indexOf("credentialsReadable()")
        val residueAt = body.indexOf("controller.postWipeResidueDetected()")
        val inactivityAt = body.indexOf("InactivityWipe.isExpired(")
        assertTrue(residueAt >= 0)
        assertTrue("post-wipe residue after the orphan check", orphanAt in 0 until residueAt)
        assertTrue("…and before the inactivity check", residueAt < inactivityAt)
    }

    @Test
    fun mintAndJournalReplay_areGatedOnTheEraseLatch() {
        val provider = shared("iosMain/kotlin/com/vg/run/CryptoProvider.ios.kt")
        val mint = functionBody(provider, "internal fun getOrCreateKey(): ByteArray {", "CryptoProvider.ios.kt")
        val gateAt = mint.indexOf("WipeErasePolicy.mayMintDeviceKey()")
        assertTrue("getOrCreateKey must refuse to mint while an erase is unresolved", gateAt >= 0)
        assertTrue("…before any key is generated", gateAt < mint.indexOf("generateSecureRandom(32)"))
        assertTrue("…and before the orphan delete", gateAt < mint.indexOf("keychain.deleteKey()"))

        val kv = shared("iosMain/kotlin/com/vg/run/KeyValueStore.ios.kt")
        val replay = functionBody(kv, "    private fun recoverPendingBatch(kc: KeychainBridge) {", "KeyValueStore.ios.kt")
        assertTrue(replay.contains("WipeErasePolicy.mayReplayJournal()"))
        assertTrue(replay.indexOf("WipeErasePolicy.mayReplayJournal()") < replay.indexOf("kc.kvPut("))

        val manager = shared("androidMain/kotlin/com/vg/run/CryptoManager.kt")
        val init = manager.substring(manager.indexOf("    init {"))
        assertTrue(
            "the Android keyset/master key must not be (re)created while an erase is unresolved",
            init.indexOf("WipeErasePolicy.mayMintDeviceKey()") in 0 until init.indexOf("ensureMasterKey()"),
        )
    }

    @Test
    fun androidWipeRoutine_consumesEveryKeyDeleteResult() {
        val wipe = SourcePins.stripped(SourcePins.WIPE_ROUTINE)
        val body = functionBody(wipe, "fun wipePersistentState(context: Context) {", "WipeRoutine")
        val beginAt = body.indexOf("WipeEraseLatch.begin()")
        val keysAt = body.indexOf("WipeEraser.run(store, WipeEraser.KEY_ITEMS)")
        assertTrue("the latch arms before the first erase", beginAt in 0 until keysAt)
        assertTrue("the outcome is recorded", body.contains("WipeEraseLatch.finish(wipeToken, report)"))
        assertFalse(
            "no unchecked key delete may remain in the routine",
            body.contains("CryptoManager.eraseMasterKey(context)") || body.contains("AuthBoundKeyStore.deleteKey(context)"),
        )
        assertTrue(wipe.contains("CryptoManager.eraseMasterKeyChecked(context)"))
        assertTrue(wipe.contains("AuthBoundKeyStore.deleteKeyChecked()"))
    }

    @Test
    fun androidProvision_runsTheFreshProvisionGateBeforeTheFirstSeal() {
        val setup = stripComments(SourcePins.text("androidApp/src/main/java/com/vg/run/PinSetupScreen.kt"))
        val body = functionBody(setup, "suspend fun provisionAndFinish(credential: String) {", "PinSetupScreen")
        val gateAt = body.indexOf("viewModel.prepareFreshProvision()")
        assertTrue(gateAt >= 0)
        assertTrue(gateAt < body.indexOf("viewModel.vaultSelector.setRealCredential("))
    }

    @Test
    fun eraseLatch_isRamOnly() {
        val src = shared("commonMain/kotlin/com/vg/run/WipeErase.kt")
        for (forbidden in listOf(
            "KeyValueStore", "putString", "NSUserDefaults", "SharedPreferences", "java.io", "writeText", "VaultDatabase",
        )) {
            assertFalse("WipeErase.kt must not persist anything (`$forbidden`)", src.contains(forbidden))
        }
    }

    @Test
    fun wipeProbe_isDebugOnly() {
        val runApp = File(repoRoot(), "iosApp/iosApp/RunApp.swift").readText()
        val at = runApp.indexOf("--test-wipe-probe")
        assertTrue("the probe switch is parsed in RunApp.init", at >= 0)
        assertTrue(
            "…inside a #if DEBUG block",
            runApp.lastIndexOf("#if DEBUG", at) > runApp.lastIndexOf("#endif", at),
        )
        val raw = iosAppStateSources()
        val decl = raw.indexOf("static var testWipeProbe")
        assertTrue(decl >= 0 && raw.lastIndexOf("#if DEBUG", decl) > raw.lastIndexOf("#endif", decl))
        val ctl = File(repoRoot(), "shared/src/iosMain/kotlin/com/vg/run/IosAppController.kt").readText()
        val probe = functionBody(ctl, "    fun wipeProbeSummary(): String", "IosAppController")
        assertTrue("the Kotlin probe answers nothing in a release framework", probe.contains("if (!isDebugBuild) return \"\""))
    }

    // -- deniability (review point 1) ----------------------------------------

    @Test
    fun explicitEraseWording_onlyAfterAUserRequestedWipeInThisProcess_iOS() {
        val cv = ios("ContentView.swift")
        val explicitAt = cv.indexOf("L10n.pinEraseFinishingTitle")
        val guardAt = cv.lastIndexOf("appState.userRequestedEraseThisProcess", explicitAt)
        assertTrue("the explicit screen is gated on a user-requested wipe", guardAt in 0 until explicitAt)
        assertTrue(cv.lastIndexOf("} else if", explicitAt) < guardAt)
        val neutralAt = cv.indexOf(".containerA11yId(\"setup_blocked\")")
        assertTrue(neutralAt >= 0)
        // The rendered block only (the branch condition names the eraseUnresolved flag).
        val neutral = cv.substring(cv.indexOf("GateNoticeScreen(", cv.lastIndexOf("} else if", neutralAt)), neutralAt)
        assertTrue(neutral.contains("L10n.pinSetupBlockedMessage") && neutral.contains("\"setup_retry_button\""))
        // What reaches the user or accessibility tooling: string literals (ids, icon)
        // and L10n keys. (Method names such as retryPendingErase are code, not UI.)
        val visible = Regex(""""[^"]*"|L10n\.\w+""").findAll(neutral).joinToString(" ") { it.value }
        assertFalse("the neutral state never mentions erasing: $visible", visible.lowercase().contains("eras"))
        val appState = functionBody(this.appState, "    func emergencyWipe(deniable: Bool = true) {", "AppState")
        assertTrue(appState.contains("if !deniable { userRequestedEraseThisProcess = true }"))
    }

    @Test
    fun explicitEraseWording_onlyAfterAUserRequestedWipeInThisProcess_android() {
        val main = SourcePins.stripped(SourcePins.MAIN_ACTIVITY)
        val explicitAt = main.indexOf("FinishingEraseScreen(")
        assertTrue(main.lastIndexOf("if (userRequestedErase)", explicitAt) in 0 until explicitAt)
        val setup = stripComments(SourcePins.text("androidApp/src/main/java/com/vg/run/PinSetupScreen.kt"))
        val neutral = functionBody(setup, "fun SetupBlockedScreen(onRetry: () -> Unit)", "PinSetupScreen")
        assertTrue(neutral.contains("R.string.pin_setup_blocked_message") && neutral.contains("\"setup_retry_button\""))
        val visible = Regex(""""[^"]*"|R\.string\.\w+""").findAll(neutral).joinToString(" ") { it.value }
        assertFalse("the neutral state never mentions erasing: $visible", visible.lowercase().contains("eras"))
        val vm = SourcePins.stripped(SourcePins.RUN_VIEW_MODEL)
        assertTrue(functionBody(vm, "fun performEmergencyWipe(deniable: Boolean = true) {", "RunViewModel")
            .contains("if (!deniable) _userRequestedErase.value = true"))
        val strings = File(repoRoot(), "androidApp/src/main/res/values/strings_onboarding.xml").readText()
        val line = strings.lines().first { it.contains("name=\"pin_setup_blocked_message\"") }
        assertFalse("the neutral message never mentions erasing", line.lowercase().contains("eras"))
    }

    // -- no wipe line after the log clear (review point 3) -------------------

    @Test
    fun iosControllerWipe_appendsNothingAfterTheLogClear() {
        val body = functionBody(controller, "    fun emergencyWipe() {", "IosAppController")
        val tail = body.substring(body.indexOf("LogBuffer.clear()"))
        assertFalse(
            "no log line may follow the LogBuffer clear in the wipe",
            tail.contains("platformLog") || tail.contains("wipeEraseDebugLog") || tail.contains("LogBuffer.append"),
        )
        val wipeErase = shared("commonMain/kotlin/com/vg/run/WipeErase.kt")
        assertFalse("every erase log line goes through the debug-only helper",
            Regex("""platformLog(Warn|Error)?\(""").findAll(wipeErase).count() != 1)
    }

    // -- consumers of a refused device key (review point 5) ------------------

    @Test
    fun swiftCryptoConsumers_neverForceTry() {
        for (f in listOf("AppState.swift", "InactivityWipe.swift", "UserSafety.swift", "RunApp.swift", "ContentView.swift")) {
            assertFalse("$f must not `try!` (a refused key would crash)", ios(f).contains("try!"))
        }
        for ((sig, label) in listOf(
            "    fun unlock(credential: String): Int {" to "unlock",
            "    fun recoverWithCode(recoveryCode: String, credential: String): Int {" to "recoverWithCode",
            "    fun reloadCryptoIfWiped() {" to "reloadCryptoIfWiped",
        )) {
            val body = functionBody(controller, sig, "IosAppController")
            val reload = body.indexOf("crypto.reloadKey()")
            assertTrue("$label: the key reload is inside a try (non-@Throws bridge)", body.indexOf("try") in 0 until reload)
        }
        val inactivity = SourcePins.stripped("androidApp/src/main/java/com/vg/run/InactivityWipe.kt")
        assertTrue("Android InactivityWipe defers on a refused key", inactivity.contains("catch (e: KeyUnavailableException)"))
    }
}
