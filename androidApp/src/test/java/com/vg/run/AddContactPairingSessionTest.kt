package com.vg.run

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.ViewModelStore
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File

/**
 * Pins the pairing-secret lifetime of the add-contact flow (ratchet-bootstrap plan,
 * phase 0, G2 + G3): ONE pairing session = ONE secret half, which survives a
 * configuration change (Android) / a duplicate appear (iOS) and is wiped — and
 * unusable — after a real leave.
 *
 * Part 1 drives the shared [PairingSession] (via [AddContactSessionViewModel]) directly; a
 * configuration change is simulated the way the NavController sees it: the
 * recreated screen asks the SAME ViewModelStore again. Part 2 is source-level (no
 * Robolectric in this module), comments stripped, for the composable wiring and the
 * iOS sibling.
 */
class AddContactPairingSessionTest {

    // -----------------------------------------------------------------------
    // 1. The holder and the session
    // -----------------------------------------------------------------------

    @Test
    fun pairingSession_has32RandomBytes_andIsUnusableAfterEnd() {
        val pairing = PairingSession.start()
        val bytes = pairing.mySecretHalf()
        assertEquals(32, bytes.size)
        assertFalse("a fresh half must not be all zero", bytes.all { it == 0.toByte() })
        assertSame("the session hands out its own array (end reaches every alias)", bytes, pairing.mySecretHalf())
        assertTrue(pairing.isActive)
        assertTrue("the codes carry the one-time key", pairing.secretOnlyCode()!!.contains("\"ek\""))

        pairing.end()
        assertFalse(pairing.isActive)
        assertTrue("end zeroes the array in place", bytes.all { it == 0.toByte() })
        try {
            pairing.mySecretHalf()
            fail("an ended session must never hand out its half as key material")
        } catch (_: IllegalStateException) {
            // expected
        }
        assertEquals("no code from an ended session", null, pairing.secretOnlyCode())
        pairing.end() // idempotent
    }

    @Test
    fun restartPairingStartsANewSession_bumpsGeneration_andShowsTheReason() {
        val vm = AddContactSessionViewModel()
        val old = vm.resumeOrStartNewSession()
        val oldPairing = vm.currentPairing()
        vm.step = AddStep.Done
        vm.pairingFailed = true
        val gen = vm.generation

        vm.restartPairing("again")

        assertTrue("the old half is zeroed", old.all { it == 0.toByte() })
        assertFalse(oldPairing.isActive)
        assertTrue("a NEW session is live right away", vm.isActive)
        assertNotSame(oldPairing, vm.currentPairing())
        assertEquals(gen + 1, vm.generation)
        assertEquals("the reason survives the reset", "again", vm.addError)
        assertEquals(AddStep.Choice, vm.step)
        assertFalse(vm.pairingFailed)
    }

    @Test
    fun theSameSecretSurvivesASimulatedConfigurationChange() {
        val store = ViewModelStore()
        val first = provider(store).get(AddContactSessionViewModel::class.java)
        val secret = first.resumeOrStartNewSession()
        val snapshot = secret.copyOf()
        first.step = AddStep.Show
        first.shown = true
        first.pendingContactId = "pending"

        // Activity recreated: the NavBackStackEntry's store is retained and the
        // rebuilt composition asks it again. The screen's dispose did NOT end the
        // session (isChangingConfigurations).
        val second = provider(store).get(AddContactSessionViewModel::class.java)
        assertSame("the recreated screen must get the same session", first, second)
        val again = second.resumeOrStartNewSession()
        assertSame("the SAME half (the QR the peer may have scanned)", secret, again)
        assertArrayEquals(snapshot, again)
        assertEquals("wizard progress survives too", AddStep.Show, second.step)
        assertTrue(second.shown)
        assertEquals("pending", second.pendingContactId)
        assertTrue(second.isActive)
    }

    @Test
    fun clearingTheStoreWipesTheSession() {
        val store = ViewModelStore()
        val vm = provider(store).get(AddContactSessionViewModel::class.java)
        val secret = vm.resumeOrStartNewSession()
        val pairing = vm.currentPairing()
        vm.scannedData = scanned()
        vm.mintState = MintState.Failed("x")
        vm.step = AddStep.Done

        store.clear() // entry popped / Activity finishing -> onCleared

        assertTrue("our half is zeroed on clear", secret.all { it == 0.toByte() })
        assertFalse("the session (and its one-time key) is ended on clear", pairing.isActive)
        assertFalse(vm.isActive)
        assertEquals("no mint runs after clear", null, vm.runningMintAbortFlag)
        assertEquals(MintState.WaitingForRelay, vm.mintState)
        assertEquals(AddStep.Choice, vm.step)
        assertEquals(null, vm.scannedData)
    }

    @Test
    fun aRealLeaveEndsTheSession_andTheNextScreenGetsANewHalf_neverTheZeroedOne() {
        val vm = AddContactSessionViewModel()
        val old = vm.resumeOrStartNewSession()
        vm.endSession()
        assertTrue(old.all { it == 0.toByte() })
        assertFalse(vm.isActive)

        val fresh = vm.resumeOrStartNewSession()
        assertNotSame("an ended session's half is never reused", old, fresh)
        assertFalse("the new half is not the zeroed bytes", fresh.all { it == 0.toByte() })
        assertTrue(vm.isActive)
    }

    @Test
    fun endSessionDropsTheScan_butReassigningTheSameScanKeepsIt() {
        val vm = AddContactSessionViewModel()
        vm.resumeOrStartNewSession()
        val first = scanned()
        vm.scannedData = first
        vm.scannedData = first // e.g. a failed save keeps it for the retry
        assertSame(first, vm.scannedData)

        vm.endSession()
        assertEquals(null, vm.scannedData)
    }

    /** Nothing of the session may reach saved instance state. */
    @Test
    fun theSessionHasNoSavedStateHandle() {
        val cls = AddContactSessionViewModel::class.java
        for (c in cls.declaredConstructors) {
            assertFalse(
                "the session must not take a SavedStateHandle (a Bundle-backed store)",
                c.parameterTypes.any { SavedStateHandle::class.java.isAssignableFrom(it) },
            )
        }
        assertFalse(
            "the session must not hold a SavedStateHandle",
            cls.declaredFields.any { SavedStateHandle::class.java.isAssignableFrom(it.type) },
        )
    }

    // -----------------------------------------------------------------------
    // 2. Wiring (source-level)
    // -----------------------------------------------------------------------

    private val screen: String by lazy { SourcePins.stripped(SourcePins.ADD_CONTACT_SCREEN) }
    private val session: String by lazy {
        stripComments(File(repoRoot(), SESSION_FILE).readText())
    }
    private val iosView: String by lazy {
        stripComments(File(repoRoot(), "iosApp/iosApp/AddContactView.swift").readText())
    }

    @Test
    fun noSaveableStateForPairingSecrets() {
        for ((name, src) in listOf("AddContactScreen.kt" to screen, "AddContactSessionViewModel.kt" to session)) {
            assertFalse("$name must not use rememberSaveable (secret halves / caps are RAM-only)",
                src.contains("rememberSaveable"))
            assertFalse("$name must not use SavedStateHandle", src.contains("SavedStateHandle"))
            assertFalse("$name must not put anything in a Bundle", src.contains("Bundle"))
        }
        assertFalse(
            "the screen must not generate its own half any more (it lived in `remember {}` " +
                "and was regenerated on every configuration change)",
            screen.contains("SecureRandom"),
        )
        assertTrue(
            "the screen must take its pairing session from the ViewModel",
            screen.contains("session.currentPairing()"),
        )
        assertTrue(
            "the session must be the NavBackStackEntry-scoped ViewModel",
            screen.contains("val session: AddContactSessionViewModel = viewModel()"),
        )
    }

    @Test
    fun theScreenEndsTheSessionOnARealLeaveOnly() {
        assertTrue(
            "dispose must end the session unless the Activity is changing configurations",
            screen.contains("if (hostActivity?.isChangingConfigurations != true) session.endSession()"),
        )
        assertTrue(
            "onCleared must end the session (entry popped / Activity finishing)",
            session.contains("override fun onCleared()") &&
                functionBody(session, "override fun onCleared()").contains("endSession()"),
        )
        assertFalse(
            "the configuration-change dispose must not wipe the scan any more " +
                "(the session's scannedData setter owns that wipe)",
            screen.contains("DisposableEffect(scannedForWipe)"),
        )
        assertTrue(
            "the mint must run in the session's scope so a rotation does not restart it",
            screen.contains("session.startMintIfIdle(mgr, toMintState)"),
        )
    }

    @Test
    fun iosHoldsTheSharedSession_startsItOnce_andEndsItOnALeave() {
        assertFalse("iOS no longer holds a Swift secret half", iosView.contains("mySecret"))
        assertEquals(
            "exactly two places start a session: the first appear and 'start again'",
            2, Regex("""PairingSession\.companion\.start\(\)""").findAll(iosView).count(),
        )
        assertTrue(
            "the session is started only for a not-yet-started phase",
            Regex("""if pairingSession == \.notStarted \{\s*pairing = PairingSession\.companion\.start\(\)\s*pairingSession = \.active""")
                .containsMatchIn(iosView),
        )
        assertTrue(
            "an appear on an ENDED session must start a new one",
            iosView.contains("AddContactView.pairingSessionOnAppear(pairingSession) == .startNewSession") &&
                iosView.contains("resetForNewPairingSession()"),
        )
        val disappear = iosView.substring(iosView.indexOf(".onDisappear {"))
        val endAt = disappear.indexOf("pairing?.end()")
        val endedAt = disappear.indexOf("pairingSession = .ended")
        assertTrue("the real-leave handler ends the session, then marks the phase",
            endAt in 0 until endedAt)
        assertTrue(
            "the save must refuse an ended session",
            iosView.contains("guard pairingSession == .active, let pairing = pairing else { return }"),
        )
        assertTrue(
            "the mint must refuse an ended session",
            iosView.contains("guard pairingSession == .active, pairing != nil else { return }"),
        )
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private fun provider(store: ViewModelStore) = ViewModelProvider(
        store,
        object : ViewModelProvider.Factory {
            @Suppress("UNCHECKED_CAST")
            override fun <T : ViewModel> create(modelClass: Class<T>): T = AddContactSessionViewModel() as T
        },
    )

    private fun scanned() = ScannedContact(
        PairingScan(inboxId = null, writeCap = null, ctlInboxId = null, ctlWriteCap = null, secretB64 = "AAAA"),
    )

    private companion object {
        const val SESSION_FILE = "androidApp/src/main/java/com/vg/run/AddContactSessionViewModel.kt"
    }
}
