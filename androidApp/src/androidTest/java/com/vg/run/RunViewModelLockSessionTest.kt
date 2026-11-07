package com.vg.run

import android.app.Application
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * RunViewModel.lockSession(stopTor) — docs/periodic-reauth-design.md §3.4.
 *
 * Extracted from `onCleared` as the ONE teardown body `onCleared` (background /
 * Lever-C, `stopTor = true`) and the new in-process periodic-re-auth lock
 * (`lockForReauth`, `stopTor = false`) now share. Pins the ONE property that
 * makes `lockForReauth` safe: it must null the vault / messageManager / reauth
 * deadline exactly like a background lock does, but leave `torManager` ALIVE
 * so the re-unlock's `connectViaTor` can ADOPT it instead of re-bootstrapping —
 * `stopTor = true` (the whole-session path) nulls it too.
 *
 * Reflection-based, mirroring [RunViewModelWipeTest]'s `privateFlow` idiom: the
 * fields under test (`vault`, `messageManager`, `reauthDeadlineElapsedMs`,
 * `torManager`) are private/`private set`, and `lockSession` itself is
 * private — both by design (MainActivity/PinEntryScreen never poke session
 * state directly, only through onVaultOpened/lockForReauth/onCleared).
 *
 * See [SpeculativeTorAdoptionSourceTest.bothTeardowns_stillCoverTheSharedTorFieldsUnconditionally]
 * for the companion SOURCE-SHAPE guard (onCleared delegates to
 * `lockSession(stopTor = true)`, and `lockSession` itself still contains the
 * unconditional Tor-field coverage) — that test can't construct a real
 * ViewModel (plain-JVM, no Context/Tor), so the two are complementary: it pins
 * the SOURCE shape, this one exercises the RUNTIME behavior.
 *
 * Run with: ./gradlew connectedAndroidTest
 */
@RunWith(AndroidJUnit4::class)
class RunViewModelLockSessionTest {

    private companion object {
        private const val DB_NAME = "run.db"
        private const val DB_KEY_PREFS = "db_key_prefs"
        private const val SELECTOR_PREFS = "vault_selector_prefs"
    }

    private val app: Application
        get() = InstrumentationRegistry.getInstrumentation()
            .targetContext.applicationContext as Application

    @After
    fun tearDown() {
        // Belt-and-braces: a DatabaseManager provisioned directly in these tests
        // (not through VaultSelector) leaves a bare DB file/prefs behind.
        app.deleteDatabase(DB_NAME)
        app.deleteSharedPreferences(DB_KEY_PREFS)
        // Never leave the selector prefs behind for a later test class
        // (instrumented tests share one process/device).
        app.deleteSharedPreferences(SELECTOR_PREFS)
        ProcessWipeCover.resetForTest()
    }

    private fun RunViewModel.setPrivate(name: String, value: Any?) {
        val f = RunViewModel::class.java.getDeclaredField(name)
        f.isAccessible = true
        f.set(this, value)
    }

    private fun RunViewModel.getPrivate(name: String): Any? {
        val f = RunViewModel::class.java.getDeclaredField(name)
        f.isAccessible = true
        return f.get(this)
    }

    private fun RunViewModel.callLockSession(stopTor: Boolean) {
        val m = RunViewModel::class.java.getDeclaredMethod("lockSession", Boolean::class.javaPrimitiveType)
        m.isAccessible = true
        m.invoke(this, stopTor)
    }

    @Test
    fun lockSession_stopTorFalse_nullsVaultMessageManagerAndDeadline_keepsTorManagerAlive() {
        val vm = RunViewModel(app)
        val db = DatabaseManager(app, ByteArray(32) { (it + 1).toByte() }, isProvision = true)
        val mm = MessageManager(db, httpClient = PlatformHttpClient.direct())
        val tor = TorManager(app)
        vm.setPrivate("vault", db)
        vm.setPrivate("messageManager", mm)
        vm.setPrivate("reauthDeadlineElapsedMs", 123_456L)
        vm.setPrivate("torManager", tor)

        // Preconditions: reflection landed on the right fields before we trust
        // the post-call asserts below.
        assertNotNull("precondition: vault set", vm.vault)
        assertNotNull("precondition: messageManager set", vm.messageManager)
        assertNotNull("precondition: reauthDeadlineElapsedMs set", vm.reauthDeadlineElapsedMs)

        vm.callLockSession(false)

        assertNull("vault must be null after a re-auth lock", vm.vault)
        assertNull("messageManager must be null after a re-auth lock", vm.messageManager)
        assertNull("the re-auth deadline must be cleared on every lock", vm.reauthDeadlineElapsedMs)
        assertNotNull(
            "torManager must stay ALIVE — stopTor=false is what lets the re-unlock's " +
                "connectViaTor ADOPT it instead of re-bootstrapping",
            vm.getPrivate("torManager"),
        )
    }

    @Test
    fun lockSession_stopTorTrue_alsoNullsTorManager() {
        val vm = RunViewModel(app)
        val tor = TorManager(app)
        vm.setPrivate("reauthDeadlineElapsedMs", 123_456L)
        vm.setPrivate("torManager", tor)

        vm.callLockSession(true)

        assertNull("the re-auth deadline must be cleared", vm.reauthDeadlineElapsedMs)
        assertNull(
            "stopTor=true must null torManager — this is the whole-session (Lever C / " +
                "onCleared) path, unlike lockForReauth's stopTor=false",
            vm.getPrivate("torManager"),
        )
    }

    /**
     * `performEmergencyWipe` is the ONE other function
     * besides `lockSession` that nulls `vault` — it must ALSO clear the
     * re-auth deadline and arm the reactive `wipedThisSession` flag, or a
     * watchdog tick racing a deniable in-session wipe (the change-PIN abuse
     * cap) fires `lockForReauth()` against an already-wiped session.
     *
     * Runtime companion of `PeriodicReauthLockSourceTest
     * .performEmergencyWipe_clearsTheReauthDeadline` /
     * `.performEmergencyWipe_armsWipedThisSessionOnlyWhenDeniable`.
     */
    @Test
    fun performEmergencyWipe_clearsTheReauthDeadlineAndArmsWipedThisSession() {
        val vm = RunViewModel(app)
        vm.setPrivate("reauthDeadlineElapsedMs", 123_456L)
        assertNotNull("precondition: reauthDeadlineElapsedMs set", vm.reauthDeadlineElapsedMs)
        assertTrue("precondition: not yet wiped", !vm.wipedThisSession.value)

        vm.performEmergencyWipe() // deniable = true (default)

        assertNull(
            "the re-auth deadline must be cleared by a deniable emergency wipe — otherwise " +
                "the watchdog's next tick fires lockForReauth() against an already-wiped session",
            vm.reauthDeadlineElapsedMs,
        )
        assertTrue(
            "a deniable emergency wipe must arm wipedThisSession — the reactive twin of " +
                "ProcessWipeCover.armed that MainActivity's global cover reads",
            vm.wipedThisSession.value,
        )
    }

    /**
     * Second layer: `lockForReauth()` must be a no-op —
     * not raising the
     * navigation flag — when there is no open vault to lock (a post-wipe
     * tick must not navigate to an interactive PIN screen).
     */
    @Test
    fun lockForReauth_withNoOpenVault_writesNothingAndNeverRaisesTheFlag() {
        // Belt-and-braces precondition: the file must not already exist from a
        // previous (unrelated) test/run before we assert on its absence below.
        app.deleteSharedPreferences(SELECTOR_PREFS)

        val vm = RunViewModel(app)
        assertNull("precondition: a fresh ViewModel has no open vault", vm.vault)
        assertTrue("precondition: reauthLocked starts false", !vm.reauthLocked.value)

        vm.lockForReauth()

        assertTrue(
            "lockForReauth() must never raise reauthLocked when there is no vault to lock — " +
                "MainActivity would otherwise navigate to an interactive PIN screen",
            !vm.reauthLocked.value,
        )
    }
}
