package com.vg.run

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Raw-key adoption (2026-10-07) END TO END through the real [VaultSelector], the
 * real store, the real Tink device key and a real SQLCipher file — the halves the
 * pure commonTest `RawKeyAdoptionDecisionTest` cannot reach:
 *
 *  - new provisions are raw-key from day one;
 *  - a passphrase-mode vault (the shape of every pre-adoption vault) unlocks in
 *    passphrase mode, adopts ONCE, and opens raw afterwards, with its data;
 *  - a K' that does not open the file is NEVER persisted;
 *  - a raw-open failure falls back to passphrase mode — Opened, never Denied/Error;
 *  - Lever B: an `ab:` vault adopts only behind a PROVEN recovery code, and the
 *    recovery code still opens an adopted vault (it wraps R; passphrase mode);
 *  - Re-key: a tier-upgrade re-key from a RAW-opened handle lands, re-adopts on the
 *    next unlock, and the archived weak-era store still no longer opens the vault.
 *
 * Which mode actually opened the file is observed through [SpyFactory], which
 * delegates every call to the real `androidVaultFactory` and only counts.
 */
@RunWith(AndroidJUnit4::class)
class RawKeyAdoptionVaultSelectorTest {

    private lateinit var context: android.content.Context

    private companion object {
        const val DB = "run.db"
        const val SELECTOR_PREFS = "vault_selector_prefs"
        const val K_REAL_CRED = "vlt_a"
        const val K_REAL_DBKEY = "vlt_c"
        const val K_PENDING = "vlt_cn"
        const val PIN = "135790"
        const val WRONG_PIN = "000000"
        val SECRET = "adopt-shared-secret".toByteArray()
    }

    @Before
    fun setUp() {
        context = InstrumentationRegistry.getInstrumentation().targetContext
        context.deleteDatabase(DB)
        context.deleteSharedPreferences(SELECTOR_PREFS)
    }

    @After
    fun tearDown() {
        context.deleteDatabase(DB)
        context.deleteSharedPreferences(SELECTOR_PREFS)
    }

    private fun prefs() = KeyValueStore(context, SELECTOR_PREFS)

    private fun selector(
        factory: VaultFactory,
        protector: DbKeyProtector? = null,
        vault: () -> VaultDatabase? = { null },
    ): VaultSelector {
        val crypto = CryptoProvider(context)
        val vs = if (protector == null) {
            VaultSelector(store = prefs(), crypto = crypto, vaultFactory = factory, vaultProvider = vault)
        } else {
            VaultSelector(store = prefs(), crypto = crypto, vaultFactory = factory,
                dbKeyProtector = protector, vaultProvider = vault)
        }
        vs.changePinMinDelayMs = 0
        return vs
    }

    private fun provision(factory: VaultFactory, protector: DbKeyProtector? = null, level: ProtectionLevel = ProtectionLevel.CASUAL) {
        assertTrue("provision must succeed",
            selector(factory, protector).setRealCredential(PIN, passphraseMode = false, level = level))
    }

    private fun opened(r: VaultSelector.UnlockResult): VaultDatabase {
        assertTrue("expected Opened, got $r", r is VaultSelector.UnlockResult.Opened)
        return (r as VaultSelector.UnlockResult.Opened).vault
    }

    // -------------------------------------------------------------------------

    @Test
    fun newProvision_isRawKeyFromDayOne() {
        provision(SpyFactory(androidVaultFactory(context)))
        val blob = prefs().getString(K_REAL_DBKEY)

        val spy = SpyFactory(androidVaultFactory(context))
        val v = opened(selector(spy).unlock(PIN))
        v.insertContact(ContactRecord("c1", SECRET, 1, "Alice", 1_700_000_000_000L))
        v.close()
        assertEquals("the very first unlock opens RAW", 1, spy.rawOpenSuccesses)
        assertEquals("…and never pays the passphrase stretch", 0, spy.passphraseOpens)
        assertEquals("an already-adopted vault is never rewritten", blob, prefs().getString(K_REAL_DBKEY))
    }

    @Test
    fun passphraseModeVault_establishesOnRead_adoptsOnce_thenOpensRawWithItsData() {
        // The shape of every pre-adoption vault: provisioned by a factory that cannot adopt.
        provision(SpyFactory(androidVaultFactory(context), adopts = false))
        val passphraseBlob = prefs().getString(K_REAL_DBKEY)

        val first = SpyFactory(androidVaultFactory(context))
        val v1 = opened(selector(first).unlock(PIN))
        v1.insertContact(ContactRecord("c1", SECRET, 1, "Alice", 1_700_000_000_000L))
        v1.close()
        assertEquals("a passphrase payload opens in passphrase mode", 1, first.passphraseOpens)
        assertEquals("…and is NOT tried raw (it has no K')", 0, first.rawOpenAttempts)
        assertEquals("adoption probed K' against the real file", 1, first.rawProbes)
        val adoptedBlob = prefs().getString(K_REAL_DBKEY)
        assertNotEquals("the blob was promoted after the confirmed open", passphraseBlob, adoptedBlob)

        val second = SpyFactory(androidVaultFactory(context))
        val v2 = opened(selector(second).unlock(PIN))
        assertNotNull("data written in the passphrase session survives", v2.getContact("c1"))
        v2.close()
        assertEquals(1, second.rawOpenSuccesses)
        assertEquals(0, second.passphraseOpens)
        assertEquals("steady state: no more probes, no more writes", 0, second.rawProbes)
        assertEquals(adoptedBlob, prefs().getString(K_REAL_DBKEY))
    }

    @Test
    fun aDerivedKeyThatDoesNotOpenTheFile_isNeverPersisted() {
        provision(SpyFactory(androidVaultFactory(context), adopts = false))
        val passphraseBlob = prefs().getString(K_REAL_DBKEY)

        val corrupt = SpyFactory(androidVaultFactory(context), corruptDerived = true)
        opened(selector(corrupt).unlock(PIN)).close()
        assertEquals(1, corrupt.rawProbes)
        assertEquals("a K' the probe could not open must never reach vlt_c",
            passphraseBlob, prefs().getString(K_REAL_DBKEY))

        // The next healthy unlock adopts normally.
        opened(selector(SpyFactory(androidVaultFactory(context))).unlock(PIN)).close()
        assertNotEquals(passphraseBlob, prefs().getString(K_REAL_DBKEY))
    }

    @Test
    fun rawOpenFailure_fallsBackToPassphraseMode_neverDeniedNorError() {
        provision(SpyFactory(androidVaultFactory(context)))
        opened(selector(SpyFactory(androidVaultFactory(context))).unlock(PIN)).let {
            it.insertContact(ContactRecord("c1", SECRET, 1, "Alice", 1_700_000_000_000L)); it.close()
        }
        val broken = SpyFactory(androidVaultFactory(context), rawOpenThrows = true)
        val v = opened(selector(broken).unlock(PIN))
        assertNotNull("the fallback open sees the real data", v.getContact("c1"))
        v.close()
        assertEquals(1, broken.rawOpenAttempts)
        assertEquals(1, broken.passphraseOpens)

        // The wrong-credential path is untouched by adoption.
        assertTrue(selector(SpyFactory(androidVaultFactory(context))).unlock(WRONG_PIN)
            is VaultSelector.UnlockResult.Denied)
    }

    @Test
    fun leverB_adoptsOnlyBehindAProvenRecoveryCode_andTheCodeStillOpensTheAdoptedVault() {
        // Pre-adoption PRIVATE vault: passphrase payload, then Lever B enabled + finalized.
        val protector = AdoptFakeAuthProtector()
        provision(SpyFactory(androidVaultFactory(context), adopts = false), protector, ProtectionLevel.PRIVATE)
        val noAdopt = selector(SpyFactory(androidVaultFactory(context), adopts = false), protector)
        opened(noAdopt.unlock(PIN)).let {
            it.insertContact(ContactRecord("c1", SECRET, 1, "Alice", 1_700_000_000_000L)); it.close()
        }
        val enable = noAdopt.enableDbKeyAuthBindingWithRecovery(PIN)
        assertTrue(enable is VaultSelector.RecoveryEnableResult.Enabled)
        val code = (enable as VaultSelector.RecoveryEnableResult.Enabled).recoveryCode
        assertTrue(noAdopt.finalizeDbKeyAuthBinding(ProtectionLevel.PRIVATE))
        val abPassphrase = prefs().getString(K_REAL_DBKEY)!!
        assertTrue(abPassphrase.startsWith("ab:"))

        // Adopting unlock: the ab: blob is re-wrapped auth-bound (proven recovery net).
        val first = SpyFactory(androidVaultFactory(context))
        opened(selector(first, protector).unlock(PIN)).close()
        val abRaw = prefs().getString(K_REAL_DBKEY)!!
        assertTrue("Lever B must survive adoption", abRaw.startsWith("ab:"))
        assertNotEquals(abPassphrase, abRaw)
        val second = SpyFactory(androidVaultFactory(context))
        opened(selector(second, protector).unlock(PIN)).close()
        assertEquals("the adopted ab: vault opens raw", 1, second.rawOpenSuccesses)

        // The hardware key dies: the recovery code (wraps R) still opens the ADOPTED
        // vault in passphrase mode, with the commit-plain-then-open ordering intact.
        protector.invalidated = true
        val rec = SpyFactory(androidVaultFactory(context))
        val v = opened(selector(rec, protector).recoverWithCode(code, PIN))
        assertNotNull(v.getContact("c1"))
        v.close()
        assertEquals("recovery opens in passphrase mode with R", 1, rec.passphraseOpens)
        assertEquals(0, rec.rawOpenAttempts)
        assertTrue("recovery commits a PLAIN blob", !prefs().getString(K_REAL_DBKEY)!!.startsWith("ab:"))

        // …and the recovered (passphrase-tagged) vault re-adopts on its next unlock.
        protector.invalidated = false
        val after = SpyFactory(androidVaultFactory(context))
        opened(selector(after, protector).unlock(PIN)).close()
        assertEquals(1, after.passphraseOpens)
        val again = SpyFactory(androidVaultFactory(context))
        opened(selector(again, protector).unlock(PIN)).close()
        assertEquals(1, again.rawOpenSuccesses)
    }

    @Test
    fun leverB_withoutAProvenRecoveryCode_isNotAdopted() {
        val protector = AdoptFakeAuthProtector()
        provision(SpyFactory(androidVaultFactory(context), adopts = false), protector, ProtectionLevel.PRIVATE)
        val noAdopt = selector(SpyFactory(androidVaultFactory(context), adopts = false), protector)
        noAdopt.enableDbKeyAuthBindingWithRecovery(PIN)
        assertTrue(noAdopt.finalizeDbKeyAuthBinding(ProtectionLevel.PRIVATE))
        // Remove the net: an ab: vault with no recovery code (the Gen-A shape).
        prefs().remove("vlt_rc")
        val before = prefs().getString(K_REAL_DBKEY)

        val spy = SpyFactory(androidVaultFactory(context))
        opened(selector(spy, protector).unlock(PIN)).close()
        assertEquals("no proven recovery net ⇒ no derive, no probe, no write", 0, spy.rawProbes)
        assertEquals(before, prefs().getString(K_REAL_DBKEY))
    }

    @Test
    fun m1TierUpgrade_fromARawOpenedHandle_landsReAdopts_andRetiresTheArchivedStore() {
        provision(SpyFactory(androidVaultFactory(context)))
        val archivedCred = prefs().getString(K_REAL_CRED)!!
        val archivedDbKey = prefs().getString(K_REAL_DBKEY)!!
        val phrase = "runes harbor violet stapler mountain ledger"

        val openSpy = SpyFactory(androidVaultFactory(context))
        val live = opened(selector(openSpy).unlock(PIN))
        assertEquals("precondition: the live handle is RAW-opened", 1, openSpy.rawOpenSuccesses)
        live.insertContact(ContactRecord("m1", SECRET, 1, "Rotated", 1_700_000_000_000L))
        assertEquals(VaultSelector.ChangePinResult.SUCCESS,
            selector(SpyFactory(androidVaultFactory(context)), vault = { live })
                .changeCredentialAndMode(PIN, phrase, newModePassphrase = true))
        live.close()
        assertNull("the rotation resolved in-line", prefs().getString(K_PENDING))

        val afterRekey = SpyFactory(androidVaultFactory(context))
        val v = opened(selector(afterRekey).unlock(phrase))
        assertNotNull(v.getContact("m1")); v.close()
        assertEquals("the rotated key is a PASSPHRASE payload", 1, afterRekey.passphraseOpens)
        val steady = SpyFactory(androidVaultFactory(context))
        opened(selector(steady).unlock(phrase)).close()
        assertEquals("…re-adopted on the next unlock", 1, steady.rawOpenSuccesses)

        // THE RE-KEY PROPERTY survives adoption: the archived (adopted!) weak-era store
        // carries the OLD R and the OLD K'; neither opens the re-keyed file.
        prefs().putStringsSync(mapOf(K_REAL_CRED to archivedCred, K_REAL_DBKEY to archivedDbKey))
        assertTrue(selector(SpyFactory(androidVaultFactory(context))).unlock(PIN)
            is VaultSelector.UnlockResult.Error)
    }
}

/** Delegates to the real factory; only counts — and, on request, breaks one thing. */
private class SpyFactory(
    private val real: VaultFactory,
    private val adopts: Boolean = true,
    private val corruptDerived: Boolean = false,
    private val rawOpenThrows: Boolean = false,
) : VaultFactory {
    var passphraseOpens = 0; private set
    var rawOpenAttempts = 0; private set
    var rawOpenSuccesses = 0; private set
    var rawProbes = 0; private set

    override fun create(dbKey: ByteArray, isProvision: Boolean): VaultDatabase =
        real.create(dbKey, isProvision).also { if (!isProvision) passphraseOpens++ }
    override fun vaultFileExists(): Boolean = real.vaultFileExists()
    override fun deleteVaultFileAfterFailedProvision() = real.deleteVaultFileAfterFailedProvision()
    override fun probeKey(dbKey: ByteArray): Boolean = real.probeKey(dbKey)
    override fun supportsRawKeyAdoption(): Boolean = adopts
    override fun deriveAdoptedRawKey(dbKey: ByteArray): ByteArray? =
        if (!adopts) null else real.deriveAdoptedRawKey(dbKey)?.also {
            if (corruptDerived) it[0] = (it[0].toInt() xor 1).toByte()
        }
    override fun createWithRawKey(rawKey: ByteArray): VaultDatabase {
        rawOpenAttempts++
        if (rawOpenThrows) throw IllegalStateException("simulated raw-key open failure")
        return real.createWithRawKey(rawKey).also { rawOpenSuccesses++ }
    }
    override fun probeRawKey(rawKey: ByteArray): Boolean { rawProbes++; return real.probeRawKey(rawKey) }
}

/** Biometric-free Lever B double (same contract as VaultSelectorTest's fake). */
private class AdoptFakeAuthProtector : DbKeyProtector {
    var invalidated = false
    override fun supportsAuthBinding(): Boolean = true
    override fun isAuthBoundBlob(stored: String): Boolean = stored.startsWith("ab:")
    override fun wrap(inner: ByteArray, authBound: Boolean): String {
        val b64 = android.util.Base64.encodeToString(inner, android.util.Base64.NO_WRAP)
        return if (authBound) "ab:$b64" else b64
    }
    override fun unwrap(stored: String): ByteArray {
        if (stored.startsWith("ab:")) {
            if (invalidated) throw KeyUnavailableException("simulated Lever B key invalidated")
            return android.util.Base64.decode(stored.removePrefix("ab:"), android.util.Base64.NO_WRAP)
        }
        return android.util.Base64.decode(stored, android.util.Base64.NO_WRAP)
    }
}
