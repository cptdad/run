package com.vg.run

import android.content.Context
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory

/**
 * Regression guard: the Tink master wrapping key must be auth-bound
 * with `setUnlockedDeviceRequired(true)` so the keyset — and every
 * CryptoProvider-encrypted blob beneath it — can only be unwrapped while the
 * device is unlocked, denying forensic access to a locked-but-powered device.
 *
 * The unlocked-device flag is NOT exposed by [KeyInfo], so the strongest
 * deterministic assertion is on the [android.security.keystore.KeyGenParameterSpec]
 * we hand to the Keystore ([CryptoManager.buildMasterKeySpec]); a companion
 * behavioural test confirms [CryptoManager] actually pre-creates the key and
 * still round-trips.
 *
 * Run with: ./gradlew connectedAndroidTest
 */
@RunWith(AndroidJUnit4::class)
class CryptoManagerKeySpecTest {

    private lateinit var context: Context
    private val ctx = "keyspec-test".toByteArray()
    private val masterKeyAlias = "run_master_key"

    @Before
    fun setUp() {
        context = InstrumentationRegistry.getInstrumentation().targetContext
        CryptoManager.eraseMasterKey(context) // clean slate — force fresh provisioning
    }

    @After
    fun tearDown() {
        CryptoManager.eraseMasterKey(context)
    }

    /**
     * The spec must request unlocked-device binding plus the exact
     * AES-256-GCM / no-padding shape Tink expects, so Tink reuses our
     * pre-created key rather than auto-creating a non-auth-bound one.
     */
    @Test
    fun buildMasterKeySpec_isUnlockedDeviceRequired_andAes256Gcm() {
        val spec = CryptoManager.buildMasterKeySpec(masterKeyAlias)

        assertTrue(
            "master key must require an unlocked device",
            spec.isUnlockedDeviceRequired
        )
        assertEquals(masterKeyAlias, spec.keystoreAlias)
        assertEquals(256, spec.keySize)
        assertTrue(
            "must use GCM block mode",
            spec.blockModes.contains(KeyProperties.BLOCK_MODE_GCM)
        )
        assertTrue(
            "must use no encryption padding",
            spec.encryptionPaddings.contains(KeyProperties.ENCRYPTION_PADDING_NONE)
        )
        assertTrue(
            "must permit encrypt",
            spec.purposes and KeyProperties.PURPOSE_ENCRYPT != 0
        )
        assertTrue(
            "must permit decrypt",
            spec.purposes and KeyProperties.PURPOSE_DECRYPT != 0
        )
    }

    /**
     * Constructing [CryptoManager] from a clean slate must pre-create the
     * master key (so it's ours, not Tink's default) and still encrypt/decrypt.
     * KeyInfo can't reveal the unlocked-device flag, but it confirms the key
     * that backs the live keyset is the AES-256 key we generated.
     */
    @Test
    fun cryptoManager_provisionsMasterKey_andRoundTrips() {
        // No alias before first crypto use.
        val ksBefore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertTrue(
            "alias must be absent on a clean slate",
            !ksBefore.containsAlias(masterKeyAlias)
        )

        // Constructing CryptoManager triggers ensureMasterKey() + keyset wrap.
        val secret = "round-trip-secret".toByteArray()
        val cipher = CryptoManager(context).encrypt(secret, ctx)
        val plain = CryptoManager(context).decrypt(cipher, ctx)
        assertTrue("round-trip must recover plaintext", plain.contentEquals(secret))

        // The alias now exists and is a 256-bit AES Keystore key.
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertTrue("master key alias must exist after provisioning", ks.containsAlias(masterKeyAlias))

        val key = ks.getKey(masterKeyAlias, null) as SecretKey
        val info = SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
            .getKeySpec(key, KeyInfo::class.java) as KeyInfo
        assertNotNull(info)
        assertEquals("master key must be AES-256", 256, info.keySize)
    }
}
