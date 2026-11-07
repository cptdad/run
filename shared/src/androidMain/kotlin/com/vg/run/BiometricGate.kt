package com.vg.run

import android.annotation.SuppressLint
import android.app.Activity
import android.hardware.biometrics.BiometricPrompt
import android.os.CancellationSignal
import android.os.Handler
import android.os.Looper
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher

// ---------------------------------------------------------------------------
// BiometricGate — shows the PLATFORM BiometricPrompt (android.hardware.biometrics,
// API 28+; authenticator constants API 30+, minSdk 30) with a CryptoObject and
// bridges its async callback back to the synchronous, off-main DB-key unwrap.
//
// Deliberately the PLATFORM API, not androidx.biometric — that avoids adding a
// dependency (and its dependency-verification checksums) and needs only a plain
// Activity context, so MainActivity stays a ComponentActivity.
//
// The calling thread (Dispatchers.IO, from VaultSelector.unlock) blocks on a
// bounded queue while the prompt runs on the main thread. Any failure (no
// foreground Activity, user cancel, lockout, timeout) surfaces as
// KeyUnavailableException so the unlock path DEFERS (retry, never count/wipe).
// ---------------------------------------------------------------------------

/**
 * Holds the current foreground Activity so [BiometricGate] can present a prompt
 * from the shared module without a compile dependency on androidApp. MainActivity
 * sets it in onResume and clears it in onPause. @Volatile — read off the main
 * thread by the unwrap, written on the main thread by the lifecycle callbacks.
 */
object AuthActivityHolder {
    @Volatile
    var activity: Activity? = null
}

internal object BiometricGate {

    /**
     * Runs [BiometricPrompt] with [cryptoObject] and returns the AUTHENTICATED
     * CryptoObject (its cipher is authorized for exactly one operation), or
     * throws [KeyUnavailableException] on any non-success. Blocks the caller.
     */
    // USE_BIOMETRIC is declared by the consuming app; the shared library has no manifest,
    // so isolated `:shared:lint` reports a false MissingPermission — suppress it here.
    @SuppressLint("MissingPermission")
    @Throws(KeyUnavailableException::class)
    fun authenticate(
        cipher: Cipher,
        title: String,
        subtitle: String,
        // Mirror the KEY's authenticators (AuthBoundKeyStore.currentKeyAllowsDeviceCredential):
        // true for a LEGACY key that still allows a device credential (keep the passcode
        // door so a passcode-only-PRIVATE user isn't locked out); false for a new
        // BIOMETRIC-only key (no passcode door — a cracked passcode must not release it).
        allowDeviceCredential: Boolean,
    ): Cipher {
        // Must run OFF the main thread. It blocks on
        // outcome.poll() while the prompt is driven on the main looper; called ON
        // main the posted work could never run and it would deadlock for the full
        // timeout (ANR). Fail loudly rather than hang.
        check(Looper.myLooper() != Looper.getMainLooper()) {
            "BiometricGate.authenticate must not be called on the main thread"
        }

        val activity = AuthActivityHolder.activity
            ?: throw KeyUnavailableException("no foreground Activity for biometric prompt")

        // Carries either an authenticated Cipher (success) or a Throwable.
        val outcome = ArrayBlockingQueue<Any>(1)
        val cryptoObject = BiometricPrompt.CryptoObject(cipher)

        // Hoisted OUT of the posted lambda so the timeout / interrupt path below
        // can dismiss an orphaned system prompt. Left inside the lambda it was
        // unreachable, so a timed-out prompt stayed on screen and the next unlock's
        // BiometricPrompt was framework-rejected (a spurious extra defer).
        val cancel = CancellationSignal()
        Handler(Looper.getMainLooper()).post {
            try {
                val prompt = BiometricPrompt.Builder(activity)
                    .setTitle(title)
                    .setSubtitle(subtitle)
                    // MIRROR the key's authenticators (allowDeviceCredential): the prompt's
                    // allowed authenticators must match what the key requires, or auth can
                    // never release it. With DEVICE_CREDENTIAL a negative button must NOT be
                    // set; a BIOMETRIC-only prompt REQUIRES one (framework rules).
                    // setAllowedAuthenticators is API 30 (R); authenticate() only runs when
                    // unlocking a Lever-B vault (gated to API 30+), so the API 30 guard
                    // below is a lint formality at minSdk 30 (the SDK_INT check stays live).
                    .apply {
                        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R) {
                            if (allowDeviceCredential) {
                                setAllowedAuthenticators(
                                    android.hardware.biometrics.BiometricManager.Authenticators.BIOMETRIC_STRONG or
                                        android.hardware.biometrics.BiometricManager.Authenticators.DEVICE_CREDENTIAL
                                )
                            } else {
                                setAllowedAuthenticators(
                                    android.hardware.biometrics.BiometricManager.Authenticators.BIOMETRIC_STRONG
                                )
                                // Biometric-only: a negative button is mandatory. Tapping it
                                // fires onAuthenticationError(ERROR_NEGATIVE_BUTTON) → deferrable.
                                setNegativeButton("Cancel", activity.mainExecutor) { _, _ -> cancel.cancel() }
                            }
                        }
                    }
                    .build()
                prompt.authenticate(
                    cryptoObject,
                    cancel,
                    activity.mainExecutor,
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                            val c = result.cryptoObject?.cipher
                            outcome.offer(c ?: KeyUnavailableException("null authenticated cipher"))
                        }

                        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                            // Cancel / lockout / no-hardware / user-canceled all
                            // land here — all deferrable (retry), never a wipe.
                            outcome.offer(KeyUnavailableException("biometric error $errorCode: $errString"))
                        }
                        // onAuthenticationFailed (a single non-matching read) leaves
                        // the prompt up for a retry; do NOT resolve on it.
                    }
                )
            } catch (e: Exception) {
                outcome.offer(KeyUnavailableException("biometric prompt failed: ${e.message}"))
            }
        }

        // Bound the wait so a stuck prompt can't hang the unlock coroutine forever.
        val result = try {
            outcome.poll(120, TimeUnit.SECONDS)
        } catch (_: InterruptedException) {
            cancel.cancel()   // dismiss the prompt we posted before bailing out
            Thread.currentThread().interrupt()
            throw KeyUnavailableException("biometric wait interrupted")
        } ?: run {
            cancel.cancel()   // timed out — dismiss the orphaned system prompt
            throw KeyUnavailableException("biometric prompt timed out")
        }

        return when (result) {
            is Cipher -> result
            is Throwable -> throw KeyUnavailableException("biometric auth failed: ${result.message}")
            else -> throw KeyUnavailableException("unexpected biometric result")
        }
    }
}
