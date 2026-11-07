package com.vg.run

import java.util.concurrent.atomic.AtomicBoolean

// ---------------------------------------------------------------------------
// RAM-only state shared by both distribution flavours' VendorPush: the FIS
// teardown gate and the identity epoch. Pure Kotlin, no Firebase, so the state
// machines are unit-testable (FisTeardownGateTest, VendorPushIdentityEpochTest)
// and the `foss` flavour, whose VendorPush stub never arms them, compiles the
// same main code (WipeRoutine, PushRegistrationCoordinator) unchanged.
// ---------------------------------------------------------------------------

/**
 * RAM-only, process-wide gate meaning "a push-identity teardown has started its
 * Firebase revocation chain and that chain has not settled yet, so the
 * Installations SDK's own state file must NOT be deleted out from under it".
 * Extracted from [VendorPush] so the state machine is testable without Play
 * Services, an Android context or a device.
 *
 * WHY IT EXISTS — measured on a Samsung A20e (API 30, Play Services 26.33,
 * firebase-bom 34.19.0 / firebase-installations 19.1.2), 2026-09-17, and
 * confirmed against the SDK's bytecode:
 *
 * The teardown's own `FirebaseMessaging.deleteToken()` needs a Firebase
 * Installation to authenticate its RPC, so it runs `doRegistrationOrRefresh`,
 * which **re-reads** `PersistedInstallation.<key>.json` on the network executor
 * a few hundred milliseconds later. When the caller's synchronous
 * [VendorPush.sweepLocalArtifacts] deleted that file in between,
 * `readPersistedInstallationEntryValue` answered the ABSENT-file default —
 * `Status = ATTEMPT_MIGRATION, Fid = null, AuthToken = null` — and
 * `doNetworkCallIfNecessary` branches to `registerFidWithServer` only for
 * `isErrored() || isUnregistered()`. ATTEMPT_MIGRATION is neither, so with an
 * empty auth token it fell through to `fetchAuthTokenFromServer`, i.e.
 * `POST projects/{p}/installations/{NULL FID}/authTokens:generate`.
 *
 * FIS answers **400 INVALID_ARGUMENT** to that (proven by calling the SDK's own
 * service client with an empty fid: 400; with an empty refresh token: 401), and
 * `RequestLimiter.setNextRequestTime` classifies anything that is not 2xx/401/404
 * as a non-retryable CONFIGURATION error worth
 * `MAXIMUM_BACKOFF_DURATION_FOR_CONFIGURATION_ERRORS` = **24 HOURS**. From that
 * moment every `createFirebaseInstallation` / `generateAuthToken` in the process
 * throws `Firebase Installations Service is unavailable` from the limiter guard
 * (`FirebaseInstallationServiceClient.java:153`) without touching the network,
 * so [VendorPush.currentToken] returns null and re-enabling notifications fails
 * for the rest of the process ("Couldn't register for notifications"). Observed
 * twice on the same phone in the `push:unregister` e2e suite, which deliberately
 * never relaunches the app; a real user recovers only by backgrounding it (this
 * app tears the session down on background, so the next foreground return is a
 * fresh process with a fresh limiter).
 *
 * The gate defers EXACTLY ONE artifact — the Installations state file — and only
 * for as long as our own chain is in flight. Everything else the sweep removes
 * (the FCM token store, the auto-init prefs, the heartbeat datastore, the
 * cross-process lock, the no-backup marker) is still deleted synchronously, so
 * the wipe's "a process death mid-wipe leaves nothing readable" guarantee is
 * unchanged for all of them.
 *
 * Why RAM-only, and why it can only ever DELAY a delete: a stale persisted value
 * would suppress the deletion of a live bearer credential forever. A fresh
 * process starts UNARMED, which is the state in which everything is deleted.
 */
object FisTeardownGate {

    private val pending = java.util.concurrent.atomic.AtomicInteger(0)

    /** Armed by [VendorPush.destroyLocalPushIdentity] before it starts the chain. */
    fun arm() {
        pending.incrementAndGet()
    }

    /**
     * Released when that chain settles — or when it has provably run out of time
     * (VendorPush's SETTLE_WAIT_CAP_MS), because a credential left on disk is
     * worse than poisoning an SDK whose own requests have already timed out.
     * Idempotent per teardown: the caller owns the one-shot latch, so a settle
     * that arrives after the cap cannot double-release.
     */
    fun release() {
        pending.updateAndGet { if (it > 0) it - 1 else 0 }
    }

    /** Pure read — never clears as a side effect of being consulted. */
    fun isPending(): Boolean = pending.get() > 0

    /** Test-only: restore the unarmed state a fresh process starts in. */
    @androidx.annotation.VisibleForTesting
    fun resetForTest() {
        pending.set(0)
    }
}

/**
 * RAM-only latch meaning "this process destroyed the local FCM identity, so
 * whatever token the SDK still hands out is SUSPECT until a delete has been
 * PROVEN". Extracted from [VendorPush] so the state machine is testable without
 * Play Services, an Android context or a device.
 *
 * The failure mode it exists for (verified against firebase-messaging 24.1.0
 * bytecode). `FirebaseMessaging.deleteToken()` awaits its `GmsRpc.deleteToken()`
 * network RPC and calls `Store.deleteToken(...)` only afterwards, on the success
 * branch — an RPC failure sets the Task's exception and leaves the LOCAL token
 * cache untouched. [VendorPush.destroyLocalPushIdentity] chained the Firebase
 * Installation delete off `addOnCompleteListener`, i.e. destroyed the FID
 * whether or not the revocation landed. The result is a live cached token bound
 * to a destroyed installation: FCM keeps returning 2xx for sends to it and the
 * device never receives one. Nothing recovers on its own — `getToken()` serves
 * that same token from a process-wide static `Store` for its 7-day cache window,
 * this SDK exposes no force-refresh, and `RunFcmService.onNewToken` is a no-op
 * by design, so every later session re-registers the identical dead token.
 * Reproduced on a real Pixel; only an OFF/ON toggle (deleteToken + getToken)
 * recovered it.
 *
 * Why a RAM-only latch is safe here even though `vendorPushToken` /
 * `vendorPushRegisteredIds` must NOT be persisted: those are values whose
 * staleness SUPPRESSES a registration, which is why their session scoping is
 * load-bearing. This flag can only ever cause an EXTRA delete-and-refetch, never
 * suppress one — a fresh process starts DISARMED, which is precisely the state
 * that registers unconditionally. Persisting it would invert that and hand a
 * stale on-disk value the power to gate registration forever.
 */
object VendorPushIdentityEpoch {

    private val destroyed = AtomicBoolean(false)

    /** Armed by [VendorPush.destroyLocalPushIdentity]; nothing else arms it. */
    fun markIdentityDestroyed() {
        destroyed.set(true)
    }

    /** Pure read — it must never clear as a side effect of being consulted. */
    fun refreshRequired(): Boolean = destroyed.get()

    /**
     * The ONLY thing that disarms it, and only a `deleteToken()` that reported
     * SUCCESS may call it. A failed or throwing delete has to leave the latch
     * armed: registering nothing is retried by the next control-poll cycle,
     * whereas re-asserting a token we have positive reason to distrust is
     * permanent — nothing downstream ever re-examines a token once accepted.
     */
    fun markRefreshProven() {
        destroyed.set(false)
    }
}
