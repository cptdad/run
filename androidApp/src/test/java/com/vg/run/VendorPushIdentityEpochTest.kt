package com.vg.run

import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.FixMethodOrder
import org.junit.Test
import org.junit.runners.MethodSorters

/**
 * The state machine behind the 2026-08-09 dead-token fix, tested off-device —
 * which is why [VendorPushIdentityEpoch] is a separate object with no Android
 * or Play-Services surface at all.
 *
 * What it guards (verified against firebase-messaging 24.1.0 bytecode):
 * `FirebaseMessaging.deleteToken()` awaits its `GmsRpc.deleteToken()` RPC and
 * calls `Store.deleteToken(...)` only on the success branch, so a failed
 * revocation leaves the LOCAL token cache intact. `destroyLocalPushIdentity`
 * chained the Firebase Installation delete off `addOnCompleteListener`, i.e.
 * destroyed the FID either way, stranding a live cached token bound to a
 * destroyed installation — FCM returns 2xx for it and the device never receives
 * it. `getToken()` then serves that token from a process-wide static `Store`
 * for its 7-day window with no force-refresh API, so every later session
 * re-registered the identical dead token.
 *
 * The three properties below are what makes the latch safe to keep in RAM only
 * (the token itself must never be persisted): it can cause an EXTRA
 * delete-and-refetch, never suppress a registration.
 *
 * NAME_ASCENDING because the object is a process-wide singleton and exactly one
 * property — the initial value of its field — is only observable before anything
 * has touched it. `t1_` therefore runs first; every later test normalises the
 * state itself, and [tearDown] leaves it disarmed for any other class.
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
class VendorPushIdentityEpochTest {

    @After
    fun tearDown() {
        VendorPushIdentityEpoch.markRefreshProven()
    }

    /**
     * A fresh process must start DISARMED. This is the property the unconditional re-register leans on: a
     * new session re-registers unconditionally, so the latch must not be able to
     * gate the first fetch of a process that destroyed nothing.
     */
    @Test
    fun t1_startsDisarmed() {
        assertFalse(
            "a fresh process must not require a proven refresh — an armed default would " +
                "gate the very first registration of a session that destroyed nothing",
            VendorPushIdentityEpoch.refreshRequired(),
        )
    }

    @Test
    fun t2_markIdentityDestroyed_arms() {
        VendorPushIdentityEpoch.markRefreshProven()

        VendorPushIdentityEpoch.markIdentityDestroyed()

        assertTrue(
            "destroying the local identity must mark every subsequent token suspect",
            VendorPushIdentityEpoch.refreshRequired(),
        )
    }

    /**
     * Reading must not clear. A read-and-clear would hand exactly one caller the
     * obligation to prove the refresh, and any other caller reaching
     * `currentToken` first (unlock, control poll, toggle — three concurrent
     * coroutines) would silently consume the signal and register the dead token.
     */
    @Test
    fun t3_refreshRequired_neverAutoClears() {
        VendorPushIdentityEpoch.markRefreshProven()
        VendorPushIdentityEpoch.markIdentityDestroyed()

        repeat(5) {
            assertTrue(
                "consulting the latch must be a pure read — it stays armed until a delete " +
                    "has actually been proven",
                VendorPushIdentityEpoch.refreshRequired(),
            )
        }
    }

    /**
     * Only a PROVEN delete disarms it. A failed `deleteToken()` must leave the
     * latch armed: the caller returns null and registers nothing, which the next
     * control-poll cycle retries, whereas re-asserting a token we have positive
     * reason to distrust is permanent — nothing downstream ever re-examines an
     * accepted token.
     */
    @Test
    fun t4_onlyAProvenRefreshClears() {
        VendorPushIdentityEpoch.markRefreshProven()
        VendorPushIdentityEpoch.markIdentityDestroyed()

        // Arming is idempotent, and a second teardown must not "cancel out".
        VendorPushIdentityEpoch.markIdentityDestroyed()
        assertTrue(VendorPushIdentityEpoch.refreshRequired())

        VendorPushIdentityEpoch.markRefreshProven()
        assertFalse(
            "a proven delete is the one and only thing that disarms the latch",
            VendorPushIdentityEpoch.refreshRequired(),
        )
    }

    /**
     * The late-settle case: `destroyLocalPushIdentity`'s chain is async and its
     * last link deletes the Firebase Installation. A user who re-enables push
     * seconds after a failed enable can complete a proven refresh — latch
     * cleared, fresh token fetched and registered — BEFORE that installation
     * delete lands, which then destroys the FID the brand-new token is bound to
     * and recreates the dead-token state. Re-arming on settle costs one extra
     * delete-and-refetch on the next registration pass and can never suppress
     * one, so arming after a clear must simply work.
     */
    @Test
    fun t5_reArmsAfterAProvenRefresh() {
        VendorPushIdentityEpoch.markRefreshProven()
        VendorPushIdentityEpoch.markIdentityDestroyed()
        VendorPushIdentityEpoch.markRefreshProven()

        VendorPushIdentityEpoch.markIdentityDestroyed()

        assertTrue(
            "an identity teardown that settles AFTER a proven refresh must re-arm — the " +
                "token minted in between is bound to an installation that delete destroyed",
            VendorPushIdentityEpoch.refreshRequired(),
        )
    }
}
