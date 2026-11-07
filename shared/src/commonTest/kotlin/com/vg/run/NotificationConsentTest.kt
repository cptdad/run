package com.vg.run

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ---------------------------------------------------------------------------
// The push opt-in is AUTHENTICATED before it can
// mint a vendor push identity.
//
// THE PROBLEM. `notif_level` was a plaintext string and the SOLE gate on
// handing a wake address to FCM/APNs/UnifiedPush and to the relay, at every
// launch and every unlock. Registration needs no OS prompt, so planting
// `vendor_push` turned a device into a push-registered one silently and
// repeatably.
//
// WHAT IS PINNED HERE:
//  1. Only a PROVEN consent proof answers anything but OFF — a plant, a damaged
//     blob and a transiently-unusable device key all answer OFF.
//  2. The legacy plaintext is trusted EXACTLY ONCE, and the latch that makes it
//     once is a `_meta` row INSIDE THE ENCRYPTED VAULT — never the presence of
//     the sealed slot, which lives in the very store this adversary can write.
//     `deletingTheProofAndPlantingThePlaintextIsNotASecondMigration` is the
//     regression test for that exact circularity. The latch is armed for EVERY
//     install, including one whose legacy value was "off" or absent, and a read
//     with NO OPEN VAULT never migrates at all.
//  3. The two slots move together on write and on clear, and an unproven write
//     is reported so the caller can revert instead of registering behind a
//     consent nothing will acknowledge.
//  4. The PLAINTEXT slot survives the migration, because it is the locked-screen
//     wake gate the push services read (the device key is unusable there by
//     construction on both platforms).
// ---------------------------------------------------------------------------

/** An in-memory [NotifLevelStore]; optionally fails the way the iOS Keychain can. */
private class FakeNotifStore(
    /** `kvPut` no-ops on a locked keybag: the write is DROPPED and nothing says so. */
    var silentlyDropWrites: Boolean = false,
) : NotifLevelStore {
    val values = mutableMapOf<String, String>()
    var writes = 0

    override fun get(key: String): String? = values[key]

    override fun putSync(key: String, value: String) {
        writes++
        if (silentlyDropWrites) return
        values[key] = value
    }

    override fun putAllSync(pairs: Map<String, String>) {
        writes++
        if (silentlyDropWrites) return
        values.putAll(pairs)
    }

    override fun remove(key: String) {
        values.remove(key)
    }
}

/**
 * The in-vault latch. `null` from [established] is "no open vault / meta
 * unreadable" — the state that must NEVER be read as "not established".
 */
private class FakeConsentMarker(
    var value: Long = 0L,
    /** No vault open, or its meta could not be read. */
    var unavailable: Boolean = false,
    /** The `_meta` write is lost (crash / @Throws putMeta failing). */
    var refuseWrite: Boolean = false,
) : NotifConsentMarker {
    var writes = 0

    override fun epoch(): Long? = if (unavailable) null else value

    override fun recordEpoch(epoch: Long): Boolean {
        writes++
        if (unavailable || refuseWrite) return false
        // MONOTONIC, like the real adapter: the self-heal must never rewind.
        if (epoch > value) value = epoch
        return value >= epoch
    }
}

/** The sealed payload for [level] at [epoch], as the store would write it. */
private fun sealedPayload(
    level: NotificationLevel,
    epoch: Long,
    cipher: FakeDeviceKeyCipher = FakeDeviceKeyCipher(),
): String = SealedPref.seal(cipher, NotificationLevelStore.SLOT_CONSENT, "${level.storageValue}:$epoch")

private const val PLAIN = NotificationLevelStore.KEY
private const val PROOF = NotificationLevelStore.KEY_CONSENT

private fun sealedLevel(level: NotificationLevel, cipher: FakeDeviceKeyCipher = FakeDeviceKeyCipher()): String =
    sealedPayload(level, NotificationLevelStore.FIRST_EPOCH, cipher)

class NotificationConsentTest {

    private val cipher = FakeDeviceKeyCipher()

    private val marker = FakeConsentMarker()

    private fun proven(
        store: FakeNotifStore,
        legacy: String? = store.values[PLAIN],
        latch: NotifConsentMarker = marker,
    ) = NotificationLevelStore.provenLevelIn(store, cipher, latch, legacy)

    // -- 1. only a proven proof decides ---------------------------------------

    @Test
    fun anAuthenticatedProofIsHonoured() {
        val store = FakeNotifStore()
        assertTrue(NotificationLevelStore.setLevelIn(store, cipher, marker, NotificationLevel.VENDOR_PUSH))
        assertEquals(NotificationLevel.VENDOR_PUSH, proven(store))

        assertTrue(NotificationLevelStore.setLevelIn(store, cipher, marker, NotificationLevel.UNIFIED_PUSH))
        assertEquals(NotificationLevel.UNIFIED_PUSH, proven(store), "a re-write replaces the proof")
    }

    @Test
    fun aPlantedProofReadsOff() {
        // Anything that is not an AEAD open under this slot's own context: the
        // bare token an attacker would copy from the plaintext slot, base64 that
        // decodes but is not ours, and outright garbage.
        for (planted in listOf("vendor_push", "unified_push", "dmVuZG9yX3B1c2g=", "!!!")) {
            val store = FakeNotifStore().also {
                it.values[PLAIN] = NotificationLevel.VENDOR_PUSH.storageValue
                it.values[PROOF] = planted
            }
            assertEquals(
                NotificationLevel.OFF,
                proven(store),
                "a planted proof (\"$planted\") must never authorise minting a push identity",
            )
            assertEquals(planted, store.values[PROOF], "and it must NOT be repaired from the plaintext slot")
        }
    }

    @Test
    fun aProofSealedForAnotherSlotReadsOff() {
        val store = FakeNotifStore().also {
            it.values[PROOF] = SealedPref.seal(cipher, DebugMode.SLOT, NotificationLevel.VENDOR_PUSH.storageValue)
        }
        assertEquals(NotificationLevel.OFF, proven(store))
    }

    @Test
    fun anUnreadableDeviceKeyAnswersOffAndWritesNothing() {
        val store = FakeNotifStore().also { it.values[PROOF] = sealedLevel(NotificationLevel.VENDOR_PUSH, cipher) }
        val locked = FakeDeviceKeyCipher(throwOnOpen = true)
        assertEquals(
            NotificationLevel.OFF,
            NotificationLevelStore.provenLevelIn(store, locked, marker, NotificationLevel.VENDOR_PUSH.storageValue),
        )
        assertEquals(0, store.writes, "a deferred read must not overwrite a healthy proof")
        // Registration is session-scoped and unconditional, so the next unlock
        // with a usable key registers again — nothing is lost, only deferred.
        assertEquals(NotificationLevel.VENDOR_PUSH, proven(store))
    }

    @Test
    fun aPermanentlyInvalidDeviceKeyAlsoAnswersOffRatherThanClaimingAForgery() {
        val store = FakeNotifStore().also { it.values[PROOF] = sealedLevel(NotificationLevel.VENDOR_PUSH, cipher) }
        val dead = FakeDeviceKeyCipher(permanentlyInvalid = true)
        assertEquals(NotificationLevel.OFF, NotificationLevelStore.provenLevelIn(store, dead, marker, null))
        assertEquals(0, store.writes)
    }

    // -- 2. the one-time legacy trust, and its latch ---------------------------

    @Test
    fun legacyPlaintextMigratesOnceAndTheVaultMarkerBecomesTheLatch() {
        // A real user who opted into push before this shipped: the plaintext is
        // all there is, and it is trusted ONCE so their device keeps waking.
        val store = FakeNotifStore().also { it.values[PLAIN] = NotificationLevel.VENDOR_PUSH.storageValue }

        assertEquals(NotificationLevel.VENDOR_PUSH, proven(store))
        val sealedAfterMigration = store.values[PROOF]
        assertNotNull(sealedAfterMigration)
        assertEquals(
            "${NotificationLevel.VENDOR_PUSH.storageValue}:${NotificationLevelStore.FIRST_EPOCH}",
            SealedPref.open(cipher, NotificationLevelStore.SLOT_CONSENT, sealedAfterMigration).value,
            "the legacy establish seals at epoch 1",
        )
        // The plaintext slot SURVIVES: it is the locked-screen wake gate.
        assertEquals(NotificationLevel.VENDOR_PUSH.storageValue, store.values[PLAIN])

        // The LATCH is the in-vault epoch, not the presence of the sealed slot.
        assertEquals(NotificationLevelStore.FIRST_EPOCH, marker.epoch())

        // …and from here the plaintext has no vote. Plant the opposite value:
        // the proof still decides, and nothing is rewritten.
        val writesAfterMigration = store.writes
        store.values[PLAIN] = NotificationLevel.OFF.storageValue
        assertEquals(NotificationLevel.VENDOR_PUSH, proven(store))
        assertEquals(writesAfterMigration, store.writes, "the migration must run exactly once")
    }

    @Test
    fun theLatchIsArmedEvenWhenTheLegacyValueIsOff() {
        // THE RESIDUAL-CLOSING CASE. An install that never enabled push has no
        // plaintext at all; if the migration only ran for installs that DID,
        // the proof slot would stay empty forever and a plaintext plant would be
        // trusted at any later moment — i.e. the weakness, unfixed, for most
        // users. The establish therefore writes a sealed "off".
        val store = FakeNotifStore()
        assertEquals(NotificationLevel.OFF, NotificationLevelStore.provenLevelIn(store, cipher, marker, null))
        assertNotNull(store.values[PROOF], "the latch is armed for every install")

        // A plant made afterwards buys nothing.
        store.values[PLAIN] = NotificationLevel.VENDOR_PUSH.storageValue
        assertEquals(NotificationLevel.OFF, proven(store))
    }

    @Test
    fun anUnprovenMigrationWriteDoesNotClaimTheLegacyLevel() {
        // iOS `kvPut` no-ops on a locked keybag. Returning VENDOR_PUSH over a
        // write that never landed would repeat the legacy trust every session
        // while pretending it had been retired — so an unproven write answers
        // OFF and the next session tries again.
        val store = FakeNotifStore(silentlyDropWrites = true).also {
            it.values[PLAIN] = NotificationLevel.VENDOR_PUSH.storageValue
        }
        assertEquals(NotificationLevel.OFF, proven(store))
        assertNull(store.values[PROOF])

        store.silentlyDropWrites = false
        assertEquals(NotificationLevel.VENDOR_PUSH, proven(store), "and it converges once the store accepts a write")
    }

    @Test
    fun anUnknownLegacyTokenMigratesToOff() {
        // POLL is dead and nothing can deliver it; an unrecognised token is the
        // same class. Both seal as OFF rather than leaving the slot empty.
        val store = FakeNotifStore().also { it.values[PLAIN] = "something-else" }
        assertEquals(NotificationLevel.OFF, proven(store))
        assertEquals(
            "${NotificationLevel.OFF.storageValue}:${NotificationLevelStore.FIRST_EPOCH}",
            SealedPref.open(cipher, NotificationLevelStore.SLOT_CONSENT, store.values[PROOF]).value,
        )
    }

    // -- 3. the two slots move together ---------------------------------------

    @Test
    fun setLevelWritesBothSlotsInOneBatch() {
        val store = FakeNotifStore()
        assertTrue(NotificationLevelStore.setLevelIn(store, cipher, marker, NotificationLevel.VENDOR_PUSH))
        assertEquals(1, store.writes, "one coupled write, never two — iOS Keychain has no transaction")
        assertEquals(NotificationLevel.VENDOR_PUSH.storageValue, store.values[PLAIN])
        assertEquals(
            "${NotificationLevel.VENDOR_PUSH.storageValue}:1",
            SealedPref.open(cipher, NotificationLevelStore.SLOT_CONSENT, store.values[PROOF]).value,
        )
    }

    @Test
    fun setLevelReportsFalseWhenTheWriteIsDropped() {
        val store = FakeNotifStore(silentlyDropWrites = true)
        assertFalse(
            NotificationLevelStore.setLevelIn(store, cipher, marker, NotificationLevel.VENDOR_PUSH),
            "an unproven consent write must be reported, so the enable reverts instead of registering silently",
        )
    }

    @Test
    fun setLevelPersistsNothingWhenTheDeviceKeyCannotSeal() {
        val store = FakeNotifStore()
        val locked = FakeDeviceKeyCipher(throwOnSeal = true)
        assertFalse(NotificationLevelStore.setLevelIn(store, locked, marker, NotificationLevel.VENDOR_PUSH))
        assertNull(store.values[PLAIN], "a plaintext-only write is the pre-fix shape and must never be left behind")
        assertNull(store.values[PROOF])
    }

    @Test
    fun setConsentProofTouchesOnlyTheProof() {
        // The iOS half: Swift owns the plaintext slot (NSUserDefaults), Kotlin
        // owns the proof, so this write must not invent a plaintext value in the
        // Keychain that the Swift reader will never see.
        val store = FakeNotifStore()
        assertTrue(NotificationLevelStore.setConsentProofIn(store, cipher, marker, NotificationLevel.VENDOR_PUSH))
        assertNull(store.values[PLAIN])
        assertEquals(NotificationLevel.VENDOR_PUSH, proven(store, legacy = null))
    }

    @Test
    fun clearLevelRemovesThePlaintextAndRetiresTheProof() {
        val store = FakeNotifStore()
        NotificationLevelStore.setLevelIn(store, cipher, marker, NotificationLevel.VENDOR_PUSH)
        NotificationLevelStore.clearLevelIn(store, cipher, marker)
        assertNull(store.values[PLAIN], "the wake gate is REMOVED, never written to \"off\" (M6)")
        assertEquals(
            "${NotificationLevel.OFF.storageValue}:2",
            SealedPref.open(cipher, NotificationLevelStore.SLOT_CONSENT, store.values[PROOF]).value,
            "the surviving proof is an explicit OFF at a FRESH epoch — that is what kills the old blobs",
        )
        // …and the vault latch survives the revocation, so the next read answers
        // OFF outright instead of re-deriving anything from the plaintext.
        assertTrue((marker.epoch() ?: 0L) >= NotificationLevelStore.FIRST_EPOCH)
        assertEquals(NotificationLevel.OFF, proven(store, legacy = null))
    }

    // -- 3b. the IN-VAULT latch (closure pass) --------------------------

    @Test
    fun deletingTheProofAndPlantingThePlaintextIsNotASecondMigration() {
        // THE EXACT ATTACK the first cut of this fix left open. The sealed slot
        // lives in the very store this threat's adversary can write, so using
        // its own PRESENCE as the "already migrated" latch was circular: delete
        // `notif_consent`, plant `notif_level=vendor_push`, and the next read was
        // indistinguishable from a first-run upgrade. The latch is now a `_meta`
        // row inside the encrypted vault, which that adversary cannot reach.
        val store = FakeNotifStore().also { it.values[PLAIN] = NotificationLevel.OFF.storageValue }
        assertEquals(NotificationLevel.OFF, proven(store))
        assertEquals(NotificationLevelStore.FIRST_EPOCH, marker.epoch(), "precondition: the establish latched at epoch 1")

        store.values.remove(PROOF)                                   // attacker deletes the proof
        store.values[PLAIN] = NotificationLevel.VENDOR_PUSH.storageValue  // …and plants the level

        assertEquals(
            NotificationLevel.OFF,
            proven(store),
            "a deleted proof over a latched vault is a REVOCATION, never a fresh migration",
        )
        assertEquals(
            "${NotificationLevel.OFF.storageValue}:2",
            SealedPref.open(cipher, NotificationLevelStore.SLOT_CONSENT, store.values[PROOF]).value,
            "the absent proof is replaced by an explicit OFF at a fresh epoch — never re-derived from the plant",
        )
        // Repeatability was the sting: assert it stays shut however often it is tried.
        repeat(3) { assertEquals(NotificationLevel.OFF, proven(store)) }
    }

    @Test
    fun theEstablishRunsOnceAndSetsTheVaultMarker() {
        val store = FakeNotifStore().also { it.values[PLAIN] = NotificationLevel.VENDOR_PUSH.storageValue }
        assertEquals(NotificationLevel.VENDOR_PUSH, proven(store))
        assertEquals(NotificationLevelStore.FIRST_EPOCH, marker.value)
        val writesAfterEstablish = store.writes
        val markerWritesAfterEstablish = marker.writes

        repeat(3) { proven(store) }
        assertEquals(writesAfterEstablish, store.writes, "the migration must not re-run")
        assertEquals(markerWritesAfterEstablish, marker.writes, "and the latch must not be re-written")
    }

    @Test
    fun aLostMarkerWriteSelfHealsOnTheNextProvenRead() {
        // ORDER: seal, then latch. A crash (or a @Throws putMeta failure) between
        // them leaves a PROVEN proof with no latch — and every later read takes
        // the PROVEN branch, so without the self-heal that gap would stay open
        // for the life of the install.
        val store = FakeNotifStore().also { it.values[PLAIN] = NotificationLevel.VENDOR_PUSH.storageValue }
        marker.refuseWrite = true
        assertEquals(NotificationLevel.VENDOR_PUSH, proven(store), "the seal landed, so the level is honoured")
        assertEquals(0L, marker.epoch(), "precondition: the latch did NOT land")

        marker.refuseWrite = false
        assertEquals(NotificationLevel.VENDOR_PUSH, proven(store))
        assertEquals(NotificationLevelStore.FIRST_EPOCH, marker.epoch(), "epoch+1 over epoch is the crash window — honour and heal")

        // …and the attack is shut from here.
        store.values.remove(PROOF)
        store.values[PLAIN] = NotificationLevel.VENDOR_PUSH.storageValue
        assertEquals(NotificationLevel.OFF, proven(store))
    }

    @Test
    fun aGenuineOptInLatchesToo() {
        // A first-ever opt-in on an install that never ran the establish must
        // record the decision as well, or deleting the proof straight afterwards
        // would send the next read back through the legacy branch.
        val store = FakeNotifStore()
        assertTrue(NotificationLevelStore.setLevelIn(store, cipher, marker, NotificationLevel.VENDOR_PUSH))
        assertEquals(NotificationLevelStore.FIRST_EPOCH, marker.epoch())

        store.values.remove(PROOF)
        assertEquals(NotificationLevel.OFF, proven(store))
    }

    @Test
    fun withNoOpenVaultTheMigrationIsSkippedEntirely() {
        // `epoch()` answers null — "cannot tell". Collapsing that into 0
        // ("never established") would hand the attack straight back: delete the
        // proof, plant the level, read while no vault is open.
        val store = FakeNotifStore().also { it.values[PLAIN] = NotificationLevel.VENDOR_PUSH.storageValue }
        val noVault = FakeConsentMarker(unavailable = true)

        assertEquals(NotificationLevel.OFF, proven(store, latch = noVault))
        assertNull(store.values[PROOF], "nothing may be sealed without the latch")
        assertEquals(0, store.writes)

        // The same read with a vault open migrates exactly once.
        assertEquals(NotificationLevel.VENDOR_PUSH, proven(store))
    }

    @Test
    fun aFreshInstallNeverBlessesAnythingOn() {
        // No legacy plaintext at all: the establish must seal OFF, never a
        // proven ON, and must still latch so a later plant is inert.
        val store = FakeNotifStore()
        assertEquals(NotificationLevel.OFF, proven(store, legacy = null))
        assertEquals(
            "${NotificationLevel.OFF.storageValue}:${NotificationLevelStore.FIRST_EPOCH}",
            SealedPref.open(cipher, NotificationLevelStore.SLOT_CONSENT, store.values[PROOF]).value,
        )
        assertTrue(marker.epoch()!! >= NotificationLevelStore.FIRST_EPOCH)

        store.values[PLAIN] = NotificationLevel.VENDOR_PUSH.storageValue
        assertEquals(NotificationLevel.OFF, proven(store))
    }

    // -- 3c. FRESHNESS: the epoch binding (replay) ------------------------------

    /** Opts in, returns the blob an operator would image off the device. */
    private fun optInAndImage(store: FakeNotifStore): String {
        assertTrue(NotificationLevelStore.setLevelIn(store, cipher, marker, NotificationLevel.VENDOR_PUSH))
        assertEquals(NotificationLevel.VENDOR_PUSH, proven(store))
        return store.values.getValue(PROOF)
    }

    /** Puts the imaged blob (and its plaintext gate) back, as a restore would. */
    private fun restore(store: FakeNotifStore, imaged: String) {
        store.values[PROOF] = imaged
        store.values[PLAIN] = NotificationLevel.VENDOR_PUSH.storageValue
    }

    @Test
    fun aRestoredOlderProofDoesNotRevertALaterOptOut_viaTheSHIPPEDOptOutPath() {
        // THE REPLAY, through the path production actually takes. `SealedPref`
        // binds only the slot NAME, so every blob this device ever sealed keeps
        // decrypting under the same device key: image the filesystem while push
        // is ON, wait for the user to opt OUT, restore the old `notif_consent`.
        //
        // The opt-out here is `clearLevelIn` — `RunViewModel`'s Settings toggle,
        // `RunPushService.onUnregistered`, `UnifiedPushSupport`'s
        // distributor-gone sweep and iOS `clearPushConsent` all route through it.
        // An earlier revision of this test opted out with `setLevelIn(OFF)`,
        // which no shipped caller uses, so it passed over a live bypass: a bare
        // removal left the vault epoch at the last proven-ON value, and the
        // restored blob was an EXACT match.
        val store = FakeNotifStore()
        val imagedWhileOn = optInAndImage(store)
        val epochWhileOn = marker.epoch()

        NotificationLevelStore.clearLevelIn(store, cipher, marker)
        assertNull(store.values[PLAIN], "the wake gate goes off the instant the user opts out")
        assertTrue(marker.epoch()!! > epochWhileOn!!, "an opt-out must ADVANCE the epoch")
        assertEquals(NotificationLevel.OFF, proven(store))

        restore(store, imagedWhileOn)
        assertEquals(
            NotificationLevel.OFF,
            proven(store),
            "a proof from an older epoch is a replay, however perfectly it decrypts",
        )
        repeat(3) { assertEquals(NotificationLevel.OFF, proven(store)) }
    }

    @Test
    fun anOptOutTakenWithNoVaultInvalidatesAtTheNextVaultOpenRead() {
        // `RunPushService.onUnregistered` / `UnifiedPushSupport`'s teardown run in
        // a process with no vault, so the epoch cannot move at that moment. The
        // removal still lands, and the next read WITH a vault must invalidate
        // before it does anything else.
        val store = FakeNotifStore()
        val imagedWhileOn = optInAndImage(store)
        val epochWhileOn = marker.epoch()!!

        val noVault = FakeConsentMarker(unavailable = true)
        NotificationLevelStore.clearLevelIn(store, cipher, noVault)
        assertNull(store.values[PROOF])
        assertNull(store.values[PLAIN])
        assertEquals(epochWhileOn, marker.epoch(), "nothing could be recorded without a vault")

        // Next unlock: the proof is absent over an established latch ⇒ invalidate.
        assertEquals(NotificationLevel.OFF, proven(store))
        assertTrue(marker.epoch()!! > epochWhileOn)

        restore(store, imagedWhileOn)
        assertEquals(NotificationLevel.OFF, proven(store), "the imaged blob is dead from that read on")
    }

    @Test
    fun anAbsentProofOverAnEstablishedLatchInvalidatesExactlyOnce() {
        // The invalidation is a SEAL, not a bare counter bump, precisely so it is
        // idempotent: a bump would re-fire on every read for as long as the user
        // stayed opted out — one durable `_meta` write per control-poll cycle.
        val store = FakeNotifStore()
        optInAndImage(store)
        store.values.remove(PROOF)

        assertEquals(NotificationLevel.OFF, proven(store))
        val epochAfterInvalidation = marker.epoch()
        val markerWrites = marker.writes
        val storeWrites = store.writes

        repeat(5) { assertEquals(NotificationLevel.OFF, proven(store)) }
        assertEquals(epochAfterInvalidation, marker.epoch(), "the epoch must advance ONCE, not per read")
        assertEquals(markerWrites, marker.writes)
        assertEquals(storeWrites, store.writes)
    }

    @Test
    fun aProofOneEpochAHEADIsTheCrashWindow_honouredAndHealed() {
        // Seal FIRST, latch SECOND: a crash between them leaves epoch n+1 sealed
        // over epoch n latched. That is OUR torn write, not a replay (a replay is
        // always BEHIND), so it is honoured and the latch heals forward — which
        // is also what stops the window from staying open.
        val store = FakeNotifStore()
        NotificationLevelStore.setLevelIn(store, cipher, marker, NotificationLevel.VENDOR_PUSH)
        NotificationLevelStore.setLevelIn(store, cipher, marker, NotificationLevel.OFF)
        assertEquals(2L, marker.epoch(), "precondition: two proven writes")

        store.values[PROOF] = sealedPayload(NotificationLevel.VENDOR_PUSH, 3L, cipher)
        marker.value = 2L
        assertEquals(NotificationLevel.VENDOR_PUSH, proven(store))
        assertEquals(3L, marker.epoch(), "the latch heals FORWARD to the blob's epoch")
    }

    @Test
    fun aProofOneEpochBEHINDIsRefused() {
        val store = FakeNotifStore()
        marker.value = 2L
        store.values[PROOF] = sealedPayload(NotificationLevel.VENDOR_PUSH, 1L, cipher)
        assertEquals(NotificationLevel.OFF, proven(store))
        assertEquals(2L, marker.epoch(), "and a refused read never touches the latch")
    }

    @Test
    fun aProofTooFarAheadIsRefused_andTheLatchNeverRewinds() {
        val store = FakeNotifStore()
        marker.value = 2L
        // Two ahead is not a torn write of ours — nothing legitimate skips an epoch.
        store.values[PROOF] = sealedPayload(NotificationLevel.VENDOR_PUSH, 4L, cipher)
        assertEquals(NotificationLevel.OFF, proven(store))
        assertEquals(2L, marker.epoch())

        // And the monotonic rule: a stale record can never pull the counter back.
        assertTrue(marker.recordEpoch(1L))
        assertEquals(2L, marker.epoch(), "recordEpoch must never rewind")
    }

    @Test
    fun aProofWithNoEpochInItReadsOff() {
        // A blob in the pre-epoch shape (or any payload without the separator)
        // cannot be placed in time, so it is not a current consent.
        val store = FakeNotifStore().also {
            it.values[PROOF] = SealedPref.seal(
                cipher,
                NotificationLevelStore.SLOT_CONSENT,
                NotificationLevel.VENDOR_PUSH.storageValue,
            )
        }
        marker.value = 1L
        assertEquals(NotificationLevel.OFF, proven(store))
    }

    @Test
    fun theLegacyEstablishRecordsEpochOne() {
        val store = FakeNotifStore().also { it.values[PLAIN] = NotificationLevel.VENDOR_PUSH.storageValue }
        assertEquals(NotificationLevel.VENDOR_PUSH, proven(store))
        assertEquals(NotificationLevelStore.FIRST_EPOCH, marker.epoch())
        assertEquals(
            "${NotificationLevel.VENDOR_PUSH.storageValue}:1",
            SealedPref.open(cipher, NotificationLevelStore.SLOT_CONSENT, store.values[PROOF]).value,
        )
    }

    // -- 4. the sealed form itself ---------------------------------------------

    @Test
    fun theSealedFormIsAConstantLengthAcrossEveryLevel() {
        // Without the fixed-length padding, "off" (3 B) and
        // "unified_push" (12 B) are distinguishable at rest with no device key
        // and no decryption — the tier/mode length side-channel `vlt_lvl` and
        // `vlt_m` already close.
        val lengths = NotificationLevel.entries.map { sealedLevel(it, cipher).length }.distinct()
        assertEquals(1, lengths.size, "every level must seal to the same ciphertext length")
    }
}
