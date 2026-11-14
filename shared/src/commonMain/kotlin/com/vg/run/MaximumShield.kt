package com.vg.run

// ---------------------------------------------------------------------------
// "Maximum shield" — a device at the MAXIMUM protection tier tells each 1:1
// contact "I use Maximum" (and, on leaving, "I no longer do"); a device that is
// itself at MAXIMUM remembers which contacts told it so and shows a small shield
// after their name. Owner decisions 2026-11-12 (mandatory, no toggle; claim
// REMEMBERED in the encrypted vault; devices below MAXIMUM never send, never
// store, never show).
//
// WIRE. A direct control message on the existing per-contact control channel,
// modelled on the screenshot notice: kind [MessageManager.CONTROL_KIND_PLEVEL]
// ("plvl"), body EXACTLY `{"max":"1"}` or `{"max":"0"}` (see [MaximumShieldPolicy.parseBody]
// — anything else is dropped). It rides the static control envelope (it is NOT a
// ratchet-sealed kind), push-suppressed, with the uniform control TTL. An older
// build classes the kind as unknown and drops it silently on both receive paths
// (docs/vault-relay-internals.md, "Maximum shield").
//
// STATE (all in the encrypted vault `_meta`, both keys in `ratchetMetaKeysForContact`
// so they die with the contact / a re-pair, and both in MoveMetaPolicy so they
// travel on a device move):
//   • `plvl-peer/<contactId>` — RECEIVER: this contact reported Maximum. Presence
//     is the whole fact ("1"); a 0 announcement deletes it. Written ONLY while this
//     device is at MAXIMUM.
//   • `plvl-sent/<contactId>` — SENDER: "1" = we last SUCCESSFULLY announced Maximum
//     to this contact. Absent = nothing announced (or a 0 was announced and the
//     marker deleted: a permanent "0" row on every contact would be a residue that
//     says "this device once used Maximum" for no benefit).
//
// SEND RULE ([reconcile]). Nothing is sent in steady state. Maximum & marker!="1" →
// send 1, set marker only after the relay accepted it; not Maximum & marker=="1" →
// send 0, delete marker. Unsent ones are retried by the next control sweep (the
// sweep is the "session start / after a tier change or a pairing" cadence — it runs
// seconds after unlock and every 60-90 s idle). Bounded per pass, spread with random
// delays, fail-soft, and never run on the unlock/connect path.
//
// CONVERGENCE. A Maximum device that receives a 1 for a contact it held NO claim for
// clears its own marker for that contact, so its own 1 is re-sent once: two phones
// that reached Maximum at different times learn about each other. A 1 for an already-
// stored claim triggers nothing, so the exchange terminates after at most three
// messages (pinned by MaximumShieldTest.noPingPong).
//
// "AM I AT MAXIMUM" comes from [VaultSelector.maximumShieldLevel] — the same
// device-key-AEAD `vlt_lvl` slot the enforcement readers use, but STRICTER than
// [VaultSelector.protectionLevelForEnforcement]: enforcement fails SECURE to MAXIMUM on an
// unauthenticated (plantable) value, which would let a forged cleartext `maximum`
// make a device announce a tier it is not on. Here anything unproven is AMBIGUOUS
// and AMBIGUOUS is inert: send nothing, store nothing, delete nothing.
//
// PRIVACY. No identifier, alias or level is ever logged: every log line below is a
// constant string.
// ---------------------------------------------------------------------------

/** The tri-state "is this device at MAXIMUM" answer the shield acts on. */
enum class MaximumShieldLevel { MAXIMUM, NOT_MAXIMUM, AMBIGUOUS }

internal object MaximumShieldPolicy {
    const val PEER_PREFIX = "plvl-peer/"
    const val SENT_PREFIX = "plvl-sent/"
    const val BODY_MAX = """{"max":"1"}"""
    const val BODY_NOT_MAX = """{"max":"0"}"""

    /** `_meta` key: this contact reported Maximum (receiver side). */
    fun peerClaimKey(contactId: String) = PEER_PREFIX + contactId

    /** `_meta` key: the value last successfully announced to this contact (sender side). */
    fun sentMarkerKey(contactId: String) = SENT_PREFIX + contactId

    fun bodyFor(max: Boolean): String = if (max) BODY_MAX else BODY_NOT_MAX

    /**
     * The one-flag payload, STRICT: exactly [BODY_MAX] -> true, exactly [BODY_NOT_MAX]
     * -> false, anything else (extra fields, whitespace, another value, null, empty)
     * -> null = drop.
     */
    fun parseBody(body: String?): Boolean? = when (body) {
        BODY_MAX -> true
        BODY_NOT_MAX -> false
        else -> null
    }

    /**
     * The shield's level decision from a raw `vlt_lvl` read. Only an AUTHENTICATED,
     * parseable level is an answer; never chosen, unauthenticated (legacy cleartext /
     * a plant), authenticated-but-unparseable (a newer tier) are all AMBIGUOUS.
     */
    fun levelOf(present: Boolean, authenticated: Boolean, storedValue: String?): MaximumShieldLevel {
        if (!present || !authenticated || storedValue == null) return MaximumShieldLevel.AMBIGUOUS
        val level = ProtectionLevel.fromStorageOrNull(storedValue) ?: return MaximumShieldLevel.AMBIGUOUS
        return if (level == ProtectionLevel.MAXIMUM) MaximumShieldLevel.MAXIMUM else MaximumShieldLevel.NOT_MAXIMUM
    }
}

/**
 * Receiver + sender logic of the Maximum shield. Stateless: every method reads the
 * vault, so lock/wipe needs no participation (there is nothing in RAM to scrub).
 * Never throws; blocking vault I/O — call from the polls' background context.
 *
 * [levelProbe] is [VaultSelector.maximumShieldLevel] on both platforms. [sleeper] and
 * [jitterMs] exist so tests do not sleep.
 */
class MaximumShield(
    private val vault: VaultDatabase,
    private val levelProbe: () -> MaximumShieldLevel,
    private val sleeper: (Long) -> Unit = { sleepMillis(it) },
    private val jitterMs: () -> Long = { MessageManager.jitterMs(SEND_SPREAD_BASE_MS, SEND_SPREAD_RANGE_MS) },
) {
    private val passLock = SyncLock()
    private var passRunning = false

    private fun level(): MaximumShieldLevel = try {
        levelProbe()
    } catch (_: Exception) {
        MaximumShieldLevel.AMBIGUOUS
    }

    /**
     * Applies one received announcement from [contactId] (the caller has already
     * authenticated the sender via the pairwise channel and checked the contact
     * exists). Silent when this device is not at MAXIMUM — "without a trace".
     */
    fun onAnnouncement(contactId: String, body: String?) {
        if (level() != MaximumShieldLevel.MAXIMUM) return
        val flag = MaximumShieldPolicy.parseBody(body)
        if (flag == null) {
            platformLogWarn(TAG, "level announcement malformed - dropped")
            return
        }
        try {
            val peerKey = MaximumShieldPolicy.peerClaimKey(contactId)
            if (flag) {
                // A 1 for an already-stored claim does NOTHING (no write, no marker
                // change): that is what stops two Maximum phones ping-ponging.
                if (vault.getMeta(peerKey) != null) return
                vault.putMeta(peerKey, "1")
                // unknown -> 1: re-send our own 1 once (convergence for late adopters).
                val sentKey = MaximumShieldPolicy.sentMarkerKey(contactId)
                if (vault.getMeta(sentKey) != null) vault.deleteMeta(sentKey)
            } else if (vault.getMeta(peerKey) != null) {
                vault.deleteMeta(peerKey)
            }
        } catch (e: Exception) {
            platformLogWarn(TAG, "level announcement not stored: ${e::class.simpleName}")
        }
    }

    /**
     * The contact ids this device should show a shield for: empty unless the device
     * is (provably) at MAXIMUM, so the UI is correct the instant the tier changes,
     * before [reconcile] has swept the stored claims away.
     */
    fun claimedContactIds(): Set<String> {
        if (level() != MaximumShieldLevel.MAXIMUM) return emptySet()
        return try {
            vault.metaKeys()
                .filter { it.startsWith(MaximumShieldPolicy.PEER_PREFIX) }
                .map { it.removePrefix(MaximumShieldPolicy.PEER_PREFIX) }
                .toSet()
        } catch (_: Exception) {
            emptySet()
        }
    }

    /** True when [contactId] reported Maximum and this device is at MAXIMUM. */
    fun isClaimed(contactId: String): Boolean {
        if (level() != MaximumShieldLevel.MAXIMUM) return false
        return try { vault.getMeta(MaximumShieldPolicy.peerClaimKey(contactId)) != null } catch (_: Exception) { false }
    }

    /**
     * One pass of the sender (and the leave-Maximum clean-up). [send] posts the
     * announcement ([MessageManager.sendMaximumAnnouncement]) and returns whether the
     * relay accepted it. Returns the number of sends ATTEMPTED (0 in steady state).
     *
     * AMBIGUOUS level: nothing is sent, stored or deleted.
     */
    fun reconcile(
        blocked: Set<String> = emptySet(),
        maxAttempts: Int = MAX_ATTEMPTS_PER_PASS,
        send: (contactId: String, max: Boolean) -> Boolean,
    ): Int {
        // One pass at a time: the sweep fires every 60-90 s and a pass with a few
        // spread sends over Tor can outlast that.
        if (!passLock.withLock { if (passRunning) false else { passRunning = true; true } }) return 0
        try {
            return reconcileLocked(blocked, maxAttempts, send)
        } finally {
            passLock.withLock { passRunning = false }
        }
    }

    private fun reconcileLocked(
        blocked: Set<String>,
        maxAttempts: Int,
        send: (contactId: String, max: Boolean) -> Boolean,
    ): Int {
        val lvl = level()
        if (lvl == MaximumShieldLevel.AMBIGUOUS) return 0
        if (!vault.isOpen) return 0
        val wantMax = lvl == MaximumShieldLevel.MAXIMUM
        var attempts = 0
        try {
            val ids = contactIds()
            // Leaving Maximum: this device no longer shows shields, so it keeps no claims.
            if (!wantMax) clearAllClaims(ids)
            for (id in ids.secureShuffled()) {
                if (id in blocked) continue
                val marker = vault.getMeta(MaximumShieldPolicy.sentMarkerKey(id))
                val needsSend = if (wantMax) marker != "1" else marker == "1"
                if (!needsSend) continue
                if (attempts >= maxAttempts) break
                if (attempts > 0) {
                    sleeper(jitterMs())
                    // The tier may have changed during the spread: stop; the next pass re-decides.
                    if (level() != lvl) break
                }
                attempts++
                if (!send(id, wantMax)) continue   // retried next pass
                if (!contactStillExists(id)) continue   // deleted mid-send: never resurrect its marker
                if (wantMax) vault.putMeta(MaximumShieldPolicy.sentMarkerKey(id), "1")
                else vault.deleteMeta(MaximumShieldPolicy.sentMarkerKey(id))
            }
        } catch (e: Exception) {
            platformLogWarn(TAG, "level announce pass failed: ${e::class.simpleName}")
        }
        return attempts
    }

    private fun contactIds(): List<String> {
        val records = vault.getAllContacts()
        val ids = records.map { it.contactId }
        records.forEach { it.sharedSecret.secureWipe() }
        return ids
    }

    private fun contactStillExists(id: String): Boolean {
        val c = vault.getContact(id) ?: return false
        c.sharedSecret.secureWipe()
        return true
    }

    private fun clearAllClaims(ids: List<String>) {
        for (id in ids) {
            val key = MaximumShieldPolicy.peerClaimKey(id)
            if (vault.getMeta(key) != null) vault.deleteMeta(key)
        }
    }

    companion object {
        private const val TAG = "MaximumShield"

        /** Announcements ATTEMPTED per sweep pass; the rest wait for the next pass. */
        internal const val MAX_ATTEMPTS_PER_PASS = 5
        private const val SEND_SPREAD_BASE_MS = 800L
        private const val SEND_SPREAD_RANGE_MS = 2200
    }
}
