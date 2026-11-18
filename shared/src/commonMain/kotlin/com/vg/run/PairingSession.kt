package com.vg.run

// ---------------------------------------------------------------------------
// One add-contact pairing session, shared by both platforms
// (docs/ratchet-bootstrap-plan.md §4.1, §3.5, §6).
//
// The platforms keep what is genuinely platform state — the inbox mint, the wizard
// steps, the camera, the "waiting for the peer's announce" loop — and route every
// pairing DECISION through here: the secret half, the one-time key, both code
// shapes, the parse of the peer's code, and the save. That is what keeps Android
// and iOS from diverging on the trust boundary and on the v3 decision rule:
//
//   v3 iff the PEER's code carries a well-formed `ek` (parse enforces "well-formed").
//
// Both sides apply the same rule to each other's code, and a session always shows
// its own `ek`, so two sessions pair v3 and a session ↔ an older build pairs legacy
// on both sides (the older build shows no `ek`, and ignores ours).
//
// Lifetime: ONE session = ONE secret half + ONE one-time keypair, generated here in
// Kotlin and never persisted before the save. The owner keeps the session across a
// configuration change (Android: AddContactSessionViewModel; iOS: the AddContactView
// session) and calls [end] on a real leave. After [end] nothing is usable: every
// accessor answers null / throws — never zeroed bytes as key material.
// ---------------------------------------------------------------------------

/**
 * The one-time X25519 keypair of one pairing session (plan §4.1 "Key holder").
 *
 *  - The canonical private key lives only here, in Kotlin memory. It is handed to the
 *    bootstrap exactly once ([takePrivateKeyForSave]); the bootstrap wipes it.
 *  - The public key is cached separately ([publicKeyB64Url]), because the scan-first
 *    side shows its full code AFTER its save, when the private key is already gone.
 *  - [wipe] makes the holder unusable: the private key is zeroed and every accessor
 *    answers null. Never an all-zero scalar — a consumed or wiped holder cannot be
 *    used for a pairing (and the bootstrap refuses a zero scalar as a backstop).
 */
class PairingKeyHolder private constructor(private var priv: ByteArray?, private var pub: ByteArray?) {

    /** True while the private key has neither been used for a save nor wiped. */
    val canSave: Boolean get() = priv != null

    /** Our public key as `"ek"` text, or null after [wipe]. Still available after a save. */
    fun publicKeyB64Url(): String? = pub?.let { encodeBase64Url(it) }

    /**
     * Hands the private key to the bootstrap (which wipes it) and forgets it. Null if
     * already taken or wiped — the caller must then refuse to pair, never retry with
     * zeroed bytes.
     */
    internal fun takePrivateKeyForSave(): ByteArray? {
        val k = priv ?: return null
        priv = null
        return k
    }

    /** Idempotent. Zeroes the private key (if still held) and drops the public one. */
    fun wipe() {
        priv?.secureWipe()
        priv = null
        pub = null
    }

    companion object {
        /** A fresh one-time keypair. */
        fun generate(): PairingKeyHolder {
            val kp = x25519GenerateKeypair()
            return PairingKeyHolder(kp.privateKey, kp.publicKey.copyOf())
        }
    }
}

/** What a [PairingSession.save] did — the small set of outcomes the UI switches on. */
enum class PairingSaveOutcome {
    /** Saved with the one-time bootstrap (the peer's code carried `ek`). */
    SAVED_V3,
    /** Saved exactly as before (the peer's build has no v3 bootstrap). */
    SAVED_LEGACY,
    /** The peer's code is unusable (the existing "invalid code" surface). */
    INVALID_CODE,
    /** One of the peer's inbox ids is already owned here (the existing inbox-in-use surface). */
    INBOX_IN_USE,
    /** Nothing was saved and this session cannot complete — show "start again" and begin a new session. */
    START_AGAIN,
}

/**
 * The shared pairing session. Not thread-safe: the owner calls it from one thread
 * (the UI thread / a single IO coroutine), as both platforms do today.
 */
class PairingSession private constructor(
    private var half: ByteArray?,
    private val keys: PairingKeyHolder,
) {
    /** True until [end]. */
    val isActive: Boolean get() = half != null

    /**
     * Our 32-byte secret half — the SESSION'S OWN array (no copy), so the platform's
     * aliases (Android passes it into MintState.Ready and the scan/paste children) are
     * all cleared by [end]'s in-place wipe. Throws after [end]: a wiped half is never
     * handed out as key material.
     */
    fun mySecretHalf(): ByteArray = checkNotNull(half) { "pairing session used after end" }

    /** Standard base64 of our half (the `secret` field), or null after [end]. */
    fun mySecretB64(): String? = half?.let { encodeBase64(it) }

    /** Our one-time public key (`ek`), or null after [end]. */
    fun myEphemeralPubB64Url(): String? = keys.publicKeyB64Url()

    /** The instant, secret-only code (shown before the mint lands). Null after [end]. */
    fun secretOnlyCode(): String? {
        val s = mySecretB64() ?: return null
        val ek = keys.publicKeyB64Url() ?: return null
        return PairingPayload.buildSecretOnlyV3(s, ek)
    }

    /** The full code (also the debug paste code). Null after [end]. */
    fun fullCode(
        inboxId: String,
        writeCap: String,
        ctlInboxId: String,
        ctlWriteCap: String,
        grpInboxId: String? = null,
        grpWriteCap: String? = null,
    ): String? {
        val s = mySecretB64() ?: return null
        val ek = keys.publicKeyB64Url() ?: return null
        return PairingPayload.buildFullV3(inboxId, writeCap, ctlInboxId, ctlWriteCap, s, ek, grpInboxId, grpWriteCap)
    }

    /**
     * Parse + validate the peer's scanned / pasted code against THIS session (echo of
     * our secret half, our inbox, our one-time key). Null = invalid code. [requireFull]
     * rejects a secret-only code (the paste path).
     */
    fun parsePeerCode(raw: String, myInboxId: String?, requireFull: Boolean): PairingScan? {
        val s = mySecretB64() ?: return null
        return PairingPayload.parse(raw, myInboxId, s, requireFull, keys.publicKeyB64Url())
    }

    /**
     * Saves the contact for the peer's code [peer] — the v3 transaction
     * ([PairingVault.savePairedContactV3]) iff [peer] carries `ek`, else
     * [PairingVault.savePairedContact] exactly as the screens call it today. Call it
     * where the screens call `savePairedContact` now: once per session, after the
     * peer's code was scanned / pasted and our mint is ready. The pending-row
     * (secret-only scan) and scan-back flows are unchanged.
     *
     * Never throws. The peer's half and the derived pairing secret are wiped here; our
     * half and the parsed [peer] stay the caller's. A LEGACY save may be retried in the
     * same session after INBOX_IN_USE. A v3 save consumes the one-time private key
     * whatever the outcome — also INBOX_IN_USE and a failed write — so a second save in
     * this session answers START_AGAIN (never a zero-scalar pairing) and both people
     * start the pairing again.
     */
    fun save(
        vault: VaultDatabase,
        contactId: String,
        peer: PairingScan,
        myInboxId: String,
        myReadCap: String,
        myCtlInboxId: String,
        myCtlReadCap: String,
        alias: String,
        mnemonic: String = "",
        myGrpInboxId: String? = null,
        myGrpReadCap: String? = null,
    ): PairingSaveOutcome {
        val mine = half ?: return PairingSaveOutcome.START_AGAIN
        val peerHalf = try { decodeBase64(peer.secretB64) } catch (_: Exception) { return PairingSaveOutcome.INVALID_CODE }
        var pairingSecret: ByteArray? = null
        try {
            if (peerHalf.size != 32) return PairingSaveOutcome.INVALID_CODE
            val ss = deriveSharedSecret(mine, peerHalf)
            pairingSecret = ss
            val ekB64 = peer.ephemeralPubB64
            if (ekB64 == null) {
                return try {
                    PairingVault.savePairedContact(
                        vault = vault, contactId = contactId, sharedSecret = ss,
                        peerInboxId = peer.inboxId, peerWriteCap = peer.writeCap,
                        peerCtlInboxId = peer.ctlInboxId, peerCtlWriteCap = peer.ctlWriteCap,
                        myInboxId = myInboxId, myReadCap = myReadCap,
                        myCtlInboxId = myCtlInboxId, myCtlReadCap = myCtlReadCap,
                        alias = alias, mnemonic = mnemonic,
                        mySecretHalf = mine, peerSecretHalf = peerHalf, peerRoleRuleV2 = peer.roleRuleV2,
                        peerGrpInboxId = peer.grpInboxId, peerGrpWriteCap = peer.grpWriteCap,
                        myGrpInboxId = myGrpInboxId, myGrpReadCap = myGrpReadCap,
                    )
                    // A legacy pairing never uses the one-time key: drop it now.
                    keys.takePrivateKeyForSave()?.secureWipe()
                    PairingSaveOutcome.SAVED_LEGACY
                } catch (_: InboxInUseException) {
                    PairingSaveOutcome.INBOX_IN_USE
                } catch (e: Exception) {
                    platformLogError(LOG_TAG, "legacy pairing save failed: ${e::class.simpleName}")
                    PairingSaveOutcome.START_AGAIN
                }
            }
            val peerEk = PairingPayload.decodeEphemeralKey(ekB64) ?: return PairingSaveOutcome.INVALID_CODE
            val priv = keys.takePrivateKeyForSave() ?: return PairingSaveOutcome.START_AGAIN
            val r = PairingVault.savePairedContactV3(
                vault = vault, contactId = contactId, pairingSecretFromHalves = ss,
                myEphemeralPriv = priv, peerEphemeralPub = peerEk,
                mySecretHalf = mine, peerSecretHalf = peerHalf,
                peerInboxId = peer.inboxId, peerWriteCap = peer.writeCap,
                peerCtlInboxId = peer.ctlInboxId, peerCtlWriteCap = peer.ctlWriteCap,
                myInboxId = myInboxId, myReadCap = myReadCap,
                myCtlInboxId = myCtlInboxId, myCtlReadCap = myCtlReadCap,
                alias = alias, mnemonic = mnemonic,
                peerGrpInboxId = peer.grpInboxId, peerGrpWriteCap = peer.grpWriteCap,
                myGrpInboxId = myGrpInboxId, myGrpReadCap = myGrpReadCap,
            )
            return outcomeOf(r)
        } finally {
            peerHalf.secureWipe()
            pairingSecret?.secureWipe()
        }
    }

    /** A real leave: zero the half and the one-time key. Idempotent; nothing usable afterwards. */
    fun end() {
        half?.secureWipe()
        half = null
        keys.wipe()
    }

    companion object {
        private const val LOG_TAG = "PairingSession"

        /** A new session: a fresh 32-byte secret half and a fresh one-time keypair. */
        fun start(): PairingSession = PairingSession(generateSecureRandom(32), PairingKeyHolder.generate())

        /** The UI outcome of a v3 save result. Exposed for tests. */
        internal fun outcomeOf(r: PairingVault.V3SaveResult): PairingSaveOutcome = when (r) {
            is PairingVault.V3SaveResult.Saved -> PairingSaveOutcome.SAVED_V3
            is PairingVault.V3SaveResult.InboxInUse -> PairingSaveOutcome.INBOX_IN_USE
            is PairingVault.V3SaveResult.Refused -> when (r.reason) {
                // The PEER's key is unusable: the code is the problem.
                PairingVault.V3Refusal.MALFORMED_INPUT,
                PairingVault.V3Refusal.REFLECTED_PEER_KEY,
                PairingVault.V3Refusal.LOW_ORDER_PEER_KEY -> PairingSaveOutcome.INVALID_CODE
                // OUR side cannot complete (spent key, platform failure).
                PairingVault.V3Refusal.SPENT_EPHEMERAL_KEY,
                PairingVault.V3Refusal.KEY_AGREEMENT_FAILED -> PairingSaveOutcome.START_AGAIN
            }
            is PairingVault.V3SaveResult.IdenticalSecretHalves -> PairingSaveOutcome.INVALID_CODE
            is PairingVault.V3SaveResult.WriteFailed -> PairingSaveOutcome.START_AGAIN
        }
    }
}
