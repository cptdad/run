package com.vg.run

/**
 * Two devices paired through the real v3 pairing transaction
 * ([PairingVault.savePairedContactV3]) and talking through real [MessageManager]s
 * over a leasing relay double — the harness for the step-A message rules
 * (docs/ratchet-bootstrap-plan.md §3.5, §7).
 *
 * Inbox wiring is production-shaped: A's outbound text/control == B's inbound
 * text/control and vice versa. [secretOnlyA] = A scanned B's SECRET-ONLY code, so
 * A's row has no peer inbox rows yet (the pending side) and learns them from B's
 * ratchet-sealed announce.
 */
internal class V3TestVault(val inner: InMemoryVault = InMemoryVault()) : VaultDatabase by inner {
    /** Export needs it (the interface default throws). */
    override fun getAllInboxIds(): List<InboxIdRecord> = inner.inboxes.toList()

    /** Overrides the read of exactly [hookedKey] (null answer = absent; a throw = read error). */
    var hookedKey: String? = null
    var hook: (() -> String?)? = null
    override fun getMeta(key: String): String? {
        val h = hook
        if (h != null && key == hookedKey) return h()
        return inner.getMeta(key)
    }
}

/** The leasing relay, also recording every append body (what a hostile relay archives). */
internal class RecordingLeasingRelay(val inner: LeasingRelay = LeasingRelay()) : RelayHttp by inner {
    val posted = mutableListOf<ByteArray>()
    override fun post(url: String, body: ByteArray, contentType: String, headers: Map<String, String>, timeoutSeconds: Int): HttpResult {
        if (url.contains("/inbox/") && !url.endsWith("/ack")) posted.add(body.copyOf())
        return inner.post(url, body, contentType, headers, timeoutSeconds)
    }
}

internal class V3Device(
    val vault: V3TestVault,
    val mm: MessageManager,
    val half: ByteArray,
    val ekPub: ByteArray,
    /** Test-only unwiped copy of the one-time private key (null unless asked for). */
    val leakedEkPriv: ByteArray?,
    /** The array handed to the pairing transaction (wiped by it). */
    val ekPrivHandedOver: ByteArray,
) {
    val stateKey: String get() = VaultRatchetStore.stateKey(V3Messaging.CID, MessageManager.RATCHET_TEXT_CHANNEL)
    fun stateBlob(): ByteArray? = vault.inner.meta[stateKey]?.let { decodeBase64(it) }
    /** Bob's state at birth has no remote key (plan §3.2). Meaningful before the first receive. */
    fun isBobAtBirth(): Boolean = V3BootstrapOracle.parseState(stateBlob()!!).remote == null
    fun contact(): ContactRecord = vault.inner.contacts.getValue(V3Messaging.CID)
}

internal class V3Messaging(
    val relay: RecordingLeasingRelay,
    val a: V3Device,
    val b: V3Device,
    val ssHalves: ByteArray,
) {
    val alice: V3Device get() = if (a.isBobAtBirth()) b else a
    val bob: V3Device get() = if (a.isBobAtBirth()) a else b

    companion object {
        const val CID = "c1"
        val IN_A = "A".repeat(32)      // A inbound text  / B outbound text
        val IN_B = "B".repeat(32)      // B inbound text  / A outbound text
        val CTL_A = "a".repeat(32)     // A inbound ctl   / B outbound ctl
        val CTL_B = "b".repeat(32)     // B inbound ctl   / A outbound ctl
        val READ_CAP = "C".repeat(43)
        val WRITE_CAP = "D".repeat(43)

        fun pair(
            secretOnlyA: Boolean = false, leakKeys: Boolean = false,
            // Re-pair into existing vaults / over an existing relay (delete + re-pair).
            vA: V3TestVault = V3TestVault(), vB: V3TestVault = V3TestVault(),
            relay: RecordingLeasingRelay = RecordingLeasingRelay(),
        ): V3Messaging {
            val halfA = generateSecureRandom(32); val halfB = generateSecureRandom(32)
            val eA = x25519GenerateKeypair(); val eB = x25519GenerateKeypair()
            val leakA = if (leakKeys) eA.privateKey.copyOf() else null
            val leakB = if (leakKeys) eB.privateKey.copyOf() else null
            val ss = deriveSharedSecret(halfA, halfB)
            fun save(v: VaultDatabase, priv: ByteArray, peerPub: ByteArray, mine: ByteArray, peer: ByteArray,
                     myIn: String, myCtl: String, peerIn: String?, peerCtl: String?) {
                val r = PairingVault.savePairedContactV3(
                    vault = v, contactId = CID, pairingSecretFromHalves = ss.copyOf(),
                    myEphemeralPriv = priv, peerEphemeralPub = peerPub,
                    mySecretHalf = mine, peerSecretHalf = peer,
                    peerInboxId = peerIn, peerWriteCap = peerIn?.let { WRITE_CAP },
                    peerCtlInboxId = peerCtl, peerCtlWriteCap = peerCtl?.let { WRITE_CAP },
                    myInboxId = myIn, myReadCap = READ_CAP, myCtlInboxId = myCtl, myCtlReadCap = READ_CAP,
                    alias = "peer",
                )
                check(r is PairingVault.V3SaveResult.Saved) { "v3 save failed: $r" }
            }
            save(vA, eA.privateKey, eB.publicKey, halfA, halfB, IN_A, CTL_A,
                if (secretOnlyA) null else IN_B, if (secretOnlyA) null else CTL_B)
            save(vB, eB.privateKey, eA.publicKey, halfB, halfA, IN_B, CTL_B, IN_A, CTL_A)
            fun mm(v: VaultDatabase) = MessageManager(v, "http://relay.test", relay).syncAcks()
            return V3Messaging(
                relay,
                V3Device(vA, mm(vA), halfA, eA.publicKey, leakA, eA.privateKey),
                V3Device(vB, mm(vB), halfB, eB.publicKey, leakB, eB.privateKey),
                ss,
            )
        }

        /** A pairing in which side A took the given role (a coin flip per pairing). */
        fun pairWithAAs(bob: Boolean, leakKeys: Boolean = false): V3Messaging {
            repeat(128) {
                val p = pair(leakKeys = leakKeys)
                if (p.a.isBobAtBirth() == bob) return p
            }
            error("no pairing with A as ${if (bob) "Bob" else "Alice"} in 128 tries")
        }
    }
}
