package com.vg.run

/**
 * Two introducees (B and C) of one referral, driven through the REAL
 * [ReferralManager] handshake (docs/ratchet-bootstrap-plan.md §4.2): the offer from
 * the introducer, each side's staged accept ([ReferralManager.registerAccepted] — the
 * accept body it returns is the production body a send carries), and the introducer
 * relaying each accept verbatim to the other side ([deliverToB] / [deliverToC]).
 *
 * Inbox wiring is production-shaped: B's minted text/control inboxes are C's outbound
 * rows and vice versa, so [attachMessaging] gives two [MessageManager]s that talk over
 * one recording leasing relay.
 *
 * Models: staging (with or without the `bv` decision — [ReferralManager.simulatePreBootstrapV3BuildForTest]),
 * the verbatim relay, a relay that strips or rewrites one accept (pass a body).
 * Does NOT model: the introducer's own vault or its control sends (the accept bodies are
 * handed over directly), the PoW mint (the minted pairs are fixed).
 */
internal class ReferralSide(
    val name: String,
    val vault: VaultDatabase,
    val inner: InMemoryVault,
    val rm: ReferralManager,
    val publicKey: ByteArray,
    /** Test-only copy of the referral one-time private key, taken before anything could wipe it. */
    val leakedPriv: ByteArray,
    val minted: MintedInboxPair,
    /** The accept body this side's send carried (what the introducer relays). */
    val acceptBody: String,
    val introId: String,
) {
    val cid: String get() = ReferralManager.referredContactIdFor(introId)
    lateinit var mm: MessageManager
    val stateKey: String get() = VaultRatchetStore.stateKey(cid, MessageManager.RATCHET_TEXT_CHANNEL)
    fun stateBlob(): ByteArray? = inner.meta[stateKey]?.let { decodeBase64(it) }
    fun contact(): ContactRecord? = inner.contacts[cid]
    /** The `ref_p` record (holds the one-time private key) while it exists. */
    fun refP(): String? = inner.meta[ReferralMetaKeys.ACCEPT_PREFIX + introId]
    /** Bob's v3 state at birth has no remote key (plan §3.2). */
    fun isBobAtBirth(): Boolean = V3BootstrapOracle.parseState(stateBlob()!!).remote == null
}

internal class V3Referral(
    val introId: String,
    val relay: RecordingLeasingRelay,
    val b: ReferralSide,
    val c: ReferralSide,
) {
    val cid: String get() = ReferralManager.referredContactIdFor(introId)

    /** The introducer relays C's accept to B (or [body], e.g. a stripped copy). */
    fun deliverToB(body: String = c.acceptBody) =
        b.rm.handleControl(INTRODUCER, MessageManager.CONTROL_KIND_REFERRAL_ACCEPT, body)

    /** The introducer relays B's accept to C (or [body]). */
    fun deliverToC(body: String = b.acceptBody) =
        c.rm.handleControl(INTRODUCER, MessageManager.CONTROL_KIND_REFERRAL_ACCEPT, body)

    /** Both sides' [MessageManager]s over the shared recording relay (after both finalized). */
    fun attachMessaging(): V3Referral = also {
        for (s in listOf(b, c)) s.mm = MessageManager(s.vault, "http://relay.test", relay).syncAcks()
    }

    /** The side whose v3 state was born as Bob / as Alice (both must have finalized v3). */
    val bob: ReferralSide get() = if (b.isBobAtBirth()) b else c
    val alice: ReferralSide get() = if (b.isBobAtBirth()) c else b

    companion object {
        const val INTRODUCER = "alice"
        val IN_B = "R".repeat(32)      // B inbound text / C outbound text
        val CTL_B = "r".repeat(32)
        val IN_C = "S".repeat(32)      // C inbound text / B outbound text
        val CTL_C = "s".repeat(32)
        val GRP_B = "G".repeat(32)
        val GRP_C = "H".repeat(32)
        val READ_CAP = "C".repeat(43)
        val WRITE_CAP = "D".repeat(43)

        private var seq = 0
        fun newIntroId(): String = "refv3-" + (seq++).toString() + "-" + bytesToHex(generateSecureRandom(4))

        /**
         * Offers + both accepts staged; NOTHING relayed yet. [bLegacy]/[cLegacy] stage that
         * side like a build without the one-time bootstrap (no `bv` anywhere).
         */
        fun stage(
            bLegacy: Boolean = false,
            cLegacy: Boolean = false,
            introId: String = newIntroId(),
            wrapB: (InMemoryVault) -> VaultDatabase = { V3TestVault(it) },
            wrapC: (InMemoryVault) -> VaultDatabase = { V3TestVault(it) },
            relay: RecordingLeasingRelay = RecordingLeasingRelay(),
            // Re-introduce into existing vaults (delete + a new introduction).
            innerB: InMemoryVault = InMemoryVault(),
            innerC: InMemoryVault = InMemoryVault(),
            // Inbox ids for this introduction (a second one into the same vaults needs fresh ids).
            ids: List<String> = listOf(IN_B, CTL_B, IN_C, CTL_C),
            // Mint the optional GROUP inbox too (B: GRP_B, C: GRP_C).
            withGrp: Boolean = false,
        ): V3Referral {
            fun side(name: String, legacy: Boolean, wrap: (InMemoryVault) -> VaultDatabase, ib: String, cib: String, inner: InMemoryVault, gib: String?): ReferralSide {
                inner.insertContact(ContactRecord(INTRODUCER, generateSecureRandom(32), 0, "Alice", 0L))
                val vault = wrap(inner)
                val rm = ReferralManager(vault) { null }
                rm.simulatePreBootstrapV3BuildForTest = legacy
                rm.handleControl(INTRODUCER, MessageManager.CONTROL_KIND_REFERRAL_OFFER, referralOfferJson(introId, "Running Fox"))
                val kp = x25519GenerateKeypair()
                val leaked = kp.privateKey.copyOf()
                val minted = MintedInboxPair(
                    MintedInbox(ib, READ_CAP, WRITE_CAP, Long.MAX_VALUE),
                    MintedInbox(cib, READ_CAP, WRITE_CAP, Long.MAX_VALUE),
                    gib?.let { MintedInbox(it, READ_CAP, WRITE_CAP, Long.MAX_VALUE) },
                )
                val body = rm.registerAccepted(introId, rm.pendingOffers().single(), kp, minted)
                return ReferralSide(name, vault, inner, rm, kp.publicKey.copyOf(), leaked, minted, body, introId)
            }
            return V3Referral(
                introId, relay,
                side("B", bLegacy, wrapB, ids[0], ids[1], innerB, if (withGrp) GRP_B else null),
                side("C", cLegacy, wrapC, ids[2], ids[3], innerC, if (withGrp) GRP_C else null),
            )
        }

        /** Staged and both accepts relayed verbatim: both sides finalized. */
        fun pair(bLegacy: Boolean = false, cLegacy: Boolean = false): V3Referral =
            stage(bLegacy, cLegacy).also { it.deliverToB(); it.deliverToC() }

        /** A v3 referral in which side B took the given role (a coin flip per introduction). */
        fun pairWithBAs(bob: Boolean): V3Referral {
            repeat(128) {
                val r = pair()
                if (r.b.isBobAtBirth() == bob) return r
            }
            error("no referral with B as ${if (bob) "Bob" else "Alice"} in 128 tries")
        }
    }
}

/**
 * A static (legacy) envelope sealed under [secret], as the production sender builds it:
 * `{"e","c","t","ch","di",…extra,"m"}`. [epoch] / [counter] / [ch] / [di] null = the field
 * is ABSENT. The epoch defaults to the one [secret] implies.
 */
internal fun staticEnvelopeBytes(
    secret: ByteArray,
    counter: Long?,
    di: String?,
    ch: String? = MessageManager.CHANNEL_TAG_MAIN,
    epoch: String? = legacyEpochFor(secret),
    extra: String = "",
    text: String = "x",
): ByteArray {
    val fields = listOfNotNull(
        epoch?.let { "\"e\":\"$it\"" },
        counter?.let { "\"c\":$it" },
        "\"t\":0",
        ch?.let { "\"ch\":\"$it\"" },
        di?.let { "\"di\":\"$it\"" },
    )
    val json = "{" + fields.joinToString(",") + extra + ",\"m\":\"$text\"}"
    return sealLegacyEnvelopeBytes(secret, json)
}
