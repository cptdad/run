package com.vg.run

// ---------------------------------------------------------------------------
// ReferralStore — the `_meta` key namespace + record codecs that make the
// referral handshake (referral.md, [ReferralManager]) survive process death and
// session teardown.
//
// WHY THIS EXISTS. Every handshake map in ReferralManager used to be RAM-only,
// and `scrubInMemory()` runs on ORDINARY BACKGROUNDING on both platforms (iOS
// `.background` → IosAppController.lock, Android onStop teardown →
// RunViewModel.onCleared), while `createSessionManagers` rebuilds an EMPTY
// manager on the next unlock. The relay control drain deletes a blob once it is acked as processed, so the
// loss was permanent: an introducee killed/backgrounded after "accept sent" hit
// the terminal "referral accept for unknown introId dropped" branch and could
// never finalize, while its peer had already committed a
// TRUST_REFERRED_CONFIRMED contact whose outbound inboxes routed to orphans —
// a silent one-way black hole.
//
// WHERE IT LIVES. The ENCRYPTED VAULT's `_meta` table, exactly like the Double
// Ratchet's `dr-*` state (VaultDatabase.putMeta/getMeta) — NOT the platform
// KeyValueStore/Keychain. That is the same at-rest protection the vault already
// gives strictly MORE sensitive material: every ratchet chain key and every
// inbox read capability (the inbox OWNER capability) already live there. A
// referral record's ephemeral X25519 private key is single-introduction,
// short-lived (7-day idle TTL, 28-day absolute ceiling — see
// [REFERRAL_RECORD_TTL_MS] / [REFERRAL_RECORD_MAX_LIFETIME_MS]) and deleted
// inside the very transaction that commits the contact, so it is a strictly
// smaller exposure than what `_meta` holds.
//
// WIRE FORMAT, CONTROL KINDS AND ANTI-REPLAY ARE UNTOUCHED — this is purely
// local persistence. Records are flat JSON with STRING-ONLY values, parsed by
// [firstStringFieldAnywhere] (the linear scanner; never a regex — Kotlin/Native's regex
// engine recurses and overflows on long values, see its kdoc).
//
// BRICK-SAFETY: every decoder below returns `null` on anything it cannot fully
// validate. A missing, truncated or malformed record is "no record" — the
// caller skips it and GCs the key. Nothing here throws, and nothing here is
// ever an input to a wipe/lock decision.
// ---------------------------------------------------------------------------

/**
 * The `_meta` keys the referral handshake owns. Both `VaultDatabase` actuals
 * purge them on `deleteContact` through [isReferralMetaResidueForContact], the
 * referral analog of [ratchetMetaKeysForContact] — see that function's kdoc.
 *
 * Every key is `<prefix><introId>` (the redrive key adds `:<toContactId>`), and
 * introIds are shape-gated by [isValidIntroId] BEFORE a key is ever built, so a
 * hostile introducer cannot smuggle structure into a key name or into the
 * newline-delimited [COMPLETED_KEY] list.
 */
internal object ReferralMetaKeys {
    /** Cheap gate every purge/GC scan applies before it reads a value. */
    const val PREFIX = "ref_"

    /** `ref_p:<introId>` — our own accepted handshake material (introducee). */
    const val ACCEPT_PREFIX = "ref_p:"

    /** `ref_o:<introId>` — a received offer awaiting the user's consent. */
    const val OFFER_PREFIX = "ref_o:"

    /** `ref_s:<introId>` — an introduction we are relaying (introducer). */
    const val SESSION_PREFIX = "ref_s:"

    /** `ref_a:<introId>` — a peer accept that arrived before our consent. */
    const val STASH_PREFIX = "ref_a:"

    /** `ref_r:<introId>:<toContactId>` — an accept we failed to relay onward. */
    const val REDRIVE_PREFIX = "ref_r:"

    /**
     * `ref_done` — LEGACY (v1) tombstone list, read-only. It stored RAW introIds,
     * which is a correlator leak: [ReferralManager.referredContactIdFor] derives the
     * referred contact's id DETERMINISTICALLY (and salt-free) from exactly this
     * introId, and that id is identical on the peer's device — so a raw introId
     * surviving in `_meta` after its contact was deleted is a computable
     * cross-device correlator for a relationship the user just erased. Rehydrate
     * migrates every v1 entry into [COMPLETED_KEY_V2] (hashed under a DIFFERENT
     * derivation than `referredContactIdFor`, so the stored value cannot be turned
     * back into the contact id) and deletes this key — see `ReferralManager`
     * `rehydrate()`. New code must never write here again.
     */
    const val COMPLETED_KEY = "ref_done"

    /**
     * `ref_done2` — the bounded (128) finalized/declined tombstone list, CURRENT
     * format. Holds `doneTokenFor(introId)` values (a hash, not the introId
     * itself) so the list can still dedupe a re-delivered offer/accept (the guard
     * only ever needs EQUALITY, never the preimage) without being a computable
     * link to the referred contact's id after that contact is deleted. See
     * [COMPLETED_KEY] for the migration story and the weakness this
     * closes.
     */
    const val COMPLETED_KEY_V2 = "ref_done2"

    /**
     * `ref_off_rl:<introducerContactId>` — the
     * referral-offer sibling of `GroupMetaKeys.INVITE_RL_PREFIX`
     * (`grp_inv_rl:<contactId>`). Value is a comma-joined list of receipt
     * timestamps (an hourly sliding window), NOT JSON, and unlike every other
     * key in this object it is keyed by CONTACT id, not introId — the
     * introducer, so [ReferralManager.handleOffer] can bound how many offers
     * one introducer may land per hour regardless of introId (introIds are
     * attacker-minted and free to enumerate). Matched by exact key equality in
     * [isReferralMetaResidueForContact], mirroring
     * `isGroupMetaResidueForContact`'s `INVITE_RL_PREFIX` case.
     */
    const val OFFER_RATE_LIMIT_PREFIX = "ref_off_rl:"
}

/**
 * How long ANY persisted referral record may live WITHOUT further activity
 * (`ReferralManager.RECORD_TTL_MS` is defined as this constant, so the codecs,
 * the rehydration GC and the mid-session GC cannot drift).
 *
 * **7 days, raised from 24 h (F1).** The two introducees accept INDEPENDENTLY
 * and a human may sit on a consent dialog overnight — or over a weekend. At 24 h
 * the early accepter's peer could have committed a TRUST_REFERRED_CONFIRMED
 * contact while our own `ref_p` (and the stash holding their relayed accept) had
 * already been GC'd, leaving a permanent HALF-PAIR with no re-pair UX: exactly
 * the black hole the persistence work exists to close, merely moved from
 * "process died" to "user took a day". 7 days is also the relay's own
 * `maxTtlSeconds` ceiling, so the record and the blob that feeds it now age out
 * on the SAME bound (see [REFERRAL_CONTROL_TTL_SECONDS]).
 *
 * It still comfortably outlives the worst realistic accept-mint window
 * (`ACCEPT_MINT_DEADLINE_MS`, 8 min).
 */
internal const val REFERRAL_RECORD_TTL_MS = 604_800_000L

/**
 * The ABSOLUTE ceiling on a referral record's life, measured from its
 * `firstSeenAt` — the stamp that refresh-on-activity deliberately does NOT move.
 *
 * Why it exists: F1 re-stamps `createdAt` on genuine activity (a redrive
 * attempt, a peer accept landing against a pending consent, an introducer
 * relaying), and F9 resets the per-session attempt budgets on every rehydrate.
 * Together those two make an obligation whose peer is permanently dead
 * refreshable once per session, forever — and `ref_p` holds an ephemeral X25519
 * PRIVATE KEY plus our own inbox READ capabilities, which referral.md justifies
 * persisting precisely on the grounds that they are TTL-bounded. This keeps that
 * justification true: no amount of activity can carry a record past this bound.
 *
 * 4x [REFERRAL_RECORD_TTL_MS] (28 days) — far past any honest introduction, far
 * short of "indefinite".
 */
internal const val REFERRAL_RECORD_MAX_LIFETIME_MS = 4L * REFERRAL_RECORD_TTL_MS

/**
 * The relay-side blob TTL (`POST /inbox/{id}?ttl=<seconds>`) every REFERRAL
 * control send asks for (F1c).
 *
 * The relay's default is 24 h and its ceiling (`maxTtlSeconds`) is 7 days; the
 * value is `coerceIn(1, maxTtlSeconds)` server-side, so asking for exactly the
 * ceiling is safe against a relay configured lower (it just clamps). Without
 * this, an offer or a relayed accept expired off the relay a day after it was
 * posted while BOTH ends of the handshake were still alive for a week — the
 * other half of the same half-pair defect [REFERRAL_RECORD_TTL_MS] describes.
 *
 * This is a URL QUERY PARAMETER ONLY. It is never part of the sealed envelope,
 * so the wire format, the AEAD-bound fields and the anti-replay counter/epoch
 * are untouched by it.
 */
internal const val REFERRAL_CONTROL_TTL_SECONDS = 604_800L

/**
 * introIds are locally minted as `encodeBase64Url(16 random bytes)` (22 chars),
 * but the value that reaches [ReferralManager.handleControl] comes off the wire
 * from the introducer, so it is attacker-chosen. Persistence is gated on this
 * shape: a weird introId simply degrades to the old RAM-only behaviour instead
 * of contaminating a `_meta` key name or the newline-delimited completed list.
 * Receive-side handling is deliberately NOT changed by this gate.
 */
private val INTRO_ID_REGEX = Regex("^[A-Za-z0-9_\\-]{1,64}$")

/** True iff [s] is safe to embed in a referral `_meta` key / the tombstone list. */
internal fun isValidIntroId(s: String): Boolean = INTRO_ID_REGEX.matches(s)

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

/**
 * Our own accepted handshake (introducee role) — everything
 * `ReferralManager.finalizeFromPeerAccept` needs to derive the shared key and
 * write the four inbox rows once the peer's relayed accept lands.
 *
 * [sent] is the crash-window discriminator, not decoration: the record is
 * written `st=0` BEFORE `sendDirectControl` and flipped to `st=1` only once the
 * relay accepted the blob. A rehydrated `st=0` record means "we may or may not
 * have sent it", and the recovery is to re-send THE SAME material — never to
 * mint a fresh keypair, because the peer may already hold this public key and a
 * new one would derive a secret they can never match.
 */
internal class StoredAccept(
    val introducerContactId: String,
    val peerAlias: String,
    val privateKey: ByteArray,
    val publicKey: ByteArray,
    val minted: MintedInboxPair,
    val sent: Boolean,
    val attempts: Int,
    val createdAt: Long,
    /** See [REFERRAL_RECORD_MAX_LIFETIME_MS]. Defaults to [createdAt] so a
     *  record written before this field existed migrates on read. */
    val firstSeenAt: Long = createdAt,
)

/** A received offer parked for consent (introducee role). */
internal class StoredOffer(
    val introducerContactId: String,
    val introducerAlias: String,
    val peerAlias: String,
    val createdAt: Long,
    /** See [REFERRAL_RECORD_MAX_LIFETIME_MS]; legacy records migrate on read. */
    val firstSeenAt: Long = createdAt,
)

/**
 * An introduction we are routing (introducer role). [relayed] holds the senders
 * whose accept we have already forwarded; both ⇒ the intro is done.
 *
 * [offered] is the F2 half: the introducees whose OFFER we have PROVABLY
 * delivered. `startReferral` used to fire both offers and discard both return
 * values, so a dropped Tor circuit silently swallowed one leg — the introducer
 * believed the introduction was under way, one introducee never saw a consent
 * prompt, and nothing ever retried. The session record is written BEFORE the
 * offers go out (it always was), so an undelivered side is now a DURABLE
 * obligation that `runMaintenance` redrives on later control sweeps, bounded by
 * [offerAttempts] exactly like the accept/relay redrives.
 *
 * Legacy records (written before these two fields existed) decode with
 * `offered = emptySet()` / `offerAttempts = 0` and are re-written with both on
 * the next persist. The consequence is deliberate and benign: an in-flight
 * legacy session re-sends its two offers once, and the receiving side's
 * `handleOffer` dedups on `offers`/`pending`/`completedIntros`, so a redundant
 * offer is a no-op while a genuinely lost one is healed.
 */
internal class StoredSession(
    val contactA: String,
    val contactB: String,
    val relayed: Set<String>,
    val createdAt: Long,
    val offered: Set<String> = emptySet(),
    val offerAttempts: Int = 0,
    /** See [REFERRAL_RECORD_MAX_LIFETIME_MS]; legacy records migrate on read. */
    val firstSeenAt: Long = createdAt,
)

/** A peer accept relayed to us before we consented. */
internal class StoredStash(
    val fromContactId: String,
    val body: String,
    val createdAt: Long,
)

/** An accept the introducer could not relay onward — retried on later sweeps. */
internal class StoredRedrive(
    val introId: String,
    val toContactId: String,
    val fromContactId: String,
    val body: String,
    val attempts: Int,
    val createdAt: Long,
    /** See [REFERRAL_RECORD_MAX_LIFETIME_MS]; legacy records migrate on read. */
    val firstSeenAt: Long = createdAt,
)

// ---------------------------------------------------------------------------
// Codecs — string-only flat JSON, read back with the linear scanner.
// ---------------------------------------------------------------------------

private fun f(key: String, value: String) = "\"" + key + "\":" + jsonEscapeString(value)

private fun b64(raw: String): ByteArray? = try { decodeBase64(raw) } catch (_: Exception) { null }

/** A vault-record number field: ReferralStore writes numbers as JSON STRINGS
 *  (`"ts":"123"`), so they are read back through [firstStringFieldAnywhere]
 *  (first match anywhere — the record is flat by construction, every value
 *  escaped by [jsonEscapeString]). */
private fun longField(raw: String, key: String): Long? = firstStringFieldAnywhere(raw, key)?.toLongOrNull()

/** A vault-record string field that must be present AND non-empty (first match
 *  anywhere — the record is flat by construction). */
private fun nonEmptyField(raw: String, key: String): String? = firstStringFieldAnywhere(raw, key)?.takeIf { it.isNotEmpty() }

/**
 * Reads the immutable `t0` (first-seen) stamp, falling back to [createdAt] for a
 * record written before the field existed — MIGRATION ON READ, never a decode
 * failure (a legacy record is a LIVE handshake; refusing it would resurrect the
 * very black hole this store exists to close). The next persist writes `t0`, so
 * the migration completes on write. A `t0` in the FUTURE of `createdAt` is
 * clamped down: the ceiling must never be extendable by a crafted record.
 */
private fun firstSeen(raw: String, createdAt: Long): Long {
    val t0 = longField(raw, "t0") ?: return createdAt
    return if (t0 > createdAt) createdAt else t0
}

internal fun encodeStoredAccept(r: StoredAccept): String =
    "{" + f("ic", r.introducerContactId) +
        "," + f("pa", r.peerAlias) +
        "," + f("sk", encodeBase64(r.privateKey)) +
        "," + f("pk", encodeBase64(r.publicKey)) +
        "," + f("mi", r.minted.main.inboxId) +
        "," + f("mr", r.minted.main.readCapability) +
        "," + f("mw", r.minted.main.writeCapability) +
        "," + f("mx", r.minted.main.expiresAt.toString()) +
        "," + f("ci", r.minted.ctl.inboxId) +
        "," + f("cr", r.minted.ctl.readCapability) +
        "," + f("cw", r.minted.ctl.writeCapability) +
        "," + f("cx", r.minted.ctl.expiresAt.toString()) +
        // The GROUP inbox — OPTIONAL, so a record written before it existed still
        // decodes (migration on read; the next persist writes the fields). Omitted
        // entirely rather than written empty: the decoder's shape checks are strict,
        // and an empty id would fail them rather than read as "absent".
        (r.minted.grp?.let {
            "," + f("gi", it.inboxId) +
                "," + f("gr", it.readCapability) +
                "," + f("gw", it.writeCapability) +
                "," + f("gx", it.expiresAt.toString())
        } ?: "") +
        "," + f("st", if (r.sent) "1" else "0") +
        "," + f("n", r.attempts.toString()) +
        "," + f("ts", r.createdAt.toString()) +
        "," + f("t0", r.firstSeenAt.toString()) + "}"

/**
 * Strict decode: EVERY field must be present and shape-valid, including our own
 * minted inbox ids/caps (they are written straight into `inbox_ids` at finalize,
 * so a corrupted record must never reach the vault). Returns null otherwise —
 * the caller GCs the key.
 */
internal fun decodeStoredAccept(raw: String): StoredAccept? {
    val ic = firstStringFieldAnywhere(raw, "ic") ?: return null
    val pa = firstStringFieldAnywhere(raw, "pa") ?: return null
    val sk = b64(firstStringFieldAnywhere(raw, "sk") ?: return null) ?: return null
    val pk = b64(firstStringFieldAnywhere(raw, "pk") ?: return null) ?: return null
    if (sk.size != 32 || pk.size != 32) return null
    val mi = firstStringFieldAnywhere(raw, "mi") ?: return null
    val mr = firstStringFieldAnywhere(raw, "mr") ?: return null
    val mw = firstStringFieldAnywhere(raw, "mw") ?: return null
    val mx = longField(raw, "mx") ?: return null
    val ci = firstStringFieldAnywhere(raw, "ci") ?: return null
    val cr = firstStringFieldAnywhere(raw, "cr") ?: return null
    val cw = firstStringFieldAnywhere(raw, "cw") ?: return null
    val cx = longField(raw, "cx") ?: return null
    if (ic.isEmpty() || mi == ci) return null
    if (!isValidInboxId(mi) || !isValidInboxId(ci)) return null
    if (!isValidCapability(mr) || !isValidCapability(mw) ||
        !isValidCapability(cr) || !isValidCapability(cw)
    ) return null
    // The GROUP inbox: ABSENT is legal (a record from before it existed, migrated on
    // read — rejecting it would GC a LIVE handshake), but a PRESENT one is held to
    // exactly the same strict shape rules as its siblings, because it is written
    // straight into `inbox_ids` at finalize. Partial/malformed ⇒ treated as absent
    // rather than failing the record: the referral still completes, with the group
    // pair simply not announced.
    val gi = firstStringFieldAnywhere(raw, "gi")
    val gr = firstStringFieldAnywhere(raw, "gr")
    val gw = firstStringFieldAnywhere(raw, "gw")
    val gx = longField(raw, "gx")
    val grp =
        if (gi != null && gr != null && gw != null && gx != null &&
            isValidInboxId(gi) && gi != mi && gi != ci &&
            isValidCapability(gr) && isValidCapability(gw)
        ) MintedInbox(gi, gr, gw, gx) else null
    val ts = longField(raw, "ts") ?: return null
    return StoredAccept(
        introducerContactId = ic,
        peerAlias = pa,
        privateKey = sk,
        publicKey = pk,
        minted = MintedInboxPair(MintedInbox(mi, mr, mw, mx), MintedInbox(ci, cr, cw, cx), grp),
        sent = firstStringFieldAnywhere(raw, "st") == "1",
        attempts = firstStringFieldAnywhere(raw, "n")?.toIntOrNull() ?: 0,
        createdAt = ts,
        firstSeenAt = firstSeen(raw, ts),
    )
}

internal fun encodeStoredOffer(r: StoredOffer): String =
    "{" + f("ic", r.introducerContactId) +
        "," + f("ia", r.introducerAlias) +
        "," + f("pa", r.peerAlias) +
        "," + f("ts", r.createdAt.toString()) +
        "," + f("t0", r.firstSeenAt.toString()) + "}"

internal fun decodeStoredOffer(raw: String): StoredOffer? {
    val ic = nonEmptyField(raw, "ic") ?: return null
    val ia = firstStringFieldAnywhere(raw, "ia") ?: return null
    val pa = firstStringFieldAnywhere(raw, "pa") ?: return null
    val ts = longField(raw, "ts") ?: return null
    return StoredOffer(ic, ia, pa, ts, firstSeen(raw, ts))
}

internal fun encodeStoredSession(r: StoredSession): String =
    "{" + f("a", r.contactA) +
        "," + f("b", r.contactB) +
        "," + f("rl", r.relayed.joinToString(",")) +
        "," + f("ts", r.createdAt.toString()) +
        // The delivered-offer set + its bounded attempt counter. Both are
        // ABSENT from records written by an older build; decodeStoredSession
        // supplies the "nothing delivered yet" default rather than failing.
        "," + f("of", r.offered.joinToString(",")) +
        "," + f("on", r.offerAttempts.toString()) +
        "," + f("t0", r.firstSeenAt.toString()) + "}"

internal fun decodeStoredSession(raw: String): StoredSession? {
    val a = nonEmptyField(raw, "a") ?: return null
    val b = nonEmptyField(raw, "b") ?: return null
    if (a == b) return null
    val ts = longField(raw, "ts") ?: return null
    val relayed = (firstStringFieldAnywhere(raw, "rl") ?: "")
        .split(",").filter { it.isNotEmpty() }.toSet()
    // MIGRATION ON READ: a legacy record has neither field. Only the two
    // parties can ever be a legitimate member of `offered`, so anything else in
    // the stored list is dropped — the set drives a SEND, and an id that names
    // no party of this introduction must never be able to suppress one.
    val offered = (firstStringFieldAnywhere(raw, "of") ?: "")
        .split(",").filter { it == a || it == b }.toSet()
    val offerAttempts = firstStringFieldAnywhere(raw, "on")?.toIntOrNull() ?: 0
    return StoredSession(a, b, relayed, ts, offered, offerAttempts, firstSeen(raw, ts))
}

internal fun encodeStoredStash(r: StoredStash): String =
    "{" + f("fr", r.fromContactId) +
        "," + f("b", r.body) +
        "," + f("ts", r.createdAt.toString()) + "}"

internal fun decodeStoredStash(raw: String): StoredStash? {
    val fr = nonEmptyField(raw, "fr") ?: return null
    val b = nonEmptyField(raw, "b") ?: return null
    val ts = longField(raw, "ts") ?: return null
    return StoredStash(fr, b, ts)
}

internal fun encodeStoredRedrive(r: StoredRedrive): String =
    "{" + f("ii", r.introId) +
        "," + f("to", r.toContactId) +
        "," + f("fr", r.fromContactId) +
        "," + f("b", r.body) +
        "," + f("n", r.attempts.toString()) +
        "," + f("ts", r.createdAt.toString()) +
        "," + f("t0", r.firstSeenAt.toString()) + "}"

internal fun decodeStoredRedrive(raw: String): StoredRedrive? {
    val ii = firstStringFieldAnywhere(raw, "ii")?.takeIf { isValidIntroId(it) } ?: return null
    val to = nonEmptyField(raw, "to") ?: return null
    val fr = nonEmptyField(raw, "fr") ?: return null
    val b = nonEmptyField(raw, "b") ?: return null
    val ts = longField(raw, "ts") ?: return null
    return StoredRedrive(ii, to, fr, b, firstStringFieldAnywhere(raw, "n")?.toIntOrNull() ?: 0, ts, firstSeen(raw, ts))
}

/** Serializes the bounded tombstone list; invalid ids are dropped, not escaped. */
internal fun encodeCompletedIntros(ids: Collection<String>, max: Int): String =
    ids.filter { isValidIntroId(it) }.let { if (it.size > max) it.takeLast(max) else it }
        .joinToString("\n")

/** Inverse of [encodeCompletedIntros]; tolerates anything (returns what parses). */
internal fun decodeCompletedIntros(raw: String, max: Int): List<String> =
    raw.split("\n").filter { isValidIntroId(it) }.let { if (it.size > max) it.takeLast(max) else it }

// ---------------------------------------------------------------------------
// Purge coupling — the referral analog of [ratchetMetaKeysForContact]
// ---------------------------------------------------------------------------

/** True iff [key] belongs to the referral namespace (the cheap prefix gate both
 *  `VaultDatabase` actuals apply before spending a `getMeta` on the value). */
internal fun isReferralMetaKey(key: String): Boolean = key.startsWith(ReferralMetaKeys.PREFIX)

/**
 * True when the referral `_meta` record [key]=[value] references [contactId] and
 * must therefore be purged by [VaultDatabase.deleteContact] — the referral
 * sibling of [isGroupMetaResidueForContact], and iterated IDENTICALLY by
 * `DatabaseManager.deleteContact` (Android) and `IosVaultDatabase.deleteContact`
 * (iOS). Any new referral record type MUST be classified here or it leaks a
 * deleted contact's handshake state (including an ephemeral X25519 private key)
 * across a delete / re-pair.
 *
 * A VALUE classifier rather than a key list, because a referral record is keyed
 * by introId — an opaque correlator that carries no contactId — while the
 * contact it references lives in the record body. Callers pass the value they
 * already read; a `null`/unparseable value classifies as "not this contact"
 * (the TTL GC in `ReferralManager` deletes unreadable records instead, so
 * nothing is stranded). [ReferralMetaKeys.OFFER_RATE_LIMIT_PREFIX] is the one
 * exception: it IS keyed by contactId directly, so it is matched by
 * exact key equality BEFORE the value is even consulted — mirroring
 * `isGroupMetaResidueForContact`'s `INVITE_RL_PREFIX` case.
 *
 * [ReferralMetaKeys.COMPLETED_KEY] / [ReferralMetaKeys.COMPLETED_KEY_V2] are
 * deliberately never matched: the v2 (current) list holds only `doneTokenFor`
 * hashes — a DIFFERENT derivation than [ReferralManager.referredContactIdFor],
 * so a stored entry cannot be turned back into the contact id it dedupes for
 * (1C-2) — and the v1 (legacy) list is read-only, migrated into v2 and deleted
 * on the next rehydrate. Neither references a contact by id in a way this
 * classifier could check, and both exist only as the guard that stops a
 * re-delivered offer from re-raising a consent dialog for an introduction the
 * user already settled.
 *
 * F2 note: the delivered-offer obligation was added as two FIELDS on the
 * existing `ref_s` record rather than as a sibling record type, precisely so it
 * needs no new clause here — `"of"` can only ever hold `a`/`b`, which the
 * session branch below already matches. Anything that DOES introduce a new
 * referral record type must add its clause, or a deleted contact leaks its
 * handshake state (an ephemeral X25519 private key, live inbox capabilities)
 * across a delete / re-pair.
 */
internal fun isReferralMetaResidueForContact(key: String, value: String?, contactId: String): Boolean {
    if (contactId.isEmpty()) return false
    // Keyed by contactId directly — match on the KEY, independent of
    // whether a value could be read (unlike every other case below).
    if (key == ReferralMetaKeys.OFFER_RATE_LIMIT_PREFIX + contactId) return true
    val raw = value ?: return false
    return when {
        key.startsWith(ReferralMetaKeys.ACCEPT_PREFIX) ||
            key.startsWith(ReferralMetaKeys.OFFER_PREFIX) ->
            firstStringFieldAnywhere(raw, "ic") == contactId
        key.startsWith(ReferralMetaKeys.SESSION_PREFIX) ->
            firstStringFieldAnywhere(raw, "a") == contactId || firstStringFieldAnywhere(raw, "b") == contactId
        key.startsWith(ReferralMetaKeys.STASH_PREFIX) ->
            firstStringFieldAnywhere(raw, "fr") == contactId
        key.startsWith(ReferralMetaKeys.REDRIVE_PREFIX) ->
            firstStringFieldAnywhere(raw, "to") == contactId || firstStringFieldAnywhere(raw, "fr") == contactId
        else -> false
    }
}
