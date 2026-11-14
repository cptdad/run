package com.vg.run

import kotlin.concurrent.Volatile
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext

// ---------------------------------------------------------------------------
// GroupManager — client-side group chat over pairwise fan-out.
//
// Security model:
//
//   • NO group state on the relay, and no group CONTENT on the wire. A group
//     message is N ordinary pairwise sends, one per member, into the per-pairing
//     group inbox (the member's TEXT inbox only as the legacy-peer fallback), and
//     all group routing (groupId, membership hash, control
//     payloads) rides INSIDE the AES-GCM envelope (see
//     MessageManager.sendGroupText/sendGroupControl).
//
//     WHAT IS NOT HIDDEN — do not re-add the old "indistinguishable from N
//     unrelated 1:1 messages" claim. A group send
//     is k POSTs into k distinct inboxes inside one fan-out window, each
//     immediately followed by that member's KIND_ACTIVITY notice into their
//     DISJOINT control inbox (INTERLEAVED per member, so the
//     notice is already on the relay when the text's push wakes the recipient
//     — see sendGroupMessage); a 1:1 send emits no control traffic at all. The
//     interleave pairs one text inbox with one control inbox in TIME, which
//     tells a logging relay nothing it does not already hold: mintInboxPair
//     mints those two back-to-back on one circuit at pairing time. Total send
//     count, jitter budget and window are unchanged by the reordering. Opening a group
//     re-drains those same k inboxes every few seconds. A relay that logs
//     arrival time + target inbox recovers "a group of k+1 exists, and these
//     are its inboxes" from either signal alone. That is intrinsic to pairwise
//     fan-out over a logging relay. What IS protected: content, the group name,
//     the member-list contents, and the mapping from inbox ids to people.
//     AboutContent's "Group chats" page states exactly this — keep them in sync.
//
//   • Sender attribution = the pairwise channel itself. Successful AEAD
//     decryption under the shared secret with contact X *is* proof the group
//     message came from X. No signatures — group messages stay repudiable.
//
//   • Single admin (the creator). Membership changes (rosters) are honored
//     ONLY when they arrive over the admin's pairwise channel, and only with
//     epoch >= the stored epoch. One author + one monotonic epoch means all
//     honest members converge on one member list without a coordination
//     server. This binds honest clients only — nothing can bind a malicious
//     member, which is also true of every other group-messaging design.
//
//   • Member identity / resolution. Members are admin-assigned random
//     memberIds (16 hex chars) — meaningless on their own, because Rún has
//     no global identities. A member resolves "memberId X is my contact C"
//     via PAIRWISE TAGS: tag = HMAC(pairwiseSharedSecret, "grp-tag:" +
//     groupId), truncated to 8 bytes. Both peers of a pairing compute the
//     same tag (deriveSharedSecret is order-independent); nobody else can.
//     Each member's join carries its tag list (padded with random dummy tags
//     to a multiple of TAG_PAD_MULTIPLE so the admin only learns a coarse
//     bucket of the member's contact count, not the exact number); the
//     admin's roster redistributes only the tags that matched between two
//     members. An unmatched (dummy or non-member) tag is an opaque HMAC
//     output and identifies nothing.
//
//   • Message-splitting detection (ADVISORY — catches HONEST drift, not a
//     malicious sender). Every group message carries
//     membershipHash = sha256(groupId | epoch | sorted memberIds)[0..15].
//     A receiver whose own hash differs knows the sender holds a different
//     member list; the message is delivered but flagged (membershipOk=false)
//     — surfaced in the UI like sequenceGap, never silently accepted.
//     IMPORTANT: this hash is lifted verbatim from the sender-controlled AEAD
//     envelope, so a MALICIOUS sender (in particular the very admin that fed the
//     receiver a divergent roster) knows the receiver's expected hash and can set
//     "h" to match — its split-inducing messages then carry membershipOk=true.
//     The 128-bit width only stops an unrelated third party from grinding a
//     collision; it does NOT authenticate the roster against a malicious admin
//     (that needs binding the hash into the AAD from the sender's own persisted
//     roster, which the wire format does not do). Treat membershipOk purely as an
//     honest-drift signal, never as a malicious-admin defense.
//
//   • Group messages stay ephemeral (never persisted), exactly like 1:1.
//     Because group and 1:1 traffic can share pairwise inboxes, a drain
//     performed while one conversation is open may pull messages belonging
//     to another. NO-PARK: such a message is NOT
//     held for its own conversation — a RAM buffer waiting for "its" screen
//     dies on every lock / relaunch (and before the leasing relay the fetch
//     had already burned it; see Retrieve-ack in docs/vault-relay-internals.md). It is shown immediately, clearly marked, in the screen whose
//     poll fetched it ([ReceivedItemKind.PRIVATE] in a group screen,
//     [ReceivedItemKind.GROUP_ECHO] in a 1:1 or another group's screen).
//
//   • The IRL constraint is the admin's to uphold: a member can only be
//     resolved by people who have actually paired with them. An unresolved
//     member can neither be sent to nor receive — the protocol degrades to
//     "visible but inert" rather than silently weakening the trust model.
// ---------------------------------------------------------------------------

class GroupManager(
    private val vault: VaultDatabase,
    // Provider, not instance: MessageManager is recreated on Tor reconnect.
    private val messageManager: () -> MessageManager?,
) {
    companion object {
        private const val TAG = "GroupManager"

        const val KIND_INVITE = "invite"
        const val KIND_JOIN   = "join"
        const val KIND_ROSTER = "roster"
        const val KIND_LEAVE  = "leave"

        /** `strings_shared.xml` keys for the client-synthesised departure notices
         *  (`%1$s` = member alias) and the alias fallback. See announceDeparture. */
        const val NOTICE_LEFT_KEY = "group_notice_left"
        const val NOTICE_REMOVED_KEY = "group_notice_removed"
        const val NOTICE_MEMBER_FALLBACK_KEY = "group_notice_member_fallback"
        // A lightweight "I just sent a group text" notice, fanned out on the
        // control channel alongside the text. Group texts go to the per-pairing
        // group inbox (the 1:1 text inbox only for legacy peers), but the background
        // unread sweep only PEEKS those (a count, no decrypt) so it can't tell a group text
        // from a 1:1 text. The control channel IS drained in the background, so
        // this notice is the signal that drives the GROUP unread dot (and lets
        // us subtract the same texts from the CONTACT dot). Carries no body —
        // the groupId in the envelope is all the receiver needs.
        const val KIND_ACTIVITY = "act"

        /**
         * The ONE optional field a [KIND_ACTIVITY] notice gained — "the text
         * this notice describes went to your GROUP inbox, not your text inbox".
         *
         * Same conventions as `rv` everywhere else in this codebase: a JSON STRING
         * (every body parser here reads only string values, so a numeric `1` would
         * read as absent), appended last, OPTIONAL on receive, and ABSENT-IS-LEGACY
         * — never a rejection reason. Its presence is what splits the two receive
         * tallies apart: WITH it the text is on the group inbox and the contact dot
         * must not move at all; WITHOUT it the text really is on the contact's text
         * inbox and today's subtraction is still the right answer (a mixed-version
         * pairing). See [handleActivity].
         */
        internal const val ACTIVITY_FIELD_GROUP_INBOX = "gi"
        internal const val ACTIVITY_BODY_GRP = """{"$ACTIVITY_FIELD_GROUP_INBOX":"1"}"""

        /**
         * A body-less "I just took a screenshot of this group" notice, fanned out
         * on the control channel exactly like [KIND_ACTIVITY].
         *
         * It is NOT a message: it never touches the ACTIVITY counters
         * ([GroupUnreadTally]) and never wakes a device
         * (`X-No-Push`). It IS persisted on receipt for 24 h
         * ([ScreenshotNoticeStore]) and surfaced two ways — [screenshotNotices] on
         * conversation open, [drainScreenshotNotices] for one that lands while the
         * conversation is already open — and an UNSEEN persisted notice adds its own
         * term to the unread dot until the conversation is polled.
         *
         * Wire value is <= 16 chars, the control-kind cap MessageManager enforces
         * on receive. An older build drops it in [handleControl]'s `else` arm —
         * one log line, no error, no render (see the forward-compat note there).
         */
        const val KIND_SCREENSHOT = "screenshot"

        /**
         * Ceiling on UNDRAINED screenshot notices held per conversation IN RAM. A
         * member is authenticated but not trusted; without a bound one could park
         * unbounded notices in RAM (and hand the UI an unbounded render list)
         * between two drains. Far above honest use — a screenshot notice is a rare,
         * deliberate user action — and the excess is dropped, never queued.
         *
         * [ScreenshotNoticeStore.MAX_PER_CONVERSATION] is the same bound on the
         * DURABLE side (there the oldest row is evicted rather than the newest
         * dropped, so the vault always holds the most recent notices).
         */
        internal const val MAX_PENDING_SCREENSHOT_NOTICES_PER_CONVERSATION = 16

        /**
         * Ceiling on OUTSTANDING (undrained) activity notices from one member.
         * Far above any real backlog — the counter decrements as group texts are
         * drained — but low enough that a flooding member cannot drive the group dot
         * or the 1:1-badge subtraction arbitrarily.
         */
        internal const val MAX_PENDING_ACTIVITY_PER_MEMBER = 99

        /**
         * An activity notice is IGNORED once it is
         * older than this. Every control append now carries the uniform 7-day relay
         * ttl ([MessageManager.CONTROL_APPEND_TTL_SECONDS]) so the ttl stops being a
         * plaintext kind classifier — but a group TEXT carries no ttl at all and so
         * expires on the relay's 24 h default. Without this gate a device that was
         * not opened for days would drain week-old [KIND_ACTIVITY] notices for texts
         * the relay had already dropped, and light a group dot with nothing behind
         * it (and subtract the same phantom from the sender's 1:1 badge).
         *
         * 48 h, not 24: the stamp is the SENDER's minute-rounded envelope time, so
         * the gate must absorb ordinary clock skew. It is peer-controlled and so
         * used in the SUPPRESS direction only — a peer that wants its notice ignored
         * can simply not send one, so honouring a stale stamp grants no new power —
         * and a MISSING or zero stamp is accepted exactly as before.
         */
        internal const val MAX_ACTIVITY_NOTICE_AGE_MS = 48L * 60 * 60 * 1000

        /**
         * Requests in flight during [primeUnreadCounts], and simultaneously the
         * CEILING its `maxConcurrency` argument is clamped to — a caller may ask for
         * fewer, never more.
         *
         * Three, not "as many contacts as there are": fully concurrent request bursts
         * over Tor's single constrained circuit were tried (the concurrent
         * inbox mint) and REVERTED as observably unreliable — on a physical device the
         * cheap warm-gate GET reached the relay while the concurrent requests failed
         * for minutes. Both platforms also open a FRESH stream per request (no
         * connection pooling), so every extra in-flight peek is another rendezvous for
         * one circuit to carry. Three is the compromise: a large win over the fully
         * sequential sweep, far short of a burst that trips the same failure.
         */
        internal const val PRIME_CONCURRENCY = 3

        /**
         * GROUP-FANOUT: inbox GETs in flight during ONE group poll
         * ([pollGroupIntoBuffer]). Concurrent because a sequential fan-out pays one
         * 60 s transport timeout per member inbox on a dead circuit (60 s × 2 ×
         * members on a back tap); concurrent, the poll is bounded by
         * ⌈inboxes / this⌉ timeouts instead.
         * Three, the same ceiling as [PRIME_CONCURRENCY] and for its reason: bursts of
         * concurrent fresh streams over Tor's one circuit were tried and
         * reverted as unreliable on physical devices. Only the GET is concurrent —
         * every vault/ratchet read and write stays serial (see [pollGroupIntoBuffer]).
         */
        internal const val GROUP_POLL_FETCH_CONCURRENCY = 3

        /**
         * Control-inbox `/peek`s in flight during a STEADY-STATE control sweep.
         * Same number and the same reasoning as
         * [PRIME_CONCURRENCY]: three is a large win over a fully sequential
         * sweep and far short of a burst that trips Tor's single circuit.
         *
         * Measured motivation: `control poll done: 6-20 contacts in 13.9 / 15.6 /
         * 15.3 / 15.5 s` on a ~34 s cadence — 16 contacts × (≈0.9 s peek +
         * 100–400 ms jitter), i.e. ≈45 % of the foreground session inside a
         * sweep, against `1-5 contacts in 0.7 s` on a smaller phone.
         *
         * ONLY THE PEEK FANS OUT. The DRAIN stays strictly sequential even when
         * the peek is parallel, because a drain is vault-heavy
         * (`pollControlMessages` reads rows, persists anti-replay counters,
         * applies inbox announces, steps the ratchet) and `DatabaseManager` /
         * `IosVaultDatabase` thread-safety under genuinely concurrent access is
         * unproven on both platforms — the same rule
         * [primeUnreadCounts]/[MessageManager.peekInboxRef] already follow. The
         * common case is an EMPTY control inbox, so the peek phase is where
         * essentially all of the latency lives.
         */
        internal const val CONTROL_PEEK_CONCURRENCY = 3

        /**
         * Per-request stagger (ms, uniform 0..this) inside the parallel peek
         * phase. The steady-state sweeps jitter 100–400 ms BETWEEN contacts
         * because a REPEATING background sweep could otherwise be aligned across
         * cycles by an observer (see [primeUnreadCounts], which is exempt only
         * because it fires once). That reason does not go away when the peeks
         * run three at a time, so each peek still starts at a CSPRNG-drawn
         * offset; the sweep is simply three times denser.
         */
        internal const val CONTROL_PEEK_JITTER_MS = 400

        /**
         * Unresolved-sender buffer: a group text can arrive from a legit
         * member whose member↔member resolution hasn't converged on THIS device yet
         * (the member is still `contactId == null` in the roster). The feeding poll is
         * a relay drain, and before the leasing relay (Retrieve-ack) that drain was
         * destructive, so dropping it lost the plaintext for good. Instead we hold such texts in the unresolved-sender buffer ([ConversationBuffers]) and
         * re-attempt attribution on every roster apply / group open, within a bounded
         * window. Both bounds sit far above any honest convergence backlog but stop an
         * unresolved/removed sender from parking unbounded plaintext in RAM.
         *
         * A GLOBAL-ONLY bound that rejected the INCOMING message would make
         * cross-sender STARVATION trivial — one removed member could hold all 64
         * slots with its own blobs and every group text from a genuinely
         * not-yet-resolved member would be dropped and lost (the exact loss this
         * buffer exists to prevent). So the bound has a per-(group, sender) sub-cap AND evicts the OLDEST entry of whichever key
         * holds the most — i.e. it routes straight through [ConversationBuffers.evictForCapacityLocked],
         * the same shared eviction every sibling content buffer uses. An arrival is
         * therefore never rejected: it displaces the largest holder's oldest entry, so
         * a flooder can only ever destroy its OWN parked blobs.
         */
        internal const val MAX_PENDING_UNRESOLVED_GROUP_TEXTS = 64
        internal const val MAX_PENDING_UNRESOLVED_PER_SENDER = 16
        internal const val PENDING_UNRESOLVED_GROUP_TEXT_TTL_MS = 10L * 60 * 1000

        /**
         * The [ConversationBuffers] screen buffers
         * hold DECRYPTED plaintext between a screen's poll and that screen's take
         * (POLL-HANDOFF-1). Every sibling buffer in this
         * file has a ceiling ([MAX_PENDING_SCREENSHOT_NOTICES_PER_CONVERSATION],
         * [MAX_PENDING_UNRESOLVED_GROUP_TEXTS], [MAX_PENDING_ACTIVITY_PER_MEMBER]) —
         * these two didn't, so an authenticated peer (any paired contact, or a group
         * co-member) could park an unbounded amount of plaintext in RAM by sending
         * texts into a conversation the victim never opens, eventually escaping every
         * `catch (e: Exception)` on the poll path with an `OutOfMemoryError`. Both a
         * per-key ceiling and a global ceiling, far above any honest backlog (the
         * relay only retains 24h of traffic).
         */
        internal const val MAX_PENDING_CONTENT_PER_KEY = 256
        internal const val MAX_PENDING_CONTENT_TOTAL = 1024

        /** Hard cap on group size — IRL-paired groups are small by design,
         *  and the cap bounds roster body size and fan-out cost. */
        const val MAX_GROUP_MEMBERS = 64

        /** Join tag lists are padded with random dummies to a multiple of
         *  this, so the admin learns only a coarse contact-count bucket. */
        internal const val TAG_PAD_MULTIPLE = 8

        /** Defense-in-depth cap when parsing a peer's tag list. */
        internal const val MAX_TAGS_PER_MEMBER = 1024

        /** Cap a peer-supplied group name for display sanity. */
        const val MAX_GROUP_NAME_CHARS = 64

        // Invite-flood blast-radius bounds. An invite only parks in
        // [pendingInvites] until the user taps Join (the consent gate, mirroring
        // ReferralManager offers), but a single paired contact can still spam
        // invites, and every distinct groupId triggers a fresh tag disclosure
        // over our whole contact list (handleInvite). So bound the damage: cap how
        // many groups ONE contact can force us into at once, and rate-limit
        // invites per contact per window. Neither replaces consent — they cap
        // unbounded local DB growth and repeated contact-graph tag harvesting.
        // The standing cap is clock-INDEPENDENT (derived from persisted groups),
        // so it holds even if an attacker rolls the device clock to defeat the
        // time-window rate-limit. Both bounds sit far above real IRL use (you
        // are rarely in 8+ groups all created by the same single person).
        internal const val MAX_FORCED_GROUPS_PER_CONTACT = 8
        internal const val INVITE_RATE_WINDOW_MS = 60L * 60 * 1000   // 1 hour
        internal const val MAX_INVITES_PER_WINDOW = 8
        private const val INVITE_RL_META_PREFIX = "grp_inv_rl:"

        // Per-offer decline tombstone: a declined invite stays declined
        // PER OFFER. A re-delivery of the SAME structural offer (same groupId,
        // inviter, epoch, admin/my memberId and member set) must NOT re-prompt or
        // consume rate budget; a genuinely NEW offer (different epoch / members /
        // inviter) still prompts. Mirrors ReferralManager.completedIntros exactly:
        // a bounded, insertion-ordered set of one-way HASHED offer tokens
        // (declineTokenFor), persisted as ONE encoded `_meta` blob
        // (DECLINED_INVITE_META) with oldest-evicts past the cap. The stored value
        // is nothing but truncated SHA-256 hashes, so — like the referral `ref_done2`
        // tombstone and the `update_nudge_v1` singleton — it exposes NO reconstructible
        // group/contact link and is deliberately NOT purged on contact/group delete
        // (that would defeat the whole per-offer-persistence point); it dies only with
        // a full-vault wipe. See GroupMetaKeys for the deliberate purge-list absence.
        internal const val MAX_DECLINED_INVITES = 128
        private const val DECLINED_INVITE_META = "grp_declined"

        // The unchanged-tags dedup in handleJoin is bypassable
        // — the tag list is attacker-controlled, so an admitted member can vary its
        // dummy padding each KIND_JOIN to force a fresh full-roster fan-out every
        // time. Content-based dedup can't fix that. So THROTTLE the broadcast per
        // (group, member) regardless of tag content: at most one re-roster per this
        // interval per member. Legitimate tag updates are occasional, so this is
        // ample for honest use while capping the amplification to 1 roster/interval.
        internal const val MIN_ROSTER_INTERVAL_MS = 15_000L
        private const val ROSTER_RL_META_PREFIX = "grp_roster_rl:"

        // Membership-change delivery is durable. A roster/leave/invite carries a 7-day relay TTL (the
        // relay ceiling; default is 24 h and the app tears its session down on
        // every background, so "did not open it for a day" is ordinary), and a
        // roster/leave that the relay refused — or that could not be sent because
        // Tor was down — is recorded as a durable `_meta` obligation and redriven
        // from the control sweep. Without this, one refused append (or one absent
        // member) left the removed member in that member's fan-out forever.
        // Despite the name, every control append carries this value (see [membershipControlTtl] and
        // [MessageManager.CONTROL_APPEND_TTL_SECONDS], the single source). The name
        // is kept because the membership redrive and its tests reference it.
        internal const val MEMBERSHIP_CONTROL_TTL_SECONDS = MessageManager.CONTROL_APPEND_TTL_SECONDS

        // An HTTP 2xx on the APPEND is proof the RELAY took
        // the blob, and nothing more. A relay that answers 201 and discards
        // suppresses a roster/leave permanently at strictly lower cost than the
        // 4xx/5xx veto the redrive closed — the removed member keeps reading group plaintext
        // from every member whose own copy was dropped the same way, and the admin is
        // told the removal landed. Delivery therefore has to be confirmed END TO END,
        // and the protocol already carries the confirmation: every group text and
        // every group control ships the sender's `membershipHash`.
        //
        // Two mechanisms, deliberately independent (either one alone converges):
        //
        //  1. ACK-GATED OBLIGATIONS. A `grp_ctl_pend` record is written on
        //     SUCCESS too, in state AWAITING_ACK, and cleared only by POSITIVE
        //     evidence — a message from that member whose membershipHash equals ours
        //     — or by the bounds below. The redrive re-sends it at a SLOW cadence
        //     ([MembershipControlRedrive.CTL_ACK_RESEND_INTERVAL_MS]) so an honest member that simply has not
        //     spoken yet costs a handful of appends, not a beacon.
        //
        //  2. HASH-MISMATCH RE-ROSTER ([rerosterUnconvergedMembers]). A message from
        //     a member carrying a membershipHash that is NOT ours is positive
        //     evidence that member has not converged, whatever the relay claimed.
        //     The admin re-sends the CURRENT roster to that member alone, at most
        //     once per [REROSTER_MIN_INTERVAL_MS] and at most
        //     [UnconvergedMembers.MAX_REROSTERS_PER_SWEEP] per control sweep.
        //
        // Known limitation: a member that never sends anything never acks.
        // Mechanism 1 gives it [MembershipControlRedrive.MAX_CTL_ACK_RESENDS] copies and then stops; after
        // that only its own traffic (mechanism 2) or the next membership change can
        // converge it. There is no ack control KIND on the wire — adding one would be
        // a new relay-visible per-member response to every roster, and a hostile
        // relay could drop it just as easily.
        internal const val REROSTER_MIN_INTERVAL_MS = 10L * 60 * 1000

        /** How long after a member is added we keep FORCING the
         *  fast control-poll cadence to converge its resolution. A member you never
         *  IRL-paired with is NEVER resolvable ("visible but inert"), so an unbounded
         *  "any unresolved member" fast-poll turns the device into a permanent ~2.5–5 s
         *  Tor beacon (+ battery/data drain) — exactly the fixed traffic signature the
         *  idle jitter exists to hide. 10 min generously covers a real multi-hop
         *  join→roster→resolve round-trip even over slow Tor; after it a still-unresolved
         *  member stops pinning fast-poll (idle poll still completes a late resolution,
         *  and any actual control traffic re-arms fast via the poll loop's `received`).
         *
         *  The window is measured from `max(m.addedAt, last membership EVENT for that
         *  group)` — see [noteUnresolvedFastAnchor] — not from `addedAt` alone:
         *  `handleRoster` preserves `addedAt` across every later roster and across
         *  relaunch, so `addedAt` alone would drop a chain that is still converging off
         *  the fast cadence at a fixed wall-clock age. The pin is untouched: a
         *  never-IRL-paired member generates no membership events, so it never
         *  re-anchors. */
        internal const val UNRESOLVED_MEMBER_FAST_WINDOW_MS = 10L * 60 * 1000

        /** Cap on the RAM-only re-anchor map (`groupId -> last membership-event
         *  clock`, see [noteUnresolvedFastAnchor]). A device has a handful of groups;
         *  the cap only exists so a peer that keeps inviting us to fresh groupIds
         *  cannot grow the map, and an evicted entry degrades to the
         *  `addedAt`-only behaviour rather than to a wrong "still converging". */
        internal const val MAX_UNRESOLVED_ANCHORS = 64

        /** The ABSOLUTE ceiling on one anchor-driven fast EPISODE
         *  per group — the same value and the same reasoning as
         *  [MessageManager.CONTROL_FAST_EPISODE_MAX_MS]: "a window any
         *  applied control re-opens" is not a bound. Measured from the FIRST
         *  [noteUnresolvedFastAnchor] of the episode; a later anchor inside the
         *  episode moves nothing. A new episode starts only once the previous
         *  anchor's own [UNRESOLVED_MEMBER_FAST_WINDOW_MS] has fully lapsed (no
         *  applied membership control for a whole window), so the worst a peer
         *  that keeps applying real changes can buy is 10 min fast per 20 min. */
        internal const val UNRESOLVED_FAST_EPISODE_MAX_MS = MessageManager.CONTROL_FAST_EPISODE_MAX_MS

        /** Max epoch advance accepted in one roster. A roster
         *  bumps the epoch by 1 per membership change, so no legitimate jump ever
         *  approaches this — but an unbounded advance lets a malicious admin set
         *  the epoch to Long.MAX_VALUE and permanently freeze membership (every
         *  later lower-epoch roster is then dropped as stale). */
        internal const val MAX_GROUP_EPOCH_ADVANCE = 1024L

        /** Absolute cap on a group epoch. A fresh INVITE carries an
         *  initial epoch (handleInvite); left unbounded, a malicious invite could
         *  set it near Long.MAX so the roster upper-bound compare `g.epoch +
         *  MAX_GROUP_EPOCH_ADVANCE` overflows Int/Long. The epoch only ever rises by
         *  1 per membership change (or <=1024 per accepted roster), so a million is
         *  already unreachable for any real group; anything above it is malicious. */
        internal const val MAX_GROUP_EPOCH = 1_000_000L

        private val MEMBER_ID_REGEX = Regex("^[0-9a-f]{16}$")
        private val TAG_REGEX       = Regex("^[0-9a-f]{16}$")

        internal fun isValidMemberId(s: String) = MEMBER_ID_REGEX.matches(s)

        /** A join tag is "sym:bound" — two 16-hex halves joined by ':'. */
        internal fun isValidTagPair(s: String): Boolean =
            s.length == 33 && s[16] == ':' &&
                TAG_REGEX.matches(s.substring(0, 16)) && TAG_REGEX.matches(s.substring(17))

        internal fun newGroupId(): String = encodeBase64Url(generateSecureRandom(24))
        internal fun newMemberId(): String = bytesToHex(generateSecureRandom(8))

        /** Sentinel admin-of-record value for a group THIS DEVICE
         *  created (or was legitimately promoted into, see handleRoster) — there is
         *  no inviting contact to record in that case. Collision-safe against every
         *  REAL contactId by construction, not just by alphabet: a contactId is
         *  always exactly 36 chars (`UUID.randomUUID().toString()` —
         *  androidApp/AddContactScreen.kt, iosApp/AddContactView.swift) or exactly
         *  24 chars (referral-derived, `ReferralManager.referredContactIdFor` —
         *  base64url of 18 fixed bytes, no padding). This 4-char marker can never
         *  equal either, independent of what characters it uses. */
        internal const val SELF_ADMIN_MARKER = "self"

        /**
         * The pairwise resolution tag for one (pairing, group) combination.
         * Symmetric: both peers derive the identical value because
         * deriveSharedSecret() is order-independent. Keyed by the pairwise
         * secret, so no third party — including the admin who relays it —
         * can link it to anything.
         */
        internal fun pairTag(sharedSecret: ByteArray, groupId: String): String =
            bytesToHex(
                hmacSha256(sharedSecret, "grp-tag:$groupId".encodeToByteArray())
                    .copyOfRange(0, 8)
            )

        /**
         * The RESOLUTION tag — like [pairTag] but also bound
         * to a memberId. The bare pairTag only proves "the receiver shares a
         * pairing with SOME contact"; it says nothing about WHICH memberId that
         * contact is, so a malicious admin could place a victim's tag under an
         * arbitrary member slot and mis-bind identity in the roster. This binds
         * the tag to a memberId: the advertiser commits to its OWN memberId, and
         * the resolver recomputes with the roster SLOT's memberId — so a tag only
         * resolves under the slot the advertiser actually claimed. The admin can
         * no longer move a tag to a different slot (it can't recompute the HMAC).
         * pairTag is still advertised alongside it so the admin can detect which
         * pairings are mutual (opaque to it) and redistribute only those.
         */
        internal fun boundTag(sharedSecret: ByteArray, groupId: String, memberId: String): String =
            bytesToHex(
                hmacSha256(sharedSecret, "grp-tag:$groupId:$memberId".encodeToByteArray())
                    .copyOfRange(0, 8)
            )

        /**
         * Deterministic digest of (group, epoch, member set), independent of
         * member order. Carried in every group message; a mismatch on receive
         * means sender and receiver disagree about who is in the group.
         */
        internal fun membershipHash(groupId: String, epoch: Long, memberIds: List<String>): String =
            bytesToHex(
                sha256(
                    (groupId + "|" + epoch + "|" + memberIds.sorted().joinToString(","))
                        .encodeToByteArray()
                ).copyOfRange(0, 16)
            )

        /**
         * The per-OFFER decline tombstone token. A one-way, domain-separated hash
         * over the STRUCTURAL identity of an invite — groupId, inviterContactId,
         * epoch, adminMemberId, myMemberId and the SORTED member set — so a
         * re-delivery of the same offer maps to the SAME token while a genuinely new
         * offer (different epoch / members / inviter) maps to a different one and
         * still prompts. The cosmetic [GroupInvite.groupName] is DELIBERATELY excluded:
         * a rename is the same offer.
         *
         * Same primitive as [ReferralManager.doneTokenFor] — a domain-prefixed
         * [sha256] truncated to 18 bytes, [encodeBase64Url]-encoded (NO new crypto).
         * One-way + truncated, so a stored token exposes no reconstructible group or
         * contact id (why it needs no delete-time purge; see GroupMetaKeys).
         */
        internal fun declineTokenFor(invite: GroupInvite): String =
            encodeBase64Url(
                sha256(
                    ("grp-declined|" + invite.groupId + "|" + invite.inviterContactId + "|" +
                        invite.epoch + "|" + invite.adminMemberId + "|" + invite.myMemberId + "|" +
                        invite.memberIds.sorted().joinToString(","))
                        .encodeToByteArray()
                ).copyOfRange(0, 18)
            )
    }

    // -----------------------------------------------------------------------
    // In-memory SCREEN buffers (POLL-HANDOFF-1). Keyed by the screen whose poll
    // fetched the item — never by "the conversation the item belongs to"
    // (NO-PARK). Session-scoped, never persisted.
    // -----------------------------------------------------------------------

    // Sink for direct referral control messages drained alongside group
    // controls (set by the platform layer to ReferralManager::handleControl).
    // GroupManager stays agnostic — it just forwards by kind.
    var onReferralControl: ((senderContactId: String, kind: String, body: String) -> Unit)? = null

    // Fired ONCE per control sweep, right after the transport check and before any
    // inbox is touched (set by SessionManagers to ReferralManager::runMaintenance).
    // The referral handshake's TTL GC and its two bounded redrive obligations need
    // a cadence with a live transport; this is that loop, and reusing it keeps
    // ReferralManager free of a timer of its own. GroupManager stays agnostic.
    var onControlSweep: (() -> Unit)? = null

    // The block set (iOS Block feature — Android ships none, so the
    // default empty set is correct there). The control channel must honor Block
    // exactly as the text peek already does (peekUnreadCounts): a blocked contact's
    // control inbox is NOT polled (severs the polling relationship, not just the
    // display), and any invite / referral-offer / inbox-announce that nonetheless
    // reaches ingest (e.g. via a shared group's member poll) from a blocked sender
    // is dropped before it can surface a modal or mutate the vault. Set by the
    // platform layer to BlockStore.blocked(); a throwing provider is treated as
    // "nothing blocked" so a transient Keychain read can't silently mass-unblock.
    var blockedContacts: (() -> Set<String>) = { emptySet() }

    private fun blockedContactsSafe(): Set<String> =
        try { blockedContacts() } catch (e: Exception) {
            platformLogWarn(TAG, "blockedContacts provider failed: ${e::class.simpleName}"); emptySet()
        }

    // Test seam for the unresolved-sender buffer's TTL (mirrors ReferralManager.clockMs).
    // Production reads the real clock; unit tests substitute it to drive
    // PENDING_UNRESOLVED_GROUP_TEXT_TTL_MS expiry deterministically. The unresolved-sender
    // buffer's stamp + its expiry sweep route through this, and so do the two connection-log
    // pass timers ([pollAllControls], [primeUnreadCounts]) — which is what lets a unit
    // test assert their seconds exactly. Other time reads are unaffected.
    internal var clockMs: () -> Long = { currentTimeMillis() }

    // Conversation screen buffers, unresolved-sender buffer, RAM screenshot notices:
    // see [ConversationBuffers] (one lock; NO-PARK is defined in its header).
    private val buffers = ConversationBuffers(
        clock = { clockMs() },
        groupOf = { vault.getGroup(it) },
        membersOf = { vault.getGroupMembers(it) },
        toMessage = { contactId, groupId, g, members, rm -> toGroupMessage(contactId, groupId, g, members, rm) },
        // A parked notice that just resolved is replayed through the SAME entry point
        // handleActivity uses — so the per-member SUM ceiling still applies, and a
        // counted `gi` notice is persisted exactly like a live one. `tally` and
        // `unreadMarkers` are declared below; this lambda only runs at flush time (post-init).
        applyNotice = { groupId, senderContactId, onGroupInbox, noticeAtMs ->
            applyActivityNotice(senderContactId, groupId, onGroupInbox, noticeAtMs)
        },
    )

    // The DURABLE side of screenshot notices (the RAM side is [ConversationBuffers]):
    // one bounded, self-expiring `_meta` row per received notice, so a notice drained by the background control sweep is
    // still there when the user next opens that conversation. Holds no cache, so it
    // takes no part in [scrubInMemory]. See ScreenshotNoticeStore.kt for the format,
    // the purge coupling and the fail-soft rule.
    private val screenshotStore = ScreenshotNoticeStore(vault)

    // The DURABLE mirror of [pendingInvites] — one bounded, self-expiring `_meta`
    // row per parked invite, so an invite the user has SEEN but not yet answered is
    // still there after the session teardown that follows every backgrounding. Like
    // [screenshotStore] it holds no cache, so it takes no part in [scrubInMemory].
    // See GroupInviteStore.kt for the format, the purge coupling and the fail-soft
    // rule. Declared BEFORE `init` so the rehydrate below can use it (Kotlin runs
    // property initializers and init blocks in declaration order).
    private val inviteStore = GroupInviteStore(vault)

    /**
     * TRANSITION-latched "no transport" logging. A missing MessageManager (Tor down /
     * being rebuilt) makes every drain a silent no-op — and for a 1:1 TEXT inbox, which
     * is only ever drained from its open conversation, that silent skip IS the stall:
     * the relay holds the message (peek keeps reporting pending>0) and nothing ever
     * retrieves it. So it must be logged. But the callers are HOT — the 1:1 poll loops
     * run at ~1 Hz (iOS has no transport guard at all) and the group loops every few
     * seconds — so logging per call would emit ~1 line/s into the 2000-entry LogBuffer
     * ring and evict the Tor/relay lines that are the actual diagnostic payload (on iOS
     * that ring is the only log surface). Log the EDGE instead: once when transport
     * goes away, once when it returns.
     */
    private var noTransportLogged = false

    // The durable `grp_ctl_pend:` obligations (record / acknowledge / redrive /
    // purge). Pure `_meta` state, no RAM and no lock of its own; [clockMs] and the
    // transport are read through lambdas so the test seams keep working.
    private val ctlRedrive = MembershipControlRedrive(
        vault = vault,
        clock = { clockMs() },
        transport = { transport(it) },
        rosterBody = { buildRosterBody(it) },
        leaveBody = { epoch, memberId -> leaveBody(epoch, memberId) },
    )

    private fun transport(where: String): MessageManager? {
        val mgr = messageManager()
        if (mgr == null) {
            if (!noTransportLogged) {
                noTransportLogged = true
                platformLogWarn(TAG, "$where skipped — no transport (nothing is draining; waiting for Tor)")
            }
        } else if (noTransportLogged) {
            noTransportLogged = false
            platformLog(TAG, "transport back — draining resumed")
        }
        return mgr
    }

    // Test seam for the presence bump's NOTICE GRACE ([GroupUnreadTally.unattributedContacts]).
    // MONOTONIC in production — deliberately NOT [clockMs] (wall clock): a wall-clock
    // step must neither hold a fallback dot back nor fire it early. Read under the
    // tally's lock, so it must stay a pure clock read. Declared before [tally].
    internal var noticeGraceClockMs: () -> Long = { GroupUnreadTally.monotonicNowMs() }

    // The session-scoped unread tallies (group dot, legacy compensator,
    // group-inbox depth, `gi`-notice count, restored units), under their own lock: see
    // [GroupUnreadTally]. Never named after the group count — the source guard
    // forbids that substring on the contact path.
    private val tally = GroupUnreadTally(nowMs = { noticeGraceClockMs() })

    // The DURABLE mirror of the tally's `gi` attribution (owner decision 2026-11-12):
    // per sender contact, which group(s) its still-pending `gi` notices named, so a
    // session that starts after a teardown restores the right group dot instead of
    // presence-bumping every group shared with that sender. Written/cleared in
    // lockstep with the tally, always OUTSIDE the tally's lock (SyncLock is
    // non-reentrant on iOS and must never be held across SQLCipher); restored once,
    // in `init`. Fail-soft: any vault failure falls back to the presence bump. See
    // GroupUnreadMarkerStore.kt for the format, the TTL/heal rules and the purge coupling.
    private val unreadMarkers = GroupUnreadMarkerStore(vault, clock = { clockMs() })

    // One-shot connect-time unread prime ([primeUnreadCounts]) — at most one pass
    // may be in flight. A Tor reconnect re-wires the transport and can re-fire the
    // prime while the previous pass is still working through its permits, and two
    // live primes are 2 × [PRIME_CONCURRENCY] streams on one circuit, i.e. exactly
    // the burst the concurrent-mint lesson bounds. A SyncLock-guarded flag rather than an
    // atomic: commonMain has no atomics here, which is why every other cross-thread
    // field in this file is lock-guarded too. Deliberately NOT cleared by
    // [scrubInMemory] — it is not sensitive state, and clearing it under a live pass
    // would re-admit the second prime this exists to stop.
    private val primeLock = SyncLock()
    private var primeInFlight = false

    // MUTUAL EXCLUSION for the CONTROL SWEEP. Two callers drain control inboxes: the
    // platform control-poll loop and the connect-time prime's pre-drain. The loop's
    // first cycle fires 3-7 s after the transport wires, while the pre-drain may still
    // be working through the same control inboxes. Two
    // concurrent drains of one inbox double the "a response lost on a cold circuit
    // destroys those invites/rosters for good" exposure, and race the per-contact
    // anti-replay counter persist (safe only because it re-reads under the row lock and
    // clamps monotonically — not something to lean on deliberately).
    //
    // The second caller SKIPS rather than waits: the work is already being done by the
    // holder, and a control sweep can block for MINUTES on a cold circuit, so waiting
    // would park the poll loop (and its push re-sync + unread publish) behind it. A
    // SyncLock-guarded flag rather than an atomic, matching [primeInFlight] — commonMain
    // has no atomics here.
    private val controlSweepLock = SyncLock()
    private var controlSweepInFlight = false

    // Set when the prime's pre-drain actually applied a control batch; CONSUMED (and
    // cleared) by the next [pollAllControls]. Both platform loops nudge their
    // vault-observing UIs off pollAllControls' return value — that is what makes an
    // applied invite surface a group row with NO navigation — so a pre-drain that
    // silently took the batch for itself would otherwise cost exactly that nudge. Holds
    // one boolean, no ids: nothing sensitive, but it is cleared in [scrubInMemory]
    // anyway so a torn-down session cannot hand a stale nudge to the next one.
    private val controlNudgeLock = SyncLock()
    private var pendingControlNudge = false


    // Departure notices already posted this session (groupId → memberIds), so a
    // member's exit is announced exactly once even though a voluntary leave both
    // sends KIND_LEAVE (→ "left") AND makes the admin re-roster (→ would also
    // detect the removal). Whichever arrives first wins; the other is deduped.
    private val departureLock = SyncLock()
    private val departureAnnounced = mutableMapOf<String, MutableSet<String>>()

    // Consent gate: invites parked awaiting the user's accept/decline.
    // Keyed by groupId, and the RAM copy is still the in-session authority (both
    // platforms poll [pendingInvites] from the main thread every 4 s, so the lock
    // must stay CHEAP: no vault WRITES and no vault scans while it is held). The
    // one exception is a single cheap keyed [VaultDatabase.getGroup] re-check
    // immediately before the park in [handleInvite] — an indexed
    // single-row lookup on both actuals, not a scan — which closes the TOCTOU
    // window against a concurrent [acceptInvite] (which commits the group and
    // drops the park OUTSIDE this lock).
    //
    // Each park is mirrored into [inviteStore] and the mirror is rehydrated in `init`
    // (i.e. on vault open, before any poll can apply new control), exactly the way
    // [declinedInvites] and ReferralManager's parked OFFERS work: the session is torn
    // down on every backgrounding, so a RAM-only park would lose an invite the user
    // has SEEN but not yet answered. Accept, decline, expiry, leaving/removal from the group
    // and deleting the inviter all drop the row. The durable mirror write itself
    // ([GroupInviteStore.record] — a full `_meta` key scan + per-row reads + a
    // transaction) is issued AFTER this lock is released: the main-thread poll takes
    // [pendingInviteLock] every 4 s, and a slow/cold vault call under it would stall
    // that poll.
    private val pendingInviteLock = SyncLock()
    private val pendingInvites = mutableMapOf<String, GroupInvite>()

    // Per-offer decline tombstone (mirrors ReferralManager.completedIntros).
    // Insertion-ordered HASHED offer tokens (declineTokenFor) of invites the user has
    // DECLINED; a re-delivery of one is suppressed in handleInvite before it can
    // re-park, re-prompt, or spend rate budget. Oldest evicts once over
    // MAX_DECLINED_INVITES. Guarded by [pendingInviteLock] (which already serialises
    // the invite state). Loaded from DECLINED_INVITE_META on construction and
    // re-persisted on every mutation; cleared in [scrubInMemory] — the persisted copy
    // reloads on the next construction, exactly like completedIntros.
    private val declinedInvites = LinkedHashSet<String>()

    init {
        // Rehydrate the decline tombstone from the vault. NEVER throws and FAILS
        // TOWARD EMPTY: a store read failure or an undecodable record must degrade to
        // "nothing declined" (a genuine invite still prompts), never to a failed
        // manager construction (which would take unlock down with it) and never to
        // silently suppressing a real invite. No lock is taken — construction is
        // single-threaded and this instance is not yet published (same as
        // ReferralManager.rehydrate, which mutates completedIntros lock-free in init).
        try {
            val raw = vault.getMeta(DECLINED_INVITE_META)
            if (raw != null) {
                declinedInvites.addAll(decodeDeclinedInvites(raw, MAX_DECLINED_INVITES))
            }
        } catch (e: Exception) {
            platformLogWarn(TAG, "declined-invite tombstone load failed — continuing empty: ${e::class.simpleName}")
        }
        // Rehydrate the invites the previous session parked but the user never
        // answered. Runs AFTER the tombstone load on purpose: a row whose offer the
        // user already declined must be suppressed (and dropped), which is only
        // knowable once [declinedInvites] is populated. Same fail-toward-EMPTY
        // discipline: a store read failure or an undecodable row degrades to "no
        // parked invite" (the pre-existing behaviour), never to a failed manager
        // construction — which would take unlock down with it. No lock is taken:
        // construction is single-threaded and this instance is not yet published.
        try {
            for (stored in inviteStore.load()) {
                val invite = resolveParkedInvite(stored) ?: continue
                if (declineTokenFor(invite) in declinedInvites) {
                    // The decline landed but its row delete did not (or the row was
                    // re-imported by a device move). Honour the tombstone and finish
                    // the delete now — never re-prompt an offer the user settled.
                    inviteStore.remove(stored.groupId, stored.inviterContactId)
                    continue
                }
                pendingInvites[stored.groupId] = invite
            }
            if (pendingInvites.isNotEmpty()) {
                platformLog(TAG, "parked group invites restored: ${pendingInvites.size}")
            }
        } catch (e: Exception) {
            platformLogWarn(TAG, "parked-invite rehydrate failed — continuing empty: ${e::class.simpleName}")
        }
        // Restore the group unread attribution the previous session persisted, BEFORE
        // anything can publish a group count or apply a new notice (construction is
        // single-threaded and this instance is not yet published; a live notice
        // applied before the restore would be counted twice). Never throws.
        restoreUnreadAttribution()
    }

    /**
     * Once per session (from `init`): hands the vault mirror of the `gi`
     * attribution back to the RAM tally. A unit whose group is gone or whose sender
     * is no longer a resolved member is DETACHED by the store (it still accounts for
     * a blob on that sender's group inbox, it lights nothing). Fail-soft: on any
     * failure the tally simply starts empty — today's presence-bump behaviour.
     */
    private fun restoreUnreadAttribution() {
        try {
            val membersByGroup = HashMap<String, Set<String>>()
            val restored = unreadMarkers.restore(
                contactExists = { vault.getContact(it) != null },
                isMember = { contactId, groupId ->
                    contactId in membersByGroup.getOrPut(groupId) {
                        if (vault.getGroup(groupId) == null) emptySet()
                        else vault.getGroupMembers(groupId).mapNotNullTo(HashSet()) { it.contactId }
                    }
                },
            )
            var n = 0
            for ((contactId, units) in restored) n += tally.restore(contactId, units.map { it.groupId })
            if (n > 0) platformLog(TAG, "group unread attribution restored: $n")
        } catch (e: Exception) {
            platformLogWarn(TAG, "group unread attribution restore failed — continuing empty: ${e::class.simpleName}")
        }
    }

    /**
     * Rebuilds the full [GroupInvite] the consent prompt needs from a persisted row,
     * re-deriving the three fields the row deliberately does NOT carry — the
     * inviter's alias and the admin-mismatch warning — from live vault state, so
     * they are as fresh as they would have been on receipt (aliases rotate).
     *
     * Returns null — and DELETES the row — for the two states that make a parked
     * invite unusable rather than merely stale, both of which are self-healing
     * rather than errors:
     *  - the group is already joined (an accept that committed but whose row delete
     *    did not land, or a join by another route). Re-parking it would show a
     *    consent prompt for a group already in the list;
     *  - the inviter contact is gone. `acceptInvite` fans our KIND_JOIN at that
     *    contact, so there is nothing to accept — and this is the belt-and-braces
     *    half of the [isGroupInviteResidueForContact] purge.
     *
     * Never throws: any vault read failure is treated as "cannot resolve", which
     * SKIPS the invite for this session WITHOUT deleting the row (a transient read
     * error must not destroy a live invite — the next unlock retries).
     */
    private fun resolveParkedInvite(stored: StoredGroupInvite): GroupInvite? {
        val alias = try {
            if (vault.getGroup(stored.groupId) != null) {
                inviteStore.remove(stored.groupId, stored.inviterContactId)
                return null
            }
            val contact = vault.getContact(stored.inviterContactId)
            if (contact == null) {
                inviteStore.remove(stored.groupId, stored.inviterContactId)
                return null
            }
            contact.alias
        } catch (e: Exception) {
            platformLogWarn(TAG, "parked invite skipped this session (vault read failed): ${e::class.simpleName}")
            return null
        }
        val (adminMismatch, priorAdminAlias) = adminEclipseCheck(stored.groupId, stored.inviterContactId)
        return GroupInvite(
            groupId = stored.groupId, inviterContactId = stored.inviterContactId,
            inviterAlias = alias, groupName = stored.groupName,
            epoch = stored.epoch, adminMemberId = stored.adminMemberId,
            myMemberId = stored.myMemberId, memberIds = stored.memberIds,
            adminMismatch = adminMismatch, priorAdminAlias = priorAdminAlias,
        )
    }

    /** THE TAKE for a group screen: everything its polls fetched (OWN group texts,
     *  PRIVATE 1:1 texts, GROUP_ECHO texts of other groups) plus its system
     *  notices, in arrival order. RAM-only, non-suspending. */
    fun takeGroupScreenItems(groupId: String): List<GroupMessage> = buffers.takeGroupScreenItems(groupId)

    // -----------------------------------------------------------------------
    // "Screenshot taken" notices (see ScreenshotNotice.kt). ONE surface for both
    // contexts: the 1:1 notice is applied by MessageManager (never surfaced as a
    // message) and collected from there; the group notice arrives as an ordinary
    // group control and is buffered by [handleScreenshotNotice].
    // -----------------------------------------------------------------------

    /**
     * Moves any 1:1 notices the TRANSPORT has collected into the per-conversation
     * buffers. Called from every poll entry point and from
     * [drainScreenshotNotices], so a notice drained on the background control
     * sweep survives a later MessageManager rebuild (Tor reconnect) instead of
     * dying with the transport instance.
     *
     * ALSO the PERSIST point for the 1:1 leg: each collected notice is written to
     * the vault ([screenshotStore]) before it is buffered, which is what makes it
     * survive the session teardown that follows every backgrounding. The write is a
     * no-throw fail-soft — a refusal (iOS locked keybag) only costs durability, and
     * the RAM buffer below still serves an open conversation.
     *
     * The alias is resolved HERE, from the vault, at collection time — the wire
     * carries no sender field, and no alias is ever persisted. A notice whose
     * contact has since been deleted is dropped (there is no conversation left to
     * render it in), and a BLOCKED contact's notice is dropped too: the block set
     * must silence every surface, and the transport has no view of it (mirrors
     * [ingest]'s backstop).
     *
     * Both the vault write and [ConversationBuffers.bufferScreenshotNotice] run OUTSIDE any lock we hold
     * — [SyncLock] is non-reentrant on iOS, and a SQLCipher write under the buffers' lock
     * would serialise every other buffer behind the database.
     */
    private fun collectDirectScreenshotNotices() {
        val drained = messageManager()?.drainDirectScreenshotNotices() ?: return
        if (drained.isEmpty()) return
        val blocked = blockedContactsSafe()
        for (n in drained) {
            if (n.contactId in blocked) continue
            val alias = vault.getContact(n.contactId)?.alias ?: continue
            val stored = screenshotStore.record(
                conversationId = n.contactId,
                isGroup = false,
                senderContactId = n.contactId,
                senderClaimedTakenAtMs = n.claimedTakenAt,
            )
            val receivedAt = stored?.receivedAt ?: n.receivedAt
            buffers.bufferScreenshotNotice(
                ScreenshotNotice(
                    conversationId = n.contactId,
                    isGroup = false,
                    senderContactId = n.contactId,
                    senderAlias = alias,
                    timestamp = stored?.takenAt
                        ?: ScreenshotNoticeStore.clampTakenAt(n.claimedTakenAt, receivedAt),
                    receivedAt = receivedAt,
                    expiresAt = receivedAt + SCREENSHOT_NOTICE_TTL_MS,
                )
            )
        }
    }

    /**
     * THE LOAD-ON-OPEN SURFACE, and the non-destructive twin of
     * [drainScreenshotNotices]: every UNEXPIRED persisted notice for one
     * conversation, oldest first. [conversationId] is a contactId for a 1:1 and a
     * groupId for a group.
     *
     * Repeatable — it returns the same rows until they expire — so a UI calls it
     * ONCE when the conversation opens and then appends new arrivals through the
     * existing drain on each poll tick. Never call it per tick: it scans and parses
     * the `ssn:` namespace.
     *
     * Aliases are resolved here from the vault (never persisted), and a BLOCKED
     * sender's notices are filtered out, so the block set silences this surface too.
     * A group notice from a since-deleted contact renders with the localized member fallback (mirroring
     * [handleScreenshotNotice]); a 1:1 notice with no contact row is dropped, since
     * there is no conversation left to render it in.
     *
     * Touches the vault — background dispatcher only, like the polls. Never throws.
     */
    fun screenshotNotices(conversationId: String): List<ScreenshotNotice> {
        val stored = try {
            screenshotStore.list(conversationId)
        } catch (e: Exception) {
            platformLogWarn(TAG, "screenshot notice load failed: ${e::class.simpleName}")
            return emptyList()
        }
        if (stored.isEmpty()) return emptyList()
        val blocked = blockedContactsSafe()
        return stored.mapNotNull { s ->
            if (s.senderContactId in blocked) return@mapNotNull null
            val alias = vault.getContact(s.senderContactId)?.alias
                ?: if (s.isGroup) platformString(NOTICE_MEMBER_FALLBACK_KEY) else return@mapNotNull null
            ScreenshotNotice(
                conversationId = s.conversationId,
                isGroup = s.isGroup,
                senderContactId = s.senderContactId,
                senderAlias = alias,
                timestamp = s.takenAt,
                receivedAt = s.receivedAt,
                expiresAt = s.expiresAt,
            )
        }
    }

    /**
     * Drops every expired (or undecodable) persisted screenshot notice, across all
     * conversations. There is NO dedicated timer: this rides the background control
     * sweep (wired in `createSessionManagers`), whose first pass runs seconds after
     * unlock, and [screenshotStore] additionally prunes the touched conversation on
     * every write and every load. Never throws.
     */
    fun pruneExpiredScreenshotNotices() {
        try {
            screenshotStore.pruneExpired()
        } catch (e: Exception) {
            platformLogWarn(TAG, "screenshot notice prune failed: ${e::class.simpleName}")
        }
    }

    // Deletes every `grp_inv_rl:<contactId>` row whose stamps are ALL outside the
    // invite rate window. Such a row admits exactly like an absent one (the window
    // discards every stamp in it), so deleting it changes no admission; it only
    // stops the time a contact last sent an invite from staying on disk after the
    // window. A row with a live stamp is left byte-for-byte as it is. Rides the
    // control sweep (wired in `createSessionManagers`); never throws.
    //
    // The delete is made under [pendingInviteLock] (the lock [inviteAllowed] runs
    // under) and only if the row still holds the value that was judged stale, so a
    // stamp an invite charged meanwhile is never dropped. The scan itself runs
    // outside the lock: the main-thread poll takes it every 4 s.
    fun pruneStaleInviteRateWindows() {
        try {
            val now = clockMs()
            for (key in vault.metaKeys()) {
                if (!key.startsWith(INVITE_RL_META_PREFIX)) continue
                val seen = vault.getMeta(key) ?: continue
                if (!RollingWindow.isSpent(seen, now, INVITE_RATE_WINDOW_MS)) continue
                pendingInviteLock.withLock {
                    if (vault.getMeta(key) == seen) vault.deleteMeta(key)
                }
            }
        } catch (e: Exception) {
            platformLogWarn(TAG, "invite rate-window prune failed: ${e::class.simpleName}")
        }
    }

    /**
     * THE PER-TICK SURFACE for the UI leg. Returns (and clears) the screenshot
     * notices BUFFERED for one conversation — [conversationId] is a contactId for a
     * 1:1 and a groupId for a group.
     *
     * Destructive with respect to the RAM buffer only, and that is unchanged: the
     * caller renders each notice once as it arrives. The notices it returns have
     * ALSO been persisted by [collectDirectScreenshotNotices] /
     * [handleScreenshotNotice], so re-opening the conversation still shows them —
     * [screenshotNotices] is the non-destructive load-on-open surface.
     *
     * Cheap on a poll tick (one lock; collecting from the transport is a no-op
     * when nothing arrived) but it may touch the VAULT to resolve an alias and to
     * persist a freshly arrived notice, so call it from the same background context
     * as the polls — never the main thread.
     */
    fun drainScreenshotNotices(conversationId: String): List<ScreenshotNotice> {
        collectDirectScreenshotNotices()
        return buffers.drainScreenshotNotices(conversationId)
    }

    /** THE TAKE for a 1:1 screen: its own 1:1 texts and GROUP_ECHO items, in
     *  arrival order. RAM-only, non-suspending. */
    fun takeDirectScreenItems(contactId: String): List<DirectItem> = buffers.takeDirectScreenItems(contactId)

    /**
     * A drain that failed because the vault CLOSED under it is session teardown,
     * not a fault. Android's `lockSession` cancels the poll jobs but a blocking relay
     * or SQL call already in flight finishes against the closed handle. Quiet
     * then; a failure with the vault still open stays a warning.
     */
    private fun drainFailed(what: String, e: Exception) {
        if (vault.isOpen) platformLogWarn(TAG, "$what failed: ${e::class.simpleName}")
        else platformLog(TAG, "$what skipped — vault closed (session teardown)")
    }

    /**
     * Scrub every in-memory buffer that can hold
     * decrypted group CONTENT (message text in the [ConversationBuffers]; group
     * names + inviter aliases + memberIds in [pendingInvites]) or social-graph ids
     * ([GroupUnreadTally]/[departureAnnounced]/[UnconvergedMembers]). The platform layer
     * "clears" this state by nulling its GroupManager reference on lock AND on panic
     * wipe, but nulling a reference only makes the old instance GC-eligible — it does NOT
     * zero the still-resident maps while the process is deliberately kept alive on the
     * deniability screen, so a live/AFU RAM image recovers the plaintext. Emptying the
     * collections drops every reference to that plaintext (String contents are immutable
     * and cannot be overwritten in place). Idempotent; each lock is taken
     * SEQUENTIALLY, never nested (SyncLock is non-reentrant on iOS).
     *
     * WHO MUST CALL THIS: the platform teardown sites, immediately BEFORE `groupManager
     * = null` — Android `RunViewModel.performEmergencyWipe()` + `onCleared()`, iOS
     * `IosAppController.lock()` + `emergencyWipe()`.
     */
    fun scrubInMemory() {
        // Message text, the unresolved-sender buffer and the RAM screenshot notices
        // (aliases + contactIds); the DURABLE `ssn:` rows are untouched — see
        // [ConversationBuffers.scrub].
        buffers.scrub()
        // All five unread tallies (contactIds/groupIds + counts). The vault mirror of
        // the `gi` attribution is deliberately untouched (it exists to survive this);
        // only its RAM index (contactIds/groupIds) goes.
        tally.scrub()
        unreadMarkers.scrub()
        departureLock.withLock { departureAnnounced.clear() }
        // (groupId, contactId) pairs — social-graph state in the same class as
        // [departureAnnounced], so it goes in the same scrub. Losing it costs one
        // convergence signal: the member's next message re-marks it.
        unconverged.scrub()
        // Fast-window re-anchor: groupIds only (no alias, no contactId), but it is
        // session-scoped RAM in the same class as the maps above and a fresh session
        // must start from the persisted `addedAt` alone — so it goes in the same scrub.
        fastAnchor.scrub()
        // The armed backfill set is contactIds — social-graph state in the same class
        // as the maps above. The DURABLE throttle is untouched (it is a spent-budget
        // record, not a cache), so a fresh session re-arms and the bound still holds.
        backfill.scrub()
        // Not sensitive (one boolean) — cleared so a nudge latched by a pre-drain that
        // ran just before the session ended cannot fire a spurious UI re-query on the
        // next one. [controlSweepInFlight] is deliberately NOT cleared, for the same
        // reason [primeInFlight] is not: clearing it under a live sweep would re-admit
        // the second concurrent drain it exists to stop.
        controlNudgeLock.withLock { pendingControlNudge = false }
        // The decline tombstone is cleared from RAM here like every other buffer;
        // its DURABLE copy in DECLINED_INVITE_META is deliberately UNTOUCHED (this
        // runs on ordinary lock/background) and reloads on the next construction, so
        // an offer the user declined stays declined across a foreground return. A
        // wipe crypto-erases the whole vault, taking the persisted copy with it.
        //
        // [pendingInvites] is cleared for the same RAM-hygiene reason (group name,
        // inviter alias, memberIds) and its durable mirror ([inviteStore]) is left
        // alone for the same reason as the tombstone: this runs on ordinary
        // lock/background, and deleting the rows here would reinstate exactly the
        // "backgrounded before tapping Join ⇒ invite lost forever" bug the mirror
        // exists to close. The next construction rehydrates it.
        pendingInviteLock.withLock { pendingInvites.clear(); declinedInvites.clear() }
        // Fourth FAST-cadence condition: screen keys carry groupIds (social-graph
        // state, same class as the maps above) and a locked session has no screen.
        clearGroupConversationForeground()
    }

    private fun clearGroupConversationForeground() {
        groupConversationForegroundLock.withLock {
            groupConversationForegroundKeys.clear()
            groupConversationForeground = false
        }
    }

    // -----------------------------------------------------------------------
    // Polling entry points — one per screen type. Both route every drained
    // message: 1:1 text out/buffered, group text out/buffered, control
    // applied. Blocking I/O — call from a background dispatcher.
    // -----------------------------------------------------------------------

    /**
     * GRP-DRAIN-1 — **a conversation poll drains BOTH of that contact's
     * TEXT-CARRYING inboxes, text first and group second, always in that order.**
     *
     * Splitting texts across two inboxes makes out-of-order ratchet delivery
     * NORMAL rather than exceptional: both channels ride the ONE
     * `dr/{contactId}/text` chain (there is deliberately no second ratchet), so
     * draining higher-numbered group messages while lower-numbered 1:1 messages sit
     * undrained generates skipped message keys — and skipped keys are key material
     * at rest, which is exactly what skipped-key expiry exists to shrink. Draining both together
     * collapses the skipping window to "whatever arrived between the two GETs".
     *
     * The ORDER is pinned, not incidental. TEXT first because:
     *  - it is the channel whose messages this poll may have to RETURN in order
     *    (a 1:1 conversation is open, or a group's own texts from a legacy peer);
     *  - it is the channel a legacy peer uses for everything, so a mixed-vintage
     *    pairing drains oldest-route-first;
     *  - and a fixed order is what makes the ratchet's skipped-key window
     *    reproducible in a test instead of dependent on map iteration.
     *
     * The group drain is skipped entirely — no vault read past the predicate, no
     * request — when we share no group with [contactId], so a 1:1-only
     * conversation costs exactly what it always did.
     */
    private fun drainBothTextInboxes(
        mgr: MessageManager,
        contactId: String,
        wantGroupId: String?,
        bufferAll: Boolean = false,
        // Whether we share a group with [contactId]. Passed IN, never re-derived:
        // [pollGroup] already knows the answer is true for every member of the
        // group it is draining, and re-enumerating `getAllGroups × getGroupMembers`
        // once per member would make a k-member group's poll O(k · groups · members)
        // of vault work for a fact the caller already holds.
        sharesGroup: Boolean,
    ): IngestResult {
        // Retrieve-ack: both drains' acks go out as ONE POST, after what they returned
        // has been routed (persist mode — the screens' uncommitted twin is
        // [pollDirectPending]).
        val acks = MessageManager.AckBatch()
        try {
            val text = try {
                mgr.pollChannelAcking(contactId, MessageManager.Chan.MAIN, acks)
            } catch (e: Exception) {
                drainFailed("text drain", e)
                emptyList()
            }
            val first = ingest(contactId, text, wantGroupId, bufferAll)
            if (!sharesGroup) return first
            val group = try {
                mgr.pollChannelAcking(contactId, MessageManager.Chan.GRP, acks)
            } catch (e: Exception) {
                drainFailed("group-inbox drain", e)
                emptyList()
            }
            val second = afterGroupInboxDrain(contactId, group, wantGroupId, bufferAll)
            return IngestResult(first.direct + second.direct, first.group + second.group)
        } finally {
            mgr.flushAcks(acks)
        }
    }

    /** The group-inbox half of [drainBothTextInboxes], shared with the concurrent
     *  group-poll fan-out: reset the tallies the drain made authoritative, then
     *  route what it returned. */
    private fun afterGroupInboxDrain(
        contactId: String,
        group: List<ReceivedMessage>,
        wantGroupId: String?,
        bufferAll: Boolean,
    ): IngestResult {
        // THE DRAIN IS AUTHORITATIVE for both group-inbox tallies — see
        // [GroupUnreadTally.groupInboxDrained] — and for their vault mirror.
        tally.groupInboxDrained(contactId)
        unreadMarkers.clear(contactId)
        if (group.isEmpty()) return IngestResult(emptyList(), emptyList())
        return ingest(contactId, group, wantGroupId, bufferAll, fromGroupInbox = true)
    }

    /**
     * THE single source of "which contacts can carry group text" — the peek
     * filter, the GRP-DRAIN-1 gate, the backfill's eligibility set AND (through
     * [groupMemberControlTargets]) the connect-time prime's control/group ref set.
     *
     * One enumeration of `getAllGroups × getGroupMembers`; every caller derives
     * from it rather than re-deriving the predicate, so the sweep, the prime and
     * the drain can never disagree about which pairings have a group inbox worth a
     * round trip. Cheap local reads; a vault hiccup answers EMPTY, which costs one
     * deferred group peek/drain and never a wrong contact dot.
     */
    private fun groupSharingContactIds(blocked: Set<String> = emptySet()): Set<String> = try {
        val out = mutableSetOf<String>()
        for (g in vault.getAllGroups()) {
            for (m in vault.getGroupMembers(g.groupId)) {
                val cid = m.contactId ?: continue
                if (cid in blocked) continue   // never poll a blocked inbox
                out.add(cid)
            }
        }
        out
    } catch (e: Exception) {
        platformLogWarn(TAG, "group-sharing enumeration failed: ${e::class.simpleName}")
        emptySet()
    }

    // -----------------------------------------------------------------------
    // POLL-HANDOFF-1: a conversation poll PARKS what it drains; the
    // screen TAKES it in a separate, synchronous step.
    //
    // A conversation poll (before the leasing relay: a DESTRUCTIVE relay drain) also
    // steps the ratchet, so once it has run, the RAM copy it produced is the ONLY copy of each message.
    // It is not handed back as the poll's RETURN VALUE because both platforms run
    // the poll as a blocking call off the UI, awaited by a cancellable consumer
    // (Android: `async(Dispatchers.IO)` inside the screen's `LaunchedEffect`; iOS: a
    // detached task awaited by the view's poll task through `awaitDrain`). A
    // blocking HTTP read does not stop on cancellation, so a consumer that goes away
    // mid-poll would leave the drain to complete, consume the blobs, and return its
    // messages to nobody — permanent, silent loss. It needs only a slow circuit plus
    // ordinary navigation (on Android opening Group Info is a separate NavHost
    // destination, which disposes the conversation's composition).
    //
    // So the hand-off has NO window: [pollGroupIntoBuffer] /
    // [pollDirectIntoBuffer] leave EVERYTHING they drain in the polling SCREEN's RAM
    // buffer ([ConversationBuffers], capacity-bounded, scrubbed with the
    // session), and the screen collects with [takeGroupScreenItems] /
    // [takeDirectScreenItems] — RAM-only,
    // non-suspending, issued on the UI thread with nothing cancellable between that
    // take and the append to the visible list. A consumer that is gone simply never
    // takes; the messages stay parked and surface on the next poll of that
    // conversation (and a group's OWN items light its dot meanwhile — see
    // [groupUnreadCounts]). [pollGroup] / [pollDirect] keep their list-returning contract
    // as `IntoBuffer + drain`, in the same order (parked first, then fresh).
    //
    // What it does NOT change: the relay traffic (same GETs, same order), the
    // ratchet/anti-replay handling, the routing of OTHER conversations' traffic, and
    // the screen-buffer ceilings — a single poll that drained more than
    // [MAX_PENDING_CONTENT_PER_KEY] messages for ONE conversation evicts its
    // oldest beyond that. 256 is far above any honest backlog of an OPEN
    // conversation (it polls every few seconds), and an unbounded return value would
    // itself be the unbounded-buffer shape.
    // -----------------------------------------------------------------------

    /** Poll for a 1:1 conversation: returns this screen's items (untaken + fresh)
     *  — the contact's 1:1 texts and GROUP_ECHO items for any group text drained
     *  alongside. A UI consumer that can be cancelled mid-poll must use
     *  [pollDirectIntoBuffer] + [takeDirectScreenItems] instead — see POLL-HANDOFF-1. */
    fun pollDirect(contactId: String): List<DirectItem> {
        pollDirectIntoBuffer(contactId)
        return takeDirectScreenItems(contactId)
    }

    /** POLL-HANDOFF-1: [pollDirect]'s drain, with every item it produces left in
     *  this 1:1 screen's buffer for the caller to take with [takeDirectScreenItems].
     *  Blocking I/O — background dispatcher only. */
    fun pollDirectIntoBuffer(contactId: String) {
        // Polling a 1:1 means its conversation is OPEN, so its persisted notices are
        // seen and their unseen term leaves the contact dot. Deliberately ahead of
        // the transport check: the user is looking at the conversation whether or not
        // Tor is up, and marking seen only clears a dot — it never drops a notice.
        // Cheap in the steady state (one key scan, zero writes once all are seen).
        screenshotStore.markSeen(contactId)
        val mgr = transport("pollDirect") ?: return
        // GRP-DRAIN-1: the 1:1 conversation drains this contact's TEXT inbox and —
        // only when we share a group with them — their GROUP inbox too, so the one
        // ratchet chain sees both channels in one pass. NO-PARK: a group text drained
        // either way becomes a GROUP_ECHO item of THIS screen. ONE enumeration for the
        // predicate, on the shared source of truth.
        // POLL-HANDOFF-1: `bufferAll` hands everything to this screen's buffer.
        drainBothTextInboxes(
            mgr, contactId, wantGroupId = null, bufferAll = true,
            sharesGroup = contactId in groupSharingContactIds(),
        )
        // Any 1:1 screenshot notice this drain applied at the transport is now
        // buffered for its conversation (see collectDirectScreenshotNotices).
        collectDirectScreenshotNotices()
        // The 1:1 just drained this contact's inbox completely (everything handed to
        // this screen) — nothing of theirs is left on the
        // relay, so their group-pending tally is authoritatively zero.
        tally.textInboxDrained(contactId)
    }

    /** Poll for a group conversation: drains every resolved member's inbox
     *  and returns this screen's items (untaken + fresh): the group's texts,
     *  PRIVATE items for 1:1 texts and GROUP_ECHO items for other groups' texts
     *  drained alongside. Member order is shuffled per poll so the relay
     *  sees no stable polling sequence. A UI consumer that can be cancelled
     *  mid-poll must use [pollGroupIntoBuffer] + [takeGroupScreenItems] instead —
     *  see POLL-HANDOFF-1. */
    fun pollGroup(groupId: String): List<GroupMessage> {
        pollGroupIntoBuffer(groupId)
        return takeGroupScreenItems(groupId)
    }

    /** POLL-HANDOFF-1: [pollGroup]'s drain, with every item it produces left in
     *  this group screen's buffer for the caller to take with
     *  [takeGroupScreenItems]. Each member's messages are handed over as soon as that
     *  member's drain returns, so a later member's failure cannot take an earlier
     *  member's already-burned messages down with it. Blocking I/O — background
     *  dispatcher only. */
    fun pollGroupIntoBuffer(groupId: String) {
        // Same rule as pollDirect, and ahead of the transport check for the same
        // reason: polling the group means its conversation is open.
        screenshotStore.markSeen(groupId)
        // …and the vault mirror of its unread dot follows [markGroupRead]: the
        // persisted units stop lighting this group but keep accounting for their
        // blobs (a later session must not presence-bump for them). Here, on the
        // background poll, not in [markGroupRead] itself — that one is called from
        // the main thread on both platforms and stays RAM-only.
        unreadMarkers.detachGroup(groupId)
        // Unresolved-sender buffer: re-attribute any group texts that were buffered while their sender was
        // unresolved — resolution may have converged since. Delivered ones land in
        // their group's screen buffer, where the caller takes them.
        buffers.flushResolvedGroupTexts()
        val mgr = transport("pollGroup") ?: return
        // Skip blocked co-members — don't poll their inbox and don't
        // surface their group traffic (the ingest guard below is the backstop).
        val blocked = blockedContactsSafe()
        val members = vault.getGroupMembers(groupId)
            .filter { it.contactId != null && it.contactId !in blocked }
            .secureShuffled()
        // GRP-DRAIN-1: each member's TEXT inbox then their GROUP inbox — the group
        // conversation is where an upgraded member's texts actually live now, and the
        // text inbox is still where a legacy member's do, so both are drained and both
        // route through the same attribution. (Every member here is RESOLVED, so
        // "shares a group" is true by construction — no re-enumeration.)
        //
        // GROUP-FANOUT, three stages so only the network is concurrent:
        //  1. SERIAL prepare — the freeze gate, ratchet activation and read-cap
        //     reconcile [MessageManager.prepareDrain] does before its GET;
        //  2. CONCURRENT fetch — the GETs alone, ≤ [GROUP_POLL_FETCH_CONCURRENCY] in
        //     flight, results kept in member order; one failing GET is that inbox's
        //     null, never the others';
        //  3. SERIAL finish + ingest, in the (shuffled) member order, text before
        //     group — decrypt, ratchet step, counter persist and every buffer write
        //     happen exactly as the sequential loop did them, one member at a time.
        // Stage 2 is BLOCKING ([runBlockingIo], like the control sweep's peek
        // fan-out) so this function keeps its blocking signature on both platforms,
        // and — deliberately — a cancelled caller can never skip stage 3 for a blob
        // a completed GET already burned off the relay (POLL-HANDOFF-1).
        //
        // POLL-HANDOFF-1: `bufferAll` hands everything this drain produced to THIS
        // screen's buffer (in drain order, after anything untaken) instead of
        // returning it through a value a cancelled consumer would drop.
        val (drains, resultOf) = prepareAndFetchMemberDrains(mgr, members)
        // Retrieve-ack: one batch for every member inbox this poll drained, sent
        // after the whole fan-out has been routed into the screen buffer.
        val acks = MessageManager.AckBatch()
        try {
            for (d in drains) {
                val text = d.text?.let { p ->
                    try { mgr.finishDrain(p, resultOf[p], acks) } catch (e: Exception) {
                        drainFailed("text drain", e); emptyList()
                    }
                } ?: emptyList()
                ingest(d.contactId, text, wantGroupId = groupId, bufferAll = true)
                val group = d.group?.let { p ->
                    try { mgr.finishDrain(p, resultOf[p], acks) } catch (e: Exception) {
                        drainFailed("group-inbox drain", e); emptyList()
                    }
                } ?: emptyList()
                afterGroupInboxDrain(d.contactId, group, wantGroupId = groupId, bufferAll = true)
            }
        } finally {
            mgr.flushAcks(acks)
        }
        // Members' TEXT inboxes can also carry a 1:1 screenshot notice (a pre-v7
        // peer has no control inbox) — those stay on their own durable path.
        collectDirectScreenshotNotices()
        // Opening (polling) the group clears its unread dot. Its OWN items still
        // untaken keep the dot lit through groupUnreadCounts' buffered term until a
        // consumer takes them (PRIVATE / GROUP_ECHO items never count).
        markGroupRead(groupId)
    }

    /** One member's two text-bearing inbox drains of a group poll (stage 1 output). */
    private class MemberDrain(
        val contactId: String,
        val text: MessageManager.PreparedDrain?,
        val group: MessageManager.PreparedDrain?,
    )

    /** GROUP-FANOUT stages 1 + 2 (see [pollGroupIntoBuffer]): SERIAL prepare, then the
     *  GETs alone CONCURRENTLY. Shared by the persist and the pending group poll. */
    private fun prepareAndFetchMemberDrains(
        mgr: MessageManager,
        members: List<GroupMemberRecord>,
    ): Pair<List<MemberDrain>, Map<MessageManager.PreparedDrain, HttpResult?>> {
        val drains = members.mapNotNull { m ->
            val contactId = m.contactId ?: return@mapNotNull null
            MemberDrain(
                contactId,
                text = try { mgr.prepareTextDrain(contactId) } catch (e: Exception) {
                    platformLogWarn(TAG, "text drain prepare failed: ${e::class.simpleName}"); null
                },
                group = try { mgr.prepareGroupInboxDrain(contactId) } catch (e: Exception) {
                    platformLogWarn(TAG, "group-inbox drain prepare failed: ${e::class.simpleName}"); null
                },
            )
        }
        val gets = drains.flatMap { listOfNotNull(it.text, it.group) }
        val fetched = boundedParallelBlocking(gets, GROUP_POLL_FETCH_CONCURRENCY) { mgr.fetchDrain(it) }
        val resultOf = HashMap<MessageManager.PreparedDrain, HttpResult?>()
        gets.forEachIndexed { i, p -> resultOf[p] = fetched[i] }
        return drains to resultOf
    }

    // -----------------------------------------------------------------------
    // Retrieve-ack: the conversation screens' UNCOMMITTED polls.
    //
    // POLL-HANDOFF-1 above exists because a destructive drain made the RAM copy the
    // only copy. With the leasing relay a drain is not destructive: these polls decrypt
    // WITHOUT persisting the ratchet / anti-replay state and return a
    // [PendingDrain] — the screen shows its messages and THEN commits (persist +
    // ack). A screen that goes away before commit loses nothing: nothing was
    // persisted or acked, the relay re-delivers after its lease, the blobs decrypt
    // again. The items are RETURNED (never parked in the screen buffer). Items an
    // earlier path already parked in the screen's buffer (unresolved-sender buffer deliveries, a
    // background-routed text, system notices) are returned first and removed from
    // the buffer only on commit. Controls a pending drain surfaces (a legacy peer's
    // group control on its text inbox) are applied at once, exactly as before —
    // a re-delivery re-applies them, and every handler is idempotent on its state.
    // -----------------------------------------------------------------------

    /**
     * The 1:1 screen's poll ([pollDirectIntoBuffer]'s drain), uncommitted: this
     * contact's TEXT inbox and — when we share a group — its GROUP inbox
     * (GRP-DRAIN-1), one drain group, so the group drain builds on the text drain's
     * uncommitted ratchet advance. Blocking I/O — background dispatcher only.
     */
    fun pollDirectPending(contactId: String): PendingDrain<DirectItem> {
        screenshotStore.markSeen(contactId)
        val mgr = transport("pollDirect") ?: return buffers.parkedDirectOnly(contactId, null)
        val drainGroup = Any()
        val parts = mutableListOf<MessageManager.PendingPart>()
        val items = mutableListOf<DirectItem>()
        val text = try { mgr.pollChannelPendingOutcome(contactId, MessageManager.Chan.MAIN, drainGroup) } catch (e: Exception) {
            drainFailed("text drain", e); MessageManager.DrainOutcome.EMPTY
        }
        text.part?.let { parts.add(it) }
        items += ingest(contactId, text.messages, wantGroupId = null, bufferAll = false).direct
        if (contactId in groupSharingContactIds()) {
            val group = try { mgr.pollChannelPendingOutcome(contactId, MessageManager.Chan.GRP, drainGroup) } catch (e: Exception) {
                drainFailed("group-inbox drain", e); MessageManager.DrainOutcome.EMPTY
            }
            group.part?.let { parts.add(it) }
            items += afterGroupInboxDrain(contactId, group.messages, wantGroupId = null, bufferAll = false).direct
        }
        collectDirectScreenshotNotices()
        tally.textInboxDrained(contactId)
        return buffers.parkedDirectOnly(contactId, mgr, items, parts)
    }

    /**
     * The group screen's poll ([pollGroupIntoBuffer]'s fan-out), uncommitted: every
     * resolved member's TEXT then GROUP inbox (GETs concurrent, everything else
     * serial and in member order), one drain group for the whole poll, ONE ack batch
     * on commit. Blocking I/O — background dispatcher only.
     */
    fun pollGroupPending(groupId: String): PendingDrain<GroupMessage> {
        screenshotStore.markSeen(groupId)
        unreadMarkers.detachGroup(groupId)   // see pollGroupIntoBuffer
        buffers.flushResolvedGroupTexts()
        val mgr = transport("pollGroup") ?: return buffers.parkedGroupOnly(groupId, null)
        val blocked = blockedContactsSafe()
        val members = vault.getGroupMembers(groupId)
            .filter { it.contactId != null && it.contactId !in blocked }
            .secureShuffled()
        val (drains, resultOf) = prepareAndFetchMemberDrains(mgr, members)
        val drainGroup = Any()
        val parts = mutableListOf<MessageManager.PendingPart>()
        val items = mutableListOf<GroupMessage>()
        for (d in drains) {
            val text = d.text?.let { p ->
                try { mgr.finishDrainPending(p, resultOf[p], drainGroup) } catch (e: Exception) {
                    drainFailed("text drain", e); null
                }
            } ?: MessageManager.DrainOutcome.EMPTY
            text.part?.let { parts.add(it) }
            items += ingest(d.contactId, text.messages, wantGroupId = groupId, bufferAll = false).group
            val group = d.group?.let { p ->
                try { mgr.finishDrainPending(p, resultOf[p], drainGroup) } catch (e: Exception) {
                    drainFailed("group-inbox drain", e); null
                }
            } ?: MessageManager.DrainOutcome.EMPTY
            group.part?.let { parts.add(it) }
            items += afterGroupInboxDrain(d.contactId, group.messages, wantGroupId = groupId, bufferAll = false).group
        }
        collectDirectScreenshotNotices()
        markGroupRead(groupId)
        return buffers.parkedGroupOnly(groupId, mgr, items, parts)
    }

    /**
     * Drains every contact's CONTROL inbox and applies what arrives — group
     * invites/rosters/joins/leaves and inbox announces. This is the delivery
     * path that makes a group appear on EVERY member's device without anyone
     * opening a particular conversation: the platform layer runs it on a
     * jittered background loop while the vault is unlocked. Control inboxes
     * are safe to drain any time (no relay-retention requirement, unlike
     * texts); anything non-control that a peer misroutes here is buffered
     * for its own conversation, never dropped. Blocking — background
     * dispatcher only.
     */
    /**
     * The drain is PEEK-FIRST — see the rationale at the loop below. Delivery
     * semantics are unchanged: only a peek that positively answered "0 queued"
     * skips a drain, and every uncertain answer still drains.
     *
     * @return true when at least one control batch was drained this sweep.
     * The platform layer uses this to nudge vault-observing UIs (e.g. the
     * contact list) to re-query — an applied invite must surface a group row
     * WITHOUT navigation, which is the whole point of the control channel.
     */
    fun pollAllControls(): Boolean {
        val mgr = transport("control sweep") ?: return false
        if (!vault.isOpen) return false  // session teardown already closed the vault — nothing to sweep into
        // Consume the pre-drain's latch FIRST, and report it even on the skip path
        // below: it describes control traffic that has ALREADY been applied to the
        // vault, so the UI nudge it stands for is owed either way.
        val latchedNudge = controlNudgeLock.withLock {
            val v = pendingControlNudge
            pendingControlNudge = false
            v
        }
        if (!beginControlSweep("control sweep")) return latchedNudge
        // Pass timer for the closing panel line below.
        val startedAtMs = clockMs()
        try {
            // Referral housekeeping rides this sweep (TTL GC + the bounded accept /
            // relay redrives). Never fatal to the sweep. Deliberately NOT run by the
            // prime's pre-drain: it is this loop's housekeeping cadence, and firing its
            // redrives inside the connect burst would only add traffic there.
            try { onControlSweep?.invoke() } catch (e: Exception) {
                platformLogWarn(TAG, "control-sweep hook failed: ${e::class.simpleName}")
            }
            // Never poll a blocked contact's control inbox — mirrors the
            // text peek's `it.contactId !in blockedContactIds`. Skipping the fetch both
            // stops the invite/offer/announce from ever being ingested AND severs the
            // ongoing polling relationship the block is supposed to end.
            val blocked = blockedContactsSafe()
            val contacts = vault.getAllContacts()
                .filter { it.contactId !in blocked }
                .secureShuffled().toMutableList()
            // The Add-contact scan-back screen is waiting on ONE contact's in-band
            // announce (a full sweep over a dozen contacts takes ~20 s; the scan-back
            // screen should not wait on it). Peek it first; the
            // rest keeps the shuffled order. Only while that screen is showing.
            mgr.pairingAwaitingContactId()?.let { cid -> contacts.moveToFront { it.contactId == cid } }
            val nudge = drainControlInboxes(mgr, contacts, allowConcurrency = true) || latchedNudge
            // The group-inbox backfill rides THIS sweep (never connect time —
            // PoW on a cold circuit is the concurrent-mint lesson). Armed by membership
            // events and once per session; bounded to one mint per sweep and, per
            // contact, by a durable 24 h / 4-attempt throttle inside MessageManager.
            backfill.armOnceForSession()
            backfill.runDue(mgr)
            // Connection-log panel: ONE line per PASS, at the end — never one per
            // contact. This sweep drains N control inboxes sequentially over the same
            // (at connect time, cold) circuit the health probe is trying to use; without
            // this line a whole sweep is invisible in the panel, which at connect time is
            // tens of seconds before the first probe line. COUNTS AND SECONDS ONLY — never a
            // contact id, an inbox id or an alias.
            ConnectionLog.append(
                ConnectionLog.Kind.RELAY,
                "control poll done: ${contacts.size} contacts in ${formatSeconds(clockMs() - startedAtMs)} s",
                ConnectionLog.Code.CONTROL_POLL_PASS,
            )
            return nudge
        } finally {
            endControlSweep()
        }
    }

    /**
     * Admits ONE control sweep at a time; see [controlSweepInFlight] for why the loser
     * skips instead of waiting. Returns true when the caller now HOLDS the sweep and
     * must therefore call [endControlSweep] in a `finally`.
     */
    private fun beginControlSweep(where: String): Boolean {
        val admitted = controlSweepLock.withLock {
            if (controlSweepInFlight) false else { controlSweepInFlight = true; true }
        }
        if (!admitted) platformLogWarn(TAG, "$where skipped — a control sweep is already in flight")
        return admitted
    }

    private fun endControlSweep() = controlSweepLock.withLock { controlSweepInFlight = false }

    // -----------------------------------------------------------------------
    // Arming the GROUP-INBOX BACKFILL: see [GroupInboxBackfillArming]. The entry
    // points below keep their names (membership-event hooks and tests call them).
    // -----------------------------------------------------------------------

    private val backfill = GroupInboxBackfillArming(
        primeInFlight = { primeLock.withLock { primeInFlight } },
        groupSharingContacts = { blocked -> groupSharingContactIds(blocked) },
        blocked = { blockedContactsSafe() },
        pendingInviters = { pendingInvites().map { it.inviterContactId } },
        groupMemberContacts = { groupId -> vault.getGroupMembers(groupId).map { it.contactId } },
    )

    /** See [GroupInboxBackfillArming.arm]. Arms the LAZY sweep AND kicks the EAGER
     *  establishment (fail-soft) so a membership event converges the pair's group
     *  inbox ahead of the first send. */
    internal fun armGroupInboxBackfill(contactId: String) {
        backfill.arm(contactId)
        eagerlyEstablishGroupInboxes(listOf(contactId))
    }

    /** See [GroupInboxBackfillArming.armForGroup]. Arms the LAZY sweep for every
     *  resolved member AND kicks the EAGER establishment for them (fail-soft). */
    internal fun armGroupInboxBackfillForGroup(groupId: String) {
        backfill.armForGroup(groupId)
        eagerlyEstablishGroupInboxes(
            try { vault.getGroupMembers(groupId).map { it.contactId } } catch (_: Exception) { emptyList() }
        )
    }

    /**
     * Runs [eagerlyEstablishGroupInboxes]'s blocking mint+announce OFF the critical
     * path. Wired ONCE per session by the platform (RunViewModel / AppState) to a
     * background-coroutine launcher; the DEFAULT is a NO-OP, which means two things,
     * both deliberate:
     *  - eager establishment is FAIL-SOFT off by default — an unwired build simply
     *    keeps today's lazy control-sweep backfill (no behaviour lost, only the
     *    durability optimisation);
     *  - the JVM unit suite's [InMemoryVault] is NOT thread-safe, so the default
     *    no-op guarantees no test ever touches a vault from a background thread it
     *    did not start. The eager tests install a synchronous launcher explicitly.
     * Same long-lived-object placement as [blockedContacts] / [onControlSweep], so
     * it survives MessageManager recreation on a Tor reconnect.
     */
    var groupBackfillLauncher: (() -> Unit) -> Unit = { }

    /**
     * EAGER per-pair group-inbox establishment (durability half of the group
     * unread-dot fix): at a MEMBERSHIP EVENT, run [MessageManager.eagerBackfillGroupInboxes]
     * via [groupBackfillLauncher] so the pair's group inbox converges PROMPTLY and
     * ahead of the first group message — which then rides the GROUP inbox (GRP
     * route) and gets the peek-depth presence-bump backstop that re-derives on every
     * session (durable, nothing persisted). Deliberately NOT wired into
     * [GroupInboxBackfillArming.armOnceForSession] (that connect-time arm must stay
     * lazy — no PoW on a cold circuit). FAIL-SOFT: unresolved / blocked contacts are
     * filtered out, a null transport is a no-op, the eager pass itself refuses on a
     * cold circuit / freeze / teardown, and the LAZY sweep (armed above) remains the
     * backstop. The launcher runs it on a background coroutine, so it NEVER blocks or
     * delays create/join.
     */
    private fun eagerlyEstablishGroupInboxes(contactIds: List<String?>) {
        val resolved = contactIds.filterNotNull().filter { it.isNotEmpty() }.distinct()
        if (resolved.isEmpty()) return
        // Never during the connect-time unread prime: a PoW mint on that cold
        // circuit is the exact cost the lazy runDue gates out, and a membership
        // control applied by the prime's own pre-drain must not kick one. The
        // backfill is still armed, so the lazy sweep converges it once the prime
        // settles. (The eager pass itself also refuses before the first relay
        // round-trip — belt and braces.)
        if (primeLock.withLock { primeInFlight }) return
        val blocked = blockedContactsSafe()
        val targets = resolved.filter { it !in blocked }
        if (targets.isEmpty()) return
        val mgr = messageManager() ?: return
        try {
            groupBackfillLauncher { mgr.eagerBackfillGroupInboxes(targets) }
        } catch (e: Exception) {
            platformLogWarn(TAG, "eager group-inbox establishment failed to launch: ${e::class.simpleName}")
        }
    }

    /**
     * The per-contact control drain shared by the background sweep ([pollAllControls])
     * and the connect-time prime's pre-drain ([primeUnreadCounts]). Callers pass the
     * contact set they want covered (already blocked-filtered and shuffled) and MUST
     * hold the sweep ([beginControlSweep]). Returns true when at least one control
     * batch was drained — or a pending contact's inbox announce landed.
     *
     * [allowConcurrency] is the parallel-peek gate, and it is FALSE for the connect-time
     * pre-drain: that pass shares a COLD circuit with the health probe, and the
     * connect-time reveal (ConnectReveal) depends on it staying sequential (see the panel-line
     * comment in [pollAllControls]). The background sweep passes true and the
     * per-sweep decision is then [controlPeekConcurrency]'s.
     *
     * [prePeeked] is the BATCH-peek path: the connect-time prime has
     * already learned these contacts' control-inbox depths in its single
     * `POST /peek`, so it hands the answered map straight in and NO peek of any kind
     * is issued here. It feeds exactly the `peeked != null` branch the bounded peek
     * fan-out ([peekControlInboxesBounded]) already produces, so the delivery semantics are identical and
     * unchanged: **only a positively answered 0 may skip a drain**, and a contact
     * that is merely ABSENT from the map is UNKNOWN and drains.
     */
    private fun drainControlInboxes(
        mgr: MessageManager,
        contacts: List<ContactRecord>,
        allowConcurrency: Boolean = false,
        prePeeked: Map<String, Int>? = null,
    ): Boolean {
        // PEEK-FIRST. A control drain WAS destructive at the relay (it deleted what it
        // returned at request-handling time, so a response lost on a cold/wedged
        // circuit destroyed those invites/rosters/announces for good — since the
        // retrieve-ack lease it costs a re-delivery instead) and is expensive on
        // a cold circuit — and the overwhelmingly common case is an EMPTY control
        // inbox. One cheap non-destructive [MessageManager.peekControlPending] tells
        // us which case we are in.
        //
        // Skipped entirely while CONVERGING: a join→roster→resolve chain is in flight,
        // so traffic is expected and the probe would just add a round-trip per hop to
        // the exchange the fast window exists to accelerate. Decided ONCE per sweep so
        // every contact in a cycle is treated alike (and so the relay sees a uniform
        // request shape across the sweep). An unreadable answer falls back to TRUE =
        // drain unconditionally, i.e. exactly the pre-peek behaviour.
        val converging = try { mgr.isControlConverging() } catch (_: Exception) { true }
        val firstRelayAnswerSeen =
            try { mgr.hasCompletedRelayRoundTrip() } catch (_: Exception) { false }
        val concurrency = controlPeekConcurrency(
            contactCount = contacts.size,
            converging = converging,
            firstRelayAnswerSeen = firstRelayAnswerSeen && allowConcurrency,
        )
        // The whole PEEK phase up front, three in flight, when this is a
        // steady-state sweep. `null` = the phase did not run (or could not), and the
        // per-contact serial peek below is then used exactly as before — never a
        // silent "assume empty". [prePeeked] (the connect-time BATCH peek) short-
        // circuits it with an already-answered map of the same shape.
        // The presence bump's NOTICE GRACE: stamped BEFORE this sweep's first request,
        // so "this check started ≥ grace after the depth was seen" can only be
        // conservative ([GroupUnreadTally.controlInboxChecked]).
        val checkStartedAtMs = tally.controlSweepStartedAtMs()
        val peeked = prePeeked
            ?: if (concurrency > 1) peekControlInboxesBounded(mgr, contacts, concurrency) else null
        var anyReceived = false
        var drains = 0
        // Retrieve-ack: ONE `POST /ack` per sweep (≤ 64 inboxes per body), sent after
        // every drained control batch has been applied — persist, apply, then ack.
        val acks = MessageManager.AckBatch()
        try {
            for ((index, c) in contacts.withIndex()) {
                if (peeked != null) {
                    // ABSENT = UNKNOWN = DRAIN. `peeked` holds only the contacts whose
                    // peek POSITIVELY answered; a 404 / 429 / timeout / unreadable body,
                    // a contact with no control inbox and a snapshot that skipped the
                    // row are all simply missing from it.
                    // A contact whose DEFERRED sealed control is due (hold expired, or a
                    // retry requested by a text drain) drains anyway — the drain is what
                    // retries / ages out the deferral. A merely-held deferral does not.
                    if (peeked[c.contactId] == 0 && !hasDeferredSealedControl(mgr, c.contactId)) {
                        // A positive 0 is "the notice is not there". Not credited for a
                        // [prePeeked] map: that batch peek ran BEFORE [checkStartedAtMs].
                        if (prePeeked == null) tally.controlInboxChecked(c.contactId, checkStartedAtMs)
                        continue
                    }
                    // The peeks are done and were jittered inside the fan-out; only a
                    // DRAIN is still a request, so only a drain pays the inter-request
                    // sleep. Paying it per CONTACT here would spend 16 × 250 ms on
                    // contacts that are not going to make a request at all — which is a
                    // large share of what the parallel peek removes.
                    if (drains > 0) sleepMillis(100L + secureRandomInt(300).toLong())
                    drains++
                } else {
                    if (index > 0) sleepMillis(100L + secureRandomInt(300).toLong())
                    // UNKNOWN (null) DRAINS. Only a peek that positively answered "0 queued"
                    // may skip the drain; a 404 / 429 / timeout / unreadable body says nothing
                    // about what is waiting, and treating it as empty would starve control
                    // delivery behind a transient failure (the drain also still owns the
                    // relay-loss 404 bookkeeping).
                    if (!converging) {
                        val pending = try {
                            mgr.peekControlPending(c.contactId)
                        } catch (e: Exception) {
                            platformLogWarn(TAG, "control peek failed: ${e::class.simpleName}")
                            null
                        }
                        // Nothing queued → nothing to drain, and nothing can have changed
                        // this contact's awaiting state either (an announce arrives only
                        // through a drain), so the transition check below is moot as well.
                        if (pending == 0 && !hasDeferredSealedControl(mgr, c.contactId)) {
                            tally.controlInboxChecked(c.contactId, checkStartedAtMs)
                            continue
                        }
                    }
                }
                // An inbox announce is applied as a vault side-effect INSIDE the poll
                // and is never returned as a surfaced message, so the drain below can
                // look empty even though a pending contact just became ready. Snapshot
                // the awaiting state around the poll to catch that transition.
                val wasAwaiting = contactAwaitingPeerInbox(vault, c.contactId)
                val received = try {
                    mgr.pollChannelAcking(c.contactId, MessageManager.Chan.CTL, acks)
                } catch (e: Exception) {
                    platformLogWarn(TAG, "control poll failed: ${e::class.simpleName}")
                    continue
                }
                if (received.isNotEmpty()) {
                    anyReceived = true
                    ingest(c.contactId, received, wantGroupId = null, bufferAll = true, background = true)
                    // AFTER the ingest: a notice in this batch has already attributed (and
                    // reset the grace), so this only credits a check that came back
                    // without it. Only a NON-EMPTY drain counts — an empty list is also
                    // what a failed GET returns (pollChannel swallows it), and a failed
                    // fetch proves nothing about the notice.
                    tally.controlInboxChecked(c.contactId, checkStartedAtMs)
                }
                // Peer's inbox just landed (awaiting → ready) with no surfaced message:
                // still a meaningful drain, so the UI re-queries and "Waiting for their
                // inbox…" clears in place — the whole point of the control channel.
                if (wasAwaiting && !contactAwaitingPeerInbox(vault, c.contactId)) {
                    anyReceived = true
                }
            }
        } finally {
            mgr.flushAcks(acks)
        }
        // The control sweep is the path a 1:1 screenshot notice normally arrives
        // on (no conversation need be open) — move what the transport applied into
        // the per-conversation buffers.
        collectDirectScreenshotNotices()
        return anyReceived
    }

    /**
     * How many control-inbox `/peek`s a sweep may keep in flight. Pure, so
     * the gate is unit-pinnable without a relay.
     *
     * 1 (= strictly sequential) in three cases, each of them
     * load-bearing:
     *  - **CONVERGING.** The peek is skipped entirely in that state, so there is
     *    nothing to fan out; every contact drains, and a drain is vault-heavy and
     *    stays serial.
     *  - **BEFORE THE FIRST RELAY ANSWER.** The connect-time sweep shares a COLD
     *    circuit with the health probe, and the connect-time reveal (ConnectReveal)
     *    depends on it staying sequential — a three-wide burst onto a circuit that has not
     *    answered once is exactly the 6a0c138 failure. The caller additionally
     *    forces this false for the prime's pre-drain, which IS the connect-time
     *    sweep. [MessageManager.hasCompletedRelayRoundTrip] is the monotonic latch
     *    the rest of the app already reads for "the relay answered".
     *  - **FEWER THAN TWO CONTACTS.** Nothing to parallelise, and it keeps a
     *    one-contact device on a code path that is byte-for-byte what it was.
     */
    private fun hasDeferredSealedControl(mgr: MessageManager, contactId: String): Boolean =
        try { mgr.sealedControlDrainDue(contactId) } catch (_: Exception) { false }

    internal fun controlPeekConcurrency(
        contactCount: Int,
        converging: Boolean,
        firstRelayAnswerSeen: Boolean,
    ): Int =
        if (converging || !firstRelayAnswerSeen || contactCount < 2) 1 else CONTROL_PEEK_CONCURRENCY

    /**
     * The BOUNDED-PARALLEL peek phase of a steady-state control sweep.
     *
     * Returns contactId → count for the peeks that POSITIVELY ANSWERED, and null
     * when the phase did not run at all (nothing resolvable to peek, or it failed) —
     * which sends the caller back to the per-contact serial peek. An answered 0 is
     * the ONLY thing that may skip a drain, so a contact that is merely missing from
     * the map is UNKNOWN and drains, exactly as a null from
     * [MessageManager.peekControlPending] does.
     *
     * Four properties, each load-bearing:
     *  - **SNAPSHOT FIRST, THEN FAN OUT.** Every vault read/write of the phase — the
     *    contact row, the read-cap reconcile, the inbound-ctl row — happens in
     *    [MessageManager.inboundControlPeekTargets] on THIS thread before any worker
     *    exists; the workers run [MessageManager.peekControlRef], which touches no
     *    vault. `DatabaseManager` / `IosVaultDatabase` thread-safety under genuinely
     *    concurrent access is unproven on both platforms and must not gain a second
     *    concurrent caller.
     *  - **THE DRAIN NEVER FANS OUT.** `pollControlMessages` persists counters,
     *    applies announces and steps the ratchet; it stays on the sweep's own thread.
     *  - **BOUNDED AND JITTERED.** [CONTROL_PEEK_CONCURRENCY] permits, and every peek
     *    still starts at a CSPRNG offset ([CONTROL_PEEK_JITTER_MS]) because this is a
     *    REPEATING sweep an observer could otherwise align across cycles.
     *  - **NEVER THROWS.** A control sweep that threw would cross the Swift bridge as
     *    an uncatchable error; anything unexpected degrades to null → the serial
     *    path.
     */
    private fun peekControlInboxesBounded(
        mgr: MessageManager,
        contacts: List<ContactRecord>,
        concurrency: Int,
    ): Map<String, Int>? = try {
        val targets = mgr.inboundControlPeekTargets(contacts.map { it.contactId })
        if (targets.isEmpty()) {
            null
        } else {
            val answered = mutableMapOf<String, Int>()
            val answerLock = SyncLock()
            runBlockingIo {
                val gate = Semaphore(concurrency.coerceIn(1, CONTROL_PEEK_CONCURRENCY))
                coroutineScope {
                    for (target in targets) {
                        launch(ioDispatcher) {
                            // Stagger OUTSIDE the permit, so a permit is only ever
                            // held for an actual request.
                            delay(secureRandomInt(CONTROL_PEEK_JITTER_MS).toLong())
                            gate.withPermit {
                                val n = try {
                                    mgr.peekControlRef(target)
                                } catch (e: Exception) {
                                    platformLogWarn(TAG, "control peek failed: ${e::class.simpleName}")
                                    null
                                }
                                if (n != null) answerLock.withLock { answered[target.contactId] = n }
                            }
                        }
                    }
                }
            }
            answered
        }
    } catch (e: Exception) {
        platformLogWarn(TAG, "control peek fan-out failed: ${e::class.simpleName}")
        null
    }

    /**
     * The FOURTH arming condition for the FAST control-poll cadence:
     * "a group conversation is open in the foreground". The other three
     * are a control SEND / a qualifying membership arrival ([MessageManager.
     * noteControlActivity], the persistent window), [hasUnresolvedMembers] (both
     * bounded clauses, per cycle) and the Add-contact scan-back screen
     * ([MessageManager.notePairingAwaitingPeer]).
     *
     * **Why.** A passive member that never sends anything learns of a kick, an admin
     * handoff or a re-add only on its next IDLE sweep (60–90 s). Measured on test phones:
     * an admin hand-off surfaced after 210 s, a member-count change after 81 s — and
     * users see the same lag on the screen where it matters most.
     *
     * **Trade-off, stated plainly.** While a group
     * conversation is on screen the device polls the control channel every 2.5–5 s
     * instead of 60–90 s. The TEXT channel already polls every 1–2 s inside an open
     * conversation, so the extra control peek barely changes the traffic shape a relay
     * or network observer sees; and the condition ends WITH THE SCREEN — it is not a
     * timer, so it cannot be re-armed by anything a peer sends, and it dies on lock,
     * wipe and background (which tears the session down on both platforms).
     *
     * **What it deliberately does NOT do.** It is OR-ed into the per-cycle
     * `convergingNow` argument of [MessageManager.controlPollDelayMs] at the two
     * platform loops ONLY. It never arms the persistent convergence window, so
     * [MessageManager.isControlConverging] stays false and the peek-before-drain
     * stays ON for every contact (an unconditional drain on every 2.5 s
     * sweep is exactly the hazard the episode cap exists for). It does not touch
     * [hasUnresolvedMembers] or its bounds. 1:1 conversations do not set it.
     *
     * Keyed by SCREEN, not a bare boolean: Android's Compose navigation can dispose
     * the conversation AFTER the group-info screen it navigated to has already
     * composed (and SwiftUI may deliver a duplicate onAppear), so a single boolean
     * would be cleared by the departing screen while its successor is still visible.
     * Each surface passes a stable key (e.g. "conv:<groupId>"); the flag is "any key
     * present". Set/clear are idempotent. RAM-only; cleared by [scrubInMemory].
     */
    fun setGroupConversationForeground(screenKey: String, open: Boolean) {
        groupConversationForegroundLock.withLock {
            if (open) groupConversationForegroundKeys.add(screenKey)
            else groupConversationForegroundKeys.remove(screenKey)
            groupConversationForeground = groupConversationForegroundKeys.isNotEmpty()
        }
    }

    /** @see setGroupConversationForeground — read once per control-poll cycle and once
     *  per idle-sleep slice by both platform loops; a lock-free volatile read. */
    fun isGroupConversationForeground(): Boolean = groupConversationForeground

    private val groupConversationForegroundLock = SyncLock()
    private val groupConversationForegroundKeys = mutableSetOf<String>()
    @Volatile
    private var groupConversationForeground = false

    /**
     * True if any joined group still has a non-self member we haven't resolved to
     * a contact (contactId == null) — i.e. member↔member resolution is pending.
     * The platform poll loop uses this to poll the control channel FAST while
     * resolution is in flight (a join→roster→resolve round-trip), so it converges
     * over slow Tor instead of stalling on the idle cadence between hops
     * (MessageManager.controlPollDelayMs). Cheap local reads; best-effort.
     *
     * **The fast-window clock is anchored on the last membership EVENT, not only on the
     * slot's `addedAt`.** `handleRoster` preserves `addedAt` (`existing?.addedAt ?: now`)
     * and the row is persisted, so `now - m.addedAt` alone measures how long ago the
     * SLOT was created — which survives every later roster and every relaunch — and on
     * a long session the fast window would expire mid-convergence, each remaining hop
     * paying a full idle interval. The [GroupFastAnchor] re-opens
     * the same 10-minute window on each applied membership control that CHANGED
     * group state, so a chain that is still MOVING keeps the fast cadence.
     *
     * The never-resolvable pin is unchanged, and that is why the anchor is per-EVENT and RAM-only:
     * a never-IRL-paired member produces no membership events, so it never re-anchors
     * and still stops pinning fast-poll 10 min after its slot was created. There is
     * deliberately NO session-start anchor — that would hand every foreground return a
     * fresh 10-minute fast window on a permanently inert member, i.e. the fixed Tor
     * beacon this window exists to prevent. The anchor is also doubly bounded
     * against a PEER: only an applied control that moved the
     * [convergenceFingerprint] re-anchors (a no-op ping never does), and anchor-driven
     * fast time is capped per group per episode at [UNRESOLVED_FAST_EPISODE_MAX_MS]
     * — see [noteUnresolvedFastAnchor].
     */
    fun hasUnresolvedMembers(): Boolean = try {
        // [clockMs] (not currentTimeMillis) so the fast window is unit-drivable, the
        // same seam the unresolved-sender buffer's TTL and the sweep timers already use. Production is
        // byte-identical — clockMs defaults to currentTimeMillis.
        val now = clockMs()
        vault.getAllGroups().any { g ->
            val anchor = fastAnchor.anchor(g.groupId)
            vault.getGroupMembers(g.groupId).any { m ->
                // Only members whose resolution could still be
                // IN FLIGHT keep fast-poll on — bound by how recently the member was
                // added OR last moved by a membership control, not merely that the slot
                // is unresolved. A never-IRL-paired member stays unresolved forever;
                // without this bound it pins the control poll to FAST indefinitely (a
                // permanent Tor traffic beacon).
                // A backward clock step fails toward FAST (the subtraction goes
                // negative).
                val since = if (anchor > m.addedAt) anchor else m.addedAt
                (m.memberId != g.myMemberId && m.contactId == null &&
                    (now - since) < UNRESOLVED_MEMBER_FAST_WINDOW_MS) ||
                    // …and the ADMIN half of the same chain (see [joinPending]).
                    joinPending(g, m, now, anchor)
            }
        }
    } catch (_: Exception) { false }

    /**
     * The ADMIN-side half of the convergence chain
     * [hasUnresolvedMembers] covers: a member row that is **resolved but carries no
     * tags** on a device that is the group's ADMIN is a member we added by contact
     * whose `KIND_JOIN` has not been ingested yet.
     *
     * Why it needed its own clause: [addMember] inserts the row WITH a `contactId`
     * (`GroupManager.kt`'s `GroupMemberRecord(groupId, newId, contactId, addedAt)`),
     * so the `contactId == null` clause above is blind to it. Without this clause an
     * admin that just sent an invite falls to the 60–90 s idle cadence once its last
     * control SEND ages out of `CONTROL_CONVERGENCE_WINDOW_MS`, so the new member's
     * join waits a whole idle interval — long enough for an admin hand-off to complete
     * first (see [transferAdmin]).
     *
     * Bounds, deliberately identical to the unresolved-member clause above so no new beacon shape
     * is introduced: ADMIN only (a non-admin device stores no tags at all —
     * `GroupMemberRecord.tags`' kdoc — so an unguarded "empty tags" test would pin
     * every plain member to FAST); never our own row; and expiring
     * [UNRESOLVED_MEMBER_FAST_WINDOW_MS] after `max(addedAt, last membership event)`.
     * It is driven purely by LOCAL state this device created, so unlike the
     * arrival-driven arming path no peer can reach it.
     */
    internal fun joinPending(
        g: GroupRecord,
        m: GroupMemberRecord,
        now: Long,
        anchor: Long,
    ): Boolean {
        if (!g.isAdmin) return false
        if (m.memberId == g.myMemberId || m.contactId == null || m.tags.isNotEmpty()) return false
        val since = if (anchor > m.addedAt) anchor else m.addedAt
        return (now - since) < UNRESOLVED_MEMBER_FAST_WINDOW_MS
    }

    /**
     * Routes a batch of decrypted messages from [contactId]'s inbox to the SCREEN
     * whose poll fetched them. [wantGroupId] is that screen (null = the 1:1 with
     * this contact). NO-PARK — nothing is held for another
     * conversation:
     *  - 1:1 screen: a 1:1 text is OWN; a group text (any group) is GROUP_ECHO.
     *  - group screen G: a text of G is OWN; a text of another group is
     *    GROUP_ECHO; a 1:1 text is PRIVATE.
     * Control messages are applied to vault state immediately. [bufferAll] hands
     * the items to the screen's buffer (POLL-HANDOFF-1) instead of returning them.
     * [background] is the control sweep (no screen): MessageManager already drops
     * every non-control blob on the control inbox, so a text can only reach here
     * through an unforeseen path — it goes to its OWN conversation's screen buffer
     * rather than being destroyed.
     */
    internal fun ingest(
        contactId: String,
        received: List<ReceivedMessage>,
        wantGroupId: String?,
        bufferAll: Boolean = false,
        // TRUE when [received] came off this contact's inbound-GROUP inbox
        // rather than their text inbox. It decides which pending tally a consumed
        // group text is subtracted from ([GroupUnreadTally.consumed]) and nothing else —
        // routing, attribution and the buffers are identical on both channels,
        // because a group text is a group text wherever it was queued.
        fromGroupInbox: Boolean = false,
        background: Boolean = false,
    ): IngestResult {
        // Backstop: a blocked contact's traffic must never apply a
        // control (invite / referral-offer / inbox-announce) or surface a message,
        // regardless of which poll path reached here. pollAllControls/pollGroup
        // already skip blocked inboxes; this guards every other caller.
        if (contactId in blockedContactsSafe()) {
            // Count-only: the relay already deleted these at fetch.
            if (received.isNotEmpty()) platformLogWarn(TAG, "ingest: blocked contact — dropped ${received.size} drained message(s)")
            return IngestResult(emptyList(), emptyList())
        }
        val direct = mutableListOf<DirectItem>()
        val group = mutableListOf<GroupMessage>()
        for (rm in received) {
            val gid = rm.groupId
            if (gid == null) {
                routeDirect(contactId, rm, wantGroupId, bufferAll, background, direct, group)
                continue
            }
            val kind = rm.controlKind
            if (kind != null) {
                applyGroupControl(contactId, gid, kind, rm)
            } else {
                routeGroupText(contactId, gid, rm, wantGroupId, bufferAll, fromGroupInbox, background, direct, group)
            }
        }
        return IngestResult(direct, group)
    }

    /** [ingest] route 1: a message with no group id — a direct referral control
     *  (handed to ReferralManager) or a 1:1 text (OWN, or PRIVATE in a group screen). */
    private fun routeDirect(
        contactId: String, rm: ReceivedMessage, wantGroupId: String?, bufferAll: Boolean, background: Boolean,
        direct: MutableList<DirectItem>, group: MutableList<GroupMessage>,
    ) {
        // Direct referral control (referral.md) — hand to ReferralManager
        // via the sink rather than buffering it as a 1:1 text.
        val ck = rm.controlKind
        if (ck != null && ck in MessageManager.DIRECT_REFERRAL_KINDS) {
            try { onReferralControl?.invoke(contactId, ck, rm.controlBody ?: "") }
            catch (e: Exception) { platformLogWarn(TAG, "referral control failed: ${e::class.simpleName}") }
            return
        }
        val screenGroup = if (background) null else wantGroupId
        if (screenGroup == null) {
            val item = DirectItem(contactId, rm.text, rm.timestamp, rm.dedupeId)
            if (!bufferAll) direct.add(item) else buffers.toDirectScreen(contactId, item)
        } else {
            // PRIVATE: a 1:1 text a GROUP poll fetched. It is shown in that
            // group's screen and never touches a group counter.
            val pm = privateItem(screenGroup, contactId, rm)
            if (!bufferAll) group.add(pm) else buffers.toGroupScreen(screenGroup, pm)
        }
    }

    /** [ingest] route 2: a group CONTROL — applied, then (membership kinds only)
     *  the fast-window anchor, convergence note and backfill arming. */
    private fun applyGroupControl(contactId: String, gid: String, kind: String, rm: ReceivedMessage) {
        // Read the sender's membership view BEFORE the handler
        // runs. Applying the control can move OUR epoch (an admin bumps it on
        // a KIND_LEAVE), and comparing a pre-change hash against a post-change
        // one would manufacture a divergence that does not exist.
        noteMembershipView(contactId, gid, rm.membershipHash, kind)
        // Only a MEMBERSHIP kind can arm the convergence window, so
        // only those pay for the before/after probe. The frequent kinds
        // (`act`, `screenshot`) never reach it.
        val qualifies = isMembershipControlKind(kind)
        val before = if (qualifies) convergenceFingerprint(gid) else ""
        try {
            handleControl(contactId, gid, kind, rm.controlBody ?: "", rm.timestamp)
        } catch (e: Exception) {
            // Control handling must never take down a poll loop.
            platformLogWarn(TAG, "control failed: ${e::class.simpleName}")
        }
        if (qualifies) {
            val after = convergenceFingerprint(gid)
            // Fast-window re-anchor FIRST — but ONLY when the control actually MOVED
            // group state: a roster/leave/invite/join that
            // the handler dropped or re-applied unchanged converges nothing, so
            // it must not buy another fast window. Re-anchoring on the mere
            // ARRIVAL let any paired co-member hold the device on the 2.5–5 s
            // cadence (and block transferAdmin via joinPending) by pinging a
            // no-op membership kind every few minutes — the exact lever the
            // kdoc on noteUnresolvedFastAnchor said a chatty peer must not have.
            // A genuine join→roster→resolve chain moves the fingerprint at
            // every applied hop, so it still re-anchors per hop. The arming
            // predicate below reads the same post-apply state.
            if (before != after) noteUnresolvedFastAnchor(gid)
            noteControlConvergence(contactId, before, after)
            // A membership event is when a pairing can newly NEED a
            // group inbox (a slot just resolved, a member joined). Arms only;
            // the durable throttle decides whether anything is actually done.
            armGroupInboxBackfillForGroup(gid)
            armGroupInboxBackfill(contactId)
        }
    }

    /** [ingest] route 3: a group TEXT — attributed (or buffered/dropped), then shown
     *  in its own group's screen or as a GROUP_ECHO in the screen that fetched it. */
    private fun routeGroupText(
        contactId: String, gid: String, rm: ReceivedMessage, wantGroupId: String?, bufferAll: Boolean,
        fromGroupInbox: Boolean, background: Boolean,
        direct: MutableList<DirectItem>, group: MutableList<GroupMessage>,
    ) {
        noteMembershipView(contactId, gid, rm.membershipHash, kind = null)
        val gm = acceptGroupText(contactId, gid, rm) ?: return
        // This group text just left the relay (returned or buffered) — drop it
        // from whichever pending tally described it.
        tally.consumed(contactId, fromGroupInbox)
        // …and ONE unit from the vault mirror, when the RAM side gave one back: a
        // group-inbox text (its `gi` unit) or an echo (its group dot). In practice the
        // group-inbox case is already empty — [afterGroupInboxDrain] cleared the whole
        // mirror for this contact a moment ago — so this is the lockstep, not the work.
        if (fromGroupInbox || (!background && gid != wantGroupId)) unreadMarkers.removeOne(contactId, gid)
        when {
            background -> buffers.toGroupScreen(gid, gm)
            gid == wantGroupId -> if (!bufferAll) group.add(gm) else buffers.toGroupScreen(gid, gm)
            else -> {
                // GROUP_ECHO: shown at once in the screen that fetched it, so the
                // group's own dot has nothing left to point at.
                tally.shownElsewhere(gid, contactId)
                if (wantGroupId == null) {
                    val echo = DirectItem(
                        contactId, gm.text, gm.timestamp, gm.dedupeId,
                        kind = ReceivedItemKind.GROUP_ECHO, groupId = gid, groupName = gm.groupName,
                    )
                    if (!bufferAll) direct.add(echo) else buffers.toDirectScreen(contactId, echo)
                } else {
                    val echo = gm.copy(kind = ReceivedItemKind.GROUP_ECHO)
                    if (!bufferAll) group.add(echo) else buffers.toGroupScreen(wantGroupId, echo)
                }
            }
        }
    }

    /** NO-PARK: the group-screen item for a 1:1 text from [contactId] that the poll
     *  of [screenGroupId] fetched. Attribution is the pairwise channel it decrypted
     *  on; the alias is read from the vault, never the wire. */
    private fun privateItem(screenGroupId: String, contactId: String, rm: ReceivedMessage): GroupMessage =
        GroupMessage(
            groupId = screenGroupId,
            senderContactId = contactId,
            senderAlias = vault.getContact(contactId)?.alias ?: platformString(NOTICE_MEMBER_FALLBACK_KEY),
            text = rm.text,
            timestamp = rm.timestamp,
            counter = rm.counter,
            sequenceGap = rm.sequenceGap,
            membershipOk = true,
            dedupeId = rm.dedupeId,
            kind = ReceivedItemKind.PRIVATE,
        )

    /** Validates and converts a group text message. Null = dropped OR buffered. */
    private fun acceptGroupText(contactId: String, groupId: String, rm: ReceivedMessage): GroupMessage? {
        val g = vault.getGroup(groupId)
        if (g == null) {
            // Group text for a group we don't know — invite lost or we left.
            platformLogWarn(TAG, "drop: text for unknown group")
            return null
        }
        val members = vault.getGroupMembers(groupId)
        // The deniability of the channel IS the attribution: this blob
        // decrypted under [contactId]'s pairwise secret. The sender must be a
        // current, resolved member.
        if (members.none { it.contactId == contactId }) {
            // Unresolved-sender buffer: the sender isn't a resolved member. If the group still has
            // UNRESOLVED members, member↔member resolution may simply not have
            // converged on THIS device yet — the feeding poll drains the relay (destructive
            // before the leasing relay), so dropping a decryptable text from a real
            // member loses it for good. Buffer it (bounded + TTL) and re-attempt attribution on each
            // roster apply / group open. Once the roster is FULLY resolved a sender
            // that still isn't a member is a genuine non-member (removed/stranger) —
            // then drop, preserving the "removed member's texts are dropped" property.
            val resolutionInFlight = members.any { it.contactId == null && it.memberId != g.myMemberId }
            if (resolutionInFlight) {
                buffers.bufferUnresolvedGroupText(groupId, contactId, rm)
            } else {
                platformLogWarn(TAG, "drop: group text from non-member contact")
            }
            return null
        }
        return toGroupMessage(contactId, groupId, g, members, rm)
    }

    /** Builds the surfaced [GroupMessage] for an ALREADY-resolved member. */
    private fun toGroupMessage(
        contactId: String, groupId: String, g: GroupRecord,
        members: List<GroupMemberRecord>, rm: ReceivedMessage,
    ): GroupMessage {
        val myHash = membershipHash(groupId, g.epoch, members.map { it.memberId })
        return GroupMessage(
            groupId = groupId,
            senderContactId = contactId,
            senderAlias = vault.getContact(contactId)?.alias ?: platformString(NOTICE_MEMBER_FALLBACK_KEY),
            text = rm.text,
            timestamp = rm.timestamp,
            counter = rm.counter,
            sequenceGap = rm.sequenceGap,
            membershipOk = rm.membershipHash == myHash,
            dedupeId = rm.dedupeId,   // preserve the namespaced id for UI de-dup
            groupName = g.name,
        )
    }

    // -----------------------------------------------------------------------
    // Sending
    // -----------------------------------------------------------------------

    /**
     * Fan-out send of a group text to every RESOLVED member. Per-copy
     * delivery is independent; the caller surfaces partial delivery. The
     * member order is shuffled and a random delay is inserted between sends
     * so the relay/observer does not see one tight burst of N same-sized
     * posts — the loudest group-shaped traffic signature. Blocking
     * (network + jitter sleeps) — call from a background dispatcher.
     *
     * Each member's KIND_ACTIVITY notice is sent IMMEDIATELY AFTER that member's
     * text copy (interleaved), not as one burst once every text has gone.
     * The notice is the ONLY thing that tells the recipient the
     * queued blob on their 1:1 text inbox is a GROUP text — a `/peek` returns a
     * bare count — and the text copy is what fires their push wake. Sent as one
     * burst, the last member's notice could be 2·(k−1) jitter gaps behind their
     * text, so a device that woke on the push (or connected and primed) in that
     * window attributed the group text to the SENDER's 1:1 row. Interleaving
     * shrinks that window to ONE gap, independent of group size.
     *
     * What the reordering deliberately does NOT change: [KIND_ACTIVITY] still ships
     * `noPush = true` (the text copy already fired this event's one wake — see
     * [fanOutControl]); a member whose TEXT send FAILED still gets no notice; and
     * the traffic budget is identical — 2k−1 POSTs with a 250-2000 ms jittered gap
     * before every one of them but the first, i.e. the same count, the same
     * distribution and the same total window the two-burst shape had.
     */
    fun sendGroupMessage(groupId: String, text: String): GroupSendResult {
        val g = vault.getGroup(groupId) ?: return GroupSendResult(0, 0)
        val members = vault.getGroupMembers(groupId)
        val hash = membershipHash(groupId, g.epoch, members.map { it.memberId })
        // Every RECEIVE path (pollGroup,
        // pollAllControls, ingest) already honors the block set; this SEND fan-out
        // didn't, so a blocked co-member kept receiving the victim's group texts
        // even though block's stated purpose is severing the polling relationship.
        // blockedContactsSafe() fails open to the empty set on an unreadable
        // Keychain (documented trade-off: a best-effort bound), so this can't brick a
        // send — it can only fail to filter, same as before this fix.
        val blocked = blockedContactsSafe()
        val targets = members
            .filter { it.contactId != null && it.memberId != g.myMemberId && it.contactId !in blocked }
            .secureShuffled()
        // Members with no resolved contact get no copy and no retry — reported so
        // the sender's mark can say "not delivered to N" instead of a false "✓".
        val unreachable = members.count { it.contactId == null && it.memberId != g.myMemberId }
        if (targets.isEmpty()) return GroupSendResult(0, 0, unreachable)
        // No relay transport (Tor not up): nobody gets a copy, and the result says so
        // for every addressable member instead of a bare 0/0.
        val mgr = transport("group send") ?: return GroupSendResult(0, targets.size, unreachable)

        var delivered = 0
        // POSTs issued so far, texts AND notices: the jitter gap goes before every
        // send except the very first, so the interleaved sequence keeps exactly the
        // old cadence rather than emitting tight text+notice pairs.
        var posts = 0
        for (m in targets) {
            val contactId = m.contactId ?: continue
            if (posts > 0) sleepInterSendJitter()
            posts++
            // The ROUTE, not the intent. The notice below carries `{"gi":"1"}`
            // iff this copy really landed on the peer's GROUP inbox — a 404
            // fallback puts it back on the text inbox even though the group row
            // exists, and a notice that lied about that would leave a real group
            // text unattributed (or subtract a phantom from a 1:1 badge, the hazard
            // described just below).
            val route = try {
                mgr.sendGroupTextRouted(contactId, groupId, hash, text)
            } catch (e: Exception) {
                platformLogWarn(TAG, "group send failed for one member: ${e::class.simpleName}")
                MessageManager.GroupTextRoute.FAILED
            }
            val ok = route != MessageManager.GroupTextRoute.FAILED
            // The activity notice goes ONLY to a member whose
            // TEXT copy actually sent. The recipient's handleActivity increments a
            // per-contact "group text pending" count that is decremented only when the
            // group text drains — so a notice to a member who never received the text
            // leaves a PHANTOM pending that gets subtracted from (and thus HIDES) that
            // contact's later real 1:1 unread badge until the 1:1 is opened.
            if (!ok) continue
            delivered++
            // Never the first POST (its own text copy just went), so the gap is
            // unconditional.
            sleepInterSendJitter()
            posts++
            // A lightweight activity notice on the CONTROL channel, so this
            // recipient's background poll (and their connect-time unread prime) lights
            // the GROUP unread dot and knows WHICH group the queued text belongs to —
            // a background sweep can only peek, never decrypt. The CONTACT-dot
            // subtraction applies ONLY when the text actually rode the 1:1 text inbox
            // (route != GRP); a group-inbox copy is never counted on the contact row at
            // all. Best-effort: a dropped notice only costs a misattributed dot, never
            // a lost message.
            // Single-target [fanOutControl], the same shape addMember's invite and
            // sendSelfJoinToNewAdmin already use — its own inter-target jitter is a
            // no-op for one target, which is why the gap above is at this call site.
            //
            // `{"gi":"1"}` says "the text this notice describes went to your
            // GROUP inbox". Same conventions as `rv` — an OPTIONAL JSON STRING,
            // appended last, absent-is-legacy, never a rejection reason — so an old
            // build reads the body field-by-field and simply never asks for it.
            val body = if (route == MessageManager.GroupTextRoute.GRP) ACTIVITY_BODY_GRP else "{}"
            fanOutControl(listOf(contactId), groupId, KIND_ACTIVITY, { body }, hash, noPush = true)
        }
        platformLog(TAG, "group send: $delivered/${targets.size} delivered, $unreachable unreachable")
        return GroupSendResult(delivered, targets.size, unreachable)
    }

    /**
     * Tells every RESOLVED member that we just took a screenshot of this group
     * ([KIND_SCREENSHOT]) — the same body-less control fan-out
     * [sendGroupMessage] uses for its activity notice, with the same shuffle +
     * jitter so it adds no new traffic shape.
     *
     * BEST-EFFORT and FIRE-AND-FORGET: it reports nothing, because there is
     * nothing a caller should do about a dropped notice, and a failure must never
     * reach the conversation as an error. Each copy still rides the ordinary
     * transient-retry machinery inside [MessageManager.sendGroupControl].
     * Blocking (network + jitter sleeps) — background dispatcher only, like
     * [sendGroupMessage].
     *
     * Unlike the activity notice this does NOT touch the ACTIVITY counters
     * ([GroupUnreadTally]): a screenshot notice is not a queued
     * message, so it must never be subtracted from a contact's badge as though a
     * group text were sitting on their inbox. (On the RECEIVER an unseen persisted
     * notice contributes its own, separate term to the dot — see
     * [handleScreenshotNotice] — which is not this counter.)
     */
    fun sendGroupScreenshotNotice(groupId: String) {
        val g = vault.getGroup(groupId) ?: return
        val members = vault.getGroupMembers(groupId)
        val hash = membershipHash(groupId, g.epoch, members.map { it.memberId })
        // Same block-set filter as sendGroupMessage above — a blocked
        // co-member must not learn the victim screenshotted the group either.
        val blocked = blockedContactsSafe()
        val targets = members
            .filter { it.contactId != null && it.memberId != g.myMemberId && it.contactId !in blocked }
            .mapNotNull { it.contactId }
        if (targets.isEmpty()) return
        // noPush: a notice must not wake a peer's device or raise a "new message"
        // banner for something that is not a message (see sendScreenshotNotice).
        fanOutControl(targets, groupId, KIND_SCREENSHOT, { "{}" }, hash, noPush = true)
    }

    /**
     * Same shuffle+jitter discipline for control fan-out.
     *
     * The jitter sits BETWEEN targets, so a SINGLE-target call (addMember's invite,
     * sendSelfJoinToNewAdmin, and sendGroupMessage's per-member activity notice)
     * emits its POST with no leading delay — a caller that is interleaving into
     * another send sequence owns that gap itself. See [sendGroupMessage].
     *
     * [noPush] DEFAULTS TO `true` — the fail-safe direction, and a deliberate flip
     * from the original `false`. Inbound CONTROL inboxes are now part of the push
     * surface ([allPushableInboxes]), and the APNs wake is an ALERT push (visible
     * banner + sound), so a control kind that leaves this unset would banner every
     * member for roster bookkeeping. Every kind that SHOULD wake a device states
     * `noPush = false` at its call site (today: only [KIND_INVITE]); everything
     * else keeps exactly the behaviour it has today, where control inboxes are not
     * registered at all. See the per-kind table in PushRegistration.kt.
     */
    private fun fanOutControl(
        targets: List<String>,            // contactIds
        groupId: String,
        kind: String,
        bodyFor: (contactId: String) -> String,
        hash: String,
        noPush: Boolean = true,
    ): List<String> {   // the targets that did NOT get the message (all of them when no transport)
        val mgr = transport("control fan-out") ?: return targets.distinct()
        val ttl = membershipControlTtl(kind)
        val failed = mutableListOf<String>()
        val shuffled = targets.secureShuffled()
        for ((index, contactId) in shuffled.withIndex()) {
            if (index > 0) sleepInterSendJitter()
            val ok = try {
                mgr.sendGroupControl(contactId, groupId, kind, bodyFor(contactId), hash, noPush, ttl)
            } catch (e: Exception) {
                platformLogWarn(TAG, "control send failed: ${e::class.simpleName}")
                false
            }
            if (!ok) { platformLogWarn(TAG, "control '$kind' not delivered to one member"); failed += contactId }
        }
        return failed
    }

    /**
     * The relay-retention hint for a control append. UNIFORM across every kind.
     *
     * The value is the same for ALL kinds (not only the membership kinds, which need
     * to outlive the relay's 24 h default), because the `?ttl` rides
     * the request line in the CLEAR: `?ttl=604800` + `X-No-Push: 1` identified a
     * ROSTER or a LEAVE and nothing else, handing a hostile relay a free
     * membership-change classifier — and the surgical selector for a
     * 201-and-discard suppression. The parameter is kept so the call site still
     * reads as a per-kind decision point; the only correct answer today is the
     * single constant. See [MessageManager.CONTROL_APPEND_TTL_SECONDS].
     */
    @Suppress("UNUSED_PARAMETER")
    private fun membershipControlTtl(kind: String): Long? = MEMBERSHIP_CONTROL_TTL_SECONDS

    // -----------------------------------------------------------------------
    // Durable, ACK-GATED redrive of membership control (roster / leave): the
    // `grp_ctl_pend:` obligations live in [MembershipControlRedrive].
    // -----------------------------------------------------------------------

    /**
     * POSITIVE ACK / DIVERGENCE detection, from the one signal the protocol
     * already carries — every group text and every group control ships the sender's
     * `membershipHash`.
     *
     *  - hash EQUALS ours ⇒ that member has converged on this exact member set.
     *    Whatever the relay told us about the append, this is END-TO-END proof;
     *    drop the obligation and any divergence marker.
     *  - hash DIFFERS ⇒ positive evidence the member has NOT converged. If we are
     *    the admin, mark it for a bounded re-roster ([rerosterUnconvergedMembers]).
     *
     * Called with the sender's view as it was BEFORE the control was applied (see
     * [ingest]): applying a KIND_LEAVE bumps OUR epoch when we are admin, so a
     * post-apply comparison would invent a divergence for the member that just left.
     * [KIND_LEAVE] and [KIND_INVITE] are skipped outright for the same reason — a
     * leaver has nothing left to converge on, and an invite names a group we are not
     * a member of.
     *
     * Never throws: a vault hiccup here costs one convergence signal, never a poll.
     */
    private fun noteMembershipView(contactId: String, groupId: String, theirHash: String?, kind: String?) {
        if (theirHash == null || theirHash.isEmpty()) return
        if (kind == KIND_LEAVE || kind == KIND_INVITE) return
        try {
            val g = vault.getGroup(groupId) ?: return
            val members = vault.getGroupMembers(groupId)
            // Attribution is the pairwise channel; an unresolved/non-member sender
            // says nothing about OUR roster.
            if (members.none { it.contactId == contactId }) return
            if (theirHash == membershipHash(groupId, g.epoch, members.map { it.memberId })) {
                unconverged.clear(groupId, contactId)
                ctlRedrive.acknowledge(groupId, contactId)
                return
            }
            if (!g.isAdmin) return   // only the admin's roster is honoured by receivers
            unconverged.mark(groupId, contactId)
        } catch (e: Exception) {
            platformLogWarn(TAG, "membership view check failed: ${e::class.simpleName}")
        }
    }

    /**
     * Arm the control-poll convergence window for a
     * QUALIFYING arrival only — a group-membership control kind from a contact that
     * is a member of at least one group this device knows.
     *
     * Not armed by every drained blob (both platforms feed
     * `received || hasUnresolvedMembers()` into [MessageManager.controlPollDelayMs],
     * and `received` is true even for a control kind that was dropped as unknown):
     * then one paired contact posting one blob a minute would hold the device in
     * 2.5–5 s sweeps for the whole foreground session AND keep
     * [MessageManager.isControlConverging] true, which disables the
     * peek-before-drain for EVERY contact and turns every sweep into an
     * unconditional drain — multiplying the chance of permanently
     * destroying a third party's invite/roster/offer on a cold circuit.
     *
     * [before]/[after] are [convergenceFingerprint] snapshots around the handler:
     * an arrival that actually MOVED group state is PROGRESS and re-anchors the
     * episode bound, so a genuine join→roster→resolve chain never runs the ceiling
     * out while pure noise does.
     *
     * DELIBERATELY NOT INCLUDED: the direct referral kinds. Their handshake is
     * durable in its own right (7-day relay TTL + two bounded redrives on this same
     * sweep), every leg of it is preceded by a SEND from one side — which arms the
     * window through [MessageManager.sendEnvelope] — and a received `ref-offer` /
     * `ref-accept` is attacker-triggerable in a way a group membership kind from a
     * known co-member is not. The cost is at most one extra idle interval at one hop
     * of an introduction; the benefit is that the pin surface stays closed.
     *
     * **[isKnownGroupMember] alone is too narrow.** It asks
     * whether [contactId] is a RESOLVED member of some group — `it.contactId ==
     * contactId` — which is false for exactly the two arrivals a fast follow-up helps
     * most: a roster/join from the peer whose own member slot is still UNRESOLVED (that
     * slot's `contactId` IS null, so it can never match), and the first group INVITE
     * from a contact we share no group with yet (the invite is parked for consent, so
     * no member row exists at all). A device whose whole group was unresolved therefore
     * armed on NOTHING and spent the rest of its session on the idle cadence.
     *
     * Two more admissions close that, and neither re-opens the peer-driven pin, because both
     * are group-scoped AND bounded by something other than peer traffic:
     *  - [hasUnresolvedMembers] — itself bounded (10 min from the slot's `addedAt`
     *    or the last membership event), so a chatty peer cannot hold it open;
     *  - [hasPendingInviteFrom] — bounded by the user's own consent decision plus the
     *    standing forced-join caps ([inviteAllowed]), so a flooder is stopped before an
     *    invite is ever parked.
     * A stranger that is in no group with us, is not an unresolved co-member's peer and
     * has no invite awaiting our consent still arms nothing — which was the pin.
     */
    private fun noteControlConvergence(contactId: String, before: String, after: String) {
        if (!isKnownGroupMember(contactId) && !hasUnresolvedMembers() && !hasPendingInviteFrom(contactId)) return
        // A cadence hint only: a failure costs one sweep of the fast cadence, nothing else.
        try { messageManager()?.noteControlActivity(progress = before != after) } catch (_: Exception) { }
    }

    /** True while an invite from [contactId] is parked awaiting the user's consent —
     *  the state in which no member row exists yet, so [isKnownGroupMember] cannot see
     *  the relationship an invite→accept→join→roster chain is about to create. */
    private fun hasPendingInviteFrom(contactId: String): Boolean = try {
        pendingInviteLock.withLock { pendingInvites.values.any { it.inviterContactId == contactId } }
    } catch (_: Exception) { false }

    /** The four kinds a fast control follow-up can actually help converge. */
    private fun isMembershipControlKind(kind: String): Boolean =
        kind == KIND_ROSTER || kind == KIND_LEAVE || kind == KIND_INVITE || kind == KIND_JOIN

    /** True when [contactId] is a resolved member of any group this device knows. */
    private fun isKnownGroupMember(contactId: String): Boolean = try {
        vault.getAllGroups().any { g -> vault.getGroupMembers(g.groupId).any { it.contactId == contactId } }
    } catch (_: Exception) { false }

    /**
     * The cheap "did this control actually move group state?" probe (the
     * PROGRESS test). Epoch, admin, member count and resolved-member count cover every
     * mutation a roster / join / leave can make; an invite parks for consent and
     * mutates no group row, so it arms the window without re-anchoring the episode.
     */
    private fun convergenceFingerprint(groupId: String): String = try {
        val g = vault.getGroup(groupId)
        if (g == null) "-" else {
            val ms = vault.getGroupMembers(groupId)
            "${g.epoch}|${g.adminMemberId}|${ms.size}|${ms.count { it.contactId != null }}"
        }
    } catch (_: Exception) { "-" }

    // (group, member) pairs the ADMIN has positive evidence have not converged,
    // plus their per-member re-roster throttle. See [UnconvergedMembers].
    private val unconverged = UnconvergedMembers { clockMs() }

    // Fast-window re-anchor (groupId -> last applied membership event, bounded per
    // episode). See [GroupFastAnchor] for why it is RAM-only and has its own lock.
    private val fastAnchor = GroupFastAnchor(
        clock = { clockMs() },
        groupExists = { groupId -> (try { vault.getGroup(groupId) } catch (_: Exception) { null }) != null },
    )

    /** See [GroupFastAnchor.note] for the contract (the internals doc and tests
     *  name this entry point). */
    internal fun noteUnresolvedFastAnchor(groupId: String) = fastAnchor.note(groupId)

    /**
     * Mechanism 2: re-send the CURRENT roster to members this device has
     * positive evidence have not converged (their traffic carries a membershipHash
     * that is not ours). Rides the control sweep beside
     * [redriveUndeliveredMembershipControl].
     *
     * This is the half that survives a relay which 2xx-and-discards EVERY copy: it
     * is driven by the member's own inbound traffic, not by anything the relay
     * reports about our appends. Bounded three ways — at most one re-roster per
     * member per [REROSTER_MIN_INTERVAL_MS], at most [UnconvergedMembers.MAX_REROSTERS_PER_SWEEP] per
     * sweep, and only ever to ONE member at a time (never a fan-out), so a member
     * that deliberately ships a junk hash buys itself one roster copy per 10 min and
     * no amplification at all — a roster is state that member is entitled to anyway.
     *
     * Every re-send is an ORDINARY append: a new outbound control counter sealed
     * inside a fresh envelope. Nothing is ever "held and released", so the
     * strict-monotonic anti-replay rule is untouched.
     */
    fun rerosterUnconvergedMembers() {
        val mgr = transport("roster re-send") ?: return
        val now = clockMs()
        val due = unconverged.takeDue(now)
        if (due.isEmpty()) return
        var sent = 0
        for ((groupId, contactId) in due) {
            val g = try { vault.getGroup(groupId) } catch (_: Exception) { null } ?: continue
            if (!g.isAdmin) continue
            val members = try { vault.getGroupMembers(groupId) } catch (_: Exception) { continue }
            if (members.none { it.contactId == contactId }) continue
            if (try { vault.getContact(contactId) } catch (_: Exception) { null } == null) continue
            val body = try { buildRosterBody(groupId) } catch (_: Exception) { null } ?: continue
            val hash = membershipHash(groupId, g.epoch, members.map { it.memberId })
            if (sent > 0) sleepInterSendJitter()
            sent++
            val ok = try {
                mgr.sendGroupControl(contactId, groupId, KIND_ROSTER, body, hash, noPush = true, ttlSeconds = MEMBERSHIP_CONTROL_TTL_SECONDS)
            } catch (e: Exception) {
                platformLogWarn(TAG, "roster re-send threw: ${e::class.simpleName}"); false
            }
            platformLog(TAG, "roster re-sent to one member whose membership hash had diverged (ok=$ok)")
            // Record it like any other fan-out, so the ack-gated obligation keeps
            // working on this copy too if the relay swallowed it.
            ctlRedrive.record(
                groupId, KIND_ROSTER, g.epoch, hash,
                failed = if (ok) emptyList() else listOf(contactId),
                delivered = if (ok) listOf(contactId) else emptyList(),
            )
        }
    }

    /** Redrive every persisted membership obligation once — see
     *  [MembershipControlRedrive.redrive] for the contract. Platform entry point
     *  (SessionManagers' control-sweep hook). */
    fun redriveUndeliveredMembershipControl() = ctlRedrive.redrive()

    /**
     * The KIND_LEAVE body, `{"ep":…,"you":…}`. Both fields are OPTIONAL on receive,
     * so a peer that sends a bare `{}` is accepted exactly as before (see
     * [handleLeave]).
     */
    internal fun leaveBody(epoch: Long, myMemberId: String): String =
        if (myMemberId.isEmpty()) """{"ep":$epoch}"""
        else """{"ep":$epoch,"you":${jsonEscapeString(myMemberId)}}"""

    // -----------------------------------------------------------------------
    // Group lifecycle — admin side
    // -----------------------------------------------------------------------

    /**
     * Creates a group with this device as admin and invites [memberContactIds].
     * IRL precondition (UI-enforced, protocol-checked where possible): every
     * chosen member must have paired with every other — the admin is the
     * accountable party for that assertion. Returns the groupId, or null if
     * nothing could be persisted. Blocking — background dispatcher.
     */
    fun createGroup(name: String, memberContactIds: List<String>): String? {
        // Sanitise for consistency with the peer-ingest paths
        // (handleInvite/handleRoster) even though this name is locally typed —
        // a pasted control/bidi/zero-width run would otherwise round-trip
        // straight into every invitee's eclipse-warning dialog unchanged.
        val sanitizedName = ContactAliasGenerator.sanitizeDisplayName(name)
        // Check the TRUNCATED name — createGroup stores and fans out
        // sanitizedName.take(MAX_GROUP_NAME_CHARS), so a name that is non-blank
        // only in its truncated-away tail (e.g. MAX_GROUP_NAME_CHARS spaces +
        // "X") would pass a raw isBlank() yet persist a locally-blank name AND
        // fan out invites every updated peer silently drops (handleInvite
        // rejects a blank truncated "n").
        if (sanitizedName.take(MAX_GROUP_NAME_CHARS).isBlank()) return null   // reject a blank/whitespace-only (post-truncation) group name
        if (memberContactIds.isEmpty() || memberContactIds.size + 1 > MAX_GROUP_MEMBERS) return null
        val contacts = memberContactIds.map { vault.getContact(it) ?: return null }
        if (memberContactIds.any { !contactFullyPaired(vault, it) }) {
            // Pending (awaiting peer inbox) contacts can't receive the invite;
            // stale ones can't be messaged at all.
            platformLogWarn(TAG, "createGroup refused: a member is not fully paired")
            return null
        }

        val groupId = newGroupId()
        val myId = newMemberId()
        val now = currentTimeMillis()
        val memberIdByContact = contacts.associate { it.contactId to newMemberId() }
        val allIds = memberIdByContact.values + myId

        try {
            // The group row + every member row persist atomically — a torn
            // insert must not leave a half-built group. withTransaction rolls back on any
            // throw, so the deleteGroup in the catch is then a redundant safety net.
            vault.withTransaction {
                vault.insertGroup(
                    GroupRecord(
                        groupId = groupId, name = sanitizedName.take(MAX_GROUP_NAME_CHARS), epoch = 1,
                        adminMemberId = myId, myMemberId = myId, createdAt = now,
                    )
                )
                vault.insertGroupMember(GroupMemberRecord(groupId, myId, contactId = null, addedAt = now))
                for ((contactId, memberId) in memberIdByContact) {
                    vault.insertGroupMember(GroupMemberRecord(groupId, memberId, contactId, addedAt = now))
                }
                // Record OURSELVES as admin-of-record. Without this a
                // group this device created never gets a group_admin tombstone (the
                // ONLY prior writer was acceptInvite), so after we leave/delete it a
                // co-member can silently re-invite us as admin-of-record with no
                // eclipse warning. SELF_ADMIN_MARKER can never equal a real
                // contactId (see its kdoc), so handleInvite's
                // `priorAdmin != inviterContactId` correctly flags ANY re-invite of
                // a self-created group — the creator never invites themselves.
                vault.putMeta(adminMetaKey(groupId), SELF_ADMIN_MARKER)
            }
        } catch (e: Exception) {
            // Fail closed: a half-persisted group must not invite anyone.
            platformLogError(TAG, "createGroup persist failed: ${e::class.simpleName}")
            try { vault.deleteGroup(groupId) } catch (d: Exception) {
                platformLogWarn(TAG, "createGroup cleanup delete failed: ${d::class.simpleName}")
            }
            return null
        }

        val hash = membershipHash(groupId, 1, allIds.toList())
        val memArray = allIds.joinToString(",") { jsonEscapeString(it) }
        fanOutControl(
            targets = memberIdByContact.keys.toList(),
            groupId = groupId,
            kind = KIND_INVITE,
            bodyFor = { contactId ->
                """{"n":${jsonEscapeString(sanitizedName.take(MAX_GROUP_NAME_CHARS))},"ep":1,"adm":${jsonEscapeString(myId)},"you":${jsonEscapeString(memberIdByContact.getValue(contactId))},"mem":[$memArray]}"""
            },
            hash = hash,
            // An invite is USER-VISIBLE: it either raises a consent prompt or (for
            // an already-IRL-verified contact) makes a new group appear. It is the
            // one group control kind worth waking a device for.
            noPush = false,
        )
        // These pairings may predate the group inbox — arm the backfill so the
        // control sweep tops them up before the first group text goes out.
        armGroupInboxBackfillForGroup(groupId)
        return groupId
    }

    /**
     * Admin adds a member. The new member must already be IRL-paired with
     * everyone (the admin's responsibility to verify out-of-band). Bumps the
     * epoch, invites the newcomer, re-rosters everyone else.
     */
    fun addMember(groupId: String, contactId: String): Boolean {
        val g = vault.getGroup(groupId) ?: return false
        if (!g.isAdmin) return false
        if (!contactFullyPaired(vault, contactId)) return false
        val members = vault.getGroupMembers(groupId)
        if (members.any { it.contactId == contactId }) return false
        if (members.size + 1 > MAX_GROUP_MEMBERS) return false

        val newId = newMemberId()
        val newEpoch = g.epoch + 1
        try {
            // The epoch bump + the new member row persist atomically.
            vault.withTransaction {
                vault.insertGroup(g.copy(epoch = newEpoch))
                vault.insertGroupMember(GroupMemberRecord(groupId, newId, contactId, addedAt = currentTimeMillis()))
            }
        } catch (e: Exception) {
            platformLogError(TAG, "addMember persist failed: ${e::class.simpleName}")
            return false
        }

        val allIds = members.map { it.memberId } + newId
        val hash = membershipHash(groupId, newEpoch, allIds)
        val memArray = allIds.joinToString(",") { jsonEscapeString(it) }
        fanOutControl(
            targets = listOf(contactId), groupId = groupId, kind = KIND_INVITE,
            bodyFor = {
                """{"n":${jsonEscapeString(g.name)},"ep":$newEpoch,"adm":${jsonEscapeString(g.adminMemberId)},"you":${jsonEscapeString(newId)},"mem":[$memArray]}"""
            },
            hash = hash,
            // Same reason as createGroup's invite: user-visible, so it wakes.
            noPush = false,
        )
        broadcastRoster(groupId)
        // The newcomer (and every member whose pairing predates the group
        // inbox) may need one minted and announced.
        armGroupInboxBackfillForGroup(groupId)
        return true
    }

    /**
     * Purge the removed member's per-member
     * roster-rate-limit `_meta` residue. [rosterBroadcastAllowed] writes
     * `grp_roster_rl:<groupId>:<contactId>` on every member-triggered JOIN (ordinary
     * participation), and until now ONLY [VaultDatabase.deleteGroup] purged it — so
     * kicking/leaving a member from a group that STAYS ALIVE orphaned a timestamped key
     * naming that contact, reconstructing a membership history the removal appeared to
     * erase. Key shape mirrors [rosterBroadcastAllowed] / `GroupMetaKeys.ROSTER_RL_PREFIX`
     * exactly, so it matches the shared purge predicates
     * (`isGroupMetaResidueForGroup`/`ForContact`). No-op when the member was unresolved
     * (no `contactId` ⇒ no key was ever written); `deleteMeta` is idempotent, so a
     * non-admin device (which never wrote the key) is unaffected. The
     * `group_admin:<groupId>` tombstone is deliberately NOT touched (anti-eclipse).
     * Call INSIDE the removal transaction so it commits atomically with the row delete —
     * a rollback keeps both, so a retry re-drives cleanly.
     */
    private fun purgeRosterRateLimit(groupId: String, contactId: String?) {
        if (contactId == null) return
        vault.deleteMeta(ROSTER_RL_META_PREFIX + groupId + ":" + contactId)
    }

    /**
     * Admin removes a member. The roster excluding them is also sent to the
     * REMOVED member (one final message) so their client deletes the group
     * locally instead of lingering forever. Honest semantics only: nothing
     * can revoke what they already received. Returns true once the LOCAL
     * removal is committed; delivery to each member is either done or held as
     * a durable redrive obligation, never silently dropped.
     */
    fun removeMember(groupId: String, memberId: String): Boolean {
        val g = vault.getGroup(groupId) ?: return false
        if (!g.isAdmin || memberId == g.myMemberId) return false
        val member = vault.getGroupMembers(groupId).firstOrNull { it.memberId == memberId } ?: return false
        try {
            // The delete + the epoch bump are ONE atomic batch. If
            // the epoch write threw after the delete committed, the member was gone
            // locally but the epoch wasn't bumped and the roster never broadcast — and a
            // RETRY early-returned false (member already absent), so removal could never
            // be re-driven while peers kept delivering to the removed member. Rollback
            // keeps the member present so the retry works.
            vault.withTransaction {
                vault.deleteGroupMember(groupId, memberId)
                purgeRosterRateLimit(groupId, member.contactId)   // no orphan roster-rl key
                vault.insertGroup(g.copy(epoch = g.epoch + 1))
            }
        } catch (e: Exception) {
            platformLogError(TAG, "removeMember persist failed: ${e::class.simpleName}")
            return false
        }
        // Their persisted unread units for this group stop lighting it (after the
        // commit — never inside a vault transaction).
        member.contactId?.let { unreadMarkers.detachMember(it, groupId) }
        broadcastRoster(groupId, alsoTo = member.contactId)
        return true
    }

    /**
     * Admin hands the role to another (resolved, joined) member. Epoch bump +
     * roster broadcast; recipients verify the roster came from the CURRENT
     * admin's channel, so only the real admin can transfer.
     *
     * Ordering subtlety: the new admin is persisted FIRST (fail closed — a
     * broadcast for a transfer that didn't persist would split the group),
     * which makes US not-admin by the time the roster goes out. That final
     * roster must still be sent: members only accept rosters from OUR
     * channel until they apply it, so the handoff roster is the one and
     * only message that can move the authority. broadcastRoster's handoff
     * mode exists for exactly this call (a prior version hit its !isAdmin
     * guard and silently dropped the broadcast — the transfer demoted the
     * sender locally and never reached anyone; 3-emulator e2e catch).
     */
    fun transferAdmin(groupId: String, newAdminMemberId: String): Boolean {
        val g = vault.getGroup(groupId) ?: return false
        if (!g.isAdmin || newAdminMemberId == g.myMemberId) return false
        val members = vault.getGroupMembers(groupId)
        val newAdmin = members.firstOrNull { it.memberId == newAdminMemberId } ?: return false
        // REFUSE the handoff while any OTHER member's
        // join is still pending ([joinPending]). This is the one roster caller whose
        // damage is IRREVERSIBLE: [buildRosterBody] can only redistribute a member's
        // bound tag when ANOTHER member carries the same sym, so a member row with
        // empty tags makes every OTHER member's entry tagless too (nothing is mutual
        // with a member we have not heard from). Every other roster caller keeps the
        // admin role here, so the join that lands a second later re-rosters with the
        // full tag set; a HANDOFF moves the only device that can ever redistribute
        // them, and `handleRoster` — the single resolution site — never runs on an
        // admin. The successor is then permanently unable to resolve its co-members,
        // which is exactly the 18:24 `cross:multi3` red ("members=2/2, unresolved=1"
        // on the promoted seat, with the relay journal showing every blob delivered
        // and drained). Returning false is safe for both callers: the plain "make
        // admin" path is a no-op the user can retry, and the handoff-then-leave path
        // is already fail-closed on this boolean and does NOT leave.
        // Time-bounded on purpose — an INHERITED admin's row for its own inviter also
        // carries no tags (`handleRoster` skips an already-resolved slot), so an
        // unbounded guard would make `transferAdmin` permanently impossible for that
        // group. After the window the transfer proceeds with its known incompleteness
        // rather than dead-ending the UI.
        if (members.any { joinPending(g, it, clockMs(), fastAnchor.anchor(groupId)) }) {
            platformLogWarn(TAG, "transferAdmin refused: a member's join has not been applied yet")
            return false
        }
        try {
            vault.withTransaction {
                vault.insertGroup(g.copy(adminMemberId = newAdminMemberId, epoch = g.epoch + 1))
                // Keep OUR OWN group_admin tombstone in step with a
                // transfer we ourselves are performing — the new admin becomes
                // admin-of-record, so a later re-invite BY THEM is not flagged,
                // while a re-invite by anyone else still is. Guarded on a resolved
                // contactId (always true from the UI, which only offers resolved
                // members per sendSelfJoinToNewAdmin's comment above) so an
                // unresolved slot can't write a null/garbage tombstone value.
                newAdmin.contactId?.let { vault.putMeta(adminMetaKey(groupId), it) }
            }
        } catch (e: Exception) {
            platformLogError(TAG, "transferAdmin persist failed: ${e::class.simpleName}")
            return false
        }
        broadcastRoster(groupId, handoff = true)
        // Post-handoff resolution: hand the successor OUR
        // resolution tags via a self-join. The creator/original admin never sent a
        // KIND_JOIN, so no successor admin holds our join-syms — and members resolve
        // each other ONLY through the current admin's mutual-sym redistribution. Without
        // this, after a handoff the new admin can neither redistribute a tag that
        // resolves US (a member added later can never resolve the ex-admin) NOR detect
        // that a newly-joined member is paired with US (WE can never resolve that member)
        // — the symmetric halves of the same missing-sym gap. Replanting our join on the
        // successor restores BOTH directions through the existing mechanism. Sent AFTER
        // the handoff roster (lower control-counter) so the successor has already applied
        // the roster and is admin (handleJoin requires isAdmin) by the time it lands. No
        // send when the successor is unresolved (can't happen from the UI, which only
        // offers resolved members).
        newAdmin.contactId?.let { sendSelfJoinToNewAdmin(groupId, it, g.myMemberId) }
        return true
    }

    /** Post-handoff resolution: fan our own KIND_JOIN (tag list bound to [myMemberId]) to the new
     *  admin so it can redistribute our resolution tags. Mirrors [acceptInvite]'s
     *  join, addressed to the successor instead of the inviter. */
    private fun sendSelfJoinToNewAdmin(groupId: String, newAdminContactId: String, myMemberId: String) {
        val g = vault.getGroup(groupId) ?: return
        val hash = membershipHash(groupId, g.epoch, vault.getGroupMembers(groupId).map { it.memberId })
        val joinBody = buildJoinBody(groupId, myMemberId)
        // noPush: a join is protocol bookkeeping for the admin's roster, not
        // something a human acts on.
        fanOutControl(listOf(newAdminContactId), groupId, KIND_JOIN, bodyFor = { joinBody }, hash = hash, noPush = true)
    }

    /** ObjC-export-friendly overload (Kotlin default args don't reach Swift). */
    fun leaveGroup(groupId: String) = leaveGroup(groupId, null)

    /**
     * Leaves the group: LOCAL deletion first, then best-effort leave
     * notices to all resolved members. Needs no authority — anyone may
     * leave. If the ADMIN leaves without transferring, the group's
     * membership is frozen for the remaining members (messaging still
     * works) — transfer first.
     *
     * Local-first ordering: leaving is the user's unilateral decision and
     * the group must vanish from their UI immediately — the notices are a
     * courtesy that can take seconds per member (jittered fan-out, Tor
     * round-trips) and must not gate the visible state. Everything the
     * fan-out needs (targets, hash) is snapshotted before the delete, and
     * the send path reads only contact/inbox/counter state, none of which
     * the delete touches. [onLocalDelete] fires right after the local
     * delete, BEFORE the slow fan-out — UIs hook their refresh here.
     */
    fun leaveGroup(groupId: String, onLocalDelete: (() -> Unit)?) {
        val g = vault.getGroup(groupId) ?: return
        val members = vault.getGroupMembers(groupId)
        val hash = membershipHash(groupId, g.epoch, members.map { it.memberId })
        val targets = members.mapNotNull { it.contactId }
        buffers.purgeGroupFromScreens(groupId)
        try { vault.deleteGroup(groupId) } catch (e: Exception) {
            platformLogWarn(TAG, "leaveGroup local delete failed: ${e::class.simpleName}")
        }
        // The persisted unread units naming this group are DETACHED, not deleted: the
        // key is per contact (purged with the contact), and a text for the left group
        // still sits on that sender's group inbox, so it must keep suppressing the
        // presence bump on the groups we still share — it just names no group now.
        unreadMarkers.detachGroup(groupId)
        onLocalDelete?.invoke()
        // noPush: a departure updates the roster silently; it is not a message.
        // The body names the epoch we left at AND our memberId, so a copy
        // that is redriven after a RE-JOIN of the same groupId is recognisably stale
        // on the receiver ([handleLeave]) instead of evicting us again.
        val body = leaveBody(g.epoch, g.myMemberId)
        val failed = fanOutControl(targets, groupId, KIND_LEAVE, bodyFor = { body }, hash = hash, noPush = true)
        // Written AFTER the local deleteGroup so the group-residue purge does
        // not sweep it; the obligation carries the hash because the members are gone.
        // ONLY the undelivered targets are recorded. A delivered target gets no
        // AWAITING-ACK record: an acknowledgement is impossible once the group is
        // gone locally ([noteMembershipView] returns at `getGroup(groupId) ?: return`),
        // so such a record could only sit in `_meta` holding the left group's roster
        // (contactIds, epoch, our memberId) until its resend bounds ran out.
        ctlRedrive.record(groupId, KIND_LEAVE, g.epoch, hash, failed, delivered = emptyList(), leaverMemberId = g.myMemberId)
    }

    /**
     * Broadcasts the admin's authoritative roster. Each member entry carries
     * only the pairwise tags that MATCHED between two members' join lists
     * (dummies and non-member tags never match and are never redistributed).
     * The admin's own entry carries tags it computes directly from its
     * pairwise secrets.
     */
    private fun broadcastRoster(
        groupId: String,
        alsoTo: String? = null,
        // True ONLY for the admin-transfer handoff: the caller has just
        // persisted itself out of the admin role but is still the only
        // channel members accept rosters from. Every other caller must be
        // the current admin — non-admin rosters are dropped by receivers
        // anyway (channel check), this guard just saves the wasted sends.
        handoff: Boolean = false,
    ) {
        val g = vault.getGroup(groupId) ?: return
        if (!g.isAdmin && !handoff) return
        val members = vault.getGroupMembers(groupId)
        val hash = membershipHash(groupId, g.epoch, members.map { it.memberId })
        val body = buildRosterBody(groupId) ?: return
        val targets = members.mapNotNull { it.contactId } + listOfNotNull(alsoTo)
        // noPush: membership sync — pure bookkeeping, and it fans to EVERY member
        // on every epoch change, so a wake here would be the noisiest kind of all.
        val failed = fanOutControl(targets, groupId, KIND_ROSTER, bodyFor = { body }, hash = hash, noPush = true)
        // Every member that missed this roster — including the REMOVED member's
        // one final copy (alsoTo), which is what makes them stop polling — becomes a
        // durable obligation the control sweep redrives.
        ctlRedrive.record(groupId, KIND_ROSTER, g.epoch, hash, failed, delivered = targets)
    }

    /**
     * The authoritative-roster JSON body from the CURRENT vault state. Split out of
     * [broadcastRoster] (which owns the isAdmin/handoff gate + targets + hash) so the
     * resolution unit tests can observe exactly what an admin would advertise.
     */
    internal fun buildRosterBody(groupId: String): String? {
        val g = vault.getGroup(groupId) ?: return null
        val members = vault.getGroupMembers(groupId)

        // Each stored tag is "sym:bound". Detect which pairings are
        // MUTUAL via the SYMMETRIC halves (two members carrying the same sym are
        // paired — opaque to us), but redistribute only the memberId-BOUND halves
        // so a peer can resolve a member ONLY at that member's real slot.
        // symTag -> memberIds whose join carried it.
        val symOwners = mutableMapOf<String, MutableList<String>>()
        for (m in members) {
            for (pair in m.tags.split(';')) {
                val sym = pair.substringBefore(':', "")
                if (sym.isNotEmpty()) symOwners.getOrPut(sym) { mutableListOf() }.add(m.memberId)
            }
        }
        // Admin's own bound tags toward each resolved member, bound to the
        // admin's memberId, so every member resolves the admin at the admin slot.
        val adminBoundTags = members.mapNotNull { m ->
            val c = m.contactId?.let { vault.getContact(it) } ?: return@mapNotNull null
            boundTag(c.sharedSecret, groupId, g.myMemberId)
        }

        val entries = members.joinToString(",") { m ->
            val tags = if (m.memberId == g.myMemberId) {
                adminBoundTags
            } else {
                m.tags.split(';').mapNotNull { pair ->
                    val sym = pair.substringBefore(':', "")
                    val bound = pair.substringAfter(':', "")
                    // Redistribute the bound half only for MUTUAL syms (another
                    // member carried the same sym → the two are paired).
                    if (sym.isNotEmpty() && bound.isNotEmpty() &&
                        symOwners[sym]?.any { it != m.memberId } == true) bound else null
                }
            }
            jsonEscapeString(m.memberId + ":" + tags.joinToString(";"))
        }
        return """{"n":${jsonEscapeString(g.name)},"ep":${g.epoch},"adm":${jsonEscapeString(g.adminMemberId)},"mem":[$entries]}"""
    }

    // -----------------------------------------------------------------------
    // Control message handling — the receive side of the protocol.
    // -----------------------------------------------------------------------

    internal fun handleControl(
        senderContactId: String,
        groupId: String,
        kind: String,
        body: String,
        // The envelope's "t" — the sender's minute-rounded CAPTURE time, already
        // inside the AEAD like every other envelope field. Only [KIND_SCREENSHOT]
        // reads it, and only for DISPLAY (it is peer-controlled; expiry and ordering
        // use our own receive clock). Defaulted to 0 so the callers that have no
        // envelope in hand are unchanged; [ingest] passes `rm.timestamp`.
        timestampMs: Long = 0L,
    ) {
        when (kind) {
            KIND_INVITE     -> handleInvite(senderContactId, groupId, body)
            KIND_JOIN       -> handleJoin(senderContactId, groupId, body)
            KIND_ROSTER     -> handleRoster(senderContactId, groupId, body)
            KIND_LEAVE      -> handleLeave(senderContactId, groupId, body)
            KIND_ACTIVITY   -> handleActivity(senderContactId, groupId, body, timestampMs)
            KIND_SCREENSHOT -> handleScreenshotNotice(senderContactId, groupId, timestampMs)
            // FORWARD COMPAT: an unknown kind is DROPPED SILENTLY — one warn line,
            // no throw, no vault mutation, nothing rendered. This is what lets a
            // newer build introduce a control kind (KIND_SCREENSHOT was the last
            // one) without breaking any peer that predates it, and the body is
            // never parsed, so an unknown kind cannot reach any parser either.
            else            -> platformLogWarn(TAG, "unknown control kind dropped")
        }
    }

    /** _meta key holding the FIRST admin-of-record contactId for a
     *  groupId. Lives in the vault `_meta` table, which deleteGroup does NOT touch,
     *  so it survives a leave/removal and lets a later different-admin invite be
     *  flagged. Namespaced to avoid collision with other _meta keys. */
    private fun adminMetaKey(groupId: String): String = "group_admin:$groupId"

    /** Invite from a paired (IRL-verified) contact. Consent gate: this does
     *  NOT auto-join and does NOT disclose any tag — it PARKS the invite for the
     *  user's decision (see pendingInvites / acceptInvite). Only acceptInvite joins +
     *  sends our tag list back so the admin can introduce us to the others. */
    /** The peer-controlled fields of a KIND_INVITE body, after every bound. */
    private class InviteFields(
        val name: String,
        val epoch: Long,
        val adminMemberId: String,
        val myMemberId: String,
        val memberIds: List<String>,
    )

    /** Parses and bounds a KIND_INVITE body; null on anything malformed (the
     *  invite is then dropped silently, exactly as before — never parked). Pure. */
    private fun parseInviteBody(body: String): InviteFields? {
        // Sanitise BEFORE truncating — a peer-supplied name may carry
        // newlines/controls/bidi-overrides/zero-width runs that would otherwise
        // survive into the eclipse-warning consent dialog (RuneDialog / SwiftUI
        // alert) and push its trailing "only join if you trust…" clause off
        // screen or visually reverse the sentence.
        val name = firstStringFieldAnywhere(body, "n")?.let { ContactAliasGenerator.sanitizeDisplayName(it) }
            ?.take(MAX_GROUP_NAME_CHARS)?.takeIf { it.isNotBlank() } ?: return null
        val ep = topLevelLong(body, "ep") ?: return null
        val adm = firstStringFieldAnywhere(body, "adm") ?: return null
        val you = firstStringFieldAnywhere(body, "you") ?: return null
        val mem = parseStringArrayField(body, "mem") ?: return null
        // Bound the initial invite epoch so a malicious invite
        // can't seed a near-Long.MAX epoch that later overflows the roster compare.
        if (ep < 1 || ep > MAX_GROUP_EPOCH || !isValidMemberId(adm) || !isValidMemberId(you)) return null
        if (mem.size > MAX_GROUP_MEMBERS || mem.any { !isValidMemberId(it) }) return null
        if (adm !in mem || you !in mem || adm == you) return null
        return InviteFields(name, ep, adm, you, mem)
    }

    private fun handleInvite(senderContactId: String, groupId: String, body: String) {
        if (vault.getGroup(groupId) != null) return  // already a member
        val fields = parseInviteBody(body) ?: return
        val name = fields.name
        val ep = fields.epoch
        val adm = fields.adminMemberId
        val you = fields.myMemberId
        val mem = fields.memberIds
        // Invites arrive on a pairwise channel, so the sender is a known contact;
        // its alias labels the consent prompt. Drop if somehow unknown.
        val inviterAlias = vault.getContact(senderContactId)?.alias ?: return

        // "Admin" is TRUST-ON-FIRST-INVITE — there is no binding
        // between a groupId and its true creator, so a co-member who re-invites a
        // victim after they leave/are-removed (deleteGroup leaves the group tables
        // empty but the group_admin tombstone below SURVIVES) can install itself as
        // the victim's admin-of-record. Flag the invite when this device has
        // previously held this groupId under a DIFFERENT admin contact, so the
        // consent UI can warn instead of the victim silently "rejoining" under a new
        // admin. (Known limitation: the creation-race variant is bounded only by the
        // alias shown in the consent prompt — a full fix needs long-term identities the design
        // deliberately lacks.)
        val (adminMismatch, priorAdminAlias) = adminEclipseCheck(groupId, senderContactId)
        if (adminMismatch) {
            platformLogWarn(TAG, "group invite names a DIFFERENT admin than this group's first admin — flagging for consent")
        }

        // Consent gate: do NOT auto-join and do NOT disclose any tag.
        // Park the invite for the user to accept/decline. Bound abuse BEFORE
        // parking so a contact can't flood pending invites (memory/UI DoS): the
        // cap counts pending + already-joined groups from this contact.
        //
        // The candidate is built here (identical fields to what would be parked) so
        // its declineTokenFor matches the token declineInvite stored for the same
        // offer — declineTokenFor ignores the cosmetic groupName/adminMismatch/alias.
        val candidate = GroupInvite(
            groupId = groupId, inviterContactId = senderContactId,
            inviterAlias = inviterAlias, groupName = name,
            epoch = ep, adminMemberId = adm, myMemberId = you, memberIds = mem,
            adminMismatch = adminMismatch, priorAdminAlias = priorAdminAlias,
        )
        // The RAM park decision is made under [pendingInviteLock]; the durable
        // mirror write is made AFTER the lock is released (see the field comment
        // above [pendingInviteLock]). [parked] is true only on the branch that
        // actually inserted into [pendingInvites], so a suppressed / deduped /
        // rate-limited / already-joined invite persists nothing and logs nothing.
        val parked = pendingInviteLock.withLock {
            // Per-offer decline tombstone: a re-delivery of an offer the user
            // already declined must NOT re-park, re-prompt, or spend rate budget.
            // Checked under [pendingInviteLock] (which guards declinedInvites) and
            // BEFORE the inviteAllowed() stamp below, so a suppressed re-delivery eats
            // no budget. A tombstone-load failure earlier failed TOWARD EMPTY, so this
            // can only ever suppress an offer the user genuinely declined, never a new
            // one. A genuinely NEW offer (different epoch/members/inviter) hashes
            // differently and falls through to the normal parking path.
            if (declineTokenFor(candidate) in declinedInvites) {
                platformLogWarn(TAG, "invite suppressed — this exact offer was previously declined")
                return
            }
            if (groupId in pendingInvites) return  // already parked — dedup re-sends
            val pendingFromContact = pendingInvites.values.count { it.inviterContactId == senderContactId }
            if (!inviteAllowed(senderContactId, currentTimeMillis(), pendingFromContact)) {
                platformLogWarn(TAG, "invite dropped: forced-join cap/rate-limit exceeded for contact")
                return
            }
            // TOCTOU close: re-check membership immediately before the park. The
            // top-of-function guard above (`vault.getGroup(groupId) != null`) was
            // evaluated before this lock was ever taken, and acceptInvite commits
            // the group + drops the park OUTSIDE this lock — so a redelivery of
            // this same invite that interleaves with a concurrent accept could
            // otherwise re-park an offer for a group the user just joined. Mirrors
            // acceptInvite's own "already joined" re-check. getGroup is a single
            // keyed-row read (indexed lookup, no scan, on both actuals).
            // NOTE: this is NOT the only vault read under this lock — the
            // [inviteAllowed] call above runs [forcedGroupCountFrom], a full
            // getAllGroups() + getGroupMembers()-per-group scan. Moving that scan
            // out of the lock changes when the cap is evaluated relative to a
            // concurrent accept, so it is a separate, reviewed change.
            if (vault.getGroup(groupId) != null) return
            pendingInvites[groupId] = candidate
            true
        }
        if (parked) {
            // Mirror the park into the vault so backgrounding (which tears the whole
            // session down) does not destroy an invite the user has SEEN but not
            // answered. FAIL-SOFT: a refused write degrades this invite to RAM-only
            // for the session — the prompt still shows, the accept still joins — and
            // it must never break the consent gate. Issued OUTSIDE [pendingInviteLock]
            // — record() does a full `_meta` key scan + per-row reads + a
            // transaction, which must never run while that lock (taken by
            // [pendingInvites] every 4 s on the main thread on both platforms) is
            // held. RAM and disk can momentarily diverge (a concurrent decline or
            // accept could in principle land between the two) — the RAM state stays
            // authoritative for THIS session, and a stray/late row is self-healing:
            // [resolveParkedInvite] drops any row for an already-joined group or a
            // tombstoned (declined) offer on the very next rehydrate, so the window
            // costs at most one extra `_meta` row until the next unlock, never a
            // resurrected prompt.
            inviteStore.record(candidate)
            platformLog(TAG, "group invite parked for consent (${mem.size} members)")
        }
    }

    /** Invites awaiting the user's decision, for the consent UI. */
    fun pendingInvites(): List<GroupInvite> = pendingInviteLock.withLock { pendingInvites.values.toList() }

    /**
     * Builds our KIND_JOIN body: our tag list for ALL contacts (we don't yet know
     * who the other members are), padded with random dummies so the admin sees only
     * a coarse count bucket. Each entry is "sym:bound" — the symmetric
     * pairTag (lets the admin detect which pairings are MUTUAL, opaque to it) plus
     * the memberId-bound tag (bound to [myMemberId], so a peer can only resolve us at
     * our real slot). Shared by [acceptInvite] and [sendSelfJoinToNewAdmin] so both
     * disclose an identically-shaped list. `internal` for the resolution unit tests.
     */
    internal fun buildJoinBody(groupId: String, myMemberId: String): String {
        val realTags = vault.getAllContacts().map {
            pairTag(it.sharedSecret, groupId) + ":" + boundTag(it.sharedSecret, groupId, myMemberId)
        }
        val padded = realTags.toMutableList()
        while (padded.size % TAG_PAD_MULTIPLE != 0 || padded.isEmpty()) {
            // Pair-shaped dummy so it's indistinguishable from a real entry.
            padded.add(bytesToHex(generateSecureRandom(8)) + ":" + bytesToHex(generateSecureRandom(8)))
        }
        padded.secureShuffle()
        return """{"you":${jsonEscapeString(myMemberId)},"tags":[${padded.joinToString(",") { jsonEscapeString(it) }}]}"""
    }

    /** The user declined a parked invite — drop it AND tombstone this exact
     *  offer so a re-delivery of the SAME offer stays declined (handleInvite suppresses
     *  it) while a genuinely new offer still prompts. No parked invite → no-op (as
     *  before). Persist is fail-soft: a store write refusal degrades the tombstone to
     *  RAM-only for this session (the offer may re-prompt after a restart) but must
     *  NEVER break the decline or a later accept. */
    fun declineInvite(groupId: String) {
        pendingInviteLock.withLock {
            val invite = pendingInvites[groupId] ?: return@withLock  // nothing parked
            // Tombstone the offer BEFORE forgetting it, oldest-evicts past the cap.
            declinedInvites.add(declineTokenFor(invite))
            while (declinedInvites.size > MAX_DECLINED_INVITES) {
                declinedInvites.remove(declinedInvites.iterator().next())
            }
            pendingInvites.remove(groupId)
            persistDeclinedInvites()
            // …and drop the durable park, so the next unlock does not re-prompt.
            // Ordering: the tombstone is written FIRST, so an interruption between
            // the two leaves a row the rehydrate suppresses (and deletes) on sight
            // rather than an offer that can silently re-prompt.
            inviteStore.remove(invite.groupId, invite.inviterContactId)
        }
    }

    /** Persist the capped decline tombstone into DECLINED_INVITE_META. Fail-soft
     *  (NEVER throws): a store write error (any DB/`_meta` upsert failure) only costs
     *  durability, never the decline or a later accept — so it logs and continues,
     *  degrading to RAM-only for the session. Call with [pendingInviteLock] held
     *  (it reads declinedInvites); the vault write is the group `_meta` (SQLCipher)
     *  singleton via getMeta/putMeta, not a Keychain-journalled credential — a locked
     *  keybag does not gate this SQLCipher write — so a plain putMeta is correct. */
    private fun persistDeclinedInvites() {
        try {
            vault.putMeta(DECLINED_INVITE_META, encodeDeclinedInvites(declinedInvites, MAX_DECLINED_INVITES))
        } catch (e: Exception) {
            platformLogWarn(TAG, "declined-invite tombstone persist failed (RAM-only this session): ${e::class.simpleName}")
        }
    }

    /** The user accepted a parked invite. Only NOW do what the old
     *  auto-join did — persist the group + members and fan out our KIND_JOIN
     *  (disclosing the contact-tag list, now with the user's consent). Returns
     *  false if there is no such pending invite (already handled, or expired /
     *  from a since-deleted contact, so the rehydrate dropped it) or the persist
     *  fails. Blocking (vault + network fan-out) — call off the main thread, like
     *  createGroup. */
    fun acceptInvite(groupId: String): Boolean {
        val invite = pendingInviteLock.withLock { pendingInvites[groupId] } ?: return false
        if (vault.getGroup(groupId) != null) {          // already joined — just clear the prompt
            pendingInviteLock.withLock { pendingInvites.remove(groupId) }
            inviteStore.remove(invite.groupId, invite.inviterContactId)
            return true
        }
        val now = currentTimeMillis()
        try {
            // The most security-relevant atomic write: the group, its member
            // rows, AND the first-admin tombstone persist ATOMICALLY. A tear that committed
            // the group+members but not the tombstone would leave the group joined with the
            // admin-of-record missing — so a later malicious re-invite under a DIFFERENT
            // admin would slip past the adminMismatch guard (handleInvite). All-or-nothing
            // closes that window. On any throw withTransaction rolls back; the deleteGroup in
            // the catch is then a redundant safety net.
            vault.withTransaction {
                vault.insertGroup(
                    GroupRecord(
                        groupId = invite.groupId, name = invite.groupName, epoch = invite.epoch,
                        adminMemberId = invite.adminMemberId, myMemberId = invite.myMemberId, createdAt = now,
                    )
                )
                for (id in invite.memberIds) {
                    vault.insertGroupMember(
                        GroupMemberRecord(
                            groupId = invite.groupId, memberId = id,
                            // The inviter's channel resolves the admin; we are
                            // "you"; everyone else resolves via roster tags.
                            contactId = if (id == invite.adminMemberId) invite.inviterContactId else null,
                            addedAt = now,
                        )
                    )
                }
                // Record the FIRST admin-of-record for this groupId in a
                // tombstone that SURVIVES deleteGroup (leave/removal) — first-admin-wins,
                // never overwritten. A later invite naming a different admin is then
                // flagged in handleInvite so the victim can't be silently eclipsed.
                if (vault.getMeta(adminMetaKey(invite.groupId)) == null) {
                    vault.putMeta(adminMetaKey(invite.groupId), invite.inviterContactId)
                }
            }
        } catch (e: Exception) {
            platformLogError(TAG, "invite accept persist failed: ${e::class.simpleName}")
            // Redundant after the rollback on both actuals; kept until their
            // withTransaction atomicity is pinned (plan-only P9), and then removed
            // together with the compensating re-record below.
            try { vault.deleteGroup(invite.groupId) } catch (d: Exception) {
                platformLogWarn(TAG, "invite accept cleanup delete failed: ${d::class.simpleName}")
            }
            // The rollback above runs the GROUP residue purge, which legitimately
            // includes this invite's own durable park ([isGroupInviteResidueForGroup]).
            // Put it back: a FAILED accept must leave an invite the user can retry
            // after a relaunch, not silently consume it. Re-stamped, which is correct
            // — trying to accept is genuine, user-driven activity on this offer.
            inviteStore.record(invite)
            return false
        }
        // Committed: drop the prompt so a re-poll can't re-park it. The durable park
        // goes AFTER the commit, never inside the transaction: if this delete is the
        // one that fails, the rehydrate sees a row for an already-joined group and
        // self-heals by dropping it (resolveParkedInvite), whereas a delete rolled
        // back with the join would resurrect a prompt for a group already joined.
        pendingInviteLock.withLock { pendingInvites.remove(groupId) }
        inviteStore.remove(invite.groupId, invite.inviterContactId)
        // Fast-window re-anchor: the local half of a membership event. This accept is what
        // CREATES the unresolved slots (only the inviter resolves above), so the
        // join→roster→resolve chain starts here and must run on the fast cadence even
        // when a rehydrated invite's rows carry an older `addedAt`.
        noteUnresolvedFastAnchor(invite.groupId)
        // Joining a group is the moment a pairing starts carrying group text.
        armGroupInboxBackfillForGroup(invite.groupId)
        armGroupInboxBackfill(invite.inviterContactId)
        // We are a member of this groupId again — every obligation recorded
        // for its PREVIOUS incarnation is now stale, and a surviving KIND_LEAVE one
        // would kick us straight back out of the group we just joined on every peer
        // that missed the original. Purged AFTER the commit (the transaction owns
        // nothing here) and before the join fan-out.
        ctlRedrive.purgeForGroup(invite.groupId)

        // We are now a member (the group row is committed and the inviter is
        // resolved): replay any activity notice we parked while this was still just
        // an invite, so the group's first message lights its dot the moment we join.
        // Non-inviter members stay parked until their roster resolves them.
        buffers.flushResolvedActivityNotices()

        // Consent given → NOW disclose our tag list and announce the join.
        val hash = membershipHash(invite.groupId, invite.epoch, invite.memberIds)
        val joinBody = buildJoinBody(invite.groupId, invite.myMemberId)
        // noPush: see sendSelfJoinToNewAdmin — a join is roster bookkeeping.
        fanOutControl(listOf(invite.inviterContactId), invite.groupId, KIND_JOIN, bodyFor = { joinBody }, hash = hash, noPush = true)
        platformLog(TAG, "group invite accepted (${invite.memberIds.size} members)")
        return true
    }

    /** How many groups this contact has ALREADY forced us into — i.e.
     *  groups where we are a non-admin member and this contact is the group's
     *  admin (the inviter is stored as the admin member in acceptInvite). Purely
     *  derived from persisted state, so it needs no timestamps and cannot be
     *  reset by a clock rollback — the clock-independent backstop for the cap. */
    private fun forcedGroupCountFrom(contactId: String): Int =
        vault.getAllGroups().count { g ->
            !g.isAdmin && vault.getGroupMembers(g.groupId)
                .any { it.memberId == g.adminMemberId && it.contactId == contactId }
        }

    // The re-invite "eclipse" check behind the consent warning: true when this
    // device has held [groupId] under a DIFFERENT admin contact than
    // [inviterContactId], plus that prior admin's alias when it is resolvable.
    //
    // A READ FAILURE of the admin-of-record tombstone fails toward the WARNING
    // (mismatch = true, no alias): the tombstone may well name another admin, and
    // a transient vault error must not silently suppress the one signal the
    // consent prompt has. The warning is re-derived on every rehydrate (it is not
    // persisted), so a transient failure costs one over-cautious prompt at most.
    private fun adminEclipseCheck(groupId: String, inviterContactId: String): Pair<Boolean, String?> {
        val priorAdmin = try { vault.getMeta(adminMetaKey(groupId)) } catch (e: Exception) {
            platformLogWarn(TAG, "group admin-of-record read failed — flagging the invite as unverifiable: ${e::class.simpleName}")
            return true to null
        }
        val mismatch = priorAdmin != null && priorAdmin != inviterContactId
        val alias = if (mismatch && priorAdmin != null) {
            try { vault.getContact(priorAdmin)?.alias } catch (_: Exception) { null }
        } else null
        return mismatch to alias
    }

    /** Forced-join gate for handleInvite. Returns true (and records the invite in the
     *  rolling window) only if this contact is within BOTH the standing forced-
     *  group cap AND the per-window invite rate; false if either is exceeded —
     *  no new stamp is charged (a window deny still persists the pruned list). Rejecting here stops the invite from being PARKED, so
     *  neither the pending buffer nor (later, on accept) the tag disclosure can
     *  be driven past the cap. [pendingFromContact] is the count of already-
     *  parked invites from this contact (computed by the caller under the pending
     *  lock) so both pending and joined groups count toward the same cap. */
    private fun inviteAllowed(contactId: String, now: Long, pendingFromContact: Int): Boolean {
        if (forcedGroupCountFrom(contactId) + pendingFromContact >= MAX_FORCED_GROUPS_PER_CONTACT) return false
        val key = INVITE_RL_META_PREFIX + contactId
        val admission = RollingWindow.admit(vault.getMeta(key), now, INVITE_RATE_WINDOW_MS, MAX_INVITES_PER_WINDOW)
        vault.putMeta(key, admission.persist)
        return admission.allowed
    }

    /** Join (admin side): store the member's tag list, re-roster everyone. */
    private fun handleJoin(senderContactId: String, groupId: String, body: String) {
        val g = vault.getGroup(groupId) ?: return
        if (!g.isAdmin) return
        val member = vault.getGroupMembers(groupId).firstOrNull { it.contactId == senderContactId }
        if (member == null) {
            platformLogWarn(TAG, "join from non-member contact dropped")
            return
        }
        val you = firstStringFieldAnywhere(body, "you") ?: return
        // The sender must claim the memberId WE assigned to their channel.
        if (you != member.memberId) {
            platformLogWarn(TAG, "join memberId mismatch dropped")
            return
        }
        // Tags are "sym:bound" pairs (see acceptInvite). Validate
        // both halves; store the pairs verbatim for broadcastRoster to split.
        val tags = parseStringArrayField(body, "tags") ?: return
        if (tags.size > MAX_TAGS_PER_MEMBER || tags.any { !isValidTagPair(it) }) return
        val newTagsJoined = tags.joinToString(";")
        // Dedup. Only re-store + re-broadcast the roster when this
        // member's tags actually CHANGED. Otherwise a member re-sending an identical
        // KIND_JOIN forces the admin to fan a full N-member roster to every member each
        // time (1 attacker msg -> N sends x N re-resolutions) — an amplification DoS
        // that also stalls the admin's jittered send loop for its other traffic.
        if (member.tags == newTagsJoined) {
            platformLogWarn(TAG, "duplicate join (unchanged tags) — skipping re-roster")
            return
        }
        try {
            vault.insertGroupMember(member.copy(tags = newTagsJoined))
        } catch (e: Exception) {
            platformLogError(TAG, "join persist failed: ${e::class.simpleName}")
            return
        }
        // Store the (changed) tags above, but THROTTLE the
        // expensive N-member fan-out per member — the dedup above is defeated by
        // attacker-varied padding. The latest tags still propagate on the next
        // allowed roster (any membership change re-rosters).
        if (!rosterBroadcastAllowed(groupId, senderContactId, currentTimeMillis())) {
            platformLogWarn(TAG, "re-roster rate-limited for this member — skipping fan-out")
            return
        }
        broadcastRoster(groupId)
    }

    /** At most one member-triggered roster fan-out per member per
     *  MIN_ROSTER_INTERVAL_MS. Records the broadcast time in meta on allow. A
     *  backward clock jump (now < last) resets the throttle rather than freezing
     *  it. Admin-initiated rosters (add/remove/transfer/leave) are NOT gated —
     *  only the member-driven handleJoin path calls this. */
    internal fun rosterBroadcastAllowed(groupId: String, contactId: String, now: Long): Boolean {
        val key = ROSTER_RL_META_PREFIX + groupId + ":" + contactId
        val last = vault.getMeta(key)?.toLongOrNull()
        if (last == null || now < last || now - last >= MIN_ROSTER_INTERVAL_MS) {
            vault.putMeta(key, now.toString())
            return true
        }
        return false
    }

    /**
     * The warn line a roster at epoch [ep] is dropped with against our stored
     * [current] epoch, or null if the epoch is acceptable. Pure.
     */
    private fun rosterEpochRejection(ep: Long, current: Long): String? {
        if (ep < current) return "stale roster dropped (epoch $ep < $current)"
        // Reject an implausible forward jump so a malicious admin cannot set
        // the epoch to Long.MAX_VALUE and freeze out every future legitimate roster.
        // Compare by SUBTRACTION (ep >= current is guaranteed above,
        // and both are >= 1, so ep - current is in [0, Long.MAX) and cannot overflow)
        // instead of `current + MAX_GROUP_EPOCH_ADVANCE`, which overflows Long when
        // current is near Long.MAX.
        if (ep - current > MAX_GROUP_EPOCH_ADVANCE) return "roster epoch jump too large (ep $ep >> $current) — dropped"
        // Re-enforce the ABSOLUTE epoch cap on the roster path,
        // not just at invite. handleInvite bounds ep<=MAX_GROUP_EPOCH, but without
        // this the stored epoch could drift above the documented cap over successive
        // +MAX_GROUP_EPOCH_ADVANCE roster jumps — make the invariant hold everywhere.
        if (ep > MAX_GROUP_EPOCH) return "roster epoch above absolute cap (ep $ep) — dropped"
        return null
    }

    /**
     * Parses roster entries `"memberId:tag1;tag2;…"` (flat strings keep the
     * pragmatic array parsing — no nested JSON objects) into (memberId, tags).
     * ALL-OR-NOTHING: one malformed entry rejects the whole roster (null). Pure.
     */
    private fun parseRosterEntries(entries: List<String>): List<Pair<String, List<String>>>? {
        val parsed = entries.mapNotNull { e ->
            val idx = e.indexOf(':')
            if (idx != 16) return@mapNotNull null
            val id = e.substring(0, idx)
            val tags = e.substring(idx + 1).split(';').filter { it.isNotEmpty() }
            if (!isValidMemberId(id)) return@mapNotNull null
            if (tags.size > MAX_TAGS_PER_MEMBER || tags.any { !TAG_REGEX.matches(it) }) return@mapNotNull null
            id to tags
        }
        return if (parsed.size != entries.size) null else parsed
    }

    /** Roster (member side): apply iff it came over the ADMIN's channel and
     *  its epoch is not stale. This is the single-admin guarantee. */
    private fun handleRoster(senderContactId: String, groupId: String, body: String) {
        val g = vault.getGroup(groupId) ?: return
        val members = vault.getGroupMembers(groupId)
        val adminContact = members.firstOrNull { it.memberId == g.adminMemberId }?.contactId
        if (adminContact == null || adminContact != senderContactId) {
            platformLogWarn(TAG, "roster from non-admin channel dropped")
            return
        }
        // Blank-name invariant: "n" stays REQUIRED (missing → drop, uniform with
        // ep/adm/mem below), but a PRESENT-but-blank/whitespace "n" KEEPS the existing
        // group name instead of falling through to the g.copy(name = …) rename that would
        // blank the group on every device on every roster — while every other roster
        // effect (membership + epoch + admin) still applies. [g] is the current record
        // fetched at the top of this function and reused at the insertGroup copy below.
        // Sanitise BEFORE truncating — same reasoning as handleInvite;
        // a roster rename is peer-controlled exactly like an invite's name.
        val name = (firstStringFieldAnywhere(body, "n")?.let { ContactAliasGenerator.sanitizeDisplayName(it) }
            ?.take(MAX_GROUP_NAME_CHARS) ?: return)
            .takeIf { it.isNotBlank() } ?: g.name
        val ep = topLevelLong(body, "ep") ?: return
        val adm = firstStringFieldAnywhere(body, "adm") ?: return
        val entries = parseStringArrayField(body, "mem") ?: return
        rosterEpochRejection(ep, g.epoch)?.let { platformLogWarn(TAG, it); return }
        if (!isValidMemberId(adm) || entries.size > MAX_GROUP_MEMBERS) return

        val parsed = parseRosterEntries(entries) ?: run {
            platformLogWarn(TAG, "malformed roster entry dropped")
            return
        }
        val newIds = parsed.map { it.first }.toSet()
        if (adm !in newIds) return

        // Our id absent → the admin removed us. Honor it locally.
        if (g.myMemberId !in newIds) {
            platformLog(TAG, "removed from group by admin — deleting locally")
            buffers.purgeGroupFromScreens(groupId)
            // A failure leaves the group live and polled; the roster blob is already
            // processed, so nothing redrives it — at least say so.
            try { vault.deleteGroup(groupId) } catch (e: Exception) {
                platformLogWarn(TAG, "removed-from-group local delete failed: ${e::class.simpleName}")
            }
            unreadMarkers.detachGroup(groupId)   // same rule as leaveGroup
            return
        }

        // Apply: group row, removals, additions, tag-based resolution.
        // This roster is already channel-authenticated as coming from
        // the CURRENT admin-of-record (the sender check above). If it also changes
        // who the admin IS, that is a legitimate transfer we are witnessing
        // first-hand — mirror it into OUR OWN group_admin tombstone so a later
        // re-invite by the new admin isn't flagged, while a re-invite by anyone
        // else still is. adminChanged is computed against the PRE-roster admin id.
        val adminChanged = adm != g.adminMemberId
        try {
            // The group-row update, member removals, and re-resolutions apply
            // ATOMICALLY — a torn roster must not leave the group half-reconciled (a member
            // deleted but the epoch/admin not updated, or resolutions half-written). The
            // "was removed" notices are an in-memory-buffer courtesy, so collect them inside
            // the transaction and fire them AFTER commit — keeps the buffer lock out of the
            // DB-lock scope and stops an announce failure from rolling back a valid roster.
            val removed = mutableListOf<Pair<String, String>>()   // (memberId, contactId)
            vault.withTransaction {
                removed += applyRosterInTxn(groupId, g, members, parsed, newIds, name, ep, adm, adminChanged)
            }
            // Post-commit: announce removals (deduped against a voluntary leave's
            // "left" notice inside announceDeparture).
            for ((memberId, contactId) in removed) {
                announceDeparture(groupId, memberId, contactId, NOTICE_REMOVED_KEY)
                unreadMarkers.detachMember(contactId, groupId)
            }
            // Unresolved-sender buffer: this roster may have just RESOLVED a member whose group text we
            // buffered while it was unresolved — surface any now-attributable texts.
            buffers.flushResolvedGroupTexts()
            // …and any ACTIVITY NOTICE parked for a member this roster just resolved:
            // replay it so that sender's first group message lights the group dot
            // (same resolution point, same reason).
            buffers.flushResolvedActivityNotices()
        } catch (e: Exception) {
            platformLogError(TAG, "roster apply failed: ${e::class.simpleName}")
        }
    }

    /**
     * [handleRoster]'s write set, in its original order: the group row, the
     * removals (with their roster-rate-limit residue), the tag-based resolutions and
     * the admin-of-record tombstone. Runs ONLY inside the caller's
     * [VaultDatabase.withTransaction]; returns the resolved members it removed as
     * (memberId, contactId), for the post-commit departure notices.
     */
    private fun applyRosterInTxn(
        groupId: String,
        g: GroupRecord,
        members: List<GroupMemberRecord>,
        parsed: List<Pair<String, List<String>>>,
        newIds: Set<String>,
        name: String,
        ep: Long,
        adm: String,
        adminChanged: Boolean,
    ): List<Pair<String, String>> {
        val removed = mutableListOf<Pair<String, String>>()
        vault.insertGroup(g.copy(name = name, epoch = ep, adminMemberId = adm))
        for (m in members) {
            if (m.memberId !in newIds) {
                vault.deleteGroupMember(groupId, m.memberId)
                purgeRosterRateLimit(groupId, m.contactId)   // no orphan roster-rl key
                // Admin dropped a member we knew (resolved) → "was removed".
                // Skip unresolved placeholders (the user never knew them).
                if (m.contactId != null) removed.add(m.memberId to m.contactId)
            }
        }
        val byId = members.associateBy { it.memberId }
        val myContacts = vault.getAllContacts()
        val usedContactIds = members.mapNotNull { it.contactId }.toMutableSet()
        // The new admin's identity as WE resolve it this roster —
        // seeded from an already-resolved prior row, then possibly refined below.
        // Only consulted when adminChanged (see above).
        var newAdminContactId: String? = byId[adm]?.contactId
        for ((id, tags) in parsed) {
            val existing = byId[id]
            if (existing != null && existing.contactId != null) continue   // already resolved
            if (id == g.myMemberId) {
                if (existing == null) vault.insertGroupMember(
                    GroupMemberRecord(groupId, id, null, currentTimeMillis())
                )
                // We ourselves are the (new) admin — no contactId represents
                // "us" in the tombstone; use the same self-marker createGroup does.
                if (id == adm) newAdminContactId = SELF_ADMIN_MARKER
                continue
            }
            // Resolve by recomputing the BOUND tag with
            // THIS slot's memberId. A tag matches only if the advertiser bound
            // it to the same memberId — so a malicious admin cannot move a
            // contact's tag to an arbitrary slot (a memberId-independent tag
            // match would NOT prove the slot was that contact). One contact
            // backs at most one member (a
            // duplicate claim is admin misbehavior — skip it).
            val slotTags = tags.toHashSet()
            val resolved = myContacts.firstOrNull { boundTag(it.sharedSecret, groupId, id) in slotTags }
                ?.takeIf { it.contactId !in usedContactIds }
            if (resolved != null) usedContactIds.add(resolved.contactId)
            val finalContactId = resolved?.contactId ?: existing?.contactId
            if (id == adm) newAdminContactId = finalContactId
            vault.insertGroupMember(
                GroupMemberRecord(
                    groupId = groupId, memberId = id,
                    contactId = finalContactId,
                    addedAt = existing?.addedAt ?: currentTimeMillis(),
                    tags = tags.joinToString(";"),
                )
            )
        }
        // Only touch the tombstone when THIS roster actually
        // moved admin somewhere (never re-affirm/downgrade it on a no-op
        // reapply), and only when we could identify who to — a
        // still-unresolved new admin leaves the tombstone untouched rather
        // than writing a null/stale value (a later roster can still catch up).
        if (adminChanged) {
            newAdminContactId?.let { vault.putMeta(adminMetaKey(groupId), it) }
        }
        return removed
    }

    /**
     * Leave: removes the SENDER's own membership (channel-authenticated).
     * If we are admin, bump the epoch and re-roster the survivors.
     *
     * **Staleness guards.** A KIND_LEAVE can be redriven
     * for up to 7 days, so one that was recorded before the sender RE-JOINED the
     * same groupId would silently evict them from the group they just joined, on
     * every peer that missed the original. Two OPTIONAL body fields close that; a
     * peer that predates them sends a bare `{}` and is accepted exactly as before.
     *
     *  - **`"you"` — the leaver's own memberId (the precise guard).** MemberIds are
     *    minted per membership instance and a re-join gets a NEW one, so a leave
     *    naming a memberId this slot no longer holds provably predates the current
     *    membership. No false positives: while the slot IS the one that sent the
     *    leave, the ids match whatever the epochs are doing.
     *  - **`"ep"` — the epoch the sender left at.** Applied ONLY when `"you"` is
     *    absent. Deliberately NOT applied on its own when both are present, and this
     *    is the one place this implementation diverges from the obvious
     *    "drop any leave whose epoch is older than ours": the epoch advances ONLY at
     *    the admin, so two members leaving within one jittered fan-out window make
     *    the second leave arrive epoch-stale at an admin that already processed the
     *    first — and dropping it would leave that member in the admin's roster (and
     *    therefore in every subsequent roster) FOREVER, which is exactly the class of
     *    harm the ack-gated redrive exists to remove. The memberId test catches every stale-redrive
     *    case the epoch test would, with none of that cost.
     */
    private fun handleLeave(senderContactId: String, groupId: String, body: String) {
        val g = vault.getGroup(groupId) ?: return
        val member = vault.getGroupMembers(groupId).firstOrNull { it.contactId == senderContactId } ?: return
        val claimedMemberId = firstStringFieldAnywhere(body, "you")
        if (claimedMemberId != null && claimedMemberId != member.memberId) {
            platformLogWarn(TAG, "stale leave dropped (names a memberId this slot no longer holds)")
            return
        }
        if (claimedMemberId == null) {
            val ep = topLevelLong(body, "ep")
            if (ep != null && ep < g.epoch) {
                platformLogWarn(TAG, "stale leave dropped (epoch $ep < ${g.epoch}, no memberId to check)")
                return
            }
        }
        try {
            // The member removal + (if we are admin) the epoch bump apply
            // ATOMICALLY — a tear must not remove the member without re-rostering, or leave
            // the epoch bumped with the member still present. The departure notice + roster
            // broadcast are courtesies (in-memory buffer / network) hoisted OUT of the
            // transaction so they never hold the DB lock and an announce/send failure can't
            // roll back a valid membership change.
            vault.withTransaction {
                vault.deleteGroupMember(groupId, member.memberId)
                purgeRosterRateLimit(groupId, member.contactId)   // no orphan roster-rl key
                if (g.isAdmin) vault.insertGroup(g.copy(epoch = g.epoch + 1))
            }
        } catch (e: Exception) {
            platformLogWarn(TAG, "leave apply failed: ${e::class.simpleName}")
            return
        }
        unreadMarkers.detachMember(senderContactId, groupId)
        // Post a system notice so the remaining members see who left.
        announceDeparture(groupId, member.memberId, senderContactId, NOTICE_LEFT_KEY)
        // If we are admin, re-roster the survivors.
        if (g.isAdmin) broadcastRoster(groupId)
    }

    /** Buffers a one-time "<alias> left the group" / "<alias> was removed from the
     *  group" system message for [memberId]'s departure. [noticeKey] is one of
     *  [NOTICE_LEFT_KEY] / [NOTICE_REMOVED_KEY] — a `strings_shared.xml` resource
     *  key with the alias as `%1$s`, resolved through [platformString] so the
     *  notice renders in the app language on both platforms (English in tests,
     *  via the override seam; the key itself when no resolver is installed).
     *  Deduped per (group, member) so a member's exit is announced exactly once,
     *  whichever signal — KIND_LEAVE or the admin's re-roster — arrives first. */
    private fun announceDeparture(groupId: String, memberId: String, contactId: String?, noticeKey: String) {
        val firstAnnounce = departureLock.withLock {
            departureAnnounced.getOrPut(groupId) { mutableSetOf() }.add(memberId)
        }
        if (!firstAnnounce) return
        val alias = contactId?.let { vault.getContact(it)?.alias } ?: platformString(NOTICE_MEMBER_FALLBACK_KEY)
        buffers.toGroupScreen(
            groupId,
            GroupMessage(
                groupId = groupId,
                senderContactId = contactId ?: "",
                senderAlias = alias,
                text = platformString(noticeKey, alias),
                timestamp = currentTimeMillis(),
                counter = 0,
                sequenceGap = false,
                membershipOk = true,
                isSystem = true,
            )
        )
    }

    /**
     * A peer reported they just sent a group text ([KIND_ACTIVITY]). Bumps the
     * group's unread count and remembers where the text it describes is sitting.
     * Same trust rule as a group text: a known group, sender a current member.
     *
     * **The third inbox split the tally in two, on the `gi` marker
     * ([ACTIVITY_FIELD_GROUP_INBOX]), and the split is the contact-dot invariant:**
     *
     *  - `gi` PRESENT — the text is on that contact's GROUP inbox, which the
     *    contact dot never reads. It is counted in the tally's `gi`-notice count, whose
     *    only job is to say how much of that inbox's /peek depth is already
     *    attributed to a named group (so the rest can raise a presence bump). It
     *    touches the legacy compensator — the contact-dot subtraction — NEVER.
     *  - `gi` ABSENT — a legacy sender, or one still in the backfill window: the
     *    text really IS on the contact's text inbox, so this is byte-for-byte
     *    today's behaviour and today's subtraction is the correct compensator.
     *    That is a deliberate transition cost, and it is provably dead for a converged new↔new
     *    pairing; the machinery goes in release N+2.
     *
     * The `gi` value is peer-controlled, so consider both lies: claiming `gi` for a
     * text sent on the TEXT inbox loses the sender their own subtraction and lights
     * their contact dot — self-harm, no new power; omitting `gi` for a text sent on
     * the GROUP inbox suppresses one unit of that sender's real 1:1 badge, which is
     * exactly the pre-existing flood hazard the [MAX_PENDING_ACTIVITY_PER_MEMBER]
     * ceiling already bounds. Neither can move a group text onto a contact row.
     */
    private fun handleActivity(
        senderContactId: String,
        groupId: String,
        body: String,
        claimedSentAtMs: Long = 0L,
    ) {
        // Stale-notice gate FIRST (it moved ahead of the membership checks so a stale
        // notice is never parked either). Every control append carries the uniform
        // 7-day relay ttl while a group TEXT still expires on the relay's 24 h
        // default, so a device closed for days could drain notices whose texts are
        // long gone and light a group dot with nothing behind it. Ignore a notice
        // older than [MAX_ACTIVITY_NOTICE_AGE_MS]. Suppress-direction only; a missing
        // or zero stamp is accepted exactly as before — see that constant.
        if (claimedSentAtMs > 0L && clockMs() - claimedSentAtMs > MAX_ACTIVITY_NOTICE_AGE_MS) {
            platformLogWarn(TAG, "stale activity notice ignored (older than the text retention)")
            return
        }
        val onGroupInbox = firstStringFieldAnywhere(body, ACTIVITY_FIELD_GROUP_INBOX) == "1"
        // The stamp a persisted `gi` unit carries (its TTL anchor) — see
        // [GroupUnreadMarkerStore.stampFor]. Computed once, so a parked notice keeps it.
        val noticeAtMs = GroupUnreadMarkerStore.stampFor(claimedSentAtMs, clockMs())
        val g = vault.getGroup(groupId)
        if (g == null) {
            // We have not JOINED this group yet. If an invite for it is parked
            // awaiting our consent, this notice describes a real group text that will
            // be sitting unseen the instant we accept — PARK it and replay on accept
            // ([acceptInvite] → flushResolvedActivityNotices), so the very first
            // message into a freshly joined group still lights its dot instead of
            // being lost (the notice is consumed off the relay the moment it drains).
            // Any other unknown group — declined, left, or a stranger's — is dropped
            // exactly as before.
            if (hasPendingInviteForGroup(groupId)) {
                buffers.bufferActivityNotice(groupId, senderContactId, onGroupInbox, noticeAtMs)
            }
            return
        }
        val members = vault.getGroupMembers(groupId)
        if (members.none { it.contactId == senderContactId }) {
            // The sender is not YET a resolved member. If member↔member resolution is
            // still in flight (unresolved slots remain) this is a real member whose
            // roster tags have not landed on this device — PARK the notice and replay
            // it on the roster apply that resolves them ([handleRoster] →
            // flushResolvedActivityNotices), the SAME asymmetry [acceptGroupText]
            // already closes for the group TEXT: dropping it here loses the group dot
            // for that sender's first message for good. Once the roster is FULLY
            // resolved a still-non-member sender is a genuine stranger / removed
            // member, so it is dropped — preserving "a removed member's traffic is
            // dropped".
            val resolutionInFlight = members.any { it.contactId == null && it.memberId != g.myMemberId }
            if (resolutionInFlight) {
                buffers.bufferActivityNotice(groupId, senderContactId, onGroupInbox, noticeAtMs)
            } else {
                platformLogWarn(TAG, "drop: activity notice from non-member contact")
            }
            return
        }
        // Bounded per member on the SUM of the two tallies — see
        // [GroupUnreadTally.noteActivity].
        applyActivityNotice(senderContactId, groupId, onGroupInbox, noticeAtMs)
    }

    /**
     * The ONE entry point an accepted activity notice is counted through — live
     * ([handleActivity]) and parked-then-replayed ([ConversationBuffers.flushResolvedActivityNotices])
     * alike. Counts it into the RAM tally (per-member ceiling there), then — only
     * for a COUNTED `gi` notice — persists the attribution, outside the tally's
     * lock. A notice the ceiling ignored is not persisted; a legacy (no-`gi`)
     * notice stays RAM-only exactly as before. The persist is fail-soft and never
     * throws into the control drain.
     */
    private fun applyActivityNotice(senderContactId: String, groupId: String, onGroupInbox: Boolean, noticeAtMs: Long) {
        val counted = tally.noteActivity(senderContactId, groupId, onGroupInbox)
        if (counted && onGroupInbox) unreadMarkers.record(senderContactId, groupId, noticeAtMs)
    }

    /** True while an invite for [groupId] is parked awaiting the user's consent —
     *  the window in which a group's first text (and its activity notice) can arrive
     *  before we have joined. Scopes the parked-notice buffer to groups we are
     *  actually about to join, so an unknown-group notice from a stranger is still
     *  dropped outright. Sibling of [hasPendingInviteFrom] (keyed by group, not
     *  inviter). Never throws. */
    private fun hasPendingInviteForGroup(groupId: String): Boolean = try {
        pendingInviteLock.withLock { pendingInvites.containsKey(groupId) }
    } catch (_: Exception) { false }

    /**
     * A peer reported taking a screenshot of this group ([KIND_SCREENSHOT]).
     * PERSISTED for 24 h ([screenshotStore]) and buffered for the group
     * conversation. Still not a message: it never touches the activity counters,
     * though an UNSEEN persisted notice adds its own term to the group dot until
     * [pollGroup] marks it seen.
     *
     * Same trust rule as a group text and as [handleActivity]: a known group whose
     * sender is a CURRENT, RESOLVED member of it. (A blocked sender never reaches
     * here — [ingest] drops their traffic first, and [screenshotNotices] filters
     * the block set again at read time.) Attribution is the pairwise channel and
     * the alias is read from the vault, never the wire.
     *
     * [claimedTakenAtMs] is the sender's envelope timestamp: DISPLAY ONLY, clamped
     * by [ScreenshotNoticeStore.clampTakenAt]. Ordering and the 24 h expiry are
     * anchored on OUR receive clock, so a peer cannot backdate its own notice out
     * of existence. The persist is fail-soft — a refusal costs durability only.
     */
    private fun handleScreenshotNotice(senderContactId: String, groupId: String, claimedTakenAtMs: Long) {
        if (vault.getGroup(groupId) == null) return
        if (vault.getGroupMembers(groupId).none { it.contactId == senderContactId }) return
        val stored = screenshotStore.record(
            conversationId = groupId,
            isGroup = true,
            senderContactId = senderContactId,
            senderClaimedTakenAtMs = claimedTakenAtMs,
        )
        val receivedAt = stored?.receivedAt ?: currentTimeMillis()
        buffers.bufferScreenshotNotice(
            ScreenshotNotice(
                conversationId = groupId,
                isGroup = true,
                senderContactId = senderContactId,
                senderAlias = vault.getContact(senderContactId)?.alias ?: platformString(NOTICE_MEMBER_FALLBACK_KEY),
                timestamp = stored?.takenAt
                    ?: ScreenshotNoticeStore.clampTakenAt(claimedTakenAtMs, receivedAt),
                receivedAt = receivedAt,
                expiresAt = receivedAt + SCREENSHOT_NOTICE_TTL_MS,
            )
        )
    }

    // -----------------------------------------------------------------------
    // Unread badges — read by the platform contact list (group dot + the
    // group-adjusted per-contact dot).
    // -----------------------------------------------------------------------

    /**
     * Per-group unread count: pending group texts (the KIND_ACTIVITY tally) PLUS
     * the group's UNSEEN persisted screenshot notices.
     *
     * The notice term is there because a notice is durable and is rendered when
     * the conversation is next opened — without it, a notice that arrived while the
     * app was backgrounded would sit in the group with nothing pointing at it. The
     * dot is a presence indicator, so +1 per unseen notice is the right shape; it is
     * cleared by [pollGroup] (i.e. by opening the group), exactly like the text term.
     *
     * The vault read happens BEFORE the [GroupUnreadTally] lock is taken — [SyncLock]
     * is non-reentrant on iOS and must never be held across SQLCipher.
     */
    fun groupUnreadCounts(): Map<String, Int> {
        val unseen = screenshotStore.unseenCounts(isGroup = true)
        // The buffered term and the presence bump both need state read OUTSIDE
        // the tally's lock (SyncLock is non-reentrant on iOS and must never be held
        // across SQLCipher), so both are snapshotted first.
        // Only a group screen's OWN items count: a PRIVATE item is a 1:1 text and a
        // GROUP_ECHO item belongs to another group (NO-PARK).
        val buffered = buffers.ownGroupCounts()
        val bump = presenceBumpedGroups()
        // max(buffered, notices) + unseen notices + the +1 bump; see
        // [GroupUnreadTally.groupCountsWith].
        return tally.groupCountsWith(buffered, unseen, bump)
    }

    /**
     * The NO-NOTICE FALLBACK, and the answer to "what does the UI do when
     * the `gi` notice is lost but the group text is not".
     *
     * ```
     * unattributed(c) = max(0, groupInboxPending[c] - grpNoticed[c])
     * due(c)          = unattributed(c) > 0 AND the NOTICE GRACE has run out for c
     * bump(g)         = 1  iff some resolved member c of g has due(c)
     * ```
     *
     * **It waits for the notice it is a fallback for** (device, 2026-11-13: two shared
     * groups, one text into one of them, BOTH lit for one sweep). The sender ships the
     * text and then the notice one jitter gap later; a sweep whose control drain ran
     * before the notice landed and whose peek then saw the text read
     * `unattributed > 0` and lit every shared group until the next cycle drained the
     * notice. So the bump for c lights only once a control check of c that STARTED at
     * least [GroupUnreadTally.NOTICE_LANDING_GRACE_MS] (15 s) after the depth was first
     * seen came back without the notice — or, if c's control drain keeps failing, once
     * the depth has stood [GroupUnreadTally.FALLBACK_CEILING_MS] (180 s). A notice that
     * lands during the wait attributes normally and the bump never shows. Both
     * platforms publish this at the end of every control cycle, right after that
     * cycle's drain, so the qualifying check and the re-publish are the same cycle.
     * Worst case for a genuinely notice-less text: one control cycle after first sight
     * (idle ≤ ~90 s + the sweep, fast ≈ 15–25 s), or ~180 s + one cycle via the
     * backstop. An ATTRIBUTED text (live or restored `gi` unit) never waits.
     *
     * Four properties, each deliberate:
     *
     *  - **+1, never `n`.** The true per-group split of a contact's group-inbox
     *    depth is not knowable before a decrypt, and inflating the number would be
     *    a lie. The number on a group row is therefore a LOWER BOUND during an
     *    unattributed window, and it self-corrects on the next drain (which
     *    decrypts, gives the real group a real count and clears the rest).
     *  - **Every SHARED group lights, not a guess.** If the contact shares exactly
     *    one group — the overwhelmingly common case — it is exact. If they share
     *    several, all of them show a dot; that is a known limitation.
     *  - **It is never, under any circumstance, a contact row.** A contact with
     *    unattributed > 0 and NO shared group lights nothing at all, and their
     *    blobs simply expire off the relay in 24 h: "peek never drains" applies to
     *    the group inbox exactly as to the text inbox, so we do not drain to clear.
     *  - **Cheap in the steady state.** The lock is taken first and the vault is
     *    touched ONLY when some contact is actually unattributed, so a converged
     *    device pays one lock and no enumeration.
     */
    private fun presenceBumpedGroups(): Set<String> {
        val unattributed = tally.unattributedContacts()
        if (unattributed.isEmpty()) return emptySet()
        return try {
            val out = mutableSetOf<String>()
            for (g in vault.getAllGroups()) {
                if (vault.getGroupMembers(g.groupId).any { it.contactId in unattributed }) {
                    out.add(g.groupId)
                }
            }
            out
        } catch (e: Exception) {
            platformLogWarn(TAG, "presence bump lookup failed: ${e::class.simpleName}")
            emptySet()
        }
    }

    /**
     * THE CONTACT DOT. Its inputs are the contact's own TEXT-inbox /peek depth, the
     * legacy group-text compensator and that contact's unseen persisted screenshot
     * notices — and **nothing about the group inbox, at any point.** That is
     * the invariant this whole third-inbox design exists to make structural: a
     * group text from an upgraded peer is not on this inbox, is not counted here,
     * and cannot reach this number by any path.
     *
     * The arithmetic is [GroupUnreadTally.contactCountsFrom] (deliberately its own
     * function, so the property above is checkable by reading one body); the peeking is
     * [sweepUnreadInboxes]. Cleared by [pollDirect] — i.e. by opening the
     * conversation, which drains the inbox.
     *
     * [onSweepFinished] (optional) is told whether the sweep got a
     * definite answer from EVERY inbox it peeked ([MessageManager.UnreadPeek.complete]);
     * `false` when there was no transport. Called after the counts are computed,
     * never with anything but that one Boolean — it cannot influence the count.
     */
    fun contactUnreadCounts(
        blockedContactIds: Set<String> = emptySet(),
        onSweepFinished: ((complete: Boolean) -> Unit)? = null,
    ): Map<String, Int> {
        val peeked = sweepUnreadInboxes(blockedContactIds)
        if (peeked == null) {
            onSweepFinished?.invoke(false)
            return emptyMap()
        }
        val unseen = screenshotStore.unseenCounts(isGroup = false)
        val counts = tally.contactCountsFrom(peeked.text, unseen, blockedContactIds)
        onSweepFinished?.invoke(peeked.complete)
        return counts
    }

    /**
     * The steady-state unread SWEEP: one pass over every non-blocked contact's
     * TEXT inbox plus — filtered to the contacts we share a group with —
     * their GROUP inbox.
     *
     * It is the only place the two halves meet, and they meet as two separate maps
     * that go to two separate consumers: the text half is returned for
     * [GroupUnreadTally.contactCountsFrom], the group half is published into the
     * tally's group-inbox depths for the GROUP dot's presence bump and is never
     * returned to the caller at all. Null = no transport (the caller answers with
     * no counts, exactly as before).
     */
    private fun sweepUnreadInboxes(blockedContactIds: Set<String>): MessageManager.UnreadPeek? {
        val mgr = transport("contactUnreadCounts") ?: return null
        val peeked = mgr.peekUnreadCountsWithGroup(
            blockedContactIds,
            // The filter that keeps the sweep cheap: for the 1:1-only majority this
            // set is empty and the sweep is byte-identical to what it always was.
            groupSharingContactIds(blockedContactIds),
        )
        publishGroupInboxDepths(peeked.group)
        return peeked
    }

    /**
     * Every GROUP-inbox depth a peek pass ANSWERED (unknown ≠ empty: an inbox the
     * relay did not answer for is absent from [depths] and changes nothing) goes to
     * the tally for the presence bump, AND heals the `gi` attribution: when the
     * definite depth is below what is attributed, the surplus describes texts that
     * are no longer on the relay. The RAM side heals only units RESTORED from the
     * vault ([GroupUnreadTally.retractRestored]); the vault mirror keeps only its
     * newest `depth` units ([GroupUnreadMarkerStore.healTo]). Vault I/O happens only
     * for a contact that holds a marker, never under the tally's lock.
     */
    private fun publishGroupInboxDepths(depths: Map<String, Int>) {
        tally.notePeekedGroupInboxDepths(depths)
        for ((contactId, depth) in depths) {
            tally.retractRestored(contactId, depth)
            unreadMarkers.healTo(contactId, depth)
        }
    }

    /**
     * The connect-time prime's CONTROL PRE-DRAIN.
     *
     * **The third inbox kept this as a MECHANISM and deleted it as a CORRECTNESS DEPENDENCY, and
     * that is the whole class of bug being closed.** Before the third inbox, a group
     * text sat on the recipient's ordinary 1:1 TEXT inbox, `/peek` returns nothing but
     * a COUNT, and the only thing that separated the two kinds was the sender's
     * KIND_ACTIVITY notice on the CONTROL channel — so the contact dot depended on this
     * drain winning a race against a peek, over Tor.
     * With group text on its OWN inbox the contact dot is correct BY CONSTRUCTION for
     * a converged pairing: skip this pass entirely and the dot is still right
     * (`GroupTextNeverOnContactTest` pins exactly that).
     *
     * What it still buys, and why it stays: it makes GROUP attribution PRECISE on the
     * first frame (the `gi` notice names WHICH group, so a presence bump is not needed),
     * it delivers invites and rosters, and it is the only thing that keeps the LEGACY
     * compensator ([GroupUnreadTally]) honest for mixed-version pairings — a
     * pre-change peer's group text really is on the text inbox, and only its notice
     * says so.
     *
     * Four properties, each load-bearing:
     *
     *  - **CONTROL ONLY, never a text inbox.** Control traffic has no relay-retention
     *    requirement and is drained every background cycle anyway. A TEXT inbox is
     *    burn-on-read and must survive on the relay until its conversation is opened,
     *    so the prime still only ever PEEKS those (see [primeUnreadCounts]).
     *
     *  - **Scoped to contacts that are RESOLVED MEMBERS of a group we already know.**
     *    Those are exactly the senders whose notice [handleActivity] would honour (it
     *    requires a known group with the sender as a current member), so a wider sweep
     *    could not improve attribution — it would only spend the prime's entire latency
     *    budget on sequential control round-trips and undo the reason the prime exists
     *    (the dot in ~1 RTT). A device in no group pays nothing beyond the
     *    group enumeration: zero extra requests. Known limitation: a group text that arrives
     *    together with the INVITE that first introduces its group is still attributed
     *    to the contact for one cycle — the sender is not a member of anything we know
     *    yet — and self-corrects on the loop's next sweep exactly as it does today.
     *
     *  - **It HOLDS the sweep** ([beginControlSweep]), so it can never drain an inbox
     *    concurrently with the platform control-poll loop, and it SKIPS if that loop
     *    got there first — the loop is doing the same work, and the steady-state sweep
     *    re-attributes seconds later, which is precisely today's behaviour.
     *
     *  - **It hands its findings back to that loop.** A received batch latches the UI
     *    nudge [pollAllControls] reports, so taking the batch cannot cost the "an
     *    applied invite surfaces a group row with no navigation" refresh. It no
     *    longer marks control activity itself: [ingest] arms the convergence
     *    window for the QUALIFYING arrivals in that batch, which is the same thing
     *    for every case that mattered and none of the cases that were the pin.
     *
     * A contact blocked by EITHER block source ([blockedContactIds] as passed to the
     * prime, or the [blockedContacts] provider the sweep reads) is not polled at all.
     *
     * Blocking (vault + network) and NEVER throws: a control failure must not cost the
     * unread dots this pass exists to deliver.
     */
    private fun drainGroupMemberControlsForPrime(
        blockedContactIds: Set<String>,
        preResolved: List<ContactRecord>? = null,
        prePeeked: Map<String, Int>? = null,
    ) {
        val mgr = transport("unread prime control pre-drain") ?: return
        val contacts = preResolved ?: try {
            // The UNION of both block sources, and deliberately so: the prime is handed
            // the set by its caller (iOS passes `BlockStore.blocked()`; Android has no
            // blocking and passes none) while the sweep reads the [blockedContacts]
            // provider, and neither is guaranteed to be installed on this instance at
            // this moment. A contact either one calls blocked is not polled.
            groupMemberControlTargets(blockedContactIds + blockedContactsSafe())
        } catch (e: Exception) {
            platformLogWarn(TAG, "unread prime: group-member snapshot failed: ${e::class.simpleName}")
            return
        }
        if (contacts.isEmpty()) return
        if (!beginControlSweep("unread prime control pre-drain")) return
        try {
            // allowConcurrency stays FALSE here: this IS the connect-time
            // sweep the panel comment in [pollAllControls] describes — it shares a
            // cold circuit with the health probe, and the connect-time reveal
            // (ConnectReveal) depends on it being sequential. [prePeeked] (batch peek) does not
            // change that: the DRAIN is what is sequential, and the peek it replaces
            // is already over.
            if (drainControlInboxes(mgr, contacts, allowConcurrency = false, prePeeked = prePeeked)) {
                controlNudgeLock.withLock { pendingControlNudge = true }
                // The convergence window is NOT armed here: arming it off any
                // drained batch is the peer-driven pin. [noteControlConvergence] arms
                // it from inside [ingest] for exactly the arrivals a fast follow-up
                // can help (a group membership kind from a known group member), which
                // this pre-drain runs through like every other drain.
            }
            platformLog(TAG, "unread prime: pre-drained ${contacts.size} member control inbox(es)")
        } catch (e: Exception) {
            platformLogWarn(TAG, "unread prime control pre-drain failed: ${e::class.simpleName}")
        } finally {
            endControlSweep()
        }
    }

    /**
     * The non-blocked contacts that are RESOLVED members of a group this device knows,
     * CSPRNG-shuffled like every other sweep — see [drainGroupMemberControlsForPrime].
     * Local vault reads only, run on ONE coroutine before the prime's fan-out exists.
     * An unresolved member slot has no inbox to poll and is skipped.
     */
    private fun groupMemberControlTargets(blocked: Set<String>): List<ContactRecord> {
        // ONE predicate for the whole feature — see [groupSharingContactIds]. The
        // prime's control refs, its GROUP refs, the steady sweep's group-peek filter
        // and the drain gate are all this same set, so they cannot drift.
        val memberContactIds = groupSharingContactIds(blocked)
        if (memberContactIds.isEmpty()) return emptyList()
        return vault.getAllContacts()
            .filter { it.contactId in memberContactIds }
            .secureShuffled()
    }

    /**
     * ONE-SHOT bounded-parallel unread PRIME, fired the instant the relay transport
     * is wired (Tor `Connected`). Peeks every non-blocked contact's inbound TEXT
     * inbox concurrently and reports each result through [onContactUnread] the
     * moment it lands, so the contact-list "message waiting" dot appears in roughly
     * one round-trip instead of after a full sequential, jittered sweep.
     *
     * It ADDS a pass; it changes nothing about the steady state. `pollAllControls`,
     * [MessageManager.peekUnreadCounts] and [MessageManager.controlPollDelayMs] keep
     * their exact cadence and traffic discipline, and their first cycle still
     * replaces whatever this produced.
     *
     * **The pass normally costs ONE relay round trip**
     * ([primeUnreadCountsBatched] → [MessageManager.peekInboxesBatch]): both inbox
     * sets — the group members' control inboxes and every contact's text inbox —
     * are peeked in a single `POST /peek`, the control inboxes the answer showed
     * non-empty are drained, and only then are the unread counts emitted. An OLD
     * relay (no such route), a failed batch or nothing to ask about falls through
     * to the path described below, UNCHANGED, so every property listed here still
     * holds in its own right and is what the fallback is pinned against.
     *
     * Five design points, each load-bearing:
     *
     *  - **CONTROL BEFORE TEXT.** The pass opens with
     *    [drainGroupMemberControlsForPrime] — the group members' CONTROL inboxes are
     *    drained (never a text inbox) so the KIND_ACTIVITY notices are applied
     *    BEFORE any peek count is attributed. With the third inbox this is PRECISION, not
     *    correctness: a converged pairing's group text is on its own inbox and the
     *    contact dot is right even if this pass is skipped entirely. It still names
     *    WHICH group on the first frame, and it is still the only signal for a
     *    LEGACY peer whose group text really is on the text inbox. Strictly
     *    sequential and finished before the fan-out exists, so the vault still has
     *    exactly one caller.
     *
     *  - **SNAPSHOT FIRST, THEN FAN OUT.** Every vault read happens up front, on the
     *    CALLING coroutine ([MessageManager.inboundTextPeekTargets]); the workers do
     *    pure HTTP ([MessageManager.peekInboxRef]) and touch no vault at all.
     *    `DatabaseManager` / `IosVaultDatabase` thread-safety under genuinely
     *    concurrent access is unproven on both platforms, and this must not become
     *    its first concurrent caller. A contact with no resolvable inbound inbox is
     *    silently skipped.
     *
     *  - **BOUNDED AT [PRIME_CONCURRENCY], never unbounded** — see that constant for
     *    the 6a0c138 Tor-concurrency lesson. [maxConcurrency] is CLAMPED to it, so a
     *    caller can only ask for fewer in-flight requests, never more.
     *
     *  - **NO inter-request sleeps**, unlike the steady-state sweeps. Those jitter
     *    100–400 ms between contacts because a REPEATING background sweep could
     *    otherwise be aligned across cycles by an observer. This fires exactly ONCE,
     *    at the moment the relay is already watching this device arrive (Tor connect,
     *    then the first control polls), so it contributes no repeating pattern to
     *    correlate — and being fast is the entire point. The ORDER is still
     *    CSPRNG-shuffled, which costs nothing.
     *
     *  - **MERGE-ONLY emission.** A failed peek (a 404 from an in-flight capability
     *    rotation, a 429, a timeout, a malformed body) emits NOTHING for that
     *    contact — never a 0 — so a transient failure can never blank a dot the
     *    caller is already showing. The steady-state cycle corrects any drift seconds
     *    later. A SUCCESSFUL peek always emits, including a genuine 0.
     *
     * [onContactUnread] is invoked **STRICTLY SERIALLY** — never from two workers at
     * once (emission is guarded by a [Mutex]) — so a platform driver can merge
     * naively with no lock of its own. It runs on a WORKER (background) thread while
     * that mutex is held, so keep it cheap and non-blocking, and do not call back
     * into this GroupManager from it. A throw from it is caught and dropped: one
     * contact's badge is never worth failing the prime.
     *
     * `count` is [MessageManager.peekInboxRef]'s raw pending total MINUS the group
     * texts riding that contact's text inbox PLUS that contact's unseen persisted
     * screenshot notices — the same two adjustments [contactUnreadCounts] applies,
     * so a group message lights the GROUP dot and not the 1:1 one and a notice that
     * landed while the app was backgrounded still shows. The notice term is
     * snapshotted with the targets, on this coroutine, before any parallelism exists
     * (the workers touch no vault), and it is why a ZERO peek can still emit 1.
     * Read-only here: the downward heal of a stale pending tally stays with the
     * steady-state sweep, which is authoritative.
     *
     * Returns once every peek has settled. Per-contact failures never throw out of
     * here; cancellation of the caller's scope does propagate (structured
     * concurrency). A second call while one pass is still in flight is a logged
     * no-op — see [primeInFlight]. Suspends, so any caller context is fine; the
     * blocking I/O runs on [ioDispatcher] (`Dispatchers.IO` on both platforms).
     */
    suspend fun primeUnreadCounts(
        blockedContactIds: Set<String>,
        maxConcurrency: Int = PRIME_CONCURRENCY,
        onContactUnread: (contactId: String, count: Int) -> Unit,
    ) {
        val mgr = transport("primeUnreadCounts") ?: return
        val admitted = primeLock.withLock {
            if (primeInFlight) false else { primeInFlight = true; true }
        }
        if (!admitted) {
            platformLogWarn(TAG, "unread prime already in flight — skipping this one")
            return
        }
        // Pass timer, anchored BEFORE the control pre-drain so the closing panel line's
        // seconds cover the WHOLE pass: the pre-drain's sequential control round-trips
        // are part of what the panel was missing (a 160 s connect showed ~40 s of
        // silence before the first health probe, with this pass holding streams on the
        // same cold circuit throughout).
        val startedAtMs = clockMs()
        try {
            // ONE ROUND TRIP FIRST. The whole pass — every group
            // member's control-inbox depth and every contact's text-inbox depth —
            // in a single `POST /peek`, which is what the user's connect wait is
            // made of. It hands back `false` for an old relay, a failed batch or
            // nothing to ask about, and the pass then runs EXACTLY the pre-batch
            // code below, unchanged.
            if (primeUnreadCountsBatched(mgr, blockedContactIds, startedAtMs, onContactUnread)) return
            primeUnreadCountsPerInbox(mgr, blockedContactIds, startedAtMs, maxConcurrency, onContactUnread)
        } finally {
            primeLock.withLock { primeInFlight = false }
        }
    }

    /**
     * The PRE-BATCH prime pass, byte-for-byte: what [primeUnreadCounts] runs when
     * [primeUnreadCountsBatched] answers false (old relay, failed batch, nothing to
     * ask). Control pre-drain, vault snapshot, then the bounded peek fan-out.
     * Caller holds the [primeInFlight] admission and releases it.
     */
    private suspend fun primeUnreadCountsPerInbox(
        mgr: MessageManager,
        blockedContactIds: Set<String>,
        startedAtMs: Long,
        maxConcurrency: Int,
        onContactUnread: (contactId: String, count: Int) -> Unit,
    ) {
        // CONTROL FIRST — see [drainGroupMemberControlsForPrime]. Blocking network
        // I/O, so it runs on [ioDispatcher] rather than whatever the caller
        // launched on (iOS primes from `Dispatchers.Default`), and STRICTLY BEFORE
        // the fan-out, so the prime keeps its one-thread-touches-the-vault
        // discipline. It never throws; a CancellationException delivered at this
        // suspension point still propagates (nothing catches it here), which is
        // what keeps a locked/wiped session from continuing into the peeks.
        withContext(ioDispatcher) { drainGroupMemberControlsForPrime(blockedContactIds) }
        // ALL remaining vault I/O for the whole pass, on this coroutine, before any
        // parallelism exists. See the kdoc's snapshot-then-fan-out point.
        val targets = try {
            mgr.inboundTextPeekTargets(blockedContactIds).toMutableList()
        } catch (e: Exception) {
            platformLogWarn(TAG, "unread prime snapshot failed: ${e::class.simpleName}")
            return
        }
        // The third inbox, same snapshot discipline, filtered to the contacts
        // we share a group with. Its answers go to the GROUP dot's presence bump
        // and are NEVER emitted through [onContactUnread].
        val groupTargets = try {
            mgr.inboundGroupPeekTargets(groupSharingContactIds(blockedContactIds).toList())
        } catch (e: Exception) {
            platformLogWarn(TAG, "unread prime group snapshot failed: ${e::class.simpleName}")
            emptyList()
        }
        // Connection-log panel (COUNTS AND SECONDS ONLY — never an inbox id, a
        // contact id or an alias). Emitted at the first point the count exists,
        // i.e. after the control pre-drain; the gap between this line and the
        // pass's elapsed seconds on the closing line IS the pre-drain's cost.
        ConnectionLog.append(
            ConnectionLog.Kind.RELAY,
            "unread prime started: ${targets.size} inboxes",
            ConnectionLog.Code.PRIME_PASS,
        )
        if (targets.isEmpty() && groupTargets.isEmpty()) {
            appendPrimePassDone(answered = 0, total = 0, startedAtMs = startedAtMs)
            return
        }
        // Part of the same up-front vault snapshot as `targets` — the workers
        // below must not touch the vault (see the kdoc's snapshot-then-fan-out
        // point). Immutable from here on, so it is safe to read from a worker.
        val unseen = screenshotStore.unseenCounts(isGroup = false)
        // CSPRNG Fisher–Yates, matching the steady-state sweeps: the ORDER of a
        // burst is observable even when its inter-request jitter is not.
        targets.secureShuffle()
        val gate = Semaphore(maxConcurrency.coerceIn(1, PRIME_CONCURRENCY))
        // Serialises EMISSION only, never the peeks — the platform drivers merge
        // without a lock of their own.
        val emitLock = Mutex()
        // Peeks that ANSWERED (any non-null count, including a genuine 0), for the
        // closing panel line. An IntArray rather than a captured `var`: it is
        // incremented from the workers, and only ever inside [emitLock], which is
        // what makes it safe on Native as well.
        val answered = intArrayOf(0)
        // GROUP depths land here, never in an emission. Written from workers, so
        // it is lock-guarded like every other cross-thread map in this file, and
        // published in ONE go after the scope closes.
        val groupDepths = mutableMapOf<String, Int>()
        val groupDepthLock = SyncLock()
        coroutineScope {
            for (target in targets) {
                // null ⇒ MERGE-ONLY: [launchPeek] calls back only for an answer, so a
                // failed peek emits nothing at all for this contact.
                launchPeek(gate, mgr, target, "unread prime peek failed") { raw ->
                    val count = tally.primeUnreadCountFor(target.contactId, raw, unseen)
                    emitLock.withLock {
                        answered[0]++
                        try {
                            onContactUnread(target.contactId, count)
                        } catch (e: Exception) {
                            platformLogWarn(TAG, "unread prime callback threw: ${e::class.simpleName}")
                        }
                    }
                }
            }
            // The same fan-out, the same permits, the same pure-HTTP worker — and
            // deliberately NO emission: a group-inbox depth must not reach
            // [onContactUnread] by any path. Sharing the gate is what keeps
            // the whole pass inside [PRIME_CONCURRENCY] rather than doubling the
            // in-flight streams on one cold circuit (the concurrent-mint lesson).
            for (target in groupTargets) {
                launchPeek(gate, mgr, target, "unread prime group peek failed") { raw ->
                    groupDepthLock.withLock { groupDepths[target.contactId] = raw }
                }
            }
        }
        publishGroupInboxDepths(groupDepths)
        platformLog(TAG, "unread prime: peeked ${targets.size} contact(s)")
        appendPrimePassDone(answered[0], targets.size, startedAtMs)
    }

    /**
     * One prime worker: under [gate], peeks [target] on [ioDispatcher] and hands a
     * non-null answer to [onAnswer]. A throw degrades to "no answer" after a warn
     * line with the fixed [failPhrase] (peekInboxRef is already non-throwing; this
     * is belt-and-braces so one inbox can never fail the whole prime).
     */
    private fun CoroutineScope.launchPeek(
        gate: Semaphore,
        mgr: MessageManager,
        target: MessageManager.PeekTarget,
        failPhrase: String,
        onAnswer: suspend (raw: Int) -> Unit,
    ) {
        launch(ioDispatcher) {
            gate.withPermit {
                val raw = try {
                    mgr.peekInboxRef(target.inboxId, target.readCap)
                } catch (e: Exception) {
                    platformLogWarn(TAG, "$failPhrase: ${e::class.simpleName}")
                    null
                }
                if (raw != null) onAnswer(raw)
            }
        }
    }

    /**
     * THE ONE-ROUND-TRIP unread prime.
     * Returns **true when it handled the whole pass** — every control
     * drain applied and every unread count emitted — and **false when the caller
     * must run the pre-batch path**, which is left byte-for-byte as it was.
     *
     * What it replaces: a sequential control round trip per group member
     * ([drainGroupMemberControlsForPrime]'s peek/drain) followed by a 3-wide
     * `/peek` fan-out over every contact, all on the coldest circuit of the
     * session, all inside the wait before the contact list appears.
     *
     * Five properties, each load-bearing:
     *
     *  - **SNAPSHOT FIRST, and there is no fan-out at all.** Every vault read of
     *    the pass happens here, before the request: the group-member contact set,
     *    the control-inbox refs ([MessageManager.inboundControlPeekTargets], which
     *    also runs the read-cap reconcile) and the text-inbox refs
     *    ([MessageManager.inboundTextPeekTargets]). The batch itself touches no
     *    vault, and the drains that follow run on ONE coroutine — so this path
     *    never has two callers in the vault at once, which the fan-out needed a
     *    whole discipline to guarantee.
     *
     *  - **CONTROL-BEFORE-TEXT IS PRESERVED — for precision, not
     *    correctness.** With the third inbox a converged pairing's group text is on its own
     *    inbox, so the contact dot is right whether or not this drain lands
     *    (`GroupTextNeverOnContactTest`). The ordering still matters for two
     *    things: a `gi` notice applied here names WHICH group, so the first frame
     *    shows an exact group count instead of a presence bump; and for a LEGACY
     *    peer (rollout cells 2/3/4) the notice is still the only thing that says a
     *    queued TEXT-inbox blob is a group text. So: drain the control inboxes the
     *    batch found non-empty, THEN emit.
     *
     *  - **UNKNOWN IS NEVER ZERO.** A per-item `status` (404/429) and an inbox
     *    missing from the answer are both `null`, which means what a null from
     *    [MessageManager.peekControlPending] has always meant: a control inbox
     *    DRAINS, and a text inbox emits NOTHING (merge-only — never a 0 that would
     *    blank a live dot).
     *
     *  - **CONVERGING still skips the control peek entirely.** In that state every
     *    group member's control inbox drains unconditionally (today's rule), so
     *    those refs are left out of the batch instead of being asked about and
     *    ignored.
     *
     *  - **The relay is UNTRUSTED.** Nothing destructive rides on its answer: the
     *    worst a lie buys is one delayed dot or one control drain deferred to the
     *    next sweep — exactly what withholding the blobs already buys it.
     */
    private suspend fun primeUnreadCountsBatched(
        mgr: MessageManager,
        blockedContactIds: Set<String>,
        startedAtMs: Long,
        onContactUnread: (contactId: String, count: Int) -> Unit,
    ): Boolean {
        // One wasted round trip per TRANSPORT on an old relay, never one per prime.
        if (mgr.isBatchPeekUnsupported()) return false
        // Decided ONCE, exactly as [drainControlInboxes] decides it, and read here
        // so the refs we ask about match the drain policy we are going to apply.
        val converging = try { mgr.isControlConverging() } catch (_: Exception) { true }
        val controlContacts: List<ContactRecord>
        val controlTargets: List<MessageManager.PeekTarget>
        val textTargets: List<MessageManager.PeekTarget>
        val groupTargets: List<MessageManager.PeekTarget>
        try {
            // Same UNION of both block sources [drainGroupMemberControlsForPrime]
            // uses, and the same CSPRNG-shuffled order.
            controlContacts = groupMemberControlTargets(blockedContactIds + blockedContactsSafe())
            controlTargets =
                if (converging || controlContacts.isEmpty()) emptyList()
                else mgr.inboundControlPeekTargets(controlContacts.map { it.contactId })
            textTargets = mgr.inboundTextPeekTargets(blockedContactIds)
            // The THIRD inbox per contact, filtered to the contacts we share a
            // group with — which, for the connect-time batch, is exactly the group
            // members already resolved above. A device in no group adds nothing.
            groupTargets = mgr.inboundGroupPeekTargets(controlContacts.map { it.contactId })
        } catch (e: Exception) {
            // Fall back rather than guess: the legacy path re-reads the same vault
            // and handles a throw exactly as it always has.
            platformLogWarn(TAG, "unread prime batch snapshot failed: ${e::class.simpleName}")
            return false
        }
        val refs = mutableListOf<MessageManager.PeekRef>()
        for (t in controlTargets) {
            refs.add(MessageManager.PeekRef(t.inboxId, t.readCap, controlContactId = t.contactId))
        }
        for (t in textTargets) refs.add(MessageManager.PeekRef(t.inboxId, t.readCap))
        // A GROUP ref carries no contactId: like a TEXT ref it must get NONE of the
        // control peek's side effects ([MessageManager.PeekRef]) — its 404 belongs
        // to the drain, which is what arms the 404 self-heal.
        for (t in groupTargets) refs.add(MessageManager.PeekRef(t.inboxId, t.readCap))
        // Nothing peekable (no contacts, everything blocked, a vault of stale rows):
        // let the pre-batch path close the pass the way it always has — and make
        // ZERO relay requests doing it.
        if (refs.isEmpty()) return false
        // The relay sees the whole set either way, but it must not additionally be
        // handed "these first N are the control inboxes" as a structural tell.
        refs.secureShuffle()
        val batchStartedAtMs = clockMs()
        val outcome = withContext(ioDispatcher) { mgr.peekInboxesBatch(refs) }
        // Unsupported (old relay) or Failed (transport/timeout/unreadable) ⇒ the
        // pre-batch path runs in full. Never "assume empty".
        val counts = (outcome as? MessageManager.BatchPeekOutcome.Counts)?.byInboxId ?: return false
        // Connection-log panel: COUNTS AND SECONDS ONLY — never an inbox id, a
        // contact id or an alias. It shares [ConnectionLog.Code.PRIME_PASS] with the
        // two lines below deliberately: the fixed phrase tells the rungs apart, and
        // a NEW code would make a relay that has not allowlisted it reject the whole
        // connect report (see ConnectionLog.Code — ship the relay first).
        ConnectionLog.append(
            ConnectionLog.Kind.RELAY,
            "unread prime batch: ${refs.size} inboxes in ${formatSeconds(clockMs() - batchStartedAtMs)} s",
            ConnectionLog.Code.PRIME_PASS,
        )
        // CONTROL FIRST, and strictly before any emission below.
        if (controlContacts.isNotEmpty()) {
            // Non-converging ⇒ hand the drain the answered map (absent = unknown =
            // drain). Converging ⇒ null, i.e. the unconditional drain today's rule
            // already prescribes.
            val peeked = if (converging) null else mutableMapOf<String, Int>().also { m ->
                for (t in controlTargets) {
                    val n = counts[t.inboxId]
                    if (n != null) m[t.contactId] = n
                }
            }
            withContext(ioDispatcher) {
                drainGroupMemberControlsForPrime(
                    blockedContactIds,
                    preResolved = controlContacts,
                    prePeeked = peeked,
                )
            }
        }
        // The GROUP depths are published AFTER the control drains, for the same
        // reason the text emissions are: a `gi` notice applied by one of those
        // drains is what tells a depth apart from an unattributed one, and a
        // presence bump raised before it landed would flash on every shared group.
        // They feed the GROUP dot only — never a contact row.
        publishGroupInboxDepths(
            buildMap { for (t in groupTargets) counts[t.inboxId]?.let { put(t.contactId, it) } }
        )
        ConnectionLog.append(
            ConnectionLog.Kind.RELAY,
            "unread prime started: ${textTargets.size} inboxes",
            ConnectionLog.Code.PRIME_PASS,
        )
        if (textTargets.isEmpty()) {
            appendPrimePassDone(answered = 0, total = 0, startedAtMs = startedAtMs)
            return true
        }
        // Read AFTER the control drains, like the pre-batch path: a drain can
        // persist a screenshot notice, and this is what makes a ZERO peek still
        // emit 1. Immutable from here on.
        val unseen = screenshotStore.unseenCounts(isGroup = false)
        // The emissions run on [ioDispatcher] for the same reason the fan-out's did:
        // [onContactUnread] has always been invoked from a background worker, and
        // both platform drivers are written for that. Serial by construction here —
        // one coroutine, no mutex needed.
        val answered = withContext(ioDispatcher) {
            var n = 0
            for (target in textTargets) {
                // null ⇒ a per-item `status`, or an inbox the relay did not answer
                // for ⇒ MERGE-ONLY: emit nothing at all for this contact.
                val raw = counts[target.inboxId] ?: continue
                n++
                try {
                    onContactUnread(target.contactId, tally.primeUnreadCountFor(target.contactId, raw, unseen))
                } catch (e: Exception) {
                    platformLogWarn(TAG, "unread prime callback threw: ${e::class.simpleName}")
                }
            }
            n
        }
        platformLog(TAG, "unread prime: one batch covered ${refs.size} inbox(es)")
        appendPrimePassDone(answered, textTargets.size, startedAtMs)
        return true
    }

    /**
     * The unread prime's closing panel line. Counts and seconds ONLY — the pass knows
     * inbox ids, read capabilities, contact ids and aliases, and none of them may reach
     * [ConnectionLog] (which ships in release and is screenshot-able).
     *
     * Deliberately NOT emitted from a `finally`: on lock/wipe the pass is cancelled and
     * [ConnectionLog.clear] has already run, and a line appended after that clear would
     * outlive the session it describes.
     */
    private fun appendPrimePassDone(answered: Int, total: Int, startedAtMs: Long) {
        ConnectionLog.append(
            ConnectionLog.Kind.RELAY,
            "unread prime done: $answered/$total answered in ${formatSeconds(clockMs() - startedAtMs)} s",
            ConnectionLog.Code.PRIME_PASS,
        )
    }

    /** Clear a group's unread dot — call when its conversation is opened. RAM-only
     *  (both platforms call it on the main thread); the vault mirror follows on the
     *  group poll that the open starts ([pollGroupIntoBuffer] / [pollGroupPending]). */
    fun markGroupRead(groupId: String) = tally.markGroupRead(groupId)

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    // String fields are read with [firstStringFieldAnywhere] (the FIRST match at
    // any depth); this number reader is DEPTH-1 only. Both are linear scans, never
    // a regex: group control bodies come from a MALICIOUS CONTACT (paired member),
    // and Kotlin/Native's recursive regex engine overflows on long values.
    private fun topLevelLong(body: String, key: String): Long? =
        parseTopLevelJson(body)[key]?.text?.toLongOrNull()

}
