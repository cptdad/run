package com.vg.run

// ---------------------------------------------------------------------------
// PeerInboxGone — persisted evidence that a PEER's inbox no longer exists on the
// relay, built only from what the relay answered to OUR appends.
//
// Why it exists: a relay 404 on a SEND was reported to exactly one caller (the
// group-text fallback) and was otherwise just "false". Every queued item that
// re-drives on failure (referral offers / accepts / relayed accepts, the group
// membership obligations, the channel-lost notice, the Maximum level notice) then
// re-POSTed to an inbox that no longer exists — for up to 28 days for a referral
// offer — because "false" cannot tell "the peer deleted us" from "Tor dropped".
//
// The relay collapses unknown inbox / wrong capability / locked capability /
// expired inbox into ONE 404 (docs/RELAY_SPEC.md, "The generic rejection"), so a
// single 404 is not proof. What makes it evidence here:
//
//  - The relay must have PROVEN, within [RELAY_PROOF_MAX_AGE_MS] of the 404, that
//    it holds our state (an authenticated 2xx on one of our own inboxes or on
//    another append). A relay that restarted with an empty or unreadable shell
//    snapshot answers 404 for EVERY inbox, ours included, so no proof exists and
//    nothing is counted — the "relay briefly lost its state" case.
//  - A correct write capability is never locked out (RELAY_SPEC "Lockout"), so a
//    lockout cannot produce these 404s at all; a wrong cap is a local defect the
//    send path already refuses before any POST.
//  - [GONE_AFTER_COUNTED_404S] counted 404s, each at least [MIN_SPACING_MS] after
//    the previous counted one, i.e. at least two hours of continuous 404s from a
//    relay that is otherwise answering for our inboxes. A burst inside one session
//    counts once.
//  - The evidence is bound to the destination INBOX ID (a hash of it), so a peer
//    that re-announces a new inbox starts clean, and ANY 2xx on that inbox clears
//    it at once.
//
// What a verdict may cause: the END of an automatic retry, and nothing else. Per
// queued item (docs/vault-relay-internals.md, the per-re-drive table): an
// introducer's introduction ENDS (its `ref_s` / `ref_r` records are dropped, as on
// expiry) and a `grp_ctl_pend` membership obligation is DROPPED — neither is
// recreated if the inbox answers again later; an introducee's unsent accept, the
// channel-lost notice and the Maximum level notice are only SKIPPED (their records
// stay, and a later 2xx clears the evidence so they go out again). Never a contact
// delete, a row or key-material delete, a ratchet change, a `dr-lost` latch or a
// wipe, and never a user-initiated send. Every ambiguity — an unreadable
// record, a malformed value, a backward clock step, no proof of relay state —
// answers [PeerInboxVerdict.SEND], i.e. "keep retrying under the existing bounds".
//
// The record is a per-contact `_meta` row, so it is in ratchetMetaKeysForContact
// (dies with the contact) and travels with a device move (MoveMetaPolicy).
// ---------------------------------------------------------------------------

/** What the persisted send-404 evidence says about the next automatic send to a peer's inbox. */
internal enum class PeerInboxVerdict {
    /** No evidence (or stale / unreadable evidence): send as usual. */
    SEND,

    /** A counted 404 less than [PeerInboxGonePolicy.MIN_SPACING_MS] ago: skip this
     *  automatic attempt without spending its budget — the next probe is worth more
     *  later than now. */
    HOLD,

    /** Positive evidence the inbox is gone: end the automatic retry of the item. */
    GONE,
}

internal object PeerInboxGonePolicy {
    /** `snd-nf/<contactId>` — one row per contact, value per [encode]. */
    const val KEY_PREFIX = "snd-nf/"

    /** Counted 404s that make the verdict [PeerInboxVerdict.GONE]. */
    const val GONE_AFTER_COUNTED_404S = 3

    /** A 404 counts only this long after the previous counted one (one hour). */
    const val MIN_SPACING_MS = 60L * 60 * 1000

    /** How recent the relay's proof that it holds our state must be (15 min — the
     *  control sweep refreshes it every 60–90 s in a healthy session). */
    const val RELAY_PROOF_MAX_AGE_MS = 15L * 60 * 1000

    /** Evidence older than this (since its last counted 404) is ignored, so a wrong
     *  verdict re-probes once a week instead of holding forever. */
    const val EVIDENCE_MAX_AGE_MS = 7L * 24 * 60 * 60 * 1000

    /** One entry per destination inbox; a pairing has at most three. */
    const val MAX_ENTRIES = 3

    private const val VERSION = "v1"
    private const val TAG_CHARS = 12

    fun keyFor(contactId: String): String = KEY_PREFIX + contactId

    /** A short, domain-separated hash of a destination inbox id. The inbox id itself
     *  is already in the vault's inbox rows; the hash only keeps the row small. */
    fun inboxTag(inboxId: String): String =
        encodeBase64Url(
            sha256("run-peer-inbox-gone|".encodeToByteArray() + inboxId.encodeToByteArray())
        ).take(TAG_CHARS)

    class Entry(val tag: String, val count: Int, val lastCountedMs: Long)

    private fun isTag(s: String): Boolean =
        s.length == TAG_CHARS && s.all { it.isLetterOrDigit() && it.code < 128 || it == '-' || it == '_' }

    /** `v1;<tag>,<count>,<lastCountedMs>[;…]`. Anything malformed decodes as NO
     *  evidence (fails toward "keep retrying"). */
    fun decode(raw: String?): List<Entry> {
        if (raw == null) return emptyList()
        val parts = raw.split(';')
        if (parts.size < 2 || parts[0] != VERSION || parts.size > MAX_ENTRIES + 1) return emptyList()
        val out = mutableListOf<Entry>()
        for (p in parts.drop(1)) {
            val f = p.split(',')
            if (f.size != 3 || !isTag(f[0])) return emptyList()
            val count = f[1].toIntOrNull() ?: return emptyList()
            val last = f[2].toLongOrNull() ?: return emptyList()
            if (count < 1 || count > GONE_AFTER_COUNTED_404S) return emptyList()
            if (out.any { it.tag == f[0] }) return emptyList()
            out += Entry(f[0], count, last)
        }
        return out
    }

    /** null = nothing to keep (the caller deletes the row). */
    fun encode(entries: List<Entry>): String? =
        if (entries.isEmpty()) null
        else VERSION + entries.joinToString("") { ";${it.tag},${it.count},${it.lastCountedMs}" }

    private fun isStale(e: Entry, now: Long): Boolean = now - e.lastCountedMs > EVIDENCE_MAX_AGE_MS

    /**
     * The evidence after a relay 404 for the inbox [tag]. Counted only when
     * [relayProvedOurState]; a backward clock step (now before the last counted 404)
     * counts nothing. Returns the SAME list instance when nothing changed, so the
     * caller can skip the write.
     */
    fun afterNotFound(entries: List<Entry>, tag: String, now: Long, relayProvedOurState: Boolean): List<Entry> {
        if (!relayProvedOurState) return entries
        val e = entries.firstOrNull { it.tag == tag }
        val next = when {
            e == null || isStale(e, now) -> Entry(tag, 1, now)
            now < e.lastCountedMs -> return entries
            now - e.lastCountedMs >= MIN_SPACING_MS ->
                Entry(tag, minOf(e.count + 1, GONE_AFTER_COUNTED_404S), now)
            else -> return entries
        }
        val others = entries.filter { it.tag != tag }.sortedByDescending { it.lastCountedMs }
        return (listOf(next) + others).take(MAX_ENTRIES)
    }

    /** The evidence after a 2xx for the inbox [tag]: that entry goes. Same instance when absent. */
    fun afterAccepted(entries: List<Entry>, tag: String): List<Entry> =
        if (entries.none { it.tag == tag }) entries else entries.filter { it.tag != tag }

    fun verdict(entries: List<Entry>, tag: String, now: Long): PeerInboxVerdict {
        val e = entries.firstOrNull { it.tag == tag } ?: return PeerInboxVerdict.SEND
        if (now < e.lastCountedMs || isStale(e, now)) return PeerInboxVerdict.SEND
        if (e.count >= GONE_AFTER_COUNTED_404S) return PeerInboxVerdict.GONE
        if (now - e.lastCountedMs < MIN_SPACING_MS) return PeerInboxVerdict.HOLD
        return PeerInboxVerdict.SEND
    }
}
