package com.vg.run

// ---------------------------------------------------------------------------
// TorReasonVocabulary — Tor's own CLOSED REASON keyword sets, in ONE place.
//
// Three consumers, which is why this lives in commonMain:
//  1. The Android control-event parser (TorControlEvents.kt, androidMain)
//     prints a REASON only when it is in its event's set here, else "OTHER".
//     iOS sibling: TorControlEventParser (TorControlEvents.swift) carries the
//     same sets — `TorReasonParitySourceTest` (androidApp) pins them equal.
//  2. [hsDescFailureCode] — the `HS_DESC FAILED` REASON → connect CODE split
//     (2026-10-23). The connect timeline used to carry one HSDESC_FAILED for
//     every failed descriptor fetch, so production could not tell "the relay's
//     descriptor is not on the HSDirs" (NOT_FOUND) from "this client has no
//     usable HSDir" (QUERY_NO_HSDIR) from "the descriptor did not decode"
//     (BAD_DESC — the clock-skew signature). The map is a FIXED lookup; a
//     reason off it (QUERY_REJECTED, a future Tor's new reason, a missing
//     REASON) keeps the pre-split [ConnectionLog.Code.HSDESC_FAILED]. A code is
//     never derived from the string itself.
//  3. [DebugLogRedactor]'s rule 3 passthrough ([DEBUG_PASSTHROUGH]): a REASON
//     such as `QUERY_NO_HSDIR` is an 8+-char run holding `_`, which the
//     opaque-token rule would otherwise turn into `[id]` — erasing exactly the
//     word that explains a stall. Only an EXACT, case-sensitive match of a
//     whole run against this list passes; the general rule is untouched.
//
// Every entry is a Tor-defined keyword from control-spec.txt — identical on
// every client, carrying nothing about a device, a relay or a circuit. Adding
// a word here is a privacy decision: it must be a Tor protocol constant, never
// anything a peer, a relay or a user could choose.
// ---------------------------------------------------------------------------

object TorReasonVocabulary {

    /** `650 HS_DESC FAILED … REASON=` (control-spec §4.1.25, client side). */
    val HS_DESC_FAIL: Set<String> = setOf(
        "NOT_FOUND", "QUERY_NO_HSDIR", "QUERY_RATE_LIMITED", "QUERY_REJECTED", "BAD_DESC", "UNEXPECTED",
    )

    /** `650 CIRC … REASON=` for FAILED / CLOSED. */
    val CIRC_FAIL: Set<String> = setOf(
        "TIMEOUT", "DESTROYED", "CHANNEL_CLOSED", "CONNECTFAILED", "NOPATH",
        "RESOURCELIMIT", "OR_IDENTITY", "INTERNAL", "MEASUREMENT_EXPIRED", "FINISHED",
    )

    /** `650 STREAM … REASON=` for FAILED / CLOSED. */
    val STREAM_FAIL: Set<String> = setOf(
        "TIMEOUT", "RESOLVEFAILED", "CONNECTREFUSED", "DESTROY", "TORPROTOCOL",
        "INTERNAL", "RESOURCELIMIT", "MISC", "END", "DONE",
    )

    /** `650 ORCONN … REASON=` for FAILED / CLOSED. */
    val ORCONN_FAIL: Set<String> = setOf(
        "DONE", "CONNECTREFUSED", "IDENTITY", "CONNECTRESET", "TIMEOUT",
        "NOROUTE", "IOERROR", "RESOURCELIMIT", "MISC", "PT_MISSING",
    )

    /** `650 STATUS_CLIENT WARN|ERR BOOTSTRAP … REASON=`. */
    val BOOTSTRAP_PROBLEM: Set<String> = setOf(
        "MISC", "RESOURCELIMIT", "IDENTITY", "CONNECTREFUSED", "CONNECTRESET",
        "TIMEOUT", "NOROUTE", "IOERROR", "PT_MISSING",
    )

    /** `650 STATUS_CLIENT … CIRCUIT_NOT_ESTABLISHED REASON=CLOCK_JUMPED`. */
    const val CLOCK_JUMPED: String = "CLOCK_JUMPED"

    /**
     * The words [DebugLogRedactor] may leave verbatim although its rule 3 would
     * otherwise take them as opaque tokens. Exactly the union of the REASON
     * sets above plus [CLOCK_JUMPED] — nothing else; in particular no bootstrap
     * TAG (those are lower-case and still pinned to `[id]` by `DebugModeTest`).
     */
    val DEBUG_PASSTHROUGH: Set<String> =
        HS_DESC_FAIL + CIRC_FAIL + STREAM_FAIL + ORCONN_FAIL + BOOTSTRAP_PROBLEM + CLOCK_JUMPED

    /**
     * The connect CODE for an `HS_DESC FAILED` whose REASON is [reason]
     * (case-insensitive). The FIXED split:
     *
     *  - `NOT_FOUND`          → [ConnectionLog.Code.HSDESC_NOT_FOUND]    (the HSDir answered 404)
     *  - `QUERY_NO_HSDIR`     → [ConnectionLog.Code.HSDESC_NO_HSDIR]     (no usable HSDir to ask)
     *  - `QUERY_RATE_LIMITED` → [ConnectionLog.Code.HSDESC_RATE_LIMITED] (Tor's own refetch limiter)
     *  - `BAD_DESC`           → [ConnectionLog.Code.HSDESC_BAD_DESC]     (fetched, did not decode)
     *  - `UNEXPECTED`         → [ConnectionLog.Code.HSDESC_UNEXPECTED]   (an unexpected HSDir answer)
     *  - anything else, or no REASON → [ConnectionLog.Code.HSDESC_FAILED] (the pre-split code)
     *
     * Pure and total. iOS sibling: `TorControlEventParser.hsDescFailCodes`.
     */
    fun hsDescFailureCode(reason: String?): ConnectionLog.Code = when (reason?.uppercase()) {
        "NOT_FOUND" -> ConnectionLog.Code.HSDESC_NOT_FOUND
        "QUERY_NO_HSDIR" -> ConnectionLog.Code.HSDESC_NO_HSDIR
        "QUERY_RATE_LIMITED" -> ConnectionLog.Code.HSDESC_RATE_LIMITED
        "BAD_DESC" -> ConnectionLog.Code.HSDESC_BAD_DESC
        "UNEXPECTED" -> ConnectionLog.Code.HSDESC_UNEXPECTED
        else -> ConnectionLog.Code.HSDESC_FAILED
    }

    /**
     * Every code [hsDescFailureCode] can return — the descriptor-fetch FAILURE
     * family. Used where the split must not change behaviour: the Android
     * panel dedupe folds the family onto one key so two failures with different
     * reasons inside one 2 s window still show as ONE line, exactly as before.
     */
    val HS_DESC_FAILURE_CODES: Set<ConnectionLog.Code> = setOf(
        ConnectionLog.Code.HSDESC_FAILED,
        ConnectionLog.Code.HSDESC_NOT_FOUND,
        ConnectionLog.Code.HSDESC_NO_HSDIR,
        ConnectionLog.Code.HSDESC_RATE_LIMITED,
        ConnectionLog.Code.HSDESC_BAD_DESC,
        ConnectionLog.Code.HSDESC_UNEXPECTED,
    )
}
