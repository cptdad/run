package com.vg.run

/**
 * What one Tor control event means for the descriptor fetch ([DescriptorHedge]
 * reads the finer [RelayDescriptorEvent.Action]): a fetch for the relay's onion
 * started ([REQUESTED]) or ended either way ([SETTLED] — `RECEIVED` or `FAILED`).
 */
enum class RelayDescriptorSignal { REQUESTED, SETTLED }

/**
 * The PURE event half of the descriptor hedge ([DescriptorHedge]), shared by both platforms so
 * the event classification cannot drift: Android's event socket reader
 * (TorControlEvents.kt) and iOS's raw-`650` tap (TorControlEventTap.swift) both
 * hand every event line to [classify]; the platform TorManagers own the timer.
 *
 * IDENTIFIER RULE. The `HS_DESC` event carries the onion address, the HSDir
 * fingerprint~nickname and the descriptor id. [classify] COMPARES the address
 * field against the relay's own address and returns only an enum — no field of
 * the event (and not the address) ever leaves this function, so nothing it
 * produces can reach a log line or the wire. The connection-log line for the
 * same event is produced, as before, by the platform parsers.
 */
object RelayDescriptorWatchdog {

    /**
     * The relay's v3 onion address in the form `HSFETCH` and the `HS_DESC`
     * event's HSAddress field both use (56 base32 chars, no `.onion`), or null
     * for a non-onion / malformed relay URL — in which case the watchdog never
     * arms. Strict by [RelayWarmup.v3OnionAddress]: the value is written into a
     * command on an AUTHENTICATED control socket, so CR/LF/space can never pass.
     * NEVER log the result.
     */
    fun hsFetchAddress(relayUrl: String): String? = RelayWarmup.v3OnionAddress(relayUrl)

    /**
     * Classifies ONE control-port line. Accepts it with or without the
     * `650 ` / `650-` reply prefix (iOS's controller strips it, Android's reader
     * does not). Null for every event that is not an `HS_DESC` REQUESTED /
     * RECEIVED / FAILED for [relayOnionAddress] — other services, the
     * service-side actions (CREATED / UPLOAD / UPLOADED), IGNORE, and every
     * other event class.
     *
     * `HS_DESC <Action> <HSAddress> <AuthType> <HsDir> [<DescriptorID>] [REASON=…]`
     */
    fun classify(rawEventLine: String, relayOnionAddress: String?): RelayDescriptorSignal? =
        when (parseEvent(rawEventLine, relayOnionAddress)?.action) {
            null -> null
            RelayDescriptorEvent.Action.REQUESTED -> RelayDescriptorSignal.REQUESTED
            RelayDescriptorEvent.Action.RECEIVED, RelayDescriptorEvent.Action.FAILED -> RelayDescriptorSignal.SETTLED
        }

    /**
     * [classify] plus the HSDir that served (or failed) the fetch — the input of
     * the per-Tor-process [HsDirLedger] (2026-10-08). Same acceptance rules as
     * [classify]; null for everything [classify] returns null for.
     *
     * The HSDir token (`$<40 hex>~nick`, `$<40 hex>=nick`, bare `$<40 hex>`, or
     * Tor's `UNKNOWN`) is reduced to its 40-hex fingerprint ([hsDirFingerprint]);
     * the nickname, the descriptor id and the address are dropped here. The
     * fingerprint is SENSITIVE: it lives only inside the returned event's
     * `internal` field, which [RelayDescriptorEvent.toString] never renders and
     * which only [HsDirLedger] reads — it never reaches a log line, the panel
     * or the wire except as the `SERVER=` argument of an `HSFETCH`.
     */
    fun parseEvent(rawEventLine: String, relayOnionAddress: String?): RelayDescriptorEvent? =
        parseEvent(rawEventLine, listOf(relayOnionAddress))

    /**
     * [parseEvent] against SEVERAL addresses of the same relay (2026-10-23,
     * [RelayAddressRace]): the event is accepted when its HSAddress equals ANY
     * non-null entry, and the returned event's [RelayDescriptorEvent.slot] is that
     * entry's index — a small integer, never the address. Same acceptance rules
     * otherwise; null when no entry matches or [relayOnionAddresses] has none.
     */
    fun parseEvent(rawEventLine: String, relayOnionAddresses: List<String?>): RelayDescriptorEvent? {
        if (relayOnionAddresses.all { it.isNullOrEmpty() }) return null
        var line = rawEventLine.trimEnd('\r', '\n')
        if (line.length >= 4 && line.startsWith("650") && (line[3] == ' ' || line[3] == '-' || line[3] == '+')) {
            line = line.substring(4)
        }
        val tokens = line.split(' ').filter { it.isNotEmpty() }
        if (tokens.size < 3 || tokens[0] != "HS_DESC") return null
        // Equality only — the address is never copied out of this frame; only
        // the matching SLOT INDEX leaves it.
        val slot = relayOnionAddresses.indexOfFirst { !it.isNullOrEmpty() && tokens[2].equals(it, ignoreCase = true) }
        if (slot < 0) return null
        val action = when (tokens[1].uppercase()) {
            "REQUESTED" -> RelayDescriptorEvent.Action.REQUESTED
            "RECEIVED" -> RelayDescriptorEvent.Action.RECEIVED
            "FAILED" -> RelayDescriptorEvent.Action.FAILED
            else -> return null
        }
        val fingerprint = tokens.getOrNull(4)?.let(::hsDirFingerprint)
        val reason = if (action != RelayDescriptorEvent.Action.FAILED) null else
            tokens.firstOrNull { it.startsWith("REASON=") }?.removePrefix("REASON=")
                ?.takeIf { it in HS_DESC_FAILURE_REASONS }
        return RelayDescriptorEvent(action, fingerprint, reason, slot)
    }

    /** Tor's closed `HS_DESC FAILED REASON=` vocabulary (control-spec). */
    private val HS_DESC_FAILURE_REASONS = setOf(
        "NOT_FOUND", "QUERY_NO_HSDIR", "QUERY_RATE_LIMITED", "QUERY_REJECTED", "BAD_DESC", "UNEXPECTED",
    )

    /**
     * The 40-hex fingerprint of an `HS_DESC` HsDir token, upper-cased, or null
     * for `UNKNOWN` / anything malformed. STRICT on purpose: the value is later
     * written into `HSFETCH … SERVER=$<fp>` on an AUTHENTICATED control socket,
     * so only `[0-9A-F]{40}` may ever pass.
     */
    internal fun hsDirFingerprint(token: String): String? {
        if (!token.startsWith("$")) return null
        val hex = token.substring(1).substringBefore('~').substringBefore('=')
        if (hex.length != 40 || !hex.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) return null
        return hex.uppercase()
    }

    /** Tor's answers to `HSFETCH … SERVER=` naming an HSDir it does not know /
     *  that is not an HSDir (`551`/`552`): drop the pin and retry plain. */
    fun isPinRejectedReply(code: Int): Boolean = code == 551 || code == 552
}

/**
 * One `HS_DESC` event for one of the relay's onions, reduced to what the watchdog and
 * the [HsDirLedger] need. [hsDirFingerprint] is SENSITIVE (see
 * [RelayDescriptorWatchdog.parseEvent]) — `internal`, so Swift never sees it, and
 * never rendered by [toString].
 */
class RelayDescriptorEvent internal constructor(
    val action: Action,
    internal val hsDirFingerprint: String?,
    /** Tor's closed REASON token of a FAILED (allowlisted), else null. */
    val failureReason: String?,
    /** Which of the relay's configured addresses the event is about — the INDEX
     *  into [RelayAddressRace.urls] (0 = slot 1), never the address itself. */
    val slot: Int = 0,
) {
    enum class Action { REQUESTED, RECEIVED, FAILED }

    override fun toString(): String = "RelayDescriptorEvent($action)"
}
