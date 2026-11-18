package com.vg.run

/**
 * The pairing QR / paste-code CODEC — the pairing TRUST boundary. Build +
 * parse + security-validation previously existed FIVE times: Android build
 * (JSONObject) + parse (parseQrPayload); iOS build (string interpolation) + parse
 * ×2 (handleScannedCode, addContactFromPastedCode), each with its own
 * isValidWriteCap. Any drift here is a trust-boundary bug (a missed echo/shape
 * check lets a reflected or malformed code through). ONE codec, both platforms,
 * pinned by PairingPayloadTest.
 *
 * Wire format — JSON, depth-1, every value a string:
 *   secret-only: {"secret": <base64-std of the 32-byte secret>, "rv": "2"}
 *   full:        {"inbox","wcap","cib","cwcap"[,"gib","gwcap"],"secret","rv"}
 *                (cib/cwcap = control pair, v7; gib/gwcap = group-text pair)
 * The secret is STANDARD base64 (matches ByteArray base64 on both platforms); the
 * inbox ids + caps are base64url. All values are JSON-safe; they are escaped
 * defensively on build and parsed with the depth-1, stack-safe [parseTopLevelJson]
 * (the same hardened scanner used for relay/control bodies), which requires each
 * value to be a real string (rejecting a JSON object/number — parity with iOS's
 * strict [String:String] cast).
 *
 * `rv` (2026-09-18) is the OPTIONAL ratchet-role-rule marker. It is
 * appended LAST so the pre-existing fields are byte-identical, and [parse] has
 * always ignored unknown keys, so an older build scanning an `rv`-bearing code is
 * unaffected and a code without `rv` simply parses with `roleRuleV2 = false`.
 */
data class PairingScan(
    val inboxId: String?,       // null on a secret-only code
    val writeCap: String?,
    val ctlInboxId: String?,    // null pre-v7 / on a secret-only code
    val ctlWriteCap: String?,
    val secretB64: String,      // validated: standard base64 of EXACTLY 32 bytes, != mySecret
    /** The peer's code carried `"rv":"2"`, i.e. it runs the
     *  secret-order role rule. false for every older peer — and false is what keeps
     *  BOTH sides on the id-order rule, which is the only answer that agrees. */
    val roleRuleV2: Boolean = false,
    /**
     * The peer's GROUP-text inbox pair. Null for a pre-group-inbox code and for a
     * secret-only code, which is not an error: no `outbound-grp` row is written and
     * the pairing simply sends group text down the text inbox, i.e. today's
     * behaviour. Carrying it in the QR is NOT optional design-wise — the two-scan
     * flow is asymmetric, and the side that SHOWED the full code never announces,
     * so without this one direction would never learn the other's group inbox.
     */
    val grpInboxId: String? = null,
    val grpWriteCap: String? = null,
    /**
     * The peer's one-time X25519 public key (`"ek"`, base64url-no-pad of 32 bytes,
     * docs/ratchet-bootstrap-plan.md §4.1), already validated by [PairingPayload.parse]:
     * well-formed, not a low-order point, not our own. Null = the peer's build has no
     * v3 bootstrap ⇒ this pairing is legacy on BOTH sides (decision rule §4.1, §6).
     */
    val ephemeralPubB64: String? = null,
)

object PairingPayload {

    /** A 32-byte read/write capability → base64url-no-pad = exactly 43 chars, strict
     *  ASCII base64url alphabet (Char.isLetterOrDigit also matches non-ASCII). */
    fun isValidCap(cap: String): Boolean =
        cap.length == 43 && cap.all {
            it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_'
        }

    // NOTE: jsonEscapeString RETURNS the value already wrapped in double-quotes
    // (and escapes " \ \n \r \t — but NOT '/', so standard-base64 secrets stay
    // raw, matching the existing wire format). The known-safe base64/base64url
    // values never contain an escaped char, so this equals raw interpolation.

    /**
     * `,"rv":"2"` — appended to BOTH payload shapes, unconditionally
     * (this build always runs the v2 role rule) and always last. Deliberately not a
     * build parameter: adding one would change the Objective-C selector both Swift
     * call sites use, for a flag that has exactly one value.
     */
    private val roleRuleField: String =
        ",${jsonEscapeString(ROLE_RULE_FIELD)}:${jsonEscapeString(ROLE_RULE_V2)}"

    /** SECRET-ONLY payload (renders instantly, before/without the mint). */
    fun buildSecretOnly(secretB64: String): String =
        "{\"secret\":${jsonEscapeString(secretB64)}$roleRuleField}"

    /**
     * The v3 one-time key field (docs/ratchet-bootstrap-plan.md §4.1): `"ek"`, the
     * base64url-no-pad of our 32-byte one-time X25519 public key, appended AFTER `rv`
     * in both code shapes. Its PRESENCE is the capability signal (it implies `rv:2`;
     * there is no version field). An older parser ignores the unknown key.
     */
    const val EPHEMERAL_KEY_FIELD = "ek"

    /** Length of a base64url-no-pad encoding of 32 bytes. */
    private const val EK_B64URL_LEN = 43

    private fun ekField(ekB64Url: String): String {
        require(decodeEphemeralKey(ekB64Url) != null) { "not a well-formed one-time key" }
        return ",${jsonEscapeString(EPHEMERAL_KEY_FIELD)}:${jsonEscapeString(ekB64Url)}"
    }

    /**
     * [buildSecretOnly] plus `"ek"` — what a v3-capable session shows. Built only by
     * [PairingSession]; the original builders stay byte-identical, so a screen that
     * has not switched to the session keeps emitting a legacy code.
     */
    internal fun buildSecretOnlyV3(secretB64: String, ekB64Url: String): String =
        buildSecretOnly(secretB64).dropLast(1) + ekField(ekB64Url) + "}"

    /** [buildFull] plus `"ek"` (see [buildSecretOnlyV3]). */
    internal fun buildFullV3(
        inboxId: String,
        writeCap: String,
        ctlInboxId: String,
        ctlWriteCap: String,
        secretB64: String,
        ekB64Url: String,
        grpInboxId: String? = null,
        grpWriteCap: String? = null,
    ): String = buildFull(inboxId, writeCap, ctlInboxId, ctlWriteCap, secretB64, grpInboxId, grpWriteCap)
        .dropLast(1) + ekField(ekB64Url) + "}"

    /**
     * Strict decode of an `"ek"` value: exactly 43 base64url characters, canonical (the
     * unused low 2 bits of the last character are zero), 32 bytes. Null otherwise.
     * Pure Kotlin — no platform base64 leniency (padding, `+`/`/`, whitespace) reaches
     * the trust boundary.
     */
    internal fun decodeEphemeralKey(s: String): ByteArray? {
        if (s.length != EK_B64URL_LEN) return null
        val out = ByteArray(32)
        var acc = 0
        var bits = 0
        var o = 0
        for ((i, ch) in s.withIndex()) {
            val v = when (ch) {
                in 'A'..'Z' -> ch - 'A'
                in 'a'..'z' -> ch - 'a' + 26
                in '0'..'9' -> ch - '0' + 52
                '-' -> 62
                '_' -> 63
                else -> return null
            }
            if (i == EK_B64URL_LEN - 1 && (v and 0x3) != 0) return null   // non-canonical tail
            acc = (acc shl 6) or v
            bits += 6
            if (bits >= 8) {
                bits -= 8
                if (o < 32) out[o++] = ((acc shr bits) and 0xFF).toByte()
            }
        }
        return if (o == 32) out else null
    }

    /** Same X25519 point (bit 255 is ignored by the function, so it is ignored here). */
    private fun samePoint(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != 32 || b.size != 32) return false
        var diff = (a[31].toInt() and 0x7F) xor (b[31].toInt() and 0x7F)
        for (i in 0 until 31) diff = diff or (a[i].toInt() xor b[i].toInt())
        return (diff and 0xFF) == 0
    }

    /**
     * FULL payload (inbox + control pair + group pair + secret) for the Done step /
     * paste.
     *
     * [grpInboxId]/[grpWriteCap] are appended LAST in the parameter list — never
     * inserted mid-list — so every existing positional caller keeps compiling; on
     * the WIRE they sit beside the control pair, before `secret`/`rv`. Both null
     * (the default) emits exactly the code this build emitted before the group
     * inbox existed, which a new build parses to `grp = null` ⇒ the text-inbox
     * fallback.
     */
    fun buildFull(
        inboxId: String,
        writeCap: String,
        ctlInboxId: String,
        ctlWriteCap: String,
        secretB64: String,
        grpInboxId: String? = null,
        grpWriteCap: String? = null,
    ): String {
        val grpPart =
            if (grpInboxId != null && grpWriteCap != null)
                "\"gib\":${jsonEscapeString(grpInboxId)}," +
                    "\"gwcap\":${jsonEscapeString(grpWriteCap)},"
            else ""
        return "{\"inbox\":${jsonEscapeString(inboxId)}," +
            "\"wcap\":${jsonEscapeString(writeCap)}," +
            "\"cib\":${jsonEscapeString(ctlInboxId)}," +
            "\"cwcap\":${jsonEscapeString(ctlWriteCap)}," +
            grpPart +
            "\"secret\":${jsonEscapeString(secretB64)}$roleRuleField}"
    }

    /**
     * Parse + validate a scanned/pasted payload against the same rules on both
     * platforms. Returns null on: malformed JSON, a non-string field, secret not
     * 32 bytes, echo (our own [myInboxId] or our own secret [mySecretB64] handed
     * back), a half-present inbox/wcap, ctl or grp pair, an invalid inbox-id/cap
     * shape, a ctl/grp pair on a secret-only code, or a ctl/grp inbox that is not
     * distinct from the others.
     * [requireFull] rejects a secret-only code (used by the paste path).
     */
    fun parse(raw: String, myInboxId: String?, mySecretB64: String?, requireFull: Boolean): PairingScan? =
        parse(raw, myInboxId, mySecretB64, requireFull, myEphemeralPubB64 = null)

    /**
     * [parse] with the v3 one-time key checks against OUR key [myEphemeralPubB64]
     * (base64url-no-pad; null = we have none, so only the echo check is skipped). An
     * `"ek"` that is present but malformed (not a string, not 43 canonical base64url
     * characters, not 32 bytes), a LOW-ORDER point ([RatchetBootstrapV3.isLowOrderPublicKey])
     * or a copy of our own key rejects the WHOLE code — the existing "invalid code"
     * result, never a crash. These checks run in the 4-argument [parse] too (minus
     * the echo check), so no build of this codec accepts a malformed `ek`.
     */
    fun parse(
        raw: String, myInboxId: String?, mySecretB64: String?, requireFull: Boolean,
        myEphemeralPubB64: String?,
    ): PairingScan? {
        return try {
            val json = parseTopLevelJson(raw)
            fun strField(key: String): String? = json[key]?.let { if (it.isString) it.text else null }

            val secretB64 = strField("secret") ?: return null
            // secretBytes / myBytes are decoded ONLY to validate the length and
            // run the self-echo check — they are transient copies of the 32-byte
            // pairing secret that are NEVER returned (the caller receives the
            // base64 STRING [secretB64] and re-decodes its own buffer, whose
            // lifetime the caller owns — AddContactScreen/AddContactView zero
            // that copy). Kotlin Strings are immutable, so [secretB64] itself
            // can't be wiped here; but these decoded byte copies can, and are
            // zeroed on EVERY exit path via the finally so a live-RAM capture
            // during a scan/paste parse can't recover the secret from them (#13).
            val secretBytes = try { decodeBase64(secretB64) } catch (_: Exception) { return null }
            var myBytes: ByteArray? = null
            try {
                if (secretBytes.size != 32) return null
                // Echo check: reject a reflected copy of our own secret half — anyone
                // who saw our (QR-visible) code could otherwise compute the shared
                // secret. Compare decoded BYTES, not the base64 text.
                if (mySecretB64 != null) {
                    myBytes = try { decodeBase64(mySecretB64) } catch (_: Exception) { null }
                    if (myBytes != null && secretBytes.contentEquals(myBytes)) return null
                }

                val inboxId = strField("inbox")
                val writeCap = strField("wcap")
                // inbox + wcap travel together — a half-present pair is malformed.
                if ((inboxId == null) != (writeCap == null)) return null
                if (inboxId == null && requireFull) return null
                if (inboxId != null && writeCap != null) {
                    if (!isValidInboxId(inboxId)) return null
                    if (!isValidCap(writeCap)) return null
                    if (myInboxId != null && inboxId == myInboxId) return null
                }

                // Optional CONTROL pair (v7) — both-or-neither, only on a full code.
                val ctlInboxId = strField("cib")
                val ctlWriteCap = strField("cwcap")
                if ((ctlInboxId == null) != (ctlWriteCap == null)) return null
                if (ctlInboxId != null && ctlWriteCap != null) {
                    if (inboxId == null) return null            // ctl pair on a secret-only code is malformed
                    if (!isValidInboxId(ctlInboxId) || !isValidCap(ctlWriteCap)) return null
                    if (ctlInboxId == inboxId) return null       // control + message inbox must differ
                }

                // Optional GROUP pair — the exact mirror of the ctl block above, and
                // the third id must differ from BOTH of the others (a code naming one
                // id twice would write two rows on one primary key and break the
                // channel with no re-pair UX). A code without it parses fine and the
                // pairing keeps sending group text down the text inbox.
                val grpInboxId = strField("gib")
                val grpWriteCap = strField("gwcap")
                if ((grpInboxId == null) != (grpWriteCap == null)) return null
                if (grpInboxId != null && grpWriteCap != null) {
                    if (inboxId == null) return null            // grp pair on a secret-only code is malformed
                    if (!isValidInboxId(grpInboxId) || !isValidCap(grpWriteCap)) return null
                    if (grpInboxId == inboxId || grpInboxId == ctlInboxId) return null
                }
                // OPTIONAL, and never a rejection reason. A missing,
                // non-string or unrecognised value reads as "this peer runs the old
                // role rule", which is the agreeing answer — the marker can only ever
                // turn the v2 rule ON, never fail a scan.
                // The v3 one-time key — OPTIONAL, but once present it must be right:
                // a malformed / low-order / reflected key rejects the code (§4.1). Its
                // absence is never a rejection (every older build).
                val ekB64: String?
                if (json.containsKey(EPHEMERAL_KEY_FIELD)) {
                    ekB64 = strField(EPHEMERAL_KEY_FIELD) ?: return null           // not a string
                    val ek = decodeEphemeralKey(ekB64) ?: return null
                    if (RatchetBootstrapV3.isLowOrderPublicKey(ek)) return null
                    if (myEphemeralPubB64 != null) {
                        val mine = decodeEphemeralKey(myEphemeralPubB64)
                        if (mine != null && samePoint(mine, ek)) return null
                    }
                } else {
                    ekB64 = null
                }
                PairingScan(
                    inboxId, writeCap, ctlInboxId, ctlWriteCap, secretB64,
                    roleRuleV2 = strField(ROLE_RULE_FIELD) == ROLE_RULE_V2,
                    grpInboxId = grpInboxId, grpWriteCap = grpWriteCap,
                    ephemeralPubB64 = ekB64,
                )
            } finally {
                secretBytes.secureWipe()
                myBytes?.secureWipe()
            }
        } catch (_: Exception) {
            null
        }
    }
}
