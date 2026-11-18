package com.vg.run

/**
 * A VERBATIM copy of `PairingPayload.parse` as the current store build runs it (the
 * logic is unchanged since the group-inbox commit; taken from commit af1b3331, the
 * last commit before the v3 `ek` field). It stands in for an OLDER peer's parser:
 * what a build without the v3 bootstrap does with a code that carries `ek`
 * (docs/ratchet-bootstrap-plan.md §6 "old parsers ignore unknown keys"). Never edit
 * it to follow a change in production — that would defeat the pin.
 */
internal object StoreBuildPairingParser {
    private fun isValidCap(cap: String): Boolean = PairingPayload.isValidCap(cap)

    fun parse(raw: String, myInboxId: String?, mySecretB64: String?, requireFull: Boolean): PairingScan? {
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
                PairingScan(
                    inboxId, writeCap, ctlInboxId, ctlWriteCap, secretB64,
                    roleRuleV2 = strField(ROLE_RULE_FIELD) == ROLE_RULE_V2,
                    grpInboxId = grpInboxId, grpWriteCap = grpWriteCap,
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
