package com.vg.run

// ---------------------------------------------------------------------------
// Crockford Base32 — the transcribable encoding for the vault recovery code.
//
// Chosen over hex (shorter) and standard Base32 (Crockford drops the ambiguous
// I/L/O/U, so a human copying the code off paper can't confuse 1/l, 0/O). Decode
// is forgiving: case-insensitive, ignores spaces/hyphens, and folds the visual
// look-alikes (O→0, I/L→1) back to their canonical symbol. No padding.
//
// The recovery secret is 20 random bytes (160 bits) → exactly 32 symbols, so the
// encoding is lossless and round-trips.  encode(decode(s)) is canonical.
// ---------------------------------------------------------------------------

object Base32 {
    private const val ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

    /** Encode [data] MSB-first with no padding. */
    fun encode(data: ByteArray): String {
        if (data.isEmpty()) return ""
        val out = StringBuilder((data.size * 8 + 4) / 5)
        var buffer = 0
        var bits = 0
        for (b in data) {
            buffer = (buffer shl 8) or (b.toInt() and 0xFF)
            bits += 8
            while (bits >= 5) {
                bits -= 5
                out.append(ALPHABET[(buffer ushr bits) and 0x1F])
            }
        }
        if (bits > 0) {
            out.append(ALPHABET[(buffer shl (5 - bits)) and 0x1F])
        }
        return out.toString()
    }

    /**
     * Decode [text], tolerating case, spaces and hyphens and folding the
     * Crockford look-alikes. Returns null if any surviving character is not a
     * valid symbol (fail closed — a mistyped code must not silently decode to
     * the wrong bytes).
     */
    fun decode(text: String): ByteArray? {
        val out = ArrayList<Byte>(text.length)
        var buffer = 0
        var bits = 0
        for (raw in text) {
            val c = when (val u = raw.uppercaseChar()) {
                ' ', '-', '\t', '\n', '\r' -> continue
                'O' -> '0'
                'I', 'L' -> '1'
                else -> u
            }
            val v = ALPHABET.indexOf(c)
            if (v < 0) return null
            buffer = (buffer shl 5) or v
            bits += 5
            if (bits >= 8) {
                bits -= 8
                out.add(((buffer ushr bits) and 0xFF).toByte())
            }
        }
        return out.toByteArray()
    }

    /** Insert [separator] every [group] symbols for display (e.g. 4-char groups). */
    fun formatGrouped(code: String, group: Int = 4, separator: String = "-"): String {
        if (group <= 0) return code
        val out = StringBuilder(code.length + code.length / group)
        for (i in code.indices) {
            if (i > 0 && i % group == 0) out.append(separator)
            out.append(code[i])
        }
        return out.toString()
    }
}
