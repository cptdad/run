package com.vg.run

import java.util.Locale

// Standalone scorer for the dynamic passphrase test (scripts/passphrase-adversary/score.sh):
// one candidate per stdin line, scored against the PRODUCTION estimator
// (CredentialPolicy.estimateBits / meetsFloor = the MAXIMUM floor). No Gradle, no device.
//
//   default            "<bits>\t<ACCEPTED|refused>\t<candidate>" for every line
//   --accepted-only    only the ACCEPTED lines (bulk runs over cracker wordlists)
//   --raw-range LO HI  only the candidate text, for lines with LO <= bits < HI (feeds hashcat rules)
//   --stats            at the end, on stderr: total, accepted, and a 10-bit histogram
fun main(args: Array<String>) {
    var acceptedOnly = false
    var stats = false
    var rangeLo = Double.NaN
    var rangeHi = Double.NaN
    var i = 0
    while (i < args.size) {
        when (args[i]) {
            "--accepted-only" -> acceptedOnly = true
            "--stats" -> stats = true
            "--raw-range" -> { rangeLo = args[i + 1].toDouble(); rangeHi = args[i + 2].toDouble(); i += 2 }
            else -> { System.err.println("unknown option ${args[i]}"); kotlin.system.exitProcess(2) }
        }
        i++
    }
    val rawRange = !rangeLo.isNaN()
    val out = java.io.PrintWriter(java.io.BufferedWriter(java.io.OutputStreamWriter(System.out, Charsets.UTF_8), 1 shl 16))
    val histogram = LongArray(16) // 0-9, 10-19, ... 150+
    var total = 0L
    var accepted = 0L
    val reader = System.`in`.bufferedReader(Charsets.UTF_8)
    while (true) {
        val raw = reader.readLine() ?: break
        val p = raw.trimEnd('\r')
        if (p.isBlank()) continue
        total++
        val bits = CredentialPolicy.estimateBits(p)
        val ok = CredentialPolicy.meetsFloor(p)
        if (ok) accepted++
        histogram[minOf((bits / 10).toInt(), 15)]++
        when {
            rawRange -> if (bits >= rangeLo && bits < rangeHi) out.println(p)
            acceptedOnly -> if (ok) out.println(String.format(Locale.ROOT, "%.1f\t%s", bits, p))
            else -> out.println(String.format(Locale.ROOT, "%.1f\t%s\t%s", bits, if (ok) "ACCEPTED" else "refused", p))
        }
    }
    out.flush()
    if (stats) {
        System.err.println(String.format(Locale.ROOT, "total=%d accepted=%d (%.3f%%)", total, accepted, if (total == 0L) 0.0 else accepted * 100.0 / total))
        System.err.println("histogram(bits): " + histogram.indices.joinToString(" ") { b -> "${b * 10}${if (b == 15) "+" else ""}:${histogram[b]}" })
    }
}
