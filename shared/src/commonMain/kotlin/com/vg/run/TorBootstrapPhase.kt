package com.vg.run

// ---------------------------------------------------------------------------
// TorBootstrapPhase — Tor's bootstrap TAG token ⇒ one [ConnectionLog.Code].
//
// Until now every bootstrap
// line on both platforms carried the SAME code, `TOR_BOOTSTRAP_TAG`: the panel
// showed the tag as text, but the connect timeline — which ships codes and
// nothing else — could only say "Tor was bootstrapping" for what were, in the
// measured reports, 70–125 second silences. "Which phase did it sit in?" is the
// first question of every bootstrap stall and the wire could not answer it.
//
// ONE TABLE, BOTH PLATFORMS. This lives in commonMain rather than being mirrored
// in Kotlin and Swift precisely because a mirrored mapping is a mapping that
// drifts: Android reads the TAG out of the NOTICE log line
// ([TorManager.parseBootstrapProgress]) and iOS reads it out of the control
// port's `STATUS_CLIENT BOOTSTRAP` arguments, but both then call [codeFor], so a
// timeline is comparable across platforms by construction.
//
// PRODUCER RULE. This is a LOOKUP, never an echo: only an exact match against
// Tor's own fixed ladder produces a phase code, and anything else — a future
// Tor's new tag, an empty tag, a garbled log line — falls back to
// [ConnectionLog.Code.TOR_BOOTSTRAP_TAG], the catch-all this replaces. No part of
// the input string can reach the code, so no argument can ride the wire through
// it. (The panel TEXT still shows the raw tag, as it always has: it is shape-
// checked at both producers and Tor's tags are a closed set.)
//
// WHY GROUPS RATHER THAN ONE CODE PER TAG. Tor 0.4.9 defines ~24 tags, most of
// them pluggable-transport / proxy variants this app can never emit (it runs no
// bridge and no proxy) and several that are one instantaneous step apart. Nine
// GROUPS name the phases a stall can actually live in — guard channel,
// directory, descriptors, the app's own first circuit — while keeping the
// vocabulary (and the relay's label cardinality) small. See the entropy note on
// [ConnectionLog.Code].
// ---------------------------------------------------------------------------

object TorBootstrapPhase {

    /**
     * The phase code for Tor's bootstrap [tag] (case-insensitive), or
     * [ConnectionLog.Code.TOR_BOOTSTRAP_TAG] for an empty or unrecognised one.
     *
     * Pure, allocation-light and total — it is called on every bootstrap line of
     * every launch, from the Android log tail and from an iOS control-port
     * callback, and must never throw or block.
     */
    fun codeFor(tag: String): ConnectionLog.Code = when (tag.lowercase()) {
        // 0 % — the daemon is up and has read its state.
        "starting" -> ConnectionLog.Code.TOR_BOOT_STARTING

        // 1–5 % — opening the TCP connection to the first relay (or, on a
        // configuration this app never ships, to a PT/proxy). A long pause here
        // is the network being unreachable or the guard being unreachable.
        "conn_pt", "conn_done_pt", "conn_proxy", "conn_done_proxy",
        "conn", "conn_dir",
        -> ConnectionLog.Code.TOR_BOOT_CONN

        // 10–15 % — the TLS/link handshake with that relay. Distinct from CONN
        // on purpose: a completed TCP connection that never finishes its
        // handshake is a censorship/middlebox signature, not a routing one.
        "conn_done", "handshake", "handshake_dir", "handshake_or", "handshake_done",
        -> ConnectionLog.Code.TOR_BOOT_HANDSHAKE

        // 20–40 % — the one-hop directory circuit and the consensus it fetches.
        "onehop_create", "requesting_status", "loading_status", "loading_keys",
        -> ConnectionLog.Code.TOR_BOOT_ONEHOP

        // 45–50 % — relay descriptors. This is where the iOS cold tail sits
        // (18 pinned FallbackDirs vs Tor's compiled-in ~200).
        "requesting_descriptors", "loading_descriptors",
        -> ConnectionLog.Code.TOR_BOOT_DESCRIPTORS

        // 75 % — enough directory info to build circuits. The single most
        // load-bearing boundary in the ladder: everything before it is the
        // DIRECTORY problem, everything after it is the CIRCUIT problem.
        "enough_dirinfo" -> ConnectionLog.Code.TOR_BOOT_DIRINFO

        // 76–90 % — the application-purpose connection + handshake to the guard
        // the first real circuit will use.
        "ap_conn_pt", "ap_conn_done_pt", "ap_conn_proxy", "ap_conn_done_proxy",
        "ap_conn", "ap_conn_done", "ap_handshake", "ap_handshake_done",
        -> ConnectionLog.Code.TOR_BOOT_AP_CONN

        // 95 % — building the first circuit.
        "circuit_create" -> ConnectionLog.Code.TOR_BOOT_CIRCUIT

        // 100 %.
        "done" -> ConnectionLog.Code.TOR_BOOT_DONE

        // Unknown / absent: the pre-C2 catch-all, never a guess.
        else -> ConnectionLog.Code.TOR_BOOTSTRAP_TAG
    }
}
