package com.vg.run

/**
 * UNLOCK-TIME CHECK OF A CACHED SOCKS PORT (iOS, 2026-11-15).
 *
 * When the vault opens while Tor is already running (speculative pre-unlock start,
 * an in-process re-unlock, a kept-warm return), the app holds a SOCKS port that was
 * published earlier and asks Tor's AUTHENTICATED control channel
 * (`GETINFO net/listeners/socks`) before trusting it: a co-installed app can bind a
 * freed `auto` port, but it cannot answer on the cookie-authenticated control socket.
 *
 * The defect this replaces: the check compared the control answer with the
 * published port only, and treated ANY difference as "Tor thread died". A network
 * toggle (`SETCONF DisableNetwork=1` / `=0`, the network-restore and guard-channel
 * kicks) re-binds `SocksPort auto` on a new port; [SocksPortRedirect] follows it
 * (blocked between the toggle and the readback, then re-pointed), and iOS also
 * re-publishes the new port about a circuit later. An unlock landing inside that
 * window saw control = new vs published = old and latched relaunch-required — a
 * one-way, process-lifetime latch — on a live Tor.
 *
 * The rule now: DEAD means the control channel is SILENT (no reply in the bounded
 * wait, or disconnected). A control channel that answers — with the published port,
 * a different port, or no SOCKS listener at all — proves tor_main is alive.
 *
 * Pure, so both the unlock path and the DEBUG suspend probe use one table, unit
 * tested in UnlockPortCheckTest. Ports are local loopback numbers; nothing here logs.
 */
object UnlockPortCheck {

    enum class Verdict {
        /** No cached port to authenticate (published 0): the current-value wiring
         *  paths wire the control-fresh port when it is published. */
        NO_CACHED_PORT,
        /** The control channel reports the listener the published port resolves to
         *  (the port itself, or where [SocksPortRedirect] already moved it): wire. */
        CONFIRMED,
        /** Alive; a listener move is in flight (the published port resolves to
         *  [SocksPortRedirect.BLOCKED_PORT]): wait for it to conclude. */
        MOVING,
        /** Alive, but the control channel lists no SOCKS listener (closed between
         *  `DisableNetwork=1` and `=0`, or a reply lost to the controller's
         *  observer race): wait. */
        NO_LISTENER,
        /** Alive on a port the redirect does not know (no move recorded to it):
         *  wait for the re-publication; never wire the stale port meanwhile. */
        UNTRACKED_PORT,
        /** The control channel did not answer: tor_main is gone (relaunch). */
        DEAD,
    }

    /**
     * @param published the cached (published) SOCKS port, 0 = none.
     * @param resolved `SocksPortRedirect.resolve(published)` at the same moment.
     * @param answered true when the control channel replied at all (even empty).
     * @param answeredPort the 127.0.0.1 SOCKS listener in that reply, 0 = none listed.
     */
    fun decide(published: Int, resolved: Int, answered: Boolean, answeredPort: Int): Verdict = when {
        published <= 0 -> Verdict.NO_CACHED_PORT
        !answered -> Verdict.DEAD
        resolved == SocksPortRedirect.BLOCKED_PORT -> Verdict.MOVING
        answeredPort <= 0 -> Verdict.NO_LISTENER
        answeredPort == resolved -> Verdict.CONFIRMED
        else -> Verdict.UNTRACKED_PORT
    }

    /** Alive but not yet confirmed: the caller re-checks after a short wait. */
    fun shouldWait(verdict: Verdict): Boolean =
        verdict == Verdict.MOVING || verdict == Verdict.NO_LISTENER || verdict == Verdict.UNTRACKED_PORT

    /** Pause between re-checks while [shouldWait]. */
    const val RECHECK_DELAY_MS = 500L

    /** At most this many re-checks... */
    const val RECHECK_BUDGET = 20

    /** ...and never past this much wall-clock time since the check began: one poll
     *  can take up to the control query's 3 s timeout, so a count alone could
     *  stretch to ~70 s. A move's own readback concludes within ~3 s of the toggle.
     *  The last poll started inside the budget may still add ≤ 3 s. */
    const val WAIT_BUDGET_MS = 15_000L

    /** True once the wait must stop and [settleAfterWait] decide. [attempt] is the
     *  poll that just answered (1-based); [elapsedMs] since the check began. */
    fun waitExhausted(attempt: Int, elapsedMs: Long): Boolean =
        attempt >= RECHECK_BUDGET || elapsedMs + RECHECK_DELAY_MS >= WAIT_BUDGET_MS

    enum class Settle {
        /** The move ended without a readback: wire the published port anyway — it
         *  resolves to the blocked port, so requests fail fast (never reach a
         *  squatter) and the health loop's NEWNYM → stalled / Reconnect ladder owns
         *  it. Never the relaunch latch: Tor answered. */
        WIRE_FAIL_CLOSED,
        /** Tor still lists no SOCKS listener: block the published port first
         *  ([SocksPortRedirect.beginMove]), then wire as [WIRE_FAIL_CLOSED]. */
        BLOCK_THEN_WIRE,
        /** Tor reports, on its authenticated control channel, a listener the redirect
         *  does not know: record published → that port ([SocksPortRedirect.completeMove],
         *  the same source a kick's readback uses), then wire the published port. */
        ADOPT_REPORTED_PORT,
        /** EVERY poll of the whole wait answered with no SOCKS listener (never a
         *  listener, never a move): a Tor that answers its control channel but has
         *  no SOCKS listener cannot serve this process, and iOS cannot restart it
         *  in-process (the bootstrap readback treats the same state as terminal).
         *  Latch relaunch-required, as for a silent channel. A toggle's empty
         *  window is sub-second and sits inside a MOVING run, so it never gets here. */
        LATCH_DEAD,
    }

    /**
     * The action once the wait is exhausted ([waitExhausted]) with [verdict] still
     * [shouldWait]. [everyPollNoListener]: every poll of this wait was NO_LISTENER.
     */
    fun settleAfterWait(verdict: Verdict, everyPollNoListener: Boolean): Settle? = when (verdict) {
        Verdict.MOVING -> Settle.WIRE_FAIL_CLOSED
        Verdict.NO_LISTENER -> if (everyPollNoListener) Settle.LATCH_DEAD else Settle.BLOCK_THEN_WIRE
        Verdict.UNTRACKED_PORT -> Settle.ADOPT_REPORTED_PORT
        else -> null
    }
}
