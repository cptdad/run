package com.vg.run

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Source guard for the iOS unlock-time check of a cached SOCKS port (2026-11-15).
 * The verdict table is shared commonMain code (`UnlockPortCheck`, pinned by
 * `UnlockPortCheckTest`); what the Swift compiler cannot check is the glue:
 *
 *  - startTorOrDirect authenticates the cached port only through
 *    authenticateCachedSocksPort, which decides with `UnlockPortCheck.decide` over
 *    the tri-state control answer — never a direct published-vs-control compare
 *    (a network toggle moves the listener before the port is re-published, and
 *    that compare declared a live Tor dead);
 *  - `markThreadDead()` is reached from AppState ONLY through latchTorDeadAtUnlock,
 *    called from the DEAD verdict's branch (a SILENT control channel) and the
 *    all-no-listener settle outcome (LATCH_DEAD) — nowhere else;
 *  - CONFIRMED SOCKS-probes the RESOLVED port, never the published one;
 *  - an alive-but-unconfirmed verdict never wires directly: only after the wait,
 *    through TorManager.settleUnconfirmedSocksPort;
 *  - the current-value wiring paths (the port sink, the health-loop self-heal)
 *    stay gated on `cachedPortAuthenticationInFlight`;
 *  - the DEBUG suspend probe uses the same table;
 *  - TorManager's query reports `.silent` only for a down channel or a timeout with
 *    no reply at all.
 * Bodies are scanned with comments stripped.
 */
class IosUnlockPortCheckSourceTest {

    private val appState: String by lazy { stripComments(iosAppStateSources()) }
    private val torManager: String by lazy {
        stripComments(File(repoRoot(), "iosApp/iosApp/TorManager.swift").readText())
    }

    private fun funcBody(src: String, signature: String): String {
        val at = src.indexOf(signature)
        assertTrue("'$signature' not found", at >= 0)
        return braceBody(src, src.indexOf('{', at + signature.length - 1))
    }

    private val startTorOrDirect by lazy { funcBody(appState, "private func startTorOrDirect()") }
    private val authenticate by lazy { funcBody(appState, "private func authenticateCachedSocksPort(") }

    @Test fun unlockPathRoutesThroughTheSharedDecision() {
        assertTrue(startTorOrDirect.contains("authenticateCachedSocksPort(token:"))
        assertTrue(startTorOrDirect.contains("cachedPortAuthenticationInFlight = true"))
        assertFalse("no direct published-vs-control compare", startTorOrDirect.contains("confirmedPort =="))
        assertFalse(startTorOrDirect.contains("markThreadDead"))
        assertTrue(authenticate.contains("querySocksListenerViaControl"))
        assertTrue(authenticate.contains("UnlockPortCheck.shared.decide("))
        assertTrue(authenticate.contains("SocksPortRedirect.shared.resolve("))
    }

    private fun branch(src: String, head: String): String {
        val at = src.indexOf(head)
        assertTrue("'$head' not found", at >= 0)
        return braceBody(src, src.indexOf('{', at + head.length - 1))
    }

    @Test fun markThreadDeadOnlyFromTheSilentVerdictOrTheAllNoListenerWait() {
        assertEquals("markThreadDead must be called exactly once in AppState",
            1, Regex("""\bmarkThreadDead\(\)""").findAll(appState).count())
        val latch = funcBody(appState, "private func latchTorDeadAtUnlock(")
        assertTrue("the one call lives in latchTorDeadAtUnlock", latch.contains("markThreadDead()"))
        // Call sites only (the declaration is `func latchTorDeadAtUnlock(reason: String)`).
        val callSite = Regex("""(?<!func )latchTorDeadAtUnlock\(reason:""")
        assertEquals("latchTorDeadAtUnlock: exactly the two call sites", 2, callSite.findAll(appState).count())
        assertEquals(2, callSite.findAll(authenticate).count())
        val dead = branch(authenticate, "} else if verdict == UnlockPortCheck.Verdict.dead {")
        assertTrue(dead.contains("latchTorDeadAtUnlock(reason:"))
        val latchDead = branch(authenticate, "if settle == UnlockPortCheck.Settle.latchDead {")
        assertTrue(latchDead.contains("latchTorDeadAtUnlock(reason:"))
        assertTrue("the all-no-listener fold feeds the settle",
            authenticate.contains("settleAfterWait(verdict: verdict, everyPollNoListener: noListenerSoFar)"))
        assertTrue(authenticate.contains("let noListenerSoFar = everyPollNoListener && verdict == UnlockPortCheck.Verdict.noListener"))
    }

    @Test fun confirmedProbesTheResolvedPort() {
        val confirmed = branch(authenticate, "if verdict == UnlockPortCheck.Verdict.confirmed {")
        assertTrue(confirmed.contains("wireAuthenticatedSocksPort(published: published, probePort: UInt16(resolved)"))
        val wire = funcBody(appState, "private func wireAuthenticatedSocksPort(")
        assertTrue(wire.contains("probeSocksPort(probePort)"))
        assertFalse("never greet the stale published port", wire.contains("probeSocksPort(published)"))
        val probes = Regex("""probeSocksPort\(([A-Za-z.]+)""").findAll(authenticate + wire).map { it.groupValues[1] }.toSet()
        assertEquals(setOf("probePort"), probes)
    }

    @Test fun unconfirmedVerdictsWireOnlyAfterTheSettle() {
        assertEquals("one direct wire in the check, the settled one",
            1, Regex("""wireRelayTransport\(""").findAll(authenticate).count())
        val wait = branch(authenticate, "} else if UnlockPortCheck.shared.shouldWait(verdict: verdict) {")
        val settleAt = wait.indexOf("tor.settleUnconfirmedSocksPort(")
        val wireAt = wait.indexOf("wireRelayTransport(")
        assertTrue("settle exists", settleAt >= 0)
        assertTrue("wire comes after the settle", wireAt > settleAt)
        val exhaustedAt = wait.indexOf("waitExhausted(")
        val returnAt = wait.indexOf("return", exhaustedAt)
        assertTrue("the re-check returns before the settle", exhaustedAt in 0 until returnAt && returnAt < settleAt)
        val confirmed = branch(authenticate, "if verdict == UnlockPortCheck.Verdict.confirmed {")
        assertFalse(confirmed.contains("wireRelayTransport("))
    }

    @Test fun currentValueWiringPathsStayGated() {
        val sink = funcBody(appState, "private func subscribeSocksPortAndUnlock()")
        val gateAt = sink.indexOf("!self.cachedPortAuthenticationInFlight")
        assertTrue("port sink gate", gateAt >= 0)
        assertTrue("gate before the wire", gateAt < sink.indexOf("wireRelayTransport("))
        val heal = funcBody(appState, "private func selfHealAbsentTransport()")
        val healGate = heal.indexOf("!cachedPortAuthenticationInFlight")
        assertTrue("self-heal gate", healGate >= 0)
        assertTrue("gate before the wire", healGate < heal.indexOf("wireRelayTransport("))
    }

    @Test fun everyExitOfTheCheckReleasesTheFlagOrRetries() {
        // Each callback path either re-schedules the check or clears the flag.
        assertTrue(authenticate.contains("UnlockPortCheck.shared.shouldWait(verdict:"))
        assertTrue(authenticate.contains("UnlockPortCheck.shared.waitExhausted("))
        assertTrue(authenticate.contains("settleAfterWait(verdict:"))
        assertTrue("superseded check never touches a newer flag", authenticate.contains("token == self.cachedPortAuthToken"))
        assertTrue("a lock ends the wait", authenticate.contains("generation == self.sessionGeneration"))
        assertTrue(Regex("""cachedPortAuthenticationInFlight = false""").findAll(authenticate).count() >= 5)
    }

    @Test fun suspendProbeUsesTheSameTable() {
        val probe = funcBody(appState, "private func runTorSuspendProbe()")
        assertTrue(probe.contains("UnlockPortCheck.shared.decide("))
        assertFalse(probe.contains("confirmedPort =="))
    }

    @Test fun silentOnlyForADownChannelOrNoReply() {
        assertFalse("the old nil-means-dead query is gone", torManager.contains("confirmSocksPortViaControl"))
        val query = funcBody(torManager, "func querySocksListenerViaControl(")
        assertTrue(query.contains("finish(sawReply ? .noListener : .silent)"))
        val attempt = funcBody(torManager, "private func attemptSocksPortQuery(")
        assertTrue(attempt.contains("finish(.noListener)"))
        assertEquals("only the down-channel guard reports .silent per attempt",
            1, Regex("""\.silent\b""").findAll(attempt).count())
    }
}
