package com.vg.run

import kotlin.concurrent.Volatile

/**
 * RENDEZVOUS HEDGE (2026-10-25). THE decision, shared by both platforms; the
 * session's [MessageManager] owns the single watcher and the one hedge `GET /`.
 *
 * WHY. With the descriptor race ([RelayAddressRace]) the descriptor phase is
 * ~1 s; the remaining slow tail of a first connect is the RENDEZVOUS. Prod 1.6.48
 * coded timelines: iOS 20 s = two `REND_CIRC_FAILED`, `REND_JOINED` ~15 s after
 * `HSDESC_RECEIVED`; Android 15 s = `INTRO_DONE` at 5 s, `REND_JOINED` at 15 s
 * (10 s waiting for the service side to join). A healthy rendezvous joins 1–3 s
 * after the descriptor. Waiting on the one slow intro/rendezvous pair is pure
 * cost — Tor only tries another when the current one fails or hits the 45 s CBT.
 *
 * WHAT. While the transport's FIRST answer is still outstanding and a probe is in
 * flight, once [HEDGE_DELAY_MS] has passed since BOTH the first cold probe
 * started AND the session address's descriptor arrived, ONE extra bare `GET /`
 * (the health probe's own request: no capability, no inbox, no secret) goes out
 * through the same SOCKS port under a FRESH SOCKS5 username/password
 * ([SocksIsolation.newCredential], CSPRNG, per hedge). Tor's default
 * `IsolateSOCKSAuth` puts that stream in its own isolation class, so Tor builds
 * an INDEPENDENT intro + rendezvous pair for it in parallel with the slow one.
 * The first answer wins; the loser is ignored.
 *
 * THE ISOLATION CLASS BECOMES THE SESSION'S (the decisive part). Tor never
 * attaches a stream to a circuit of another isolation class — a no-auth stream
 * and an auth-X stream are incompatible (`connection_edge_compatible_with_circuit`,
 * ISO_SOCKSAUTH), and that holds for `HS_CLIENT_REND` circuits too. Measured on a
 * Mac Tor 0.4.9 client (control-port trace): GET A with auth X joined rend 14;
 * a NO-AUTH GET B afterwards did NOT use it — Tor built rend 16 + intro 17 for
 * it; GET C with auth X reused 14, GET D with no auth reused 16. So a hedge win
 * that left later traffic in the default class would buy nothing: the next
 * request would queue on the same slow rendezvous. On a win the credential is
 * therefore ADOPTED as the session's ([SocksIsolation.adopt]): every Tor-proxied
 * request of the process (session MessageManager, push registration, telemetry,
 * bug report, the next warm-up) is sent under it, exactly like
 * [RelayConfig.BASE_URL] follows the descriptor race. If the normal probe wins,
 * nothing changes (default class, today's behaviour, warm-up circuits reused).
 *
 * BOUNDS. ≤ 1 hedge per transport ([MessageManager] instance), only before its
 * first answer, only while a probe attempt is in flight (no timer without a live
 * request), never once an app-fired NEWNYM was accepted on the transport (the
 * NEWNYM rungs own recovery; an in-flight hedge opts into the NEWNYM abort and
 * is dropped by it), never without a known descriptor (a hedge stream would only
 * queue on the same fetch), never in external-SOCKS-proxy mode or on a direct
 * transport ([RelayHttp.supportsSocksIsolation] false).
 *
 * IDENTIFIERS. The credential is random, lives in RAM, travels only over the
 * loopback SOCKS handshake to the embedded Tor (Tor never forwards SOCKS auth)
 * and is never logged — neither here nor in either transport. The relay sees one
 * more bare `GET /` over a second rendezvous circuit, nothing else. Every line
 * below is fixed text plus whole seconds, UNCODED (so it never reaches the
 * connect telemetry — the relay allowlist has no hedge code yet).
 */
object RendezvousHedge {

    /** Hedge delay after max(first cold probe start, descriptor RECEIVED). A healthy
     *  rendezvous joins 1–3 s after the descriptor; the slow tail (10–15 s) is what
     *  this buys back. */
    const val HEDGE_DELAY_MS: Long = 3_000L

    /** Re-check granularity of the watcher while it waits (descriptor not yet
     *  known, or the delay not yet over). Only while a probe attempt is in flight. */
    const val POLL_MS: Long = 250L

    /** What the watcher does next. */
    enum class Action {
        /** Send the hedge now. */
        FIRE,
        /** Check again in [Step.recheckInMs]. */
        WAIT,
        /** No probe attempt in flight: stop watching; the next attempt re-arms. */
        PAUSE,
        /** Never on this transport (warm, NEWNYM seen, spent, unsupported). */
        NEVER,
    }

    class Step internal constructor(val action: Action, val recheckInMs: Long) {
        override fun toString(): String = "Step($action, $recheckInMs)"
    }

    /**
     * THE pure decision. All times on one monotonic clock ([DescriptorHedge.nowMs]).
     *
     * @param attemptInFlight a health-probe attempt of this transport is blocked on the relay now
     * @param coldProbeStartedAtMs the FIRST cold probe attempt of this transport, null = none yet
     * @param descriptorReceivedAtMs the session address's latest `HS_DESC RECEIVED` in the
     *        current Tor HS state ([RelayAddressRace.descriptorReceivedAtMs]), null = unknown
     * @param transportWarm this transport already had its first relay answer
     * @param newnymSeen an app-fired NEWNYM was accepted while this transport existed
     * @param spent this transport's one hedge is already used (or the control arm consumed it)
     * @param isolationSupported the transport can carry a SOCKS isolation credential
     */
    fun decide(
        nowMs: Long,
        attemptInFlight: Boolean,
        coldProbeStartedAtMs: Long?,
        descriptorReceivedAtMs: Long?,
        transportWarm: Boolean,
        newnymSeen: Boolean,
        spent: Boolean,
        isolationSupported: Boolean,
    ): Step {
        if (transportWarm || newnymSeen || spent || !isolationSupported) return Step(Action.NEVER, 0)
        if (!attemptInFlight || coldProbeStartedAtMs == null) return Step(Action.PAUSE, 0)
        // Descriptor not in Tor's cache yet: a hedge stream would just queue on the
        // same fetch (the descriptor hedge's business). Look again shortly.
        val descAt = descriptorReceivedAtMs ?: return Step(Action.WAIT, POLL_MS)
        val dueAt = maxOf(coldProbeStartedAtMs, descAt) + HEDGE_DELAY_MS
        val wait = dueAt - nowMs
        return if (wait <= 0) Step(Action.FIRE, 0) else Step(Action.WAIT, minOf(wait, POLL_MS))
    }

    // ------------------------------------------------------------ phrases
    // Fixed text + whole seconds. Uncoded → never part of the connect telemetry.

    /** `rendezvous hedge sent (no answer 3 s into the rendezvous)`. */
    val FIRED_PHRASE: String = "rendezvous hedge sent (no answer ${HEDGE_DELAY_MS / 1000} s into the rendezvous)"
    const val CONTROL_PHRASE: String = "rendezvous hedge off (control arm)"
    const val LOST_PHRASE: String = "rendezvous hedge not needed - the first rendezvous answered first"
    const val ABANDONED_PHRASE: String = "rendezvous hedge abandoned for fresh circuits"
    const val STALE_PHRASE: String = "rendezvous hedge answered after a Tor restart - ignored"

    /** `rendezvous hedge won in 2.4 s - relay traffic moves to its circuit`. */
    fun wonPhrase(elapsedMs: Long): String =
        "rendezvous hedge won in ${formatSeconds(elapsedMs)} s - relay traffic moves to its circuit"

    /** `rendezvous hedge got no answer in 20 s`. */
    fun noAnswerPhrase(elapsedMs: Long): String =
        "rendezvous hedge got no answer in ${formatSeconds(elapsedMs)} s"

    internal fun line(text: String) {
        platformLog("MessageManager", text)
        ConnectionLog.append(ConnectionLog.Kind.HEALTH, text)
    }

    // ------------------------------------------------------------ control arm

    @Volatile
    private var noHedgeControl = false

    /**
     * Physical-phone A/B no-hedge control arm (same shape as
     * [DescriptorHedge.setNoHedgeControl]). DEBUG BUILDS ONLY: returns false and
     * changes nothing in a release binary, so a shipped app always hedges.
     * Process-wide; read when a hedge would fire.
     */
    fun setNoHedgeControl(on: Boolean): Boolean {
        if (!isDebugBuild) return false
        noHedgeControl = on
        return true
    }

    /** False only while the debug-only control arm is set. */
    fun isHedgeEnabled(): Boolean = !noHedgeControl
}

/**
 * The process's SOCKS isolation class for relay traffic through the EMBEDDED Tor
 * (see [RendezvousHedge], "THE ISOLATION CLASS BECOMES THE SESSION'S").
 *
 * null = Tor's default class — exactly today's SOCKS handshake on both platforms.
 * Set only by a WON rendezvous hedge; sticky, like the descriptor race's winner,
 * until a new Tor process starts ([reset]: no circuit of any class survives one).
 * A new session in the same Tor process keeps it, so the pre-unlock warm-up and
 * the next session land in the class whose rendezvous is already joined.
 *
 * Read per request by the Tor transports (Android `PlatformHttpClient.torProxy`,
 * iOS `PlatformHttpClient(socksPort)` → SwiftTorHttp), never by the external-proxy
 * or direct ones. The value is a credential for the LOCAL Tor's SOCKS listener
 * only — never logged, never persisted, never sent past the loopback.
 */
object SocksIsolation {
    /** RFC 1929 requires PLEN ≥ 1. Tor isolates on username AND password; the
     *  username alone carries the randomness, so the password is a constant. */
    const val PASSWORD: String = "r"

    /** 16 CSPRNG bytes → 32 lowercase hex chars (well inside RFC 1929's 255). */
    private const val CREDENTIAL_BYTES = 16

    private val lock = SyncLock()
    private var tag: String? = null
    private var generation = 0L

    /** The session's isolation username, or null for Tor's default class. NEVER log. */
    fun current(): String? = lock.withLock { tag }

    /** Bumped by every [reset]; a hedge captures it when it fires so an answer from
     *  a previous Tor process can never be adopted. */
    fun generation(): Long = lock.withLock { generation }

    /** A fresh, never-reused isolation username. NEVER log. */
    fun newCredential(): String {
        val bytes = generateSecureRandom(CREDENTIAL_BYTES)
        val hex = "0123456789abcdef"
        val sb = StringBuilder(CREDENTIAL_BYTES * 2)
        for (b in bytes) {
            val v = b.toInt() and 0xff
            sb.append(hex[v ushr 4]).append(hex[v and 0x0f])
        }
        bytes.fill(0)
        return sb.toString()
    }

    /** A won hedge: relay traffic moves to [credential]'s class. Refused (false)
     *  when a new Tor process started since the hedge fired ([generationAtFire]). */
    fun adopt(credential: String, generationAtFire: Long): Boolean = lock.withLock {
        if (generation != generationAtFire || !isValidCredential(credential)) return@withLock false
        tag = credential
        true
    }

    /** A new Tor process: back to the default class. */
    fun reset() {
        lock.withLock {
            tag = null
            generation++
        }
    }

    /** What both transports accept as a username: 1..255 bytes of [a-z0-9]. */
    fun isValidCredential(credential: String): Boolean =
        credential.length in 1..255 && credential.all { it in 'a'..'z' || it in '0'..'9' }
}

/**
 * SOCKS5 (RFC 1928) + username/password (RFC 1929) byte builders for the Android
 * isolated transport. Pure, so the exact bytes are unit-pinned in commonTest. iOS
 * (SwiftTorHttp) builds the identical bytes in Swift.
 */
internal object Socks5Wire {
    const val VERSION: Int = 0x05
    const val METHOD_NO_AUTH: Int = 0x00
    const val METHOD_USER_PASS: Int = 0x02
    const val AUTH_VERSION: Int = 0x01

    /** `05 01 02` — exactly one method offered: username/password. Never 0x00 as
     *  well: a server choosing "no auth" would silently drop the isolation. */
    fun greetingUserPass(): ByteArray = byteArrayOf(0x05, 0x01, 0x02)

    /** `05 02 00 02` — the greeting java.net's SOCKS client sends (no-auth AND
     *  username/password). The Android OPTIMISTIC route repeats it byte for byte
     *  so its streams land in the default route's Tor isolation class — and so on
     *  the rendezvous circuit that route already joined (PlatformHttpClient.android.kt
     *  `socks5OptimisticOpen`). */
    fun greetingJavaNet(): ByteArray = byteArrayOf(0x05, 0x02, 0x00, 0x02)

    /** `01 ULEN UNAME PLEN PASSWD`. */
    fun userPassRequest(username: String, password: String): ByteArray {
        val u = username.encodeToByteArray()
        val p = password.encodeToByteArray()
        require(u.size in 1..255 && p.size in 1..255) { "SOCKS5 credential length out of range" }
        return byteArrayOf(AUTH_VERSION.toByte(), u.size.toByte()) + u + byteArrayOf(p.size.toByte()) + p
    }

    /** `05 01 00 03 LEN HOST PORT` — CONNECT by DOMAINNAME, so Tor resolves (SOCKS5h). */
    fun connectDomain(host: String, port: Int): ByteArray {
        val h = host.encodeToByteArray()
        require(h.size in 1..255) { "SOCKS5 host length out of range" }
        require(port in 1..65535) { "SOCKS5 port out of range" }
        return byteArrayOf(0x05, 0x01, 0x00, 0x03, h.size.toByte()) + h +
            byteArrayOf((port ushr 8).toByte(), (port and 0xff).toByte())
    }

    /** Bytes after the 4-byte reply header for ATYP [atyp] (BND.ADDR + BND.PORT);
     *  -1 = domain (read one length byte first, then that + 2); -2 = invalid. */
    fun replyTailLength(atyp: Int): Int = when (atyp) {
        0x01 -> 4 + 2
        0x04 -> 16 + 2
        0x03 -> -1
        else -> -2
    }
}
