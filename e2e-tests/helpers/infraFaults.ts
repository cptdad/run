/**
 * Infra-fault classification for the physical cross-platform e2e suites.
 *
 * GOAL (2026-07-24): make "a failed test == a real bug". On the physical
 * cross suites, far more reds come from the automation TRANSPORT dying under
 * load — the WebDriver session dropping, Appium/WDA being torn down, the proxy
 * socket hanging up — than from a genuine product assertion. Those transport
 * deaths must be QUARANTINED: detected, logged distinctly, and recovered via a
 * clean-slate spec-file retry (a fresh session). They must NOT read as a
 * product failure, because then a red result no longer means a bug.
 *
 * This module is the single source of truth for the question "is this error
 * the transport dying, or is it the app / an assertion?". It keys ONLY on
 * transport/session-level signatures. A `NoSuchElementError` is deliberately
 * NOT an infra fault — that is either a slow app (which the Device.ts waits
 * already absorb) or a real product bug, and either way must be allowed to
 * surface. Keep INFRA_SIGNATURES conservative: a false "infra" verdict would
 * let a genuine bug be retried away and reported green.
 */

/**
 * Lowercase substrings that appear ONLY when the WebDriver/Appium/WDA/adb
 * transport itself has failed — never on a normal element-not-found or a
 * product assertion. Sourced from observed physical-run failures (the
 * "socket hang up" iOS WDA drop and the "session is either terminated or not
 * started" Appium reap this suite has actually hit) plus the standard
 * node/appium transport-death set.
 */
const INFRA_SIGNATURES: readonly string[] = [
    'socket hang up',
    'could not proxy command',
    'invalid session id',
    'session not created',
    'terminated or not started', // "session is either terminated or not started"
    'session does not exist',
    'a session is either terminated',
    'econnreset',
    'econnrefused',
    'connection refused',
    'client network socket disconnected',
    'was not in the list of connected devices',
    'appium exited',
    'not started or has crashed',
    'device is not connected',
    'unable to launch webdriveragent',
    'wda is not ready',
    'instruments crashed',
    'closed with error code',
]

/** Flatten any thrown value into the lowercased text we match signatures against. */
function faultText(err: unknown): string {
    if (err == null) return ''
    if (typeof err === 'string') return err.toLowerCase()
    const e = err as { message?: unknown; stack?: unknown; cause?: unknown }
    const parts: string[] = []
    if (typeof e.message === 'string') parts.push(e.message)
    if (typeof e.stack === 'string') parts.push(e.stack)
    // WebdriverIO frequently nests the real transport error under `cause`.
    if (e.cause != null && e.cause !== err) parts.push(faultText(e.cause))
    if (parts.length === 0) parts.push(String(err))
    return parts.join(' \n ').toLowerCase()
}

/**
 * True iff [err] is an automation-transport death (session/Appium/WDA/adb),
 * as opposed to an app-slowness or assertion failure. This is the ONLY
 * predicate callers should use to decide "quarantine + recover" vs. "surface
 * as a real failure".
 */
export function isInfraFault(err: unknown): boolean {
    if (err instanceof InfraFaultError) return true
    const text = faultText(err)
    if (!text) return false
    return INFRA_SIGNATURES.some((sig) => text.includes(sig))
}

/** The specific signature that matched, for legible logging. '' if none. */
export function infraFaultSignature(err: unknown): string {
    if (err instanceof InfraFaultError) return err.signature
    const text = faultText(err)
    return INFRA_SIGNATURES.find((sig) => text.includes(sig)) ?? ''
}

/**
 * A transport-death error, distinguishable by type so a long polling loop can
 * abort its whole attempt IMMEDIATELY (in seconds) instead of swallowing the
 * dead-session error in a bare `catch` and spinning to its multi-minute
 * deadline with a misleading app-logic message. Carries the original error as
 * `cause` and the matched `signature`.
 */
export class InfraFaultError extends Error {
    readonly signature: string
    readonly original: unknown
    constructor(original: unknown, whileDoing?: string) {
        const sig = infraFaultSignature(original)
        const where = whileDoing ? ` during ${whileDoing}` : ''
        super(`[INFRA-FAULT${sig ? ` ${sig}` : ''}]${where}: ${describeError(original)}`)
        this.name = 'InfraFaultError'
        this.signature = sig
        this.original = original
    }
}

/**
 * Re-throw [err] as an {@link InfraFaultError} IFF it is a transport death;
 * otherwise return silently so the caller's existing best-effort handling
 * (e.g. "no-op if the element isn't there") proceeds unchanged. Drop this into
 * the bare `catch { /* best-effort *\/ }` blocks that today swallow a dead
 * session and keep polling:
 *
 *     } catch (e) { rethrowIfInfra(e, 'readMyCode'); /* else best-effort *\/ }
 */
export function rethrowIfInfra(err: unknown, whileDoing?: string): void {
    if (isInfraFault(err)) throw new InfraFaultError(err, whileDoing)
}

/** 'infra' if the failure is a transport death, else 'test' (product/assertion). */
export function classifyFailure(err: unknown): 'infra' | 'test' {
    return isInfraFault(err) ? 'infra' : 'test'
}

/** Short one-line description of any thrown value, for log lines. */
export function describeError(err: unknown): string {
    if (err == null) return '(no error)'
    if (typeof err === 'string') return err.split('\n')[0].slice(0, 300)
    const e = err as { message?: unknown }
    if (typeof e.message === 'string') return e.message.split('\n')[0].slice(0, 300)
    return String(err).slice(0, 300)
}
