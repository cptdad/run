// Test-side control of the mock relay (mock-relay/server.js). A spec starts it
// in `before`, drives relay-side conditions during the test, and stops it in
// `after`. The app on a sim/emulator reaches it at host :8080 (10.0.2.2 / localhost).
//
//   import * as MockRelay from '../helpers/MockRelay'
//   before(async () => { await MockRelay.start() })
//   after(async () => { await MockRelay.stop() })
//   // ... pair / send over the mock ...
//   await MockRelay.dropAllInboxes()   // simulate a full relay wipe → contacts flip to "Re-pair required"
import { spawn, ChildProcess } from 'child_process'
import * as http from 'http'
import * as path from 'path'

const PORT = 8080
const SERVER = path.resolve(__dirname, '..', 'mock-relay', 'server.js')
let proc: ChildProcess | undefined

/**
 * Spawn the mock relay on :8080 and wait until it answers. Idempotent.
 *
 * this used to accept "something answered on
 * :8080" as success. If the port was already taken — an orphaned
 * `mock-relay/server.js` from an earlier run is the usual culprit — our child died of
 * an unobserved EADDRINUSE while the suite drove that FOREIGN server, producing
 * failures with no plausible cause. Now: refuse to start if the port is already
 * occupied, watch the child for an early exit, and verify via `/__control/whoami`
 * that the thing answering is actually ours.
 */
export async function start(): Promise<void> {
  if (proc) return
  if (await reachable()) {
    throw new Error(
      `port ${PORT} is already in use before the mock relay started — ` +
      `something else owns it (orphaned mock-relay/server.js? another suite?). ` +
      `Free it with: lsof -iTCP:${PORT} -sTCP:LISTEN`,
    )
  }
  const child = spawn('node', [SERVER], { env: { ...process.env, MOCK_RELAY_PORT: String(PORT) }, stdio: 'inherit' })
  proc = child
  let exited: string | undefined
  child.on('exit', (code, signal) => { exited = `code=${code} signal=${signal}` })
  for (let i = 0; i < 60; i++) {
    if (exited) throw new Error(`mock relay exited during startup (${exited}) — port ${PORT} taken?`)
    if (await reachable()) {
      const id = await control('whoami').catch(() => undefined)
      if (!id || id.server !== 'mock-relay') {
        throw new Error(
          `:${PORT} is answering but is NOT our mock relay (whoami=${JSON.stringify(id)}) — ` +
          `refusing to run the suite against a foreign server`,
        )
      }
      return
    }
    await sleep(100)
  }
  throw new Error('mock relay did not come up on :' + PORT)
}

/** Kill the mock relay process. */
export async function stop(): Promise<void> {
  if (proc) { proc.removeAllListeners('exit'); proc.kill(); proc = undefined }
}

// --- Control API ---
export const reset = () => control('reset')
export const dropAllInboxes = () => control('dropAll')                       // full relay wipe
export const dropInbox = (inboxId: string) => control('drop', { inboxId })   // lose one inbox
export const restoreInbox = (inboxId: string) => control('restore', { inboxId })
export const listInboxes = (): Promise<{ inboxes: string[]; dropped: string[] }> => control('inboxes')
export const state = (): Promise<{ inboxCount: number; dropped: string[]; difficulty: number; rateLimit: boolean }> => control('state')
export const setDifficulty = (difficulty: number) => control('difficulty', { difficulty })
export const setRateLimit = (on: boolean) => control('rateLimit', { on })
/**
 * Set the mock relay's advertised update-nudge version headers
 * (docs/update-nudge-plan.md): a present string sets that platform's value
 * (passed through verbatim — the mock does no validation, since client-side
 * parsing is what's under test), `null` clears it, an omitted key leaves it
 * unchanged. Must be called BEFORE the app's vault unlocks — the client
 * latches onto the FIRST successful relay response of the session, so a
 * version set after connect is too late.
 */
export const setVersions = (v: { ios?: string | null; android?: string | null }) => control('version', v)
/** Clear both advertised versions (header absent on both platforms). */
export const clearVersions = () => control('version', { ios: null, android: null })
/** The mock's currently advertised pair — handy for debugging. */
export const getVersions = (): Promise<{ ios: string | null; android: string | null }> => request('GET', '/__control/version')

function control(cmd: string, body?: object): Promise<any> {
  return request('POST', `/__control/${cmd}`, body)
}
function reachable(): Promise<boolean> {
  return request('GET', '/').then(() => true).catch(() => false)
}
function request(method: string, p: string, body?: object): Promise<any> {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : undefined
    const req = http.request(
      { host: '127.0.0.1', port: PORT, path: p, method, headers: data ? { 'content-type': 'application/json' } : {} },
      (res) => {
        const cs: Buffer[] = []
        res.on('data', (c) => cs.push(c as Buffer))
        res.on('end', () => { const s = Buffer.concat(cs).toString(); try { resolve(s ? JSON.parse(s) : {}) } catch { resolve(s) } })
      },
    )
    req.on('error', reject)
    if (data) req.write(data)
    req.end()
  })
}
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))
