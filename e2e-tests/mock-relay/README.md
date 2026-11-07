# Mock relay (simulator/emulator e2e)

A controllable, dependency-free mock of the Rún relay so the app can mint / send /
poll **on a simulator or emulator**, where the real `.onion` relay is unreachable.

On a sim the app's relay URL is rewritten to `http://10.0.2.2:8080` (Android emu)
or `http://localhost:8080` (iOS sim) — both reach the **host on :8080**. Run the
mock there and the app talks to it over plain HTTP (no Tor — the URL isn't `.onion`).

## Run it standalone

```bash
npm run mock:relay            # listens on :8080 (MOCK_RELAY_PORT to override)
node mock-relay/selftest.js   # protocol self-test (16 assertions)
```

## Protocol

The protocol (inbox minting, blob transport, lease/ack, push registration, uniform `404`) is described in [`../README.md`](../README.md), section "The mock relay".

PoW difficulty defaults to **0** — the app solves `counter=0` instantly, so the
mint is free while keeping the real handshake shape.

Push handling mirrors the real relay: `POST /inbox/{id}` fires a
(recorded, not real) push iff the inbox has a registered token and the
request lacks `X-No-Push: 1` — no token means no push, unchanged from today.
Inspect intent with `GET /__control/pushes` (below); nothing ever reaches
real APNs from this mock.

## Control it from a spec

```ts
import * as MockRelay from '../helpers/MockRelay'

before(async () => { await MockRelay.start() })   // app now sees the relay reachable
after(async () => { await MockRelay.stop() })

// simulate the relay losing inboxes → affected contacts flip to "Re-pair required"
await MockRelay.dropAllInboxes()          // full wipe
await MockRelay.dropInbox(someInboxId)    // one inbox (see MockRelay.listInboxes())
await MockRelay.restoreInbox(someInboxId) // bring it back
await MockRelay.reset()                   // wipe all state between tests
await MockRelay.setRateLimit(true)        // 429 everything (exercise backoff)
await MockRelay.setVersions({ ios: '9.9.9' })   // advertise an update-nudge version header
await MockRelay.clearVersions()                 // back to "no header" (also done by reset())
```

`setVersions`/`clearVersions` drive `POST /__control/version {ios?, android?}`
(a present string sets that platform's `ios-version`/`android-version`
response header verbatim — no validation, since client-side parsing is what's
under test — `null` clears it, an omitted key leaves it unchanged; `GET
/__control/version` reads the current pair back). The resulting header is
sent on **every** response this mock makes, not just `/inbox/*` — see
`tests/update-nudge.spec.ts`.

Push intent is inspectable directly (no `MockRelay` helper yet):

```ts
const { pushes } = await (await fetch(`${base}/__control/pushes`)).json();
// [{ inboxId, count }, ...] — reset via the existing control-reset
```

