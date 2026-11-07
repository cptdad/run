#!/usr/bin/env node
// ---------------------------------------------------------------------------
// Controllable mock of the Rún relay, for the simulator/emulator e2e suites.
//
// On a sim/emulator the app's relay URL is rewritten to http://10.0.2.2:8080
// (Android emu) / http://localhost:8080 (iOS sim) — both reach the HOST :8080,
// where nothing normally listens (so the relay is "always unreachable"). Run
// this there and the app can actually mint / send / poll against it, WITHOUT
// Tor (the URL isn't .onion, so the app uses direct HTTP).
//
// It speaks the real relay protocol (mirrors MessageManager):
//   GET    /                                   → 200            (health: any response = "up")
//   POST   /inbox            (no X-PoW-Token)   → 400 {nonce,token,difficulty,...}  (PoW challenge)
//   POST   /inbox            (valid X-PoW-Token)→ 201 {inboxId,readCapability,writeCapability,expiresAt}
//   POST   /inbox/{id}       + X-Write-Capability → 202   (append raw body bytes)
//   GET    /inbox/{id}       + X-Read-Capability  → 200 {"blobs":["<std-b64>"]} + DRAINS visible blobs
//   GET    /inbox/{id}?lease=1                    → 200 {"blobs","ids","token"}; deletes nothing, LEASES
//            the blobs for MOCK_RELAY_LEASE_MS (default 60000) — see lease.js
//   POST   /ack  {"v":1,"items":[{id,rc,token,delete:[ids]}]} → per-item {deleted,released}|{status:404}
//   GET    /inbox/{id}/peek  + X-Read-Capability  → 200 {"pending":N}            (non-destructive)
//   DELETE /inbox/{id}       + X-Read-Capability  → 200            (owner-only)
//   PUT    /inbox/{id}/(read|write)-capability    → 200            (owner-only)
//            auth X-Read-Capability (writers can NOT rotate),
//            new value X-New-Read-Capability / X-New-Write-Capability
//   PUT    /inbox/{id}/push  + X-Read-Capability  → 200  body:{platform,token,env,p256dh?,auth?}
//            platform: apns|fcm|unifiedpush. unifiedpush requires an https://
//            token (≤1024 chars) + p256dh/auth as a matched pair; apns/fcm
//            reject bodies carrying either key (platform-exclusive).
//   DELETE /inbox/{id}/push  + X-Read-Capability  → 200  (deregister; 200 even if none)
//   gone / wrong-cap / locked / dropped inbox     → 404 {"error":"request rejected"}
//
// PoW: difficulty defaults to 0, so the app solves counter=0 instantly and the
// mint is effectively free — the handshake shape is preserved, the grind isn't.
//
// Phase-3 push (mirrors the real relay's contentless-APNs contract):
// a registered push token lives on the inbox itself, so DELETE /inbox/{id} or a
// control drop/reset takes it with it — no separate expiry bookkeeping needed.
// POST /inbox/{id} never calls real APNs; it just records "a push would have
// fired" in pushCounts, inspectable via GET /__control/pushes, so specs can
// assert push intent without a real APNs key. `X-No-Push: 1` suppresses it,
// exactly like the real relay.
//
// Control API (test-only — the app never calls /__control/*):
//   POST /__control/reset                    wipe all state (incl. push registrations/counts
//                                             AND the advertised ios/android versions below)
//   POST /__control/inboxes                  → {inboxes:[ids], dropped:[ids]}
//   POST /__control/drop      {inboxId}      that inbox now 404s (relay "lost" it)
//   POST /__control/dropAll                  every inbox now 404s (full relay wipe)
//   POST /__control/restore   {inboxId}      un-drop
//   POST /__control/difficulty {difficulty}  set the PoW difficulty (default 0)
//   POST /__control/rateLimit  {on}          429 everything (exercise backoff)
//   POST /__control/state                    → {inboxCount,dropped,difficulty,rateLimit}
//   GET  /__control/pushes                   → {"pushes":[{"inboxId":..,"count":N}]}
//   POST /__control/version {ios?,android?}  set the advertised update-nudge version headers
//                                             a present string sets
//                                             that platform's value verbatim (no validation — the
//                                             mock passes ANY string through unchanged, since
//                                             client-side parsing is what's under test), `null`
//                                             clears it, an omitted key leaves it unchanged.
//                                             Initial values from env MOCK_RELAY_IOS_VERSION /
//                                             MOCK_RELAY_ANDROID_VERSION (unset → absent). The
//                                             resulting header (`ios-version` / `android-version`)
//                                             is sent on EVERY response this server makes — every
//                                             route, every 404/429, the control API itself — iff
//                                             the respective value is set.
//   GET  /__control/version                  → {ios,android} current advertised values (null if unset)
// ---------------------------------------------------------------------------

const http = require('http');
const crypto = require('crypto');
const L = require('./lease');

// Standard base64 (matches java.util.Base64.getDecoder() the app uses to decode
// drained blobs) and base64url (the inbox-id / cap / nonce / token alphabet).
const b64 = (buf) => buf.toString('base64');
const b64url = (buf) => buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

function createMockRelay() {
  const inboxes = new Map();   // id -> { readCap, writeCap, blobs: [Buffer], expiresAt, push: {platform,token,env,p256dh?,auth?}|null }
  const tokens = new Set();    // PoW tokens issued in phase 1, consumed in phase 2
  const dropped = new Set();   // inbox ids the relay has "lost" → 404 everything
  const pushCounts = new Map(); // id -> number of pushes that "fired" on append (see GET /__control/pushes)
  const state = { difficulty: 0, rateLimit: false };
  // Update-nudge advertised versions. Env sets the
  // initial value; unset env → absent (null), not an empty string, matching
  // the real relay's "absent config → header absent" contract.
  const versions = {
    ios: process.env.MOCK_RELAY_IOS_VERSION || null,
    android: process.env.MOCK_RELAY_ANDROID_VERSION || null,
  };

  const newInboxId = () => b64url(crypto.randomBytes(24)).slice(0, 32);  // 32 chars, ^[A-Za-z0-9_-]{32}$
  const newCap = () => b64url(crypto.randomBytes(32));                   // 43 chars, header-safe
  // A capability is base64url-no-pad(32 bytes) = 43 chars — the shape newCap()
  // mints, what MessageManager generates for a rotation, and what the real
  // relay's isValidCapability() enforces before it will rotate anything.
  const isCap = (v) => typeof v === 'string' && /^[A-Za-z0-9_\-]{43}$/.test(v);
  const newChallenge = () => {
    const token = b64url(crypto.randomBytes(18));
    tokens.add(token);
    return {
      error: 'pow required', nonce: b64url(crypto.randomBytes(18)), token,
      difficulty: state.difficulty, ttlSeconds: 120, algorithm: 'sha256', preimage: 'nonce:counter',
    };
  };

  const readBody = (req) => new Promise((resolve) => {
    const chunks = []; req.on('data', (c) => chunks.push(c)); req.on('end', () => resolve(Buffer.concat(chunks)));
  });
  const json = (res, code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); };
  const reject = (res) => json(res, 404, { error: 'request rejected' });

  const server = http.createServer(async (req, res) => {
    const path = new URL(req.url, 'http://x').pathname;
    const method = req.method;
    const h = req.headers;

    // Update-nudge headers, on EVERY response (all routes, 404s, 429s, the
    // control API too) — mirrors the real relay's intercept-at-Plugins-stage
    // placement, just simpler since this mock has no plugin pipeline. Set via
    // res.setHeader() (not writeHead's headers arg) so it survives whichever
    // branch below eventually calls writeHead()/end() — Node merges queued
    // setHeader() values into writeHead(), headers passed to writeHead()
    // taking precedence (none of our writeHead() calls pass these names, so
    // there's never a conflict).
    if (versions.ios != null) res.setHeader('ios-version', versions.ios);
    if (versions.android != null) res.setHeader('android-version', versions.android);

    // --- Control API (test-only) ---
    if (path.startsWith('/__control/')) {
      let body = {};
      try { body = JSON.parse((await readBody(req)).toString() || '{}'); } catch { /* tolerate empty */ }
      switch (path.slice('/__control/'.length)) {
        case 'reset': inboxes.clear(); tokens.clear(); dropped.clear(); pushCounts.clear(); state.difficulty = 0; state.rateLimit = false; versions.ios = null; versions.android = null; return json(res, 200, { ok: true });
        case 'inboxes': return json(res, 200, { inboxes: [...inboxes.keys()], dropped: [...dropped] });
        case 'pushes': return json(res, 200, { pushes: [...pushCounts.entries()].map(([inboxId, count]) => ({ inboxId, count })) });
        case 'drop': if (body.inboxId) dropped.add(body.inboxId); return json(res, 200, { ok: true, dropped: [...dropped] });
        case 'dropAll': for (const id of inboxes.keys()) dropped.add(id); return json(res, 200, { ok: true, dropped: [...dropped] });
        case 'restore': dropped.delete(body.inboxId); return json(res, 200, { ok: true });
        case 'difficulty': state.difficulty = (body.difficulty | 0); return json(res, 200, { ok: true, difficulty: state.difficulty });
        case 'rateLimit': state.rateLimit = !!body.on; return json(res, 200, { ok: true, rateLimit: state.rateLimit });
        case 'state': return json(res, 200, { inboxCount: inboxes.size, dropped: [...dropped], difficulty: state.difficulty, rateLimit: state.rateLimit });
        // Update-nudge. POST {ios?, android?}: a
        // present string (ANY string — the mock does no validation, unlike
        // the real relay's ApplicationTest-covered grammar check) sets that
        // platform's advertised version verbatim; `null` clears it; an
        // omitted key leaves it unchanged. GET (or a bodyless POST) just
        // reports the current pair — handy for debugging.
        case 'version':
          if (method === 'POST') {
            if (Object.prototype.hasOwnProperty.call(body, 'ios')) versions.ios = body.ios === null ? null : String(body.ios);
            if (Object.prototype.hasOwnProperty.call(body, 'android')) versions.android = body.android === null ? null : String(body.android);
          }
          return json(res, 200, { ios: versions.ios, android: versions.android });
        // Identity probe. "Something answers on
        // :8080" is NOT proof it is OUR mock relay — an orphaned mock-relay/server.js
        // from an earlier run answers too, and the suite would then silently drive
        // a foreign server. MockRelay.start() checks this marker.
        case 'whoami': return json(res, 200, { server: 'mock-relay', pid: process.pid });
        default: return json(res, 404, { error: 'unknown control' });
      }
    }

    if (state.rateLimit) return json(res, 429, { error: 'rate limited' });

    // --- Health ---
    if (path === '/' && method === 'GET') { res.writeHead(200); return res.end('mock relay up'); }

    // --- Mint (two-phase PoW handshake) ---
    if (path === '/inbox' && method === 'POST') {
      await readBody(req);
      const token = h['x-pow-token'];
      if (!token) return json(res, 400, newChallenge());           // phase 1: hand out a challenge
      if (!tokens.has(token)) return json(res, 400, newChallenge()); // stale/unknown token → re-solve
      tokens.delete(token);                                         // phase 2: counter trusted (difficulty 0)
      const id = newInboxId(), readCap = newCap(), writeCap = newCap();
      const expiresAt = Date.now() + 365 * 24 * 60 * 60 * 1000;    // far future in any unit interpretation
      inboxes.set(id, { readCap, writeCap, blobs: [], expiresAt, push: null });
      return json(res, 201, { inboxId: id, readCapability: readCap, writeCapability: writeCap, expiresAt });
    }

    // --- Retrieve-ack (mirrors the real relay's POST /ack) ---
    if (path === '/ack' && method === 'POST') {
      const r = L.ack(await readBody(req), (id) => (dropped.has(id) ? undefined : inboxes.get(id)),
        (a, b) => typeof a === 'string' && typeof b === 'string' && a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)));
      return json(res, r.code, r.body);
    }

    // --- /inbox/{id} and /inbox/{id}/<suffix> ---
    const m = path.match(/^\/inbox\/([A-Za-z0-9_\-]{32})(\/peek|\/read-capability|\/write-capability|\/push)?$/);
    if (m) {
      const id = m[1], suffix = m[2] || '';
      const inbox = inboxes.get(id);
      if (!inbox || dropped.has(id)) return reject(res);           // gone / lost / unknown → 404

      if (method === 'GET' && suffix === '/peek') {
        if (h['x-read-capability'] !== inbox.readCap) return reject(res);
        return json(res, 200, { pending: L.visibleCount(inbox) });   // leased blobs are invisible
      }
      if (method === 'GET' && suffix === '') {
        if (h['x-read-capability'] !== inbox.readCap) return reject(res);
        // ?lease=1: nothing deleted, blobs leased until POST /ack (or expiry);
        // plain GET: legacy delete-on-fetch of the visible (unleased) blobs.
        if (new URL(req.url, 'http://x').searchParams.get('lease') === '1') return json(res, 200, L.lease(inbox));
        return json(res, 200, L.drain(inbox));
      }
      if (method === 'POST' && suffix === '') {
        if (h['x-write-capability'] !== inbox.writeCap) return reject(res);
        inbox.blobs.push(L.makeBlob(await readBody(req)));
        // Phase-3 push: fires (records intent, never calls real APNs) iff a
        // token is registered AND the sender didn't opt out. No token => no
        // push — same back-compat guarantee as the real relay.
        if (inbox.push && h['x-no-push'] !== '1') {
          pushCounts.set(id, (pushCounts.get(id) || 0) + 1);
        }
        return json(res, 202, { ok: true });
      }
      // Owner-only ops. Delete AND both rotations authenticate with the inbox's
      // READ cap (writers cannot rotate) — mirrors MessageManager's wire-contract
      // header block and the real relay. Without this check a rotation/deletion
      // spec would pass even if the client sent no capability at all. A rejected
      // request must also be a NO-OP: the inbox and its caps stay untouched.
      if (method === 'DELETE' && suffix === '') {
        if (h['x-read-capability'] !== inbox.readCap) return reject(res);
        inboxes.delete(id); pushCounts.delete(id);
        return json(res, 200, { ok: true });
      }
      if (method === 'PUT' && (suffix === '/read-capability' || suffix === '/write-capability')) {
        await readBody(req);
        if (h['x-read-capability'] !== inbox.readCap) return reject(res);
        const rotatingRead = suffix === '/read-capability';
        const next = h[rotatingRead ? 'x-new-read-capability' : 'x-new-write-capability'];
        if (!isCap(next)) return reject(res);                      // absent/malformed new cap → cap unchanged
        if (rotatingRead) inbox.readCap = next; else inbox.writeCap = next;
        return json(res, 200, { ok: true });
      }
      if (method === 'PUT' && suffix === '/push') {
        if (h['x-read-capability'] !== inbox.readCap) return reject(res);
        let body = {};
        try { body = JSON.parse((await readBody(req)).toString() || '{}'); } catch { return json(res, 400, { error: 'invalid push registration body' }); }
        const platform = body.platform;
        const validPlatform = platform === 'apns' || platform === 'fcm' || platform === 'unifiedpush';
        const validEnv = body.env === 'sandbox' || body.env === 'production';
        if (!validPlatform || !body.token || !validEnv) {
          return json(res, 400, { error: 'invalid push registration body' });
        }
        if (platform === 'unifiedpush') {
          // Endpoint URL must be https (≤1024 chars); p256dh/auth (WebPush
          // keys) are a matched pair — both required, neither optional.
          const hasKeys = typeof body.p256dh === 'string' && body.p256dh.length > 0
            && typeof body.auth === 'string' && body.auth.length > 0;
          if (typeof body.token !== 'string' || !body.token.startsWith('https://') || body.token.length > 1024 || !hasKeys) {
            return json(res, 400, { error: 'invalid push registration body' });
          }
          inbox.push = { platform, token: body.token, env: body.env, p256dh: body.p256dh, auth: body.auth };
        } else {
          // apns/fcm: p256dh/auth are unifiedpush-exclusive — reject if either is present.
          if (body.p256dh !== undefined || body.auth !== undefined) {
            return json(res, 400, { error: 'invalid push registration body' });
          }
          inbox.push = { platform, token: body.token, env: body.env };
        }
        return json(res, 200, { ok: true });
      }
      if (method === 'DELETE' && suffix === '/push') {
        if (h['x-read-capability'] !== inbox.readCap) return reject(res);
        inbox.push = null;                                         // 200 even if it was already null
        return json(res, 200, { ok: true });
      }
      return reject(res);
    }

    return json(res, 404, { error: 'not found' });
  });

  return server;
}

if (require.main === module) {
  const port = process.env.MOCK_RELAY_PORT || 8080;
  const server = createMockRelay();
  // Without an 'error' handler an EADDRINUSE is an unhandled 'error' event
  // that kills this process silently, while the suite happily talks to whatever
  // already owns the port. Fail loudly and non-zero instead.
  server.on('error', (err) => {
    console.error(`[mock-relay] cannot listen on :${port} — ${err.code || err.message}`);
    process.exit(1);
  });
  server.listen(port, () => console.log(`[mock-relay] listening on :${port}`));
}

module.exports = { createMockRelay };
