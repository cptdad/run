#!/usr/bin/env node
// Protocol self-test for the mock relay: drives the full handshake the app
// performs (mint → append → peek → drain → drop/restore) and asserts the shapes
// the app validates. Run: `node e2e-tests/mock-relay/selftest.js`.
const http = require('http');
const { createMockRelay } = require('./server');

const PORT = 8099; // distinct from the :8080 a running mock would use

function req(method, path, { headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const r = http.request({ host: '127.0.0.1', port: PORT, path, method, headers }, (res) => {
      const cs = []; res.on('data', (c) => cs.push(c)); res.on('end', () => resolve({ code: res.statusCode, body: Buffer.concat(cs) }));
    });
    r.on('error', reject); if (body) r.write(body); r.end();
  });
}
const j = (r) => JSON.parse(r.body.toString());
let failures = 0;
const ok = (cond, msg) => { if (cond) { console.log('  ok  ', msg); } else { failures++; console.error('  FAIL', msg); } };

(async () => {
  const server = createMockRelay();
  await new Promise((r) => server.listen(PORT, r));
  try {
    let res = await req('GET', '/');
    ok(res.code === 200, 'GET / health → 200');

    res = await req('POST', '/inbox');
    const ch = j(res);
    ok(res.code === 400, 'mint phase-1 → 400 challenge');
    ok(!!ch.token && !!ch.nonce && ch.difficulty === 0, 'challenge has token + nonce + difficulty=0');

    res = await req('POST', '/inbox', { headers: { 'x-pow-token': ch.token, 'x-pow-counter': '0' } });
    const mint = j(res);
    ok(res.code === 201, 'mint phase-2 (token+counter) → 201');
    ok(/^[A-Za-z0-9_\-]{32}$/.test(mint.inboxId), 'inboxId matches ^[A-Za-z0-9_-]{32}$');
    ok(mint.readCapability.length <= 256 && mint.writeCapability.length <= 256 && !!mint.expiresAt, 'caps header-safe + expiresAt present');
    const id = mint.inboxId;

    res = await req('POST', `/inbox/${id}`, { headers: { 'x-write-capability': 'wrong' }, body: Buffer.from('x') });
    ok(res.code === 404, 'append with wrong write-cap → 404');

    res = await req('POST', `/inbox/${id}`, { headers: { 'x-write-capability': mint.writeCapability }, body: Buffer.from('hello-blob-bytes') });
    ok(res.code === 202, 'append with right write-cap → 202');

    res = await req('GET', `/inbox/${id}/peek`, { headers: { 'x-read-capability': mint.readCapability } });
    ok(res.code === 200 && j(res).pending === 1, 'peek → pending=1 (non-destructive)');

    res = await req('GET', `/inbox/${id}`, { headers: { 'x-read-capability': mint.readCapability } });
    const drained = j(res);
    ok(res.code === 200 && drained.blobs.length === 1, 'drain → {blobs:[1]}');
    ok(Buffer.from(drained.blobs[0], 'base64').toString() === 'hello-blob-bytes', 'blob round-trips via standard base64');

    res = await req('GET', `/inbox/${id}/peek`, { headers: { 'x-read-capability': mint.readCapability } });
    ok(j(res).pending === 0, 'drain destroyed the blob (pending=0)');

    res = await req('GET', `/inbox/${id}`, { headers: { 'x-read-capability': 'wrong' } });
    ok(res.code === 404, 'drain with wrong read-cap → 404');

    await req('POST', '/__control/drop', { headers: { 'content-type': 'application/json' }, body: JSON.stringify({ inboxId: id }) });
    res = await req('GET', `/inbox/${id}/peek`, { headers: { 'x-read-capability': mint.readCapability } });
    ok(res.code === 404, 'control drop → inbox 404s (simulated relay loss)');

    await req('POST', '/__control/restore', { headers: { 'content-type': 'application/json' }, body: JSON.stringify({ inboxId: id }) });
    res = await req('GET', `/inbox/${id}/peek`, { headers: { 'x-read-capability': mint.readCapability } });
    ok(res.code === 200, 'control restore → inbox 200s again');

    // --- Phase-3 push: register/deregister, fires-only-with-token, X-No-Push,
    // EXISTING-BEHAVIOR-UNCHANGED (append with no token still 202, no push) ---

    res = await req('POST', `/inbox/${id}`, { headers: { 'x-write-capability': mint.writeCapability }, body: Buffer.from('no-push-token-yet') });
    ok(res.code === 202, 'append before any push registration still 202 (back-compat)');
    res = await req('GET', '/__control/pushes');
    ok((j(res).pushes || []).every((p) => p.inboxId !== id || p.count === 0), 'no push recorded when no token is registered');

    res = await req('PUT', `/inbox/${id}/push`, {
      headers: { 'x-read-capability': 'wrong', 'content-type': 'application/json' },
      body: JSON.stringify({ platform: 'apns', token: 'deadbeef', env: 'sandbox' }),
    });
    ok(res.code === 404, 'PUT push with wrong read-cap → 404');

    res = await req('PUT', `/inbox/${id}/push`, {
      headers: { 'x-read-capability': mint.readCapability, 'content-type': 'application/json' },
      body: JSON.stringify({ platform: 'apns', token: 'deadbeef', env: 'sandbox' }),
    });
    ok(res.code === 200, 'PUT push with valid read-cap → 200 (register)');

    res = await req('POST', `/inbox/${id}`, { headers: { 'x-write-capability': mint.writeCapability }, body: Buffer.from('push-me') });
    ok(res.code === 202, 'append with a registered token still 202');
    res = await req('GET', '/__control/pushes');
    let entry = (j(res).pushes || []).find((p) => p.inboxId === id);
    ok(!!entry && entry.count === 1, 'push fires (count=1) once a token is registered');

    res = await req('POST', `/inbox/${id}`, {
      headers: { 'x-write-capability': mint.writeCapability, 'x-no-push': '1' },
      body: Buffer.from('do-not-push-me'),
    });
    ok(res.code === 202, 'append with X-No-Push: 1 still 202');
    res = await req('GET', '/__control/pushes');
    entry = (j(res).pushes || []).find((p) => p.inboxId === id);
    ok(!!entry && entry.count === 1, 'X-No-Push: 1 suppresses the push (count unchanged)');

    res = await req('DELETE', `/inbox/${id}/push`, { headers: { 'x-read-capability': mint.readCapability } });
    ok(res.code === 200, 'DELETE push → 200 (deregister)');
    res = await req('DELETE', `/inbox/${id}/push`, { headers: { 'x-read-capability': mint.readCapability } });
    ok(res.code === 200, 'DELETE push again → 200 even when none was registered (idempotent)');

    res = await req('POST', `/inbox/${id}`, { headers: { 'x-write-capability': mint.writeCapability }, body: Buffer.from('after-deregister') });
    ok(res.code === 202, 'append after deregistration still 202');
    res = await req('GET', '/__control/pushes');
    entry = (j(res).pushes || []).find((p) => p.inboxId === id);
    ok(!!entry && entry.count === 1, 'no further push fires after deregistration (count still 1)');

    // --- Owner-only ops: capability rotation + inbox delete. All three are
    // authenticated by the inbox's READ cap; a rejected request must be a
    // NO-OP (cap unchanged / inbox alive), not just a 404. ---

    const mintInbox = async () => {
      const c = j(await req('POST', '/inbox'));
      return j(await req('POST', '/inbox', { headers: { 'x-pow-token': c.token, 'x-pow-counter': '0' } }));
    };
    const CAP_A = 'A'.repeat(43), CAP_B = 'B'.repeat(43);   // base64url-no-pad(32) shape

    let box = await mintInbox();
    res = await req('PUT', `/inbox/${box.inboxId}/read-capability`, { headers: { 'x-read-capability': 'wrong', 'x-new-read-capability': CAP_A } });
    ok(res.code === 404, 'rotate read-cap with wrong current cap → 404');
    res = await req('PUT', `/inbox/${box.inboxId}/read-capability`, { headers: { 'x-new-read-capability': CAP_A } });
    ok(res.code === 404, 'rotate read-cap with NO current cap → 404');
    res = await req('PUT', `/inbox/${box.inboxId}/read-capability`, { headers: { 'x-read-capability': box.readCapability } });
    ok(res.code === 404, 'rotate read-cap with no X-New-Read-Capability → 404');
    res = await req('GET', `/inbox/${box.inboxId}/peek`, { headers: { 'x-read-capability': box.readCapability } });
    ok(res.code === 200, 'rejected read-cap rotations are no-ops (stored cap UNCHANGED)');
    res = await req('GET', `/inbox/${box.inboxId}/peek`, { headers: { 'x-read-capability': CAP_A } });
    ok(res.code === 404, 'the refused new read-cap was never installed');

    res = await req('PUT', `/inbox/${box.inboxId}/read-capability`, { headers: { 'x-read-capability': box.readCapability, 'x-new-read-capability': CAP_A } });
    ok(res.code === 200, 'rotate read-cap with the correct current cap → 200');
    res = await req('GET', `/inbox/${box.inboxId}/peek`, { headers: { 'x-read-capability': box.readCapability } });
    ok(res.code === 404, 'OLD read-cap rejected after rotation');
    res = await req('GET', `/inbox/${box.inboxId}/peek`, { headers: { 'x-read-capability': CAP_A } });
    ok(res.code === 200, 'NEW read-cap works after rotation');

    res = await req('PUT', `/inbox/${box.inboxId}/write-capability`, { headers: { 'x-read-capability': box.writeCapability, 'x-new-write-capability': CAP_B } });
    ok(res.code === 404, 'rotate write-cap authenticated with the WRITE cap → 404 (writers cannot rotate)');
    res = await req('POST', `/inbox/${box.inboxId}`, { headers: { 'x-write-capability': box.writeCapability }, body: Buffer.from('old-write-cap-still-valid') });
    ok(res.code === 202, 'rejected write-cap rotation is a no-op (stored write-cap UNCHANGED)');
    res = await req('PUT', `/inbox/${box.inboxId}/write-capability`, { headers: { 'x-read-capability': CAP_A, 'x-new-write-capability': CAP_B } });
    ok(res.code === 200, 'rotate write-cap with the current READ cap → 200');
    res = await req('POST', `/inbox/${box.inboxId}`, { headers: { 'x-write-capability': box.writeCapability }, body: Buffer.from('nope') });
    ok(res.code === 404, 'OLD write-cap rejected after rotation');
    res = await req('POST', `/inbox/${box.inboxId}`, { headers: { 'x-write-capability': CAP_B }, body: Buffer.from('yep') });
    ok(res.code === 202, 'NEW write-cap works after rotation');

    box = await mintInbox();
    res = await req('DELETE', `/inbox/${box.inboxId}`, { headers: { 'x-read-capability': 'wrong' } });
    ok(res.code === 404, 'DELETE inbox with wrong read-cap → 404');
    res = await req('DELETE', `/inbox/${box.inboxId}`);
    ok(res.code === 404, 'DELETE inbox with NO read-cap → 404');
    res = await req('DELETE', `/inbox/${box.inboxId}`, { headers: { 'x-write-capability': box.writeCapability } });
    ok(res.code === 404, 'DELETE inbox with the WRITE cap → 404 (read cap is the owner proof)');
    res = await req('GET', `/inbox/${box.inboxId}/peek`, { headers: { 'x-read-capability': box.readCapability } });
    ok(res.code === 200, 'rejected DELETEs left the inbox ALIVE');
    res = await req('DELETE', `/inbox/${box.inboxId}`, { headers: { 'x-read-capability': box.readCapability } });
    ok(res.code === 200, 'DELETE inbox with the correct read-cap → 200');
    res = await req('GET', `/inbox/${box.inboxId}/peek`, { headers: { 'x-read-capability': box.readCapability } });
    ok(res.code === 404, 'deleted inbox 404s on a subsequent GET');

    res = await req('POST', '/__control/reset');
    res = await req('GET', '/__control/pushes');
    ok(Array.isArray(j(res).pushes) && j(res).pushes.length === 0, 'control reset clears push counts');

    res = await req('POST', '/__control/rateLimit', { headers: { 'content-type': 'application/json' }, body: JSON.stringify({ on: true }) });
    res = await req('POST', '/inbox');
    ok(res.code === 429, 'control rateLimit → everything 429s');
  } finally {
    server.close();
  }
  console.log(failures === 0 ? '\nALL MOCK-RELAY SELF-TESTS PASSED' : `\n${failures} SELF-TEST(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
})();
