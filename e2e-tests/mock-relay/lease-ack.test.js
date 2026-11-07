#!/usr/bin/env node
// Contract test for the mock relay's retrieve-lease + POST /ack (real relay 0ab7f56).
// Run: npm run test:mock-lease
process.env.MOCK_RELAY_LEASE_MS = '700';
const http = require('http');
const { createMockRelay } = require('./server');
const PORT = 8098;

function req(method, path, { headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const r = http.request({ host: '127.0.0.1', port: PORT, path, method, headers }, (res) => {
      const cs = []; res.on('data', (c) => cs.push(c));
      res.on('end', () => { const t = Buffer.concat(cs).toString(); let j; try { j = JSON.parse(t); } catch { j = null; } resolve({ code: res.statusCode, json: j }); });
    });
    r.on('error', reject); if (body !== undefined) r.write(body); r.end();
  });
}
let failures = 0;
const ok = (c, m) => { if (c) console.log('  ok  ', m); else { failures++; console.error('  FAIL', m); } };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const B64 = (s) => Buffer.from(s).toString('base64');

async function mint() {
  const ch = (await req('POST', '/inbox')).json;
  const m = (await req('POST', '/inbox', { headers: { 'x-pow-token': ch.token, 'x-pow-counter': '0' } })).json;
  return m;
}
const put = (box, s) => req('POST', `/inbox/${box.inboxId}`, { headers: { 'x-write-capability': box.writeCapability }, body: s });
const get = (box, q = '') => req('GET', `/inbox/${box.inboxId}${q}`, { headers: { 'x-read-capability': box.readCapability } });
const peek = async (box) => (await req('GET', `/inbox/${box.inboxId}/peek`, { headers: { 'x-read-capability': box.readCapability } })).json.pending;
const ack = (items, raw) => req('POST', '/ack', { body: raw !== undefined ? raw : JSON.stringify({ v: 1, items }) });

(async () => {
  const server = createMockRelay();
  await new Promise((r) => server.listen(PORT, r));
  try {
    const box = await mint();
    for (const s of ['a', 'b', 'c']) await put(box, s);
    ok(await peek(box) === 3, 'peek counts 3 visible');

    // lease hides from GET + peek
    let r = await get(box, '?lease=1');
    const t1 = r.json.token, ids = r.json.ids;
    ok(r.code === 200 && r.json.blobs.length === 3 && ids.length === 3, 'lease returns 3 blobs + 3 ids');
    ok(r.json.blobs[0] === B64('a') && r.json.blobs[2] === B64('c'), 'blobs in order, std base64');
    ok(ids.every((i) => /^[A-Za-z0-9_-]{22}$/.test(i)) && /^[A-Za-z0-9_-]{22}$/.test(t1), 'ids + token are 22-char base64url');
    ok(await peek(box) === 0, 'peek sees 0 while leased');
    ok((await get(box, '?lease=1')).json.token === '' && (await get(box, '?lease=1')).json.blobs.length === 0, 'second lease: empty, token ""');
    ok((await get(box)).json.blobs.length === 0, 'plain GET sees nothing while leased');

    // plain GET during a lease leaves leased blobs; drains new visible ones
    await put(box, 'd');
    ok(await peek(box) === 1, 'new blob visible during lease');
    r = await get(box);
    ok(r.json.blobs.length === 1 && r.json.blobs[0] === B64('d'), 'plain GET drains only the unleased blob');
    ok(r.json.ids === undefined, 'plain GET has no ids');

    // ack deletes + releases
    r = await ack([{ id: box.inboxId, rc: box.readCapability, token: t1, delete: [ids[0], 'garbageGARBAGEgarbage12', 'x'] }]);
    ok(r.code === 200 && r.json.v === 1 && r.json.results[0].deleted === 1 && r.json.results[0].released === 2, 'ack: deleted 1, released 2');
    ok(await peek(box) === 2, 'released blobs visible at once');
    r = await ack([{ id: box.inboxId, rc: box.readCapability, token: t1, delete: [ids[0]] }]);
    ok(r.json.results[0].deleted === 0 && r.json.results[0].released === 0, 'ack idempotent');
    r = await get(box, '?lease=1');
    ok(r.json.ids.join() === ids.slice(1).join(), 'released blobs keep their ids');

    // expiry re-exposes with SAME ids
    const t2 = r.json.token;
    ok(await peek(box) === 0, 'leased again');
    await sleep(850);
    ok(await peek(box) === 2, 'lease expired: visible again');
    r = await get(box, '?lease=1');
    ok(r.json.ids.join() === ids.slice(1).join() && r.json.token !== t2, 'same ids after expiry, fresh token');
    // ack deletes whatever lease
    r = await ack([{ id: box.inboxId, rc: box.readCapability, token: 'stale-token-stale-token', delete: r.json.ids }]);
    ok(r.json.results[0].deleted === 2, 'ack deletes ids regardless of token');
    ok((await get(box)).json.blobs.length === 0, 'inbox empty');

    // per-item 404s, order preserved
    const other = await mint();
    r = await ack([
      { id: box.inboxId, rc: 'x'.repeat(43), token: '', delete: [] },
      { id: 'nope', rc: box.readCapability, token: '', delete: [] },
      { id: 'A'.repeat(32), rc: box.readCapability, token: '', delete: [] },
      { id: other.inboxId, rc: other.readCapability, token: '', delete: [] },
    ]);
    ok(r.code === 200 && r.json.results.map((x) => x.status || 'ok').join() === '404,404,404,ok', 'wrong cap / malformed / unknown -> 404 per item, order kept');
    ok(r.json.results[0].id === box.inboxId, 'result echoes id');

    // request-level errors
    ok((await ack(null, 'not json')).code === 400, 'unreadable body -> 400');
    ok((await ack(null, JSON.stringify({ v: 2, items: [{}] }))).code === 400, 'wrong v -> 400');
    ok((await ack([])).code === 400, 'empty items -> 400');
    ok((await ack(Array(65).fill({ id: box.inboxId, rc: box.readCapability, token: '', delete: [] }))).code === 413, '65 items -> 413');
    ok((await ack([{ id: box.inboxId, rc: box.readCapability, token: '', delete: Array(257).fill('A'.repeat(22)) }])).code === 413, '257 ids -> 413');
  } finally {
    server.close();
  }
  console.log(failures ? `\n${failures} FAILED` : '\nall passed');
  process.exit(failures ? 1 : 0);
})();
