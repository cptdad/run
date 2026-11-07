// Retrieve-lease + ack semantics for the mock relay (server.js). Mirrors the relay's "Retrieve-ack" contract (docs/RELAY_SPEC.md):
//   GET /inbox/{id}?lease=1  -> {blobs, ids, token}; nothing deleted, blobs LEASED
//   POST /ack                -> delete the acked ids, RELEASE the rest of that token
// A queue entry is { data: Buffer, id, leaseUntil (ms epoch, 0 = visible), token }.
const crypto = require('crypto');

const b64url = (buf) => buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const newBlobId = () => b64url(crypto.randomBytes(16));      // 22 chars
const newLeaseToken = () => b64url(crypto.randomBytes(16));  // 22 chars
const leaseMs = () => {
  const n = Number(process.env.MOCK_RELAY_LEASE_MS);
  return Number.isFinite(n) && n >= 0 && process.env.MOCK_RELAY_LEASE_MS !== undefined && process.env.MOCK_RELAY_LEASE_MS !== '' ? n : 60000;
};
const ID_RE = /^[A-Za-z0-9_-]{22}$/;
const INBOX_ID_RE = /^[A-Za-z0-9_-]{32}$/;
const MAX_ITEMS = 64, MAX_IDS = 256;

const makeBlob = (data) => ({ data, id: newBlobId(), leaseUntil: 0, token: null });
// Accepts a persisted entry: legacy base64 string, or {d,id,leaseUntil,token}.
const loadBlob = (e) => (typeof e === 'string'
  ? makeBlob(Buffer.from(e, 'base64'))
  : { data: Buffer.from(e.d, 'base64'), id: e.id || newBlobId(), leaseUntil: e.leaseUntil || 0, token: e.token || null });
const dumpBlob = (b) => ({ d: b.data.toString('base64'), id: b.id, leaseUntil: b.leaseUntil, token: b.token });

// Expired leases become visible again (same id).
function expire(box, now) {
  for (const b of box.blobs) if (b.leaseUntil && b.leaseUntil <= now) { b.leaseUntil = 0; b.token = null; }
}
const visible = (box, now = Date.now()) => { expire(box, now); return box.blobs.filter((b) => !b.leaseUntil); };
const visibleCount = (box, now = Date.now()) => visible(box, now).length;

// Plain drain: delete + return the visible blobs (leased ones stay).
function drain(box, now = Date.now()) {
  const vis = visible(box, now);
  box.blobs = box.blobs.filter((b) => b.leaseUntil);
  return { blobs: vis.map((b) => b.data.toString('base64')) };
}
// Leasing retrieve: nothing deleted.
function lease(box, now = Date.now()) {
  const vis = visible(box, now);
  if (vis.length === 0) return { blobs: [], ids: [], token: '' };
  const token = newLeaseToken(), until = now + leaseMs();
  for (const b of vis) { b.leaseUntil = until; b.token = token; }
  return { blobs: vis.map((b) => b.data.toString('base64')), ids: vis.map((b) => b.id), token };
}

// POST /ack body handling. `lookup(id)` -> box|undefined. `timingSafeEq(a,b)`.
// Returns { code, body, mutated }.
function ack(rawBody, lookup, timingSafeEq, now = Date.now()) {
  let req;
  try { req = JSON.parse(rawBody.toString('utf8')); } catch { return { code: 400, body: { error: 'bad request' } }; }
  if (!req || req.v !== 1 || !Array.isArray(req.items) || req.items.length === 0) return { code: 400, body: { error: 'bad request' } };
  if (req.items.length > MAX_ITEMS) return { code: 413, body: { error: 'too many items' } };
  for (const it of req.items) if (it && Array.isArray(it.delete) && it.delete.length > MAX_IDS) return { code: 413, body: { error: 'too many ids' } };
  let mutated = false;
  const results = req.items.map((it) => {
    const id = it && typeof it.id === 'string' ? it.id : '';
    const gone = { id, status: 404 };
    if (!it || !INBOX_ID_RE.test(id) || typeof it.rc !== 'string') return gone;
    const box = lookup(id);
    if (!box || !timingSafeEq(it.rc, box.readCap)) return gone;
    const del = new Set((Array.isArray(it.delete) ? it.delete : []).filter((x) => typeof x === 'string' && ID_RE.test(x)));
    const token = typeof it.token === 'string' ? it.token : '';
    expire(box, now);
    let deleted = 0, released = 0;
    box.blobs = box.blobs.filter((b) => {
      if (del.has(b.id)) { deleted++; return false; }
      return true;
    });
    if (token) for (const b of box.blobs) if (b.token === token) { b.leaseUntil = 0; b.token = null; released++; }
    if (deleted || released) mutated = true;
    return { id, deleted, released };
  });
  return { code: 200, body: { v: 1, results }, mutated };
}

module.exports = { makeBlob, loadBlob, dumpBlob, visible, visibleCount, drain, lease, ack };
