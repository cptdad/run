#!/usr/bin/env node
/**
 * Deterministic test for the Rún mock relay's push contract.
 * Covers mint, register, append, suppress, deregister, validation, auth, and reset.
 */

const http = require('http');
const assert = require('assert');
const { createMockRelay } = require('./server');

let passCount = 0;
let failCount = 0;

function pass(msg) {
  passCount++;
  console.log(`✓ ${msg}`);
}

function fail(msg, err) {
  failCount++;
  console.error(`✗ ${msg}${err ? ': ' + err.message : ''}`);
  if (err) console.error(err.stack);
}

/**
 * Helper: make HTTP request and return {status, headers, body}
 */
function request(port, method, path, headers, bodyData) {
  return new Promise((resolve, reject) => {
    const opts = { hostname: 'localhost', port, path, method, headers: headers || {} };
    const req = http.request(opts, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const body = Buffer.concat(chunks).toString();
        resolve({ status: res.statusCode, headers: res.headers, body });
      });
    });
    req.on('error', reject);
    if (bodyData) {
      if (typeof bodyData === 'string') req.write(bodyData);
      else req.write(bodyData);
    }
    req.end();
  });
}

/**
 * Helper: parse JSON response
 */
function parseJson(body) {
  try {
    return JSON.parse(body);
  } catch (e) {
    return null;
  }
}

/**
 * Test suite
 */
async function runTests() {
  const srv = createMockRelay();
  let port;

  // Start server on ephemeral port
  await new Promise((resolve, reject) => {
    srv.on('error', reject);
    srv.listen(0, () => {
      port = srv.address().port;
      console.log(`\nMock relay listening on port ${port}\n`);
      resolve();
    });
  });

  try {
    // =========================================================================
    // Test 1: Mint an inbox (two-phase PoW)
    // =========================================================================
    let inboxId, readCap, writeCap;
    {
      // Phase 1: request challenge
      const res1 = await request(port, 'POST', '/inbox', {});
      assert.strictEqual(res1.status, 400, 'Phase 1 should return 400');
      const challenge = parseJson(res1.body);
      assert(challenge, 'Phase 1 should return JSON challenge');
      assert(challenge.token, 'Challenge should have token');
      const token = challenge.token;

      // Phase 2: submit token
      const res2 = await request(port, 'POST', '/inbox', { 'x-pow-token': token });
      assert.strictEqual(res2.status, 201, 'Phase 2 with valid token should return 201');
      const mint = parseJson(res2.body);
      assert(mint.inboxId, 'Mint should return inboxId');
      assert(mint.readCapability, 'Mint should return readCapability');
      assert(mint.writeCapability, 'Mint should return writeCapability');
      inboxId = mint.inboxId;
      readCap = mint.readCapability;
      writeCap = mint.writeCapability;
      pass('Mint inbox (two-phase PoW)');
    }

    // =========================================================================
    // Test 2: Append with no push registered → count should be 0 or absent
    // =========================================================================
    {
      const res = await request(port, 'POST', `/inbox/${inboxId}`,
        { 'x-write-capability': writeCap },
        Buffer.from([1, 2, 3]));
      assert.strictEqual(res.status, 202, 'Append should return 202');

      const pushRes = await request(port, 'GET', '/__control/pushes', {});
      const pushData = parseJson(pushRes.body);
      const entry = pushData.pushes.find(p => p.inboxId === inboxId);
      assert(!entry || entry.count === 0, 'Push count should be 0 or absent for no-registration');
      pass('Append with no push registered → count is 0');
    }

    // =========================================================================
    // Test 3: Register a push token → 200
    // =========================================================================
    {
      const body = JSON.stringify({ platform: 'apns', token: 'deadbeef', env: 'sandbox' });
      const res = await request(port, 'PUT', `/inbox/${inboxId}/push`,
        { 'x-read-capability': readCap },
        body);
      assert.strictEqual(res.status, 200, 'Register push should return 200');
      pass('Register push token → 200');
    }

    // =========================================================================
    // Test 4: Append (no X-No-Push) → count increments to 1
    // =========================================================================
    {
      const res = await request(port, 'POST', `/inbox/${inboxId}`,
        { 'x-write-capability': writeCap },
        Buffer.from([4, 5, 6]));
      assert.strictEqual(res.status, 202, 'Append should return 202');

      const pushRes = await request(port, 'GET', '/__control/pushes', {});
      const pushData = parseJson(pushRes.body);
      const entry = pushData.pushes.find(p => p.inboxId === inboxId);
      assert(entry && entry.count === 1, `Push count should be 1, got ${entry?.count}`);
      pass('Append (no X-No-Push) → count increments to 1');
    }

    // =========================================================================
    // Test 5: Append again → count is 2
    // =========================================================================
    {
      const res = await request(port, 'POST', `/inbox/${inboxId}`,
        { 'x-write-capability': writeCap },
        Buffer.from([7, 8, 9]));
      assert.strictEqual(res.status, 202, 'Append should return 202');

      const pushRes = await request(port, 'GET', '/__control/pushes', {});
      const pushData = parseJson(pushRes.body);
      const entry = pushData.pushes.find(p => p.inboxId === inboxId);
      assert(entry && entry.count === 2, `Push count should be 2, got ${entry?.count}`);
      pass('Append again → count increments to 2');
    }

    // =========================================================================
    // Test 6: Append with X-No-Push: 1 → count stays 2 (suppressed)
    // =========================================================================
    {
      const res = await request(port, 'POST', `/inbox/${inboxId}`,
        { 'x-write-capability': writeCap, 'x-no-push': '1' },
        Buffer.from([10, 11, 12]));
      assert.strictEqual(res.status, 202, 'Append with suppression should return 202');

      const pushRes = await request(port, 'GET', '/__control/pushes', {});
      const pushData = parseJson(pushRes.body);
      const entry = pushData.pushes.find(p => p.inboxId === inboxId);
      assert(entry && entry.count === 2, `Push count should stay 2, got ${entry?.count}`);
      pass('Append with X-No-Push: 1 → count stays 2 (suppressed)');
    }

    // =========================================================================
    // Test 7: DELETE push registration → 200
    // =========================================================================
    {
      const res = await request(port, 'DELETE', `/inbox/${inboxId}/push`,
        { 'x-read-capability': readCap });
      assert.strictEqual(res.status, 200, 'DELETE push should return 200');
      pass('DELETE push registration → 200');
    }

    // =========================================================================
    // Test 8: Append after delete → count stays 2 (no token)
    // =========================================================================
    {
      const res = await request(port, 'POST', `/inbox/${inboxId}`,
        { 'x-write-capability': writeCap },
        Buffer.from([13, 14, 15]));
      assert.strictEqual(res.status, 202, 'Append should return 202');

      const pushRes = await request(port, 'GET', '/__control/pushes', {});
      const pushData = parseJson(pushRes.body);
      const entry = pushData.pushes.find(p => p.inboxId === inboxId);
      assert(!entry || entry.count === 2, `Push count should stay 2, got ${entry?.count}`);
      pass('Append after DELETE push → count stays 2 (no token)');
    }

    // =========================================================================
    // Test 9: mint a second inbox + register fcm push token → 200 (accepted)
    // =========================================================================
    let inboxId2, readCap2, writeCap2;
    {
      const chal = await request(port, 'POST', '/inbox', {});
      const challenge = parseJson(chal.body);
      const mintRes = await request(port, 'POST', '/inbox', { 'x-pow-token': challenge.token });
      const mint = parseJson(mintRes.body);
      inboxId2 = mint.inboxId;
      readCap2 = mint.readCapability;
      writeCap2 = mint.writeCapability;

      const body = JSON.stringify({ platform: 'fcm', token: 'fcm-registration-token-abc', env: 'sandbox' });
      const res = await request(port, 'PUT', `/inbox/${inboxId2}/push`,
        { 'x-read-capability': readCap2 },
        body);
      assert.strictEqual(res.status, 200, 'fcm platform should be accepted');

      // Confirm it actually fires, not just accepted at the validation layer.
      const appendRes = await request(port, 'POST', `/inbox/${inboxId2}`,
        { 'x-write-capability': writeCap2 },
        Buffer.from([1]));
      assert.strictEqual(appendRes.status, 202, 'Append should return 202');
      const pushRes = await request(port, 'GET', '/__control/pushes', {});
      const pushData = parseJson(pushRes.body);
      const entry = pushData.pushes.find(p => p.inboxId === inboxId2);
      assert(entry && entry.count === 1, `fcm push should have fired once, got ${entry?.count}`);
      pass('Register fcm push token → 200 (accepted), and it fires on append');
    }

    // =========================================================================
    // Test 10: register unifiedpush with https token + p256dh/auth pair → 200
    // =========================================================================
    {
      const body = JSON.stringify({
        platform: 'unifiedpush',
        token: 'https://up.example.org/push/abc123',
        p256dh: 'BJXb4gsdkjfDeadbeef00112233445566778899AAbb',
        auth: 'ZGVhZGJlZWZhdXRoc2VjcmV0',
        env: 'production',
      });
      const res = await request(port, 'PUT', `/inbox/${inboxId2}/push`,
        { 'x-read-capability': readCap2 },
        body);
      assert.strictEqual(res.status, 200, 'unifiedpush with https token + matched p256dh/auth pair should be accepted');

      // Confirm the new registration fires too (overwrote the fcm one from Test 9).
      const appendRes = await request(port, 'POST', `/inbox/${inboxId2}`,
        { 'x-write-capability': writeCap2 },
        Buffer.from([2]));
      assert.strictEqual(appendRes.status, 202, 'Append should return 202');
      const pushRes = await request(port, 'GET', '/__control/pushes', {});
      const pushData = parseJson(pushRes.body);
      const entry = pushData.pushes.find(p => p.inboxId === inboxId2);
      assert(entry && entry.count === 2, `unifiedpush should have fired, got ${entry?.count}`);
      pass('Register unifiedpush (https token + p256dh/auth) → 200, and it fires on append');
    }

    // =========================================================================
    // Test 11: unifiedpush with a non-https (http://) token URL → 400
    // =========================================================================
    {
      const body = JSON.stringify({
        platform: 'unifiedpush',
        token: 'http://up.example.org/push/insecure',
        p256dh: 'BJXb4gsdkjfDeadbeef00112233445566778899AAbb',
        auth: 'ZGVhZGJlZWZhdXRoc2VjcmV0',
        env: 'production',
      });
      const res = await request(port, 'PUT', `/inbox/${inboxId2}/push`,
        { 'x-read-capability': readCap2 },
        body);
      assert.strictEqual(res.status, 400, 'unifiedpush with a non-https token URL should be rejected');
      pass('unifiedpush with http:// (non-https) token URL → 400');
    }

    // =========================================================================
    // Test 12: unifiedpush missing auth (p256dh present alone) → 400
    // =========================================================================
    {
      const body = JSON.stringify({
        platform: 'unifiedpush',
        token: 'https://up.example.org/push/abc123',
        p256dh: 'BJXb4gsdkjfDeadbeef00112233445566778899AAbb',
        env: 'production',
      });
      const res = await request(port, 'PUT', `/inbox/${inboxId2}/push`,
        { 'x-read-capability': readCap2 },
        body);
      assert.strictEqual(res.status, 400, 'unifiedpush missing auth (p256dh alone) should be rejected');
      pass('unifiedpush with p256dh but no auth → 400 (matched pair required)');
    }

    // =========================================================================
    // Test 13: apns carrying p256dh/auth (platform-exclusive to unifiedpush) → 400
    // =========================================================================
    {
      const body = JSON.stringify({
        platform: 'apns',
        token: 'apns-device-token-abc123',
        env: 'sandbox',
        p256dh: 'BJXb4gsdkjfDeadbeef00112233445566778899AAbb',
        auth: 'ZGVhZGJlZWZhdXRoc2VjcmV0',
      });
      const res = await request(port, 'PUT', `/inbox/${inboxId2}/push`,
        { 'x-read-capability': readCap2 },
        body);
      assert.strictEqual(res.status, 400, 'apns carrying p256dh/auth should be rejected (unifiedpush-exclusive fields)');
      pass('apns with p256dh/auth present → 400 (platform-exclusive)');
    }

    // =========================================================================
    // Test 14: PUT with wrong X-Read-Capability → 404, token not registered
    // =========================================================================
    {
      const wrongCap = 'wrong_capability_string';
      const body = JSON.stringify({ platform: 'apns', token: 'abc123', env: 'sandbox' });
      const res = await request(port, 'PUT', `/inbox/${inboxId}/push`,
        { 'x-read-capability': wrongCap },
        body);
      assert.strictEqual(res.status, 404, 'Wrong capability should return 404');

      // Verify token was NOT registered: append should not increment count
      const appendRes = await request(port, 'POST', `/inbox/${inboxId}`,
        { 'x-write-capability': writeCap },
        Buffer.from([16, 17, 18]));
      assert.strictEqual(appendRes.status, 202, 'Append should return 202');

      const pushRes = await request(port, 'GET', '/__control/pushes', {});
      const pushData = parseJson(pushRes.body);
      const entry = pushData.pushes.find(p => p.inboxId === inboxId);
      assert(!entry || entry.count === 2, `Push count should stay 2 (token not registered), got ${entry?.count}`);
      pass('PUT with wrong X-Read-Capability → 404, token NOT registered');
    }

    // =========================================================================
    // Test 15: POST /__control/reset → pushes list empty
    // =========================================================================
    {
      const resetRes = await request(port, 'POST', '/__control/reset', {});
      assert.strictEqual(resetRes.status, 200, 'Reset should return 200');

      const pushRes = await request(port, 'GET', '/__control/pushes', {});
      const pushData = parseJson(pushRes.body);
      assert(pushData.pushes.length === 0, 'Pushes list should be empty after reset');
      pass('POST /__control/reset → pushes list empty');
    }

    console.log(`\n${'='.repeat(60)}`);
    console.log(`Test Results: ${passCount} passed, ${failCount} failed`);
    console.log(`${'='.repeat(60)}\n`);

    if (failCount === 0) {
      console.log('✓ All tests passed!');
      process.exit(0);
    } else {
      console.log('✗ Some tests failed.');
      process.exit(1);
    }
  } catch (err) {
    fail('Unexpected error', err);
    console.log(`\n${'='.repeat(60)}`);
    console.log(`Test Results: ${passCount} passed, ${failCount + 1} failed`);
    console.log(`${'='.repeat(60)}\n`);
    process.exit(1);
  } finally {
    srv.close();
  }
}

runTests().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
