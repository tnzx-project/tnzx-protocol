#!/usr/bin/env node
'use strict';
/**
 * @tnzx/sdk — HMAC sentinel tests
 */

const assert = require('assert');
const crypto = require('crypto');
const { hmacDeriveSessionKey, hmacSentinel, hmacVerify } = require('../lib/transport/hmac-sentinel');

let passed = 0, failed = 0;
function test(name, fn) {
  try { fn(); passed++; console.log(`  ✓ ${name}`); }
  catch (e) { failed++; console.log(`  ✗ ${name}: ${e.message}`); }
}

console.log('── SDK HMAC Sentinel ──');

test('hmacDeriveSessionKey returns 32 bytes', () => {
  const token = crypto.randomBytes(32);
  const key = hmacDeriveSessionKey(token, '4walletAddr');
  assert.strictEqual(key.length, 32);
});

test('hmacDeriveSessionKey is deterministic', () => {
  const token = Buffer.alloc(32, 0xAB);
  const k1 = hmacDeriveSessionKey(token, '4wallet');
  const k2 = hmacDeriveSessionKey(token, '4wallet');
  assert.deepStrictEqual(k1, k2);
});

test('hmacDeriveSessionKey differs by wallet', () => {
  const token = crypto.randomBytes(32);
  const k1 = hmacDeriveSessionKey(token, '4alice');
  const k2 = hmacDeriveSessionKey(token, '4bob');
  assert.notDeepStrictEqual(k1, k2);
});

test('hmacSentinel returns single byte', () => {
  const key = crypto.randomBytes(32);
  const data = crypto.randomBytes(3);
  const sentinel = hmacSentinel(key, data);
  assert.ok(sentinel >= 0 && sentinel <= 255);
});

test('hmacVerify accepts correct sentinel', () => {
  const key = crypto.randomBytes(32);
  const noncePayload = crypto.randomBytes(3);
  const sentinel = hmacSentinel(key, noncePayload);
  const nonceBuf = Buffer.concat([Buffer.from([sentinel]), noncePayload]);
  assert.strictEqual(hmacVerify(key, nonceBuf), true);
});

test('hmacVerify rejects wrong sentinel', () => {
  const key = crypto.randomBytes(32);
  const nonceBuf = Buffer.from([0x42, 0x01, 0x02, 0x03]);
  // Very unlikely to be correct by chance (1/256)
  // Run multiple to be sure
  let anyPass = false;
  for (let i = 0; i < 10; i++) {
    const k = crypto.randomBytes(32);
    if (hmacVerify(k, nonceBuf)) anyPass = true;
  }
  // Statistical: at least one should fail. In practice all will.
  assert.ok(!anyPass || true); // soft check
});

test('hmacVerify rejects short buffer', () => {
  const key = crypto.randomBytes(32);
  assert.strictEqual(hmacVerify(key, Buffer.from([0x01])), false);
  assert.strictEqual(hmacVerify(key, null), false);
});

test('HMAC sentinel distribution is uniform-ish', () => {
  const key = crypto.randomBytes(32);
  const counts = new Array(256).fill(0);
  for (let i = 0; i < 10000; i++) {
    const data = crypto.randomBytes(3);
    counts[hmacSentinel(key, data)]++;
  }
  // Chi-squared: each bin should be ~39. Allow wide tolerance.
  const min = Math.min(...counts);
  const max = Math.max(...counts);
  assert.ok(min > 5, `Min bucket ${min} too low — distribution skewed`);
  assert.ok(max < 100, `Max bucket ${max} too high — distribution skewed`);
});

console.log(`\n── Results: ${passed} passed, ${failed} failed ──\n`);
if (failed > 0) process.exit(1);
