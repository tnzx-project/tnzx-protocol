#!/usr/bin/env node
'use strict';
/**
 * @tnzx/sdk — Key management tests
 */

const assert = require('assert');
const { generateKeyPair, ecdh, deriveKey } = require('../lib/crypto/keys');

let passed = 0, failed = 0;
function test(name, fn) {
  try { fn(); passed++; console.log(`  ✓ ${name}`); }
  catch (e) { failed++; console.log(`  ✗ ${name}: ${e.message}`); }
}

console.log('── SDK Keys ──');

test('generateKeyPair returns 32-byte keys', () => {
  const kp = generateKeyPair();
  assert.strictEqual(kp.publicKey.length, 32);
  assert.strictEqual(kp.privateKey.length, 32);
});

test('ECDH shared secret is symmetric', () => {
  const alice = generateKeyPair();
  const bob = generateKeyPair();
  const s1 = ecdh(alice.privateKey, bob.publicKey);
  const s2 = ecdh(bob.privateKey, alice.publicKey);
  assert.deepStrictEqual(s1, s2);
});

test('ECDH different keys produce different secrets', () => {
  const alice = generateKeyPair();
  const bob = generateKeyPair();
  const eve = generateKeyPair();
  const s1 = ecdh(alice.privateKey, bob.publicKey);
  const s2 = ecdh(alice.privateKey, eve.publicKey);
  assert.notDeepStrictEqual(s1, s2);
});

test('deriveKey returns 32-byte key and salt', () => {
  const shared = ecdh(generateKeyPair().privateKey, generateKeyPair().publicKey);
  const { key, salt } = deriveKey(shared);
  assert.strictEqual(key.length, 32);
  assert.strictEqual(salt.length, 32);
});

test('deriveKey is deterministic with same salt', () => {
  const shared = Buffer.alloc(32, 0x42);
  const salt = Buffer.alloc(32, 0x01);
  const { key: k1 } = deriveKey(shared, salt);
  const { key: k2 } = deriveKey(shared, salt);
  assert.deepStrictEqual(k1, k2);
});

test('deriveKey produces different keys with different salts', () => {
  const shared = Buffer.alloc(32, 0x42);
  const { key: k1 } = deriveKey(shared, Buffer.alloc(32, 0x01));
  const { key: k2 } = deriveKey(shared, Buffer.alloc(32, 0x02));
  assert.notDeepStrictEqual(k1, k2);
});

console.log(`\n── Results: ${passed} passed, ${failed} failed ──\n`);
if (failed > 0) process.exit(1);
