#!/usr/bin/env node
'use strict';
/**
 * @tnzx/sdk — Crypto test suite
 * Tests XChaCha20-Poly1305 and E2E one-shot encryption.
 */

const assert = require('assert');
const crypto = require('crypto');
const xchacha = require('../lib/crypto/xchacha20');
const { encryptOneShot, decryptOneShot, generateKeyPair } = require('../lib/crypto/e2e');
const { REPLAY_ID_LEN, EPH_PUB_LEN, SALT_LEN, NONCE_LEN, TAG_LEN, ENCRYPT_OVERHEAD } = require('../lib/constants');

let passed = 0, failed = 0;
function test(name, fn) {
  try { fn(); passed++; console.log(`  ✓ ${name}`); }
  catch (e) { failed++; console.log(`  ✗ ${name}: ${e.message}`); }
}

console.log('── SDK Crypto ──');

// HChaCha20 RFC test vector (draft-irtf-cfrg-xchacha, Section 2.2.1)
test('HChaCha20 RFC test vector', () => {
  const key = Buffer.from('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', 'hex');
  const nonce16 = Buffer.from('000000090000004a0000000031415927', 'hex');
  const expected = Buffer.from('82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc', 'hex');
  const result = xchacha.hchacha20(key, nonce16);
  assert.deepStrictEqual(result, expected);
});

test('XChaCha20 encrypt/decrypt roundtrip', () => {
  const key = crypto.randomBytes(32);
  const nonce = crypto.randomBytes(24);
  const pt = Buffer.from('test plaintext');
  const { ciphertext, tag } = xchacha.encrypt(key, nonce, pt);
  const decrypted = xchacha.decrypt(key, nonce, ciphertext, tag);
  assert.deepStrictEqual(decrypted, pt);
});

test('XChaCha20 tampered ciphertext rejected', () => {
  const key = crypto.randomBytes(32);
  const nonce = crypto.randomBytes(24);
  const { ciphertext, tag } = xchacha.encrypt(key, nonce, Buffer.from('test'));
  ciphertext[0] ^= 0xFF;
  assert.throws(() => xchacha.decrypt(key, nonce, ciphertext, tag));
});

test('XChaCha20 wrong key rejected', () => {
  const key1 = crypto.randomBytes(32);
  const key2 = crypto.randomBytes(32);
  const nonce = crypto.randomBytes(24);
  const { ciphertext, tag } = xchacha.encrypt(key1, nonce, Buffer.from('secret'));
  assert.throws(() => xchacha.decrypt(key2, nonce, ciphertext, tag));
});

test('seal/open roundtrip', () => {
  const key = crypto.randomBytes(32);
  const packet = xchacha.seal(key, Buffer.from('seal test'));
  const pt = xchacha.open(key, packet);
  assert.strictEqual(pt.toString('utf8'), 'seal test');
});

test('E2E one-shot roundtrip', () => {
  const alice = generateKeyPair();
  const bob = generateKeyPair();
  const ct = encryptOneShot('Hello Bob', bob.publicKey);
  const pt = decryptOneShot(ct, bob.privateKey);
  assert.strictEqual(pt.toString('utf8'), 'Hello Bob');
});

test('E2E wire format byte offsets', () => {
  const bob = generateKeyPair();
  const ct = encryptOneShot('x', bob.publicKey);
  // replayId(16) + ephPub(32) + salt(32) + nonce(24) + ct(1) + tag(16) = 121
  assert.strictEqual(ct.length, ENCRYPT_OVERHEAD + 1);
  // Verify we can parse fields at correct offsets
  let off = 0;
  const replayId = ct.subarray(off, off + REPLAY_ID_LEN); off += REPLAY_ID_LEN;
  const ephPub = ct.subarray(off, off + EPH_PUB_LEN); off += EPH_PUB_LEN;
  assert.strictEqual(replayId.length, 16);
  assert.strictEqual(ephPub.length, 32);
});

test('E2E replay detection', () => {
  const bob = generateKeyPair();
  const cache = new Set();
  const ct = encryptOneShot('once', bob.publicKey);
  decryptOneShot(ct, bob.privateKey, cache);
  assert.throws(() => decryptOneShot(ct, bob.privateKey, cache), /Replay/);
});

test('E2E wrong key rejected', () => {
  const alice = generateKeyPair();
  const bob = generateKeyPair();
  const eve = generateKeyPair();
  const ct = encryptOneShot('secret', bob.publicKey);
  assert.throws(() => decryptOneShot(ct, eve.privateKey));
});

test('E2E empty plaintext', () => {
  const bob = generateKeyPair();
  const ct = encryptOneShot(Buffer.alloc(0), bob.publicKey);
  const pt = decryptOneShot(ct, bob.privateKey);
  assert.strictEqual(pt.length, 0);
});

test('E2E ciphertext non-determinism', () => {
  const bob = generateKeyPair();
  const ct1 = encryptOneShot('same', bob.publicKey);
  const ct2 = encryptOneShot('same', bob.publicKey);
  assert.notDeepStrictEqual(ct1, ct2);
});

console.log(`\n── Results: ${passed} passed, ${failed} failed ──\n`);
if (failed > 0) process.exit(1);
