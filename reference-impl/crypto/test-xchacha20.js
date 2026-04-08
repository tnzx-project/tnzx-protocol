/**
 * XChaCha20-Poly1305 test suite
 * @license LGPL-2.1
 *
 * What these tests cover:
 *   1. HChaCha20 against RFC draft-irtf-cfrg-xchacha Section 2.2.1 test vector
 *   2. XChaCha20-Poly1305 encrypt/decrypt roundtrip
 *   3. Authentication failure on tampered ciphertext, tag, and wrong key
 *   4. seal/open wire format (nonce + ciphertext + tag)
 *   5. AAD: correct AAD passes, wrong AAD rejected, missing AAD rejected
 *   6. Edge cases: empty plaintext, 1MB plaintext
 *   7. Nonce uniqueness: seal() generates distinct nonces
 *
 * What these tests do NOT cover:
 *   - Cross-implementation interoperability: no test against libsodium or
 *     another XChaCha20 implementation (only self-roundtrip).
 *   - HChaCha20 edge cases: only one RFC test vector. No test for all-zero
 *     key, all-zero nonce, or counter overflow.
 *   - Nonce reuse detection: no test that reusing the same nonce with different
 *     plaintexts leaks information (this is a known property of AEAD, not a bug).
 *   - Performance: no benchmark for throughput or latency.
 *   - Side channels: trusts that the ARX operations in HChaCha20 are
 *     constant-time on the target platform (they should be, but untested).
 */

'use strict';

const crypto = require('crypto');
const { hchacha20, encrypt, decrypt, seal, open, NONCE_LEN, TAG_LEN } = require('./xchacha20');

let passed = 0;
let failed = 0;

function assert(condition, name) {
  if (condition) {
    passed++;
    console.log(`  PASS: ${name}`);
  } else {
    failed++;
    console.error(`  FAIL: ${name}`);
  }
}

function assertThrows(fn, name) {
  try {
    fn();
    failed++;
    console.error(`  FAIL: ${name} (no exception thrown)`);
  } catch (e) {
    passed++;
    console.log(`  PASS: ${name}`);
  }
}

function bufEqual(a, b) {
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

// ============================================================================
// Test 1: HChaCha20 RFC test vector
// draft-irtf-cfrg-xchacha, Section 2.2.1
// ============================================================================
console.log('\n=== HChaCha20 RFC test vector ===');
{
  const key = Buffer.from(
    '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', 'hex'
  );
  const nonce = Buffer.from(
    '000000090000004a0000000031415927', 'hex'
  );
  const expected = Buffer.from(
    '82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc', 'hex'
  );

  const result = hchacha20(key, nonce);
  assert(bufEqual(result, expected), 'HChaCha20 matches RFC test vector');
}

// ============================================================================
// Test 2: XChaCha20-Poly1305 roundtrip
// ============================================================================
console.log('\n=== XChaCha20-Poly1305 roundtrip ===');
{
  const key = crypto.randomBytes(32);
  const nonce = crypto.randomBytes(24);
  const plaintext = Buffer.from('The quick brown fox jumps over the lazy dog');

  const { ciphertext, tag } = encrypt(key, nonce, plaintext);
  const decrypted = decrypt(key, nonce, ciphertext, tag);

  assert(bufEqual(decrypted, plaintext), 'Decrypt recovers plaintext');
  assert(!bufEqual(ciphertext, plaintext), 'Ciphertext differs from plaintext');
  assert(tag.length === 16, 'Tag is 16 bytes');
}

// ============================================================================
// Test 3: Tampered ciphertext fails authentication
// ============================================================================
console.log('\n=== Authentication integrity ===');
{
  const key = crypto.randomBytes(32);
  const nonce = crypto.randomBytes(24);
  const plaintext = Buffer.from('Authenticated encryption test');

  const { ciphertext, tag } = encrypt(key, nonce, plaintext);

  // Flip one bit in ciphertext
  const tampered = Buffer.from(ciphertext);
  tampered[0] ^= 0x01;

  assertThrows(
    () => decrypt(key, nonce, tampered, tag),
    'Tampered ciphertext rejected'
  );
}

// ============================================================================
// Test 4: Tampered tag fails authentication
// ============================================================================
{
  const key = crypto.randomBytes(32);
  const nonce = crypto.randomBytes(24);
  const plaintext = Buffer.from('Tag integrity test');

  const { ciphertext, tag } = encrypt(key, nonce, plaintext);

  const badTag = Buffer.from(tag);
  badTag[0] ^= 0x01;

  assertThrows(
    () => decrypt(key, nonce, ciphertext, badTag),
    'Tampered tag rejected'
  );
}

// ============================================================================
// Test 5: Wrong key fails
// ============================================================================
{
  const key1 = crypto.randomBytes(32);
  const key2 = crypto.randomBytes(32);
  const nonce = crypto.randomBytes(24);
  const plaintext = Buffer.from('Wrong key test');

  const { ciphertext, tag } = encrypt(key1, nonce, plaintext);

  assertThrows(
    () => decrypt(key2, nonce, ciphertext, tag),
    'Wrong key rejected'
  );
}

// ============================================================================
// Test 6: seal/open wire format roundtrip
// ============================================================================
console.log('\n=== seal/open wire format ===');
{
  const key = crypto.randomBytes(32);
  const plaintext = Buffer.from('Wire format test message');

  const packet = seal(key, plaintext);

  assert(packet.length === NONCE_LEN + plaintext.length + TAG_LEN,
    `Packet length correct (${NONCE_LEN} + ${plaintext.length} + ${TAG_LEN} = ${packet.length})`);

  const decrypted = open(key, packet);
  assert(bufEqual(decrypted, plaintext), 'open() recovers plaintext from seal()');
}

// ============================================================================
// Test 7: AAD support
// ============================================================================
console.log('\n=== AAD (Additional Authenticated Data) ===');
{
  const key = crypto.randomBytes(32);
  const nonce = crypto.randomBytes(24);
  const plaintext = Buffer.from('AAD test');
  const aad = Buffer.from('authenticated header data');

  const { ciphertext, tag } = encrypt(key, nonce, plaintext, aad);

  // Correct AAD
  const decrypted = decrypt(key, nonce, ciphertext, tag, aad);
  assert(bufEqual(decrypted, plaintext), 'Decrypt with correct AAD works');

  // Wrong AAD
  const wrongAad = Buffer.from('wrong header');
  assertThrows(
    () => decrypt(key, nonce, ciphertext, tag, wrongAad),
    'Wrong AAD rejected'
  );

  // Missing AAD
  assertThrows(
    () => decrypt(key, nonce, ciphertext, tag),
    'Missing AAD rejected'
  );
}

// ============================================================================
// Test 8: Empty plaintext
// ============================================================================
console.log('\n=== Edge cases ===');
{
  const key = crypto.randomBytes(32);
  const nonce = crypto.randomBytes(24);
  const plaintext = Buffer.alloc(0);

  const { ciphertext, tag } = encrypt(key, nonce, plaintext);
  assert(ciphertext.length === 0, 'Empty plaintext produces empty ciphertext');
  assert(tag.length === 16, 'Empty plaintext still has 16-byte tag');

  const decrypted = decrypt(key, nonce, ciphertext, tag);
  assert(decrypted.length === 0, 'Decrypt empty ciphertext returns empty');
}

// ============================================================================
// Test 9: Large plaintext (1MB)
// ============================================================================
{
  const key = crypto.randomBytes(32);
  const nonce = crypto.randomBytes(24);
  const plaintext = crypto.randomBytes(1024 * 1024);

  const { ciphertext, tag } = encrypt(key, nonce, plaintext);
  const decrypted = decrypt(key, nonce, ciphertext, tag);
  assert(bufEqual(decrypted, plaintext), 'Large plaintext (1MB) roundtrip');
}

// ============================================================================
// Test 10: Nonce uniqueness
// ============================================================================
{
  const key = crypto.randomBytes(32);
  const plaintext = Buffer.from('nonce test');

  const p1 = seal(key, plaintext);
  const p2 = seal(key, plaintext);

  // First 24 bytes are nonce — must differ
  const n1 = p1.subarray(0, NONCE_LEN);
  const n2 = p2.subarray(0, NONCE_LEN);
  assert(!bufEqual(n1, n2), 'seal() generates unique nonces');

  // Both must decrypt correctly
  assert(bufEqual(open(key, p1), plaintext), 'First packet decrypts');
  assert(bufEqual(open(key, p2), plaintext), 'Second packet decrypts');
}

// ============================================================================
// Test 11: Input validation
// ============================================================================
console.log('\n=== Input validation ===');
{
  assertThrows(() => encrypt(crypto.randomBytes(16), crypto.randomBytes(24), Buffer.from('x')),
    'Short key (16B) rejected');
  assertThrows(() => encrypt(crypto.randomBytes(32), crypto.randomBytes(12), Buffer.from('x')),
    'Short nonce (12B) rejected');
  assertThrows(() => open(crypto.randomBytes(32), Buffer.alloc(10)),
    'Short packet rejected by open()');
}

// ============================================================================
// Test 12: seal/open with AAD
// ============================================================================
console.log('\n=== seal/open with AAD ===');
{
  const key = crypto.randomBytes(32);
  const plaintext = Buffer.from('seal with AAD');
  const aad = Buffer.from('header');

  const packet = seal(key, plaintext, aad);
  const decrypted = open(key, packet, aad);
  assert(bufEqual(decrypted, plaintext), 'seal/open with AAD roundtrip');

  assertThrows(
    () => open(key, packet, Buffer.from('wrong')),
    'seal/open wrong AAD rejected'
  );
}

// ============================================================================
// Summary
// ============================================================================
console.log(`\n=== Results: ${passed} passed, ${failed} failed ===`);
if (failed > 0) process.exit(1);
