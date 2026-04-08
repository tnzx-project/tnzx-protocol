/**
 * test-compact-session.js — Tests for Compact Session Encryption
 *
 * What these tests cover:
 *   - Encrypt/decrypt roundtrip (single and multi-message)
 *   - Counter monotonicity and wire format
 *   - Tampered counter rejection (Poly1305 auth failure)
 *   - Wrong shared secret rejection
 *   - Replay protection (duplicate ciphertext rejected)
 *   - Out-of-order delivery (counters 2,0,1 decrypted successfully)
 *   - Edge cases: empty plaintext, binary data
 *   - Input validation: short key, short data
 *   - Overhead comparison: 32 bytes vs 88 bytes standard (-64%)
 *
 * What these tests do NOT cover:
 *   - Counter overflow at 2^32: no test that re-key is triggered.
 *   - Concurrent sessions between the same parties.
 *   - Performance under high message rates.
 *   - HKDF output correctness against known test vectors.
 *   - Timing side channels in ChaCha20-Poly1305 (trusts Node.js OpenSSL).
 *
 * @license LGPL-2.1
 */

'use strict';

const crypto = require('crypto');
const { CompactSession } = require('./compact-session.js');

let passed = 0;
let failed = 0;

function assert(condition, name) {
  if (condition) { passed++; console.log(`  ✓ ${name}`); }
  else { failed++; console.error(`  ✗ FAIL: ${name}`); }
}

// Generate a shared secret (simulates X25519 ECDH output)
const sharedSecret = crypto.randomBytes(32);

console.log('\n═══ Compact Session Encryption Tests ═══\n');

// ── Roundtrip ────────────────────────────────────────────────────────────────

console.log('Test 1: Roundtrip');
const alice = new CompactSession(sharedSecret);
const bob = new CompactSession(sharedSecret);

const ct1 = alice.encrypt('Hello');
const pt1 = bob.decrypt(ct1);
assert(pt1.toString() === 'Hello', 'Encrypt/decrypt roundtrip');

const ct2 = alice.encrypt('World');
const pt2 = bob.decrypt(ct2);
assert(pt2.toString() === 'World', 'Second message roundtrip');

// ── Counter Increment ────────────────────────────────────────────────────────

console.log('\nTest 2: Counter behavior');
assert(alice.sendCounter === 2, 'Alice counter incremented to 2');
assert(ct1.readUInt32BE(0) === 0, 'First message has counter 0');
assert(ct2.readUInt32BE(0) === 1, 'Second message has counter 1');

// ── Tampered Counter ─────────────────────────────────────────────────────────

console.log('\nTest 3: Tampered counter rejected');
const ct3 = alice.encrypt('test');
const tampered = Buffer.from(ct3);
tampered[0] ^= 0xFF; // flip counter byte
let tamperedFailed = false;
try { bob.decrypt(tampered); } catch { tamperedFailed = true; }
assert(tamperedFailed, 'Tampered counter causes decryption failure');

// ── Wrong Key ────────────────────────────────────────────────────────────────

console.log('\nTest 4: Wrong key rejected');
const eve = new CompactSession(crypto.randomBytes(32));
const ct4 = alice.encrypt('secret');
let wrongKeyFailed = false;
try { eve.decrypt(ct4); } catch { wrongKeyFailed = true; }
assert(wrongKeyFailed, 'Wrong shared secret causes decryption failure');

// ── Replay Protection ────────────────────────────────────────────────────────

console.log('\nTest 5: Replay protection');
const ct5 = alice.encrypt('no-replay');
bob.decrypt(ct5); // first time OK
let replayFailed = false;
try { bob.decrypt(ct5); } catch { replayFailed = true; }
assert(replayFailed, 'Replay of same ciphertext rejected');

// ── Out-of-Order ─────────────────────────────────────────────────────────────

console.log('\nTest 6: Out-of-order delivery');
const alice2 = new CompactSession(sharedSecret);
const bob2 = new CompactSession(sharedSecret);
const m1 = alice2.encrypt('first');
const m2 = alice2.encrypt('second');
const m3 = alice2.encrypt('third');
// Deliver out of order: 3, 1, 2
const p3 = bob2.decrypt(m3);
const p1 = bob2.decrypt(m1);
const p2 = bob2.decrypt(m2);
assert(p1.toString() === 'first', 'Out-of-order msg 1');
assert(p2.toString() === 'second', 'Out-of-order msg 2');
assert(p3.toString() === 'third', 'Out-of-order msg 3');

// ── Empty and Binary ─────────────────────────────────────────────────────────

console.log('\nTest 7: Edge cases');
const alice3 = new CompactSession(sharedSecret);
const bob3 = new CompactSession(sharedSecret);

const ctEmpty = alice3.encrypt(Buffer.alloc(0));
const ptEmpty = bob3.decrypt(ctEmpty);
assert(ptEmpty.length === 0, 'Empty plaintext roundtrip');

const binary = crypto.randomBytes(256);
const ctBin = alice3.encrypt(binary);
const ptBin = bob3.decrypt(ctBin);
assert(Buffer.compare(binary, ptBin) === 0, 'Binary data roundtrip');

// ── Input Validation ─────────────────────────────────────────────────────────

console.log('\nTest 8: Input validation');
let badKey = false;
try { new CompactSession(Buffer.alloc(16)); } catch { badKey = true; }
assert(badKey, 'Rejects 16-byte key');

let badData = false;
try { bob3.decrypt(Buffer.alloc(10)); } catch { badData = true; }
assert(badData, 'Rejects data too short');

// ── Overhead Calculation ─────────────────────────────────────────────────────

console.log('\nTest 9: Overhead comparison');
assert(CompactSession.OVERHEAD === 32, `Compact overhead is 32 bytes (got ${CompactSession.OVERHEAD})`);

const STANDARD_OVERHEAD = 76; // nonce(16) + salt(32) + IV(12) + tag(16)
const COMPACT_OVERHEAD = CompactSession.OVERHEAD;
const HEADER = 8; // VS3 frame header

const sizes = [5, 50, 128, 1024, 6400];
console.log('\n  ┌─────────┬──────────┬──────────┬─────────┬──────────┬──────────┬─────────┐');
console.log('  │ Payload  │ Std(enc) │ Cmp(enc) │ Saved   │ Std(shr) │ Cmp(shr) │ Saved   │');
console.log('  ├─────────┼──────────┼──────────┼─────────┼──────────┼──────────┼─────────┤');
for (const sz of sizes) {
  const stdTotal = sz + STANDARD_OVERHEAD + HEADER;
  const cmpTotal = sz + COMPACT_OVERHEAD + HEADER;
  const stdShares = Math.ceil(stdTotal / 5);
  const cmpShares = Math.ceil(cmpTotal / 5);
  const savedBytes = stdTotal - cmpTotal;
  const savedShares = stdShares - cmpShares;
  console.log(`  │ ${String(sz).padStart(7)} │ ${String(stdTotal).padStart(7)}B │ ${String(cmpTotal).padStart(7)}B │ ${String(savedBytes).padStart(5)}B  │ ${String(stdShares).padStart(8)} │ ${String(cmpShares).padStart(8)} │ ${String(savedShares).padStart(5)}   │`);
}
console.log('  └─────────┴──────────┴──────────┴─────────┴──────────┴──────────┴─────────┘');

// ── Summary ──────────────────────────────────────────────────────────────────

console.log(`\n═══ Results: ${passed} passed, ${failed} failed ═══\n`);
if (failed > 0) process.exit(1);
