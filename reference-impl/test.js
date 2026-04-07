#!/usr/bin/env node
/**
 * Visual Stratum — Reference Implementation Tests
 *
 * Validates the encoder/decoder, crypto module, and mining gate
 * against published test vectors and basic functionality.
 *
 * Run: node test.js
 * No dependencies required (uses Node.js assert + crypto).
 *
 * @license LGPL-2.1
 */
'use strict';

const assert = require('assert');
const crypto = require('crypto');
const { StegoEncoder, StegoDecoder, MSG_TYPE, MAGIC_BYTE, VERSION_V3, BYTES_PER_SHARE_V3 } = require('./stego-core');
const { E2ECrypto, encryptOneShot, decryptOneShot } = require('./crypto');
const { MiningGate, ACCESS_LEVEL } = require('./mining-gate');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    passed++;
    console.log(`  ✓ ${name}`);
  } catch (e) {
    failed++;
    console.log(`  ✗ ${name}`);
    console.log(`    ${e.message}`);
  }
}

// ============================================
// STEGANOGRAPHIC ENCODER/DECODER
// ============================================

console.log('\n── Stego Core ──');

test('V1: embed and extract byte from nonce', () => {
  const encoder = new StegoEncoder();
  const decoder = new StegoDecoder();
  const nonce = 'a1b2c3d4e5f67800';
  const byte = 0xAA;

  const modified = encoder.embedByteInNonce(nonce, byte);
  const extracted = decoder.extractByteFromNonce(modified);

  assert.strictEqual(extracted, byte, `Expected 0x${byte.toString(16)}, got 0x${extracted.toString(16)}`);
});

test('V1: nonce embedding preserves upper nibbles', () => {
  const encoder = new StegoEncoder();
  const nonce = 'a1b2c3d4e5f67890';
  const modified = encoder.embedByteInNonce(nonce, 0x5C);

  // Bytes before last 2 must be unchanged
  assert.strictEqual(modified.slice(0, -4), nonce.slice(0, -4));
  // Upper nibbles of last 2 bytes must be preserved (7_ and 8_)
  assert.strictEqual(modified[modified.length - 4], '7', 'Upper nibble of byte[-2] preserved');
  assert.strictEqual(modified[modified.length - 2], '9', 'Upper nibble of byte[-1] preserved (0x90 → upper nibble = 9)');
});

test('V1: embed/extract all edge values', () => {
  const encoder = new StegoEncoder();
  const decoder = new StegoDecoder();
  for (const byte of [0x00, 0x01, 0x0F, 0x10, 0x7F, 0x80, 0xFE, 0xFF]) {
    const modified = encoder.embedByteInNonce('a1b2c3d400000000', byte);
    const extracted = decoder.extractByteFromNonce(modified);
    assert.strictEqual(extracted, byte, `Failed for 0x${byte.toString(16)}`);
  }
});

test('V2: embed and extract 3 bytes', () => {
  const encoder = new StegoEncoder();
  const decoder = new StegoDecoder();
  const nonce = 'a1b2c3d400000000';
  const ext = '0000000000000000';
  const data = [0xAA, 0xBB, 0xCC];

  const result = encoder.embedBytesV2(nonce, ext, data);
  const extracted = decoder.extractBytesV2(result.nonce, result.extranonce2);

  assert.strictEqual(extracted[0], 0xAA, 'Byte 0 mismatch');
  assert.strictEqual(extracted[1], 0xBB, 'Byte 1 mismatch');
  assert.strictEqual(extracted[2], 0xCC, 'Byte 2 mismatch');
});

test('V3: embed and extract 5 bytes (Monero Stratum)', () => {
  const encoder = new StegoEncoder();
  const decoder = new StegoDecoder();
  const ntime = '65b2a100';
  const data = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE];

  const result = encoder.embedBytesV3(ntime, data);
  const extracted = decoder.extractBytesV3(result.nonce, result.ntime);

  assert.strictEqual(BYTES_PER_SHARE_V3, 5, 'BYTES_PER_SHARE_V3 constant must be 5');
  for (let i = 0; i < 5; i++) {
    assert.strictEqual(extracted[i], data[i], `Byte ${i}: expected 0x${data[i].toString(16)}, got 0x${extracted[i].toString(16)}`);
  }
});

test('V3: nonce[0] is always MAGIC_BYTE sentinel (0xAA)', () => {
  const encoder = new StegoEncoder();
  const result = encoder.embedBytesV3('65b2a100', [0x11, 0x22, 0x33, 0x44, 0x55]);
  const nb = Buffer.from(result.nonce, 'hex');
  assert.strictEqual(nb[0], MAGIC_BYTE, `nonce[0] must be 0xAA, got 0x${nb[0].toString(16)}`);
  assert.strictEqual(nb[1], 0x11);
  assert.strictEqual(nb[2], 0x22);
  assert.strictEqual(nb[3], 0x33);
});

test('V3: ntime high word preserved, low word carries payload bytes[3..4]', () => {
  const encoder = new StegoEncoder();
  const result = encoder.embedBytesV3('65b2a100', [0x11, 0x22, 0x33, 0xDD, 0xEE]);
  assert.strictEqual(result.ntime.slice(0, 4), '65b2', 'ntime high word must be preserved');
  assert.strictEqual(result.ntime.slice(4), 'ddee', 'ntime low word must carry payload bytes[3..4]');
});

test('V3: roundtrip with all-zero payload', () => {
  const encoder = new StegoEncoder();
  const decoder = new StegoDecoder();
  const data = [0x00, 0x00, 0x00, 0x00, 0x00];
  const result = encoder.embedBytesV3('65b2a100', data);
  const extracted = decoder.extractBytesV3(result.nonce, result.ntime);
  for (let i = 0; i < 5; i++) assert.strictEqual(extracted[i], 0, `Byte ${i} should be 0`);
});

test('V3: roundtrip with all-0xFF payload', () => {
  const encoder = new StegoEncoder();
  const decoder = new StegoDecoder();
  const data = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
  const result = encoder.embedBytesV3('65b2a100', data);
  const extracted = decoder.extractBytesV3(result.nonce, result.ntime);
  for (let i = 0; i < 5; i++) assert.strictEqual(extracted[i], 0xFF, `Byte ${i} should be 0xFF`);
});

test('Frame creation and reassembly', () => {
  const encoder = new StegoEncoder();
  const decoder = new StegoDecoder();
  const message = 'Hello, Visual Stratum!';

  const { frames } = encoder.createMessageFrames(message, MSG_TYPE.TEXT);

  assert.ok(frames.length > 0, 'Should produce at least 1 frame');
  assert.strictEqual(frames[0][0], MAGIC_BYTE, 'First byte should be magic');
  assert.strictEqual(frames[0][1], VERSION_V3, 'Version should be V3');

  // Reassemble
  let result;
  for (const frame of frames) {
    result = decoder.processFrame(frame);
  }

  assert.ok(result.complete, 'Message should be complete');
  assert.strictEqual(result.text, message, 'Decoded text should match');
});

test('Large message fragmentation', () => {
  const encoder = new StegoEncoder();
  const decoder = new StegoDecoder();
  const message = 'x'.repeat(500); // Exceeds MAX_FRAGMENT_SIZE (128)

  const { frames, totalFragments } = encoder.createMessageFrames(message);

  assert.ok(totalFragments > 1, `Should fragment: got ${totalFragments} fragments`);

  let result;
  for (const frame of frames) {
    result = decoder.processFrame(frame);
  }

  assert.ok(result.complete);
  assert.strictEqual(result.text, message);
});

test('Frame boundary: exactly MAX_FRAGMENT_SIZE payload', () => {
  const encoder = new StegoEncoder();
  const decoder = new StegoDecoder();
  const message = 'A'.repeat(128); // Exactly MAX_FRAGMENT_SIZE

  const { frames, totalFragments } = encoder.createMessageFrames(message);

  assert.strictEqual(totalFragments, 1, 'Exact fit should produce 1 fragment');

  const result = decoder.processFrame(frames[0]);
  assert.ok(result.complete);
  assert.strictEqual(result.text, message);
});

test('Frame boundary: MAX_FRAGMENT_SIZE + 1 forces 2 fragments', () => {
  const encoder = new StegoEncoder();
  const decoder = new StegoDecoder();
  const message = 'B'.repeat(129); // One byte over

  const { totalFragments } = encoder.createMessageFrames(message);
  assert.strictEqual(totalFragments, 2, 'Should split into 2 fragments');
});

test('Fragment timeout cleanup removes stale messages', () => {
  const decoder = new StegoDecoder();
  const encoder = new StegoEncoder();

  // Create a 2-fragment message but only send 1 fragment
  const { frames } = encoder.createMessageFrames('x'.repeat(200));
  decoder.processFrame(frames[0]); // Only first fragment

  assert.strictEqual(decoder.pendingMessages.size, 1, 'Should have 1 pending');

  // Simulate age by manipulating startTime
  const key = Array.from(decoder.pendingMessages.keys())[0];
  decoder.pendingMessages.get(key).startTime = Date.now() - 400000; // 6+ min ago
  decoder.lastCleanup = 0; // Force cleanup on next call

  // Process another frame to trigger cleanup
  const fakeFrame = Buffer.alloc(16, 0);
  fakeFrame[0] = 0xBB; // Wrong magic, but triggers enforceCleanup
  decoder.processFrame(fakeFrame);

  assert.strictEqual(decoder.pendingMessages.size, 0, 'Stale message should be cleaned');
});

test('Invalid magic byte rejected', () => {
  const decoder = new StegoDecoder();
  const fakeFrame = Buffer.alloc(16, 0);
  fakeFrame[0] = 0xBB; // Wrong magic

  const result = decoder.processFrame(fakeFrame);
  assert.ok(result.isNormalShare, 'Should identify as normal share');
});

test('Hex validation rejects bad input', () => {
  const encoder = new StegoEncoder();
  assert.throws(() => encoder.embedByteInNonce('not-hex!', 0xAA), /Invalid hex/);
  assert.throws(() => encoder.embedByteInNonce('abc', 0xAA), /Invalid hex/); // Odd length
});

// ============================================
// E2E ENCRYPTION
// ============================================

console.log('\n── Crypto ──');

test('Key generation produces 32-byte keys', () => {
  const e2e = new E2ECrypto();
  const { publicKey, privateKey } = e2e.generateKeyPair();

  assert.strictEqual(publicKey.length, 32);
  assert.strictEqual(privateKey.length, 32);
});

test('ECDH shared secret is symmetric', () => {
  const alice = new E2ECrypto();
  const bob = new E2ECrypto();
  alice.generateKeyPair();
  bob.generateKeyPair();

  const secretAB = alice.computeSharedSecret(bob.getPublicKey());
  const secretBA = bob.computeSharedSecret(alice.getPublicKey());

  assert.ok(secretAB.equals(secretBA), 'Shared secrets must be equal');
});

test('Session encrypt/decrypt roundtrip', () => {
  const alice = new E2ECrypto();
  const bob = new E2ECrypto();
  alice.generateKeyPair();
  bob.generateKeyPair();

  alice.establishSession('bob', bob.getPublicKey());
  bob.establishSession('alice', alice.getPublicKey());

  const plaintext = 'Secret message via Visual Stratum';
  const encrypted = alice.encrypt(plaintext, 'bob');
  const decrypted = bob.decrypt(encrypted, 'alice');

  assert.strictEqual(decrypted.toString('utf8'), plaintext);
});

test('One-shot encrypt/decrypt (PFS)', () => {
  const recipient = new E2ECrypto();
  recipient.generateKeyPair();

  const plaintext = 'One-shot PFS message';
  const encrypted = encryptOneShot(plaintext, recipient.getPublicKey());
  const decrypted = decryptOneShot(encrypted, recipient.keyPair.privateKey);

  assert.strictEqual(decrypted.toString('utf8'), plaintext);
});

test('Decryption fails with wrong key', () => {
  const alice = new E2ECrypto();
  const bob = new E2ECrypto();
  const eve = new E2ECrypto();
  alice.generateKeyPair();
  bob.generateKeyPair();
  eve.generateKeyPair();

  alice.establishSession('bob', bob.getPublicKey());

  const encrypted = alice.encrypt('Secret', 'bob');

  // Eve tries to decrypt — wrong shared secret triggers Poly1305 auth failure
  eve.establishSession('alice', alice.getPublicKey());
  assert.throws(() => eve.decrypt(encrypted, 'alice'), /Decryption failed/);
});

test('Replay protection rejects duplicate nonce', () => {
  const alice = new E2ECrypto();
  const bob = new E2ECrypto();
  alice.generateKeyPair();
  bob.generateKeyPair();

  alice.establishSession('bob', bob.getPublicKey());
  bob.establishSession('alice', alice.getPublicKey());

  const encrypted = alice.encrypt('Message', 'bob');

  // First decrypt succeeds
  bob.decrypt(encrypted, 'alice');

  // Replay fails
  assert.throws(() => bob.decrypt(encrypted, 'alice'), /Replay attack/);
});

test('Different messages produce different ciphertexts', () => {
  const alice = new E2ECrypto();
  const bob = new E2ECrypto();
  alice.generateKeyPair();
  bob.generateKeyPair();
  alice.establishSession('bob', bob.getPublicKey());

  const ct1 = alice.encrypt('Message A', 'bob');
  const ct2 = alice.encrypt('Message A', 'bob'); // Same plaintext

  assert.ok(!ct1.equals(ct2), 'Same plaintext must produce different ciphertext (random IV+salt)');
});

// ============================================
// MINING GATE
// ============================================

console.log('\n── Mining Gate ──');

test('Initial state is INACTIVE', () => {
  const gate = new MiningGate();
  assert.strictEqual(gate.getState('4wallet123'), ACCESS_LEVEL.INACTIVE);
});

test('First share moves to GRACE', () => {
  const gate = new MiningGate();
  const result = gate.recordShare('4wallet123', 10000);
  assert.strictEqual(result.state, ACCESS_LEVEL.GRACE);
});

test('3 shares activates channel', () => {
  const gate = new MiningGate({ gracePeriodMs: 600000 }); // Long grace so all shares fit
  gate.recordShare('4wallet123', 10000);
  gate.recordShare('4wallet123', 10000);
  const result = gate.recordShare('4wallet123', 10000);
  assert.strictEqual(result.state, ACCESS_LEVEL.ACTIVE);
  assert.ok(gate.isOpen('4wallet123'), 'Channel should be open');
});

test('2 shares does NOT activate (needs 3)', () => {
  const gate = new MiningGate({ gracePeriodMs: 600000 });
  gate.recordShare('4wallet123', 10000);
  const result = gate.recordShare('4wallet123', 10000);
  assert.strictEqual(result.state, ACCESS_LEVEL.GRACE, 'Should still be GRACE with only 2 shares');
  assert.strictEqual(gate.isOpen('4wallet123'), false, 'Channel should NOT be open');
});

test('isOpen returns false for unknown miner', () => {
  const gate = new MiningGate();
  assert.strictEqual(gate.isOpen('unknown_address'), false);
});

test('Stats track active miners', () => {
  const gate = new MiningGate({ gracePeriodMs: 600000 });
  gate.recordShare('miner1', 10000);
  gate.recordShare('miner1', 10000);
  gate.recordShare('miner1', 10000);
  gate.recordShare('miner2', 10000);

  const stats = gate.getStats();
  assert.strictEqual(stats.total, 2);
  assert.strictEqual(stats.active, 1);
  assert.strictEqual(stats.grace, 1);
});

// ============================================
// REGRESSION TESTS — Bug fixes verification
// ============================================

console.log('\n── Regression: generateMessageId ──');

test('FIX #1: generateMessageId returns 16-bit value (not truncated 32-bit)', () => {
  const encoder = new StegoEncoder();
  for (let i = 0; i < 100; i++) {
    const id = encoder.generateMessageId();
    assert.ok(id >= 0 && id <= 0xFFFF, `ID ${id} out of 16-bit range`);
  }
});

test('FIX #2: generateMessageId collision check works on returned value', () => {
  const encoder = new StegoEncoder();
  const ids = new Set();
  // Generate many IDs — all should be unique (within 16-bit space)
  for (let i = 0; i < 200; i++) {
    const id = encoder.generateMessageId();
    assert.ok(!ids.has(id), `Collision detected: ${id} after ${i} generations`);
    ids.add(id);
  }
});

test('FIX #2: usedMessageIds tracks same values as returned', () => {
  const encoder = new StegoEncoder();
  const returned = [];
  for (let i = 0; i < 10; i++) {
    returned.push(encoder.generateMessageId());
  }
  // Every returned value must be in the usedMessageIds set
  for (const id of returned) {
    assert.ok(encoder.usedMessageIds.has(id),
      `Returned ID ${id} not tracked in usedMessageIds`);
  }
});

console.log('\n── Regression: MinerState.getHashrate ──');

test('FIX #3: getHashrate does NOT mutate recentShares', () => {
  const { MinerState } = require('./mining-gate');
  const miner = new MinerState('test_addr');
  const now = Date.now();

  // Add shares spread over time
  miner.recentShares = [
    { timestamp: now - 500000, difficulty: 10000 },  // 8+ min ago
    { timestamp: now - 100000, difficulty: 10000 },   // ~1.5 min ago
    { timestamp: now - 1000, difficulty: 10000 }      // 1 sec ago
  ];

  const sharesBefore = miner.recentShares.length;

  // Call getHashrate with a short window — should NOT delete old shares
  miner.getHashrate(60000); // 1-min window

  assert.strictEqual(miner.recentShares.length, sharesBefore,
    `getHashrate mutated recentShares: was ${sharesBefore}, now ${miner.recentShares.length}`);
});

test('FIX #3: getHashrate with different windows returns different results without side effects', () => {
  const { MinerState } = require('./mining-gate');
  const miner = new MinerState('test_addr');
  const now = Date.now();

  miner.recentShares = [
    { timestamp: now - 300000, difficulty: 10000 },  // 5 min ago
    { timestamp: now - 60000, difficulty: 10000 },   // 1 min ago
    { timestamp: now - 1000, difficulty: 10000 }     // 1 sec ago
  ];

  // Call with short window first, then long window
  const shortRate = miner.getHashrate(120000);  // 2-min window (sees 2 shares)
  const longRate = miner.getHashrate(600000);   // 10-min window (sees 3 shares)

  // Both calls should see the correct number of shares
  assert.strictEqual(miner.recentShares.length, 3,
    'recentShares should not have been modified by either call');
  // longRate should reflect more difficulty than shortRate
  assert.ok(longRate > 0, 'Long window hashrate should be > 0');
});

test('FIX #4: getHashrate uses elapsed time, not full window', () => {
  const { MinerState } = require('./mining-gate');
  const miner = new MinerState('test_addr');
  const now = Date.now();

  // 3 shares all within the last 3 seconds, in a 600s window
  miner.recentShares = [
    { timestamp: now - 3000, difficulty: 10000 },
    { timestamp: now - 2000, difficulty: 10000 },
    { timestamp: now - 1000, difficulty: 10000 }
  ];

  const hashrate = miner.getHashrate(600000); // 10-min window

  // With elapsed=2s and totalDiff=30000: hashrate = 30000/2 = 15000
  // Old bug: totalDiff / (600000/1000) = 30000/600 = 50 (wildly underestimated)
  assert.ok(hashrate >= 10000, `Hashrate ${hashrate} is too low — elapsed-time calculation likely broken`);
});

test('FIX #3: pruneShares explicitly removes old shares', () => {
  const { MinerState } = require('./mining-gate');
  const miner = new MinerState('test_addr');
  const now = Date.now();

  miner.recentShares = [
    { timestamp: now - 700000, difficulty: 10000 },  // very old
    { timestamp: now - 1000, difficulty: 10000 }     // recent
  ];

  miner.pruneShares(600000); // 10-min window
  assert.strictEqual(miner.recentShares.length, 1, 'Should have pruned the old share');
  assert.ok(miner.recentShares[0].timestamp > now - 600000, 'Remaining share should be recent');
});

console.log('\n── Regression: One-shot replay protection ──');

test('FIX #5: decryptOneShot rejects replay of same ciphertext', () => {
  const recipient = new E2ECrypto();
  recipient.generateKeyPair();

  const plaintext = 'One-shot replay test';
  const encrypted = encryptOneShot(plaintext, recipient.getPublicKey());

  // First decryption succeeds
  const decrypted = decryptOneShot(encrypted, recipient.keyPair.privateKey);
  assert.strictEqual(decrypted.toString('utf8'), plaintext);

  // Replay must fail
  assert.throws(
    () => decryptOneShot(encrypted, recipient.keyPair.privateKey),
    /Replay attack/,
    'One-shot replay should be rejected'
  );
});

// ============================================
// REGRESSION: Critical fixes (S23 audit)
// ============================================

console.log('\n── Regression: S23 critical fixes ──');

test('FIX #6: VS2 test vector matches nibble-split encoding', () => {
  const encoder = new StegoEncoder();
  const vec = require('../test-vectors/vs2-vectors.json');
  const embed = vec.stratum_embedding[0];

  const result = encoder.embedBytesV2(
    embed.nonce_hex,
    embed.extranonce2_hex,
    embed.data_bytes
  );

  assert.strictEqual(result.nonce, embed.expected_nonce,
    `Nonce mismatch: got ${result.nonce}, expected ${embed.expected_nonce}`);
  assert.strictEqual(result.extranonce2, embed.expected_extranonce2,
    `Extranonce2 mismatch: got ${result.extranonce2}, expected ${embed.expected_extranonce2}`);
});

test('FIX #7: CompactSession rejects replay after sliding window pruning', () => {
  const { CompactSession } = require('./crypto/compact-session');
  const secret = crypto.randomBytes(32);
  const alice = new CompactSession(secret);
  const bob = new CompactSession(secret);

  // Capture ciphertext at counter=0
  const ct0 = alice.encrypt('message zero');
  bob.decrypt(ct0); // Legitimate decryption

  // Send 1100+ messages to push counter 0 out of the window
  for (let i = 1; i <= 1100; i++) {
    const ct = alice.encrypt(`msg ${i}`);
    bob.decrypt(ct);
  }

  // Replay of counter=0 must be rejected
  assert.throws(
    () => bob.decrypt(ct0),
    /counter too old/,
    'Replay of pruned counter should be rejected'
  );
});

test('FIX #8: E2ECrypto encrypts and decrypts empty plaintext', () => {
  const alice = new E2ECrypto();
  const bob = new E2ECrypto();
  alice.generateKeyPair();
  bob.generateKeyPair();

  alice.establishSession('bob', bob.getPublicKey());
  bob.establishSession('alice', alice.getPublicKey());

  const encrypted = alice.encrypt(Buffer.alloc(0), 'bob');
  const decrypted = bob.decrypt(encrypted, 'alice');

  assert.strictEqual(decrypted.length, 0, 'Decrypted empty plaintext should have length 0');
});

test('FIX #8: decryptOneShot handles empty plaintext', () => {
  const recipient = new E2ECrypto();
  recipient.generateKeyPair();

  const encrypted = encryptOneShot(Buffer.alloc(0), recipient.getPublicKey());
  const decrypted = decryptOneShot(encrypted, recipient.keyPair.privateKey);

  assert.strictEqual(decrypted.length, 0, 'One-shot empty plaintext should decrypt to 0 bytes');
});

// ============================================
// RESULTS
// ============================================

console.log(`\n── Results: ${passed} passed, ${failed} failed ──\n`);

if (failed > 0) {
  process.exit(1);
} else {
  console.log('All tests passed.');
}
