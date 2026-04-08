#!/usr/bin/env node
'use strict';
/**
 * SDK smoke test — fully automated Alice↔Bob E2E encrypted conversation.
 * Uses the mock Stratum server (no real pool needed).
 *
 * This proves:
 *   1. VS3Client connects and performs key exchange automatically
 *   2. Encrypted messages are delivered and decrypted correctly
 *   3. Multiple messages in both directions work
 *   4. The 120-byte encryption overhead is correct
 *   5. Messages arrive in order
 *
 * Exit code 0 = all checks pass.
 */

const assert = require('assert');
const MockStratumServer = require('../test/helpers/mock-stratum-server');
const { VS3Client, ENCRYPT_OVERHEAD, MSG_TYPE } = require('..');

const MESSAGES = [
  { from: 'alice', text: 'Hello Bob, this is Alice.' },
  { from: 'bob',   text: 'Hi Alice! Encrypted and steganographic.' },
  { from: 'alice', text: 'Can you read this through the pool?' },
  { from: 'bob',   text: 'The pool sees only 0x05 ENCRYPTED frames.' },
  { from: 'alice', text: 'Perfect forward secrecy — every message uses a fresh key.' },
];

(async () => {
  console.log('╔══════════════════════════════════════════════════════╗');
  console.log('║  @tnzx/sdk — End-to-End Integration Smoke Test      ║');
  console.log('╚══════════════════════════════════════════════════════╝\n');

  // Start mock pool
  const server = new MockStratumServer();
  const port = await server.start();
  console.log(`  [pool] Mock Stratum server on port ${port}\n`);

  // Create Alice and Bob
  const alice = new VS3Client({ pool: `127.0.0.1:${port}`, wallet: '4alice_smoke', ghostIntervalMs: 5 });
  const bob   = new VS3Client({ pool: `127.0.0.1:${port}`, wallet: '4bob_smoke',   ghostIntervalMs: 5 });

  console.log(`  [alice] pubkey: ${alice.publicKey.toString('hex').slice(0, 16)}...`);
  console.log(`  [bob]   pubkey: ${bob.publicKey.toString('hex').slice(0, 16)}...\n`);

  // Track received messages
  const aliceReceived = [];
  const bobReceived = [];

  alice.on('message', (m) => { aliceReceived.push(m.text); });
  bob.on('message', (m) => { bobReceived.push(m.text); });

  alice.on('error', (e) => console.log(`  [alice err] ${e.message}`));
  bob.on('error', (e) => console.log(`  [bob err] ${e.message}`));

  // Connect both
  const aliceReady = new Promise(r => alice.on('ready', r));
  const bobReady   = new Promise(r => bob.on('ready', r));
  alice.connect();
  bob.connect();
  await aliceReady;
  await bobReady;
  console.log('  [1/5] Both connected to pool ✓');

  // Trigger key exchange
  const alicePeer = new Promise((r, j) => {
    alice.on('peer', r);
    setTimeout(() => j(new Error('alice key exchange timeout')), 10000);
  });
  const bobPeer = new Promise((r, j) => {
    bob.on('peer', r);
    setTimeout(() => j(new Error('bob key exchange timeout')), 10000);
  });

  // Send initial messages to trigger key exchange
  alice.send('4bob_smoke', '__init__');
  bob.send('4alice_smoke', '__init__');

  await Promise.all([alicePeer, bobPeer]);
  console.log('  [2/5] Key exchange complete ✓');

  // Wait for init messages to be delivered and settle
  await new Promise(r => setTimeout(r, 1500));
  // Clear init messages
  aliceReceived.length = 0;
  bobReceived.length = 0;

  // Send the conversation
  for (const msg of MESSAGES) {
    if (msg.from === 'alice') {
      await alice.send('4bob_smoke', msg.text);
    } else {
      await bob.send('4alice_smoke', msg.text);
    }
    // Wait for delivery (ghost share pacing + network)
    await new Promise(r => setTimeout(r, 300));
  }

  // Final wait for last message delivery
  await new Promise(r => setTimeout(r, 1000));

  // Verify
  const expectedByBob = MESSAGES.filter(m => m.from === 'alice').map(m => m.text);
  const expectedByAlice = MESSAGES.filter(m => m.from === 'bob').map(m => m.text);

  console.log(`  [3/5] Bob received ${bobReceived.length}/${expectedByBob.length} messages`);
  for (let i = 0; i < expectedByBob.length; i++) {
    assert.strictEqual(bobReceived[i], expectedByBob[i],
      `Bob message ${i}: expected "${expectedByBob[i]}", got "${bobReceived[i]}"`);
  }
  console.log('  [3/5] Bob received all messages correctly ✓');

  console.log(`  [4/5] Alice received ${aliceReceived.length}/${expectedByAlice.length} messages`);
  for (let i = 0; i < expectedByAlice.length; i++) {
    assert.strictEqual(aliceReceived[i], expectedByAlice[i],
      `Alice message ${i}: expected "${expectedByAlice[i]}", got "${aliceReceived[i]}"`);
  }
  console.log('  [4/5] Alice received all messages correctly ✓');

  // Verify encryption overhead
  const { encryptOneShot, generateKeyPair } = require('..');
  const kp = generateKeyPair();
  const ct = encryptOneShot('test', kp.publicKey);
  assert.strictEqual(ct.length - 4, ENCRYPT_OVERHEAD,
    `Overhead should be ${ENCRYPT_OVERHEAD}, got ${ct.length - 4}`);
  console.log(`  [5/5] Encryption overhead: ${ENCRYPT_OVERHEAD} bytes ✓`);

  // Cleanup
  alice.disconnect();
  bob.disconnect();
  server.stop();

  console.log('\n══════════════════════════════════════════════════════');
  console.log('  ALL CHECKS PASSED — SDK is working correctly.');
  console.log('══════════════════════════════════════════════════════\n');
  process.exit(0);
})().catch(e => {
  console.error(`\n  FAILED: ${e.message}`);
  process.exit(1);
});
