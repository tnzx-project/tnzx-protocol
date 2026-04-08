#!/usr/bin/env node
'use strict';
/**
 * @tnzx/sdk — VS3Client integration test
 * Alice and Bob exchange E2E encrypted messages through a mock pool.
 */

const assert = require('assert');
const MockStratumServer = require('./helpers/mock-stratum-server');
const VS3Client = require('../lib/vs3-client');

let passed = 0, failed = 0;
async function test(name, fn) {
  try { await fn(); passed++; console.log(`  ✓ ${name}`); }
  catch (e) { failed++; console.log(`  ✗ ${name}: ${e.message}`); }
}

async function run() {
  console.log('── SDK VS3Client ──');

  const server = new MockStratumServer();
  const port = await server.start();

  await test('Alice sends encrypted message to Bob', async () => {
    const alice = new VS3Client({
      pool: `127.0.0.1:${port}`,
      wallet: '4alice_wallet_test',
      ghostIntervalMs: 10,
    });
    const bob = new VS3Client({
      pool: `127.0.0.1:${port}`,
      wallet: '4bob_wallet_test',
      ghostIntervalMs: 10,
    });

    const aliceReady = new Promise(r => alice.on('ready', r));
    const bobReady = new Promise(r => bob.on('ready', r));

    alice.connect();
    bob.connect();
    await aliceReady;
    await bobReady;

    // Set up message listener before triggering key exchange
    const msgReceived = new Promise((resolve, reject) => {
      bob.on('message', resolve);
      setTimeout(() => reject(new Error('message timeout')), 15000);
    });

    // Alice sends to Bob — this triggers key exchange automatically.
    // The message is queued until Bob's key arrives.
    alice.send('4bob_wallet_test', 'Hello from SDK!');

    // Bob also initiates to Alice (triggers his key exchange)
    bob.send('4alice_wallet_test', 'Hi Alice');

    // Wait for the encrypted message to arrive
    const msg = await msgReceived;

    assert.strictEqual(msg.text, 'Hello from SDK!');
    assert.ok(msg.raw instanceof Buffer);

    alice.disconnect();
    bob.disconnect();
  });

  await test('VS3Client auto-generates keypair', () => {
    const client = new VS3Client({ pool: '127.0.0.1:1234', wallet: '4test' });
    assert.ok(client.publicKey instanceof Buffer);
    assert.strictEqual(client.publicKey.length, 32);
  });

  await test('VS3Client accepts pre-existing keypair', () => {
    const { generateKeyPair } = require('../lib/crypto/e2e');
    const kp = generateKeyPair();
    const client = new VS3Client({
      pool: '127.0.0.1:1234', wallet: '4test',
      privateKey: kp.privateKey, publicKey: kp.publicKey,
    });
    assert.deepStrictEqual(client.publicKey, kp.publicKey);
  });

  server.stop();
  console.log(`\n── Results: ${passed} passed, ${failed} failed ──\n`);
  if (failed > 0) process.exit(1);
}

run().catch(e => { console.error(e); process.exit(1); });
