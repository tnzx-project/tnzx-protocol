#!/usr/bin/env node
'use strict';
/**
 * @tnzx/sdk — StratumClient integration tests (with mock server)
 */

const assert = require('assert');
const MockStratumServer = require('./helpers/mock-stratum-server');
const StratumClient = require('../lib/transport/stratum-client');
const { buildVS3Frame } = require('../lib/transport/ghost-share');
const { MSG_TYPE } = require('../lib/constants');

let passed = 0, failed = 0;
async function test(name, fn) {
  try { await fn(); passed++; console.log(`  ✓ ${name}`); }
  catch (e) { failed++; console.log(`  ✗ ${name}: ${e.message}`); }
}

async function run() {
  console.log('── SDK StratumClient ──');

  const server = new MockStratumServer();
  const port = await server.start();

  await test('connects and emits ready', async () => {
    const client = new StratumClient({ host: '127.0.0.1', port, wallet: '4test_alice' });
    const ready = new Promise((resolve, reject) => {
      client.on('ready', resolve);
      client.on('error', reject);
      setTimeout(() => reject(new Error('timeout')), 5000);
    });
    client.connect();
    const info = await ready;
    assert.ok(info.minerId, 'should have minerId');
    assert.ok(info.jobId, 'should have jobId');
    assert.strictEqual(client.connected, true);
    client.disconnect();
  });

  await test('sends frame and peer receives it', async () => {
    const alice = new StratumClient({ host: '127.0.0.1', port, wallet: '4test_alice2', ghostIntervalMs: 10 });
    const bob = new StratumClient({ host: '127.0.0.1', port, wallet: '4test_bob2', ghostIntervalMs: 10 });

    const aliceReady = new Promise(r => alice.on('ready', r));
    const bobReady = new Promise(r => bob.on('ready', r));
    alice.connect();
    bob.connect();
    await aliceReady;
    await bobReady;

    const frameReceived = new Promise((resolve, reject) => {
      bob.on('frame', resolve);
      setTimeout(() => reject(new Error('frame timeout')), 10000);
    });

    const frame = buildVS3Frame(Buffer.from('hello'), MSG_TYPE.TEXT);
    await alice.sendFrame(frame, '4test_bob2');

    const received = await frameReceived;
    assert.strictEqual(received.type, MSG_TYPE.TEXT);
    assert.strictEqual(received.payload.toString('utf8'), 'hello');

    alice.disconnect();
    bob.disconnect();
  });

  server.stop();
  console.log(`\n── Results: ${passed} passed, ${failed} failed ──\n`);
  if (failed > 0) process.exit(1);
}

run().catch(e => { console.error(e); process.exit(1); });
