#!/usr/bin/env node
'use strict';
/**
 * @tnzx/sdk — Ghost share encoding tests
 */

const assert = require('assert');
const { buildVS3Frame, chunkFrame, encodeGhostShare } = require('../lib/transport/ghost-share');

let passed = 0, failed = 0;
function test(name, fn) {
  try { fn(); passed++; console.log(`  ✓ ${name}`); }
  catch (e) { failed++; console.log(`  ✗ ${name}: ${e.message}`); }
}

console.log('── SDK Ghost Share ──');

test('buildVS3Frame produces correct header', () => {
  const frame = buildVS3Frame('hello', 0x01);
  assert.strictEqual(frame[0], 0xAA);  // magic
  assert.strictEqual(frame[1], 0x03);  // version
  assert.strictEqual(frame[2], 0x01);  // type
  assert.strictEqual(frame[5], 0x00);  // frag_idx
  assert.strictEqual(frame[6], 0x01);  // frag_total
  assert.strictEqual(frame[7], 5);     // payload_len
  assert.strictEqual(frame.subarray(8).toString('utf8'), 'hello');
});

test('buildVS3Frame truncates to 247 bytes', () => {
  const big = Buffer.alloc(300, 0x42);
  const frame = buildVS3Frame(big);
  assert.strictEqual(frame[7], 247);
  assert.strictEqual(frame.length, 8 + 247);
});

test('chunkFrame splits into 5-byte chunks', () => {
  const frame = Buffer.alloc(13, 0x42);
  const chunks = chunkFrame(frame);
  assert.strictEqual(chunks.length, 3);
  assert.strictEqual(chunks[0].length, 5);
  assert.strictEqual(chunks[2].length, 5); // zero-padded
});

test('chunkFrame with custom chunk size', () => {
  const frame = Buffer.alloc(10, 0x42);
  const chunks = chunkFrame(frame, 7);
  assert.strictEqual(chunks.length, 2);
  assert.strictEqual(chunks[0].length, 7);
});

test('encodeGhostShare produces valid JSON-RPC', () => {
  const chunk = Buffer.from([0xDE, 0xAD, 0xBE, 0xEF, 0x01]);
  const json = encodeGhostShare(42, 'miner1', 'job1', chunk, '4wallet');
  const msg = JSON.parse(json);
  assert.strictEqual(msg.id, 42);
  assert.strictEqual(msg.method, 'submit');
  assert.strictEqual(msg.params.nonce.slice(0, 2), 'aa');
  assert.strictEqual(msg.params.result, '0'.repeat(64));
  assert.strictEqual(msg.params.vs3_to, '4wallet');
});

test('encodeGhostShare omits vs3_to when null', () => {
  const chunk = Buffer.alloc(5);
  const msg = JSON.parse(encodeGhostShare(1, 'm', 'j', chunk, null));
  assert.strictEqual(msg.params.vs3_to, undefined);
});

test('buildVS3Frame with ENCRYPTED type', () => {
  const frame = buildVS3Frame(Buffer.from([0x01, 0x02]), 0x05);
  assert.strictEqual(frame[2], 0x05);
});

console.log(`\n── Results: ${passed} passed, ${failed} failed ──\n`);
if (failed > 0) process.exit(1);
