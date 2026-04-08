#!/usr/bin/env node
'use strict';
/**
 * example: E2E encrypted chat using @tnzx/sdk
 *
 * This is the "10-line developer experience" — a complete encrypted
 * chat app built entirely on the SDK's public API.
 *
 * Usage:
 *   node chat.js <myWallet> <peerWallet> [host:port]
 *
 * Example (3 terminals):
 *   Terminal 1: node ../../../tnzx-pool-demo/src/stratum-demo.js
 *   Terminal 2: node chat.js 4alice 4bob 127.0.0.1:4444
 *   Terminal 3: node chat.js 4bob 4alice 127.0.0.1:4444
 */

const readline = require('readline');
const { VS3Client } = require('..');

const myWallet   = process.argv[2];
const peerWallet = process.argv[3];
const pool       = process.argv[4] || '127.0.0.1:4444';

if (!myWallet || !peerWallet) {
  console.error('Usage: node chat.js <myWallet> <peerWallet> [host:port]');
  process.exit(1);
}

// ── That's it. This is the entire app. ──────────────────────────────────────

const client = new VS3Client({ pool, wallet: myWallet });

client.on('ready', () => {
  console.log(`Connected to ${pool} as ${myWallet.slice(0, 12)}...`);
  console.log(`Peer: ${peerWallet.slice(0, 12)}...`);
  console.log('Initiating key exchange...\n');
  // Trigger key exchange by queueing a greeting
  client.send(peerWallet, '[connected]');
});

client.on('peer', ({ publicKey }) => {
  console.log(`Key exchange complete. Cipher: XChaCha20-Poly1305 (PFS)`);
  console.log(`Peer key: ${publicKey.toString('hex').slice(0, 16)}...`);
  console.log('Type a message and press Enter.\n');
  startChat();
});

client.on('message', ({ text }) => {
  const ts = new Date().toISOString().slice(11, 19);
  if (rl) {
    readline.clearLine(process.stdout, 0);
    readline.cursorTo(process.stdout, 0);
  }
  console.log(`  ${ts} [peer] ${text}`);
  if (rl) rl.prompt(true);
});

client.on('error', (e) => console.error(`[error] ${e.message}`));
client.on('close', () => { console.log('Disconnected.'); process.exit(0); });

client.connect();

// ── Interactive readline ────────────────────────────────────────────────────

let rl = null;
function startChat() {
  rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  rl.setPrompt('  [you] ');
  rl.prompt();
  rl.on('line', (input) => {
    const text = input.trim();
    if (text) client.send(peerWallet, text);
    rl.prompt();
  });
  rl.on('close', () => client.disconnect());
}
