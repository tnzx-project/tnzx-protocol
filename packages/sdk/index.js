'use strict';
/**
 * @tnzx/sdk — Build apps on the TNZX protocol
 *
 * Censorship-resistant messaging over cryptocurrency mining channels.
 * Zero external dependencies. Node.js >= 18.
 *
 * Quick start:
 *   const { VS3Client } = require('@tnzx/sdk');
 *   const client = new VS3Client({ pool: 'host:3333', wallet: '4...' });
 *   client.on('message', ({ text }) => console.log(text));
 *   client.on('peer', ({ wallet }) => client.send(wallet, 'Hello'));
 *   client.connect();
 *
 * @license LGPL-2.1
 */

const VS3Client     = require('./lib/vs3-client');
const StratumClient = require('./lib/transport/stratum-client');
const { encryptOneShot, decryptOneShot, generateKeyPair } = require('./lib/crypto/e2e');
const { buildVS3Frame, chunkFrame, encodeGhostShare } = require('./lib/transport/ghost-share');
const { hmacDeriveSessionKey, hmacSentinel, hmacVerify } = require('./lib/transport/hmac-sentinel');
const { MSG_TYPE, MAGIC, VERSION_V3, ENCRYPT_OVERHEAD } = require('./lib/constants');

module.exports = {
  // High-level (Tier 1)
  VS3Client,

  // Transport (Tier 2 — advanced)
  StratumClient,

  // Crypto (Tier 2 — advanced)
  encryptOneShot,
  decryptOneShot,
  generateKeyPair,

  // Frame utilities (Tier 2 — advanced)
  buildVS3Frame,
  chunkFrame,
  encodeGhostShare,

  // HMAC sentinel (Tier 2 — pool integration)
  hmacDeriveSessionKey,
  hmacSentinel,
  hmacVerify,

  // Constants
  MSG_TYPE,
  MAGIC,
  VERSION_V3,
  ENCRYPT_OVERHEAD,
};
