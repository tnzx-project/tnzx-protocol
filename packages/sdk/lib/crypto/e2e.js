'use strict';
/**
 * @tnzx/sdk — E2E encryption (reference-impl wire format)
 *
 * One-shot PFS encryption: each message generates a fresh ephemeral X25519
 * keypair. The wire format includes a replay ID for duplicate detection.
 *
 * Wire format:
 *   replayId(16) || ephPub(32) || salt(32) || nonce(24) || ciphertext || tag(16)
 *   Overhead: 120 bytes
 *
 * This is the canonical format from tnzx-protocol/reference-impl/crypto.
 * It is NOT compatible with pool-demo's lib/e2e.js (which omits replayId
 * and uses a different AAD string).
 *
 * @license LGPL-2.1
 */

const crypto = require('crypto');
const xchacha = require('./xchacha20');
const { generateKeyPair, ecdh, deriveKey } = require('./keys');
const {
  REPLAY_ID_LEN, EPH_PUB_LEN, SALT_LEN, NONCE_LEN, TAG_LEN,
  ENCRYPT_OVERHEAD, AAD_PREFIX,
} = require('../constants');

/**
 * Encrypt a message with one-shot PFS.
 * Generates a fresh ephemeral keypair per call.
 *
 * @param {Buffer|string} plaintext - Message to encrypt
 * @param {Buffer} recipientPub - Recipient's 32-byte X25519 public key
 * @returns {Buffer} Wire-format packet (120 + plaintext.length bytes)
 */
function encryptOneShot(plaintext, recipientPub) {
  const ptBuf = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext, 'utf8');
  const ephemeral = generateKeyPair();
  const shared = ecdh(ephemeral.privateKey, recipientPub);
  const { key, salt } = deriveKey(shared);

  const replayId = crypto.randomBytes(REPLAY_ID_LEN);
  const nonce = crypto.randomBytes(NONCE_LEN);
  const aad = Buffer.concat([
    Buffer.from(AAD_PREFIX, 'utf8'),
    replayId,
    ephemeral.publicKey,
  ]);

  try {
    const { ciphertext, tag } = xchacha.encrypt(key, nonce, ptBuf, aad);
    return Buffer.concat([replayId, ephemeral.publicKey, salt, nonce, ciphertext, tag]);
  } finally {
    key.fill(0);
  }
}

/**
 * Decrypt a one-shot PFS message.
 *
 * @param {Buffer} packet - Wire-format packet from encryptOneShot
 * @param {Buffer} myPrivateKey - Recipient's 32-byte X25519 private key
 * @param {Set<string>} [replayCache] - Optional set of seen replayId hex strings
 * @returns {Buffer} Decrypted plaintext
 * @throws {Error} On auth failure, replay, or malformed packet
 */
function decryptOneShot(packet, myPrivateKey, replayCache) {
  if (packet.length < ENCRYPT_OVERHEAD) {
    throw new Error('Packet too short');
  }

  let off = 0;
  const replayId  = packet.subarray(off, off + REPLAY_ID_LEN);  off += REPLAY_ID_LEN;
  const ephPub    = packet.subarray(off, off + EPH_PUB_LEN);    off += EPH_PUB_LEN;
  const salt      = packet.subarray(off, off + SALT_LEN);       off += SALT_LEN;
  const nonce     = packet.subarray(off, off + NONCE_LEN);      off += NONCE_LEN;
  const ciphertext = packet.subarray(off, packet.length - TAG_LEN);
  const tag       = packet.subarray(packet.length - TAG_LEN);

  // Replay detection
  if (replayCache) {
    const hex = replayId.toString('hex');
    if (replayCache.has(hex)) throw new Error('Replay attack detected');
    replayCache.add(hex);
  }

  const shared = ecdh(myPrivateKey, ephPub);
  const { key } = deriveKey(shared, salt);
  const aad = Buffer.concat([
    Buffer.from(AAD_PREFIX, 'utf8'),
    replayId,
    ephPub,
  ]);

  try {
    return xchacha.decrypt(key, nonce, ciphertext, tag, aad);
  } catch (err) {
    throw new Error(`Decryption failed: ${err.message}`);
  } finally {
    key.fill(0);
  }
}

module.exports = { encryptOneShot, decryptOneShot, generateKeyPair };
