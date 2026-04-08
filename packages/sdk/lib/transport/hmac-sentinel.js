'use strict';
/**
 * @tnzx/sdk — HMAC sentinel for ghost share detection
 *
 * Instead of the trivially-detectable 0xAA sentinel in nonce[0], HMAC mode
 * sets nonce[0] = HMAC-SHA256(sessionKey, nonce[1..3])[0]. This makes ghost
 * shares statistically indistinguishable from real shares to a DPI observer.
 *
 * The session key is derived via HKDF from a per-connection token provided
 * by the proxy in the login response (extensions.vs3_session).
 *
 * Extracted from tnzx-pool-demo/poc/vs3-proxy.js lines 47-70.
 *
 * @license LGPL-2.1
 */

const crypto = require('crypto');
const { HMAC_INFO, KEY_LEN } = require('../constants');

/**
 * Derive HMAC session key from proxy-provided token + wallet.
 * @param {Buffer|string} sessionToken - 32-byte token from login response
 * @param {string} wallet - Miner wallet address
 * @returns {Buffer} 32-byte HMAC session key
 */
function hmacDeriveSessionKey(sessionToken, wallet) {
  const ikm  = Buffer.isBuffer(sessionToken) ? sessionToken : Buffer.from(sessionToken, 'hex');
  const salt = Buffer.from(wallet, 'utf8');
  const info = Buffer.from(HMAC_INFO, 'utf8');
  return Buffer.from(crypto.hkdfSync('sha256', ikm, salt, info, KEY_LEN));
}

/**
 * Compute HMAC sentinel byte for nonce[0].
 * @param {Buffer} sessionKey - 32-byte session key
 * @param {Buffer} nonceData - nonce[1..3] (the 3 payload bytes)
 * @returns {number} Single byte (0-255)
 */
function hmacSentinel(sessionKey, nonceData) {
  return crypto.createHmac('sha256', sessionKey).update(nonceData).digest()[0];
}

/**
 * Verify HMAC sentinel on a received nonce.
 * @param {Buffer} sessionKey - 32-byte session key
 * @param {Buffer} nonceBuf - 4-byte nonce buffer
 * @returns {boolean} True if nonce[0] matches HMAC(nonce[1..3])
 */
function hmacVerify(sessionKey, nonceBuf) {
  if (!nonceBuf || nonceBuf.length < 4) return false;
  const expected = hmacSentinel(sessionKey, nonceBuf.subarray(1, 4));
  return crypto.timingSafeEqual(Buffer.from([nonceBuf[0]]), Buffer.from([expected]));
}

module.exports = { hmacDeriveSessionKey, hmacSentinel, hmacVerify };
