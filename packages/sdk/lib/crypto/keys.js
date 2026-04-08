'use strict';
/**
 * @tnzx/sdk — X25519 key management
 *
 * Key generation, ECDH shared secret, and HKDF key derivation.
 * Extracted from pool-demo lib/e2e.js, adapted to use canonical
 * HKDF info string from the reference-impl specification.
 *
 * @license LGPL-2.1
 */

const crypto = require('crypto');
const { KEY_LEN, SALT_LEN, HKDF_INFO } = require('../constants');

// DER prefixes for wrapping raw 32-byte X25519 keys into PKCS8/SPKI
// so that Node.js crypto.diffieHellman() can consume them.
const PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');
const SPKI_PREFIX  = Buffer.from('302a300506032b656e032100', 'hex');

/**
 * Generate an X25519 keypair.
 * @returns {{ publicKey: Buffer, privateKey: Buffer }} 32-byte raw keys
 */
function generateKeyPair() {
  const kp = crypto.generateKeyPairSync('x25519', {
    publicKeyEncoding:  { type: 'spki',  format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });
  return {
    publicKey:  kp.publicKey.subarray(-32),
    privateKey: kp.privateKey.subarray(-32),
  };
}

/**
 * X25519 Diffie-Hellman shared secret.
 * @param {Buffer} myPrivate - 32-byte private key
 * @param {Buffer} theirPublic - 32-byte public key
 * @returns {Buffer} 32-byte shared secret
 */
function ecdh(myPrivate, theirPublic) {
  const privateKeyObj = crypto.createPrivateKey({
    key: Buffer.concat([PKCS8_PREFIX, myPrivate]),
    format: 'der', type: 'pkcs8',
  });
  const publicKeyObj = crypto.createPublicKey({
    key: Buffer.concat([SPKI_PREFIX, theirPublic]),
    format: 'der', type: 'spki',
  });
  return crypto.diffieHellman({ privateKey: privateKeyObj, publicKey: publicKeyObj });
}

/**
 * Derive encryption key via HKDF-SHA256.
 * @param {Buffer} shared - Shared secret from ECDH
 * @param {Buffer} [salt] - Random salt (generated if omitted)
 * @param {string} [info] - HKDF info string (default: canonical 'tnzx-e2e-v3')
 * @returns {{ key: Buffer, salt: Buffer }}
 */
function deriveKey(shared, salt, info) {
  if (!salt) salt = crypto.randomBytes(SALT_LEN);
  if (!info) info = HKDF_INFO;
  const key = Buffer.from(crypto.hkdfSync('sha256', shared, salt, info, KEY_LEN));
  return { key, salt };
}

module.exports = { generateKeyPair, ecdh, deriveKey };
