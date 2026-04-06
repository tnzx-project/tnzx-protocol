/**
 * Visual Stratum — E2E Encryption Module (Reference Implementation)
 *
 * Standalone implementation of the VS cryptographic layer:
 * - X25519 ECDH key exchange
 * - AES-256-GCM authenticated encryption
 * - HKDF-SHA256 key derivation
 * - Ed25519 → X25519 key conversion (wallet-based identity)
 * - Perfect forward secrecy via ephemeral keys
 * - Replay protection via nonce tracking
 *
 * Dependencies: Node.js crypto module only (no external packages)
 *
 * @version 2.0.0
 * @license LGPL-2.1
 */
'use strict';

const crypto = require('crypto');

// Constants
const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32;
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const SALT_LENGTH = 32;
const NONCE_LENGTH = 16;
const MAX_NONCE_AGE_MS = 300000; // 5-minute replay window

// Field prime p = 2^255 - 19 (Curve25519)
const FIELD_PRIME = BigInt('0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed');

/**
 * E2E Crypto — Key exchange and message encryption
 */
class E2ECrypto {
  constructor() {
    this.sessionKeys = new Map();
    this.keyPair = null;
    this.seenNonces = new Map();
  }

  /**
   * Generate X25519 keypair
   * @returns {{ publicKey: Buffer, privateKey: Buffer }}
   */
  generateKeyPair() {
    const kp = crypto.generateKeyPairSync('x25519', {
      publicKeyEncoding: { type: 'spki', format: 'der' },
      privateKeyEncoding: { type: 'pkcs8', format: 'der' }
    });
    const publicKey = kp.publicKey.slice(-32);
    const privateKey = kp.privateKey.slice(-32);
    this.keyPair = { publicKey, privateKey, raw: kp };
    return { publicKey, privateKey };
  }

  /**
   * Get public key (generates if needed)
   * @returns {Buffer} 32-byte X25519 public key
   */
  getPublicKey() {
    if (!this.keyPair) this.generateKeyPair();
    return this.keyPair.publicKey;
  }

  /**
   * Convert Ed25519 public key to X25519
   * Birational map: u = (1 + y) / (1 - y) mod p
   * @param {Buffer} ed25519PubKey - 32-byte Ed25519 public key
   * @returns {Buffer} 32-byte X25519 public key
   */
  ed25519ToX25519(ed25519PubKey) {
    if (ed25519PubKey.length !== 32) {
      throw new Error('Invalid Ed25519 public key length');
    }
    const yBytes = Buffer.from(ed25519PubKey);
    yBytes[31] &= 0x7F; // Clear sign bit

    const y = bufferToBigIntLE(yBytes);
    const one = BigInt(1);
    const num = ((one + y) % FIELD_PRIME + FIELD_PRIME) % FIELD_PRIME;
    const den = ((one - y) % FIELD_PRIME + FIELD_PRIME) % FIELD_PRIME;
    const denInv = modInverse(den, FIELD_PRIME);
    if (denInv === null) throw new Error('Degenerate point');
    const u = (num * denInv) % FIELD_PRIME;

    return bigIntToBufferLE(u, 32);
  }

  /**
   * X25519 Diffie-Hellman
   * @param {Buffer} theirPublicKey - 32-byte public key
   * @returns {Buffer} 32-byte shared secret
   */
  computeSharedSecret(theirPublicKey) {
    if (!this.keyPair) this.generateKeyPair();

    const privateKeyObj = crypto.createPrivateKey({
      key: Buffer.concat([
        Buffer.from('302e020100300506032b656e04220420', 'hex'),
        this.keyPair.privateKey
      ]),
      format: 'der', type: 'pkcs8'
    });

    const publicKeyObj = crypto.createPublicKey({
      key: Buffer.concat([
        Buffer.from('302a300506032b656e032100', 'hex'),
        theirPublicKey
      ]),
      format: 'der', type: 'spki'
    });

    return crypto.diffieHellman({ privateKey: privateKeyObj, publicKey: publicKeyObj });
  }

  /**
   * Derive encryption key via HKDF-SHA256
   * @param {Buffer} sharedSecret
   * @param {Buffer|null} salt - Random salt (generated if null)
   * @param {string} info - Context string
   * @returns {{ key: Buffer, salt: Buffer }}
   */
  deriveKey(sharedSecret, salt = null, info = 'tnzx-stego-e2e-v2') {
    if (!salt) salt = crypto.randomBytes(SALT_LENGTH);
    const key = Buffer.from(crypto.hkdfSync('sha256', sharedSecret, salt, info, KEY_LENGTH));
    return { key, salt };
  }

  /**
   * Establish session with recipient
   * @param {string} recipientId - Wallet address or identifier
   * @param {Buffer} recipientPublicKey - Their X25519 public key
   * @returns {Object} Session info
   */
  establishSession(recipientId, recipientPublicKey) {
    const sharedSecret = this.computeSharedSecret(recipientPublicKey);
    const session = {
      recipientId,
      recipientPublicKey,
      sharedSecret,
      established: Date.now(),
      messageCount: 0
    };
    this.sessionKeys.set(recipientId, session);
    return session;
  }

  /**
   * Encrypt message for recipient
   * @param {Buffer|string} plaintext
   * @param {string} recipientId
   * @returns {Buffer} nonce(16) + salt(32) + iv(12) + ciphertext + tag(16)
   */
  encrypt(plaintext, recipientId) {
    const session = this.sessionKeys.get(recipientId);
    if (!session) throw new Error(`No session with ${recipientId}`);

    const ptBuf = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext, 'utf8');
    const nonce = crypto.randomBytes(NONCE_LENGTH);
    const salt = crypto.randomBytes(SALT_LENGTH);
    const { key } = this.deriveKey(session.sharedSecret, salt);
    const iv = crypto.randomBytes(IV_LENGTH);

    const cipher = crypto.createCipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
    const aad = Buffer.concat([Buffer.from('tnzx-e2e-v2', 'utf8'), nonce]);
    cipher.setAAD(aad);

    const ciphertext = Buffer.concat([cipher.update(ptBuf), cipher.final()]);
    const tag = cipher.getAuthTag();
    session.messageCount++;

    return Buffer.concat([nonce, salt, iv, ciphertext, tag]);
  }

  /**
   * Decrypt message from sender
   * @param {Buffer} encryptedData
   * @param {string} senderId
   * @returns {Buffer} Decrypted plaintext
   */
  decrypt(encryptedData, senderId) {
    const minLen = NONCE_LENGTH + SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH;
    if (encryptedData.length < minLen) throw new Error('Data too short');

    const session = this.sessionKeys.get(senderId);
    if (!session) throw new Error(`No session with ${senderId}`);

    let off = 0;
    const nonce = encryptedData.slice(off, off + NONCE_LENGTH); off += NONCE_LENGTH;
    const salt = encryptedData.slice(off, off + SALT_LENGTH); off += SALT_LENGTH;
    const iv = encryptedData.slice(off, off + IV_LENGTH); off += IV_LENGTH;
    const tag = encryptedData.slice(-AUTH_TAG_LENGTH);
    const ciphertext = encryptedData.slice(off, -AUTH_TAG_LENGTH);

    if (!this._checkNonce(nonce)) throw new Error('Replay attack detected');

    const { key } = this.deriveKey(session.sharedSecret, salt);
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
    decipher.setAuthTag(tag);
    decipher.setAAD(Buffer.concat([Buffer.from('tnzx-e2e-v2', 'utf8'), nonce]));

    try {
      return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    } catch (err) {
      throw new Error(`Decryption failed: ${err.message}`);
    }
  }

  hasSession(id) { return this.sessionKeys.has(id); }

  _checkNonce(nonce) {
    const hex = nonce.toString('hex');
    const now = Date.now();
    // Cleanup expired
    for (const [k, t] of this.seenNonces) {
      if (now - t > MAX_NONCE_AGE_MS) this.seenNonces.delete(k);
    }
    if (this.seenNonces.has(hex)) return false;
    this.seenNonces.set(hex, now);
    return true;
  }
}

/**
 * One-shot encryption (no pre-established session, PFS via ephemeral key)
 * @param {Buffer|string} plaintext
 * @param {Buffer} recipientPublicKey - 32-byte X25519 public key
 * @returns {Buffer} nonce(16) + ephemeralPub(32) + salt(32) + iv(12) + ciphertext + tag(16)
 */
function encryptOneShot(plaintext, recipientPublicKey) {
  const e2e = new E2ECrypto();
  const ephemeral = e2e.generateKeyPair();
  const shared = e2e.computeSharedSecret(recipientPublicKey);
  const { key, salt } = e2e.deriveKey(shared);

  const ptBuf = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext, 'utf8');
  const nonce = crypto.randomBytes(NONCE_LENGTH);
  const iv = crypto.randomBytes(IV_LENGTH);

  const cipher = crypto.createCipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
  const aad = Buffer.concat([Buffer.from('tnzx-oneshot-v2', 'utf8'), nonce, ephemeral.publicKey]);
  cipher.setAAD(aad);

  const ciphertext = Buffer.concat([cipher.update(ptBuf), cipher.final()]);
  const tag = cipher.getAuthTag();

  return Buffer.concat([nonce, ephemeral.publicKey, salt, iv, ciphertext, tag]);
}

/**
 * Shared nonce tracker for one-shot decryption replay protection.
 * Module-level singleton — persists across calls within the same process.
 */
const _oneShotSeenNonces = new Map();

function _checkOneShotNonce(nonce) {
  const hex = nonce.toString('hex');
  const now = Date.now();
  // Cleanup expired entries
  for (const [k, t] of _oneShotSeenNonces) {
    if (now - t > MAX_NONCE_AGE_MS) _oneShotSeenNonces.delete(k);
  }
  if (_oneShotSeenNonces.has(hex)) return false;
  _oneShotSeenNonces.set(hex, now);
  return true;
}

/**
 * One-shot decryption
 * @param {Buffer} encryptedData
 * @param {Buffer} privateKey - Recipient's X25519 private key
 * @returns {Buffer} Decrypted plaintext
 */
function decryptOneShot(encryptedData, privateKey) {
  const minLen = NONCE_LENGTH + 32 + SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH;
  if (encryptedData.length < minLen) throw new Error('Data too short');

  let off = 0;
  const nonce = encryptedData.slice(off, off + NONCE_LENGTH); off += NONCE_LENGTH;
  const ephPub = encryptedData.slice(off, off + 32); off += 32;
  const salt = encryptedData.slice(off, off + SALT_LENGTH); off += SALT_LENGTH;
  const iv = encryptedData.slice(off, off + IV_LENGTH); off += IV_LENGTH;
  const tag = encryptedData.slice(-AUTH_TAG_LENGTH);
  const ciphertext = encryptedData.slice(off, -AUTH_TAG_LENGTH);

  if (!_checkOneShotNonce(nonce)) throw new Error('Replay attack detected (one-shot)');

  const e2e = new E2ECrypto();
  e2e.keyPair = { privateKey, publicKey: null };
  const shared = e2e.computeSharedSecret(ephPub);
  const { key } = e2e.deriveKey(shared, salt);

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
  decipher.setAuthTag(tag);
  decipher.setAAD(Buffer.concat([Buffer.from('tnzx-oneshot-v2', 'utf8'), nonce, ephPub]));

  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

// --- BigInt helpers for Ed25519→X25519 ---
function bufferToBigIntLE(buf) {
  let r = BigInt(0);
  for (let i = buf.length - 1; i >= 0; i--) r = (r << BigInt(8)) | BigInt(buf[i]);
  return r;
}
function bigIntToBufferLE(n, len) {
  const buf = Buffer.alloc(len);
  let t = n;
  for (let i = 0; i < len; i++) { buf[i] = Number(t & BigInt(0xFF)); t >>= BigInt(8); }
  return buf;
}
function modInverse(a, p) {
  a = ((a % p) + p) % p;
  if (a === BigInt(0)) return null;
  let [old_r, r] = [a, p], [old_s, s] = [BigInt(1), BigInt(0)];
  while (r !== BigInt(0)) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  if (old_r !== BigInt(1)) return null;
  return ((old_s % p) + p) % p;
}

module.exports = {
  E2ECrypto,
  encryptOneShot,
  decryptOneShot,
  ALGORITHM, KEY_LENGTH, IV_LENGTH, AUTH_TAG_LENGTH, SALT_LENGTH, NONCE_LENGTH, MAX_NONCE_AGE_MS
};
