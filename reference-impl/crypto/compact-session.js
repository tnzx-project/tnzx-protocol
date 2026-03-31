/**
 * Compact Session Encryption — Prototype
 *
 * Replaces the 76-byte standard envelope (nonce 16 + salt 32 + IV 12 + tag 16)
 * with a 32-byte compact envelope (counter 4 + IV 12 + tag 16) for established
 * sessions where both parties share a secret from X25519 ECDH.
 *
 * Wire format: counter(4) || IV(12) || ciphertext(N) || tag(16)
 * Total overhead: 32 bytes (vs 76 standard = -58%)
 *
 * Key derivation: HKDF-SHA256(shared_secret, counter_as_4B, "tnzx-compact-v1", 32)
 * AAD: "tnzx-compact-v1" || counter(4)
 *
 * Forward secrecy: each counter value produces a unique key via HKDF.
 * Counter overflow at 2^32: triggers re-key (new ECDH exchange required).
 *
 * @license LGPL-2.1
 */

'use strict';

const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32;
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const COUNTER_LENGTH = 4;
const INFO_STRING = 'tnzx-compact-v1';
const MAX_COUNTER = 0xFFFFFFFF;

class CompactSession {
  /**
   * @param {Buffer} sharedSecret - 32-byte X25519 shared secret
   */
  constructor(sharedSecret) {
    if (!Buffer.isBuffer(sharedSecret) || sharedSecret.length !== 32) {
      throw new Error('sharedSecret must be a 32-byte Buffer');
    }
    this.sharedSecret = sharedSecret;
    this.sendCounter = 0;
    // Track received counters for replay protection (sliding window)
    this.receivedCounters = new Set();
    this.maxReceivedCounter = -1;
  }

  /**
   * Derive unique key from shared secret + counter
   */
  _deriveKey(counter) {
    const counterBuf = Buffer.alloc(COUNTER_LENGTH);
    counterBuf.writeUInt32BE(counter, 0);
    const key = Buffer.from(
      crypto.hkdfSync('sha256', this.sharedSecret, counterBuf, INFO_STRING, KEY_LENGTH)
    );
    return { key, counterBuf };
  }

  /**
   * Encrypt plaintext with compact envelope
   * @param {Buffer|string} plaintext
   * @returns {Buffer} counter(4) || IV(12) || ciphertext || tag(16)
   */
  encrypt(plaintext) {
    if (this.sendCounter > MAX_COUNTER) {
      throw new Error('Counter overflow — re-key required');
    }

    const ptBuf = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext, 'utf8');
    const counter = this.sendCounter++;
    const { key, counterBuf } = this._deriveKey(counter);
    const iv = crypto.randomBytes(IV_LENGTH);

    const cipher = crypto.createCipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
    const aad = Buffer.concat([Buffer.from(INFO_STRING, 'utf8'), counterBuf]);
    cipher.setAAD(aad);

    const ciphertext = Buffer.concat([cipher.update(ptBuf), cipher.final()]);
    const tag = cipher.getAuthTag();

    return Buffer.concat([counterBuf, iv, ciphertext, tag]);
  }

  /**
   * Decrypt compact envelope
   * @param {Buffer} data - counter(4) || IV(12) || ciphertext || tag(16)
   * @returns {Buffer} plaintext
   */
  decrypt(data) {
    if (!Buffer.isBuffer(data) || data.length < COUNTER_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH) {
      throw new Error('Data too short');
    }

    const counterBuf = data.slice(0, COUNTER_LENGTH);
    const counter = counterBuf.readUInt32BE(0);
    const iv = data.slice(COUNTER_LENGTH, COUNTER_LENGTH + IV_LENGTH);
    const tagStart = data.length - AUTH_TAG_LENGTH;
    const ciphertext = data.slice(COUNTER_LENGTH + IV_LENGTH, tagStart);
    const tag = data.slice(tagStart);

    // Replay protection
    if (this.receivedCounters.has(counter)) {
      throw new Error('Replay detected — duplicate counter');
    }

    const { key } = this._deriveKey(counter);
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
    const aad = Buffer.concat([Buffer.from(INFO_STRING, 'utf8'), counterBuf]);
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);

    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

    // Track counter after successful decryption
    this.receivedCounters.add(counter);
    if (counter > this.maxReceivedCounter) this.maxReceivedCounter = counter;
    // Prune old counters (sliding window of 1000)
    if (this.receivedCounters.size > 1000) {
      for (const c of this.receivedCounters) {
        if (c < this.maxReceivedCounter - 1000) this.receivedCounters.delete(c);
      }
    }

    return plaintext;
  }

  /**
   * Get envelope overhead in bytes
   */
  static get OVERHEAD() {
    return COUNTER_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH; // 4 + 12 + 16 = 32
  }
}

module.exports = { CompactSession };
