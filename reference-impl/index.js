/**
 * Visual Stratum Protocol — Reference Implementation
 *
 * @license LGPL-2.1
 *
 * @example
 * const vs = require('visual-stratum-reference');
 *
 * // Steganographic encoding
 * const encoder = new vs.StegoEncoder();
 * const { frames } = encoder.createMessageFrames('Hello VS3');
 *
 * // E2E encryption
 * const alice = new vs.E2ECrypto();
 * const bob = new vs.E2ECrypto();
 * alice.generateKeyPair();
 * bob.generateKeyPair();
 * alice.establishSession('bob', bob.getPublicKey());
 * const encrypted = alice.encrypt('Secret message', 'bob');
 *
 * // Mining Gate
 * const gate = new vs.MiningGate();
 * gate.recordShare('4wallet...', 10000);
 * console.log(gate.isOpen('4wallet...')); // true after 3 shares
 */
'use strict';

const { StegoEncoder, StegoDecoder, MSG_TYPE, MAGIC_BYTE, HEADER_SIZE,
        VERSION_V1, VERSION_V2, VERSION_V3, isValidHex, safeHexToBuffer,
        wrapTypedPayload, unwrapTypedPayload
      } = require('./stego-core');

const { E2ECrypto, encryptOneShot, decryptOneShot,
        KEY_LENGTH, AUTH_TAG_LENGTH, SALT_LENGTH, NONCE_LENGTH
      } = require('./crypto');

const { MiningGate, MinerState, ACCESS_LEVEL, DEFAULT_CONFIG } = require('./mining-gate');

module.exports = {
  // Steganography
  StegoEncoder, StegoDecoder, MSG_TYPE, MAGIC_BYTE, HEADER_SIZE,
  VERSION_V1, VERSION_V2, VERSION_V3, isValidHex, safeHexToBuffer,
  wrapTypedPayload, unwrapTypedPayload,

  // Cryptography
  E2ECrypto, encryptOneShot, decryptOneShot,
  KEY_LENGTH, AUTH_TAG_LENGTH, SALT_LENGTH, NONCE_LENGTH,

  // Mining Gate
  MiningGate, MinerState, ACCESS_LEVEL, DEFAULT_CONFIG
};
