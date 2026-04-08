'use strict';
/**
 * @tnzx/sdk — Protocol constants
 *
 * Single source of truth for all magic numbers, type enums, HKDF domain
 * strings, and wire format sizes used across the SDK.
 *
 * @license LGPL-2.1
 */

// VS3 frame header
const MAGIC = 0xAA;
const VERSION_V3 = 0x03;
const HEADER_LEN = 8;
const MAX_PAYLOAD = 247;        // 255 - HEADER_LEN
const MAX_FRAGMENT_SIZE = 128;

// Message types (VS3 spec, 8-bit enum)
// 0x01-0x06 are protocol-reserved. 0x07-0xFF available for applications.
const MSG_TYPE = {
  TEXT:          0x01,
  ACK:           0x02,
  PING:          0x03,
  KEY_EXCHANGE:  0x04,
  ENCRYPTED:     0x05,
  HASHCASH:      0x06,
};

// Crypto wire format sizes (reference-impl canonical)
const REPLAY_ID_LEN = 16;
const EPH_PUB_LEN   = 32;
const SALT_LEN       = 32;
const NONCE_LEN      = 24;
const TAG_LEN        = 16;
const KEY_LEN        = 32;

// Total encryption overhead: replayId + ephPub + salt + nonce + tag
const ENCRYPT_OVERHEAD = REPLAY_ID_LEN + EPH_PUB_LEN + SALT_LEN + NONCE_LEN + TAG_LEN; // 120

// HKDF domain strings — must match reference-impl exactly
const HKDF_INFO     = 'tnzx-e2e-v3';
const AAD_PREFIX    = 'tnzx-oneshot-v3';
const HMAC_INFO     = 'tnzx-ghost-v1';

// Ghost share encoding
const BYTES_PER_SHARE_V3 = 5;  // nonce[1..3] + ntime[2..3]
const ZERO_RESULT = '0'.repeat(64);
const DEFAULT_GHOST_INTERVAL_MS = 150;

module.exports = {
  MAGIC, VERSION_V3, HEADER_LEN, MAX_PAYLOAD, MAX_FRAGMENT_SIZE,
  MSG_TYPE,
  REPLAY_ID_LEN, EPH_PUB_LEN, SALT_LEN, NONCE_LEN, TAG_LEN, KEY_LEN,
  ENCRYPT_OVERHEAD,
  HKDF_INFO, AAD_PREFIX, HMAC_INFO,
  BYTES_PER_SHARE_V3, ZERO_RESULT, DEFAULT_GHOST_INTERVAL_MS,
};
