/**
 * Visual Stratum — Steganographic Encoder/Decoder (Reference Implementation)
 *
 * DESIGN PRINCIPLE
 * ----------------
 * Visual Stratum embeds payload bytes in Stratum share fields by having the
 * miner constrain specific bits/bytes to carry payload values, then searching
 * for a valid PoW solution within the remaining degrees of freedom.
 * A VS-aware pool extracts the payload; a non-VS pool sees a structurally
 * normal share and processes it as usual.
 *
 * Three profiles, three carrier combinations:
 *
 *   V1 — Generic Stratum (1 byte/share)
 *     Carrier:  nonce LSB — the two least-significant nibbles of the nonce
 *     How:      The miner fixes the low 8 bits of the nonce to the payload
 *               byte and searches for a valid PoW solution by varying the
 *               upper 24 bits. The pool validates the full hash (all 32 bits
 *               of nonce contribute); by restricting 8 bits the search space
 *               is reduced by a factor of 256, which is always feasible.
 *               One payload byte is split across two nibble slots (4 bits each).
 *     Requires: TNZX-enhanced miner (tnzxminer). Standard XMRig does not
 *               constrain nonce bits to payload values.
 *
 *   V2 — Bitcoin-style Stratum (3 bytes/share)
 *     Carrier:  nonce LSB (1B) + extranonce2 last 2 bytes (2B)
 *     How:      extranonce2 is part of the Bitcoin coinbase transaction.
 *               The miner PRESETS the last 2 bytes of extranonce2 to the
 *               desired payload, then mines with that extranonce2 to find
 *               a valid nonce. The pool recomputes the full PoW chain
 *               (coinbase → merkle root → block header → hash) and validates
 *               the result. Modifying extranonce2 after the nonce is found
 *               would invalidate the share. This profile therefore requires
 *               a custom miner that controls extranonce2 layout before mining.
 *               Note: standard Bitcoin miners use extranonce2 as a sequential
 *               counter; preset-extranonce2 mining requires TNZX-enhanced client.
 *
 *   V3 — Monero Stratum / VS3-Monero profile (5 bytes/share)
 *     Carrier:  nonce[1..3] (3B) + ntime[2..3] (2B)
 *     How:      Ghost shares (difficulty ≤ ghostDiffMax) do not require valid
 *               PoW — the TNZX pool accepts them regardless of hash value.
 *               The miner freely sets all 4 nonce bytes: byte [0] = 0xAA
 *               (sentinel for pool detection), bytes [1..3] carry 3 payload
 *               bytes. The `ntime` field does NOT exist in standard Monero
 *               Stratum (mining.submit contains only nonce, job_id, result).
 *               ntime is a TNZX extension field sent by tnzxminer; the pool
 *               falls back to zero bytes if absent. With standard XMRig
 *               (no ntime, no ghost shares): 0 bytes/share via this channel.
 *               With tnzxminer: 5 bytes/share (3 from nonce + 2 from ntime).
 *     Requires: TNZX-aware pool (ghostDiffMax configured) + tnzxminer.
 *
 * VS3 FRAME FORMAT (identical for all profiles — transport-independent)
 * ──────────────────────────────────────────────────────────────────────
 *   Offset  Field            Size  Value / Notes
 *   [0]     MAGIC_BYTE       1     0xAA — frame boundary marker
 *   [1]     version          1     0x03 = VS3
 *   [2]     type             1     MSG_TYPE enum (text, encrypted, ...)
 *   [3-4]   message_id       2     16-bit message ID, big-endian
 *   [5]     fragment_index   1     0-based fragment number
 *   [6]     fragment_total   1     Total fragments (1 = no fragmentation)
 *   [7]     payload_len      1     N: byte length of this fragment's data
 *   [8..8+N] payload         N     Fragment content
 *
 * Dependencies: Node.js crypto module only
 *
 * @version 2.1.0
 * @license LGPL-2.1
 */
'use strict';

const crypto = require('crypto');

// Protocol constants
const MAGIC_BYTE = 0xAA;
const VERSION_V1 = 0x01;
const VERSION_V2 = 0x02;
const VERSION_V3 = 0x03;
const HEADER_SIZE = 8;
const MAX_FRAGMENT_SIZE = 128;

// V3 encoding parameters (Monero Stratum)
const BYTES_PER_SHARE_V3 = 5; // 3 bytes in nonce[1..3] + 2 bytes in ntime[2..3]

// Security limits
// MAX_PENDING_MESSAGES (1000): caps in-flight multi-fragment reassembly state.
//   Prevents a sender flooding incomplete frames from exhausting memory.
// MESSAGE_TIMEOUT_MS (300s): incomplete messages older than 5 minutes are
//   discarded. A 5-minute window is generous even at 1 share/second throughput
//   (300s × 5B/share = 1500B capacity per window — larger than any single frame).
// MAX_COMPLETED_MESSAGES (500): sliding window of decoded messages kept for
//   deduplication and replay detection. Oldest entries are dropped first.
// MAX_TOTAL_FRAGMENTS (50): a single logical message split into more than 50
//   fragments is rejected. At 128 bytes/fragment this caps message size at
//   6400 bytes — adequate for all expected use cases (keys, text, metadata).
const MAX_PENDING_MESSAGES = 1000;
const MESSAGE_TIMEOUT_MS = 300000;
const MAX_COMPLETED_MESSAGES = 500;
const MAX_TOTAL_FRAGMENTS = 50;

const MSG_TYPE = {
  TEXT: 0x01,
  ACK: 0x02,
  PING: 0x03,
  KEY_EXCHANGE: 0x04,
  ENCRYPTED: 0x05,
  HASHCASH: 0x06
};

/**
 * Validate hex string
 */
function isValidHex(hex) {
  if (typeof hex !== 'string') return false;
  if (hex.length === 0 || hex.length % 2 !== 0) return false;
  return /^[0-9a-fA-F]+$/.test(hex);
}

function safeHexToBuffer(hex, field = 'input') {
  if (!isValidHex(hex)) throw new Error(`Invalid hex ${field}`);
  return Buffer.from(hex, 'hex');
}

/**
 * Steganographic Encoder
 *
 * Two-step workflow:
 *   1. createMessageFrames(payload) — splits payload into VS3 frames, each
 *      carrying up to MAX_FRAGMENT_SIZE bytes with an 8-byte header.
 *   2. embedBytesV1/V2/V3(shareFields, frameBytes) — encodes 5 bytes of a
 *      frame into the nonce/ntime/extranonce2 fields of one Stratum submit.
 *
 * The caller is responsible for chunking frames into BYTES_PER_SHARE_V3-byte
 * slices and calling embed once per share submission.
 */
class StegoEncoder {
  constructor() {
    this.usedMessageIds = new Set();
  }

  /**
   * Generate cryptographic message ID (16-bit)
   *
   * Uses XOR of timestamp and CSPRNG to produce a 16-bit ID.
   * Collision check operates on the same 16-bit space as the returned value.
   */
  generateMessageId() {
    let msgId, attempts = 0;
    do {
      const rand = crypto.randomBytes(2).readUInt16BE(0);
      const time = Date.now() & 0xFFFF;
      msgId = (rand ^ time) & 0xFFFF;
      attempts++;
    } while (this.usedMessageIds.has(msgId) && attempts < 100);

    if (this.usedMessageIds.size > 10000) {
      const old = Array.from(this.usedMessageIds).slice(0, 5000);
      old.forEach(id => this.usedMessageIds.delete(id));
    }
    this.usedMessageIds.add(msgId);
    return msgId;
  }

  /**
   * Create message frames for embedding in shares
   * @param {Buffer|string} payload - Message content
   * @param {number} msgType - Message type (MSG_TYPE enum)
   * @returns {{ msgId: number, frames: Buffer[], totalFragments: number }}
   */
  createMessageFrames(payload, msgType = MSG_TYPE.TEXT) {
    const buf = Buffer.isBuffer(payload) ? payload : Buffer.from(payload, 'utf8');
    const msgId = this.generateMessageId();
    const totalFragments = Math.ceil(buf.length / MAX_FRAGMENT_SIZE);
    const frames = [];

    for (let i = 0; i < totalFragments; i++) {
      const start = i * MAX_FRAGMENT_SIZE;
      const frag = buf.slice(start, Math.min(start + MAX_FRAGMENT_SIZE, buf.length));

      // Build the 8-byte frame header (matches VS3 frame format above)
      const header = Buffer.alloc(HEADER_SIZE);
      header[0] = MAGIC_BYTE;        // [0] 0xAA — pool's ghost-share sentinel doubles as frame marker
      header[1] = VERSION_V3;        // [1] protocol version
      header[2] = msgType;           // [2] message type (TEXT, ENCRYPTED, ...)
      header.writeUInt16BE(msgId, 3);// [3-4] message_id — ties all fragments of this message together
      header[5] = i;                 // [5] fragment_index (0-based)
      header[6] = totalFragments;    // [6] fragment_total — receiver knows when collection is complete
      header[7] = frag.length;       // [7] payload_len — allows partial last fragment

      frames.push(Buffer.concat([header, frag]));
    }

    return { msgId, frames, totalFragments };
  }

  // --- V1: 1 byte in nonce LSB (nibble-split encoding) ---
  //
  // The nonce's two least-significant bytes each donate their low nibble (4 bits):
  //   nonce[len-2] low nibble ← byte >> 4   (high nibble of payload byte)
  //   nonce[len-1] low nibble ← byte & 0x0F (low nibble of payload byte)
  //
  // The low nibbles are used as the embedding slot: the miner fixes them to the
  // payload value and varies the upper bits during PoW search. All nonce bits
  // affect the hash equally (cryptographic property of SHA256/RandomX); the
  // lower bits are not "less validated" — they simply leave a larger search
  // space in the upper bits after being constrained to the payload value.
  //
  // @param {string} nonceHex - Original nonce hex string (≥2 bytes)
  // @param {number} byte     - Single payload byte to embed (0-255)
  // @returns {string} Modified nonce hex with byte encoded in LSB nibbles

  embedByteInNonce(nonceHex, byte) {
    const buf = safeHexToBuffer(nonceHex, 'nonce');
    const len = buf.length;
    if (len < 2) throw new Error('Nonce too short');
    buf[len - 1] = (buf[len - 1] & 0xF0) | (byte & 0x0F);
    buf[len - 2] = (buf[len - 2] & 0xF0) | ((byte >> 4) & 0x0F);
    return buf.toString('hex');
  }

  // --- V2: 3 bytes (nonce LSB nibbles + extranonce2 last 2 bytes) ---
  //
  // Bitcoin-style Stratum pools assign each miner an extranonce2 field that
  // participates in the coinbase transaction and thus in the full PoW chain
  // (coinbase → merkle root → block header → hash). The pool validates the
  // complete hash, which depends on extranonce2. Modifying extranonce2 after
  // a nonce is found invalidates the share.
  //
  // V2 encoding therefore requires the miner to PRESET the last 2 bytes of
  // extranonce2 to the desired payload values BEFORE beginning PoW search.
  // The miner then varies the remaining extranonce2 bytes and the nonce until
  // a valid hash is found. This requires a TNZX-enhanced miner; standard
  // miners iterate extranonce2 as a sequential counter without payload preset.
  //
  // embedBytesV2() constructs the extranonce2 value that should be used as
  // input to the PoW search — it must be called before mining, not after.
  //
  // V2 encoding per share:
  //   bytes[0] → nonce LSB nibbles       (via embedByteInNonce, same as V1)
  //   bytes[1] → extranonce2[len-2]      (second-to-last byte, full byte)
  //   bytes[2] → extranonce2[len-1]      (last byte, full byte)
  // Total: 1 + 2 = 3 bytes/share.

  embedBytesInExtranonce2(hex, byte1, byte2) {
    const buf = safeHexToBuffer(hex, 'extranonce2');
    const len = buf.length;
    if (len >= 2) { buf[len - 1] = byte2 & 0xFF; buf[len - 2] = byte1 & 0xFF; }
    return buf.toString('hex');
  }

  embedBytesV2(nonceHex, extranonce2Hex, bytes) {
    const b = Array.isArray(bytes) ? bytes : Array.from(bytes);
    const nonce = this.embedByteInNonce(nonceHex, b[0] || 0);
    const ext = this.embedBytesInExtranonce2(extranonce2Hex, b[1] || 0, b[2] || 0);
    return { nonce, extranonce2: ext };
  }

  // --- V3: 5 bytes (nonce sentinel + ntime, Monero Stratum) ---
  //
  // Encoding layout per share:
  //   nonce[0]   = MAGIC_BYTE (0xAA) — ghost share sentinel
  //   nonce[1..3]= bytes[0..2]       — 3 payload bytes
  //   ntime[0..1]= real epoch hi-word (preserved from input)
  //   ntime[2..3]= bytes[3..4]       — 2 payload bytes
  //
  // The ntime high 16 bits are taken from the caller's current ntime value,
  // keeping the timestamp within ±18h of the actual clock — well inside the
  // ±7200s pool acceptance window for ntime drift tolerance.
  //
  // @param {string} ntimeHex - Current ntime (4 bytes hex) from pool job
  // @param {number[]} bytes  - Exactly 5 payload bytes to embed
  // @returns {{ nonce: string, ntime: string }}

  embedBytesV3(ntimeHex, bytes) {
    const b = Array.isArray(bytes) ? bytes : Array.from(bytes);

    // nonce = 0xAA | bytes[0..2]
    const nonce = 'aa' +
      (b[0] || 0).toString(16).padStart(2, '0') +
      (b[1] || 0).toString(16).padStart(2, '0') +
      (b[2] || 0).toString(16).padStart(2, '0');

    // Preserve ntime high word; embed bytes[3..4] in low word
    const ntBuf = safeHexToBuffer(ntimeHex, 'ntime');
    if (ntBuf.length >= 4) {
      ntBuf[2] = b[3] || 0;
      ntBuf[3] = b[4] || 0;
    }

    return { nonce, ntime: ntBuf.toString('hex') };
  }
}

/**
 * Steganographic Decoder
 *
 * Extracts payload bytes from Stratum share fields and reassembles VS3 frames.
 *
 * Reassembly state machine:
 *   Each logical message is keyed by its 16-bit message_id. Fragments
 *   arrive out-of-order-safe (indexed by fragment_index). When all
 *   fragment_total fragments have arrived, the payload is concatenated
 *   in order and the entry is moved from pendingMessages to completedMessages.
 *
 *   pendingMessages: Map<msgId, { fragments[], receivedCount, totalFrags, ... }>
 *   completedMessages: Buffer[] (sliding window, capped at MAX_COMPLETED_MESSAGES)
 *
 * The pool-side equivalent of this decoder is _handleGhostShare() in
 * stratum-demo.js, which operates on the raw byte stream rather than
 * already-parsed frame objects.
 */
class StegoDecoder {
  constructor() {
    this.pendingMessages = new Map();
    this.completedMessages = [];
    this.lastCleanup = Date.now();
  }

  // --- Extract bytes from share fields (inverse of StegoEncoder methods) ---

  // Reverses embedByteInNonce: reads the low nibble of each of the last 2
  // bytes and reassembles them into the original 8-bit payload byte.
  // @param {string} nonceHex - Nonce hex from a V1 ghost share
  // @returns {number} Extracted byte (0-255)
  extractByteFromNonce(nonceHex) {
    const buf = safeHexToBuffer(nonceHex, 'nonce');
    const len = buf.length;
    if (len < 2) return 0;
    return ((buf[len - 2] & 0x0F) << 4) | (buf[len - 1] & 0x0F);
  }

  // Reverses embedBytesV2: extracts 1 byte from nonce and 2 bytes from extranonce2.
  // @param {string} nonceHex       - Nonce hex from a V2 ghost share
  // @param {string} extranonce2Hex - Extranonce2 hex from a V2 ghost share
  // @returns {number[]} [byte0, byte1, byte2] — the 3 embedded payload bytes
  extractBytesV2(nonceHex, extranonce2Hex) {
    const nByte = this.extractByteFromNonce(nonceHex);
    const eBuf = safeHexToBuffer(extranonce2Hex, 'extranonce2');
    const eLen = eBuf.length;
    return [nByte, eLen >= 2 ? eBuf[eLen - 2] : 0, eLen >= 2 ? eBuf[eLen - 1] : 0];
  }

  // Reverses embedBytesV3: reads nonce[1..3] and ntime[2..3].
  // nonce[0] (the 0xAA sentinel) is consumed by the pool's ghost-share
  // detector and is not part of the payload.
  // @param {string} nonceHex - 4-byte nonce from ghost share (nonce[0] must be 0xAA)
  // @param {string} ntimeHex - 4-byte ntime from ghost share
  // @returns {number[]} 5 payload bytes: [nonce[1], nonce[2], nonce[3], ntime[2], ntime[3]]
  extractBytesV3(nonceHex, ntimeHex) {
    const nb = safeHexToBuffer(nonceHex, 'nonce');
    const tb = safeHexToBuffer(ntimeHex, 'ntime');

    return [
      nb.length >= 4 ? nb[1] : 0,
      nb.length >= 4 ? nb[2] : 0,
      nb.length >= 4 ? nb[3] : 0,
      tb.length >= 4 ? tb[2] : 0,
      tb.length >= 4 ? tb[3] : 0
    ];
  }

  // --- Frame reassembly ---

  /**
   * Process one VS3 frame buffer — parse its header, store the fragment,
   * and return the complete message if all fragments have now arrived.
   *
   * This is the client-side mirror of the pool's _handleGhostShare() parser.
   * The difference is that the pool operates on a raw byte stream (assembling
   * frames from ghost share payloads), while this method receives a single
   * already-assembled frame buffer (e.g. decoded from the "vs3" field of a
   * job notification).
   *
   * @param {Buffer} frameBuffer - A complete VS3 frame (MAGIC_BYTE header + payload)
   * @returns {{ complete: boolean, msgId, payload?, text?, error? }}
   */
  processFrame(frameBuffer) {
    // Run eviction before any new state is added to keep memory bounded.
    this._enforceCleanup();

    // ── Step 1: Validate frame structure ────────────────────────────────────
    // A frame shorter than HEADER_SIZE (8 bytes) cannot contain even an empty
    // payload — the header alone is 8 bytes. Frames not starting with MAGIC_BYTE
    // are normal (non-VS3) shares — flag them so the caller can route correctly.
    if (frameBuffer.length < HEADER_SIZE) return { error: 'Frame too short' };
    if (frameBuffer[0] !== MAGIC_BYTE) return { error: 'Invalid magic', isNormalShare: true };

    // ── Step 2: Parse header fields ──────────────────────────────────────────
    const msgType  = frameBuffer[2];
    const msgId    = frameBuffer.readUInt16BE(3); // big-endian 16-bit message ID
    const fragIdx  = frameBuffer[5];
    const totalFrags = frameBuffer[6];
    const fragLen  = frameBuffer[7];

    // Bounds checks guard against malformed frames that could cause out-of-bounds
    // array access or create oversized pending message state.
    if (totalFrags > MAX_TOTAL_FRAGMENTS || totalFrags === 0) return { error: 'Invalid fragment count' };
    if (fragIdx >= totalFrags) return { error: 'Invalid fragment index' };

    // ── Step 3: Extract payload bytes for this fragment ──────────────────────
    // fragLen bytes immediately follow the 8-byte header.
    const fragData = frameBuffer.slice(HEADER_SIZE, HEADER_SIZE + fragLen);
    const key = msgId.toString(); // Map key — message_id as string

    // ── Step 4: Accumulate fragment into the pending message entry ───────────
    // On first fragment: create the entry with a pre-allocated fragments array
    // of length totalFrags, each slot null until filled.
    if (!this.pendingMessages.has(key)) {
      this.pendingMessages.set(key, {
        msgId, msgType, totalFrags,
        fragments: new Array(totalFrags).fill(null),
        receivedCount: 0,
        startTime: Date.now()
      });
    }

    const msg = this.pendingMessages.get(key);
    // Idempotent: ignore duplicate fragments (retransmission or replay).
    if (msg.fragments[fragIdx] === null) {
      msg.fragments[fragIdx] = fragData;
      msg.receivedCount++;
    }

    // ── Step 5: Check for message completion ─────────────────────────────────
    // When every fragment slot is filled, concatenate in index order and return
    // the complete payload. The pending entry is deleted; a completed entry is
    // appended to the sliding window.
    if (msg.receivedCount === msg.totalFrags) {
      const payload = Buffer.concat(msg.fragments);
      this.pendingMessages.delete(key);
      const result = {
        complete: true, msgId, msgType: msg.msgType, payload,
        // Convenience: decode UTF-8 text inline for TEXT-type messages.
        text: msg.msgType === MSG_TYPE.TEXT ? payload.toString('utf8') : null
      };
      this.completedMessages.push(result);
      if (this.completedMessages.length > MAX_COMPLETED_MESSAGES) {
        this.completedMessages = this.completedMessages.slice(-MAX_COMPLETED_MESSAGES);
      }
      return result;
    }

    // Still waiting for more fragments.
    return { complete: false, msgId, progress: `${msg.receivedCount}/${msg.totalFrags}` };
  }

  // Two independent eviction strategies, each guarding a different failure mode:
  //
  // Strategy 1 — TTL eviction (runs at most once per minute):
  //   Scans all pending messages and removes those older than MESSAGE_TIMEOUT_MS.
  //   Guards against abandoned partial messages — a sender who disconnects
  //   mid-transmission leaves orphaned state that would otherwise never complete.
  //
  // Strategy 2 — Capacity eviction (runs whenever the map is full):
  //   If pending message count reaches MAX_PENDING_MESSAGES, the oldest 20%
  //   of entries (by startTime) are evicted immediately. This bounds worst-case
  //   memory usage to O(MAX_PENDING_MESSAGES × MAX_FRAGMENT_SIZE × MAX_TOTAL_FRAGMENTS)
  //   regardless of sender behavior, preventing a trivial DoS via incomplete frames.
  _enforceCleanup() {
    const now = Date.now();
    if (now - this.lastCleanup > 60000) {
      for (const [k, m] of this.pendingMessages) {
        if (now - m.startTime > MESSAGE_TIMEOUT_MS) this.pendingMessages.delete(k);
      }
      this.lastCleanup = now;
    }
    if (this.pendingMessages.size >= MAX_PENDING_MESSAGES) {
      const sorted = Array.from(this.pendingMessages.entries()).sort((a, b) => a[1].startTime - b[1].startTime);
      const remove = Math.ceil(MAX_PENDING_MESSAGES * 0.2);
      for (let i = 0; i < remove && i < sorted.length; i++) this.pendingMessages.delete(sorted[i][0]);
    }
  }
}

module.exports = {
  StegoEncoder, StegoDecoder,
  MSG_TYPE, MAGIC_BYTE, HEADER_SIZE, MAX_FRAGMENT_SIZE,
  VERSION_V1, VERSION_V2, VERSION_V3, BYTES_PER_SHARE_V3,
  MAX_PENDING_MESSAGES, MESSAGE_TIMEOUT_MS, MAX_TOTAL_FRAGMENTS,
  isValidHex, safeHexToBuffer
};
