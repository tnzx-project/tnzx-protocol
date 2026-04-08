'use strict';
/**
 * @tnzx/sdk — Low-level Stratum client
 *
 * Manages a TCP connection to a Stratum pool or VS3 proxy.
 * Handles login, job reception, ghost share submission, and VS3 frame
 * reception. Emits events for each lifecycle stage.
 *
 * Extracted from tnzx-pool-demo/vs3-chat.js and refactored into a
 * reusable EventEmitter class.
 *
 * @license LGPL-2.1
 */

const net = require('net');
const { EventEmitter } = require('events');
const { MAGIC, HEADER_LEN, ZERO_RESULT, DEFAULT_GHOST_INTERVAL_MS } = require('../constants');
const { buildVS3Frame, chunkFrame, encodeGhostShare } = require('./ghost-share');
const { hmacDeriveSessionKey, hmacSentinel } = require('./hmac-sentinel');

class StratumClient extends EventEmitter {
  /**
   * @param {Object} options
   * @param {string} options.host - Pool/proxy hostname
   * @param {number} options.port - Pool/proxy port
   * @param {string} options.wallet - Miner wallet address
   * @param {string} [options.pass='x'] - Miner password
   * @param {string} [options.agent='tnzx-sdk/1.0'] - Agent string
   * @param {number} [options.ghostIntervalMs=150] - Delay between ghost share submissions
   */
  constructor(options) {
    super();
    this.host = options.host;
    this.port = options.port;
    this.wallet = options.wallet;
    this.pass = options.pass || 'x';
    this.agent = options.agent || 'tnzx-sdk/1.0';
    this.ghostIntervalMs = options.ghostIntervalMs || DEFAULT_GHOST_INTERVAL_MS;

    this._sock = null;
    this._buf = '';
    this._minerId = null;
    this._jobId = null;
    this._reqId = 100;
    this._connected = false;
    this._sessionKey = null;   // HMAC sentinel key (set if proxy provides session token)
    this._sendInterval = null; // Track active send interval for cleanup
  }

  get connected() { return this._connected; }
  get minerId() { return this._minerId; }
  get currentJobId() { return this._jobId; }
  get sessionToken() { return this._sessionKey; }

  /**
   * Open TCP connection and send Stratum login.
   */
  connect() {
    this._sock = net.connect(this.port, this.host, () => {
      this._sock.write(JSON.stringify({
        id: 1, jsonrpc: '2.0', method: 'login',
        params: { login: this.wallet, pass: this.pass, agent: this.agent },
      }) + '\n');
    });

    this._sock.on('data', (d) => this._onData(d));
    this._sock.on('error', (e) => this.emit('error', e));
    this._sock.on('close', () => {
      this._connected = false;
      this.emit('close');
    });
  }

  /**
   * Close the connection.
   */
  disconnect() {
    if (this._sendInterval) { clearInterval(this._sendInterval); this._sendInterval = null; }
    if (this._sock) this._sock.destroy();
  }

  /**
   * Send a VS3 frame as paced ghost shares.
   * @param {Buffer} frameBytes - Complete VS3 frame (header + payload)
   * @param {string} recipientWallet - Target wallet for vs3_to
   * @returns {Promise<void>} Resolves when all shares are sent
   */
  sendFrame(frameBytes, recipientWallet) {
    const chunks = chunkFrame(frameBytes);
    let i = 0;
    return new Promise((resolve, reject) => {
      if (!this._sock || !this._minerId || !this._jobId) {
        return reject(new Error('Not connected'));
      }
      const iv = setInterval(() => {
        if (i >= chunks.length || !this._sock || this._sock.destroyed) {
          clearInterval(iv); this._sendInterval = null; resolve(); return;
        }
        const vs3To = i === 0 ? recipientWallet : null;
        const chunk = chunks[i];

        // Apply HMAC sentinel if session key available
        let nonce;
        if (this._sessionKey) {
          const payloadBytes = chunk.subarray(0, 3);
          const sentinel = hmacSentinel(this._sessionKey, payloadBytes);
          nonce = sentinel.toString(16).padStart(2, '0') +
            payloadBytes[0].toString(16).padStart(2, '0') +
            payloadBytes[1].toString(16).padStart(2, '0') +
            payloadBytes[2].toString(16).padStart(2, '0');
        } else {
          // Fallback: 0xAA sentinel
          nonce = 'aa' +
            chunk[0].toString(16).padStart(2, '0') +
            chunk[1].toString(16).padStart(2, '0') +
            chunk[2].toString(16).padStart(2, '0');
        }

        const now = Math.floor(Date.now() / 1000);
        const ntimeVal = ((now & 0xFFFF0000) | (chunk[3] << 8) | chunk[4]) >>> 0;
        const ntime = ntimeVal.toString(16).padStart(8, '0');

        const params = {
          id: this._minerId, job_id: this._jobId,
          nonce, result: ZERO_RESULT, ntime,
        };
        if (vs3To) params.vs3_to = vs3To;

        const msg = JSON.stringify({ id: this._reqId++, jsonrpc: '2.0', method: 'submit', params });
        this._sock.write(msg + '\n');
        i++;
      }, this.ghostIntervalMs);
      this._sendInterval = iv;
    });
  }

  // ── Internal ──────────────────────────────────────────────────────────────

  _onData(d) {
    this._buf += d.toString();
    if (this._buf.length > 1048576) { // 1 MB cap — prevents DoS via no newline
      this.emit('error', new Error('Buffer overflow: server sent >1MB without newline'));
      this._sock.destroy();
      return;
    }
    const lines = this._buf.split('\n');
    this._buf = lines.pop();

    for (const line of lines) {
      if (!line.trim()) continue;
      let msg;
      try { msg = JSON.parse(line); } catch { continue; }
      if (!msg || typeof msg !== 'object' || Array.isArray(msg)) continue;

      // Login response
      if (msg.id === 1 && msg.result) {
        this._minerId = msg.result.id;
        this._jobId = msg.result.job?.job_id;

        // Check for HMAC session token from proxy
        const token = msg.result.extensions?.vs3_session;
        if (token) {
          this._sessionKey = hmacDeriveSessionKey(
            Buffer.from(token, 'hex'), this.wallet
          );
        }

        if (this._jobId && !this._connected) {
          this._connected = true;
          this.emit('ready', { minerId: this._minerId, jobId: this._jobId });
        }
      }

      // Job notification
      if (msg.method === 'job' && msg.params) {
        if (msg.params.job_id) this._jobId = msg.params.job_id;

        if (!this._connected && this._jobId && this._minerId) {
          this._connected = true;
          this.emit('ready', { minerId: this._minerId, jobId: this._jobId });
        }

        this.emit('job', msg.params);

        // Extract VS3 frame if present
        if (msg.params.vs3) {
          const frame = Buffer.from(msg.params.vs3, 'hex');
          if (frame.length >= HEADER_LEN + 1 && frame[0] === MAGIC) {
            const type = frame[2];
            const payloadLen = frame[7];
            if (8 + payloadLen > frame.length) return; // malformed
            const payload = frame.subarray(8, 8 + payloadLen);
            this.emit('frame', { type, payload, raw: frame });
          }
        }
      }
    }
  }
}

module.exports = StratumClient;
