'use strict';
/**
 * Minimal Stratum server for SDK integration tests.
 *
 * Supports: login, ghost share submit (with VS3 frame reassembly),
 * job notifications with VS3 frame delivery.
 *
 * NOT a real pool — no PoW validation, no block templates.
 */

const net = require('net');
const crypto = require('crypto');

class MockStratumServer {
  constructor() {
    this._server = null;
    this._miners = new Map(); // minerId → { sock, wallet, ghostBuf, pendingFrames }
    this._walletToMiner = new Map();
    this.port = 0;
  }

  start() {
    return new Promise((resolve) => {
      this._server = net.createServer((sock) => this._onConnect(sock));
      this._server.listen(0, '127.0.0.1', () => {
        this.port = this._server.address().port;
        resolve(this.port);
      });
    });
  }

  stop() {
    for (const [, m] of this._miners) m.sock.destroy();
    if (this._server) this._server.close();
  }

  _onConnect(sock) {
    let buf = '';
    sock.on('data', (d) => {
      buf += d.toString();
      const lines = buf.split('\n');
      buf = lines.pop();
      for (const line of lines) {
        if (!line.trim()) continue;
        try { this._handleMsg(sock, JSON.parse(line)); } catch {}
      }
    });
    sock.on('error', () => {});
  }

  _handleMsg(sock, msg) {
    // Login
    if (msg.method === 'login') {
      const minerId = crypto.randomBytes(4).toString('hex');
      const wallet = msg.params?.login || 'unknown';
      const jobId = crypto.randomBytes(4).toString('hex');

      const miner = { sock, wallet, minerId, jobId, ghostBuf: Buffer.alloc(0), pendingFrames: [] };
      this._miners.set(minerId, miner);
      this._walletToMiner.set(wallet, miner);

      const resp = {
        id: msg.id, jsonrpc: '2.0',
        result: {
          id: minerId, status: 'OK',
          job: { job_id: jobId, blob: '0'.repeat(152), target: 'ffffffff', height: 1, seed_hash: '0'.repeat(64) },
        },
      };
      sock.write(JSON.stringify(resp) + '\n');
      return;
    }

    // Submit (ghost share)
    if (msg.method === 'submit' && msg.params) {
      const { id: minerId, nonce, ntime, vs3_to } = msg.params;
      const miner = this._miners.get(minerId);
      if (!miner) return;

      // Respond OK
      sock.write(JSON.stringify({ id: msg.id, jsonrpc: '2.0', result: { status: 'OK' } }) + '\n');

      // Extract 5 bytes from ghost share
      const nb = Buffer.from(nonce, 'hex');
      const tb = Buffer.from(ntime || '00000000', 'hex');
      const bytes = Buffer.from([
        nb.length >= 4 ? nb[1] : 0,
        nb.length >= 4 ? nb[2] : 0,
        nb.length >= 4 ? nb[3] : 0,
        tb.length >= 4 ? tb[2] : 0,
        tb.length >= 4 ? tb[3] : 0,
      ]);

      if (vs3_to) miner.ghostTo = vs3_to;
      miner.ghostBuf = Buffer.concat([miner.ghostBuf, bytes]);

      // Try to parse a complete VS3 frame
      this._tryParseFrame(miner);
    }
  }

  _tryParseFrame(miner) {
    const buf = miner.ghostBuf;
    // Parse strictly from the start of the buffer.
    // The ghost buffer is a sequential stream of 5-byte chunks;
    // frames appear in order. Never scan for magic inside payload.
    if (buf.length < 8) return;
    if (buf[0] !== 0xAA || buf[1] !== 0x03) {
      // Not at frame start — discard one byte and retry
      miner.ghostBuf = buf.subarray(1);
      if (miner.ghostBuf.length >= 8) this._tryParseFrame(miner);
      return;
    }

    const payloadLen = buf[7];
    const frameLen = 8 + payloadLen;
    if (buf.length < frameLen) return; // incomplete

    const frame = Buffer.from(buf.subarray(0, frameLen));
    miner.ghostBuf = buf.subarray(frameLen);

    // Route to recipient
    const recipient = miner.ghostTo;
    if (recipient) {
      const target = this._walletToMiner.get(recipient);
      if (target) {
        // Deliver via job notification with vs3 field
        const jobId = crypto.randomBytes(4).toString('hex');
        target.jobId = jobId;
        const jobMsg = {
          jsonrpc: '2.0', method: 'job',
          params: {
            job_id: jobId, blob: '0'.repeat(152), target: 'ffffffff',
            height: 1, seed_hash: '0'.repeat(64),
            vs3: frame.toString('hex'),
          },
        };
        target.sock.write(JSON.stringify(jobMsg) + '\n');
      }
    }

    // Check for more frames in the buffer
    if (miner.ghostBuf.length >= 8) this._tryParseFrame(miner);
  }
}

module.exports = MockStratumServer;
