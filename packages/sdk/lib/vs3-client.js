'use strict';
/**
 * @tnzx/sdk — VS3Client
 *
 * High-level facade for sending and receiving encrypted messages over
 * TNZX mining channels. Handles key exchange, encryption, and framing
 * automatically.
 *
 * Usage:
 *   const { VS3Client } = require('@tnzx/sdk');
 *   const client = new VS3Client({ pool: 'host:port', wallet: '4...' });
 *   client.on('message', ({ from, text }) => console.log(from, text));
 *   client.on('ready', () => client.send('4recipient...', 'Hello'));
 *   client.connect();
 *
 * @license LGPL-2.1
 */

const { EventEmitter } = require('events');
const { MSG_TYPE } = require('./constants');
const { generateKeyPair } = require('./crypto/keys');
const { encryptOneShot, decryptOneShot } = require('./crypto/e2e');
const { buildVS3Frame } = require('./transport/ghost-share');
const StratumClient = require('./transport/stratum-client');

// Replay cache: auto-prune entries older than this
const REPLAY_MAX_AGE_MS = 600000; // 10 minutes

class VS3Client extends EventEmitter {
  /**
   * @param {Object} options
   * @param {string} options.pool - Pool address as 'host:port'
   * @param {string} options.wallet - Miner wallet address
   * @param {Buffer} [options.privateKey] - Existing X25519 private key (auto-generated if omitted)
   * @param {Buffer} [options.publicKey] - Matching public key (required if privateKey is provided)
   * @param {number} [options.ghostIntervalMs=150] - Delay between ghost share submissions
   */
  constructor(options) {
    super();
    const parts = options.pool.split(':');
    if (parts.length < 2 || !parts[1]) throw new Error('pool must be "host:port"');
    this._host = parts[0];
    this._port = parseInt(parts[1], 10);
    if (isNaN(this._port) || this._port < 1 || this._port > 65535) {
      throw new Error(`Invalid port: ${parts[1]}`);
    }
    this._wallet = options.wallet;
    this._ghostIntervalMs = options.ghostIntervalMs;

    // Identity
    if (options.privateKey) {
      this._privateKey = options.privateKey;
      this._publicKey = options.publicKey;
    } else {
      const kp = generateKeyPair();
      this._privateKey = kp.privateKey;
      this._publicKey = kp.publicKey;
    }

    // Peer keys: wallet → Buffer(32)
    this._peers = new Map();
    // Message queue: wallet → Buffer[]
    this._pendingMessages = new Map();
    // Replay cache
    this._replayCache = new Set();
    this._replayCacheTimestamps = new Map();
    // Send queue — serializes frame transmission (no interleaving)
    this._sendQueue = Promise.resolve();

    this._stratum = null;
  }

  get publicKey() { return this._publicKey; }
  get wallet() { return this._wallet; }
  get connected() { return this._stratum?.connected || false; }

  /**
   * Connect to the pool/proxy and initiate key exchange.
   */
  connect() {
    this._stratum = new StratumClient({
      host: this._host,
      port: this._port,
      wallet: this._wallet,
      ghostIntervalMs: this._ghostIntervalMs,
    });

    this._stratum.on('ready', () => {
      this.emit('ready');
    });

    this._stratum.on('frame', ({ type, payload }) => {
      this._handleFrame(type, payload);
    });

    this._stratum.on('error', (e) => this.emit('error', e));
    this._stratum.on('close', () => this.emit('close'));

    this._stratum.connect();
  }

  /**
   * Disconnect from the pool.
   */
  disconnect() {
    if (this._stratum) this._stratum.disconnect();
  }

  /**
   * Send an encrypted text message to a peer.
   * If the peer's key is not yet known, the message is queued.
   *
   * @param {string} recipientWallet - Peer's wallet address
   * @param {string} text - Message text
   * @returns {Promise<void>}
   */
  async send(recipientWallet, text) {
    return this.sendRaw(recipientWallet, Buffer.from(text, 'utf8'));
  }

  /**
   * Send an encrypted raw payload to a peer.
   * @param {string} recipientWallet - Peer's wallet address
   * @param {Buffer} payload - Raw data to encrypt and send
   * @returns {Promise<void>}
   */
  async sendRaw(recipientWallet, payload) {
    const peerKey = this._peers.get(recipientWallet);
    if (!peerKey) {
      // Queue until key exchange completes
      if (!this._pendingMessages.has(recipientWallet)) {
        this._pendingMessages.set(recipientWallet, []);
        // Initiate key exchange with this peer
        this._sendKeyExchange(recipientWallet);
      }
      const queue = this._pendingMessages.get(recipientWallet);
      if (queue.length >= 100) queue.shift(); // cap at 100 pending messages per peer
      queue.push(payload);
      return;
    }

    const encrypted = encryptOneShot(payload, peerKey);
    const frame = buildVS3Frame(encrypted, MSG_TYPE.ENCRYPTED);
    this._queueSend(frame, recipientWallet);
  }

  // ── Internal ──────────────────────────────────────────────────────────────

  /**
   * Send our public key to a specific peer (or broadcast if no wallet).
   * Serialized through the send queue to prevent frame interleaving.
   * @param {string} [recipientWallet] - Target wallet
   */
  _sendKeyExchange(recipientWallet) {
    const frame = buildVS3Frame(this._publicKey, MSG_TYPE.KEY_EXCHANGE);
    this._queueSend(frame, recipientWallet || '');
  }

  /**
   * Queue a frame for serialized sending.
   * Prevents ghost share interleaving when multiple frames are sent rapidly.
   */
  _queueSend(frame, recipientWallet) {
    if (!this._stratum) return; // not connected yet — frame is lost (message was queued for later)
    this._sendQueue = this._sendQueue
      .then(() => this._stratum.sendFrame(frame, recipientWallet))
      .catch((e) => this.emit('error', e));
  }

  _handleFrame(type, payload) {
    if (type === MSG_TYPE.KEY_EXCHANGE && payload.length === 32) {
      this._handleKeyExchange(payload);
      return;
    }

    if (type === MSG_TYPE.ENCRYPTED) {
      this._handleEncrypted(payload);
      return;
    }

    // Unknown or unhandled type — emit for advanced consumers
    this.emit('frame', { type, payload });
  }

  _handleKeyExchange(peerPubKey) {
    const pubHex = peerPubKey.toString('hex');

    // Associate this key with the first wallet that has pending messages
    // and no key yet. In production, the pool's vs3_to routing ensures
    // the correct sender→recipient mapping.
    let walletForKey = null;
    for (const [wallet] of this._pendingMessages) {
      if (!this._peers.has(wallet)) {
        walletForKey = wallet;
        break;
      }
    }

    if (walletForKey) {
      this._peers.set(walletForKey, peerPubKey);
    }

    const isNew = !this._peers.has('_responded_' + pubHex);
    if (isNew) {
      this._peers.set('_responded_' + pubHex, true);
      // Send our key back so peer can encrypt to us.
      // Route to the sender's wallet if known, otherwise broadcast.
      this._sendKeyExchange(walletForKey);
    }

    this.emit('peer', { wallet: walletForKey, publicKey: peerPubKey });

    // Flush queued messages now that we have the peer's key
    if (walletForKey && this._pendingMessages.has(walletForKey)) {
      const queued = this._pendingMessages.get(walletForKey);
      this._pendingMessages.delete(walletForKey);
      for (const payload of queued) {
        this.sendRaw(walletForKey, payload).catch(() => {});
      }
    }
  }

  _handleEncrypted(payload) {
    this._pruneReplayCache();
    try {
      const plaintext = decryptOneShot(payload, this._privateKey, this._replayCache);
      this._replayCacheTimestamps.set(
        payload.subarray(0, 16).toString('hex'),
        Date.now()
      );

      // Try to find sender by checking which peer key can decrypt
      // (the AAD includes ephPub so we can't easily identify sender from packet)
      this.emit('message', {
        from: null, // sender identification requires protocol extension
        text: plaintext.toString('utf8'),
        raw: plaintext,
      });
    } catch {
      // Expected for frames not addressed to us, or corrupted data.
      // Not surfaced as 'error' to avoid crashing without listener.
    }
  }

  _pruneReplayCache() {
    const cutoff = Date.now() - REPLAY_MAX_AGE_MS;
    for (const [hex, ts] of this._replayCacheTimestamps) {
      if (ts < cutoff) {
        this._replayCache.delete(hex);
        this._replayCacheTimestamps.delete(hex);
      }
    }
  }
}

module.exports = VS3Client;
