# @tnzx/sdk

Developer SDK for the TNZX protocol — censorship-resistant messaging over cryptocurrency mining channels.

Zero external dependencies. Node.js >= 18.

## Quick Start

```js
const { VS3Client } = require('@tnzx/sdk');

const client = new VS3Client({ pool: 'host:3333', wallet: '4...' });

client.on('ready', () => console.log('Connected'));
client.on('peer', ({ wallet }) => client.send(wallet, 'Hello TNZX'));
client.on('message', ({ text }) => console.log(text));
client.connect();
```

## Limits

| Constraint | Value | Why |
|-----------|-------|-----|
| Max plaintext per message | **127 bytes** | Single VS3 frame (247B) minus 120B encryption overhead |
| Encryption overhead | **120 bytes** | replayId(16) + ephPub(32) + salt(32) + nonce(24) + tag(16) |
| Ghost shares per message | ~28 for 127B | Frame chunked at 5 bytes/share (Monero V3) |
| Send pacing | 150ms default | Configurable via `ghostIntervalMs` |
| Key exchange | **Unauthenticated (TOFU)** | A malicious pool can MITM the key exchange. See Threat Model below. |

Messages longer than 127 bytes will be rejected with an error. Multi-frame fragmentation is planned for a future release.

## API Reference

### VS3Client (high-level)

```js
const { VS3Client } = require('@tnzx/sdk');
```

#### Constructor

```js
new VS3Client({
  pool: 'host:port',           // required — Stratum pool or VS3 proxy
  wallet: '4...',              // required — 95-char Monero wallet
  privateKey: Buffer,          // optional — 32-byte X25519 (auto-generated if omitted)
  publicKey: Buffer,           // optional — must match privateKey if provided
  ghostIntervalMs: 150,        // optional — delay between ghost share submissions
})
```

#### Methods

| Method | Description |
|--------|-------------|
| `connect()` | Open TCP connection, send Stratum login |
| `disconnect()` | Close connection, clear timers |
| `send(wallet, text)` | Encrypt and send a text message (queued if key exchange pending) |
| `sendRaw(wallet, payload)` | Encrypt and send a raw Buffer |

#### Events

| Event | Payload | When |
|-------|---------|------|
| `ready` | `void` | Connected and logged in |
| `peer` | `{ wallet, publicKey }` | Key exchange completed with a peer |
| `message` | `{ from, text, raw }` | Decrypted message received |
| `error` | `Error` | Network or protocol error |
| `close` | `void` | Connection closed |

#### Key Exchange

Key exchange is automatic. When you call `send()` for a wallet with no known key, VS3Client:

1. Queues the message
2. Sends a KEY_EXCHANGE frame (type `0x04`) with your public key
3. Waits for the peer's KEY_EXCHANGE frame
4. Encrypts and sends all queued messages

Pending messages are capped at 100 per peer.

### StratumClient (low-level)

```js
const { StratumClient } = require('@tnzx/sdk');
```

For developers who need fine-grained control over frame types, manual encryption, or custom protocols on top of VS3.

#### Constructor

```js
new StratumClient({
  host: '127.0.0.1',
  port: 3333,
  wallet: '4...',
  pass: 'x',                   // optional
  agent: 'tnzx-sdk/1.0',       // optional
  ghostIntervalMs: 150,         // optional
})
```

#### Methods

| Method | Description |
|--------|-------------|
| `connect()` | Open TCP connection, send Stratum login |
| `disconnect()` | Close connection |
| `sendFrame(frameBytes, recipientWallet)` | Send a VS3 frame as paced ghost shares. Returns `Promise<void>`. |

#### Events

| Event | Payload | When |
|-------|---------|------|
| `ready` | `{ minerId, jobId }` | Login accepted, first job received |
| `job` | `{ job_id, blob, target, ... }` | New mining job from pool |
| `frame` | `{ type, payload, raw }` | VS3 frame received in job notification |
| `error` | `Error` | Network or protocol error |
| `close` | `void` | Connection closed |

#### HMAC Sentinel

If the proxy provides a session token in the login response (`result.extensions.vs3_session`), StratumClient automatically derives an HMAC session key and uses HMAC-tagged nonces instead of the fixed `0xAA` sentinel. This makes ghost shares statistically indistinguishable from real shares to a DPI observer. No configuration needed — it is opportunistic.

### Crypto Functions

```js
const { encryptOneShot, decryptOneShot, generateKeyPair } = require('@tnzx/sdk');
```

| Function | Description |
|----------|-------------|
| `generateKeyPair()` | Returns `{ publicKey, privateKey }` (32-byte X25519 Buffers) |
| `encryptOneShot(plaintext, recipientPub)` | One-shot PFS encryption. Fresh ephemeral key per call. Returns wire-format Buffer. |
| `decryptOneShot(packet, myPrivateKey, replayCache?)` | Decrypt and verify. Optional `Set<string>` for replay detection. |

Wire format: `replayId(16) || ephPub(32) || salt(32) || nonce(24) || ciphertext || tag(16)`

### Frame Utilities

```js
const { buildVS3Frame, chunkFrame, encodeGhostShare, MSG_TYPE } = require('@tnzx/sdk');
```

| Function | Description |
|----------|-------------|
| `buildVS3Frame(payload, msgType)` | Build a single-fragment VS3 frame. Max payload 247 bytes. |
| `chunkFrame(frameBytes, bytesPerChunk?)` | Split frame into 5-byte chunks for ghost share encoding. |
| `encodeGhostShare(reqId, minerId, jobId, chunk, vs3To)` | Encode a chunk as a Stratum JSON-RPC submit. |

### Constants

```js
const { MSG_TYPE, MAGIC, VERSION_V3, ENCRYPT_OVERHEAD } = require('@tnzx/sdk');
```

| Constant | Value | Description |
|----------|-------|-------------|
| `MSG_TYPE.TEXT` | `0x01` | Plaintext message |
| `MSG_TYPE.KEY_EXCHANGE` | `0x04` | Public key exchange |
| `MSG_TYPE.ENCRYPTED` | `0x05` | Encrypted envelope (external type for all encrypted frames) |
| `ENCRYPT_OVERHEAD` | `120` | Bytes added by one-shot encryption |

Full enum: TEXT (0x01), ACK (0x02), PING (0x03), KEY_EXCHANGE (0x04), ENCRYPTED (0x05), HASHCASH (0x06). Types 0x07-0xFF are available for application-layer protocols.

## Threat Model

**What the SDK protects:**
- Message content (E2E encrypted, pool cannot read)
- Message type (encrypted envelope, pool sees only `0x05`)
- Ghost share detection (HMAC sentinel, indistinguishable from real shares)

**What the SDK does NOT protect:**
- **Key exchange is unauthenticated (TOFU).** A malicious pool or MITM can inject a fake public key during key exchange. The SDK trusts the pool's routing. Authenticated key exchange (signed keys) is planned for a future release.
- **Timing correlation.** An observer who monitors when Alice and Bob are mining can correlate sessions.
- **Message size.** Fragment count is visible to the pool (it sees how many ghost shares form a message).

## Wire Format Compatibility

The SDK uses the **reference-impl** wire format for encryption. It is **NOT compatible** with `tnzx-pool-demo/lib/e2e.js`, which uses a different AAD string and omits replay protection. When migrating from pool-demo to SDK, all parties must upgrade simultaneously.

| Field | SDK (canonical) | pool-demo (legacy) |
|-------|----------------|-------------------|
| Wire layout | replayId + ephPub + salt + nonce + ct + tag | ephPub + salt + nonce + ct + tag |
| Overhead | 120 bytes | 104 bytes |
| AAD | `tnzx-oneshot-v3` | `tnzx-demo-v1` |
| HKDF info | `tnzx-e2e-v3` | `tnzx-e2e-demo-v1` |
| Replay protection | Yes | No |

## Tests

```
node test/run-all.js
```

40 tests across 6 suites: crypto (11), keys (6), ghost-share (10), HMAC sentinel (8), StratumClient integration (2), VS3Client E2E integration (3).

## Examples

- [`examples/chat.js`](examples/chat.js) — Interactive E2E encrypted chat (readline UI)
- [`examples/e2e-test.js`](examples/e2e-test.js) — Automated 5-message bidirectional smoke test
- [`examples/real-pool-test.js`](examples/real-pool-test.js) — Integration test against real pool

## License

LGPL-2.1
