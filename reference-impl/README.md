# Reference Implementation

Standalone Node.js implementation of the Visual Stratum protocol suite.

## Modules

| Module | Description | Dependencies |
|--------|-------------|-------------|
| `crypto/` | E2E encryption: X25519 ECDH, XChaCha20-Poly1305, HKDF, replay protection | Node.js `crypto` only |
| `stego-core/` | Steganographic encoder/decoder for Stratum share embedding | Node.js `crypto` only |
| `mining-gate/` | Proof-of-work gated access control (Mining Gate) | Node.js `crypto` only |

## Requirements

- Node.js >= 14.0 (for `crypto.hkdfSync`)
- No external dependencies

## Usage

```javascript
const { StegoEncoder, StegoDecoder, MSG_TYPE } = require('./stego-core');
const { E2ECrypto, encryptOneShot, decryptOneShot } = require('./crypto');
const { MiningGate, MinerState } = require('./mining-gate');
```

## Security Notes

- All randomness uses `crypto.randomBytes()` — never `Math.random()`
- All secret comparisons are constant-time where applicable
- Keys are never logged or persisted in plaintext
- Nonce tracking prevents replay attacks (5-minute TTL window)

## License

LGPL-2.1
