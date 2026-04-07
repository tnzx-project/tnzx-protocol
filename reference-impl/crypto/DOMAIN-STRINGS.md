# TNZX Cryptographic Domain Strings

This file lists every key-derivation label and authentication tag used
in the protocol. If two components use different labels, they will
silently fail to talk to each other: encryption works on each side,
but decryption always fails on the other. This happened in practice
(see v1/v2 history below) and is why this registry exists.

## Current strings (v3)

### Key derivation (HKDF info)

| Purpose | String | Who uses it |
|---------|--------|-------------|
| E2E message encryption | `tnzx-e2e-v3` | reference-impl, pool, miner |
| Compact session (counter-based) | `tnzx-compact-v1` | reference-impl |
| Ghost share HMAC | `tnzx-ghost-v1` | pool stratum engine |
| Messenger key from wallet | `tnzx-wallet-bound-v3` | miner |
| Messenger master seed | `tnzx-messenger-master-v1` | miner |

### Authentication data (AAD)

| Purpose | AAD content | 
|---------|-------------|
| Session message | `"tnzx-e2e-v3"` + replay ID (16 bytes) |
| One-shot message | `"tnzx-oneshot-v3"` + replay ID + ephemeral public key |
| Compact session | `"tnzx-compact-v1"` + counter (4 bytes) |

## How it evolved

**v1 (2025)** — First version. Used AES-256-GCM. The pool called its
key derivation `tnzx-stego-e2e-v1` while the miner called it
`tnzx-e2e-v1`. Nobody noticed because they were never tested together.

**v2 (early 2026)** — Security fixes added replay protection and
authentication tags. The pool updated its AAD strings to `v2` but
kept the old HKDF label. The miner jumped straight to `v3` for its
HKDF label. The two still couldn't interoperate, and still nobody
tested cross-component. This version was never cleanly released.

**v3 (2026-04-06)** — Complete rewrite. Cipher changed from AES-256-GCM
to XChaCha20-Poly1305. All labels unified across every component.
Cross-component communication tested and verified for the first time.
Old encrypted files (vault, 2FA, onion keys) can still be read via
a v1 fallback path, but all new data is written as v3.

## Rules

1. **Same label = same key.** If you change the cipher or the wire
   format, you must change the label too. Otherwise the old code
   derives the same key and tries to decrypt with the wrong cipher.

2. **Different purpose = different label.** The E2E label and the
   ghost HMAC label must stay separate. Reusing a label across
   contexts is a cryptographic mistake called "domain separation
   violation."

3. **New code uses v3.** Any new component (client SDK, multichain
   bridge, mobile app) must use the v3 strings listed above.
   Do not copy labels from old source files.
