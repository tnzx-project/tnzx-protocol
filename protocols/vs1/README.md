# Visual Stratum 1 (VS1)

**Version:** 1.0 | **Status:** Archived | **License:** LGPL-2.1

---

## Summary

Visual Stratum 1 is the foundational steganographic protocol. It hides encrypted payloads in the least significant bits (LSB) of procedurally generated PNG chart images, delivered over standard HTTPS.

## Architecture

```
Application Layer    (Messages, Files, Commands)
        ↓
Encryption Layer     (ChaCha20-Poly1305 + X25519 ECDH)
        ↓
Steganography Layer  (LSB encoding in PNG pixels)
        ↓
Transport Layer      (HTTPS, standard port 443)
```

## Image Specifications

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Format | PNG 24-bit | Lossless (preserves LSB) |
| Size | 400x300 px | 120,000 pixels available |
| Channels | RGB (no alpha) | 3 bits/pixel for LSB |
| Capacity | 45,000 bytes (45 KB) | 360,000 bits / 8 |

## Key Design Decisions

1. **Procedural chart generation** — Images are real mining statistics charts, not arbitrary pictures. This provides natural cover traffic.

2. **Pixel permutation** — LSB insertion order is pseudo-randomly permuted using a PRNG seeded by the session key. Without the key, an attacker cannot determine which pixels carry payload.

3. **Constant-time operations** — Both encoding and decoding process the full image regardless of actual payload size, preventing timing side channels.

4. **Random padding** — Unused capacity is filled with encrypted random data, indistinguishable from payload.

## Limitations (Addressed by VS2)

- **No anti-spam mechanism** — Any connected client can send unlimited messages
- **No economic sustainability** — Server costs have no funding model
- **Download only** — PNG channel is pool→miner; upload requires separate HTTP POST
- **Bandwidth ceiling** — ~45 KB/s limited by image generation rate

## Test Data

See `test-vectors/vs1-vectors.json` for interoperability test vectors.
