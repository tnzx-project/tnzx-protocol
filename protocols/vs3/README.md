# Visual Stratum 3 (VS3)

**Version:** 3.0 | **Status:** Partially implemented | **License:** LGPL-2.1

---

## Summary

Visual Stratum 3 extends VS2 with a multi-layer transport architecture that specifies four simultaneous communication channels. The Stratum embedding channel is implemented and tested in the reference implementation. The additional channels (PNG LSB, WebSocket, HTTP/2) are fully specified; implementation is planned for a future release. The design targets a combined bandwidth of approximately 195 KB/s while maintaining censorship resistance and statistical undetectability.

## What's New vs VS2

| Feature | VS2 | VS3 |
|---------|-----|-----|
| Transport layers | 2 (PNG + Stratum) | **4 (PNG + WS + HTTP/2 + Stratum)** |
| Download bandwidth | 45 KB/s | **195 KB/s** |
| Adaptive modes | No | **Yes (Speed/Anon/Balanced)** |
| Fallback | No | **Yes (graceful degradation)** |
| Voice support | No | **Theoretical (SPEED mode bandwidth sufficient, not implemented)** |
| Compression | No | **Yes (LZ4)** |

## Transport Layers

```
┌─────────────────────────────────────────────────────────────┐
│                    APPLICATION LAYER                         │
│         Chat, Files, Voice, Marketplace, Hosting             │
├─────────────────────────────────────────────────────────────┤
│                    ENCRYPTION LAYER                          │
│         AES-256-GCM + X25519 + HKDF-SHA256                  │
├─────────────────────────────────────────────────────────────┤
│                    TRANSPORT LAYER                           │
│  ┌──────────┬──────────┬───────────┬──────────────────┐     │
│  │ L4: PNG  │L3: WS    │L2: HTTP/2 │L1: Stratum Stego │     │
│  │ 45KB/s ↓ │50KB/s ↕  │100KB/s ↕  │5-256 B/share ↑   │     │
│  └──────────┴──────────┴───────────┴──────────────────┘     │
├─────────────────────────────────────────────────────────────┤
│                    MINING GATE (from VS2)                    │
│         Proof-of-work verification (sliding window)          │
└─────────────────────────────────────────────────────────────┘
```

## Adaptive Modes

VS3 automatically selects the optimal transport strategy based on message type:

| Mode | Channels | Use Case | Stealth |
|------|----------|----------|---------|
| **ANON** | Stratum only | Private chat, escrow | Maximum |
| **BALANCED** | Stratum + bonus channels (delayed) | DNS, marketplace | High |
| **SPEED** | All channels parallel | File transfer, hosting | Medium |

### Automatic Mode Selection

| Message Type | Mode |
|-------------|------|
| Chat, presence, escrow operations | ANON |
| DNS queries, marketplace listings | BALANCED |
| File transfers, web hosting | SPEED |

### Timing Decorrelation

In BALANCED mode, bonus channels send fragments with random delays (500-3000ms) to prevent cross-channel correlation. An observer cannot link Stratum traffic to WebSocket traffic even if monitoring both.

## Stratum Embedding — Two Profiles

VS3 defines two encoding profiles for different Stratum variants. The frame format (8-byte header + payload) is **identical** in both — the profiles differ only in how bytes are transported per share.

### Profile Comparison

| Property | VS3-Monero | VS3-Generic |
|----------|-----------|-------------|
| **Target** | Monero / XMRig | Bitcoin / Ethereum (Slushpool, Foundry, Antpool, …) |
| **Bytes/share** | **5** | **7** |
| **Fields used** | nonce + ntime | nonce + extranonce2 + ntime |
| **extranonce2** | Not required | Required (≥ 4 bytes) |
| **Detection** | `nonce[0] == 0xAA` | `extranonce2` field present in params |
| **Reference-impl** | ✅ Published (`stego-core`) | ⏳ Spec published, impl pending |
| **Test vectors** | ✅ Published | ✅ Published |
| **Demo** | ✅ `tnzx-pool-demo` | ⏳ Pending |

### VS3-Monero Encoding (5 bytes/share)

```
Share submit fields:
┌──────────────────────────────┬──────────────────────────┐
│        NONCE  (4 bytes)      │       NTIME  (4 bytes)   │
│  [ 0xAA ][ b0 ][ b1 ][ b2 ] │  [ hi ][ hi ][ b3 ][ b4 ]│
│  sentinel   payload[0..2]    │  ← preserved →  payload[3..4] │
└──────────────────────────────┴──────────────────────────┘
```

- `nonce[0] = 0xAA` — sentinel, identifies ghost share at the pool
- `nonce[1..3]` — 3 payload bytes
- `ntime[0..1]` — real epoch high word, preserved (keeps timestamp within ±7200 s pool window)
- `ntime[2..3]` — 2 payload bytes

### VS3-Generic Encoding (7 bytes/share)

```
Share submit fields:
┌──────────────┬──────────────────────────┬──────────────┐
│  NONCE       │     EXTRANONCE2          │    NTIME     │
│  (8 bytes)   │     (≥ 4 bytes)          │  (4 bytes)   │
│  …[ h ][ l ] │  …[ b1 ][ b2 ][ b3 ][ b4 ] │  …[ b5 ][ b6 ]│
│  ↑ 1 byte    │       4 bytes            │    2 bytes   │
│  as nibbles  │  last 4 bytes replaced   │ last 2 bytes │
└──────────────┴──────────────────────────┴──────────────┘
```

- `nonce` last 2 bytes: high nibble kept, low nibble carries half-byte of payload byte 0
- `extranonce2` last 4 bytes: payload bytes 1–4 (direct replacement)
- `ntime` last 2 bytes: payload bytes 5–6

### Dual-Mode Pool Detection

A VS3-aware pool detects both profiles unambiguously from the share params:

```
if difficulty > ghostDiffMax   → regular mining share, pass through
else if nonce starts with "aa" → VS3-Monero ghost share (5B)
else if extranonce2 present    → VS3-Generic ghost share (7B)
```

Both code paths return `{"status":"OK"}` — indistinguishable to a passive observer.

### Higher-Bandwidth Modes

| Mode | Bytes/Share | Mechanism | Stratum | Stealth |
|------|-------------|-----------|---------|---------|
| VS3-Monero | 5 | nonce sentinel + ntime | Monero | Maximum |
| VS3-Generic | 7 | nonce nibble + extranonce2 + ntime | Bitcoin/ETH | Maximum |
| BURST | 200 | Extended extranonce2 space | Bitcoin/ETH | High |
| GHOST | 200 | Difficulty-1 cover shares | Any | Medium |
| TURBO | 256 | Worker password field | Any | Lower |

## Bandwidth Capacity

| Application | Requirement | VS3 Support |
|-------------|-------------|-------------|
| Text chat | < 1 KB/s | Yes |
| File transfer | 10-50 KB/s | Yes |
| Voice (Opus) | 6-12 KB/s | Theoretical (SPEED mode only, not yet implemented) |
| Audio streaming | 16-32 KB/s | Yes |
| Web hosting | 45 KB/s | Yes |
| Low-res video | 50-100 KB/s | Yes (limited) |

## Compression

LZ4 compression is applied before encryption for payloads > 64 bytes:

```
Plaintext → LZ4 Compress → AES-256-GCM Encrypt → Fragment → Send
```

LZ4 header magic: `0x4C 0x5A 0x34 0x01` — used by receiver to detect compressed payloads.

## Additional Resources

- Full protocol specification: see `papers/visual-stratum/paper.md` (Sections 3.3 and 6)
- Test vectors: see `test-vectors/` directory

## References

1. TNZX Project (2025). Visual Stratum Protocol v1.0.
2. TNZX Project (2026). Visual Stratum 2 Protocol v2.0.
3. Belshe, M. et al. (2015). HTTP/2. RFC 7540.
4. Fette, I. (2011). The WebSocket Protocol. RFC 6455.
5. RFC 7748 — Elliptic Curves for Security (X25519).
6. RFC 8439 — ChaCha20 and Poly1305 for IETF Protocols.
