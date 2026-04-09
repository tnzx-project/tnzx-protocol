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
│         Chat, Files, Voice, Services, Data Transfer          │
├─────────────────────────────────────────────────────────────┤
│                    ENCRYPTION LAYER                          │
│     XChaCha20-Poly1305 + X25519 + HKDF-SHA256               │
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
| **ANON** | Stratum only | Private messaging, sensitive operations | Maximum |
| **BALANCED** | Stratum + bonus channels (delayed) | General queries, service requests | High |
| **SPEED** | All channels parallel | File transfer, bulk data | Medium |

### Automatic Mode Selection

| Message Type | Mode |
|-------------|------|
| Chat, presence, sensitive operations | ANON |
| Service queries, name resolution | BALANCED |
| File transfers, bulk data | SPEED |

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

### VS3-Monero Encoding (5 bytes/share with tnzxminer)

> **Protocol note:** Standard Monero Stratum `mining.submit` contains only
> `nonce`, `job_id`, and `result`. The `ntime` field does **not** exist in
> standard Monero Stratum — it is a Bitcoin concept. In VS3-Monero, `ntime`
> is a TNZX extension field added by tnzxminer to the submit params. Standard
> XMRig does not send this field. Standard XMRig does not produce ghost shares.
> VS3 communication requires a VS3-aware client (tnzxminer or a VS3 proxy).
> With tnzxminer: 5 bytes/share.
> Ghost shares require a TNZX-aware pool with `ghostDiffMax` configured;
> standard Monero pools reject sub-difficulty shares.

```
Share submit fields (tnzxminer, TNZX-aware pool):
┌──────────────────────────────┬──────────────────────────┐
│        NONCE  (4 bytes)      │  NTIME (TNZX ext, 4 bytes)│
│  [ 0xAA ][ b0 ][ b1 ][ b2 ] │  [ hi ][ hi ][ b3 ][ b4 ]│
│  sentinel   payload[0..2]    │  ← preserved →  payload[3..4] │
└──────────────────────────────┴──────────────────────────┘
```

- `nonce[0] = 0xAA` — sentinel, identifies ghost share at the pool (detectable; see §7.2.2 of paper)
- `nonce[1..3]` — 3 payload bytes (freely chosen; ghost share, no PoW required)
- `ntime[0..1]` — real epoch high word, preserved (TNZX extension field, not standard Monero)
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
else if nonce starts with "aa" → VS3-Monero ghost share (3–5 B)
else if extranonce2 present    → VS3-Generic ghost share (7B)
```

> **Detection note:** Standard Bitcoin miners always include `extranonce2` in
> `mining.submit`. The `extranonce2 present` branch only applies meaningfully
> when `difficulty ≤ ghostDiffMax`, which filters out regular mining shares.
> However, legitimate sub-difficulty shares (during vardiff transitions) from
> Bitcoin miners also contain extranonce2 and would be misidentified. Pools
> should apply additional heuristics or require an out-of-band capability
> negotiation before treating sub-difficulty Bitcoin shares as VS3-Generic.

Both code paths return `{"status":"OK"}` — indistinguishable to a passive observer.

### Field Profiles

VS3 defines field profiles — configurations that vary based on which Stratum
fields the miner controls. V1 and V2 apply to Bitcoin-style Stratum; V3 applies
to Monero via ghost shares + tnzxminer extensions. All profiles require a
TNZX-enhanced miner; standard XMRig does not implement any of them.

- **V1** — 1 byte/share: nonce low nibbles (any chain, tnzxminer)
- **V2** — 3 bytes/share: nonce (1 B) + extranonce2 preset (2 B) — Bitcoin-style only
- **V3** — 7 bytes/share: nonce (1 B) + extranonce2 preset (4 B) + ntime (2 B) — Bitcoin-style only

> **Monero note:** Standard Monero Stratum does not include `extranonce2` (as
> a separate submit field) or `ntime`. VS3-Monero uses ghost shares for the
> nonce channel (3 B) plus a TNZX extension field `ntime` sent by tnzxminer
> (2 B). Standard XMRig does not produce ghost shares; VS3 requires tnzxminer
> or a VS3 proxy. With tnzxminer: 5 B/share (3 B nonce + 2 B ntime).

| Profile        | VERSION | Chain          | Stratum fields                                         | B/share | Stealth | Status      |
|----------------|---------|----------------|--------------------------------------------------------|---------|---------|-------------|
| V3-constrained | `0x03`  | Monero         | nonce ghost (3 B) + ntime TNZX-ext (2 B)              | 3–5     | Maximum | Implemented (tnzxminer) |
| V3-full        | `0x03`  | Bitcoin-style  | nonce preset (1 B) + extranonce2 preset (4 B) + ntime (2 B) | 7  | Maximum | Specified   |
| V3-BURST       | `0x04`  | Any            | extranonce2 full field (base64)                        | 200     | High    | Specified   |
| V3-GHOST       | `0x05`  | Any            | difficulty-1 cover share                               | 200     | Medium  | Specified   |
| V3-TURBO       | `0x06`  | Any            | worker password field                                  | 256     | Lower   | Specified   |

Higher-bandwidth profiles (BURST, GHOST, TURBO) trade stealth for throughput.
TURBO requires a reconnect per message and produces reconnect patterns
detectable under DPI; it is intended for burst transfers where reconnect
frequency is already high.

## Bandwidth Capacity

| Application | Requirement | VS3 Support |
|-------------|-------------|-------------|
| Text chat | < 1 KB/s | Yes |
| File transfer | 10-50 KB/s | Yes |
| Voice (Opus) | 6-12 KB/s | Theoretical (SPEED mode only, not yet implemented) |
| Audio streaming | 16-32 KB/s | Yes |
| Bulk data transfer | 45 KB/s | Yes |
| Low-res video | 50-100 KB/s | Yes (limited) |

## Compression

LZ4 compression is applied before encryption for payloads > 64 bytes:

```
Plaintext → LZ4 Compress → XChaCha20-Poly1305 Encrypt → Fragment → Send
```

LZ4 header magic: `0x4C 0x5A 0x34 0x01` — used by receiver to detect compressed payloads.

## Encrypted Type Envelope

> **Implementation status:** The reference implementation provides `wrapTypedPayload()`
> and `unwrapTypedPayload()` in `stego-core/index.js` (since draft-02). The pool demo
> does not yet enforce the envelope — it currently transmits types in cleartext.
> Migration is tracked in the pool demo CHANGELOG.

All VS3 frames use `MSG_ENCRYPTED` (`0x05`) as the external type in the wire header.
The real message type is the first byte of the encrypted payload.

### Motivation

Without this envelope, the pool or any intermediate proxy can inspect the
`TYPE` byte and distinguish between chat messages, service queries,
key exchanges, and other traffic. This leaks application-level
metadata to infrastructure operators. The encrypted type envelope removes
this distinguisher: the pool sees only `0x05 ENCRYPTED` for every frame,
regardless of the actual operation.

### Wire Format

```
Wire header (cleartext, visible to pool/proxy):
┌───────┬───────┬──────────────┬─────────┬──────────┬────────────┬──────────┐
│ MAGIC │ VER   │ TYPE = 0x05  │ MSG_ID  │ FRAG_IDX │ TOTAL_FRAG │ FRAG_LEN │
│ 0xAA  │ 0x03  │ (ENCRYPTED)  │ 2B      │ 1B       │ 1B         │ 1B       │
└───────┴───────┴──────────────┴─────────┴──────────┴────────────┴──────────┘

Encrypted payload (decrypted by recipient):
┌───────────┬──────────────────────────────────┐
│ REAL_TYPE │ ...application data...           │
│ 1 byte    │ (up to 127 bytes per fragment)   │
└───────────┴──────────────────────────────────┘
```

### Encryption

- `KEY_EXCHANGE` frames use `encryptOneShot` on the recipient's X25519
  public key (derived from Ed25519 wallet identity via `walletToX25519`).
- All subsequent frames use the session key established by the key exchange.

### Coverage

Zero exceptions. All defined message types are wrapped in the encrypted
envelope:

| Real Type | Code | Wrapped in 0x05 |
|-----------|------|-----------------|
| TEXT | 0x01 | Yes |
| ACK | 0x02 | Yes |
| PING | 0x03 | Yes |
| KEY_EXCHANGE | 0x04 | Yes |
| HASHCASH | 0x06 | Yes |

The external header always carries `TYPE = 0x05`. The real type is never
exposed in cleartext on the wire.

### Observable Properties

From the pool/proxy perspective, all VS3 traffic is a homogeneous stream of
encrypted fragments. The pool cannot determine whether a user is chatting,
resolving names, performing authenticated operations, or tunneling data. Only the
message size (fragment count) and timing remain as potential side channels;
these are addressed separately by timing decorrelation (see Adaptive Modes)
and padding strategies.

### Known Types

Implementations MUST accept all types defined in the `MSG_TYPE` enum
(0x01 through 0x06). An implementation that only handles a subset of
defined types (e.g., only TEXT and ACK) will silently drop valid messages
from peers that use the full type set. Unknown type codes (> 0x06) SHOULD
be rejected with an appropriate error rather than silently discarded, to
aid debugging during protocol evolution.

## Implementation Status

| Component | Reference Impl | Pool Demo | Test Vectors | Status |
|-----------|---------------|-----------|--------------|--------|
| VS3-Monero (5 B/share, ghost shares) | Yes | Yes | Yes | Implemented |
| VS3-Generic (7 B/share, Bitcoin-style) | No | No | Yes | Specified |
| Multi-channel (WS, HTTP/2) | No | No | N/A | Specified |
| Adaptive modes (ANON/BALANCED/SPEED) | No | No | N/A | Specified |
| LZ4 compression | No | No | N/A | Specified |
| Timing decorrelation | No | No | N/A | Specified |
| High-bandwidth profiles (BURST/GHOST/TURBO) | No | No | N/A | Specified |
| Encrypted Type Envelope | Yes | No | N/A | Implemented (ref-impl + SDK) |

Components marked "Specified" are fully described in this document and the
design paper, with test vectors where applicable. Implementation is planned
for a future release.

## Pool Configuration: ghostDiffMax

VS3 ghost shares require a pool-side configuration parameter `ghostDiffMax`.
Shares with difficulty <= `ghostDiffMax` are treated as ghost shares (VS3 data
carriers) rather than mining contributions.

Recommended default: `ghostDiffMax = 1` (minimum difficulty). Ghost shares at
difficulty 1 require negligible computational effort, ensuring that bandwidth
is not constrained by PoW requirements.

Pool detection logic (pseudocode):

```
if share.difficulty > ghostDiffMax:
    process as regular mining share
elif share.nonce starts with 0xAA:
    process as VS3-Monero ghost share (5 B/share)
elif share has extranonce2 field:
    process as VS3-Generic ghost share (7 B/share)
```

## Implementation Limits

The reference implementation enforces the following safety limits:

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| MAX_PENDING_MESSAGES | 1,000 | Caps in-flight reassembly state to prevent memory exhaustion |
| MESSAGE_TIMEOUT_MS | 300,000 (5 min) | Incomplete messages older than 5 minutes are discarded |
| MAX_COMPLETED_MESSAGES | 500 | Sliding window for deduplication and replay detection |
| MAX_TOTAL_FRAGMENTS | 50 | Caps message size at ~6,400 bytes (50 x 128 bytes/fragment) |

These values are recommendations. Implementations MAY adjust them based on
deployment constraints, but SHOULD NOT remove them entirely. Removing reassembly
limits creates a denial-of-service vector: an attacker could send unbounded
incomplete fragments to exhaust receiver memory.

Implementations MUST enforce at least `MAX_PENDING_MESSAGES` and
`MESSAGE_TIMEOUT_MS` to bound memory usage. Implementations SHOULD log
discarded messages for operational monitoring.

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
