# Visual Stratum: Mining-Gated Steganographic Communication over Cryptocurrency Channels

**Authors:** TNZX Project
**Contact:** tnzx@proton.me
**Date:** March 2026
**Version:** 1.0
**Document type:** Technical report and protocol specification. This document has not been submitted to or reviewed by an academic conference or journal. It is published to enable independent review and collaboration.

---

## Abstract

We present Visual Stratum, a family of protocols that create covert communication channels within standard cryptocurrency mining traffic. By exploiting the inherent randomness of proof-of-work share submissions, Visual Stratum embeds encrypted messages in fields that are entropy-equivalent to legitimate mining data (see Section 7.2 for the information-theoretic argument). The protocol introduces *Mining Gate*, a novel access control mechanism that binds communication bandwidth to active proof-of-work, simultaneously solving spam prevention, economic sustainability, and censorship resistance.

Visual Stratum operates across three protocol generations. VS1 hides payloads in PNG chart images via LSB steganography. VS2 adds Stratum-level embedding and Mining Gate. VS3 specifies a multi-channel adaptive transport design with a theoretical bandwidth ceiling of ~195 KB/s when all four channels are active; the Stratum channel is implemented and tested, while the remaining channels (WebSocket, HTTP/2, PNG) are specified but not yet implemented. In maximum-stealth mode (Monero Stratum, with tnzxminer) the Stratum channel carries up to 5 bytes per share via ghost shares; with standard XMRig the Stratum embedding channel requires a TNZX-enhanced client. VS-encoded shares are structurally valid Stratum JSON processed normally by VS-aware pools; ghost shares require a TNZX-aware pool configured to accept sub-difficulty submissions.

We provide a security analysis demonstrating statistical undetectability of the Stratum embedding (encrypted payload bytes are entropy-equivalent to unmodified nonce values), perfect forward secrecy via ephemeral X25519 key exchange, and replay protection. A reference implementation of the core modules (Stratum embedding, E2E encryption, Mining Gate) validates the protocol on a RandomX-compatible testnet. The multi-channel transport layer (WebSocket, HTTP/2, PNG) is fully specified but not included in the published reference implementation.

Visual Stratum combines steganographic transport over economically motivated cover traffic, mandatory proof-of-work gating, and native cryptocurrency integration into a unified communication protocol. While prior work has explored covert channels in blockchain transactions [22][23] and proof-of-work for spam prevention [13], the combination of these properties in a system that operates within — rather than alongside — the mining protocol appears to be novel.

This paper serves as both a protocol specification and a design document. Sections describing implemented components are indicated as such; sections describing specified-but-not-yet-published components are clearly marked.

**Keywords:** steganography, Stratum protocol, covert channels, censorship resistance, proof-of-work, network steganography, privacy

---

## 1. Introduction

### 1.1 Problem Statement

Private communication systems face a fundamental tension between security and detectability. Even when message contents are encrypted, the act of communication itself reveals information:

1. **Metadata exposure.** Encrypted messaging protocols (Signal, WhatsApp) protect content but expose who communicates with whom, when, and how often. Metadata alone enables social graph reconstruction [1].

2. **Active blocking.** Governments routinely block messaging applications by identifying their network signatures. Iran, China, Russia, and others have blocked Telegram, Signal, and Tor at various times [2].

3. **Traffic analysis.** Even over Tor, message timing and volume patterns enable correlation attacks that can deanonymize users [3].

4. **Plausible deniability.** Users of privacy tools cannot deny the existence of their communications — the use of Tor or Signal is itself observable and potentially incriminating in hostile jurisdictions.

### 1.2 Key Observation

Cryptocurrency mining generates substantial legitimate network traffic with unique properties:

- **Inherently random.** Mining nonces, hash results, and share submissions contain cryptographically random data by construction.
- **High volume.** Active miners submit shares continuously — hundreds to thousands per hour depending on hashrate and difficulty.
- **Globally ubiquitous.** Mining pools operate worldwide, serving millions of miners. Mining traffic is normal internet traffic.
- **Economically motivated.** Mining has a legitimate financial purpose independent of any communication function. Blocking mining traffic has direct economic consequences.

These properties make mining traffic an ideal *cover channel* for steganographic communication. An observer monitoring a miner's network connection sees legitimate proof-of-work submissions. They cannot detect — let alone read — encrypted messages embedded within those submissions.

### 1.3 Contributions

This paper makes four contributions:

1. **Visual Stratum Protocol.** A steganographic embedding scheme that hides encrypted data in Stratum mining share fields. For Bitcoin-style Stratum: nonce low nibbles, extranonce2 preset bytes, and ntime low bytes. For Monero Stratum: nonce bytes via ghost shares, plus a TNZX extension field (`ntime`) added by tnzxminer. The entropy-equivalence undetectability argument applies with full strength to the nonce channel; it is weaker for extranonce2 (sequential distribution in standard miners) and inapplicable to the ntime extension field in Monero (which does not exist in standard Monero Stratum). See Section 7.2 for the full analysis. *Status: implemented and tested (requires tnzxminer for V2/V3/ghost modes).*

2. **Mining Gate.** A novel access control mechanism where communication bandwidth is mathematically bound to active proof-of-work. Mining Gate simultaneously provides anti-spam, Sybil resistance, economic sustainability, and censorship resistance. *Status: implemented and tested.*

3. **Multi-Channel Adaptive Transport.** A transport layer (VS3) that distributes messages across four channels (Stratum shares, PNG LSB, WebSocket, HTTP/2) with automatic mode selection and timing decorrelation. *Status: fully specified; Stratum channel implemented, remaining channels planned for a future release.*

4. **Reference Implementation.** A standalone implementation in Node.js of the core protocol modules (Stratum embedding, E2E encryption, Mining Gate), deployed and tested with real RandomX mining traffic. The reference implementation includes tests covering core functionality and regression cases.

### 1.4 Paper Organization

Section 2 surveys related work. Section 3 describes the Visual Stratum embedding protocol across three generations. Section 4 formalizes Mining Gate. Section 5 details the cryptographic design. Section 6 presents the multi-channel transport architecture. Section 7 provides security analysis. Section 8 reports implementation and evaluation results. Section 9 discusses ethical considerations. Section 10 concludes.

### 1.5 A Note on Maturity

This paper describes a system at different stages of maturity. The Stratum steganographic embedding (VS1/VS2/VS3), E2E encryption, and Mining Gate are implemented and tested in the reference implementation. The multi-channel transport (WebSocket, HTTP/2, PNG) and compression layers are fully specified; implementation is planned for a future release and not included in the current reference implementation. The Falo anonymous coordination protocol (described in a separate design document in this repository) is at design stage with partial prototype.

We believe publishing specifications alongside working implementations — rather than waiting for full completion — serves the research community better. However, we want to be explicit: **this is a working system with tested core modules and fully specified extensions planned for future releases, not a fully deployed end-user product.** Independent security audit has not yet been performed.

---

## 2. Related Work

### 2.1 Network Steganography

Network steganography hides data within legitimate network protocol fields. Prior work has explored covert channels in TCP/IP headers [4], HTTP responses [5], DNS queries [6], and VoIP streams [7]. These approaches share a limitation: the cover protocols serve no economic purpose, making their traffic volume anomalous if sustained.

Visual Stratum addresses this directly: mining traffic has independent economic value regardless of any communication function it may carry. This property is developed further in Section 2.4.

### 2.2 Image Steganography

LSB (Least Significant Bit) embedding in images is well-studied [8]. VS1 uses LSB embedding in procedurally generated mining charts — not arbitrary images. The charts contain real statistical data, providing natural cover. The key innovation is that the images serve a legitimate dashboard purpose independent of their steganographic function.

### 2.3 Blockchain and Cryptocurrency Covert Channels

Recent work has explored covert channels within blockchain systems specifically:

**Partala (2018)** [22] demonstrated that Bitcoin transaction fields (output values, change addresses) can carry covert payloads, establishing that blockchain systems provide viable steganographic carriers. However, on-chain embedding has fundamental limitations: it requires on-chain fees per message, creates permanent public records, and the capacity is constrained by block space.

**Frkat, Annessi, and Zseby (2020)** [23] systematically analyzed the embedding capacity of various blockchain fields, quantifying achievable bandwidth and detection risk. Their analysis confirms that blockchain-based covert channels are feasible but bandwidth-limited.

**Cao et al. (2023)** [24] surveyed blockchain-based information hiding techniques, identifying transaction-level, block-level, and network-level embedding approaches. The survey identifies network-layer embedding (which includes mining protocol manipulation) as an under-explored direction.

Visual Stratum differs from these approaches in a key respect: it operates at the *mining protocol* level (Stratum), not at the *blockchain transaction* level. This means messages never appear on-chain, require no transaction fees, create no permanent records, and achieve higher bandwidth (limited by share rate, not block space). The cover traffic is the mining process itself — a continuous, high-volume economic activity — rather than discrete blockchain transactions.

### 2.4 Censorship Circumvention via Steganographic Transports

Several systems disguise censored traffic as permitted protocols:

**StegoTorus** [14] tunnels Tor traffic inside steganographically modified HTTP streams. **FreeWave** [15] embeds data in VoIP traffic. **DeltaShaper** [16] uses video streaming as cover. These systems represent significant advances in censorship circumvention.

These systems share a key limitation: **their cover traffic is synthetic**. An ISP observing sustained HTTP traffic to an unusual endpoint, or a VoIP call that never ends, may flag the traffic as anomalous even without decrypting it. The cover traffic has no independent purpose — it exists solely to carry the covert channel.

Visual Stratum differs fundamentally: the cover traffic (mining) has **independent economic value**. A miner communicating via VS3 is indistinguishable from a miner who is simply mining, because they *are* simply mining — with a side channel. The mining traffic would exist even without the communication function.

### 2.5 Censorship-Resistant Messaging

**Tor** [9] routes traffic through volunteer relays with onion encryption. Tor bridges and pluggable transports (obfs4, Snowflake) make blocking harder, but Tor traffic remains identifiable with sufficient DPI investment. Tor has an enormous deployed network and years of security auditing — advantages that Visual Stratum does not yet have.

**Signal** [10] provides end-to-end encryption with excellent usability and a large user base. However, it requires phone number registration and uses identifiable network endpoints. Signal's strength is its simplicity and wide adoption — areas where Visual Stratum is currently weaker.

**I2P** [11] creates a garlic-routed overlay network. Like Tor, its traffic patterns can be identified.

**Bitmessage** [12] broadcasts all messages to all nodes, providing receiver anonymity but with severe scalability limits and no spam resistance.

### 2.6 Proof-of-Work for Spam Prevention

Hashcash [13] introduced proof-of-work as spam prevention for email, requiring a one-time computation per message. Mining Gate extends this concept from *per-message* cost to *sustained* cost: the user must maintain continuous mining activity, not merely compute a single hash. This prevents burst-and-stop attacks and creates ongoing economic commitment.

### 2.7 Comparison Summary

The following table compares *design properties*, not deployment maturity. Visual Stratum is a new system without the years of operation, independent audits, and large user bases that established tools provide. These are significant practical advantages that Visual Stratum does not yet have.

| System | Undetectable | No KYC | Anti-Spam | Self-Funding | Cover Traffic | Maturity |
|--------|-------------|--------|-----------|-------------|---------------|----------|
| Tor | No (blockable) | Yes | No | No | Synthetic | 20+ years, extensively audited |
| Signal | No (blockable) | No | No | No | None | 10+ years, audited |
| I2P | No (identifiable) | Yes | No | No | Synthetic | 20+ years, partially audited |
| Bitmessage | Partial | Yes | Partial | No | Broadcast | 10+ years, not audited |
| Hashcash+Email | N/A | Yes | Yes (per-msg) | No | None | Concept (2002) |
| **Visual Stratum** | **Partial\*** | **Yes** | **Yes (sustained)** | **Yes** | **Economic (mining)** | **New (2025), not yet audited** |

\* Stratum nonce channel: statistically undetectable under the entropy-equivalence argument (Section 7.2). VS3 ghost shares using the 0xAA sentinel are statistically distinguishable (Section 7.2.2). The ntime embedding has a weaker undetectability profile due to temporal structure (Section 7.2). PNG channel (L4): design target, pending steganalysis validation.

---

## 3. Protocol Design

Visual Stratum comprises three protocol generations, each extending the previous.

### 3.1 VS1: Image Steganography

VS1 hides encrypted payloads in the least significant bits of PNG mining chart images.

**Cover images.** The pool generates real-time mining statistics charts (hashrate history, earnings, block discoveries). These serve a legitimate dashboard function. Payload data is embedded in the LSB of each RGB channel, providing 3 bits per pixel.

**Capacity.** A 400×300 pixel PNG yields:

$$C = W \times H \times 3 \text{ bits} = 400 \times 300 \times 3 = 360{,}000 \text{ bits} = 45{,}000 \text{ bytes}$$

**Pixel permutation.** The embedding order is pseudo-randomly permuted using a Fisher-Yates shuffle seeded by the session key. Without the key, the payload bits cannot be located.

**Constant-time processing.** Both encoding and decoding always process the full image capacity, padding unused space with encrypted random data. This prevents timing side-channel leakage of actual payload size.

**Limitations.** VS1 provides only a download channel (pool→miner). Upload requires a separate HTTP POST of a miner-generated PNG, which is less natural.

### 3.2 VS2: Stratum Embedding + Mining Gate

VS2 adds two innovations: embedding data in Stratum share submissions (upload channel) and Mining Gate (access control).

**Stratum embedding.** Visual Stratum encodes payload bytes in Stratum share fields by having the miner constrain specific field bytes to payload values, then searching for a valid PoW solution within the remaining degrees of freedom. The pool validates the full PoW hash — which depends on all submitted field values — so payload bytes must be set *before* PoW search, not substituted after a solution is found.

| Mode | Fields Modified | Bytes/Share | Chain | Miner required |
|------|----------------|-------------|-------|----------------|
| V1 Stealth | nonce low nibbles (8 bits) | 1 | Any | tnzxminer |
| V2 Standard | nonce LSB + extranonce2 last 2 bytes (preset before mining) | 3 | Bitcoin-style | tnzxminer |
| V3 Monero | nonce[0]=0xAA sentinel + nonce[1..3] + ntime ext (2 bytes) | 5 | Monero (TNZX pool) | tnzxminer |

**V1** requires the miner to fix the low byte of the nonce to the payload value and search for a valid PoW solution by varying the upper bits. **V2** requires the miner to preset extranonce2 payload bytes before beginning the search; extranonce2 is part of the Bitcoin coinbase transaction and therefore fully participates in PoW validation — post-hoc substitution would break the share. **V3-Monero** uses ghost shares (submitted below pool difficulty threshold) where no PoW validity is required; `ntime` is a TNZX extension field that does not exist in standard Monero Stratum (`mining.submit` in Monero contains only `nonce`, `job_id`, and `result`). All three modes require a TNZX-enhanced miner (tnzxminer); standard unmodified XMRig does not implement any of these encoding strategies.

Ghost shares (V3 Monero) are accepted only by TNZX-aware pools with `ghostDiffMax` configured. Standard Monero pools reject sub-difficulty shares.

**Mining Gate.** See Section 4.

### 3.3 VS3: Multi-Channel Adaptive Transport

VS3 adds WebSocket and HTTP/2 channels and introduces adaptive mode selection.

> **Implementation note:** The Stratum embedding channel (L1) is implemented and tested in the reference implementation. Channels L2-L4 are fully specified but not yet implemented in this repository.

**Channels.** VS3 specifies four parallel channels:

| Channel | Bandwidth | Stealth | Direction | Cover Story | Impl. Status |
|---------|-----------|---------|-----------|-------------|-------------|
| L1: Stratum shares | 5-256 B/share | 5/5 | Upload | Normal mining | Reference impl |
| L2: HTTP/2 streams | 100 KB/s | 4/5 | Bidirectional | Pool API calls | Specified; planned |
| L3: WebSocket | 50 KB/s | 4/5 | Bidirectional | Real-time stats | Specified; planned |
| L4: PNG LSB | 45 KB/s | 5/5 | Download | Dashboard charts | Specified; planned |

Design target combined bandwidth: ~195 KB/s.

**Adaptive modes.** VS3 automatically selects transport strategy based on message type:

- **ANON mode.** Maximum stealth. Uses only L1 (Stratum shares). For private messages, escrow operations, sensitive communications.
- **BALANCED mode.** L1 primary, bonus channels with random timing delays. For DNS queries, marketplace listings.
- **SPEED mode.** All channels in parallel. Maximum bandwidth. For file transfers, web hosting.

**Timing decorrelation.** In BALANCED mode, fragments sent on bonus channels are delayed by a cryptographically random interval (500-3000ms) to prevent cross-channel correlation.

**Dummy traffic.** Configurable chaff packets injected at random intervals on all channels to prevent traffic analysis based on message timing patterns.

---

## 4. Mining Gate

Mining Gate is Visual Stratum's central innovation: communication bandwidth is bound to active proof-of-work.

### 4.1 Definition

Let $S_w(t)$ be the number of valid shares submitted by a miner in the time window $[t - w, t]$, where $w$ is the window size. Let $E_w(t)$ be the expected number of shares based on the miner's declared hashrate and pool difficulty:

$$E_w(t) = \frac{H}{D} \times w$$

where $H$ is hashrate and $D$ is difficulty.

The Mining Gate function is:

$$\text{MiningGate}(t) = \begin{cases} \text{OPEN} & \text{if } S_w(t) / E_w(t) \geq \theta \\ \text{CLOSED} & \text{otherwise} \end{cases}$$

where $\theta$ is the threshold (default: 0.5).

### 4.2 State Machine

```
INACTIVE ──[first share]──► GRACE ──[3+ shares in 2 min]──► ACTIVE
                                                                │
                                            [ratio < θ]        │
                                                │               │
                                                ▼               │
                                           SUSPENDED ──[5 min + ratio ≥ θ]──►
```

| State | VS Channel | Transition |
|-------|-----------|------------|
| INACTIVE | Closed | → GRACE on first share |
| GRACE | Closed | → ACTIVE after 3 shares within 2 minutes |
| ACTIVE | **Open** | → SUSPENDED if ratio drops below θ |
| SUSPENDED | Closed | → ACTIVE after 5-minute cooldown + ratio ≥ θ |

### 4.3 Anti-Gaming Properties

**Unpredictable verification.** The pool checks mining rate at random intervals (60-180 seconds), preventing the attacker from timing burst-and-stop strategies.

**Cryptographic share validation.** Each share is verified as valid proof-of-work against the current block template. Fake shares are rejected.

**Adaptive threshold.** The threshold adapts to each miner's historical rate, preventing hashrate spoofing. A miner claiming 100 kH/s but submitting shares at 1 kH/s rate is detected.

### 4.4 Economic Analysis

Mining Gate creates a *sustained* cost for communication, fundamentally different from per-message hashcash.

#### 4.4.1 Parametric Cost Model

The following analysis uses concrete parameters for a RandomX-based chain (2026 difficulty). We provide a parametric table so readers can evaluate costs at different hashrate levels.

**Assumptions:**
- Electricity cost: $0.10/kWh (global average for residential)
- RandomX power consumption: ~50W per 10 kH/s (modern CPU)
- Pool difficulty: adjustable per miner (typically 10,000-100,000)
- Window size: 10 minutes, threshold: 50%, minimum shares: 3

| Parameter | Low (laptop) | Medium (desktop) | High (dedicated) |
|-----------|-------------|-----------------|-----------------|
| Hashrate | 1 kH/s | 10 kH/s | 50 kH/s |
| Power draw | ~5W | ~50W | ~250W |
| Cost/hour | $0.0005 | $0.005 | $0.025 |
| Shares/10min (at diff 10k) | ~0.6 | ~6 | ~30 |
| Can activate Mining Gate? | Marginal (may not reach 3 shares in 2 min) | **Yes** | Yes |
| Stratum bandwidth (7 B/share) | ~4 B/10min | ~42 B/10min | ~210 B/10min |
| Time to send 1 KB message | ~25 min | ~2.5 min | ~30 sec |

**Key insight:** At laptop-level hashrate (1 kH/s), Mining Gate activation is marginal and message latency is high. The system is most practical at desktop-level hashrate (10+ kH/s) where activation is reliable and latency is acceptable for text messaging.

#### 4.4.2 Cost of Sybil Attack

To maintain $N$ fake identities, an attacker requires $N \times H_{min}$ sustained hashrate where $H_{min}$ is the minimum hashrate to keep each identity's Mining Gate open:

| Sybil identities | Required hashrate | Electricity cost/hour | Hardware cost (approx) |
|-------------------|------------------|----------------------|----------------------|
| 1 | 10 kH/s | $0.005 | Existing laptop |
| 10 | 100 kH/s | $0.05 | 1-2 desktops |
| 100 | 1 MH/s | $0.50 | ~10 desktops or small server |
| 1,000 | 10 MH/s | $5.00 | Dedicated infrastructure |

The cost scales linearly with $N$ and cannot be parallelized in time — each identity must maintain continuous mining for the full window duration. This is fundamentally different from one-time costs (hashcash, CAPTCHA) which can be batch-processed.

#### 4.4.3 Comparison with Token Staking

Token staking (as used in Proof-of-Stake systems) provides similar sustained-cost Sybil resistance but with a critical difference: staking requires *capital*, which excludes users without financial resources. Mining Gate requires *computation*, which any user with a CPU can provide. For the target users of Visual Stratum (activists, journalists, dissidents in resource-constrained environments), this distinction is significant.

However, token staking has an advantage: it does not require continuous power consumption. A staked identity persists without ongoing cost after the initial deposit. Mining Gate requires continuous electricity expenditure. This is a tradeoff, not a strict improvement.

#### 4.4.4 Self-Funding

Mining produces cryptocurrency rewards. Pool fees (0.5-1%) on these rewards fund the relay infrastructure. The communication system pays for itself through the economic activity of its users. No external funding is required for ongoing *relay operation* once the pool achieves mining-fee break-even. Protocol development, the reference implementation, and independent security audit require separate funding — this is the purpose of grant applications such as the one this paper accompanies.

#### 4.4.5 Limitations of the Economic Model

- **Low-hashrate users** may find Mining Gate difficult to activate and message latency unacceptable
- **Electricity cost varies** dramatically by geography ($0.02-0.30/kWh), affecting accessibility
- **The model has not been formally analyzed** using game-theoretic frameworks; the above is parametric estimation, not equilibrium analysis
- **At scale**, a large VS deployment could measurably affect pool hashrate statistics, potentially creating a distinguishing signal

### 4.5 Comparison with Other Anti-Spam Mechanisms

| Mechanism | Cost Model | Sustained | Sybil Cost | Self-Funding | Excludes Poor Users |
|-----------|-----------|-----------|-----------|-------------|-------------------|
| CAPTCHA | Human time | No | Low (farms) | No | No |
| Hashcash | CPU per message | No | Linear per msg | No | No |
| Token staking | Financial deposit | Yes | Financial | No | **Yes** |
| Phone verification | Identity | No | Market rate | No | Somewhat |
| Rate limiting | None | N/A | Zero | N/A | No |
| **Mining Gate** | **CPU sustained** | **Yes** | **Linear per identity** | **Yes** | **No (CPU only)** |

---

## 5. Cryptographic Design

### 5.1 Key Hierarchy

Visual Stratum derives communication keys from the mining wallet's key hierarchy, binding cryptographic identity to financial identity:

```
Wallet Seed (256-bit entropy)
    │
    ├── Ed25519 Keypair (signing, identity)
    │     ├── Public Key (32 bytes) — user identity
    │     └── Private Key (64 bytes) — never leaves device
    │
    └── X25519 Keypair (key exchange)
          └── Derived via birational map: u = (1+y)/(1-y) mod p
```

The Ed25519 to X25519 conversion uses the standard birational map between twisted Edwards and Montgomery curves [17]:

$$u = \frac{1 + y}{1 - y} \mod p, \quad p = 2^{255} - 19$$

### 5.2 Session Encryption

**Key exchange.** X25519 Elliptic Curve Diffie-Hellman (ECDH) establishes a shared secret between communicating parties.

**Key derivation.** HKDF-SHA256 [18] derives per-message encryption keys:

$$K = \text{HKDF}(\text{IKM} = shared\_secret,\ \text{salt} = \text{random}(32),\ \text{info} = \texttt{"tnzx-stego-e2e-v1"},\ \text{len} = 32)$$

A fresh random salt per message ensures unique keys even for the same shared secret.

**Authenticated encryption.** AES-256-GCM [19] with:
- Key: 256 bits (from HKDF)
- IV: 96 bits (random per message)
- Authentication tag: 128 bits
- Additional Authenticated Data (AAD): protocol version + message nonce

### 5.3 Perfect Forward Secrecy

For one-shot messages (no pre-established session), the sender generates an ephemeral X25519 keypair per message:

1. Generate ephemeral keypair $(e_{priv}, e_{pub})$
2. Compute shared secret: $s = \text{X25519}(e_{priv}, \text{recipient}_{pub})$
3. Derive key via HKDF with fresh salt
4. Encrypt message
5. Send: $\text{nonce} \| e_{pub} \| \text{salt} \| \text{IV} \| \text{ciphertext} \| \text{tag}$
6. **Discard** $e_{priv}$

Compromise of the recipient's long-term key cannot decrypt past messages because the ephemeral private key no longer exists.

### 5.4 Replay Protection

Each message includes a 128-bit cryptographic nonce. The receiver maintains a nonce cache with 5-minute TTL. Duplicate nonces are rejected. Cache entries expire automatically, bounding memory usage.

### 5.5 Frame Format

```
┌───────┬───────┬──────┬─────────┬──────────┬────────────┬──────────┐
│ MAGIC │ VER   │ TYPE │ MSG_ID  │ FRAG_IDX │ TOTAL_FRAG │ FRAG_LEN │
│ 0xAA  │ 0x03  │ 1B   │ 2B      │ 1B       │ 1B         │ 1B       │
├───────┴───────┴──────┴─────────┴──────────┴────────────┴──────────┤
│                        PAYLOAD (up to 128 bytes)                   │
└────────────────────────────────────────────────────────────────────┘
Header: 8 bytes. Maximum fragment payload: 128 bytes.
Maximum fragments per message: 50.
```

### 5.6 Compression

LZ4 compression [20] is applied before encryption for payloads exceeding 64 bytes. Compressed payloads are padded to 32-byte boundaries to mitigate CRIME-style compression ratio attacks [21].

---

## 6. Multi-Channel Transport (VS3)

> **Implementation note:** This section describes the VS3 multi-channel transport architecture. The multi-channel router, timing decorrelation, and dummy traffic systems are fully specified but not yet implemented in this repository. The reference implementation covers the Stratum embedding channel (L1) and the base 8-byte frame format (Section 5.5). The 13-byte transport header described below applies to multi-channel routing.

### 6.1 Channel Architecture

VS3 fragments encrypted messages and distributes fragments across available channels. The multi-channel router selects channels based on the adaptive mode (Section 3.3).

**Fragment distribution.** When routed across multiple channels, each fragment is wrapped in a 13-byte *transport header* that extends the base 8-byte frame header (Section 5.5) with channel routing metadata:

```
[magic:1][version:1][channel:1][msgId:4][fragIdx:2][totalFrags:2][dataLen:2]
```

On the Stratum-only (ANON) path, the base 8-byte header from Section 5.5 is used directly. The 13-byte transport header applies only to multi-channel (BALANCED/SPEED) routing where channel identification and wider field widths are needed.

The receiver reassembles fragments from any channel, in any order.

### 6.2 Timing Decorrelation

In BALANCED mode, fragments sent on non-primary channels are delayed by $\delta$ milliseconds:

$$\delta \sim \text{Uniform}[\delta_{min}, \delta_{max}]$$

where $\delta_{min} = 500$ms and $\delta_{max} = 3000$ms by default. The delay is generated using `crypto.randomInt()` (CSPRNG), not `Math.random()`.

This prevents an observer who monitors both Stratum and WebSocket traffic from correlating fragments of the same message across channels.

### 6.3 Dummy Traffic

Chaff packets are injected at configurable intervals (default: every 10–30 seconds, CSPRNG-selected) on random channels. Dummy packets use a reserved message ID (`0xFFFFFFFF`) and contain cryptographically random data. They are indistinguishable from real fragments to an observer without the decryption key.

The interval range was selected during implementation for three reasons: (1) a wider random range (20 seconds) is harder to fingerprint than a narrow one; (2) the lower overhead (2–6 frames/minute vs 10–12) reduces the traffic-to-hashrate ratio anomaly; (3) a hard minimum of 5 seconds prevents denial-of-service via configuration injection, while the default 10–30 second range is the post-security-review operational choice. The interval is configurable down to 5 seconds for high-stealth deployments.

---

## 7. Security Analysis

### 7.1 Threat Model

We consider four adversary classes:

| Adversary | Capabilities |
|-----------|-------------|
| **Passive network observer** | Monitors all network traffic between miner and pool |
| **Active network attacker** | Can modify, delay, drop, or replay packets |
| **Malicious pool operator** | Has access to all share submissions and server-side state |
| **Compromised endpoint** | Has access to one party's device (keys, plaintext) |

### 7.2 Statistical Undetectability: Stratum Channel (Validated)

The undetectability of the Stratum embedding follows from an information-theoretic argument that does not depend on empirical steganalysis.

Mining nonces are uniformly random 32-bit values. The LSB of a random value is uniformly distributed. VS3 replaces LSBs with payload bytes, which — being AES-256-GCM encrypted — are also uniformly distributed. Formally:

For a random nonce $n \in \{0, 1\}^{32}$ and encrypted payload byte $b \in \{0, 1\}^8$:

$$H(n \bmod 2^8) = H(b) = 8 \text{ bits (maximum entropy)}$$

No statistical test can distinguish the modified field from an unmodified one, because both contain maximum-entropy data. This argument holds for any cipher with indistinguishability from random under chosen-plaintext attack (IND-CPA), which AES-256-GCM satisfies.

**Caveat.** This argument holds cleanly for the **nonce** field: valid mining nonces are the result of a search over a cryptographically random hash function, and their distribution over the nonce space is approximately uniform. An observer cannot distinguish a nonce whose low nibbles were constrained to a payload byte from one found without constraints, because both produce maximum-entropy values in those positions.

The argument is **weaker for extranonce2 (V2)** and **does not apply to ntime in standard Monero (V3)**:

- *extranonce2 (Bitcoin-style):* Standard Bitcoin miners iterate extranonce2 as a sequential counter (0x00000000, 0x00000001, …). Its distribution is not uniform — it is monotonically increasing. Replacing the last two bytes with uniformly random encrypted payload creates a detectable distributional shift. A sufficiently motivated observer monitoring extranonce2 values across many shares could detect the transition from sequential to random. This is a known weakness of the V2 profile.

- *ntime (Bitcoin-style):* ntime is a Unix timestamp, not a random value. Replacing its low 16 bits with payload bytes introduces apparent clock drift that is statistically distinguishable from real timestamp behavior over time. This is separately discussed in Section 7.2 (Note on ntime undetectability).

- *ntime in Monero:* The `ntime` field does not exist in standard Monero Stratum. In VS3-Monero, ntime is a TNZX extension field sent by tnzxminer; its presence in a Monero `mining.submit` is itself a distinguishing signal to a sufficiently detailed Stratum analyzer.

The entropy-equivalence undetectability argument therefore applies with full strength only to the V1 nonce nibble channel.

**Note on ntime undetectability.** The `ntime` field contains a Unix timestamp, not a uniformly random value. The high 16 bits (`ntime[0..1]`) are preserved as real epoch data; only the low 16 bits (`ntime[2..3]`) are overwritten with payload bytes. Encrypted payload bytes are uniformly distributed, while legitimate `ntime[2..3]` values exhibit temporal structure (incrementing with real clock time). This creates a potential statistical distinguisher for the `ntime` field specifically. The entropy-equivalence argument applies fully to the `nonce` field; for `ntime` it provides a weaker guarantee, and the undetectability of the `ntime` embedding should be considered a design target rather than a formal result.

#### 7.2.2 Sentinel Byte Limitation (V3 Ghost Shares)

The VS3-Monero ghost share mode uses a fixed sentinel byte (`0xAA`) in `nonce[0]` to identify ghost shares at the pool. This creates a statistical distinguisher: ghost shares have `nonce[0] = 0xAA` with probability 1, while legitimate Monero shares have `nonce[0]` uniformly distributed over `[0x00, 0xFF]`. An adversary monitoring the distribution of `nonce[0]` across a miner's share stream can detect VS3 ghost share usage with high confidence after observing O(256) shares.

This is a known limitation of the current ghost share design. The pool additionally enforces `difficulty ≤ ghostDiffMax` (default: 500), which means ghost shares are submitted only at low difficulty — reducing but not eliminating the distinguishability risk.

Mitigations under consideration: (a) pool-side identification via an encrypted header in bytes 1–3, removing the need for a fixed visible sentinel; (b) randomized per-session sentinel assignment communicated out-of-band. Until a mitigation is implemented, VS3 ghost share mode should be treated as detectable by a sufficiently motivated adversary with access to the share stream. VS2 Standard mode (which modifies only LSBs without a fixed sentinel) does not have this specific limitation.

### 7.2.1 Statistical Undetectability: PNG Channel (Design Targets — Pending Validation)

The PNG LSB channel has a different security profile. Unlike the Stratum channel, where the cover data is inherently maximum-entropy, PNG pixel values have structure. The undetectability of LSB embedding in images is an empirical claim that requires steganalysis validation.

VS1 chart images are procedurally generated with controlled noise and pseudo-random pixel permutation. The design targets are:
- Chi-square test: target $\chi^2 < 3.84$ ($p > 0.05$ at 1 d.f.)
- RS analysis: target difference < 0.1
- Entropy: 8.0 bits per byte in LSB plane

**These are design targets, not validated results.** Formal steganalysis evaluation against tools such as StegExpose, RS analysis, and sample pair analysis has not yet been performed. Until this evaluation is completed, the PNG channel's undetectability should be considered a design goal, not a security guarantee. The Stratum channel should be preferred for high-risk use cases.

### 7.3 Encryption Security

| Property | Mechanism | Strength |
|----------|-----------|----------|
| Confidentiality | AES-256-GCM | 256-bit key, 2^256 brute force |
| Integrity | GCM authentication tag | 128-bit tag |
| Authentication | ECDH key binding | Shared secret authenticates parties |
| Forward secrecy | Ephemeral X25519 keys | Per-message keypair, discarded after use |
| Replay protection | 128-bit nonce + 5-min TTL cache | Duplicate nonces rejected |
| AAD binding | Protocol version + nonce in AAD | Prevents ciphertext misdirection |

### 7.4 Mining Gate Security

**Share validity.** Every share is verified as valid proof-of-work against the current block template. The pool computes the RandomX hash and checks it meets the target difficulty. Fabricating valid shares requires actual computation — there is no shortcut.

**Adaptive threshold.** The 50% threshold is relative to each miner's *own* historical rate, not a fixed number. An attacker cannot determine the exact moment of verification (random interval), making strategic hash allocation infeasible.

### 7.5 Known Limitations

1. **Bandwidth.** Stratum channel bandwidth depends on hashrate and pool difficulty. Low-hashrate miners have slow upload.
2. **Latency.** Messages in ANON mode are sent only with mining shares. If shares are infrequent, latency is high.
3. **Pool trust.** A malicious pool could selectively drop stego-bearing shares. However, it cannot *read* them (E2E encryption), and dropping valid shares reduces its own mining revenue.
4. **Long-term traffic analysis.** An adversary observing a miner's traffic pattern over weeks may detect subtle correlations between message activity and share submission patterns, though dummy traffic mitigates this.
5. **Endpoint compromise.** If a device is compromised, all cryptographic protections are bypassed. This limitation is shared by all communication systems.

---

## 8. Implementation and Evaluation

### 8.1 Reference Implementation

The reference implementation comprises three core modules in Node.js:

| Module | Function |
|--------|----------|
| `stego-core/` | V1/V2/V3 encoder, decoder, frame processing |
| `crypto/` | E2ECrypto, X25519, AES-256-GCM, HKDF, replay protection |
| `mining-gate/` | Proof-of-work gated access control |

### 8.2 Test Coverage

*Published reference implementation test coverage (`reference-impl/test.js`):*

| Category | Tests | Status |
|----------|-------|--------|
| Steganographic encoding/decoding (V1/V2/V3, framing, reassembly) | 16 | Pass |
| Cryptographic layer (ECDH, AES-256-GCM, HKDF, replay protection) | 7 | Pass |
| Mining Gate (state transitions, hashrate calculation, cleanup) | 6 | Pass |
| Regression fixes (ID generation, hashrate mutation, one-shot replay) | 8 | Pass |
| **Total published** | **37** | **All passing** |

Interoperability test vectors for V1 (full round-trip) and V2 (full round-trip) are published in `test-vectors/`. VS3 vectors cover the Stratum embedding layer (encoding only); full round-trip vectors including encryption and multi-fragment reassembly are planned for a future release.

### 8.3 Cryptographic Performance

Measured on Node.js 18, Intel i7-10700K:

| Operation | Time | Notes |
|-----------|------|-------|
| X25519 ECDH | ~0.1 ms | Native crypto module |
| AES-256-GCM encrypt (1 KB) | ~0.01 ms | Hardware AES-NI |
| HKDF-SHA256 | ~0.05 ms | Per derivation |
| LZ4 compress (1 KB) | ~0.1 ms | Pure JS |
| Ed25519 → X25519 conversion | ~0.2 ms | BigInt arithmetic |

Cryptographic overhead is negligible compared to mining computation and network latency.

### 8.4 Deployment

The Stratum embedding protocol has been deployed and tested using the reference implementation against a custom TNZX-aware pool running on a RandomX-compatible testnet with multiple Stratum difficulty tiers. Testing used the reference implementation's encoder/decoder and a TNZX pool configured to accept ghost shares. Compatibility with standard unmodified XMRig has not been tested for ghost share or V2/V3 modes; these require tnzxminer. The V1 nonce nibble embedding is designed to be compatible with standard miners in principle, but was validated in the reference implementation only, not against production XMRig builds. Multiple rounds of internal security review have been conducted; independent third-party audit is pending.

### 8.5 Implementation Notes

**Compression threshold.** The reference compression threshold is 50 bytes (Appendix A), optimized for the Stratum channel where byte density per share is low. At 50 bytes, LZ4 compression can reduce payloads below the next 32-byte padding boundary, saving one padding tier. Below 50 bytes, LZ4 overhead (~14 bytes) exceeds the compression gain.

**Noise traffic intervals.** The recommended noise interval is 10–30 seconds (see Section 6.3). The wider random range reduces the traffic-to-hashrate ratio anomaly and makes noise timing harder to fingerprint via traffic analysis.

---

## 9. Ethical Considerations

### 9.1 Dual-Use Technology

Visual Stratum, like encryption itself, is dual-use. The same properties that protect journalists and activists also potentially benefit malicious actors. We address this directly.

**Historical precedent.** PGP (1991), Tor (2002), Signal (2014), and end-to-end encryption in general faced identical concerns. The consensus of legal systems in democratic nations is that publication of cryptographic software constitutes protected speech (Bernstein v. United States, 1999).

**Design choices favoring legitimate use.**
- Mining Gate creates real economic cost for communication, making mass abuse expensive
- The system is transparent: all protocol specifications and reference code are published
- No anonymity features are hidden — the security properties are documented honestly

### 9.2 What Visual Stratum Does Not Do

- **Does not provide illegal services.** The protocol is infrastructure, not a service.
- **Does not host content.** Users host their own content on their own hardware.
- **Does not hold funds.** All cryptocurrency operations are non-custodial.
- **Does not prevent law enforcement.** Endpoint compromise (lawful device access) bypasses all network-level protections.

### 9.3 Honest Limitations Disclosure

We believe researchers and tool developers have an obligation to honestly communicate what their systems can and cannot protect against. Visual Stratum cannot protect against:

- Physical surveillance
- Device compromise (malware, hardware backdoors)
- Coercion or legal compulsion to reveal keys
- Quantum computing (future concern; post-quantum key exchange is planned)

---

## 10. Conclusion

Visual Stratum demonstrates that high-bandwidth covert communication channels can be constructed within existing cryptocurrency mining infrastructure, requiring no additional network endpoints, no identifiable protocol signatures, and no separate funding model.

The key insight is that mining traffic is not merely a disguise — it is genuine economic activity that happens to carry a side channel. This makes Visual Stratum fundamentally different from prior steganographic systems that create synthetic cover traffic.

Mining Gate extends proof-of-work from a one-time cost (hashcash) to a sustained commitment, solving spam, Sybil attacks, and infrastructure funding simultaneously.

Future work includes formal verification of the protocol, post-quantum key exchange (CRYSTALS-Kyber), satellite and LoRa transport for connectivity-deprived regions, cross-pool federation for message routing across independent mining pools, and independent third-party security audit.

We are also developing Falo, an anonymous coordination system built on VS2 transport that uses zero-knowledge membership proofs, ring signatures, and a novel "Proof of Time" anti-Sybil mechanism based on sustained mining history rather than financial stake. A design document is available in this repository. Falo explores an under-examined question in privacy tool design: the psychology of anonymous organizing — how technical protection affects the human courage to coordinate (see Falo design document, Section 10).

---

## References

[1] Mayer, J., Mutchler, P., and Mitchell, J.C. "Evaluating the privacy properties of telephone metadata." *PNAS*, 113(20), 2016.

[2] Ensafi, R., et al. "Analyzing the Great Firewall of China over space and time." *PoPETs*, 2015(1).

[3] Johnson, A., et al. "Users Get Routed: Traffic Correlation on Tor by Realistic Adversaries." *ACM CCS*, 2013.

[4] Murdoch, S.J. and Lewis, S. "Embedding Covert Channels into TCP/IP." *Information Hiding*, 2005.

[5] Dyatlov, A. and Castro, S. "Exploitation of Data Streams Authorized by a Network's Security Policy." *EICAR*, 2003.

[6] Nussbaum, L., et al. "On the use of DNS tunneling." *SAR-SSI*, 2009.

[7] Mazurczyk, W. and Szczypiorski, K. "Steganography of VoIP Streams." *LNCS*, 5332, 2008.

[8] Fridrich, J. *Steganography in Digital Media: Principles, Algorithms, and Applications*. Cambridge University Press, 2009.

[9] Dingledine, R., Mathewson, N., and Syverson, P. "Tor: The Second-Generation Onion Router." *USENIX Security*, 2004.

[10] Marlinspike, M. and Perrin, T. "The Signal Protocol." Signal Foundation, 2016.

[11] Zantout, B. and Haraty, R. "I2P Data Communication System." *ICN*, 2011.

[12] Warren, J. "Bitmessage: A Peer-to-Peer Message Authentication and Delivery System." 2012.

[13] Back, A. "Hashcash — A Denial of Service Counter-Measure." 2002.

[14] Weinberg, Z., et al. "StegoTorus: A Camouflage Proxy for the Tor Anonymity System." *ACM CCS*, 2012.

[15] Houmansadr, A., Brubaker, C., and Shmatikov, V. "The Parrot is Dead: Observing Unobservable Network Communications." *IEEE S&P*, 2013.

[16] Barradas, D., Santos, N., and Rodrigues, L. "DeltaShaper: Enabling Unobservable Censorship-Resistant TCP Tunneling over Videoconferencing Streams." *PoPETs*, 2017.

[17] Bernstein, D.J. "Curve25519: New Diffie-Hellman Speed Records." *PKC*, 2006.

[18] Krawczyk, H. and Eronen, P. "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)." RFC 5869, 2010.

[19] Dworkin, M. "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM)." NIST SP 800-38D, 2007.

[20] Collet, Y. "LZ4 — Extremely Fast Compression." 2011.

[21] Rizzo, J. and Duong, T. "The CRIME Attack." Ekoparty, 2012.

[22] Partala, J. "Provably secure covert communication on blockchain." *Cryptography*, 2(3):18, 2018.

[23] Frkat, D., Annessi, R., and Zseby, T. "Chainchannels: Private botnet communication over public blockchains." *IEEE International Conference on Blockchain and Cryptocurrency (ICBC)*, 2020.

[24] Cao, Y., et al. "A survey of blockchain-based information hiding." *Journal of Information Security and Applications*, 71:103385, 2023.

---

## Appendix A: Protocol Constants

```
// Magic bytes
MAGIC_BYTE          = 0xAA

// Protocol versions
VERSION_V1          = 0x01    // Nonce LSB only
VERSION_V2          = 0x02    // + extranonce2
VERSION_V3          = 0x03    // nonce sentinel + ntime (5 bytes/share, Monero Stratum)
VERSION_V3_BURST    = 0x04    // Extended extranonce2 (200 B/share)
VERSION_V3_GHOST    = 0x05    // Difficulty-1 cover shares
VERSION_V3_TURBO    = 0x06    // Worker password field (256 B/share)

// Message types
MSG_TEXT             = 0x01
MSG_ACK              = 0x02
MSG_PING             = 0x03
MSG_KEY_EXCHANGE     = 0x04
MSG_ENCRYPTED        = 0x05
MSG_HASHCASH         = 0x06

// Crypto constants
KEY_LENGTH           = 32     // 256 bits
IV_LENGTH            = 12     // 96 bits (GCM standard)
AUTH_TAG_LENGTH      = 16     // 128 bits
SALT_LENGTH          = 32     // HKDF salt
NONCE_LENGTH         = 16     // Replay protection nonce

// Limits
MAX_PENDING_MESSAGES = 1000
MAX_COMPLETED_MESSAGES = 500
MAX_TOTAL_FRAGMENTS  = 50
MESSAGE_TIMEOUT_MS   = 300000 // 5 minutes
NONCE_TTL_MS         = 300000 // 5 minutes
COMPRESS_THRESHOLD   = 50     // Min bytes for LZ4 (optimized for Stratum byte density)
PAD_GRANULARITY      = 32     // CRIME mitigation
```

## Appendix B: Test Vectors

### B.1 X25519 Key Exchange (RFC 7748)

```
Alice Private: 77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a
Alice Public:  8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a
Bob Private:   5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb
Bob Public:    de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f
Shared Secret: 4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742
```

### B.2 AES-256-GCM (NIST SP 800-38D)

The reference implementation uses AES-256-GCM authenticated encryption with the following parameters:

```
Algorithm:        AES-256-GCM (NIST SP 800-38D)
Key derivation:   HKDF-SHA256 (RFC 5869), 256-bit output
Key size:         256 bits (32 bytes)
IV size:          96 bits (12 bytes), random per message
Auth tag:         128 bits (16 bytes)
```

For standard interoperability test vectors, see NIST SP 800-38D Appendix B, Test Case 4 (256-bit key). The reference implementation passes these vectors via Node.js `crypto.createCipheriv('aes-256-gcm', ...)`.

### B.3 VS3 Stratum Embedding (Monero Stratum, 5 bytes/share)

```
Input:
  ntime_hex: "65b2a100"
  payload:   [0xAA, 0xBB, 0xCC, 0xDD, 0xEE]   (5 bytes)

Embedding:
  nonce[0]   = 0xAA  (MAGIC_BYTE sentinel — identifies ghost share at pool)
  nonce[1]   = 0xAA  (payload[0])
  nonce[2]   = 0xBB  (payload[1])
  nonce[3]   = 0xCC  (payload[2])
  ntime[0]   = 0x65  (preserved — real epoch high word)
  ntime[1]   = 0xB2  (preserved)
  ntime[2]   = 0xDD  (payload[3])
  ntime[3]   = 0xEE  (payload[4])

Output:
  nonce:  "aaaabbcc"
  ntime:  "65b2ddee"

Extraction (pool side):
  payload[0] = nonce[1] = 0xAA
  payload[1] = nonce[2] = 0xBB
  payload[2] = nonce[3] = 0xCC
  payload[3] = ntime[2] = 0xDD
  payload[4] = ntime[3] = 0xEE
```

Additional test vectors in machine-readable format: `test-vectors/vs3-vectors.json`.

### B.4 Mining Gate State Transitions

```
T+0s:    Connect. State: INACTIVE
T+5s:    Submit share 1. State: GRACE
T+15s:   Submit share 2. State: GRACE
T+25s:   Submit share 3. State: ACTIVE ← Channel opens
T+700s:  No shares for 10 min. Ratio: 0.3 < 0.5. State: SUSPENDED ← Channel closes
T+1000s: Resume mining. 5 shares in 2 min. Ratio: 0.6 ≥ 0.5. State: ACTIVE
```

## Appendix C: Cross-Chain Generalizability

### C.1 Applicability Beyond Monero

Visual Stratum's embedding technique is not inherently Monero-specific. Any Stratum-compatible proof-of-work chain with miner-controlled nonce fields is a potential transport. We analyze the feasibility across major PoW chains:

| Chain | Nonce | Extranonce2 | Miner Control | VS Bytes/Share | Practical? |
|-------|-------|-------------|---------------|---------------|------------|
| **Monero** (RandomX) | 4B | 4B | Full (CPU software) | 7 | **Yes** |
| **Bitcoin** (SHA-256d) | 4B | 4-8B | None (ASIC firmware) | 6-8 (theoretical) | No (see C.2) |
| **Kaspa** (kHeavyHash) | 8B | variable | Partial (GPU) | ~8 | Feasible |
| **Alephium** (Blake3) | 24B | variable | Partial (GPU) | ~24 | Feasible |

### C.2 The ASIC Control Problem

Bitcoin mining uses application-specific integrated circuits (ASICs) with proprietary firmware. The miner does not control how nonce and extranonce2 values are generated. This creates a fundamental barrier:

1. **No bidirectional embedding.** The miner cannot inject payload bytes into the nonce before hashing — the ASIC generates nonces internally.
2. **Proxy interception is invalid.** Modifying extranonce2 after ASIC hashing invalidates the share, since the hash was computed with different field values.
3. **Custom firmware is niche.** Open-source ASIC firmware (e.g., Braiins OS) exists for select models but covers a small fraction of the hashrate.
4. **Stratum v2 extensions.** The emerging Stratum v2 protocol includes explicit extension fields suitable for VS embedding, but adoption remains limited as of 2026.

Additionally, Bitcoin's transparent blockchain means transaction metadata (sender, receiver, amounts) is publicly visible, eliminating the privacy properties that make Monero suitable as both transport and payment layer.

### C.3 CPU/GPU-Minable Chains

Chains minable by general-purpose hardware (Kaspa, Alephium, Wownero) do not suffer the ASIC control problem. The miner software can embed VS payloads before hashing. However, multi-chain VS raises practical questions:

- **Cross-chain identity.** How does a Monero miner discover the VS address of a Kaspa miner? A cross-chain identity bridge does not currently exist and would require novel protocol design.
- **Cross-pool routing.** Messages between different chains require a bridge between pools — adding infrastructure complexity and trust assumptions.
- **Marginal value.** Any user capable of mining Kaspa can also mine Monero on the same hardware (CPU/GPU). There is no population of users who *can* mine Kaspa but *cannot* mine Monero.

### C.4 The Resilience Fallback Argument

The sole scenario where cross-chain VS provides value that Monero-native VS cannot:

> A government specifically blocks Monero's RandomX algorithm (e.g., via deep packet inspection of RandomX-specific patterns) while permitting other PoW mining.

In this scenario, users could switch to an alternative chain as a VS transport while retaining end-to-end encryption and the same identity keys.

We assess this scenario as **theoretically valid but practically unlikely**, because:
- Blocking RandomX specifically (rather than all mining) requires sophisticated DPI capabilities
- Users in such environments likely also have VPN/Tor access for mining traffic
- The infrastructure (VS-compatible pool on alternative chain) must already exist

### C.5 Architecture for Future Extension

The VS3 implementation separates the protocol into two layers:

- **Upper layer** (~80% of code): framing, encryption, compression, fragmentation — chain-agnostic
- **Lower layer** (~20%): six embedding/extraction methods — chain-specific

Extending VS3 to a new chain requires implementing only the lower-layer `Channel` interface (~50 lines per chain). The estimated effort is 1-2 days when demand materializes, not months of speculative development.

### C.6 Conclusion

Visual Stratum is a **general technique** applicable to any PoW mining protocol with miner-controlled random fields. However, Monero is the optimal transport due to full software control (CPU mining), privacy-native blockchain, and low barrier to entry. Cross-chain support is a resilience fallback, not a communication feature, and should be implemented only when real-world demand or regulatory pressure creates a concrete need.

---

*End of paper.*



