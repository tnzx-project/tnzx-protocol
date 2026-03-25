# TNZX Protocol Suite

**Open protocols for censorship-resistant communication over cryptocurrency mining channels.**

---

## What is this?

TNZX is a family of protocols that exploit the inherent randomness of cryptocurrency mining traffic to create covert communication channels. Mining shares — legitimate proof-of-work submissions — carry hidden encrypted payloads that are entropy-equivalent to normal mining data — see the design paper (Section 7.2) for the information-theoretic argument.

The key innovation is **Mining Gate**: communication bandwidth is mathematically bound to proof-of-work. You must mine to message. This creates anti-spam, economic sustainability, and censorship resistance in a single mechanism.

## Project Status

This repository contains protocol specifications, a design paper, and a reference implementation. The project is in active development. Some components are production-tested; others are at design stage.

| Component | Status | Notes |
|-----------|--------|-------|
| Stratum steganographic embedding (VS1/VS2/VS3) | **Implemented and tested** | Core encoder/decoder, all 3 versions |
| E2E encryption (X25519 + AES-256-GCM) | **Implemented and tested** | Session and one-shot modes, replay protection |
| Mining Gate (PoW-gated access) | **Implemented and tested** | State machine, adaptive threshold |
| PNG LSB channel (VS1) | **Archived** | Proof-of-concept only; superseded by Stratum channel |
| WebSocket / HTTP/2 channels | **Specified** | Design complete, not in reference impl |
| Multi-channel adaptive routing | **Specified** | Design complete, not in reference impl |
| LZ4 compression | **Specified** | Design complete, not in reference impl |
| Falo (anonymous coordination) | **Design phase** | Identity layer prototyped; ZK proofs, ring signatures not yet implemented |
| Independent security audit | **Pending** | Internal review completed; third-party audit not yet performed |

## Protocols

| Protocol | Version | Description | Status |
|----------|---------|-------------|--------|
| [Visual Stratum 1](protocols/vs1/) | 1.0 | PNG LSB steganography over HTTPS | Archived |
| [Visual Stratum 2](protocols/vs2/) | 2.0 | Mining Gate + Stratum embedding | Implemented |
| [Visual Stratum 3](protocols/vs3/) | 3.0 | Multi-channel adaptive transport | Partially implemented (Stratum channel only) |
| [Falo](protocols/falo/) | 0.1 | Anonymous coordination via ZK proofs | Design phase |

### Evolution

```
VS1 (2025)          VS2 (2026)              VS3 (2026)
PNG steganography → + Mining Gate         → + Multi-channel transport (design)
45 KB per image     + Stratum embedding     + Adaptive mode selection (design)
HTTPS only          + Economic model        + Timing decorrelation (design)
                    + Anti-spam via PoW
```

## Key Innovations

### 1. Steganographic Mining Communication

Data is hidden within standard Stratum mining share fields (nonce, extranonce2, ntime). The share is structurally valid and accepted by any standard pool; a VS-aware pool additionally extracts the payload bytes.

```
Normal share:  { nonce: "a1b2c3d4", extranonce2: "00000001" }
VS3 share:     { nonce: "aa48656c", extranonce2: "00006c6f" }
                         ↑ sentinel  payload bytes in LSBs ↑
```

The information-theoretic argument for Stratum channel undetectability is in the design paper (Section 7.2). The PNG channel requires separate steganalysis validation.

### 2. Mining Gate (Proof-of-Work Gated Communication)

Communication requires active mining. This solves three problems simultaneously:

- **Anti-spam**: Every message has a real computational cost
- **Sustainability**: Mining fees fund the infrastructure
- **Cover traffic**: Mining traffic is economically motivated and globally distributed

### 3. Multi-Channel Adaptive Transport (Design)

VS3 specifies distribution of messages across four channels with different stealth/bandwidth tradeoffs. The reference implementation currently covers the Stratum channel only. The full multi-channel architecture is specified in the design paper.

| Channel | Bandwidth | Stealth | Direction | Implementation |
|---------|-----------|---------|-----------|----------------|
| Stratum shares | 5 B/share (Monero) · 7 B/share (Generic) | Highest | Upload | **Reference impl** |
| PNG charts (LSB) | 45 KB/image | Highest | Download | Specified |
| WebSocket | 50 KB/s | High | Bidirectional | Specified |
| HTTP/2 streams | 100 KB/s | High | Bidirectional | Specified |

### 4. Falo: Anonymous Coordination (Research)

A design for anonymous group coordination using zero-knowledge proofs, ring signatures, and Merkle tree membership. See [papers/falo/](papers/falo/) for the full design document. Falo is a research direction, not a production protocol.

## Security Properties

| Property | Mechanism | Status |
|----------|-----------|--------|
| **Confidentiality** | AES-256-GCM | Implemented, tested |
| **Key Exchange** | X25519 ECDH with ephemeral keys | Implemented, tested |
| **Forward Secrecy** | New keypair per message (one-shot mode) | Implemented, tested |
| **Replay Protection** | Nonce tracking with 5-minute TTL | Implemented, tested |
| **Undetectability (Stratum)** | Entropy-equivalent embedding | Implemented; information-theoretic argument |
| **Undetectability (PNG)** | LSB with controlled noise | Specified; formal steganalysis pending |
| **Anti-spam** | Mining Gate (PoW-gated access) | Implemented, tested |
| **Independent audit** | — | Pending |

## Papers

- [Visual Stratum: Mining-Gated Steganographic Communication](papers/visual-stratum/) — Protocol design, specification, and security analysis. Describes both implemented and specified components.

### Research Notes

- [Falo: Anonymous Censorship-Resistant Coordination](papers/falo/) — Design document for zero-knowledge group coordination over mining channels. Core cryptographic modules (ring signatures, ZK proofs) are in design phase. Of particular interest: Section 10 explores the human psychology of anonymous organizing.

## Reference Implementation

A reference implementation in Node.js is provided in [`reference-impl/`](reference-impl/). It includes:

- Steganographic encoder/decoder (VS1/VS2/VS3 Stratum embedding)
- E2E encryption (X25519 + AES-256-GCM + HKDF + replay protection)
- Mining Gate verification (PoW-gated access control)
- Test suite with regression tests (`node test.js` — no external dependencies)

**Not included in reference implementation** (specified in paper, planned for a future release):
- PNG LSB steganographic channel
- WebSocket and HTTP/2 transport channels
- LZ4 compression and padding
- Multi-channel routing and timing decorrelation
- Dummy traffic generation

## Test Vectors

Interoperability test vectors are provided in [`test-vectors/`](test-vectors/) for all protocol versions.

## Demo

A standalone proof-of-concept pool and client is available at [tnzx-project/tnzx-pool-demo](https://github.com/tnzx-project/tnzx-pool-demo).

It demonstrates the complete VS3 transport round-trip — ghost share encoding, frame reassembly, and bidirectional delivery — running locally with no Monero daemon and no external dependencies. Two parties can exchange messages through the pool using three terminal windows.

## Comparison with Existing Systems

This table compares design properties, not deployment maturity. Tor and Signal are battle-tested systems with years of independent auditing and massive user bases — advantages that Visual Stratum does not have.

| System | Undetectable Traffic | No KYC | Spam-Resistant | Self-Funding | Maturity |
|--------|---------------------|--------|----------------|--------------|----------|
| Tor (+obfs4) | Disguised | Yes | No | Grants | 20+ years, extensively audited |
| Signal | No (identifiable) | Phone # | No | Grants+Foundation | 10+ years, audited |
| I2P | Partially | Yes | No | Donations | 20+ years, partially audited |
| Bitmessage | Broadcast | Yes | Partial | No | 10+ years, not audited |
| **Visual Stratum** | **Economic cover** | **Yes** | **Yes (PoW)** | **Yes (mining)** | **New (2025), not yet audited** |

Visual Stratum's advantage is undetectable transport (real mining traffic, not synthetic cover). Its current disadvantages are a small user base, no independent audit, and the requirement to actively mine. We consider honest acknowledgment of these limitations to be essential for a project targeting users in high-risk environments.

## Applications

See [APPLICATIONS.md](APPLICATIONS.md) for intended use cases — journalists, activists, human rights defenders, and populations under censorship.

## License

LGPL-2.1. See [LICENSE](LICENSE).

## Citation

```bibtex
@misc{tnzx2026vs,
  title={Visual Stratum: Steganographic Communication via Cryptocurrency Mining},
  author={TNZX Project},
  year={2026},
  url={https://github.com/tnzx-project/tnzx-protocol}
}
```

## Contact

- Protocol questions: tnzx@proton.me
- Security issues: See [SECURITY.md](SECURITY.md)


