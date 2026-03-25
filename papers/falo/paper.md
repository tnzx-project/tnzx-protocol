# Falo: Anonymous Censorship-Resistant Coordination via Mining-Gated Zero-Knowledge Proofs

**Authors:** TNZX Project
**Contact:** tnzx@proton.me
**Date:** March 2026
**Version:** 0.1
**Status:** Design Document & Research Note
**Document type:** This is a design document, not a specification of an implemented system. It describes a research direction that builds on the Visual Stratum transport layer.

---

## Abstract

We present the design of Falo, a coordination system for human groups that aims to guarantee participant anonymity, censorship resistance, and protection against infiltration. Unlike existing secure communication tools that protect message content, Falo is designed to protect the *existence* of the group, the *identity* of its members, and the *organizational structure*.

**Note on maturity:** This document describes a system in active design — **not a production system**. The identity layer (ZK commitments, Merkle tree membership) and core data structures are prototyped. Ring signatures, blind vouching, ZK proof generation, and the trap system are in design phase with interface definitions but no production implementation. The core cryptographic primitives (ZK proofs, ring signatures) require audited third-party libraries that have not yet been integrated.

We publish this design document to invite review, critique, and collaboration. **Falo should not be relied upon for any real-world coordination until the core cryptographic modules are implemented and independently audited.**

**Relationship to Visual Stratum:** Falo is a separate research direction that uses Visual Stratum 2 as its transport layer. The maturity of VS2 (implemented, tested) does not extend to Falo. They are at different stages of development.

Of particular interest is Section 10 (Psychology and Motivation), which explores the human dimension of anonymous coordination — a topic rarely addressed in technical protocol literature.

Falo combines zero-knowledge membership proofs (Merkle tree commitments), ring signatures for anonymous messaging, blind vouching for member admission, and a novel "Proof of Time" anti-Sybil mechanism based on sustained cryptocurrency mining history. The system uses Visual Stratum 2 (VS2) [1] as its transport layer, hiding all coordination traffic within legitimate mining share submissions.

Falo explicitly does not claim invulnerability. Instead, it raises the cost of attacking organized groups from "trivial" to "expensive, risky, and non-scalable," while honestly communicating its limitations to users.

**Keywords:** anonymous coordination, zero-knowledge proofs, ring signatures, censorship resistance, anti-infiltration, proof-of-work, Stratum protocol

---

## 1. Introduction

### 1.1 The Problem

The freedom of association is a fundamental right recognized by Article 20 of the Universal Declaration of Human Rights. However, exercising this right carries increasing risks:

- **Mass surveillance.** Governments and corporations collect metadata revealing who communicates with whom [2]. Even encrypted messaging exposes social graphs.
- **Infiltration.** Agent provocateurs infiltrate movements to gather intelligence or destabilize organizations [3].
- **Betrayal.** Members under pressure (arrest, blackmail, corruption) reveal information about the group.
- **Platform dependency.** Centralized platforms (WhatsApp, Telegram, Signal) have servers that can be compelled to produce data, and endpoints that can be blocked.

### 1.2 The Fundamental Paradox

> To coordinate, people must exchange information.  
> Any information exchanged can be intercepted or betrayed.  
> The absence of information prevents coordination.

Falo does not solve this paradox — it is mathematically impossible to solve. Instead, Falo *circumvents* it:

- Information exists only when needed, not before
- Information is distributed — no single person has the complete picture
- The cost of betrayal exceeds the benefit
- Active traps make infiltration risky

### 1.3 Existing Solutions and Their Limits

| System | E2E Encryption | No Central Server | No Member List | Anti-Infiltration |
|--------|---------------|------------------|---------------|------------------|
| WhatsApp | Yes | No | No | No |
| Signal | Yes | No | No | No |
| Telegram | Partial | No | No | No |
| Briar [4] | Yes | Yes | No | No |
| **Falo** | **Yes** | **Yes** | **Yes** | **Yes** |

*Note: Falo columns reflect design properties — not currently implemented capabilities. Existing systems listed have the additional advantage of years of independent security auditing and large deployed user bases. See Section 12 for Falo implementation status.*

Every existing system stores a member list somewhere — on a server, on devices, or in the protocol state. Falo has no member list. The Merkle tree contains *commitments* (hashes), not identities. A seized server reveals nothing about who is in the group.

### 1.4 Design Contributions

This document makes the following design contributions. Implementation status for each is detailed in Section 12.

1. **Zero-knowledge group membership** *(designed; identity commitments prototyped)* — Members prove they belong to the group without revealing which member they are, using Merkle tree inclusion proofs.

2. **Blind vouching** *(designed; pending ZK circuit implementation)* — New members are admitted by existing members who do not learn the new member's identity, and vice versa.

3. **Proof of Time** *(designed; thresholds pending empirical calibration)* — A Sybil resistance mechanism that requires sustained mining activity over 30 days, replacing monetary stake.

4. **Emergent location** *(designed; algorithm not yet implemented)* — Meeting coordinates are computed as a deterministic function of all participants' encrypted contributions.

5. **Honest threat modeling** *(this document)* — Explicit, user-facing documentation of what Falo can and cannot protect against.

---

## 2. System Architecture

### 2.1 Protocol Stack

```
Layer 7: Application     Proposals, Events, Votes, Chat
Layer 6: Traps           Canary, Honeypot, Consistency checks
Layer 5: Consensus       Emergency, Quorum, ZK Vote
Layer 4: Reputation      Score, Vouching, Decay
Layer 3: Identity        ZK Commitment, Ring Signature, Nullifier
Layer 2: Encryption      ChaCha20-Poly1305, X25519, HKDF
Layer 1: Transport       Visual Stratum 2 (steganographic)
Layer 0: Proof of Work   RandomX-compatible mining
```

### 2.2 Design Principles

1. **Security by default.** No configuration required for base-level privacy.
2. **No unnecessary data.** The system never collects data it does not need.
3. **Fail secure.** On any error, the system denies access rather than falling back to an insecure mode.
4. **Minimum privilege.** Each component sees only the data required for its function.

---

## 3. Identity System

### 3.1 Zero-Knowledge Membership

Each participant generates a local identity:

$$\text{secret} \leftarrow \text{random}(256 \text{ bits})$$
$$\text{nullifier\_seed} \leftarrow \text{random}(256 \text{ bits})$$
$$\text{commitment} = H(\text{secret} \| \text{nullifier\_seed})$$

where $H$ is SHA-256 (or Blake3).

The commitment is published in the group's Merkle tree. To prove membership:

$$\pi = \text{ZK-Prove}\left(\exists\, (\text{secret}, \text{nullifier\_seed}) : H(\text{secret} \| \text{nullifier\_seed}) \in \text{MerkleTree} \right)$$

The verifier learns that $\pi$ corresponds to *some* leaf of the tree, but not *which* leaf.

### 3.2 Nullifiers (Double-Action Prevention)

For elections and other one-per-member actions, the participant computes:

$$\text{nullifier} = H(\text{nullifier\_seed} \| \text{action\_id})$$

The nullifier is deterministic: the same identity always produces the same nullifier for the same action. If two votes share a nullifier, the second is rejected as a double vote. But the nullifier reveals nothing about which member produced it.

### 3.3 Ring Signatures for Anonymous Messaging

Messages within a Falo group are signed using ring signatures [5]:

$$\sigma = \text{RingSign}(m, sk_i, \{pk_1, pk_2, \ldots, pk_n\})$$

The signature proves that *one of* the $n$ members signed message $m$, without revealing which one. The ring is the set of all active members' public keys.

---

## 4. Blind Vouching

### 4.1 Admission Protocol

To join a Falo group, a new participant must be vouched for by $k$ existing members (default $k = 2$). The vouching is blind:

1. New participant generates commitment $c = H(s \| n)$
2. New participant publishes $c$ (anonymously, via VS2)
3. Two existing members each produce a blind signature on $c$
4. New participant collects $k$ blind signatures
5. New participant proves in ZK: "I have $k$ valid blind signatures on my commitment"
6. Commitment $c$ is added to the Merkle tree

**Properties:**
- The vouchers do not know whose commitment they signed
- The new member does not know which members vouched for them
- The system verifies that exactly $k$ distinct members approved

### 4.2 Voucher Accountability

If a vouched member later triggers trap systems (Section 7), the vouchers' reputation scores are reduced. This creates a cost for careless vouching without revealing identities — the reputation system operates on pseudonymous scores linked to Merkle tree positions.

---

## 5. Proof of Time

### 5.1 Motivation

Traditional Sybil resistance mechanisms require financial stake: deposit money to prove commitment. This excludes the people who most need anonymous coordination tools — those without economic resources.

Falo replaces monetary stake with *temporal stake*: sustained mining activity over a minimum period.

### 5.2 Requirements

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| `MIN_MINING_DAYS` | 30 | Sustained commitment, not burst |
| `MIN_HASHES` | 1,000,000 | ~0.5–3 hours CPU mining at typical RandomX rates; threshold subject to empirical calibration |
| `MIN_CONSISTENCY` | 70% | Active 70% of days in the period |
| `MAX_ANOMALY_SCORE` | 30 | No suspicious behavioral patterns |

### 5.3 Properties

**Time cannot be transferred or fabricated.** A 30-day mining history cannot be purchased as a credential, transferred between identities, or fabricated retroactively. It requires actual computation spread over calendar time.

**Consistent behavior cannot be faked indefinitely.** The anomaly detection system monitors mining patterns. A bot producing perfectly regular shares at exact intervals will score higher anomaly than a human with natural variance.

**Scalable cost for attackers.** To infiltrate a Falo with $N$ identities, the attacker must maintain $N$ mining setups for 30 days each. The cost scales linearly with $N$ and cannot be parallelized in time (only in hardware).

**Known limitation: rented hashrate.** An attacker with access to large-scale rented hashrate (e.g. via mining rental services) can run $N$ identity setups in parallel on rented hardware, reducing the real-world cost of a Sybil attack proportionally. Proof of Time is most effective against commodity CPU adversaries — the intended threat model for at-risk users in resource-constrained environments. Against well-funded nation-state actors with access to industrial hashrate, it should be combined with social vouching (Section 4.3) and the anomaly detection layer (Section 7).

### 5.4 Comparison

| Mechanism | Excludes Poor? | Time-Bounded? | Transferable? | Scalable Attack? |
|-----------|---------------|--------------|--------------|-----------------|
| Financial stake | **Yes** | No | Yes (buy account) | Yes (buy accounts) |
| Phone number | Somewhat | No | Yes (buy SIMs) | Yes (SIM farms) |
| Social vouching only | No | No | N/A | Yes (social engineering) |
| CAPTCHA | No | No | N/A | Yes (CAPTCHA farms) |
| **Proof of Time** | **No** | **Yes (30 days)** | **No** | **Linear cost** |

---

## 6. Consensus and Coordination

### 6.1 Emergent Proposals

Decisions in Falo are not "made" by any authority. They emerge through collective action:

1. A member publishes a proposal (ring-signed — anonymous)
2. Other members add support (+1, each ring-signed)
3. If support count < threshold before deadline → proposal expires
4. If support ≥ threshold → proposal activates
5. Members who wish to participate submit ZK commitments
6. If commitments ≥ quorum → event materializes

No one "decides." The proposal either reaches critical mass or it doesn't.

### 6.2 Anonymous Verifiable Voting

For formal decisions:

1. Compute nullifier: $\text{nullifier} = H(\text{nullifier\_seed} \| \text{election\_id})$
2. Generate ZK membership proof
3. Encrypt vote
4. Publish $(\text{encrypted\_vote}, \text{nullifier}, \pi)$

Verification:
- $\pi$ valid → legitimate member
- Nullifier not seen before → first vote
- Vote counted

Nobody knows who voted what. The result is mathematically verifiable.

### 6.3 Emergent Location

For physical gatherings, the meeting location does not exist before the event:

1. Each confirmed participant contributes encrypted coordinates
2. When all contributions are received, a deterministic algorithm computes the meeting point as a function of ALL inputs
3. No single participant could predict the result
4. Progressive revelation: city → zone → neighborhood → address (time-locked)

This prevents informants from pre-positioning surveillance at a known location.

---

## 7. Trap System

Falo includes active countermeasures against infiltration. **Specific trap implementations are not publicly documented** — publishing them would allow adversaries to circumvent them.

General principles:

- Each Falo instance can deploy different trap configurations
- Traps change over time
- Triggering a trap flags the actor
- No automatic action — humans decide the response
- Trap results inform reputation scores

### 7.1 Trap Categories (General)

| Category | Principle |
|----------|-----------|
| **Canary** | Unique information given to each suspected member; leakage identifies the source |
| **Honeypot** | Deliberately attractive targets that only an adversary would approach |
| **Consistency** | Cross-referencing behavior patterns that honest members wouldn't exhibit |

---

## 8. Transport

### 8.1 Visual Stratum 2

Falo is designed to use VS2 [1] as its primary transport. VS2 transport integration is at design phase (see Section 12). Once integrated, Falo will inherit the following properties:

- **Steganographic.** All Falo traffic will travel hidden in mining share submissions
- **Mining-gated.** Only active miners will be able to send/receive Falo messages
- **Self-funding.** Mining fees will fund the relay infrastructure
- **Undetectable.** An observer will see mining traffic, nothing more

### 8.2 LoRa Mesh Fallback

In internet blackout scenarios, Falo can fall back to LoRa mesh networking:

| Property | Value |
|----------|-------|
| Hardware | Meshtastic-compatible (~€25-50) |
| Range | 2-15 km urban, 40+ km open terrain |
| Bandwidth | 300 bps - 50 kbps |
| Power | Very low (days of battery) |
| Legal | ISM band, no license required |

Limitation: LoRa transmitters can be triangulated with specialized equipment.

### 8.3 Transport Priority

```
1. VS2 via TNZX pool (default — most stealth)
2. VS2 via other compatible pools
3. Tor + VS2 (for IP anonymity)
4. Direct P2P (same local network)
5. LoRa mesh (emergency, no internet)
```

---

## 9. Security Analysis

### 9.1 Threat Model

| Adversary | Capabilities | Falo Defense |
|-----------|-------------|-------------|
| Passive observer | Sees all network traffic | VS2 steganography |
| ISP / Government | Traffic analysis, DPI | Mining traffic as cover |
| Single infiltrator | Joins the group | Sees minimal info, traps active |
| Multiple infiltrators | Collude | Cost scales linearly (Proof of Time) |
| Corrupted member | Betrays under pressure | Distributed info — no one knows enough |
| Sybil attacker | Creates many fake identities | 30-day Proof of Time per identity |

### 9.2 Security Properties (Design Targets)

| Property | Mechanism |
|----------|-----------|
| Content confidentiality | E2E ChaCha20-Poly1305 |
| Sender anonymity | Ring signatures |
| Membership anonymity | ZK Merkle proofs |
| Censorship resistance | VS2 steganography + Mining Gate |
| Vote integrity | ZK verifiable, nullifier-based |
| Sybil resistance | Proof of Time (30 days mining) |
| Betrayal cost | Reputation system, cross-group consequences |

*These are the properties the system is designed to provide when fully implemented. No security guarantee can be made until core cryptographic components (ring signatures, ZK proofs) are implemented and independently audited. See Section 12 for current implementation status.*

### 9.3 Explicit Non-Guarantees

Falo **cannot** protect against:

- **Physical surveillance.** Cameras, tailing, ambient recording
- **Device compromise.** If your phone has malware, all bets are off
- **Coercion.** No cryptographic system resists a wrench applied with determination
- **Persistent human error.** Screenshots, careless speech, misplaced trust
- **State-level individual targeting.** Unlimited resources applied to a single target will eventually succeed

We consider honest communication of these limitations to be a security feature, not a weakness. False confidence is more dangerous than informed caution.

### 9.4 Planned User-Facing Warning (Not Yet Implemented)

When fully implemented, the system will display on first use:

```
Falo protects you from:
  ✓ Automated mass surveillance
  ✓ Large-scale infiltration
  ✓ Accidental information leaks

Falo does NOT protect you from:
  ✗ Targeted operations against you personally
  ✗ Compromise of your device
  ✗ Physical surveillance
  ✗ Your own mistakes
```

---

## 10. Psychology and Motivation

### 10.1 The Courage to Organize

> "The real value of this system may not be its technical security. It is giving people the courage to organize."

Fear paralyzes. Knowing that protection exists — even imperfect protection — changes behavior. Falo does not promise invulnerability. It promises that you are not alone, that it is not stupid to try, and that the system is on your side.

### 10.2 The Anonymity Paradox

Total anonymity means no bonds, which means no community. Strong community means bonds, which means vulnerability. Falo addresses this with optional layers:

| Layer | Description | Risk |
|-------|-------------|------|
| 0: Anonymous | Default. Maximum privacy. Cold. | Isolation |
| 1: Pseudonymous | Persistent pseudonym. Build visible reputation. | Behavioral correlation |
| 2: Inner circle | Reveal identity to max 5 people (opt-in). | If one falls, you're exposed |

Each layer is a conscious choice by the participant, with explicit risk disclosure.

### 10.3 Long-Term Engagement

The system must remain useful for years, not just during crises:

- **Progression.** Reputation grows with time and participation
- **Visible impact.** Proposals become reality through collective action
- **Community.** Anonymous but real connection with others
- **Resilience.** The system survives even if individual members cannot participate

---

## 11. Discussion

### 11.1 Ethical Considerations

Falo, like any privacy tool, is dual-use. The same properties that protect activists in authoritarian regimes could theoretically be misused. We argue that:

1. The right to free association is fundamental and should be protected by default
2. Existing tools (Tor, Signal, encrypted email) face identical dual-use concerns and are broadly legal
3. Mining Gate creates real economic cost that makes mass abuse expensive
4. The core protocol is fully transparent — all cryptographic specifications and data structures are published (exception: specific trap implementations are deliberately not published; see Section 7)
5. Endpoint compromise (lawful device access) remains available to law enforcement investigating specific individuals

### 11.2 Comparison with Secret Societies

Falo is not a tool for secrecy — it is a tool for *privacy*. The distinction matters:

- **Secrecy** hides the existence of communication
- **Privacy** protects the identity of communicators

Falo members' communications are visible on the blockchain as mining traffic. The mining pool sees valid shares. What it cannot see is the content of messages or the identity of participants. This is privacy, not secrecy — the same property provided by sealed envelopes, private conversations, and attorney-client privilege.

---

## 12. Implementation Status

| Component | Status | Notes |
|-----------|--------|-------|
| Identity system (commitments, Merkle tree) | Implemented | Core module, tested |
| Proposal/election data structures | Implemented | Core module |
| Ring signatures | Placeholder | Requires audited crypto library |
| Blind vouching | Design only | ZK circuit needed |
| VS2 transport integration | Design only | Uses existing VS2 implementation |
| ZK proof generation (snarkjs/circom) | Not started | Depends on circuit design |
| Emergent location algorithm | Design only | |
| Trap system (plugin architecture) | Interface only | Implementations not published |
| LoRa fallback | Design only | |

---

## 13. Future Work

1. **ZK circuit implementation.** Design and audit Groth16/PLONK circuits for membership proofs and voting.
2. **Ring signature library.** Integrate audited ring signature implementation (possibly from Monero's own libraries).
3. **Cross-Falo federation.** Allow members of different Falo instances to interact while maintaining group separation.
4. **Mobile client.** Lightweight client for iOS/Android with delegated mining (mine on desktop, coordinate on phone).
5. **Post-quantum preparation.** Evaluate lattice-based ZK proofs and key exchange for quantum resistance.
6. **Formal verification.** Machine-verified proofs of the protocol's security properties.

---

## 14. Conclusion

Falo does not solve the fundamental paradox of coordinated privacy — that paradox is unsolvable. Instead, it transforms the economics of attack. Infiltrating and disrupting an organized group goes from "easy, cheap, and scalable" to "expensive, risky, and linear-cost."

The system is built on three pillars: zero-knowledge proofs provide membership anonymity, Visual Stratum provides undetectable transport, and Proof of Time provides Sybil resistance without financial exclusion.

Perhaps most importantly, Falo is honest about its limitations. It tells users exactly what it can and cannot protect against. We believe this honesty is itself a security feature — because informed users make better decisions than overconfident ones.

---

## References

[1] TNZX Project. "Visual Stratum: Mining-Gated Steganographic Communication over Cryptocurrency Channels." 2026.

[2] Mayer, J., Mutchler, P., and Mitchell, J.C. "Evaluating the privacy properties of telephone metadata." *PNAS*, 113(20), 2016.

[3] Marx, G.T. "Undercover: Police Surveillance in America." University of California Press, 1988.

[4] Briar Project. "Briar: Secure Messaging, Anywhere." briarproject.org, 2017.

[5] Rivest, R.L., Shamir, A., and Tauman, Y. "How to Leak a Secret." *ASIACRYPT*, 2001.

[6] Katz, J., Kolesnikov, V., and Wang, X. "Improved Non-Interactive Zero Knowledge with Applications to Post-Quantum Signatures." *ACM CCS*, 2018.

[7] Semaphore. "Anonymous Signaling on Ethereum." semaphore.appliedzkp.org.

[8] Chaum, D. "Blind Signatures for Untraceable Payments." *CRYPTO*, 1982.

[9] Nakamoto, S. "Bitcoin: A Peer-to-Peer Electronic Cash System." 2008.

[10] Van Saberhagen, N. "CryptoNote v2.0." 2013.

[11] Dingledine, R., Mathewson, N., and Syverson, P. "Tor: The Second-Generation Onion Router." *USENIX Security*, 2004.

[12] United Nations. "Universal Declaration of Human Rights." Article 20, 1948.

---

## Appendix A: Cryptographic Primitives

| Primitive | Usage in Falo | Reference |
|-----------|--------------|-----------|
| SHA-256 | Identity commitments, nullifiers | NIST FIPS 180-4 |
| ChaCha20-Poly1305 | Message encryption | RFC 8439 |
| X25519 | Key exchange | RFC 7748 |
| Ed25519 | Signing (non-anonymous contexts) | RFC 8032 |
| HKDF-SHA256 | Key derivation | RFC 5869 |
| Groth16 / PLONK | ZK membership proofs | [6] |
| Ring signatures | Anonymous message signing | [5] |
| Blind signatures | Vouching protocol | [8] |
| Merkle tree | Membership set | Standard |

## Appendix B: Comparison with Semaphore

Semaphore [7] is the closest existing system to Falo's identity layer. Key differences:

| Feature | Semaphore | Falo |
|---------|-----------|------|
| Blockchain | Ethereum (on-chain Merkle tree) | None (local/P2P Merkle tree) |
| Transport | Standard internet | VS2 steganographic |
| Anti-Sybil | Financial (ETH gas) | Proof of Time (mining) |
| Coordination features | Signal only | Full (proposals, votes, locations) |
| Anti-infiltration | None | Active trap system |
| Target users | Ethereum developers | Non-technical activists |

Falo's identity layer could be implemented *on top of* Semaphore's circuits, but the coordination, transport, and anti-infiltration layers are novel contributions.

---

*End of paper.*


