# Falo: Anonymous Censorship-Resistant Coordination

**Version:** 0.1 | **Status:** Design Phase | **License:** AGPL-3.0

---

## Abstract

Falo is a coordination system for human groups *designed* to provide participant anonymity, censorship resistance, and protection against infiltration and betrayal. **Current status: design phase — core cryptographic modules (ring signatures, ZK proofs) are not yet implemented.** Unlike existing systems that protect only communication content, Falo protects the existence of the group itself, the identity of its members, and the organizational structure.

The system is built on three principles:

1. **Nobody knows enough to betray** — Information is distributed so no single point of failure can compromise the system
2. **Betrayal is expensive** — Economic and reputational mechanisms make betrayal costly
3. **Attackers get attacked** — Active traps identify and neutralize infiltrators

## How It Works

### Identity: Zero-Knowledge Membership

Each participant has a ZK identity:

```
identity_secret   = random(32 bytes)
nullifier_seed    = random(32 bytes)
identity_commitment = H(identity_secret || nullifier_seed)
```

The commitment is published in the group's Merkle Tree. To prove membership:

```
ZK-Proof: "I know (secret, nullifier_seed) such that
           H(secret || nullifier_seed) is a leaf of this Merkle Tree"
```

Nobody can determine which leaf corresponds to which person.

### Joining: Blind Vouching

To join a Falo, two existing members must vouch — but the vouching is blind:

1. New user generates commitment (anonymous)
2. Two members sign with blind signatures
3. New user proves in ZK they have 2 valid signatures
4. Entry granted

Result: signers don't know who they signed. The new member doesn't know who signed them. The system knows that 2 members approved.

### Decisions: Emergent Consensus

Decisions are not "made" by anyone. They emerge:

1. Someone publishes a proposal (ring signature — anonymous)
2. Others add support (+1, ring signature)
3. If support >= threshold → proposal activates
4. Participants commit (ZK commitment)
5. If commitments >= quorum → event materializes

### Voting: Anonymous and Verifiable

```
To vote:
1. Compute nullifier = H(nullifier_seed || election_id)
2. Generate ZK-proof of Merkle Tree membership
3. Publish (encrypted_vote, nullifier, proof)

Verification:
- Valid proof → legitimate member
- Unique nullifier → first vote (prevents double voting)
- Vote counted

Nobody knows who voted what. Result is mathematically correct.
```

### Location: Emergent (Does Not Exist Before The Event)

1. Each confirmed participant contributes encrypted coordinates
2. When all have contributed, deterministic algorithm computes meeting point
3. The point is a function of ALL contributions — no one could predict it
4. Progressive revelation: zone → neighborhood → address

## Transport

Falo uses Visual Stratum 2 (VS2) as its primary transport:

- Messages travel hidden in mining traffic
- Mining Gate provides Sybil resistance
- No additional server infrastructure needed

Fallback: LoRa mesh networking for internet blackout scenarios.

## Threat Model

### Protected Against

| Threat | Defense |
|--------|---------|
| Mass surveillance | VS2 steganography over Stratum |
| Traffic analysis | Mining traffic as cover |
| Single infiltrator | Sees very little, traps active |
| Multiple infiltrators | Cost scales linearly |
| Sybil attacks | Proof-of-Time (30 days mining) |

### NOT Protected Against

| Threat | Why |
|--------|-----|
| State-level targeting of individual | Unlimited resources, physical compromise |
| Device compromise | Hardware backdoors beyond crypto's reach |
| Coercion/torture | No cryptographic system can resist |
| Persistent human error | Screenshots, talking too much |

### Honesty Toward Users

Falo explicitly tells users what it can and cannot protect against. No false promises of invulnerability.

## Anti-Sybil: Proof of Time

Instead of monetary stake (which excludes those who need the tool most), Falo requires **time**:

```
MIN_MINING_DAYS: 30        (sustained mining, not burst)
MIN_HASHES: 1,000,000      (~100h CPU mining)
MIN_CONSISTENCY: 70%        (active 70% of days)
```

Time cannot be bought. Consistent behavior cannot be faked indefinitely.

## Stack

```
Layer 7: Application     (Proposals, Events, Votes, Chat)
Layer 6: Traps           (Canary, Honeypot — NOT publicly documented)
Layer 5: Consensus       (Emergency, Quorum, ZK Vote)
Layer 4: Reputation      (Score, Vouching, Decay)
Layer 3: Identity        (ZK Commitment, Ring Signature, Nullifier)
Layer 2: Encryption      (ChaCha20-Poly1305, X25519, HKDF)
Layer 1: Transport       (VS2 Steganographic over Stratum / LoRa Mesh)
Layer 0: Proof of Work   (RandomX-compatible mining)
```

## Status

- [x] Identity system (ZK commitments, Merkle tree)
- [x] Core data structures (proposals, elections)
- [ ] Ring signatures for anonymous messaging
- [ ] Blind vouching protocol
- [ ] VS2 transport integration
- [ ] ZK-proof implementation (snarkjs/circom)
- [ ] Emergent location algorithm
- [ ] Trap system (plugin architecture)

## Paper

See [papers/falo/](../../papers/falo/) for the full design document.

## References

1. TNZX Project (2026). Visual Stratum 2 Protocol.
2. Semaphore — Anonymous signaling on Ethereum.
3. Signal Protocol — E2E encryption design.
4. Briar — P2P messaging.
5. Meshtastic — LoRa mesh networking.

