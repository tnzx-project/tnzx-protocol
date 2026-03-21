# Visual Stratum 2 (VS2)

**Version:** 2.0 | **Status:** Production | **License:** LGPL-2.1

---

## Summary

Visual Stratum 2 extends VS1 with two critical innovations:

1. **Mining Gate** — Communication bandwidth is bound to active proof-of-work
2. **Stratum embedding** — Data hidden directly in mining share fields (upload channel)

Together, these create the first communication protocol that is simultaneously censorship-resistant, spam-resistant, and economically self-sustaining.

## What's New vs VS1

| Feature | VS1 | VS2 |
|---------|-----|-----|
| Download channel | PNG LSB (45 KB/s) | PNG LSB (45 KB/s) |
| Upload channel | HTTP POST | **Stratum share embedding** |
| Anti-spam | None | **Mining Gate (PoW-gated)** |
| Economic model | None | **Mining fees fund infrastructure** |
| Sybil resistance | None | **PoW cost per identity** |

## Architecture

```
Miner Client
    │
    ├──── Stratum :3333 ────► Pool (shares + hidden payload)
    │                              ↓
    ├──── HTTPS :443 ◄──── Pool (PNG charts + hidden response)
    │
    └──── WebSocket :8443 ──► Pool (real-time messaging relay)
```

## Stratum Embedding

VS2 hides data in fields of Stratum share submissions that contain inherently random values:

| Mode | Fields Used | Bytes/Share | Stealth |
|------|-------------|-------------|---------|
| STEALTH | nonce LSB | 1 | Highest |
| STANDARD | nonce + extranonce2 | 3 | High |
| EXTENDED | nonce + extranonce2 + ntime | 7 | High |

The embedded data is entropy-equivalent to the random values these fields normally contain — see the design paper (Section 7.2) for the information-theoretic argument.

## Core Innovation: Mining Gate

See [MINING-GATE.md](MINING-GATE.md) for full specification.

The VS2 channel only functions while the user is actively mining. This single mechanism solves:
- **Spam**: Every message has real computational cost
- **Funding**: Mining fees pay for infrastructure
- **Cover traffic**: Mining traffic is economically motivated and globally distributed
- **Sybil attacks**: Fake identities require sustained hashrate

## Novelty Claim

To our knowledge, VS2 is the first protocol to combine:
1. Steganographic transport over standard network protocols
2. Mandatory proof-of-work for access control
3. Native cryptocurrency integration for self-funding
4. Censorship resistance through economic ubiquity

## Files

- `MINING-GATE.md` — Mining Gate specification
- `ECONOMICS.md` — Economic model
- See `test-vectors/vs2-vectors.json` for interoperability test data

## References

1. Fridrich, J. (2009). *Steganography in Digital Media*. Cambridge University Press.
2. Nakamoto, S. (2008). Bitcoin: A Peer-to-Peer Electronic Cash System.
3. Van Saberhagen, N. (2013). CryptoNote v2.0.
4. Bernstein, D.J. (2008). ChaCha, a variant of Salsa20.
5. Slush Pool (2012). Stratum Mining Protocol.
