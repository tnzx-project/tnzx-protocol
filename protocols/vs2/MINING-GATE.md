# Mining Gate: Proof-of-Work Gated Communication

**Version:** 2.0
**Status:** Implemented and tested

---

## Concept

Mining Gate binds communication bandwidth to active proof-of-work. The VS2 covert channel functions **only** while the user is actively submitting valid mining shares via the Stratum protocol.

Stratum is the dominant mining protocol, used by pools across Bitcoin, Monero, Kaspa, Alephium, and most other PoW chains. Mining Gate can be added to any Stratum-based pool — it is pool-side software that tracks share rates per miner.

This creates a system where:
- **Spam is economically costly** — every message requires real computation
- **Infrastructure is self-funding** — mining fees pay for the relay
- **Sybil attacks are expensive** — fake identities require sustained hashrate
- **Censorship is impractical** — blocking mining traffic blocks legitimate economic activity

## State Machine

```
INACTIVE → GRACE → ACTIVE ↔ SUSPENDED
```

| State | Description | VS2 Channel |
|-------|-------------|-------------|
| INACTIVE | Never mined | Closed |
| GRACE | First 2 minutes, needs 3 valid shares | Closed |
| ACTIVE | Mining above threshold | **Open** |
| SUSPENDED | Dropped below threshold | Closed (5 min cooldown) |

## Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| `WINDOW_SIZE` | 10 min | Rolling observation window |
| `CHECK_INTERVAL` | 1-3 min | Randomized (unpredictable to attacker) |
| `THRESHOLD` | 50% | Of expected share rate |
| `GRACE_PERIOD` | 2 min | Initial connection allowance |
| `MIN_ACTIVATION` | 3 shares | Minimum to enter ACTIVE state |
| `COOLDOWN` | 5 min | Penalty period after suspension |

## Verification Algorithm

```
mining_active = (shares_in_window / expected_shares) >= THRESHOLD

expected_shares = (hashrate / difficulty) * (window_seconds)

If mining_active:
    VS2 channel = OPEN
Else:
    VS2 channel = CLOSED
```

The threshold is **adaptive** — it adjusts to each miner's historical rate, not a fixed number. A miner with 100 shares/10min needs 50 to stay active. A miner with 10 shares/10min needs 5.

## Anti-Gaming Measures

| Attack | Why It Fails |
|--------|-------------|
| Fake shares | PoW cryptographically verified against block template |
| Old shares | Timestamp must fall within observation window |
| Burst-and-stop | Checks are continuous and randomly timed |
| Wallet spoofing | Session cryptographically bound to Stratum connection |
| Predicting checks | Check interval is random (1-3 min), unpredictable |

### Supported PoW Algorithms

Mining Gate is algorithm-agnostic: it verifies that each submitted share meets
the pool's current difficulty target, regardless of the underlying hash function.
It has been tested with RandomX (Monero) and SHA-256d (Bitcoin).

The gate operates on Stratum-reported difficulty, not raw hash values. Any chain
whose Stratum implementation reports valid difficulty is compatible.

## Economic Analysis

Mining Gate creates an inherent **cost per message**:

```
At 10 kH/s CPU mining (RandomX algorithm):
- Power cost: ~0.05 kWh * $0.10 = $0.005/hour
- Messages per hour: unlimited (while mining)
- Effective cost: negligible per message, but requires sustained computation

To spam 1000 messages:
- Must maintain mining for duration of sending
- Cost: proportional to time, not message count
- Cannot be parallelized without proportional hardware
```

This makes Mining Gate fundamentally different from hashcash (one-time PoW per message): the cost is **sustained**, not per-unit.

## Comparison with Other Anti-Spam Mechanisms

| Mechanism | Cost Type | Sustained | Self-Funding | Censorship-Resistant |
|-----------|-----------|-----------|-------------|---------------------|
| CAPTCHA | Human time | No | No | No (blockable) |
| Hashcash | CPU per message | No | No | Yes |
| Token staking | Financial deposit | Yes | No | Excludes poor users |
| Phone number | Identity | No | No | No (KYC) |
| **Mining Gate** | **CPU sustained** | **Yes** | **Yes** | **Yes** |
