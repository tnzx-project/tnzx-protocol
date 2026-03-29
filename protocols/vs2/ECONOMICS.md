# Visual Stratum 2 — Economic Model

**Version:** 2.0
**Status:** Implemented and tested

---

## Principle: No Token, No ICO, No Custodial Wallet

The Visual Stratum protocol does not introduce any custom token, internal credit, or custodial balance. All fees are denominated in the native PoW coin of the mining pool. The reference implementation uses a RandomX-compatible pool; operators deploying on other PoW chains use the corresponding native coin.

Users hold their own keys at all times.

## How Mining Gate Funds Communication

The core economic insight: **messaging has zero marginal cost** to the pool operator. Mining fees already cover infrastructure. Adding a covert communication channel requires no additional revenue.

```
Miner mines            → Pool fee (0.5-1% of block rewards)
  Mining Gate opens    → Messaging: FREE (funded by existing mining fees)
```

The communication channel is a byproduct of mining — not an additional service requiring its own funding model.

## Protocol-Level Economic Properties

- No custom token (uses native PoW coin of the chain)
- No internal credits or balance system
- No custodial wallet (pool never holds user funds)
- All payments are direct on-chain transactions
- Adding VS2 support requires VS2-specific code for ghost share detection, but no changes to the pool's fee calculation or payout logic

## Sustainability

The system is sustainable when mining fees cover infrastructure costs. No additional revenue stream is required for the communication protocol to function.

Break-even requires: mining fee revenue >= server + maintenance costs.

This aligns incentives: more miners = more revenue = better infrastructure = more miners.

## Why a Privacy-Native PoW Chain Is Recommended

For deployments targeting censorship-resistant communication (the primary use case), the PoW chain should ideally have:

1. **CPU-minable algorithm** — so any user can mine without specialized hardware
2. **Private transactions** — so payment metadata does not leak communication patterns
3. **Widely available mining software** — so setup friction is low

The reference implementation is designed for a RandomX-based chain meeting these criteria. See `papers/visual-stratum/paper.md` Appendix C for a full technical analysis of chain selection tradeoffs.
