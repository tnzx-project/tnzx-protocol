# Test Vectors

Static interoperability vectors for verifying cross-implementation compatibility.
Each file contains a set of input/output pairs that any conforming implementation
must reproduce exactly.

| File | Protocol | Coverage |
|------|----------|----------|
| `vs1-vectors.json` | VS1 — PNG LSB | Encode/decode round-trip |
| `vs2-vectors.json` | VS2 — Stratum embedding | Encode/decode round-trip |
| `vs3-vectors.json` | VS3 — Ghost share (V3-constrained, V3-full) | Embedding only |

## VS3 Live End-to-End Test

For VS3-constrained (Monero profile), a live end-to-end test is provided in
[tnzx-pool-demo/test-ghost.js](https://github.com/tnzx-project/tnzx-pool-demo).
It demonstrates a complete ghost share session: frame construction, chunked
transmission over Stratum, pool reassembly, and payload verification.

Static interoperability vectors covering full frame round-trips (header +
encryption + fragmentation) are planned for a future release.
