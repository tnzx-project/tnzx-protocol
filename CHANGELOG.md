# Changelog

## [1.0.2] — 2026-03-31

### Added
- `crypto/compact-session.js` — Compact session encryption prototype.
  Counter-based HKDF replaces random nonce+salt, reducing encryption
  overhead from 76 to 32 bytes (-58%). Encrypted "Hello" drops from
  18 to 9 shares on VS3-Monero.
- `crypto/test-compact-session.js` — 16 unit tests for compact session
  (roundtrip, counter, tamper detection, replay protection, out-of-order).

## [1.0.1] — 2026-03-31

### Fixed (Specification)
- **README.md:** VS2 Bitcoin-style status corrected from "Implemented" to
  "Specified; demonstrated in pool demo proxy" — the reference implementation
  contains VS3-Monero, not VS2-Generic.
- **MINING-GATE.md:** Added "Supported PoW Algorithms" section clarifying that
  Mining Gate is algorithm-agnostic (operates on Stratum-reported difficulty).
  Tested with RandomX (Monero) and SHA-256d (Bitcoin).
- **VS3 README.md:** Clarified implementation status for all components with
  a detailed table (reference-impl vs pool demo vs test vectors).

### Added (Specification)
- **VS3 README.md — ghostDiffMax:** Documented pool configuration parameter
  with recommended default (`ghostDiffMax = 1`), detection pseudocode, and
  notes on vardiff false positives for Bitcoin Stratum.
- **VS3 README.md — Implementation Limits:** Documented frame reassembly
  safety limits (MAX_PENDING_MESSAGES, MESSAGE_TIMEOUT_MS, MAX_COMPLETED_MESSAGES,
  MAX_TOTAL_FRAGMENTS) with RFC 2119 keywords (MUST, SHOULD, MAY).

### Verified
- All 37 reference implementation tests pass without modification.
- Implementation limit values verified against `stego-core/index.js` constants.

## [1.0.0] — 2026-03-28 — Initial public release

First public release of the Visual Stratum protocol specification and
reference implementation.

Includes VS1 (PNG LSB), VS2 (Mining Gate + Stratum embedding), VS3
(multi-layer transport with ghost shares), and Falo (anonymous group
coordination design document).

Reference implementation: Node.js, zero dependencies, 37 unit tests,
published test vectors for VS1/VS2/VS3 interoperability.
