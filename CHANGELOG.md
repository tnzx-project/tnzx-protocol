# Changelog

## [draft-01] — 2026-04-07

### Changed (Cryptography)
- **Cipher migration:** AES-256-GCM replaced by XChaCha20-Poly1305 (E2E, storage)
  and ChaCha20-Poly1305 (session/transport). Zero external dependencies.
- `crypto/xchacha20.js` — New: HChaCha20 vendored from @noble/ciphers (MIT,
  Paul Miller, audit Cure53 2023) + XChaCha20-Poly1305 encrypt/decrypt/seal/open.
- `crypto/index.js` — v2→v3: wire format `replayId(16) + salt(32) + nonce(24) + ct + tag(16)`.
- `crypto/compact-session.js` — AES-GCM → ChaCha20-Poly1305 native (session, 12B nonce).
- `crypto/DOMAIN-STRINGS.md` — New: authoritative registry of all HKDF info and AAD strings.

### Changed (Specification)
- **Encrypted type envelope:** All VS3 frames use `MSG_ENCRYPTED` (0x05) as external type;
  real type encrypted inside payload. Zero exceptions. (VS3 README, paper Appendix D.6)
- **ECDH session key:** Ghost share HMAC derived from ECDH wallet identity, not `pass` field.
  (Paper Appendix D.6)
- **knownTypes requirement:** Implementations MUST accept all defined MSG_TYPE codes.
- **Post-quantum considerations:** Added to paper Section 9.3 — hybrid ECDH+PQC KEM
  on non-steganographic channel, graceful degradation principle.
- **Paper Section 5.2:** Fixed stale HKDF info string (`tnzx-stego-e2e-v1` → `tnzx-e2e-v3`).
- **Paper Section 8.2:** Updated test count from 37 to 65 (41 main + 24 xchacha20).
- **Paper Section 10:** Removed unsubstantiated satellite/LoRa claim; replaced CRYSTALS-Kyber
  with general hybrid PQC approach.
- **Paper Appendix D.3:** Added note clarifying `miner_pass` derivation is simplified exposition;
  production uses ECDH (D.6).
- **APPLICATIONS.md:** LoRa downgraded from "design phase" to "research idea".

### Added (Tests)
- `crypto/test-xchacha20.js` — 24 tests: HChaCha20 RFC vector, AEAD roundtrip,
  authentication integrity, seal/open, AAD, edge cases, input validation.
- 4 regression tests in `test.js` for S23 audit fixes (VS2 vector, CompactSession
  replay window, empty plaintext session and one-shot).

### Verified
- All 65 reference implementation tests pass.

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
