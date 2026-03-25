# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in any TNZX protocol or reference implementation, please report it responsibly.

**Email:** tnzx@proton.me

**What to include:**
- Protocol and version affected
- Description of the vulnerability
- Steps to reproduce (if applicable)
- Potential impact assessment

**Response timeline:**
- Acknowledgment: within 48 hours
- Initial assessment: within 7 days
- Fix or mitigation: within 90 days of acknowledgment (coordinated disclosure)

## Scope

This security policy covers:
- Visual Stratum protocols (VS1, VS2, VS3)
- Falo coordination protocol
- Reference implementations in this repository
- Cryptographic primitives and their usage

## Out of Scope

- Endpoint security (device compromise)
- Physical attacks
- Social engineering
- Third-party implementations not in this repository

## Cryptographic Standards

All implementations in this repository use:
- `crypto.getRandomValues()` or `crypto.randomBytes()` for randomness (NEVER `Math.random()`)
- Constant-time comparison for all secret values
- Audited cryptographic libraries where available
- NIST/IETF standard algorithms (AES-256-GCM, X25519, Ed25519, HKDF-SHA256)
