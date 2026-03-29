# Contributing to TNZX Protocol

Thank you for your interest in contributing to the TNZX protocol suite.

## How to Contribute

### Protocol Specifications
- Open an issue to discuss proposed changes before submitting
- Follow the existing format and structure
- Include security analysis for any protocol modifications
- Update test vectors when changing message formats

### Reference Implementation
- All code must use `crypto.randomBytes()` / `crypto.getRandomValues()` — never `Math.random()`
- All secret comparisons must be constant-time
- Include unit tests for new functionality
- No logging of sensitive data (keys, plaintexts, user identifiers)

### Papers
- Academic contributions welcome
- Follow standard academic paper format
- Include proper citations for prior work

## Code of Conduct

- Focus on technical merit
- Respect privacy (this project exists to protect it)
- No personally identifiable information in issues or PRs
- Security vulnerabilities: report privately (see SECURITY.md), not in public issues

## CLA

By submitting a pull request, you agree to the [Contributor License Agreement](CLA.md).
You retain copyright of your work.

## License

LGPL-2.1. Exception: Falo (protocols/falo/ and papers/falo/) is AGPL-3.0. See [LICENSE](LICENSE).
