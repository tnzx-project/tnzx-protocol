# Applications and Use Cases

This document describes intended use cases for the TNZX protocol suite.

## Implementation Status

Not all described capabilities are currently available. The following table summarizes what is implemented and what is at design stage:

| Capability | Status | Notes |
|-----------|--------|-------|
| Text messaging via Stratum channel | **Implemented** | 5 B/share (Monero) · 7 B/share (Generic), high stealth |
| E2E encryption | **Implemented** | AES-256-GCM, X25519, replay protection |
| Mining Gate access control | **Implemented** | PoW-gated, adaptive threshold |
| PNG steganographic download | Specified | Not in published reference implementation |
| WebSocket / HTTP/2 channels | Specified | Not in published reference implementation |
| File transfer (SPEED mode) | Specified | Requires multi-channel transport |
| Voice communication | Theoretical | Bandwidth may suffice; not implemented or tested |
| Falo anonymous coordination | Design phase | Identity layer prototyped; ZK/ring sigs not implemented |
| LoRa mesh fallback | Design phase | Not implemented |

## Primary Use Case: Communication Under Surveillance and Censorship

The TNZX protocols are designed for individuals who need to communicate privately in environments where:

- Messaging applications are blocked (Iran, Russia, China, Belarus, Ethiopia)
- The *use* of privacy tools is itself illegal or dangerous — not just the content
- Metadata exposure (who communicates with whom) is as dangerous as content exposure
- Centralized servers can be compelled to produce data or shut down

**What works today:** Text messaging over the Stratum channel with E2E encryption and Mining Gate access control. This provides the core value proposition — covert text communication hidden within mining traffic — at low bandwidth but high stealth.

## Who This Is For

### Journalists and Whistleblowers

Reporters working in high-censorship environments need to communicate with sources and editors without revealing the existence of the communication. VS3's Stratum traffic uses the same protocol structure as standard mining activity. The information-theoretic argument for the Stratum channel is in the design paper (Section 7.2).

*Available today: text messaging via Stratum channel.*

### LGBTQ+ Activists

In jurisdictions where being LGBTQ+ is criminalized, coordination between community members is dangerous. Falo's zero-knowledge membership is designed to provide group coordination where even a seized server reveals no member identities or communications.

*Status: Falo is at design phase. The transport layer (VS2) that Falo would use is implemented.*

### Political Dissidents and Human Rights Defenders

Organized groups face infiltration as a primary attack vector. A single compromised member can expose entire networks. Falo's design aims to make infiltration expensive and limit what any single infiltrator can learn.

*Status: Falo is at design phase.*

### Populations Under Internet Blackout

The LoRa mesh networking fallback (Falo design) targets scenarios where internet access is fully cut.

*Status: Design phase. Not implemented.*

## Secondary Use Case: Infrastructure for Organizations

NGOs and civil society organizations operating in high-risk environments need:

- **Anonymous internal coordination** (Falo) without central servers that can be subpoenaed — *design phase*
- **Secure file transfer** (VS3 SPEED mode) for sensitive documents — *specified, requires multi-channel transport*
- **Voice communication** (VS3 bandwidth in SPEED mode is theoretically sufficient for Opus at 6-12 KB/s) — *not implemented or tested*

## What This Is NOT For

TNZX protocols are designed for free expression and human rights protection. They are not appropriate for illegal activity, and the Mining Gate mechanism creates an economic cost that discourages casual misuse.

The protocols do not provide:
- Legal protection (technical privacy ≠ legal immunity)
- Protection against device compromise or physical seizure
- Protection against coercion
- Invulnerability to state-level adversaries with unlimited resources

See the Falo threat model for an honest assessment of protections and limitations.

## Comparison with Alternative Approaches

This table compares design properties. Tor and Signal are mature, audited systems with large user bases — advantages that VS3 does not have. VS3's advantage is transport undetectability via economically motivated cover traffic.

| Scenario | Tor | Signal | VS3 (current) |
|----------|-----|--------|---------------|
| Blocked by ISP | Sometimes | Often | Unlikely (blocks mining) |
| Requires phone number | No | Yes | No |
| Traffic identifiable | With DPI | Yes | No (Stratum channel) |
| Works under blackout | No | No | No (LoRa planned) |
| Usable without smartphone | Yes | No | Yes (CPU miner) |
| Independently audited | Yes | Yes | **No (pending)** |
| User base | Millions | Hundreds of millions | **New** |

## Access Without Mining Hardware

Users without dedicated mining hardware can participate via:

1. **CPU mining** — any modern laptop can mine at low hashrate; sufficient for text messaging bandwidth. Desktop-level hashrate (10+ kH/s) recommended for reliable Mining Gate activation.
2. **Pool-subsidized access** — pool operators can sponsor bandwidth credits for verified NGO partners, covering the proof-of-work cost on behalf of users who cannot or do not wish to mine. *Not yet implemented.*
3. **WASM browser client** — planned future development; runs mining in-browser with no installation. *Not yet implemented.*

## Reporting Security Issues

If you discover a vulnerability that could endanger users in high-risk environments, please report it via the process in [SECURITY.md](SECURITY.md) before public disclosure.
