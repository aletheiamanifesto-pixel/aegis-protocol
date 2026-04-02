# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability in AEGIS Protocol, please report it
responsibly by emailing:

📧 **security@aegis-protocol.dev**

Include as much of the following as possible:

- A description of the vulnerability and its potential impact
- Steps to reproduce the issue
- Affected components (smart contracts, API, crypto primitives, etc.)
- Any suggested fixes or mitigations

## Response Timeline

| Stage | Target |
|-------|--------|
| Acknowledgement | Within 48 hours |
| Initial assessment | Within 5 business days |
| Fix or mitigation plan | Within 15 business days |
| Public disclosure (coordinated) | After fix is deployed |

## Scope

The following are in scope for security reports:

- **Smart contracts** (`contracts/`, `src/`) — reentrancy, access control, integer overflow, logic flaws
- **API endpoints** (`routers/`, `main_app.py`) — authentication bypass, injection, authorization flaws
- **Cryptographic primitives** (`crypto_primitives.py`, `noir_circuits/`) — weak randomness, key leakage
- **Private key handling** — encryption/decryption, storage, transport
- **Compliance engine** — bypass of MiCA rules, velocity limit evasion
- **Dependencies** — known vulnerabilities in third-party packages

## Out of Scope

- Vulnerabilities in third-party services (Polygon, Chainlink, etc.)
- Social engineering attacks
- Denial of service via rate limiting (unless bypassing existing limits)

## Smart Contract Audit Status

⚠️ **The smart contracts in this repository have NOT been formally audited.**
Use at your own risk. Do not deploy to mainnet with real funds without a
professional security audit.

## Bug Bounty

There is currently no formal bug bounty program. Significant findings will be
acknowledged in the CHANGELOG and release notes.

## Acknowledgements

We thank all security researchers who responsibly disclose vulnerabilities.
Contributors will be credited (with permission) in this file.
