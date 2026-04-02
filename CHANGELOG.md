# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2024-12-01

### Added

- FastAPI backend with JWT authentication and PostgreSQL storage
- `AegisSmartAccount.sol` — ERC-4337 smart account with guardian recovery
- `AegisEUR.sol` — ERC-20 EUR stablecoin with ZK proof transfers and MiCA freeze/unfreeze
- `AegisVault.sol` — Reserve vault with 1:1 EUR backing and on-chain audit reports
- `AegisBundleVerifier.sol` — Merkle tree bundle verification for batched transactions
- `NoirVerifier.sol` — On-chain ZK proof verifier (Noir / UltraPlonk)
- MiCA compliance engine with 1 000 EUR threshold and velocity limits
- Noir ZK circuits for balance, transfer, and compliance proofs
- Pedersen commitments, MiMC hashing, and Merkle tree primitives
- Zcash-style viewing keys with selective disclosure
- Chainlink EUR/USD oracle integration
- Cross-chain bridge manager
- Transaction bundler with Merkle settlement
- Docker and Docker Compose setup
- Hardhat test suite for all Solidity contracts
- CI/CD pipelines (tests, Docker build, security scanning)

[Unreleased]: https://github.com/aletheiamanifesto-pixel/aegis-protocol/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/aletheiamanifesto-pixel/aegis-protocol/releases/tag/v0.1.0
