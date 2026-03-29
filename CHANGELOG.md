# Changelog

All notable changes to the Entanglement Transfer Protocol will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [5.0.0] - 2026-03-25

### Added
- LTPAnchorRegistry v5 deployed on GSX Testnet (Chain ID `103115120`)
  - UUPS Proxy: `0xB29d8BFF4973D1D7bcB10E32112EBB8fdd530bF4`
  - Implementation: `0xADf01df5B6Bef8e37d253571ab6e21177aCb7796`
  - MultiSig (2-of-2): `0x0106A79e9236009a05742B3fB1e3B7a52F44373D`
  - Timelock (60s): `0x7C2665F7e68FE635ee8F10aa0130AEBC603a9Db8`
- Author attribution in contract `version()` return

### Changed
- Contract version bumped from 4 to 5
- All 84 Solidity tests passing with v5 assertions
- Full end-to-end PQC pipeline verified before deployment

## [4.0.0] - 2026-03-25

### Added
- Verified production deployment on GSX Testnet (block 687137)
- 84 Solidity tests: unit, integration, fuzz (256 iterations), invariant (3,840 calls), cross-parity
- `FormalVerification.t.sol` — fuzz testing + invariant testing
- `CrossParityTest` — Python ↔ Solidity state machine validation
- `DeployMainnet.s.sol` — configurable N-of-M + timelock for production
- `UpgradeV4.s.sol` — 4-step governance-controlled UUPS upgrade script

### Changed
- Test suite expanded from 821 to 1,251+ (1,167 Python + 84 Solidity)
- All four pillars verified end-to-end before on-chain deployment

## [3.2.0] - 2026-03-24

### Added
- TimelockController governance (OpenZeppelin) between MultiSig and Registry
- Governance chain: MultiSig → Timelock (60s) → Registry

### Changed
- Registry admin transferred from MultiSig to Timelock
- 60-second delay on testnet (production: 24-48 hours)

## [3.1.0] - 2026-03-23

### Added
- **Smart Contracts:**
  - `LTPAnchorRegistry.sol` — on-chain anchor registry with UUPS proxy pattern
  - `LTPMultiSig.sol` — N-of-M multi-signature governance wallet
  - `ILTPAnchorRegistry.sol` — registry interface with events and errors
  - `Deploy.s.sol`, `DeployTestnet.s.sol` — deployment scripts
  - `contracts.yml` CI workflow — 3-stage pipeline (forge → pytest → integration)
  - Initial GSX Testnet deployment (Chain ID `103115120`)
- **New Python modules (40+):**
  - `src/ltp/anchor/` — EntityState machine, AnchorSubmission, AnchorClient with circuit breaker
  - `src/ltp/dual_lane/` — SHA3-256 canonical + BLAKE3-256 internal lane separation
  - `src/ltp/merkle_log/` — RFC 6962 Merkle tree, signed tree heads, inclusion/consistency proofs
  - `src/ltp/network/` — gRPC client/server with 7 RPCs, RemoteNode proxy
  - `src/ltp/storage/` — Memory, SQLite (WAL mode), Filesystem shard stores
  - `src/ltp/verify/` — Pure verification SDK (no state, no side effects)
  - `domain.py` — 11 domain separation tags (`GSX-LTP:*`)
  - `encoding.py` — Deterministic canonical binary serialization
  - `envelope.py` — ML-DSA-65 signed envelope wrapper
  - `receipt.py` — Approval receipts with RFC 8392 temporal semantics
  - `sequencing.py` — Per-signer monotonic sequence tracking
  - `governance.py` — SignerPolicy, ApprovalRule framework
  - `evidence.py` — Self-contained trust artifact bundles
  - `hybrid.py` — ML-DSA-65 + Ed25519-SHA512 composite signatures
  - `entity.py` — Entity model with `canonicalize_shape()` media type normalization
  - `run_trust_layer.py` — Full demo entry point covering all trust layer features

### Changed
- Dual-lane architecture enforced: SHA3-256 for settlement, BLAKE3-256 for internal only
- Real PQ crypto active (`_USE_REAL_KEM`, `_USE_REAL_DSA`, `_USE_REAL_AEAD` all `True`)
- Python test count from 821 to 1,167 across 38 test files
- Module count from ~35 to 60+ across 8 subpackages

## [3.0.0] - 2026-03-13

### Added
- Pluggable commitment backends (Local, Monad L1, Ethereum L2) with factory pattern
- Cross-chain bridge protocol (L1Anchor, Relayer, L2Materializer) with replay protection
- Cross-deployment federation with three-tier trust model (UNTRUSTED/VERIFIED/FEDERATED)
- Chunked streaming protocol with backpressure and pipelined distribution
- ZK transfer mode with Poseidon hiding commitments and simulated Groth16 proofs
- Economics engine with staking, rewards, progressive slashing, and correlation penalties
- Enforcement pipeline with PDP storage proofs, programmable slashing, VDF-enhanced audits
- Compliance framework with 9 control families and automated evidence collection
- HSM interface for hardware-backed key management
- Merkle log with append-only hash chain and signed tree heads
- Configurable security levels (Standard, Enhanced, Maximum, Post-Quantum, Custom)

### Changed
- Test suite expanded from 160 to 821 tests across 19 test files
- Commitment records now store Merkle root of encrypted shard hashes (no plaintext shard IDs)
- Lattice key reduced from ~869 bytes to ~160 bytes (Option C: encrypted shards + derivable metadata)

## [2.0.0] - 2026-02-24

### Added
- Option C security model: shard encryption with random CEK + sealed envelope
- Post-quantum cryptographic primitives (ML-KEM-768, ML-DSA-65)
- Formal security proofs for 7 theorems (TSEC, SINT, IMM, TRECON, TCONF, TNREP, TLINK)
- Security review and attack chain analysis (001-lattice-key-shard-exposure)

### Changed
- Lattice key sealed via ML-KEM-768 envelope encryption (replaces plaintext JSON)
- Commitment nodes store AEAD-encrypted ciphertext (nodes cannot read shard content)
- Commitment log stores Merkle root only (individual shard IDs removed)

## [1.0.0] - 2026-02-01

### Added
- Initial COMMIT / LATTICE / MATERIALIZE three-phase protocol
- Erasure coding (Reed-Solomon over GF(256)) with k-of-n reconstruction
- Content-addressed entity identity via BLAKE2b hashing
- Append-only commitment log with hash-chain integrity
- Commitment network with consistent-hash shard placement
- Burst audit challenge-response protocol for storage verification
- Proof-of-concept demo with end-to-end transfer flow
