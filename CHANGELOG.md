# Changelog

All notable changes to the Entanglement Transfer Protocol will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
