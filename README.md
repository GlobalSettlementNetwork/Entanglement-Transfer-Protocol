# Lattice Transfer Protocol (ETP)

### A Post-Quantum Secure Data Transfer Protocol Built on the Lattice Transfer Protocol (LTP)


> "Don't move the data. Transfer the proof. Reconstruct the truth."

---

## The Problem With Data Transfer Today

Every existing protocol — TCP/IP, HTTP, FTP, QUIC, even modern streaming protocols — operates
on the same foundational assumption:

**Data is a payload that must travel from Point A to Point B.**

This assumption chains us to three unsolvable constraints:
1. **Latency** — bound by the speed of light and routing hops
2. **Geography** — further = slower, always
3. **Compute** — larger payloads demand more processing at both ends

LTP rejects this assumption entirely.

---

## The Core Thesis

**Data transfer is not about moving bits. It is about transferring the *ability to reconstruct* a
deterministic output at a destination, verified by an immutable commitment.**

An LTP transfer consists of three atomic operations:

| Phase | Name | What Happens |
|-------|------|-------------|
| 1 | **Commit** | Data is split via Shamir secret sharing, shards encrypted with ML-KEM-768, distributed to nodes via consistent hashing, and a Merkle tree is built over the shard set |
| 2 | **Lattice** | Nodes are audited with random nonces for proof-of-possession. Strike system enforces honesty. A constant-size sealed key (~1,400 bytes) is transmitted — independent of payload size |
| 3 | **Materialize** | Threshold shards are retrieved, decrypted, Shamir-reconstructed, and verified against the anchored Merkle root. Original data is restored |

The entity is never serialized and shipped as a monolithic payload. It is **committed, proved, and reconstructed**.

---

## Four Pillars

| Pillar | Implementation | Status |
|--------|---------------|--------|
| **Post-Quantum Cryptography** | ML-KEM-768 (FIPS 203) + ML-DSA-65 (FIPS 204) + XChaCha20-Poly1305 | Active — real crypto, no simulations |
| **Lattice Transfer Protocol** | 3-phase lifecycle with Shamir sharing, Merkle audit log, threshold reconstruction | Complete |
| **Dual-Lane Hashing** | SHA3-256 (canonical/on-chain) + BLAKE3-256 (internal/performance) | Enforced separation |
| **On-Chain Settlement** | LTPAnchorRegistry v5 with UUPS proxy + MultiSig + Timelock governance | Deployed on GSX Testnet |

---

## Smart Contracts — GSX Testnet

Deployed on GSX Testnet (Chain ID `103115120`), block 687609.

| Contract | Address |
|----------|---------|
| UUPS Proxy (registry) | `0xB29d8BFF4973D1D7bcB10E32112EBB8fdd530bF4` |
| Implementation v5 | `0xADf01df5B6Bef8e37d253571ab6e21177aCb7796` |
| MultiSig (2-of-2) | `0x0106A79e9236009a05742B3fB1e3B7a52F44373D` |
| Timelock (60s delay) | `0x7C2665F7e68FE635ee8F10aa0130AEBC603a9Db8` |

**Governance chain:** MultiSig → Timelock → Registry

**Deployment evolution:**
```
v1 (Mar 23)   Implementation only          No proxy, no governance
v2 (Mar 23)   + UUPS Proxy + MultiSig      Upgradeable, 2-of-2 control
v3 (Mar 23)   + TimelockController          Time-delayed governance
v4 (Mar 25)   Verified production deploy    84 Solidity + 1,167 Python tests
v5 (Mar 25)   Author attribution + v5      Current production
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Application Layer                             │
│  LTPProtocol → CommitmentNetwork → 6 nodes, 3 regions          │
├─────────────────────────────────────────────────────────────────┤
│                    Cryptographic Layer                           │
│  ML-KEM-768 (KEM) │ ML-DSA-65 (DSA) │ XChaCha20-Poly1305      │
├─────────────────────────────────────────────────────────────────┤
│                    Dual-Lane Hashing                             │
│  SHA3-256 (canonical/on-chain) │ BLAKE3-256 (internal/cache)    │
├─────────────────────────────────────────────────────────────────┤
│                    Verification Layer                            │
│  Merkle Log (RFC 6962) │ Inclusion/Consistency Proofs │ STH     │
├─────────────────────────────────────────────────────────────────┤
│                    Governance Layer                              │
│  SignerPolicy │ SequenceTracker │ StakeManager │ SlashingEngine  │
├─────────────────────────────────────────────────────────────────┤
│                    Infrastructure Layer                          │
│  Storage (Memory/SQLite/FS) │ Networking (gRPC) │ Resilience    │
├─────────────────────────────────────────────────────────────────┤
│                    Settlement Layer (On-Chain)                   │
│  LTPAnchorRegistry (UUPS) → TimelockController → LTPMultiSig   │
│  GSX Testnet — Chain ID 103115120                               │
└─────────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
src/ltp/
├── commitment.py          # Core commitment logic
├── compliance.py          # FIPS, RBAC, GDPR, HSM interfaces
├── economics.py           # Economic incentive layer
├── enforcement.py         # PDP, slashing, disputes, governance
├── keypair.py             # PQ key generation and management
├── primitives.py          # ML-KEM-768, ML-DSA-65, XChaCha20 wrappers
├── streaming.py           # Streaming transfer support
├── anchor/                # On-chain anchoring client
├── backends/              # Local, MonadL1, Ethereum backends
├── bridge/                # Cross-chain bridge protocol
├── dual_lane/             # SHA3/BLAKE3 lane separation
├── merkle_log/            # RFC 6962 Merkle tree + proofs
├── network/               # gRPC client/server (7 RPCs)
├── storage/               # SQLite (WAL), filesystem, memory stores
└── verify/                # Verification SDK

contracts/
├── src/
│   ├── LTPAnchorRegistry.sol      # On-chain anchor registry (UUPS)
│   ├── LTPMultiSig.sol            # N-of-M multi-signature wallet
│   └── interfaces/
│       └── ILTPAnchorRegistry.sol  # Registry interface
├── test/
│   ├── LTPAnchorRegistry.t.sol    # 63 unit/integration tests
│   └── FormalVerification.t.sol   # 21 fuzz/invariant/parity tests
└── script/
    ├── Deploy.s.sol               # Local deployment
    ├── DeployTestnet.s.sol        # GSX Testnet deployment
    ├── DeployMainnet.s.sol        # Production deployment (configurable)
    └── UpgradeV4.s.sol            # Governance-controlled UUPS upgrade
```

---

## Test Coverage

| Category | Count |
|----------|-------|
| Python tests | 1,167 |
| Solidity tests | 84 |
| Adversarial/attack tests | 56 |
| State machine exhaustive (36 transition pairs) | Verified |
| Storage backend parametrized | 3 backends x 14 methods |
| gRPC round-trip (real servers) | 14 tests |
| Fuzz runs (per test) | 256 iterations |
| Invariant tests | 256 runs x 3,840 calls each |
| **Total** | **1,251+** |

```bash
# Run Python tests
pip install -e ".[dev]"
pytest tests/ -v

# Run Solidity tests
cd contracts && forge test -vvv
```

---

## Key Properties

- **Constant-bandwidth sealed keys:** ~1,400 bytes O(1), independent of payload size
- **FIPS-compliant settlement:** SHA3-256 canonical hashing on all on-chain paths
- **No simulations:** `_USE_REAL_KEM`, `_USE_REAL_DSA`, `_USE_REAL_AEAD` all resolve `True`
- **Python↔Solidity parity:** Identical accept/reject for all validation rules
- **Zero external dependencies:** Core library has no runtime dependencies beyond PQ crypto libs

---

## Documentation

- [Technical Architecture & Deployment Report](LTP_COMPREHENSIVE_REPORT.md) — Full 13-section report covering protocol design, all 5 deployment versions, test coverage, governance model, and observations

---

## License

This protocol specification is released for open exploration and research.
