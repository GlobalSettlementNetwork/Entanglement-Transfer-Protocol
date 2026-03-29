<div align="center">

# Entanglement Transfer Protocol

### A Post-Quantum Cryptographic Data Transfer Protocol

> *"Don't move the data. Transfer the proof. Reconstruct the truth."*

[![Tests](https://img.shields.io/badge/tests-1,251+_passing-brightgreen)]()
[![Python](https://img.shields.io/badge/python-3.10+-blue)]()
[![License](https://img.shields.io/badge/license-MIT-green)]()
[![Version](https://img.shields.io/badge/version-3.0.0-orange)]()
[![Post-Quantum](https://img.shields.io/badge/crypto-post--quantum-purple)]()

</div>

---

## The Problem

Every existing protocol -- TCP/IP, HTTP, FTP, QUIC -- operates on the same
foundational assumption: **data is a payload that must travel from Point A to
Point B.** This chains us to three unsolvable constraints:

1. **Latency** -- bound by the speed of light and routing hops
2. **Geography** -- further = slower, always
3. **Compute** -- larger payloads demand more processing at both ends

ETP rejects this assumption. Data transfer is not about moving bits. It is about
transferring the *ability to reconstruct* a deterministic output at a destination,
verified by an immutable commitment.

## Three-Phase Protocol

```mermaid
flowchart LR
    S[Sender] -->|"1. COMMIT"| CL[Commitment Layer]
    CL -->|"Encrypted shards"| N1[Node 1]
    CL -->|"Encrypted shards"| N2[Node 2]
    CL -->|"Encrypted shards"| N3[Node ...]
    S -->|"2. LATTICE (~1.3KB sealed key)"| R[Receiver]
    R -->|"3. MATERIALIZE"| CL
    CL -->|"Reconstruct"| R
```

| Phase | Operation | What Happens |
|-------|-----------|-------------|
| **COMMIT** | Sender commits entity | Erasure encode, encrypt shards with random CEK, distribute to nodes, append to Merkle log |
| **LATTICE** | Sender seals key to receiver | ML-KEM-768 sealed envelope (~1.3KB) containing entity_id + CEK + commitment reference |
| **MATERIALIZE** | Receiver reconstructs entity | Unseal key, verify commitment, fetch k-of-n shards, decrypt, decode, verify integrity |

The entity is never serialized and shipped as a monolithic payload. It is
**committed, proved, and reconstructed**.

## Core Guarantees

| Property | Guarantee | Mechanism |
|----------|-----------|-----------|
| O(1) transfer path | Sender-to-receiver carries ~1.3KB regardless of entity size | ML-KEM sealed lattice key |
| Immutability | Committed entities cannot be altered | Append-only Merkle log with ML-DSA-65 signatures |
| Threshold secrecy | < k shards reveal nothing about the entity | Information-theoretic security via erasure coding |
| Non-repudiation | Sender cannot deny having committed an entity | ML-DSA-65 signatures on commitment records |
| Post-quantum security | Resistant to quantum computer attacks | ML-KEM-768 (FIPS 203) + ML-DSA-65 (FIPS 204) |
| Forward secrecy | Compromising one transfer doesn't compromise others | Fresh ML-KEM encapsulation per transfer |

## Four Pillars

| Pillar | Implementation | Status |
|--------|---------------|--------|
| **Post-Quantum Cryptography** | ML-KEM-768 (FIPS 203) + ML-DSA-65 (FIPS 204) + XChaCha20-Poly1305 | Active — real crypto, no simulations |
| **Lattice Transfer Protocol** | 3-phase lifecycle with Shamir sharing, Merkle audit log, threshold reconstruction | Complete |
| **Dual-Lane Hashing** | SHA3-256 (canonical/on-chain) + BLAKE3-256 (internal/performance) | Enforced separation |
| **On-Chain Settlement** | LTPAnchorRegistry v5 with UUPS proxy + MultiSig + Timelock governance | Deployed on GSX Testnet |

## What's Implemented

| Capability | Status | Module |
|------------|--------|--------|
| Three-phase protocol (COMMIT/LATTICE/MATERIALIZE) | Done | `protocol.py` |
| Erasure coding (Reed-Solomon GF(256)) | Done | `erasure.py` |
| AEAD shard encryption (CEK per entity) | Done | `shards.py` |
| ML-KEM-768 sealed envelope | Done | `keypair.py` |
| ML-DSA-65 commitment signatures | Done | `primitives.py` |
| Append-only Merkle commitment log | Done | `commitment.py` |
| Pluggable backends (Local, Monad L1, Ethereum L2) | Done | `backends/` |
| Cross-chain bridge (L1Anchor, Relayer, L2Materializer) | Done | `bridge/` |
| Cross-deployment federation | Done | `federation.py` |
| Chunked streaming with backpressure | Done | `streaming.py` |
| ZK transfer mode (hiding commitments) | Done | `zk_transfer.py` |
| Economics engine (staking, slashing, rewards) | Done | `economics.py` |
| Enforcement pipeline (PDP, programmable slashing) | Done | `enforcement.py` |
| Compliance framework (9 control families) | Done | `compliance.py` |

## Architecture

```mermaid
flowchart TD
    subgraph Core["Core Protocol"]
        P[protocol.py] --> E[erasure.py]
        P --> S[shards.py]
        P --> K[keypair.py]
        P --> C[commitment.py]
        P --> PR[primitives.py]
        P --> L[lattice.py]
        P --> EN[entity.py]
    end

    subgraph Extensions["Extensions"]
        ST[streaming.py]
        ZK[zk_transfer.py]
        FED[federation.py]
    end

    subgraph Infrastructure["Infrastructure"]
        EC[economics.py]
        ENF[enforcement.py]
        EP[enforcement_pipeline.py]
        CO[compliance.py]
        HSM[hsm.py]
    end

    subgraph Backends["Commitment Backends"]
        BF[factory.py]
        BL[local.py]
        BM[monad_l1.py]
        BE[ethereum.py]
    end

    subgraph Bridge["Bridge Protocol"]
        BA[anchor.py]
        BR[relayer.py]
        BMA[materializer.py]
    end

    P --> ST
    P --> ZK
    C --> BF
    BF --> BL
    BF --> BM
    BF --> BE
    P --> BA
    P --> BR
    P --> BMA
```

## Security Stack

```mermaid
flowchart BT
    L1["Layer 1: Information-Theoretic Security\nErasure coding (k-of-n threshold)\n< k shards reveal nothing"]
    L2["Layer 2: Cryptographic Integrity\nBLAKE2b content addressing\nMerkle root + ML-DSA-65 signatures"]
    L3["Layer 3: Zero-Knowledge (Optional)\nPoseidon hiding commitments\nGroth16 proofs (not PQ-safe)"]
    L4["Layer 4: Shard Encryption\nAEAD with random 256-bit CEK\nPer-shard nonce derivation"]
    L5["Layer 5: Sealed Envelope\nML-KEM-768 encapsulation\nForward secrecy per transfer"]
    L6["Layer 6: Access Policy\nOne-time materialization\nTime-bounded, delegatable, revocable"]

    L1 --> L2
    L2 --> L3
    L3 --> L4
    L4 --> L5
    L5 --> L6
```

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

## Quick Start

```bash
# Clone and install
git clone https://github.com/GlobalSettlementNetwork/Entanglement-Transfer-Protocol.git
cd Entanglement-Transfer-Protocol
pip install -e ".[dev]"

# Run the demo
python run_trust_layer.py

# Run all tests
pytest tests/ -v

# Run Solidity tests (requires Foundry)
cd contracts && forge test -vvv
```

## Project Structure

```
Entanglement-Transfer-Protocol/
├── src/ltp/                    # Core protocol library (60+ modules)
│   ├── protocol.py             # Three-phase COMMIT/LATTICE/MATERIALIZE
│   ├── primitives.py           # ML-KEM-768, ML-DSA-65, AEAD, hashing
│   ├── commitment.py           # Merkle log, commitment network, node lifecycle
│   ├── erasure.py              # Reed-Solomon erasure coding over GF(256)
│   ├── shards.py               # AEAD shard encryption with CEK
│   ├── keypair.py              # ML-KEM sealed envelope (lattice key)
│   ├── lattice.py              # Lattice key construction
│   ├── entity.py               # Entity identity and shape analysis
│   ├── economics.py            # Staking, rewards, progressive slashing
│   ├── enforcement.py          # PDP proofs, programmable slashing, VDF audits
│   ├── enforcement_pipeline.py # Enforcement orchestration
│   ├── compliance.py           # 9-family compliance framework
│   ├── federation.py           # Cross-deployment discovery and trust
│   ├── streaming.py            # Chunked streaming with backpressure
│   ├── zk_transfer.py          # ZK hiding commitments (Poseidon + Groth16)
│   ├── hsm.py                  # HSM interface for key management
│   ├── anchor/                 # On-chain anchoring client
│   ├── backends/               # Local, MonadL1, Ethereum backends
│   ├── bridge/                 # Cross-chain bridge protocol
│   ├── dual_lane/              # SHA3/BLAKE3 lane separation
│   ├── merkle_log/             # RFC 6962 Merkle tree + proofs
│   ├── network/                # gRPC client/server (7 RPCs)
│   ├── storage/                # SQLite (WAL), filesystem, memory stores
│   └── verify/                 # Verification SDK
│
├── contracts/
│   ├── src/
│   │   ├── LTPAnchorRegistry.sol      # On-chain anchor registry (UUPS)
│   │   ├── LTPMultiSig.sol            # N-of-M multi-signature wallet
│   │   └── interfaces/
│   │       └── ILTPAnchorRegistry.sol  # Registry interface
│   ├── test/
│   │   ├── LTPAnchorRegistry.t.sol    # 63 unit/integration tests
│   │   └── FormalVerification.t.sol   # 21 fuzz/invariant/parity tests
│   └── script/
│       ├── Deploy.s.sol               # Local deployment
│       ├── DeployTestnet.s.sol        # GSX Testnet deployment
│       ├── DeployMainnet.s.sol        # Production deployment (configurable)
│       └── UpgradeV4.s.sol            # Governance-controlled UUPS upgrade
│
├── tests/                      # 1,167 Python tests across 38 files
├── docs/                       # Protocol documentation
│   ├── WHITEPAPER.md           # Full protocol specification
│   └── ...                     # See docs/README.md for index
├── pyproject.toml              # Package configuration
├── CHANGELOG.md                # Version history
├── CONTRIBUTING.md             # Contribution guidelines
├── SECURITY.md                 # Security policy
└── LICENSE                     # MIT License
```

## Documentation

See [docs/README.md](docs/README.md) for the full documentation index.

| Document | Description |
|----------|-------------|
| [Whitepaper](docs/WHITEPAPER.md) | Full protocol specification |
| [Technical Report](LTP_COMPREHENSIVE_REPORT.md) | 13-section architecture & deployment report |
| [Architecture](docs/design-decisions/ARCHITECTURE.md) | System components and data flow |
| [Production Plan](docs/PRODUCTION_PLAN.md) | PoC to production roadmap |
| [Deployment Guide](docs/DEPLOYMENT_GUIDE.md) | Docker, Kubernetes, CI/CD |
| [Bridge MVP](docs/bridge-mvp-scope.md) | Cross-chain bridge scope |
| [Security Review](docs/design-decisions/Security/SECURITY_REVIEW-2-24-2026.md) | Formal security analysis |

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

## Key Properties

- **Constant-bandwidth sealed keys:** ~1,400 bytes O(1), independent of payload size
- **FIPS-compliant settlement:** SHA3-256 canonical hashing on all on-chain paths
- **No simulations:** `_USE_REAL_KEM`, `_USE_REAL_DSA`, `_USE_REAL_AEAD` all resolve `True`
- **Python↔Solidity parity:** Identical accept/reject for all validation rules
- **Zero external dependencies:** Core library has no runtime dependencies beyond PQ crypto libs

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## Security

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities.

## License

MIT License. See [LICENSE](LICENSE).
