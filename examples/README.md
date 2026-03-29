# Examples

Self-contained code examples demonstrating ETP's core capabilities.

## Prerequisites

```bash
pip install -e ".[dev]"
```

## Examples

| Example | Description | Demonstrates |
|---------|-------------|-------------|
| [basic_transfer.py](basic_transfer.py) | End-to-end COMMIT → LATTICE → MATERIALIZE | Core 3-phase protocol |
| [signed_envelopes.py](signed_envelopes.py) | ML-DSA-65 authenticated message wrappers | Signatures, KID discovery, drift validation |
| [merkle_proofs.py](merkle_proofs.py) | Append-only ledger with inclusion proofs | Merkle log, STH, tamper evidence |
| [bridge_transfer.py](bridge_transfer.py) | L1 → L2 cross-chain transfer | Bridge protocol, PQ-secure relay |

## Running

```bash
# Run any example
python examples/basic_transfer.py

# Run the full demo (covers everything)
python run_trust_layer.py
```

## Key Concepts

- **Entity**: Content + shape (media type). Content-addressed via SHA3-256.
- **CEK**: Random 256-bit Content Encryption Key. One per entity.
- **Sealed Key**: ~1.3KB ML-KEM-768 envelope. Constant size regardless of content.
- **Commitment Record**: ML-DSA-65 signed Merkle root. Append-only.
- **Forward Secrecy**: Fresh ML-KEM encapsulation per transfer.
