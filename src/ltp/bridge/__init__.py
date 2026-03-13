"""
ETP Bridge — L1↔L2 cross-chain transfer via the Lattice Transfer Protocol.

Maps ETP's three-phase protocol to blockchain bridging:

  COMMIT      → Lock tokens on L1, erasure-code + encrypt the lock event
  LATTICE     → Seal a minimal key (~1.3KB) to the L2 verifier
  MATERIALIZE → Unseal, verify commitment + signature, reconstruct, mint on L2

Security properties:
  - PQ-secure relay (ML-KEM-768 sealed key, untrusted transport)
  - Forward secrecy per bridge message (fresh encapsulation each time)
  - Append-only audit trail (CT-style Merkle log + ML-DSA STH)
  - Data availability (erasure-coded shards, k-of-n reconstruction)
  - Replay protection (per-sender monotonic nonces)
"""

from .message import BridgeMessage, BridgeCommitment, RelayPacket
from .nonce import NonceTracker
from .anchor import L1Anchor
from .relayer import Relayer
from .materializer import L2Materializer

__all__ = [
    "BridgeMessage",
    "BridgeCommitment",
    "RelayPacket",
    "NonceTracker",
    "L1Anchor",
    "Relayer",
    "L2Materializer",
]
