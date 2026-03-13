"""
ZK Transfer Mode for the Lattice Transfer Protocol.

Provides privacy-preserving transfers where the commitment log does not
reveal which entity was committed. Uses hiding commitments (simulated
Pedersen scheme) and zero-knowledge proofs.

Whitepaper reference: §3.2, Open Question 8

⚠ WARNING: ZK mode is NOT post-quantum safe. Groth16 over BLS12-381 is
broken by Shor's algorithm. Standard LTP mode is fully post-quantum.
ZK mode MUST NOT be used with a quantum-adversary threat model.

Design decision: docs/design-decisions/ZK_TRANSFER_MODE.md
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .primitives import H, H_bytes

__all__ = [
    "ZKProofSystem",
    "ZKConfig",
    "ZKCommitment",
    "ZKProof",
    "ZKTransferMode",
]


class ZKProofSystem(Enum):
    """Available ZK proof systems."""
    SIMULATED = "simulated"    # PoC simulation (no real cryptography)
    GROTH16 = "groth16"        # BLS12-381, NOT post-quantum
    STARK = "stark"            # Post-quantum candidate (no trusted setup)


@dataclass
class ZKConfig:
    """Configuration for ZK transfer mode."""
    enabled: bool = False
    proof_system: ZKProofSystem = ZKProofSystem.SIMULATED
    curve: str = "bls12_381"   # Only relevant for Groth16
    hiding_commitment: bool = True  # Use hiding commitment for entity_id


@dataclass
class ZKCommitment:
    """
    A hiding commitment to an entity_id.

    In production (Groth16): C = g^{entity_id} · h^r over BLS12-381
    In simulation: C = H(entity_id || blinding_factor)

    The commitment hides entity_id from the commitment log while
    allowing ZK proof of knowledge.
    """
    commitment_value: str       # The commitment C (hex string)
    blinding_factor: bytes      # Random blinding factor r
    entity_id: str              # The hidden entity_id (known to creator only)

    @property
    def is_hiding(self) -> bool:
        """A commitment is hiding if it has a non-zero blinding factor."""
        return len(self.blinding_factor) > 0 and any(b != 0 for b in self.blinding_factor)


@dataclass
class ZKProof:
    """
    A zero-knowledge proof of knowledge of entity_id.

    Proves: "I know entity_id such that C = Commit(entity_id, r)"
    without revealing entity_id.

    In simulation: proof = H(entity_id || blinding_factor || "proof")
    In production: Groth16 proof (~192 bytes) or STARK proof (~45 KB)
    """
    proof_bytes: bytes
    proof_system: ZKProofSystem
    public_inputs: dict = field(default_factory=dict)

    @property
    def proof_size_bytes(self) -> int:
        return len(self.proof_bytes)


class ZKTransferMode:
    """
    Zero-knowledge transfer mode for entity_id privacy.

    Allows commits to the log without revealing which entity was committed.
    The commitment log sees only C (a hiding commitment) and a ZK proof
    that the committer knows the opening.

    PoC uses simulated commitments and proofs. Production requires
    Groth16 (BLS12-381) or STARK circuit implementations.
    """

    def __init__(self, config: ZKConfig | None = None) -> None:
        self.config = config or ZKConfig()

    def create_hiding_commitment(self, entity_id: str) -> ZKCommitment:
        """
        Create a hiding commitment to entity_id.

        Production: Pedersen commitment C = g^{entity_id} · h^r
        Simulation: C = H(entity_id || r)
        """
        blinding_factor = os.urandom(32)

        if self.config.proof_system == ZKProofSystem.SIMULATED:
            commitment_value = H(
                entity_id.encode() + blinding_factor
            )
        else:
            # Production would use actual elliptic curve operations
            commitment_value = H(
                entity_id.encode() + blinding_factor + self.config.curve.encode()
            )

        return ZKCommitment(
            commitment_value=commitment_value,
            blinding_factor=blinding_factor,
            entity_id=entity_id,
        )

    def create_zk_proof(
        self,
        entity_id: str,
        commitment: ZKCommitment,
    ) -> ZKProof:
        """
        Create a ZK proof that the committer knows entity_id opening C.

        Production: Groth16 proof (~192 bytes, ~2s generation)
        Simulation: H(entity_id || blinding_factor || "proof")
        """
        if commitment.entity_id != entity_id:
            raise ValueError("Entity ID does not match commitment")

        if self.config.proof_system == ZKProofSystem.SIMULATED:
            proof_bytes = H_bytes(
                entity_id.encode()
                + commitment.blinding_factor
                + b"proof"
            )
        elif self.config.proof_system == ZKProofSystem.GROTH16:
            # Simulated Groth16 proof (192 bytes in production)
            proof_bytes = H_bytes(
                entity_id.encode()
                + commitment.blinding_factor
                + b"groth16-proof"
            )
            # Pad to approximate Groth16 proof size
            proof_bytes = proof_bytes + os.urandom(160)
        elif self.config.proof_system == ZKProofSystem.STARK:
            # Simulated STARK proof (~45KB in production, no trusted setup)
            proof_bytes = H_bytes(
                entity_id.encode()
                + commitment.blinding_factor
                + b"stark-proof"
            )
        else:
            raise ValueError(f"Unknown proof system: {self.config.proof_system}")

        return ZKProof(
            proof_bytes=proof_bytes,
            proof_system=self.config.proof_system,
            public_inputs={
                "commitment": commitment.commitment_value,
            },
        )

    def verify_zk_proof(
        self,
        commitment: ZKCommitment,
        proof: ZKProof,
    ) -> bool:
        """
        Verify a ZK proof against a commitment.

        Checks that the prover knows entity_id such that
        C = Commit(entity_id, r) without learning entity_id.
        """
        if proof.proof_system != self.config.proof_system:
            return False

        if self.config.proof_system == ZKProofSystem.SIMULATED:
            expected = H_bytes(
                commitment.entity_id.encode()
                + commitment.blinding_factor
                + b"proof"
            )
            return proof.proof_bytes == expected
        elif self.config.proof_system == ZKProofSystem.GROTH16:
            expected_prefix = H_bytes(
                commitment.entity_id.encode()
                + commitment.blinding_factor
                + b"groth16-proof"
            )
            return proof.proof_bytes[:len(expected_prefix)] == expected_prefix
        elif self.config.proof_system == ZKProofSystem.STARK:
            expected = H_bytes(
                commitment.entity_id.encode()
                + commitment.blinding_factor
                + b"stark-proof"
            )
            return proof.proof_bytes == expected

        return False

    def open_commitment(
        self,
        commitment: ZKCommitment,
        entity_id: str,
        blinding_factor: bytes,
    ) -> bool:
        """
        Open (reveal) a commitment — verify that C was created from
        the given entity_id and blinding_factor.

        This is NOT zero-knowledge (it reveals entity_id). Used for
        dispute resolution or selective disclosure.
        """
        expected = H(entity_id.encode() + blinding_factor)
        return commitment.commitment_value == expected


@dataclass
class ContentPropertyProof:
    """
    A proof about entity content properties without revealing the content.

    Examples:
      - "This entity is a valid JSON document"
      - "This entity's 'age' field is >= 18"
      - "This entity conforms to schema X"

    Open Question 8(a): What is the appropriate circuit composition model?
    """
    property_name: str            # Human-readable property
    property_circuit_id: str      # Circuit identifier
    proof: ZKProof                # The ZK proof
    public_inputs: dict           # Public inputs to the circuit

    @property
    def is_verifiable(self) -> bool:
        """Whether the proof can be verified (has required fields)."""
        return (
            bool(self.property_circuit_id)
            and self.proof.proof_bytes is not None
            and len(self.proof.proof_bytes) > 0
        )
