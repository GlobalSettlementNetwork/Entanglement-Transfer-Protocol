"""
L1Anchor — source chain commitment for the ETP bridge.

Wraps LTPProtocol.commit() with bridge-specific logic:
  - Serializes BridgeMessage → Entity
  - Validates nonce monotonicity
  - Generates Merkle inclusion proof
  - Returns BridgeCommitment + CEK
"""

from __future__ import annotations

import logging

from ..entity import Entity
from ..keypair import KeyPair
from ..protocol import LTPProtocol
from .message import BridgeCommitment, BridgeMessage
from .nonce import NonceTracker

logger = logging.getLogger(__name__)

__all__ = ["L1Anchor"]


class L1Anchor:
    """
    Source-chain anchor: commits bridge messages to the ETP commitment log.

    Operates on the L1 side.  For each bridge message:
      1. Validates nonce freshness (replay protection)
      2. Serializes the message to an Entity
      3. Calls LTPProtocol.commit() (erasure-code, encrypt, distribute, sign)
      4. Generates a Merkle inclusion proof
      5. Returns a BridgeCommitment (public) + CEK (secret, for lattice phase)
    """

    def __init__(
        self,
        protocol: LTPProtocol,
        operator_keypair: KeyPair,
        chain_id: str = "ethereum",
    ) -> None:
        self.protocol = protocol
        self.operator_keypair = operator_keypair
        self.chain_id = chain_id
        self.nonce_tracker = NonceTracker()
        self._block_counter = 0  # Simulated L1 block height

    def commit_message(
        self,
        message: BridgeMessage,
        n: int = 8,
        k: int = 4,
    ) -> tuple[BridgeCommitment, bytes]:
        """
        Commit a bridge message to the L1 anchor.

        Steps:
          1. Validate source chain matches this anchor
          2. Validate nonce is fresh (strictly increasing per sender)
          3. Serialize message → Entity
          4. LTPProtocol.commit() → entity_id, record, CEK
          5. Generate Merkle inclusion proof
          6. Package as BridgeCommitment

        Returns: (BridgeCommitment, cek)
        Raises: ValueError if nonce is replayed or chain mismatch.
        """
        # Validate source chain
        if message.source_chain != self.chain_id:
            raise ValueError(
                f"Message source_chain '{message.source_chain}' "
                f"does not match anchor chain '{self.chain_id}'"
            )

        # Validate nonce (replay protection)
        if not self.nonce_tracker.validate_and_advance(
            message.source_chain, message.sender, message.nonce
        ):
            raise ValueError(
                f"Nonce {message.nonce} for sender {message.sender} "
                f"is not strictly increasing (replay detected)"
            )

        # Serialize message → Entity
        content = message.to_canonical_bytes()
        entity = Entity(content=content, shape="application/vnd.etp.bridge-message+json")

        logger.info(
            "[L1Anchor] Committing bridge message: %s %s→%s nonce=%d",
            message.msg_type, message.source_chain, message.dest_chain,
            message.nonce,
        )

        # COMMIT phase
        entity_id, record, cek = self.protocol.commit(
            entity, self.operator_keypair, n=n, k=k
        )

        # Generate Merkle inclusion proof
        proof = self.protocol.network.log.get_inclusion_proof(entity_id)
        if proof is None:
            raise RuntimeError(
                f"Failed to generate inclusion proof for {entity_id[:16]}..."
            )

        # Advance simulated block height
        self._block_counter += 1

        commitment = BridgeCommitment(
            message=message,
            entity_id=entity_id,
            commitment_ref=record.to_bytes().hex()[:64],
            merkle_proof=proof,
            source_block=self._block_counter,
        )

        logger.info(
            "[L1Anchor] Committed at block %d, entity_id=%s...",
            self._block_counter, entity_id[:16],
        )

        return commitment, cek
