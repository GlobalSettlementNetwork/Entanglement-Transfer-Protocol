"""
L2Materializer — destination chain verification and reconstruction.

Wraps LTPProtocol.materialize() with bridge-specific verification:
  - Unseal the lattice key (ML-KEM decapsulation)
  - Verify commitment record + ML-DSA signature
  - Verify Merkle inclusion proof
  - Reconstruct the BridgeMessage from shards
  - Validate bridge invariants (nonce, dest_chain, finality)
"""

from __future__ import annotations

import logging
from typing import Optional

from ..keypair import KeyPair
from ..protocol import LTPProtocol
from .message import BridgeMessage, RelayPacket
from .nonce import NonceTracker

logger = logging.getLogger(__name__)

__all__ = ["L2Materializer"]


class L2Materializer:
    """
    Destination-chain materializer: verifies and reconstructs bridge messages.

    Operates on the L2 side.  For each RelayPacket:
      1. Validates routing metadata (dest_chain, finality)
      2. Validates nonce freshness (replay protection)
      3. Calls LTPProtocol.materialize() to unseal + verify + reconstruct
      4. Deserializes the reconstructed bytes back to a BridgeMessage
      5. Cross-checks the deserialized message against the relay metadata

    The materializer maintains its own NonceTracker to independently enforce
    replay protection on the L2 side.
    """

    def __init__(
        self,
        protocol: LTPProtocol,
        verifier_keypair: KeyPair,
        chain_id: str = "optimism",
        required_confirmations: int = 1,
    ) -> None:
        self.protocol = protocol
        self.verifier_keypair = verifier_keypair
        self.chain_id = chain_id
        self.required_confirmations = required_confirmations
        self.nonce_tracker = NonceTracker()
        self._current_l1_block = 0  # Simulated view of L1 finality

    def set_l1_block_height(self, height: int) -> None:
        """Update the materializer's view of L1 finality."""
        self._current_l1_block = height

    def materialize(
        self, packet: RelayPacket
    ) -> Optional[BridgeMessage]:
        """
        Verify and reconstruct a bridge message from a RelayPacket.

        Verification steps:
          1. dest_chain matches this materializer's chain
          2. source_block has sufficient finality confirmations
          3. Nonce is fresh (not replayed)
          4. LTPProtocol.materialize() succeeds (unseal, verify sig, reconstruct)
          5. Deserialized message matches relay packet metadata

        Returns:
            The verified BridgeMessage, or None if verification fails.
        """
        # Step 1: Validate destination chain
        if packet.dest_chain != self.chain_id:
            logger.warning(
                "[L2Materializer] dest_chain mismatch: packet=%s, this=%s",
                packet.dest_chain, self.chain_id,
            )
            return None

        # Step 2: Check L1 finality
        confirmations = self._current_l1_block - packet.source_block
        if confirmations < self.required_confirmations:
            logger.warning(
                "[L2Materializer] Insufficient finality: %d confirmations "
                "(need %d), source_block=%d, current_l1=%d",
                confirmations, self.required_confirmations,
                packet.source_block, self._current_l1_block,
            )
            return None

        # Step 3: Validate nonce (L2-side replay protection)
        if not self.nonce_tracker.validate_and_advance(
            packet.source_chain, packet.entity_id, packet.nonce
        ):
            logger.warning(
                "[L2Materializer] Replay detected: nonce=%d for entity=%s...",
                packet.nonce, packet.entity_id[:16],
            )
            return None

        logger.info(
            "[L2Materializer] Processing packet: %s→%s, nonce=%d, block=%d",
            packet.source_chain, packet.dest_chain,
            packet.nonce, packet.source_block,
        )

        # Step 4: MATERIALIZE phase — unseal, verify, reconstruct
        content = self.protocol.materialize(
            packet.sealed_key, self.verifier_keypair
        )
        if content is None:
            logger.warning("[L2Materializer] Materialization FAILED")
            return None

        # Step 5: Deserialize and cross-check
        try:
            message = BridgeMessage.from_bytes(content)
        except (ValueError, KeyError) as e:
            logger.warning(
                "[L2Materializer] Failed to deserialize bridge message: %s", e
            )
            return None

        # Cross-check relay metadata against inner message
        if message.source_chain != packet.source_chain:
            logger.warning(
                "[L2Materializer] source_chain mismatch: inner=%s, packet=%s",
                message.source_chain, packet.source_chain,
            )
            return None

        if message.dest_chain != packet.dest_chain:
            logger.warning(
                "[L2Materializer] dest_chain mismatch: inner=%s, packet=%s",
                message.dest_chain, packet.dest_chain,
            )
            return None

        if message.nonce != packet.nonce:
            logger.warning(
                "[L2Materializer] nonce mismatch: inner=%d, packet=%d",
                message.nonce, packet.nonce,
            )
            return None

        logger.info(
            "[L2Materializer] Bridge message verified: %s, %s→%s, nonce=%d",
            message.msg_type, message.source_chain, message.dest_chain,
            message.nonce,
        )

        return message
