"""
Relayer — cross-chain sealed key transport for the ETP bridge.

Wraps LTPProtocol.lattice() to produce a RelayPacket:
  - Seals the CEK + entity_id + commitment_ref to the L2 verifier's public key
  - Packages the sealed key with bridge routing metadata
  - The relayer itself is UNTRUSTED — it transports an opaque blob

Trust model:
  The relayer cannot read the CEK (ML-KEM encrypted), cannot forge the
  commitment (ML-DSA signed), and cannot redirect to a different recipient
  (sealed to a specific ML-KEM encapsulation key).
"""

from __future__ import annotations

import logging

from ..keypair import KeyPair
from ..protocol import LTPProtocol
from .message import BridgeCommitment, RelayPacket

logger = logging.getLogger(__name__)

__all__ = ["Relayer"]


class Relayer:
    """
    Cross-chain relayer: seals a LatticeKey and packages it for transport.

    The relayer is intentionally minimal and untrusted.  It:
      1. Receives a BridgeCommitment + CEK from the L1Anchor
      2. Calls LTPProtocol.lattice() to seal the key to the L2 verifier
      3. Returns a RelayPacket containing the sealed key + routing metadata

    The sealed key is ~1.3KB — orders of magnitude smaller than the original
    bridge message + shards.  This is the ONLY data that crosses chains.
    """

    def __init__(self, protocol: LTPProtocol) -> None:
        self.protocol = protocol

    def relay(
        self,
        commitment: BridgeCommitment,
        cek: bytes,
        l2_verifier_keypair: KeyPair,
    ) -> RelayPacket:
        """
        Seal the bridge commitment into a RelayPacket for L2.

        Args:
            commitment: The L1-side BridgeCommitment (public metadata)
            cek: The Content Encryption Key (secret, from L1Anchor)
            l2_verifier_keypair: The L2 verifier's keypair (only ek used)

        Returns:
            RelayPacket — the minimal cross-chain blob (~1.3KB sealed key
            + routing metadata).
        """
        # Fetch the commitment record from the log
        record = self.protocol.network.log.fetch(commitment.entity_id)
        if record is None:
            raise ValueError(
                f"Commitment record not found for entity_id={commitment.entity_id[:16]}..."
            )

        logger.info(
            "[Relayer] Sealing key for %s→%s, entity_id=%s...",
            commitment.message.source_chain,
            commitment.message.dest_chain,
            commitment.entity_id[:16],
        )

        # LATTICE phase — seal to L2 verifier's public key
        sealed_key = self.protocol.lattice(
            entity_id=commitment.entity_id,
            record=record,
            cek=cek,
            receiver_keypair=l2_verifier_keypair,
        )

        packet = RelayPacket(
            sealed_key=sealed_key,
            source_chain=commitment.message.source_chain,
            dest_chain=commitment.message.dest_chain,
            nonce=commitment.message.nonce,
            source_block=commitment.source_block,
            entity_id=commitment.entity_id,
        )

        logger.info(
            "[Relayer] RelayPacket ready: %d bytes sealed key, block=%d, nonce=%d",
            len(sealed_key), commitment.source_block, commitment.message.nonce,
        )

        return packet
