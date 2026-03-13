"""
Integration tests for the ETP Bridge — L1↔L2 cross-chain transfer.

End-to-end scenario:
  1. Alice locks 100 USDC on L1 (Ethereum)
  2. L1Anchor commits the lock event
  3. Relayer seals the key to L2 verifier
  4. L2Materializer on Optimism verifies + reconstructs
  5. Bridge mints 100 USDC to Alice on L2
  6. Replay attempt → REJECTED
  7. Tampered packet → FAILS
"""

import pytest

from src.ltp import CommitmentNetwork, KeyPair, LTPProtocol
from src.ltp.bridge import (
    BridgeMessage,
    L1Anchor,
    L2Materializer,
    Relayer,
    RelayPacket,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def l1_operator() -> KeyPair:
    """L1 bridge operator keypair (signs commitment records)."""
    return KeyPair.generate("l1-operator")


@pytest.fixture(scope="session")
def l2_verifier() -> KeyPair:
    """L2 verifier keypair (unseals lattice keys)."""
    return KeyPair.generate("l2-verifier")


@pytest.fixture
def bridge_network() -> CommitmentNetwork:
    """Shared commitment network (simulates DA layer)."""
    net = CommitmentNetwork()
    for node_id, region in [
        ("bridge-us-1", "US-East"),
        ("bridge-us-2", "US-West"),
        ("bridge-eu-1", "EU-West"),
        ("bridge-eu-2", "EU-East"),
        ("bridge-ap-1", "AP-East"),
        ("bridge-ap-2", "AP-South"),
    ]:
        net.add_node(node_id, region)
    return net


@pytest.fixture
def bridge_protocol(bridge_network: CommitmentNetwork) -> LTPProtocol:
    return LTPProtocol(bridge_network)


@pytest.fixture
def l1_anchor(bridge_protocol: LTPProtocol, l1_operator: KeyPair) -> L1Anchor:
    return L1Anchor(bridge_protocol, l1_operator, chain_id="ethereum")


@pytest.fixture
def relayer(bridge_protocol: LTPProtocol) -> Relayer:
    return Relayer(bridge_protocol)


@pytest.fixture
def l2_materializer(
    bridge_protocol: LTPProtocol, l2_verifier: KeyPair
) -> L2Materializer:
    return L2Materializer(
        bridge_protocol,
        l2_verifier,
        chain_id="optimism",
        required_confirmations=1,
    )


def _make_lock_message(nonce: int = 0) -> BridgeMessage:
    """Create a standard token_lock bridge message."""
    return BridgeMessage(
        msg_type="token_lock",
        source_chain="ethereum",
        dest_chain="optimism",
        sender="0xAliceSenderAddress",
        recipient="0xAliceRecipientAddress",
        payload={"token": "USDC", "amount": 100, "decimals": 6},
        nonce=nonce,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestBridgeEndToEnd:
    """Full lock → relay → materialize → mint flow."""

    def test_happy_path(
        self,
        l1_anchor: L1Anchor,
        relayer: Relayer,
        l2_materializer: L2Materializer,
        l2_verifier: KeyPair,
    ):
        """Alice locks 100 USDC on L1, receives them on L2."""
        msg = _make_lock_message(nonce=0)

        # Phase 1: COMMIT on L1
        commitment, cek = l1_anchor.commit_message(msg)
        assert commitment.entity_id
        assert commitment.merkle_proof is not None
        assert commitment.source_block == 1

        # Phase 2: LATTICE (relay)
        packet = relayer.relay(commitment, cek, l2_verifier)
        assert len(packet.sealed_key) > 1000  # ~1.3KB
        assert packet.source_chain == "ethereum"
        assert packet.dest_chain == "optimism"
        assert packet.nonce == 0

        # Phase 3: MATERIALIZE on L2
        l2_materializer.set_l1_block_height(10)  # Sufficient finality
        result = l2_materializer.materialize(packet)

        assert result is not None
        assert result.msg_type == "token_lock"
        assert result.payload["token"] == "USDC"
        assert result.payload["amount"] == 100
        assert result.sender == "0xAliceSenderAddress"
        assert result.recipient == "0xAliceRecipientAddress"
        assert result.nonce == 0

    def test_multiple_messages(
        self,
        l1_anchor: L1Anchor,
        relayer: Relayer,
        l2_materializer: L2Materializer,
        l2_verifier: KeyPair,
    ):
        """Multiple sequential bridge messages with increasing nonces."""
        l2_materializer.set_l1_block_height(100)

        for nonce in range(3):
            msg = _make_lock_message(nonce=nonce)
            commitment, cek = l1_anchor.commit_message(msg)
            packet = relayer.relay(commitment, cek, l2_verifier)
            result = l2_materializer.materialize(packet)

            assert result is not None
            assert result.nonce == nonce
            assert result.payload["amount"] == 100


class TestReplayProtection:
    """Nonce-based replay attack prevention."""

    def test_l1_nonce_replay_rejected(self, l1_anchor: L1Anchor):
        """Same nonce on L1 → commit fails."""
        msg1 = _make_lock_message(nonce=0)
        l1_anchor.commit_message(msg1)

        msg2 = _make_lock_message(nonce=0)
        with pytest.raises(ValueError, match="replay"):
            l1_anchor.commit_message(msg2)

    def test_l2_nonce_replay_rejected(
        self,
        l1_anchor: L1Anchor,
        relayer: Relayer,
        l2_materializer: L2Materializer,
        l2_verifier: KeyPair,
    ):
        """Same packet replayed on L2 → materialization fails."""
        l2_materializer.set_l1_block_height(100)

        msg = _make_lock_message(nonce=0)
        commitment, cek = l1_anchor.commit_message(msg)
        packet = relayer.relay(commitment, cek, l2_verifier)

        # First materialization succeeds
        result1 = l2_materializer.materialize(packet)
        assert result1 is not None

        # Replay → rejected
        result2 = l2_materializer.materialize(packet)
        assert result2 is None


class TestChainValidation:
    """Cross-chain routing validation."""

    def test_wrong_source_chain(self, l1_anchor: L1Anchor):
        """Message with wrong source_chain → L1 rejects."""
        msg = BridgeMessage(
            msg_type="token_lock",
            source_chain="arbitrum",  # Wrong — anchor is "ethereum"
            dest_chain="optimism",
            sender="0xAlice",
            recipient="0xAlice",
            payload={"token": "USDC", "amount": 50},
            nonce=0,
        )
        with pytest.raises(ValueError, match="source_chain"):
            l1_anchor.commit_message(msg)

    def test_wrong_dest_chain(
        self,
        l1_anchor: L1Anchor,
        relayer: Relayer,
        l2_verifier: KeyPair,
        bridge_protocol: LTPProtocol,
    ):
        """Packet routed to wrong L2 chain → materializer rejects."""
        msg = BridgeMessage(
            msg_type="token_lock",
            source_chain="ethereum",
            dest_chain="arbitrum",  # Not "optimism"
            sender="0xAlice",
            recipient="0xAlice",
            payload={"token": "USDC", "amount": 50},
            nonce=0,
        )
        commitment, cek = l1_anchor.commit_message(msg)
        packet = relayer.relay(commitment, cek, l2_verifier)

        # Materializer is for "optimism", packet says "arbitrum"
        materializer = L2Materializer(
            bridge_protocol, l2_verifier, chain_id="optimism"
        )
        materializer.set_l1_block_height(100)
        result = materializer.materialize(packet)
        assert result is None


class TestFinalityChecks:
    """L1 finality confirmation requirements."""

    def test_insufficient_finality(
        self,
        l1_anchor: L1Anchor,
        relayer: Relayer,
        l2_materializer: L2Materializer,
        l2_verifier: KeyPair,
    ):
        """Packet from too-recent L1 block → rejected."""
        msg = _make_lock_message(nonce=0)
        commitment, cek = l1_anchor.commit_message(msg)
        packet = relayer.relay(commitment, cek, l2_verifier)

        # L2 thinks L1 is at block 0, but packet is from block 1
        l2_materializer.set_l1_block_height(0)
        result = l2_materializer.materialize(packet)
        assert result is None

    def test_sufficient_finality(
        self,
        l1_anchor: L1Anchor,
        relayer: Relayer,
        l2_materializer: L2Materializer,
        l2_verifier: KeyPair,
    ):
        """Packet with enough confirmations → accepted."""
        msg = _make_lock_message(nonce=0)
        commitment, cek = l1_anchor.commit_message(msg)
        packet = relayer.relay(commitment, cek, l2_verifier)

        l2_materializer.set_l1_block_height(100)
        result = l2_materializer.materialize(packet)
        assert result is not None


class TestTampering:
    """Tamper detection at various layers."""

    def test_wrong_receiver_key(
        self,
        l1_anchor: L1Anchor,
        relayer: Relayer,
        l2_verifier: KeyPair,
        bridge_protocol: LTPProtocol,
    ):
        """Sealed key opened with wrong private key → fails."""
        msg = _make_lock_message(nonce=0)
        commitment, cek = l1_anchor.commit_message(msg)
        packet = relayer.relay(commitment, cek, l2_verifier)

        # Eve tries to materialize with her own key
        eve = KeyPair.generate("eve-bridge-attacker")
        materializer = L2Materializer(
            bridge_protocol, eve, chain_id="optimism"
        )
        materializer.set_l1_block_height(100)
        result = materializer.materialize(packet)
        assert result is None

    def test_corrupted_sealed_key(
        self,
        l1_anchor: L1Anchor,
        relayer: Relayer,
        l2_materializer: L2Materializer,
        l2_verifier: KeyPair,
    ):
        """Bit-flipped sealed key → unseal fails."""
        msg = _make_lock_message(nonce=0)
        commitment, cek = l1_anchor.commit_message(msg)
        packet = relayer.relay(commitment, cek, l2_verifier)

        # Corrupt one byte in the sealed key
        corrupted = bytearray(packet.sealed_key)
        corrupted[500] ^= 0xFF
        corrupted_packet = RelayPacket(
            sealed_key=bytes(corrupted),
            source_chain=packet.source_chain,
            dest_chain=packet.dest_chain,
            nonce=packet.nonce,
            source_block=packet.source_block,
            entity_id=packet.entity_id,
        )

        l2_materializer.set_l1_block_height(100)
        result = l2_materializer.materialize(corrupted_packet)
        assert result is None


class TestMessageSerialization:
    """BridgeMessage canonical serialization round-trip."""

    def test_round_trip(self):
        msg = _make_lock_message(nonce=42)
        data = msg.to_canonical_bytes()
        restored = BridgeMessage.from_bytes(data)

        assert restored.msg_type == msg.msg_type
        assert restored.source_chain == msg.source_chain
        assert restored.dest_chain == msg.dest_chain
        assert restored.sender == msg.sender
        assert restored.recipient == msg.recipient
        assert restored.payload == msg.payload
        assert restored.nonce == msg.nonce
        assert restored.timestamp == msg.timestamp

    def test_canonical_determinism(self):
        """Same message → same bytes every time."""
        msg = _make_lock_message(nonce=7)
        assert msg.to_canonical_bytes() == msg.to_canonical_bytes()
