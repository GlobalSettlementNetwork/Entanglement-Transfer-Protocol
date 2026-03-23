"""
Anchor client — submits AnchorSubmission instances to the on-chain LTPAnchorRegistry.

Bridges the Python trust layer to the Solidity contract via web3.py.
The client reads from AnchorSubmission dataclass fields directly (not
to_calldata() packed bytes), passing individual parameters through
web3.py's contract function interface for standard ABI encoding.

Requires: pip install web3>=6.0.0  (or install ltp[chain])

Reference: GSX_PRE_BLOCKCHAIN_ROADMAP.md §2.10
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..anchor.state import EntityState

__all__ = ["AnchorClient"]

# Minimal ABI for LTPAnchorRegistry — only the functions we call.
_REGISTRY_ABI = [
    {
        "type": "function",
        "name": "anchor",
        "inputs": [
            {"name": "anchorDigest", "type": "bytes32"},
            {"name": "entityIdHash", "type": "bytes32"},
            {"name": "merkleRoot", "type": "bytes32"},
            {"name": "policyHash", "type": "bytes32"},
            {"name": "signerVkHash", "type": "bytes32"},
            {"name": "sequence", "type": "uint64"},
            {"name": "validUntil", "type": "uint64"},
            {"name": "receiptType", "type": "uint8"},
        ],
        "outputs": [],
        "stateMutability": "nonpayable",
    },
    {
        "type": "function",
        "name": "batchAnchor",
        "inputs": [
            {"name": "anchorDigests", "type": "bytes32[]"},
            {"name": "entityIdHashes", "type": "bytes32[]"},
            {"name": "merkleRoots", "type": "bytes32[]"},
            {"name": "policyHashes", "type": "bytes32[]"},
            {"name": "signerVkHashes", "type": "bytes32[]"},
            {"name": "sequences", "type": "uint64[]"},
            {"name": "validUntils", "type": "uint64[]"},
            {"name": "receiptTypes", "type": "uint8[]"},
        ],
        "outputs": [],
        "stateMutability": "nonpayable",
    },
    {
        "type": "function",
        "name": "transitionState",
        "inputs": [
            {"name": "entityIdHash", "type": "bytes32"},
            {"name": "newState", "type": "uint8"},
            {"name": "signerVkHash", "type": "bytes32"},
            {"name": "sequence", "type": "uint64"},
            {"name": "validUntil", "type": "uint64"},
        ],
        "outputs": [],
        "stateMutability": "nonpayable",
    },
    {
        "type": "function",
        "name": "registerSigner",
        "inputs": [{"name": "vkHash", "type": "bytes32"}],
        "outputs": [],
        "stateMutability": "nonpayable",
    },
    {
        "type": "function",
        "name": "revokeSigner",
        "inputs": [{"name": "vkHash", "type": "bytes32"}],
        "outputs": [],
        "stateMutability": "nonpayable",
    },
    {
        "type": "function",
        "name": "isAnchored",
        "inputs": [{"name": "anchorDigest", "type": "bytes32"}],
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "view",
    },
    {
        "type": "function",
        "name": "getEntityState",
        "inputs": [{"name": "entityIdHash", "type": "bytes32"}],
        "outputs": [{"name": "", "type": "uint8"}],
        "stateMutability": "view",
    },
    {
        "type": "function",
        "name": "getSignerSequence",
        "inputs": [{"name": "vkHash", "type": "bytes32"}],
        "outputs": [{"name": "", "type": "uint64"}],
        "stateMutability": "view",
    },
    {
        "type": "function",
        "name": "areAnchored",
        "inputs": [{"name": "anchorDigests", "type": "bytes32[]"}],
        "outputs": [{"name": "", "type": "bool[]"}],
        "stateMutability": "view",
    },
    {
        "type": "function",
        "name": "getEntityStates",
        "inputs": [{"name": "entityIdHashes", "type": "bytes32[]"}],
        "outputs": [{"name": "", "type": "uint8[]"}],
        "stateMutability": "view",
    },
]

# ReceiptType string → uint8 ordinal mapping (mirrors receipt.py ReceiptType enum)
_RECEIPT_TYPE_ORDINALS: dict[str, int] = {
    "COMMIT": 0,
    "MATERIALIZE": 1,
    "SHARD_AUDIT_PASS": 2,
    "KEY_ROTATION": 3,
    "DELETION": 4,
    "GOVERNANCE": 5,
}


class AnchorClient:
    """Submits AnchorSubmission instances to the on-chain LTPAnchorRegistry."""

    def __init__(
        self,
        rpc_url: str,
        contract_address: str,
        private_key: str,
        chain_id: int,
    ) -> None:
        try:
            from web3 import Web3
        except ImportError as e:
            raise ImportError(
                "web3 is required for on-chain anchoring. "
                "Install with: pip install 'ltp[chain]'"
            ) from e

        self._w3 = Web3(Web3.HTTPProvider(rpc_url))
        self._account = self._w3.eth.account.from_key(private_key)
        self._chain_id = chain_id
        self._contract = self._w3.eth.contract(
            address=Web3.to_checksum_address(contract_address),
            abi=_REGISTRY_ABI,
        )

    def _send_tx(self, fn, *, gas: int = 300_000) -> str:
        """Build, sign, and send a contract function call. Returns tx hash hex."""
        tx = fn.build_transaction({
            "from": self._account.address,
            "nonce": self._w3.eth.get_transaction_count(self._account.address),
            "chainId": self._chain_id,
            "gas": gas,
            "gasPrice": self._w3.eth.gas_price,
        })
        signed = self._account.sign_transaction(tx)
        tx_hash = self._w3.eth.send_raw_transaction(signed.raw_transaction)
        return tx_hash.hex()

    def anchor(self, submission: "AnchorSubmission") -> str:
        """Anchor a single submission on-chain. Returns tx hash."""
        from .submission import AnchorSubmission  # noqa: F811

        receipt_ordinal = _RECEIPT_TYPE_ORDINALS.get(submission.receipt_type, 0)
        entity_id_hash = getattr(submission, "entity_id_hash", submission.anchor_digest)
        fn = self._contract.functions.anchor(
            submission.anchor_digest,
            entity_id_hash,
            submission.merkle_root,
            submission.policy_hash,
            submission.signer_vk_hash,
            submission.sequence,
            submission.valid_until,
            receipt_ordinal,
        )
        return self._send_tx(fn)

    def batch_anchor(self, submissions: list["AnchorSubmission"]) -> str:
        """Anchor multiple submissions in a single transaction. Returns tx hash."""
        digests = [s.anchor_digest for s in submissions]
        entity_ids = [
            getattr(s, "entity_id_hash", s.anchor_digest) for s in submissions
        ]
        roots = [s.merkle_root for s in submissions]
        policies = [s.policy_hash for s in submissions]
        signers = [s.signer_vk_hash for s in submissions]
        sequences = [s.sequence for s in submissions]
        valid_untils = [s.valid_until for s in submissions]
        receipt_types = [
            _RECEIPT_TYPE_ORDINALS.get(s.receipt_type, 0) for s in submissions
        ]

        fn = self._contract.functions.batchAnchor(
            digests, entity_ids, roots, policies, signers,
            sequences, valid_untils, receipt_types,
        )
        return self._send_tx(fn, gas=200_000 * len(submissions))

    def transition_state(
        self,
        entity_id_hash: bytes,
        new_state: int,
        signer_vk_hash: bytes,
        sequence: int,
        valid_until: int,
    ) -> str:
        """Transition an entity's state on-chain. Returns tx hash."""
        fn = self._contract.functions.transitionState(
            entity_id_hash, new_state, signer_vk_hash, sequence, valid_until,
        )
        return self._send_tx(fn)

    def register_signer(self, vk_hash: bytes) -> str:
        """Register an authorized signer. Returns tx hash."""
        fn = self._contract.functions.registerSigner(vk_hash)
        return self._send_tx(fn)

    def revoke_signer(self, vk_hash: bytes) -> str:
        """Revoke an authorized signer. Returns tx hash."""
        fn = self._contract.functions.revokeSigner(vk_hash)
        return self._send_tx(fn)

    def is_anchored(self, anchor_digest: bytes) -> bool:
        """Check if an anchor digest has been recorded on-chain."""
        return self._contract.functions.isAnchored(anchor_digest).call()

    def entity_state(self, entity_id_hash: bytes) -> "EntityState":
        """Get the on-chain entity state for an entity ID hash."""
        from ..anchor.state import EntityState
        raw = self._contract.functions.getEntityState(entity_id_hash).call()
        return EntityState(raw)

    def signer_sequence(self, vk_hash: bytes) -> int:
        """Get the current on-chain sequence for a signer VK hash."""
        return self._contract.functions.getSignerSequence(vk_hash).call()

    def are_anchored(self, anchor_digests: list[bytes]) -> list[bool]:
        """Batch check if anchor digests have been recorded on-chain."""
        return self._contract.functions.areAnchored(anchor_digests).call()

    def get_entity_states(self, entity_id_hashes: list[bytes]) -> list["EntityState"]:
        """Batch get entity states for multiple entity ID hashes."""
        from ..anchor.state import EntityState
        raw_states = self._contract.functions.getEntityStates(entity_id_hashes).call()
        return [EntityState(s) for s in raw_states]
