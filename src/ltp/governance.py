"""
Signer governance for the Lattice Transfer Protocol.

Defines the policy framework for multi-signer authorization:
  - SignerEntry:    A signer's identity, roles, and validity window
  - ApprovalRule:   Required roles/signers for a given action type
  - SignerPolicy:   The complete policy governing receipt authorization

Integrates with existing ComplianceRole and Permission enums from
compliance.py (read-only imports).

Reference: GSX_PRE_BLOCKCHAIN_ROADMAP.md §2.7
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from .encoding import CanonicalEncoder
from .domain import (
    DOMAIN_SIGNER_POLICY,
    domain_hash_bytes,
    domain_sign,
    domain_verify,
    signer_fingerprint,
)
from .primitives import canonical_hash

__all__ = ["SignerEntry", "ApprovalRule", "SignerPolicy"]


@dataclass
class SignerEntry:
    """A signer's identity, roles, and validity window.

    Fields:
        signer_id:       Human-readable identifier (maps to KeyPair.label)
        vk:              ML-DSA-65 verification key
        roles:           Set of authorized roles (e.g. {"operator", "auditor"})
        valid_from:      Epoch from which this entry is active
        valid_until:     Epoch after which this entry is inactive
        predecessor_vk:  Previous VK if this is a key rotation (None otherwise)
    """

    signer_id: str
    vk: bytes
    roles: set[str]
    valid_from: int
    valid_until: int
    predecessor_vk: bytes | None = None


@dataclass
class ApprovalRule:
    """Required authorization for a given action type.

    Fields:
        action_type:     The action this rule governs ("COMMIT", "MATERIALIZE", etc.)
        required_roles:  At least one signer must hold each of these roles
        min_signers:     Minimum number of distinct signers required
        max_age_seconds: Maximum age of a receipt for this action type
    """

    action_type: str
    required_roles: set[str]
    min_signers: int = 1
    max_age_seconds: int = 3600


@dataclass
class SignerPolicy:
    """The complete policy governing receipt authorization.

    A SignerPolicy defines who can sign what, with what thresholds,
    and over what time windows. It is itself signed by a policy authority.

    Fields:
        policy_id:        Content-addressed identifier
        policy_version:   Monotonically increasing version
        signers:          Authorized signer entries
        approval_rules:   Per-action authorization rules
        policy_signature: ML-DSA-65 signature over policy content
    """

    policy_id: str
    policy_version: int
    signers: list[SignerEntry]
    approval_rules: list[ApprovalRule]
    policy_signature: bytes = b""

    def canonical_bytes(self) -> bytes:
        """Deterministic encoding for hashing/signing."""
        enc = (
            CanonicalEncoder(DOMAIN_SIGNER_POLICY)
            .uint32(self.policy_version)
            .uint32(len(self.signers))
        )
        for s in self.signers:
            enc.string(s.signer_id)
            enc.length_prefixed_bytes(s.vk)
            # Encode roles sorted
            sorted_roles = sorted(s.roles)
            enc.uint32(len(sorted_roles))
            for r in sorted_roles:
                enc.string(r)
            enc.uint64(s.valid_from)
            enc.uint64(s.valid_until)
            enc.optional_bytes(s.predecessor_vk)

        enc.uint32(len(self.approval_rules))
        for rule in self.approval_rules:
            enc.string(rule.action_type)
            sorted_roles = sorted(rule.required_roles)
            enc.uint32(len(sorted_roles))
            for r in sorted_roles:
                enc.string(r)
            enc.uint32(rule.min_signers)
            enc.uint32(rule.max_age_seconds)

        return enc.finalize()

    def policy_hash(self) -> str:
        """Content-addressed hash of the policy."""
        return canonical_hash(self.canonical_bytes())

    def sign_policy(self, authority_sk: bytes) -> None:
        """Sign this policy with the policy authority's key."""
        self.policy_id = self.policy_hash()
        self.policy_signature = domain_sign(
            DOMAIN_SIGNER_POLICY, authority_sk, self.canonical_bytes(),
        )

    def verify_policy(self, authority_vk: bytes) -> bool:
        """Verify the policy signature."""
        if not self.policy_signature:
            return False
        return domain_verify(
            DOMAIN_SIGNER_POLICY, authority_vk, self.canonical_bytes(),
            self.policy_signature,
        )

    def is_signer_authorized(self, vk: bytes, action: str, epoch: int) -> bool:
        """Check if a signer (by VK) is authorized for an action at an epoch.

        Returns True if the signer:
          1. Has an active SignerEntry (valid_from <= epoch < valid_until)
          2. Holds at least one role required by the action's ApprovalRule
        """
        # Find the signer entry
        entry = None
        for s in self.signers:
            if s.vk == vk:
                entry = s
                break
        if entry is None:
            return False

        # Check epoch validity
        if not (entry.valid_from <= epoch < entry.valid_until):
            return False

        # Find applicable rule
        rule = None
        for r in self.approval_rules:
            if r.action_type == action:
                rule = r
                break
        if rule is None:
            return False

        # Check role overlap
        return bool(entry.roles & rule.required_roles)

    def verify_receipt(self, receipt: "ApprovalReceipt") -> tuple[bool, str]:
        """Verify a receipt against this policy.

        Checks:
          1. Signer is authorized for the receipt's action type
          2. Receipt is not too old per the action's max_age_seconds
          3. Receipt signature is valid

        Returns: (True, "") or (False, reason)
        """
        # Check signer authorization
        action = receipt.receipt_type.value
        if not self.is_signer_authorized(receipt.signer_vk, action, receipt.epoch):
            return False, f"signer not authorized for {action} at epoch {receipt.epoch}"

        # Check receipt age
        rule = None
        for r in self.approval_rules:
            if r.action_type == action:
                rule = r
                break
        if rule is not None:
            age = time.time() - receipt.timestamp
            if age > rule.max_age_seconds:
                return False, f"receipt too old: {age:.0f}s > {rule.max_age_seconds}s"

        # Check signature
        if not receipt.verify(receipt.signer_vk):
            return False, "invalid signature"

        return True, ""
