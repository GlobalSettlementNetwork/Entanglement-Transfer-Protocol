"""
Cross-deployment federation for the Lattice Transfer Protocol.

Enables independently bootstrapped LTP networks to discover each other,
establish trust, and resolve entities across network boundaries.

Whitepaper reference: Open Question 7
Design decision: docs/design-decisions/CROSS_DEPLOYMENT_FEDERATION.md
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .primitives import canonical_hash, internal_hash_bytes

__all__ = [
    "TrustLevel",
    "FederationConfig",
    "FederatedNetwork",
    "EntityResolution",
    "FederationRegistry",
]


class TrustLevel(Enum):
    """Trust level for a federated network."""
    UNTRUSTED = "untrusted"       # Discovered but not verified
    VERIFIED = "verified"         # STH exchange successful, identity confirmed
    FEDERATED = "federated"       # Full bidirectional federation established


class DiscoveryMethod(Enum):
    """How networks discover each other."""
    STATIC = "static"             # Manually configured
    DNS = "dns"                   # DNS-based discovery (like ENR)
    ONCHAIN = "onchain"           # Shared L1 registry


@dataclass
class FederationConfig:
    """Configuration for federation behavior."""
    enabled: bool = False
    discovery_method: DiscoveryMethod = DiscoveryMethod.STATIC
    min_trust_for_resolution: TrustLevel = TrustLevel.VERIFIED
    sth_exchange_interval_epochs: int = 24   # Exchange STHs every 24 epochs
    max_resolution_hops: int = 2             # Max networks to traverse


@dataclass
class FederatedNetwork:
    """
    Represents a remote LTP network in the federation.

    Each federated network has:
      - A unique network_id derived from its genesis STH
      - A discovery endpoint for entity resolution
      - A public key for STH signature verification
      - Trust level tracking for progressive trust establishment
    """
    network_id: str                # Unique identifier (H(genesis_sth))
    display_name: str              # Human-readable name
    discovery_endpoint: str        # URL or address for resolution queries
    public_key: bytes              # ML-DSA-65 public key for STH verification
    trust_level: TrustLevel = TrustLevel.UNTRUSTED
    last_sth: Optional[dict] = None
    last_sth_verified_epoch: int = -1
    registered_at: float = 0.0
    entity_count: int = 0          # Known entity count from last STH

    @property
    def is_trusted(self) -> bool:
        return self.trust_level in (TrustLevel.VERIFIED, TrustLevel.FEDERATED)

    @property
    def is_federated(self) -> bool:
        return self.trust_level == TrustLevel.FEDERATED


@dataclass
class EntityResolution:
    """
    Result of resolving an entity_id to its home network.

    Used by receivers to find which network holds the shards
    for a given entity_id when it's not in the local network.
    """
    entity_id: str
    found: bool
    home_network_id: Optional[str] = None
    home_network_name: Optional[str] = None
    shard_endpoints: list[str] = field(default_factory=list)
    resolution_hops: int = 0
    resolution_time_ms: float = 0.0
    trust_level: Optional[TrustLevel] = None

    @property
    def is_cross_network(self) -> bool:
        return self.found and self.home_network_id is not None


class FederationRegistry:
    """
    Manages the federation of LTP networks.

    Responsibilities:
      - Network discovery and registration
      - Trust level management
      - Cross-network entity resolution
      - STH exchange and verification
    """

    def __init__(self, config: FederationConfig | None = None) -> None:
        self.config = config or FederationConfig()
        self._networks: dict[str, FederatedNetwork] = {}
        self._local_network_id: Optional[str] = None
        # Local entity index: entity_id → True (for resolution)
        self._local_entities: set[str] = set()
        # Cross-network entity cache: entity_id → network_id
        self._resolution_cache: dict[str, str] = {}

    def set_local_network_id(self, network_id: str) -> None:
        """Set the local network's identifier."""
        self._local_network_id = network_id

    def register_local_entity(self, entity_id: str) -> None:
        """Register an entity as existing in the local network."""
        self._local_entities.add(entity_id)

    def register_network(
        self,
        network_id: str,
        display_name: str,
        discovery_endpoint: str,
        public_key: bytes,
    ) -> FederatedNetwork:
        """
        Register a new federated network.

        Initially registered as UNTRUSTED. Trust is escalated via
        STH verification and mutual agreement.
        """
        if network_id in self._networks:
            raise ValueError(f"Network '{network_id}' already registered")

        if network_id == self._local_network_id:
            raise ValueError("Cannot register self as federated network")

        network = FederatedNetwork(
            network_id=network_id,
            display_name=display_name,
            discovery_endpoint=discovery_endpoint,
            public_key=public_key,
            registered_at=time.time(),
        )
        self._networks[network_id] = network
        return network

    def unregister_network(self, network_id: str) -> bool:
        """Remove a network from the federation."""
        removed = self._networks.pop(network_id, None)
        if removed:
            # Clean resolution cache
            self._resolution_cache = {
                eid: nid for eid, nid in self._resolution_cache.items()
                if nid != network_id
            }
        return removed is not None

    def upgrade_trust(
        self,
        network_id: str,
        new_level: TrustLevel,
    ) -> bool:
        """
        Upgrade a network's trust level.

        Trust can only be escalated, never downgraded (use revoke_trust).
        UNTRUSTED → VERIFIED: requires successful STH exchange
        VERIFIED → FEDERATED: requires mutual agreement
        """
        network = self._networks.get(network_id)
        if network is None:
            return False

        current_order = [TrustLevel.UNTRUSTED, TrustLevel.VERIFIED, TrustLevel.FEDERATED]
        current_idx = current_order.index(network.trust_level)
        new_idx = current_order.index(new_level)

        if new_idx <= current_idx:
            return False  # Can't downgrade via upgrade

        network.trust_level = new_level
        return True

    def revoke_trust(self, network_id: str) -> bool:
        """Revoke trust for a network (set to UNTRUSTED)."""
        network = self._networks.get(network_id)
        if network is None:
            return False
        network.trust_level = TrustLevel.UNTRUSTED
        return True

    def verify_sth(
        self,
        network_id: str,
        sth: dict,
        current_epoch: int,
    ) -> bool:
        """
        Verify a Signed Tree Head from a federated network.

        Checks:
          1. STH is properly structured
          2. Monotonically increasing sequence/timestamp
          3. Signature valid against network's public key (simulated)

        On success, updates trust to VERIFIED if currently UNTRUSTED.
        """
        network = self._networks.get(network_id)
        if network is None:
            return False

        # Validate STH structure
        required_fields = {"sequence", "root_hash", "timestamp", "record_count"}
        if not required_fields.issubset(sth.keys()):
            return False

        # Monotonicity check
        if network.last_sth is not None:
            if sth["sequence"] <= network.last_sth["sequence"]:
                return False
            if sth["timestamp"] < network.last_sth["timestamp"]:
                return False

        # Simulated signature verification
        # Production: MLDSA.verify(network.public_key, sth_bytes, sth_signature)
        sth_hash = canonical_hash(str(sth).encode())
        if not sth_hash:
            return False

        # Update network state
        network.last_sth = dict(sth)
        network.last_sth_verified_epoch = current_epoch
        network.entity_count = sth.get("record_count", 0)

        # Auto-upgrade trust if currently untrusted
        if network.trust_level == TrustLevel.UNTRUSTED:
            network.trust_level = TrustLevel.VERIFIED

        return True

    def resolve_entity(
        self,
        entity_id: str,
    ) -> EntityResolution:
        """
        Resolve an entity_id to its home network.

        Resolution order:
          1. Check local network
          2. Check resolution cache
          3. Query federated networks (in trust order)

        Only queries networks meeting min_trust_for_resolution.
        """
        t0 = time.monotonic()

        # 1. Check local
        if entity_id in self._local_entities:
            elapsed = (time.monotonic() - t0) * 1000
            return EntityResolution(
                entity_id=entity_id,
                found=True,
                home_network_id=self._local_network_id,
                home_network_name="local",
                resolution_time_ms=round(elapsed, 3),
                trust_level=TrustLevel.FEDERATED,
            )

        # 2. Check cache
        cached_network_id = self._resolution_cache.get(entity_id)
        if cached_network_id and cached_network_id in self._networks:
            network = self._networks[cached_network_id]
            elapsed = (time.monotonic() - t0) * 1000
            return EntityResolution(
                entity_id=entity_id,
                found=True,
                home_network_id=network.network_id,
                home_network_name=network.display_name,
                shard_endpoints=[network.discovery_endpoint],
                resolution_hops=0,
                resolution_time_ms=round(elapsed, 3),
                trust_level=network.trust_level,
            )

        # 3. Query federated networks
        min_trust = self.config.min_trust_for_resolution
        trust_order = [TrustLevel.FEDERATED, TrustLevel.VERIFIED, TrustLevel.UNTRUSTED]
        min_idx = trust_order.index(min_trust)

        for network in sorted(
            self._networks.values(),
            key=lambda n: trust_order.index(n.trust_level),
        ):
            if trust_order.index(network.trust_level) > min_idx:
                continue

            # Simulated resolution query
            # Production: HTTP/gRPC query to network.discovery_endpoint
            # For PoC, we check if entity_id hash maps to this network
            resolution_hash = internal_hash_bytes(
                entity_id.encode() + network.network_id.encode()
            )
            # In production, this would be an actual network query
            # The simulation always returns "not found" for remote queries
            # since we can't actually contact remote networks in the PoC

        elapsed = (time.monotonic() - t0) * 1000
        return EntityResolution(
            entity_id=entity_id,
            found=False,
            resolution_time_ms=round(elapsed, 3),
        )

    def register_resolution(
        self,
        entity_id: str,
        network_id: str,
    ) -> bool:
        """
        Manually register that an entity exists on a specific network.

        Used when resolution succeeds via out-of-band means (e.g.,
        the lattice key contains a network hint).
        """
        if network_id not in self._networks:
            return False
        self._resolution_cache[entity_id] = network_id
        return True

    def get_network(self, network_id: str) -> Optional[FederatedNetwork]:
        return self._networks.get(network_id)

    @property
    def federated_networks(self) -> list[FederatedNetwork]:
        return [n for n in self._networks.values() if n.is_federated]

    @property
    def verified_networks(self) -> list[FederatedNetwork]:
        return [n for n in self._networks.values() if n.is_trusted]

    @property
    def all_networks(self) -> list[FederatedNetwork]:
        return list(self._networks.values())
