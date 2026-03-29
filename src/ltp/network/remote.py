"""
RemoteNode: CommitmentNode-compatible proxy that routes through gRPC.

Allows CommitmentNetwork to treat remote nodes identically to local nodes.
The shard operations (store, fetch, audit, remove) go over the network.
"""

from __future__ import annotations

from typing import Optional

from .client import NodeClient

__all__ = ["RemoteNode"]


class RemoteNode:
    """A commitment node proxy that delegates shard operations to a remote gRPC server.

    Quacks like CommitmentNode — has the same shard methods and properties —
    so CommitmentNetwork can use it transparently.

    Usage:
        node = RemoteNode("n1", "US-East", "10.0.1.5:50051")
        network.add_existing_node(node)  # network treats it like any node
    """

    def __init__(
        self,
        node_id: str,
        region: str,
        address: str,
        timeout: float = 10.0,
    ) -> None:
        self.node_id = node_id
        self.region = region
        self.strikes: int = 0
        self.audit_passes: int = 0
        self.evicted: bool = False
        self.stake: float = 0.0
        self.stake_locked_until: float = 0.0
        self.pending_slashes: list = []
        self.offense_history: list = []
        self.reputation_score: float = 1.0
        self.registered_at: float = 0.0
        self.evicted_at: float = 0.0
        self.eviction_count: int = 0
        self.withheld_earnings: float = 0.0
        self.total_earnings: float = 0.0

        self._address = address
        self._client = NodeClient(address, timeout=timeout)
        self._shard_proxy = _RemoteShardProxy(self._client)

    @property
    def shards(self) -> "_RemoteShardProxy":
        """Dict-like proxy — allows `node.shards[key]` to go over gRPC."""
        return self._shard_proxy

    @property
    def shard_count(self) -> int:
        info = self._client.get_node_info()
        return info["shard_count"]

    def store_shard(self, entity_id: str, shard_index: int, encrypted_data: bytes) -> bool:
        if self.evicted:
            return False
        return self._client.store_shard(entity_id, shard_index, encrypted_data)

    def fetch_shard(self, entity_id: str, shard_index: int) -> Optional[bytes]:
        if self.evicted:
            return None
        return self._client.fetch_shard(entity_id, shard_index)

    def respond_to_audit(self, entity_id: str, shard_index: int, nonce: bytes) -> Optional[str]:
        if self.evicted:
            return None
        return self._client.audit_challenge(entity_id, shard_index, nonce)

    def remove_shard(self, entity_id: str, shard_index: int) -> bool:
        return self._client.remove_shard(entity_id, shard_index)

    def close(self) -> None:
        self._client.close()


class _RemoteShardProxy:
    """Minimal dict-like proxy for remote shard access.

    Supports: __getitem__, __setitem__, __delitem__, __contains__,
    get(), keys() (limited — uses node info for count).
    """

    def __init__(self, client: NodeClient) -> None:
        self._client = client

    def __getitem__(self, key: tuple[str, int]) -> bytes:
        data = self._client.fetch_shard(key[0], key[1])
        if data is None:
            raise KeyError(key)
        return data

    def __setitem__(self, key: tuple[str, int], value: bytes) -> None:
        self._client.store_shard(key[0], key[1], value)

    def __delitem__(self, key: tuple[str, int]) -> None:
        if not self._client.remove_shard(key[0], key[1]):
            raise KeyError(key)

    def __contains__(self, key: tuple[str, int]) -> bool:
        return self._client.fetch_shard(key[0], key[1]) is not None

    def get(self, key: tuple[str, int], default=None):
        data = self._client.fetch_shard(key[0], key[1])
        return data if data is not None else default
