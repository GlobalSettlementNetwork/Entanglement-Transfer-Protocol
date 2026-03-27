"""
Persistent shard storage for the Lattice Transfer Protocol.

Provides:
  - ShardStore       — abstract dict-like interface for shard storage
  - MemoryShardStore — in-memory store (default, compatible with existing behavior)
  - SQLiteShardStore — persistent SQLite-backed store
  - FileShardStore   — persistent filesystem-backed store (one file per shard)
"""

from .base import ShardStore
from .memory import MemoryShardStore
from .sqlite import SQLiteShardStore
from .filesystem import FileShardStore

__all__ = ["ShardStore", "MemoryShardStore", "SQLiteShardStore", "FileShardStore"]
