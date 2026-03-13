"""
Commitment network backends for the Lattice Transfer Protocol.

Provides pluggable backend implementations for the commitment log and
network economics layer:

  - CommitmentBackend   — abstract interface every backend must implement
  - LocalBackend        — in-memory backend (default, used by PoC and tests)
  - MonadL1Backend      — custom L1 based on Monad-style parallel EVM execution
  - EthereumBackend     — Ethereum L1/L2 using smart contracts for commitment log

Usage:
  from ltp.backends import BackendConfig, create_backend

  # Option 1: Custom L1 (Monad fork)
  backend = create_backend(BackendConfig(backend_type="monad-l1", ...))

  # Option 2: Ethereum
  backend = create_backend(BackendConfig(backend_type="ethereum", ...))

  # Default: local in-memory
  backend = create_backend(BackendConfig(backend_type="local"))
"""

from .base import CommitmentBackend, BackendConfig, BackendCapabilities
from .local import LocalBackend
from .monad_l1 import MonadL1Backend
from .ethereum import EthereumBackend
from .factory import create_backend

__all__ = [
    "CommitmentBackend",
    "BackendConfig",
    "BackendCapabilities",
    "LocalBackend",
    "MonadL1Backend",
    "EthereumBackend",
    "create_backend",
]
