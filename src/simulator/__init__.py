"""
LTP Network Simulator — Discrete-event simulation of the Lattice Transfer Protocol.

Provides a realistic, simulation-native network environment for exercising
the full LTP commit/lattice/materialize lifecycle across geographically
distributed nodes with modelled latency, bandwidth, packet loss, storage
capacity, node churn, and failure injection.

Core components:
  - SimClock / Event / EventQueue    — deterministic discrete-event engine
  - Link / Region / Topology         — network graph with latency/bandwidth
  - SimNode                          — capacity-bounded node wrapping CommitmentNode
  - Message / MessageBus             — delivery simulation with realistic timing
  - SimClient                        — sender/receiver agents at a location
  - NetworkSimulator                 — top-level orchestrator and failure injection
  - MetricsCollector                 — latency, throughput, availability analytics
  - DockerNodeManager                — optional Docker-based real-process nodes
"""

from .clock import SimClock, Event, EventQueue
from .topology import Link, Region, Topology
from .node import SimNode, StorageCapacity
from .message import Message, MessageBus, MessageType
from .client import SimClient
from .network import NetworkSimulator
from .metrics import MetricsCollector, TransferMetrics
from .docker_node import DockerNodeManager, DockerNode

__all__ = [
    "SimClock",
    "Event",
    "EventQueue",
    "Link",
    "Region",
    "Topology",
    "SimNode",
    "StorageCapacity",
    "Message",
    "MessageBus",
    "MessageType",
    "SimClient",
    "NetworkSimulator",
    "MetricsCollector",
    "TransferMetrics",
    "DockerNodeManager",
    "DockerNode",
]
