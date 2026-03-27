"""
gRPC server for a commitment node.

Wraps a CommitmentNode and exposes its shard operations over the network.
"""

from __future__ import annotations

import logging
from concurrent import futures
from typing import TYPE_CHECKING, Iterator

import grpc

from . import shard_service_pb2 as pb2
from . import shard_service_pb2_grpc as pb2_grpc

if TYPE_CHECKING:
    from ..commitment import CommitmentNode

logger = logging.getLogger(__name__)

__all__ = ["NodeServer"]


class _ShardServicer(pb2_grpc.ShardServiceServicer):
    """gRPC servicer backed by a CommitmentNode."""

    def __init__(self, node: "CommitmentNode") -> None:
        self._node = node

    def StoreShard(self, request: pb2.StoreShardRequest, context) -> pb2.StoreShardResponse:
        ok = self._node.store_shard(request.entity_id, request.shard_index, request.encrypted_data)
        if not ok:
            return pb2.StoreShardResponse(success=False, error="node evicted")
        return pb2.StoreShardResponse(success=True)

    def FetchShard(self, request: pb2.FetchShardRequest, context) -> pb2.FetchShardResponse:
        data = self._node.fetch_shard(request.entity_id, request.shard_index)
        if data is None:
            return pb2.FetchShardResponse(found=False)
        return pb2.FetchShardResponse(found=True, encrypted_data=data)

    def AuditChallenge(self, request: pb2.AuditChallengeRequest, context) -> pb2.AuditChallengeResponse:
        proof = self._node.respond_to_audit(
            request.entity_id, request.shard_index, request.nonce,
        )
        if proof is None:
            return pb2.AuditChallengeResponse(found=False)
        return pb2.AuditChallengeResponse(found=True, proof_hash=proof)

    def RemoveShard(self, request: pb2.RemoveShardRequest, context) -> pb2.RemoveShardResponse:
        removed = self._node.remove_shard(request.entity_id, request.shard_index)
        return pb2.RemoveShardResponse(removed=removed)

    def GetNodeInfo(self, request: pb2.NodeInfoRequest, context) -> pb2.NodeInfoResponse:
        return pb2.NodeInfoResponse(
            node_id=self._node.node_id,
            region=self._node.region,
            shard_count=self._node.shard_count,
            evicted=self._node.evicted,
            reputation_score=self._node.reputation_score,
        )

    def FetchShardsBatch(self, request: pb2.FetchShardsBatchRequest, context) -> pb2.FetchShardsBatchResponse:
        responses = []
        for req in request.requests:
            data = self._node.fetch_shard(req.entity_id, req.shard_index)
            if data is None:
                responses.append(pb2.FetchShardResponse(found=False))
            else:
                responses.append(pb2.FetchShardResponse(found=True, encrypted_data=data))
        return pb2.FetchShardsBatchResponse(responses=responses)

    def StoreShardsStream(self, request_iterator: Iterator, context) -> pb2.StoreShardsStreamResponse:
        stored = 0
        failed = 0
        for req in request_iterator:
            ok = self._node.store_shard(req.entity_id, req.shard_index, req.encrypted_data)
            if ok:
                stored += 1
            else:
                failed += 1
        return pb2.StoreShardsStreamResponse(stored_count=stored, failed_count=failed)


class NodeServer:
    """gRPC server wrapping a CommitmentNode.

    Usage:
        node = CommitmentNode("n1", "US-East")
        server = NodeServer(node, port=50051)
        server.start()
        # ... server is running ...
        server.stop()
    """

    def __init__(
        self,
        node: "CommitmentNode",
        port: int = 50051,
        host: str = "0.0.0.0",
        max_workers: int = 10,
    ) -> None:
        self._node = node
        self._port = port
        self._host = host
        self._server = grpc.server(futures.ThreadPoolExecutor(max_workers=max_workers))
        pb2_grpc.add_ShardServiceServicer_to_server(
            _ShardServicer(node), self._server,
        )
        self._server.add_insecure_port(f"{host}:{port}")

    @property
    def node(self) -> "CommitmentNode":
        return self._node

    @property
    def address(self) -> str:
        return f"{self._host}:{self._port}"

    def start(self) -> None:
        """Start serving (non-blocking)."""
        self._server.start()
        logger.info("NodeServer %s listening on %s:%d", self._node.node_id, self._host, self._port)

    def stop(self, grace: float = 1.0) -> None:
        """Stop the server."""
        self._server.stop(grace)
        logger.info("NodeServer %s stopped", self._node.node_id)

    def wait_for_termination(self, timeout: float | None = None) -> None:
        """Block until the server terminates."""
        self._server.wait_for_termination(timeout=timeout)
