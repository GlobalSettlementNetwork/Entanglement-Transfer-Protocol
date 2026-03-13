"""
Nonce tracker — per-sender monotonic nonce registry for replay protection.

Each (source_chain, sender) pair maintains a high-water mark.  A nonce is
valid iff it is strictly greater than the last processed nonce for that sender.
"""

from __future__ import annotations


class NonceTracker:
    """
    Per-sender monotonic nonce registry.

    Prevents replay attacks by ensuring each (chain, sender) pair's nonce
    is strictly increasing.  The tracker is chain-scoped: L1 and L2 each
    maintain their own instance.
    """

    def __init__(self) -> None:
        # (source_chain, sender) → highest processed nonce
        self._hwm: dict[tuple[str, str], int] = {}

    def validate_and_advance(
        self, source_chain: str, sender: str, nonce: int
    ) -> bool:
        """
        Check nonce and advance the high-water mark if valid.

        Returns True if the nonce is fresh (strictly greater than HWM).
        Returns False if replayed or out of order.
        """
        key = (source_chain, sender)
        current = self._hwm.get(key, -1)
        if nonce <= current:
            return False
        self._hwm[key] = nonce
        return True

    def current_nonce(self, source_chain: str, sender: str) -> int:
        """Return the last processed nonce for a sender, or -1 if unseen."""
        return self._hwm.get((source_chain, sender), -1)
