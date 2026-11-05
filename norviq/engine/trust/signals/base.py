# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Abstract signal contract."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from norviq.engine.trust.models import TrustInput


def collapse_repeated_refusals(history: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """History with each refused call counted once, however often it was retried.

    A retried call is the SAME tool with the SAME parameters (``tool_name`` + ``param_hash``). Without
    this, an agent stuck retrying one blocked call — a policy loop, or a client that retries on any
    error — added a block per attempt, crossed the violation cap's 20% band and was capped to 0.30, so
    its UNRELATED benign calls escalated too. Measured on kind: 12 retries of one refused run_query took
    trust 0.8 -> 0.30, and post_message and search_issues on another MCP server then escalated. It is
    also a denial of service anyone can trigger against an agent: make it retry something refused.

    Only the repetition is collapsed. A different tool or different parameters is a different attempt
    and counts again, so an attacker probing with variations still loses trust on every variant, and
    every call is still blocked — this changes the score, never the decision. The first occurrence is
    kept, so a retry loop does not keep resetting time_decay's "last block" clock either. Entries
    without both keys are left alone: the calculator's history-unavailable fallback fabricates twenty
    keyless blocks to mean "assume the worst", and collapsing them would quietly undo that.
    """
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, Any]] = []
    for entry in sorted(history, key=lambda e: e.get("timestamp_unix") or 0):
        tool, params = entry.get("tool_name"), entry.get("param_hash")
        if entry.get("decision") == "block" and tool and params:
            key = (str(tool), str(params))
            if key in seen:
                continue
            seen.add(key)
        out.append(entry)
    return out


class BaseSignal(ABC):
    """Compute one trust signal between zero and one."""

    @abstractmethod
    async def compute(self, input_data: TrustInput, history: list[dict[str, Any]], profile: dict[str, Any]) -> float:
        """Return normalized trust contribution."""
