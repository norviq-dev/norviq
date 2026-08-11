# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Model Context Protocol (MCP) action-firewall.

Norviq is a policy enforcement point for agent TOOL CALLS. MCP is a wire protocol for tool calls,
so the engine already models everything an ``mcp/tools/call`` carries — this package is the
protocol adapter, not a second engine:

    MCP  {"method":"tools/call","params":{"name":..., "arguments":{...}}}
              |
              v   (1:1, no new evaluate contract)
    ToolCallEvent{tool_name=name, tool_params=arguments, agent_identity=<caller's SVID>}
              |
              v
    POST /api/v1/evaluate  ->  PolicyDecision{allow|audit|block|escalate}

Two gates:

* **Gate B — invocation.** Every ``tools/call`` (and, in scope, ``resources/read`` and
  ``sampling/createMessage``) is evaluated BEFORE it reaches the upstream server. A block is
  answered locally; the server never executes it. Output DLP masks the result on the way back.

* **Gate A — discovery.** ``initialize`` / ``tools/list`` responses are scanned for instructions
  hidden in tool DEFINITIONS (tool poisoning) and content-hash pinned so a server that later
  changes a definition (rug pull) is detected. Gate A runs at discovery and on
  ``notifications/tools/list_changed`` ONLY — the per-call path does one dict lookup.

Gate A is a heuristic and is evadable by construction; Gate B is the deterministic backstop. See
DESIGN-NOTE-MCP-FIREWALL.md for the threat model and what this honestly does not catch.
"""

from norviq.mcp.protocol import JsonRpcMessage
from norviq.mcp.firewall import McpFirewall, MediationResult

__all__ = ["JsonRpcMessage", "McpFirewall", "MediationResult"]
