# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Upstream MCP servers for the Norviq chatbot demo.

Three servers -- kb, crm and ops -- selected at start-up by ``python -m demo_mcp --server <id>``.
They are ordinary MCP servers built on the official SDK's FastMCP; nothing in here imports Norviq,
because the firewall that governs them runs in the CALLER's pod. See ``servers.py``.
"""

from __future__ import annotations

from .servers import CONTRACT_TOOLS, SERVER_IDS, build_server, verify_catalog

__all__ = ["CONTRACT_TOOLS", "SERVER_IDS", "build_server", "verify_catalog"]
