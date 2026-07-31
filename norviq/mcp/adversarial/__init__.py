# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Adversarial MCP servers — the conformance harness for the action-firewall.

These are DEFENSIVE test fixtures, in the same spirit as ``norviq/redteam``: a set of MCP servers
that behave badly on purpose, so the firewall's coverage can be measured rather than asserted. Each
server implements a real, published MCP attack class and is driven through the proxy by
``tests/mcp/test_adversarial_harness.py`` and by the kind demo script.

They are servers, not exploits: nothing here attacks a third party, reaches the network, or touches
a real credential. The "secrets" are fixtures in a temp directory. The interesting output is the
scoreboard — including the rows the firewall does NOT catch, which is the honest half of the result
and the reason the harness exists.

Servers:
  benign        — the control. Nothing is wrong with it; if the firewall breaks this, it is broken.
  poisoned      — instructions hidden in a tool description (the classic tool-poisoning payload).
  evasive       — the same intent, obfuscated: homoglyphs, zero-width joiners, schema-buried text,
                  and a paraphrase that no keyword list can reasonably catch.
  rugpull       — serves a clean definition, then changes it after approval.
  shadowing     — registers a tool whose name is visually identical to another server's.
  deputy_a/b    — a two-server confused-deputy: one server can read secrets, the other can send
                  mail; neither is dangerous alone.
"""
