# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""LangGraph agent whose tools come from REAL MCP servers, governed by the Norviq MCP firewall.

Same shape as `agent.py`, one substitution: `protect(tools, interceptor)` is gone. There is nothing
to wrap, because no tool body lives in this process — every tool is a `tools/call` to a
`python -m norviq.mcp --http` sidecar on loopback, which adjudicates it before the upstream server
sees it. Gate A runs on `initialize`/`tools/list`, Gate B on `tools/call`.

That difference is the demo's point. In `agent.py` the enforcement point is a Python decorator, so
it governs the calls this process happens to route through it. Here the enforcement point is a
different process holding the only network path to the tool, so it governs the calls regardless of
what this process does — including calls made by code that never heard of Norviq.
"""

from __future__ import annotations

import os

from langchain_groq import ChatGroq
from langgraph.prebuilt import create_react_agent

from mcp_tools import aclose, load_mcp_tools, servers_from_env

# Same default and same caveat as agent.py: tool-calling reliability varies by model, and a
# `tool_use_failed` is a model problem, not a Norviq wiring problem.
llm = ChatGroq(
    model=os.getenv("GROQ_MODEL", "openai/gpt-oss-120b"),
    api_key=os.getenv("GROQ_API_KEY"),
    temperature=0,
)

# Reported to the policy engine by the SIDECARS, not by this process — each firewall derives its own
# session id from its attested identity (`mcp-http-<svid>`). This constant exists so /chat can echo
# something stable to the UI and so the two demo paths answer the same shape.
SESSION_ID = os.getenv("NRVQ_SESSION_ID", "demo-session-mcp")

# Same persona knob as agent.py, and the same reason for it: point NRVQ_CHATBOT_SYSTEM_PROMPT at a
# capable-agent persona and let the firewall — not the prompt — be what stops a destructive call.
SYSTEM_PROMPT = os.getenv(
    "NRVQ_CHATBOT_SYSTEM_PROMPT",
    "You are a helpful customer support agent for Acme Corp.\n"
    "Your tools are provided by MCP servers: a knowledge base, a CRM, and an operations server.\n"
    "Use them to answer questions about policies, customers, orders and tickets.\n"
    "If a tool comes back saying a call was blocked by policy, tell the user plainly what was "
    "refused and why, and do not retry it.",
)

_agent = None
_tools: list = []
_problems: list[str] = []


async def get_agent():
    """Build the agent on first use, then reuse it.

    Construction is async because discovery is a network round trip — `agent.py` can build at import
    because its tools are local functions, and this module cannot. It is NOT built at import via
    `asyncio.run()`: that would make importing this module fail whenever a sidecar is a second slow
    to bind, and an import-time failure takes the whole web server down instead of one request.

    Not locked. The demo serves one request at a time and a concurrent double-build would cost a
    duplicated discovery, not a wrong answer — a lock here would imply a contention story this
    example does not have.
    """
    global _agent, _tools, _problems
    if _agent is None:
        _tools, _problems = await load_mcp_tools(servers_from_env())
        _agent = create_react_agent(model=llm, tools=_tools, prompt=SYSTEM_PROMPT)
    return _agent


def tool_names() -> list[str]:
    """Names of the tools discovery actually returned — empty until `get_agent()` has run."""
    return [t.name for t in _tools]


def discovery_problems() -> list[str]:
    """Endpoints that did not answer discovery. A DENIED tool is not in here; it is simply absent
    from `tool_names()`, because Gate A withholding a definition is the control working."""
    return list(_problems)


async def close() -> None:
    """Mirror of `agent.py`'s `engine.close()` so app.py's lifespan is identical in both modes."""
    await aclose()
