# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""FastAPI wrapper around the demo LangGraph agent.

Two enforcement surfaces, one `/chat` contract, selected by `NRVQ_DEMO_TOOLS`:

  * `mcp`   (default) — tools come from three real MCP servers, reached through the Norviq MCP
    firewall sidecars on 127.0.0.1:9101/9102/9103. Gate A adjudicates discovery, Gate B the call.
  * `local` — the original in-process path: tools.py functions wrapped by the SDK's `protect()`.

`local` is kept because the repo's README documents it and it is the reference the other four
`agent_*.py` variants imitate; deleting it silently would break a documented demo. The two modes
answer the SAME response shape so the page can render either without knowing which is running.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from dotenv import load_dotenv

load_dotenv()  # load examples/chatbot/.env before agent.py reads GROQ_API_KEY / NRVQ_* at import

from fastapi import FastAPI  # noqa: E402 - after load_dotenv(), by design
from fastapi.responses import HTMLResponse  # noqa: E402 - after load_dotenv(), by design
from pydantic import BaseModel  # noqa: E402 - after load_dotenv(), by design

from chat_ui import chat_page  # noqa: E402 - after load_dotenv(), by design

_MODE = os.getenv("NRVQ_DEMO_TOOLS", "mcp").lower()
if _MODE not in ("mcp", "local"):
    raise SystemExit(f"unknown NRVQ_DEMO_TOOLS={_MODE!r}; choose 'mcp' or 'local'")

# Imported per mode, not both. Importing `agent` constructs the SDK interceptor and wraps the local
# tools; importing `agent_mcp` constructs a Groq client. Doing both would build an enforcement path
# that is not in use, and the unused one would still show up in logs and in the audit trail.
if _MODE == "mcp":
    import agent_mcp  # noqa: E402 - after load_dotenv(), by design
    from mcp_tools import capture_mcp_calls, probe  # noqa: E402 - after load_dotenv(), by design

    SESSION_ID = agent_mcp.SESSION_ID
    _SURFACE = "mcp"
else:
    from norviq.sdk import NorviqBlockError, NorviqEscalateError  # noqa: E402 - after load_dotenv()

    from agent import SESSION_ID, agent, engine  # noqa: E402 - after load_dotenv(), by design

    _SURFACE = "sdk"


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    """Warm the MCP catalog at startup, and release connections on shutdown.

    Discovery is warmed rather than required: three sidecars start independently of this container,
    so a failure here is far more likely to be a startup race than a real fault, and refusing to
    become ready would turn that race into a crash loop. A genuinely unreachable sidecar surfaces as
    a missing tool on `/tools` and as a discovery problem in the log — visible, not fatal.
    """
    if _MODE == "mcp":
        try:
            await agent_mcp.get_agent()
        except Exception as exc:  # noqa: BLE001 — see the docstring: warm, do not gate readiness
            print(f"[startup] MCP discovery not complete yet: {type(exc).__name__}: {exc}", flush=True)
    yield
    if _MODE == "mcp":
        await agent_mcp.close()
    else:
        await engine.close()


app = FastAPI(title="Norviq Demo Chatbot", version="0.1.0", lifespan=lifespan)


class ChatRequest(BaseModel):
    """Request payload for chat endpoint."""

    message: str


class ChatResponse(BaseModel):
    """Response payload with model answer, tool calls, and any policy denial."""

    reply: str
    tools_called: list[str] = []
    session_id: str = SESSION_ID
    # Populated only when Norviq refused a call: the rule that fired and the decision.
    denied_by: str = ""
    decision: str = ""
    # Which enforcement surface adjudicated: "mcp" (a firewall sidecar) or "sdk" (in-process).
    # The page renders this, because "a tool was blocked" is a much weaker claim than "the MCP
    # firewall in front of the ops server blocked it at Gate B".
    enforced_by: str = _SURFACE
    # Parallel to tools_called: the MCP server id each call went to. Empty strings in local mode,
    # where there is no server — the field stays present so the page has one shape to render.
    tool_servers: list[str] = []
    # The subset of tools_called that Norviq REFUSED. tools_called keeps its documented meaning —
    # every call the model attempted — but on the MCP path a refused turn typically continues (the
    # firewall answers with `isError`, so the model routes around and calls something else), and a
    # response that could not separate the two would let the page put a green "ran tool" chip on a
    # call that never executed. That is the one claim this demo must never get wrong.
    tools_blocked: list[str] = []
    denied_server: str = ""
    gate: str = ""


@app.get("/health")
async def health() -> dict[str, str]:
    """Liveness check endpoint."""
    return {"status": "ok", "tools": _MODE}


@app.get("/", response_class=HTMLResponse)
async def home() -> str:
    """Minimal chat UI so a human can drive the demo and watch Norviq enforce."""
    return chat_page("LangChain", surface=_SURFACE)


async def _chat_local(message: str) -> ChatResponse:
    """The original in-process SDK path, unchanged.

    A block/escalate decision raises out of the agent loop BEFORE the tool body runs. The model can
    pick a denied tool on any turn, so this is a normal outcome returned as a safe reply, not a 500.
    """
    try:
        result = await agent.ainvoke({"messages": [{"role": "user", "content": message}]})
    except NorviqBlockError as exc:
        return ChatResponse(
            reply=f"I can't do that — a tool call was blocked by policy ({exc.decision.reason}).",
            tools_called=[],
            denied_by=exc.decision.rule_id,
            decision="block",
        )
    except NorviqEscalateError as exc:
        return ChatResponse(
            reply=f"That needs human approval before it can run ({exc.decision.reason}).",
            tools_called=[],
            denied_by=exc.decision.rule_id,
            decision="escalate",
        )
    messages = result.get("messages", [])
    reply = messages[-1].content if messages else "No response"
    tools_called: list[str] = []
    for msg in messages:
        if hasattr(msg, "tool_calls") and msg.tool_calls:
            for tool_call in msg.tool_calls:
                tools_called.append(tool_call.get("name", ""))
    return ChatResponse(
        reply=str(reply),
        tools_called=tools_called,
        tool_servers=[""] * len(tools_called),
    )


async def _chat_mcp(message: str) -> ChatResponse:
    """The MCP path.

    Nothing Norviq-shaped propagates here and that is by design: the firewall answers a blocked
    `tools/call` with an `isError` result so the refusal lands in the model's context (see
    `tool_error_result` in norviq/mcp/protocol.py). The agent therefore finishes its turn normally
    and paraphrases the refusal. `capture_mcp_calls` is what makes the decision reportable anyway —
    the same problem, and the same solution, as serve.py's `capture_decisions` for the SDK path.

    The reply kept is the MODEL's, not a canned string: on this path the model was told it was
    refused and got to answer the user about it, which is the behaviour the `isError` shape exists
    to produce. The badge carries the machine-readable truth alongside it.
    """
    agent_impl = await agent_mcp.get_agent()
    with capture_mcp_calls() as calls:
        try:
            result = await agent_impl.ainvoke({"messages": [{"role": "user", "content": message}]})
        except Exception as exc:  # noqa: BLE001 — a real agent error is still a reply, never a 500
            return ChatResponse(
                reply=f"(agent error: {type(exc).__name__}: {exc})",
                tools_called=[c.tool for c in calls],
                tool_servers=[c.server_id for c in calls],
            )
    messages = result.get("messages", [])
    reply = messages[-1].content if messages else "No response"
    # From the recorder, not from the message list: the recorder is the layer that actually issued
    # each `tools/call`, so it cannot report a call the agent only intended to make.
    denied = [c for c in calls if c.denial is not None]
    response = ChatResponse(
        reply=str(reply),
        tools_called=[c.tool for c in calls],
        tool_servers=[c.server_id for c in calls],
        tools_blocked=[c.tool for c in denied],
    )
    if denied:
        # Last denial wins, matching serve.py's `rec.last_denial`: on a multi-call turn the most
        # recent refusal is the one the model's closing reply is actually about.
        denial = denied[-1].denial
        response.denied_by = denial.label
        response.decision = denial.decision
        response.denied_server = denial.server_id
        response.gate = denial.gate
    return response


@app.post("/chat")
async def chat(req: ChatRequest) -> ChatResponse:
    """Invoke the agent with one user message, on whichever surface is configured."""
    return await (_chat_mcp(req.message) if _MODE == "mcp" else _chat_local(req.message))


@app.get("/tools")
async def list_tools() -> dict[str, Any]:
    """What tools this agent actually has.

    In `mcp` mode this is a LIVE `tools/list` through each firewall, so it is a Gate A report: a
    tool the firewall withheld (poisoned description, drifted definition) is missing from it, and
    that absence is the interesting signal. In `local` mode it stays the original static table.

    Either way the labels are descriptive only — Norviq decides from the policy loaded for this
    agent class and namespace, never from this response.
    """
    if _MODE == "mcp":
        report = await probe()
        report["bound"] = agent_mcp.tool_names()
        report["discovery_problems"] = agent_mcp.discovery_problems()
        return report
    return {
        "tools": [
            {"name": "search_kb", "risk": "low", "category": "read"},
            {"name": "get_customer", "risk": "medium", "category": "read"},
            {"name": "get_order", "risk": "medium", "category": "read"},
            {"name": "execute_sql", "risk": "critical", "category": "execute"},
            {"name": "delete_record", "risk": "critical", "category": "delete"},
            {"name": "send_email", "risk": "high", "category": "external"},
        ]
    }
