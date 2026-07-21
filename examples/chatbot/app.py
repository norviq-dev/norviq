# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""FastAPI wrapper around the demo LangGraph agent."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from norviq.sdk import NorviqBlockError, NorviqEscalateError
from pydantic import BaseModel

from agent import SESSION_ID, agent, engine


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    """Release the policy-engine HTTP connection pool on shutdown."""
    yield
    await engine.close()


app = FastAPI(title="Norviq Demo Chatbot", version="0.1.0", lifespan=lifespan)


class ChatRequest(BaseModel):
    """Request payload for chat endpoint."""

    message: str


class ChatResponse(BaseModel):
    """Response payload with model answer, tool calls, and any policy denial."""

    reply: str
    tools_called: list[str]
    session_id: str = SESSION_ID
    # Populated only when Norviq refused a call: the rule that fired and the decision.
    denied_by: str = ""
    decision: str = ""


@app.get("/health")
async def health() -> dict[str, str]:
    """Liveness check endpoint."""
    return {"status": "ok"}


@app.post("/chat")
async def chat(req: ChatRequest) -> ChatResponse:
    """Invoke the protected agent with one user message.

    A block/escalate decision raises out of the agent loop BEFORE the tool body runs. The model
    can pick a denied tool on any turn, so this is handled as a normal outcome and returned as a
    safe reply — not as a 500.
    """
    try:
        result = await agent.ainvoke({"messages": [{"role": "user", "content": req.message}]})
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
    return ChatResponse(reply=str(reply), tools_called=tools_called)


@app.get("/tools")
async def list_tools() -> dict[str, list[dict[str, str]]]:
    """List demo tool metadata for UI and debugging.

    Descriptive only — these labels are not what Norviq enforces on. The decision comes from the
    policy loaded for this agent class/namespace, not from this table.
    """
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
