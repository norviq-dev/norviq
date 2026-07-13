# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""FastAPI wrapper around the demo LangGraph agent."""

from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel

from agent import agent

app = FastAPI(title="Norviq Demo Chatbot", version="0.1.0")


class ChatRequest(BaseModel):
    """Request payload for chat endpoint."""

    message: str
    session_id: str = "demo-session"


class ChatResponse(BaseModel):
    """Response payload with model answer and tool calls."""

    reply: str
    tools_called: list[str]


@app.get("/health")
async def health() -> dict[str, str]:
    """Liveness check endpoint."""
    return {"status": "ok"}


@app.post("/chat")
async def chat(req: ChatRequest) -> ChatResponse:
    """Invoke the protected agent with one user message."""
    result = await agent.ainvoke(
        {"messages": [{"role": "user", "content": req.message}]},
        config={"configurable": {"session_id": req.session_id}},
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
    """List demo tool metadata for UI and debugging."""
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
