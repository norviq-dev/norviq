# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Framework-switchable demo server: one chat UI, any Norviq SDK adapter.

Set ``NRVQ_CHATBOT_FRAMEWORK`` to one of ``langchain`` (default), ``langgraph``, ``crewai``,
``autogen``, ``semantic_kernel`` and this serves that framework's protected agent behind the same
chat page. Whatever the framework, the interesting case is identical: the model picks a dangerous
tool and Norviq stops it BEFORE the tool body runs — proving enforcement lives at the tool boundary,
not in any one framework's plumbing.
"""

from __future__ import annotations

import asyncio
import os

from dotenv import load_dotenv

load_dotenv()  # load examples/chatbot/.env before the selected agent module reads GROQ/NRVQ at import

from fastapi import FastAPI  # noqa: E402 - after load_dotenv(), by design
from fastapi.responses import HTMLResponse  # noqa: E402 - after load_dotenv(), by design
from norviq.sdk import NorviqBlockError, NorviqEscalateError  # noqa: E402 - after load_dotenv()
from pydantic import BaseModel  # noqa: E402 - after load_dotenv(), by design

from chat_ui import chat_page  # noqa: E402 - after load_dotenv(), by design

_FW = os.getenv("NRVQ_CHATBOT_FRAMEWORK", "langchain").lower()
_LABELS = {
    "langchain": "LangChain", "langgraph": "LangGraph", "crewai": "CrewAI",
    "autogen": "AutoGen", "semantic_kernel": "Semantic Kernel",
}
if _FW not in _LABELS:
    raise SystemExit(f"unknown NRVQ_CHATBOT_FRAMEWORK={_FW!r}; choose one of {sorted(_LABELS)}")


def _tools_from_messages(messages: list) -> list[str]:
    """Best-effort tool-name extraction from a LangChain/LangGraph message list."""
    out: list[str] = []
    for m in messages:
        for tc in getattr(m, "tool_calls", None) or []:
            name = tc.get("name") if isinstance(tc, dict) else getattr(tc, "name", "")
            if name:
                out.append(name)
    return out


# --- per-framework: import the agent + define how to run ONE user message --------------------------
if _FW in ("langchain", "langgraph"):
    mod = __import__("agent" if _FW == "langchain" else "agent_langgraph")
    _agent = mod.agent

    async def _run(message: str) -> tuple[str, list[str]]:
        result = await _agent.ainvoke({"messages": [{"role": "user", "content": message}]})
        messages = result.get("messages", [])
        reply = messages[-1].content if messages else "No response"
        return str(reply), _tools_from_messages(messages)

elif _FW == "crewai":
    from agent_crewai import crew

    async def _run(message: str) -> tuple[str, list[str]]:
        # kickoff is synchronous; run it off the event loop. A blocked tool raises out of kickoff.
        result = await asyncio.to_thread(crew.kickoff, inputs={"user_input": message})
        return str(result), []

elif _FW == "autogen":
    from agent_autogen import agent as _agent

    async def _run(message: str) -> tuple[str, list[str]]:
        result = await _agent.run(task=message)
        msgs = getattr(result, "messages", [])
        reply, tools = "No response", []
        for m in msgs:
            content = getattr(m, "content", None)
            if isinstance(content, str) and content.strip():
                reply = content
            elif isinstance(content, list):  # ToolCallRequestEvent: list[FunctionCall]
                tools += [getattr(c, "name", "") for c in content if getattr(c, "name", "")]
        return reply, [t for t in tools if t]

else:  # semantic_kernel
    from agent_semantic_kernel import kernel, llm, settings
    from agent_semantic_kernel import SYSTEM_PROMPT as _SK_PROMPT
    from semantic_kernel.contents import ChatHistory

    async def _run(message: str) -> tuple[str, list[str]]:
        history = ChatHistory()
        history.add_system_message(_SK_PROMPT)
        history.add_user_message(message)
        result = await llm.get_chat_message_content(chat_history=history, settings=settings, kernel=kernel)
        return str(result), []


def _find_norviq_error(exc: BaseException) -> NorviqBlockError | NorviqEscalateError | None:
    """Walk the exception chain — Semantic Kernel's filter pipeline re-wraps a filter's exception, so a
    block can arrive wrapped rather than as a bare NorviqBlockError at the call site."""
    seen: set[int] = set()
    cur: BaseException | None = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        if isinstance(cur, (NorviqBlockError, NorviqEscalateError)):
            return cur
        cur = cur.__cause__ or cur.__context__
    return None


app = FastAPI(title=f"Norviq Demo Chatbot — {_LABELS[_FW]}", version="0.1.0")


class ChatRequest(BaseModel):
    """Request payload for the chat endpoint."""

    message: str


class ChatResponse(BaseModel):
    """Model answer, any tool calls, and the policy decision when Norviq refused."""

    reply: str
    tools_called: list[str] = []
    denied_by: str = ""
    decision: str = ""


@app.get("/health")
async def health() -> dict[str, str]:
    """Liveness + which framework is being served."""
    return {"status": "ok", "framework": _FW}


@app.get("/", response_class=HTMLResponse)
async def home() -> str:
    """The chat page, tagged with the active framework."""
    return chat_page(_LABELS[_FW])


@app.post("/chat")
async def chat(req: ChatRequest) -> ChatResponse:
    """Run one user message through the selected framework's protected agent.

    A block/escalate raises out of the framework's run loop BEFORE the tool body executes. Some
    frameworks (Semantic Kernel) re-wrap the filter exception, so the decision is recovered from the
    exception chain and returned as a safe reply — never a 500.
    """
    try:
        reply, tools = await _run(req.message)
    except (NorviqBlockError, NorviqEscalateError) as exc:
        nrvq = exc
    except Exception as exc:  # noqa: BLE001 — recover a wrapped Norviq decision, else it's a real error
        nrvq = _find_norviq_error(exc)
        if nrvq is None:
            return ChatResponse(reply=f"(agent error: {type(exc).__name__}: {exc})")
    else:
        return ChatResponse(reply=str(reply), tools_called=tools)

    decision = "escalate" if isinstance(nrvq, NorviqEscalateError) else "block"
    verb = "needs human approval before it can run" if decision == "escalate" else "was blocked by policy"
    return ChatResponse(
        reply=f"I can't do that — a tool call {verb} ({nrvq.decision.reason}).",
        denied_by=nrvq.decision.rule_id,
        decision=decision,
    )
