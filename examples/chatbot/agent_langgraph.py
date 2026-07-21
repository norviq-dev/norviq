# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""LangGraph agent protected with the Norviq LangGraph adapter.

Enforcement path: in-process SDK. `PolicyEngineClient` POSTs each tool call to the central API's
`/api/v1/evaluate`; `GuardedToolNode` is a drop-in for `langgraph.prebuilt.ToolNode` that intercepts
every tool call in the last message's `tool_calls` and raises on a `block`/`escalate` decision BEFORE
the wrapped ToolNode runs any tool body. See docs/guides/integrating-agents.md.

Same wiring as `agent.py`, but the graph is assembled by hand instead of `create_react_agent`: an
agent node calls the model, a conditional edge routes to `GuardedToolNode` when the model emits tool
calls, and the tools node loops back to the agent. Enforcement lives at the tool node, not the prompt.
"""

from __future__ import annotations

import os
from typing import Any

from langchain_core.messages import SystemMessage
from langchain_core.tools import tool
from langchain_groq import ChatGroq
from langgraph.graph import END, START, MessagesState, StateGraph
from norviq.sdk import PolicyEngineClient, ToolInterceptor
from norviq.sdk.langgraph.adapter import GuardedToolNode

from tools import (
    delete_record,
    execute_sql,
    get_customer,
    get_order,
    search_kb,
    send_email,
)

# Tool-calling reliability varies by model. openai/gpt-oss-120b is a solid default on Groq;
# if you see tool_use_failed errors, change the model — not the Norviq wiring.
llm = ChatGroq(
    model=os.getenv("GROQ_MODEL", "openai/gpt-oss-120b"),
    api_key=os.getenv("GROQ_API_KEY"),
    temperature=0,
)

# Reads NRVQ_POLICY_ENGINE_URL and NRVQ_API_TOKEN (norviq/config.py). If the engine is
# unreachable the client returns its fail-closed fallback decision (NRVQ_SDK_FALLBACK_MODE,
# default "block") rather than letting the call through.
engine = PolicyEngineClient()
interceptor = ToolInterceptor(evaluator=engine)

# `GuardedToolNode` binds ONE session id at construction time — the LangGraph adapter has no per-call
# override — so the whole process reports as one policy session.
SESSION_ID = os.getenv("NRVQ_SESSION_ID", "demo-session")

# The model must be bound to the SAME tool objects the guarded node executes, so tool names line up.
# GuardedToolNode wraps every one of them; a call it can't recognize fails closed inside its ToolNode
# rather than running unprotected.
tools = [
    tool(search_kb),
    tool(get_customer),
    tool(get_order),
    tool(execute_sql),
    tool(delete_record),
    tool(send_email),
]
model = llm.bind_tools(tools)

# Persona is configurable so you can demonstrate the point Norviq exists to make: enforcement lives
# at the TOOL boundary, not in the prompt. Set NRVQ_CHATBOT_SYSTEM_PROMPT to a capable-agent persona
# (no self-censoring "never run SQL") and let Norviq — not prompt engineering — be what stops a
# destructive call. Defaults to the cautious persona.
SYSTEM_PROMPT = os.getenv(
    "NRVQ_CHATBOT_SYSTEM_PROMPT",
    "You are a helpful customer support agent for Acme Corp.\n"
    "You can search the knowledge base, look up customers and orders, and help with common requests.\n"
    "Never execute SQL directly unless explicitly asked. Never delete records. Be professional.",
)


async def call_model(state: MessagesState) -> dict[str, Any]:
    """Agent node: ask the model for the next step, prepending the persona as a system message."""
    response = await model.ainvoke([SystemMessage(content=SYSTEM_PROMPT), *state["messages"]])
    return {"messages": [response]}


def route_tools(state: MessagesState) -> str:
    """Route to the guarded tool node when the model emitted tool calls, otherwise finish."""
    last = state["messages"][-1]
    return "tools" if getattr(last, "tool_calls", None) else END


# Self-assembled ReAct loop: agent -> (tools -> agent)* -> END. `GuardedToolNode` is the tools node,
# so every tool call the model chooses is evaluated by Norviq before its body runs.
graph = StateGraph(MessagesState)
graph.add_node("agent", call_model)
graph.add_node("tools", GuardedToolNode(tools, interceptor, session_id=SESSION_ID))
graph.add_edge(START, "agent")
graph.add_conditional_edges("agent", route_tools, {"tools": "tools", END: END})
graph.add_edge("tools", "agent")

agent = graph.compile()
