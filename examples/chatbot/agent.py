# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""LangGraph agent protected with the Norviq LangChain adapter.

Enforcement path: in-process SDK. `PolicyEngineClient` POSTs each tool call to the central API's
`/api/v1/evaluate`; `protect()` wraps every tool's `_run`/`_arun` so a `block`/`escalate` decision
raises BEFORE the tool body executes. See docs/guides/integrating-agents.md.
"""

from __future__ import annotations

import os

from langchain_core.tools import tool
from langchain_groq import ChatGroq
from langgraph.prebuilt import create_react_agent
from norviq.sdk import PolicyEngineClient, ToolInterceptor
from norviq.sdk.langchain.adapter import protect

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

# `protect()` binds ONE session id at wrap time — the LangChain adapter has no per-call override —
# so the whole process reports as one policy session.
SESSION_ID = os.getenv("NRVQ_SESSION_ID", "demo-session")

protected_tools = protect(
    [
        tool(search_kb),
        tool(get_customer),
        tool(get_order),
        tool(execute_sql),
        tool(delete_record),
        tool(send_email),
    ],
    interceptor,
    session_id=SESSION_ID,
)

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

agent = create_react_agent(
    model=llm,
    tools=protected_tools,
    prompt=SYSTEM_PROMPT,
)
