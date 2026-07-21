# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""AutoGen AssistantAgent protected with the Norviq AutoGen adapter.

Enforcement path: in-process SDK. `PolicyEngineClient` POSTs each tool call to the central API's
`/api/v1/evaluate`; `protect()` wraps every tool's async `run()` so a `block`/`escalate` decision
raises BEFORE the tool body executes. See docs/guides/integrating-agents.md.
"""

from __future__ import annotations

import os

from autogen_agentchat.agents import AssistantAgent
from autogen_core.models import ModelFamily, ModelInfo
from autogen_core.tools import FunctionTool
from autogen_ext.models.openai import OpenAIChatCompletionClient
from norviq.sdk import PolicyEngineClient, ToolInterceptor
from norviq.sdk.autogen.adapter import protect

from tools import (
    delete_record,
    execute_sql,
    get_customer,
    get_order,
    search_kb,
    send_email,
)

# Groq is OpenAI wire-compatible, so AutoGen reaches it through OpenAIChatCompletionClient pointed
# at Groq's OpenAI endpoint. openai/gpt-oss-120b is a solid tool-calling default on Groq; if you see
# tool_use_failed errors, change the model — not the Norviq wiring.
model_client = OpenAIChatCompletionClient(
    model=os.getenv("GROQ_MODEL", "openai/gpt-oss-120b"),
    base_url="https://api.groq.com/openai/v1",
    api_key=os.getenv("GROQ_API_KEY"),
    temperature=0,
    # Groq's models aren't in OpenAIChatCompletionClient's built-in capability table, so declare
    # what they can do explicitly — tool calling is the one this demo depends on.
    model_info=ModelInfo(
        vision=False,
        function_calling=True,
        json_output=True,
        family=ModelFamily.UNKNOWN,
        structured_output=False,
        multiple_system_messages=True,
    ),
)

# Reads NRVQ_POLICY_ENGINE_URL and NRVQ_API_TOKEN (norviq/config.py). If the engine is
# unreachable the client returns its fail-closed fallback decision (NRVQ_SDK_FALLBACK_MODE,
# default "block") rather than letting the call through.
engine = PolicyEngineClient()
interceptor = ToolInterceptor(evaluator=engine)

# `protect()` binds ONE session id at wrap time — the AutoGen adapter has no per-call override —
# so the whole process reports as one policy session.
SESSION_ID = os.getenv("NRVQ_SESSION_ID", "demo-session")

# AutoGen's AssistantAgent consumes autogen_core.tools.BaseTool objects; FunctionTool is the
# concrete one that adapts a plain Python callable. `protect()` replaces each tool's async run()
# so policy runs BEFORE the tool body executes, and raises on a block/escalate decision.
protected_tools = protect(
    [
        FunctionTool(search_kb, description=search_kb.__doc__ or "", name="search_kb"),
        FunctionTool(get_customer, description=get_customer.__doc__ or "", name="get_customer"),
        FunctionTool(get_order, description=get_order.__doc__ or "", name="get_order"),
        FunctionTool(execute_sql, description=execute_sql.__doc__ or "", name="execute_sql"),
        FunctionTool(delete_record, description=delete_record.__doc__ or "", name="delete_record"),
        FunctionTool(send_email, description=send_email.__doc__ or "", name="send_email"),
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

agent = AssistantAgent(
    name="support_agent",
    model_client=model_client,
    tools=protected_tools,
    system_message=SYSTEM_PROMPT,
)
