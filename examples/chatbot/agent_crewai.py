# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""CrewAI agent protected with the Norviq CrewAI adapter.

Enforcement path: in-process SDK. `PolicyEngineClient` POSTs each tool call to the central API's
`/api/v1/evaluate`; `protect()` wraps every tool's `_run` (CrewAI's `BaseTool` is sync-only) so a
`block`/`escalate` decision raises BEFORE the tool body executes. See
docs/guides/integrating-agents.md.

This is the CrewAI sibling of agent.py (LangGraph): same env-var contract, same six-tool toolset,
same Groq LLM — assembled as a CrewAI Agent + Task + Crew instead of a prebuilt LangGraph agent.
"""

from __future__ import annotations

import os

from crewai import LLM, Agent, Crew, Process, Task
from crewai.tools import tool
from norviq.sdk import PolicyEngineClient, ToolInterceptor
from norviq.sdk.crewai.adapter import protect

from tools import (
    delete_record,
    execute_sql,
    get_customer,
    get_order,
    search_kb,
    send_email,
)

# Tool-calling reliability varies by model. openai/gpt-oss-120b is a solid default on Groq;
# if you see tool_use_failed errors, change the model — not the Norviq wiring. CrewAI routes Groq
# through LiteLLM, so the model id is prefixed "groq/"; the base id is the same GROQ_MODEL agent.py
# uses.
llm = LLM(
    model="groq/" + os.getenv("GROQ_MODEL", "openai/gpt-oss-120b"),
    api_key=os.getenv("GROQ_API_KEY"),
    temperature=0,
)

# Reads NRVQ_POLICY_ENGINE_URL and NRVQ_API_TOKEN (norviq/config.py). If the engine is
# unreachable the client returns its fail-closed fallback decision (NRVQ_SDK_FALLBACK_MODE,
# default "block") rather than letting the call through.
engine = PolicyEngineClient()
interceptor = ToolInterceptor(evaluator=engine)

# `protect()` binds ONE session id at wrap time — the CrewAI adapter has no per-call override —
# so the whole process reports as one policy session.
SESSION_ID = os.getenv("NRVQ_SESSION_ID", "demo-session")

# `tool(fn)` turns each plain demo function into a real `crewai.tools.BaseTool`; `protect()` then
# wraps its `_run`. Fail-closed by default: `protect()` raises if handed anything that isn't a
# CrewAI `BaseTool`, so a tool can never slip through unprotected.
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

# CrewAI composes an agent's system prompt from role + goal + backstory; the env-overridable persona
# above is the backstory, so NRVQ_CHATBOT_SYSTEM_PROMPT is the one knob that changes how the agent
# behaves — exactly as `prompt=SYSTEM_PROMPT` is in agent.py.
agent = Agent(
    role="Customer Support Agent",
    goal="Resolve the customer's request using the available tools.",
    backstory=SYSTEM_PROMPT,
    tools=protected_tools,
    llm=llm,
    allow_delegation=False,
    verbose=False,
)

# The user's message is templated into the task at run time. A driver runs the crew with
# `crew.kickoff(inputs={"user_input": user_text})`; every tool the model picks is evaluated by
# Norviq before it runs, and a blocked call raises NorviqBlockError out of `kickoff`.
task = Task(
    description="Handle this customer request:\n{user_input}",
    expected_output="A concise, professional reply to the customer.",
    agent=agent,
)

crew = Crew(
    agents=[agent],
    tasks=[task],
    process=Process.sequential,
    verbose=False,
)
