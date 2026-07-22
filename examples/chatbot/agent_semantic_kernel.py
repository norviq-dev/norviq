# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Semantic Kernel (Azure) agent protected with the Norviq Semantic Kernel adapter.

Enforcement path: in-process SDK. `PolicyEngineClient` POSTs each tool call to the central API's
`/api/v1/evaluate`; `policy_filter` is a function-invocation filter registered on the kernel, so a
`block`/`escalate` decision raises BEFORE `next(context)` runs the function body. Semantic Kernel is
Azure's agent-framework runtime, so this same wiring is the Azure integration point too.
See docs/guides/integrating-agents.md.
"""

from __future__ import annotations

import os

import openai
from norviq.sdk import PolicyEngineClient, ToolInterceptor
from norviq.sdk.semantic_kernel.adapter import policy_filter
from semantic_kernel import Kernel
from semantic_kernel.connectors.ai.function_choice_behavior import FunctionChoiceBehavior
from semantic_kernel.connectors.ai.open_ai import (
    OpenAIChatCompletion,
    OpenAIChatPromptExecutionSettings,
)
from semantic_kernel.functions import kernel_function

from tools import (
    delete_record,
    execute_sql,
    get_customer,
    get_order,
    search_kb,
    send_email,
)

# Tool-calling reliability varies by model. openai/gpt-oss-120b is a solid default on Groq; if you
# see tool_use_failed errors, change the model — not the Norviq wiring. Groq is OpenAI-compatible,
# so Semantic Kernel reaches it through the OpenAI connector pointed at Groq's base URL.
_groq_client = openai.AsyncOpenAI(
    base_url="https://api.groq.com/openai/v1",
    api_key=os.getenv("GROQ_API_KEY"),
)
llm = OpenAIChatCompletion(
    ai_model_id=os.getenv("GROQ_MODEL", "openai/gpt-oss-120b"),
    async_client=_groq_client,
)

# Reads NRVQ_POLICY_ENGINE_URL and NRVQ_API_TOKEN (norviq/config.py). If the engine is
# unreachable the client returns its fail-closed fallback decision (NRVQ_SDK_FALLBACK_MODE,
# default "block") rather than letting the call through.
engine = PolicyEngineClient()
interceptor = ToolInterceptor(evaluator=engine)

# `policy_filter()` binds ONE session id at filter-creation time — the Semantic Kernel filter has
# no per-call override — so the whole process reports as one policy session.
SESSION_ID = os.getenv("NRVQ_SESSION_ID", "demo-session")


class SupportPlugin:
    """The six shared demo tools, registered as Semantic Kernel functions.

    Each method delegates to the identically named implementation imported from `tools.py` — the
    tool bodies are NOT redefined here. (A method name is not in scope as a bare call inside its own
    body, so `search_kb(query)` below resolves to the imported function, not the method — no
    recursion.)
    """

    @kernel_function(name="search_kb", description="Search the knowledge base for product and policy information.")
    def search_kb(self, query: str) -> str:
        """Search the knowledge base for product and policy information."""
        return search_kb(query)

    @kernel_function(name="get_customer", description="Get customer details by ID.")
    def get_customer(self, customer_id: str) -> str:
        """Get customer details by ID."""
        return get_customer(customer_id)

    @kernel_function(name="get_order", description="Get order details by ID.")
    def get_order(self, order_id: str) -> str:
        """Get order details by ID."""
        return get_order(order_id)

    @kernel_function(name="execute_sql", description="Execute a SQL query against the database.")
    def execute_sql(self, query: str) -> str:
        """Execute a SQL query against the database."""
        return execute_sql(query)

    @kernel_function(name="delete_record", description="Delete a record from the database.")
    def delete_record(self, table: str, record_id: str) -> str:
        """Delete a record from the database."""
        return delete_record(table, record_id)

    @kernel_function(name="send_email", description="Send an email to a customer.")
    def send_email(self, to: str, subject: str, body: str) -> str:
        """Send an email to a customer."""
        return send_email(to, subject, body)


# Register all six shared tools as one plugin, then add the policy filter. The filter is the
# enforcement point: `kernel.add_filter("function_invocation", ...)` runs it on EVERY function
# invocation before the function body, so all six are guarded at once — there is no per-tool wrapper
# to forget and no allow_unwrapped escape hatch. A block/escalate decision raises and `next(context)`
# is never called, so the tool body never runs (fail-closed). Semantic Kernel reports tool names
# plugin-qualified (`support.execute_sql`), but the adapter deliberately sends the BARE name
# (`execute_sql`) — plugin scoping is an SK addressing detail, not part of policy identity. Sending
# the qualified name made a framework-agnostic `delete_record` policy silently NOT match, so the same
# call that was blocked under LangChain was allowed under SK. See norviq/sdk/semantic_kernel/adapter.py.
kernel = Kernel()
kernel.add_service(llm)
kernel.add_plugin(SupportPlugin(), plugin_name="support")
kernel.add_filter("function_invocation", policy_filter(interceptor, session_id=SESSION_ID))

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

# Enable automatic tool calling: the model picks a function, Semantic Kernel invokes it, and the
# policy filter above runs first. A runner seeds a ChatHistory with SYSTEM_PROMPT and invokes the
# kernel with these settings — the same assembled shape as agent.py's `agent`, minus the run loop.
settings = OpenAIChatPromptExecutionSettings(
    function_choice_behavior=FunctionChoiceBehavior.Auto(),
)
