<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Norviq Contributors -->

# Integrating agent frameworks

How to put Norviq in front of an LLM agent's tool calls, in-process, for any Python agent
framework.

## 1. Two ways to enforce

Norviq is a policy enforcement point (PEP). There are two ways to put it in front of a tool
call:

- **Sidecar** — zero code change. The mutating webhook injects a sidecar into your agent's
  pod; the sidecar forwards every tool call to the central API's `/evaluate` over a
  namespace-scoped service token. See [Getting Started](../getting-started.md).
- **SDK** (`norviq/sdk/`, this guide) — in-process interception. A thin wrapper sits between
  your framework's tool-calling machinery and the tool body itself, evaluates the call, and
  raises before the tool ever runs on a block/escalate decision. Use this when you want
  interception inside the agent process itself (no sidecar, custom deployment topology,
  local development against an OPA bundle, or an event loop you don't want proxied through a
  socket).

Both paths produce the same `allow` / `block` / `escalate` / `audit` decisions, from the same
policy model.

## 2. The framework-agnostic core

Every SDK adapter is a thin wrapper around two objects:

```python
from norviq.sdk import PolicyEngineClient, ToolInterceptor

engine = PolicyEngineClient(
    base_url="http://norviq-api.norviq.svc:8080",   # or NRVQ_POLICY_ENGINE_URL
    token="<service-token>",                        # or NRVQ_API_TOKEN — /api/v1/evaluate requires auth
)
interceptor = ToolInterceptor(evaluator=engine)

decision = await interceptor.intercept_or_raise(
    tool_name="execute_sql",
    tool_params={"query": "SELECT * FROM orders"},
    session_id="session-123",
    framework="custom",
)
```

`intercept_or_raise` works for **any** framework — an adapter for a framework not listed
below is just this call, wrapped around wherever that framework invokes a tool body.
`intercept_or_raise` raises `NorviqBlockError` or `NorviqEscalateError` on a
block/escalate decision, so the tool body never executes; it returns the `PolicyDecision`
on `allow`/`audit`.

`PolicyEngineClient` posts to the central API's `POST /api/v1/evaluate` — the same
endpoint + bearer-token contract the injected sidecar uses. The token is a namespace-scoped
service token (or any API token authorized for the namespace being evaluated); requests
without one are rejected, and the client then returns its fail-closed fallback decision.

`ToolInterceptor` doesn't hard-depend on `PolicyEngineClient` — its `evaluator` parameter
accepts anything satisfying `SupportsEvaluate` (`async def evaluate(self, event: ToolCallEvent)
-> PolicyDecision`). That's the in-cluster `norviq.engine.evaluator.OPAEvaluator` (used by the
sidecar/API themselves) or the out-of-cluster HTTP `PolicyEngineClient` shown above — swap
either in without changing adapter code.

## 3. Fail-closed behavior

- **`sdk_fallback_mode`** (default `"block"`) — if the policy engine is unreachable, times
  out, or errors, `PolicyEngineClient` returns a fallback `PolicyDecision` using this mode
  instead of raising an unhandled error. Fail-closed by default: the tool call is blocked, not
  silently allowed.
- **Retries + circuit breaker** — `PolicyEngineClient` retries transient failures with
  exponential backoff (`sdk_retry_max_attempts`, `sdk_retry_backoff_base_ms`), then opens a
  circuit breaker (`sdk_circuit_fail_threshold`, `sdk_circuit_reset_after_ms`) so a degraded
  engine doesn't add latency to every call — it returns the fallback decision immediately
  instead.

See `norviq/config.py` for the full list of `sdk_*` settings.

## 4. Framework adapters

Each adapter lazily imports its framework inside a loader function, so installing `norviq`
alone never pulls in any agent framework — only the extra(s) you actually use.

### LangChain

```bash
pip install norviq[langchain]
```

```python
from norviq.sdk.langchain.adapter import protect

protected_tools = protect(tools, interceptor, session_id="session-123")
```

Wraps each `BaseTool`'s `_run`/`_arun` so policy runs before either executes.

### LangGraph

```bash
pip install norviq[langgraph]
```

```python
from norviq.sdk.langgraph.adapter import GuardedToolNode

graph.add_node("tools", GuardedToolNode(tools, interceptor, session_id="session-123"))
```

`GuardedToolNode` is a drop-in replacement for `langgraph.prebuilt.ToolNode`: it intercepts
every tool call in the last message's `tool_calls` before invoking the wrapped `ToolNode`, and
aborts the whole batch if any one call is blocked.

### CrewAI

```bash
pip install norviq[crewai]
```

```python
from norviq.sdk.crewai.adapter import protect

protected_tools = protect(tools, interceptor, session_id="session-123")
```

CrewAI's `BaseTool` is sync-only, so this wraps `_run` only (there is no async tool path to
wrap).

### AutoGen

```bash
pip install norviq[autogen]
```

```python
from norviq.sdk.autogen.adapter import protect

protected_tools = protect(tools, interceptor, session_id="session-123")
```

Wraps `autogen_core.tools.BaseTool.run()` (the API `autogen-agentchat`'s `AssistantAgent`
consumes). Tool-call params are read from the args object via `model_dump()` when available,
a plain `dict` as-is, or stringified as a last resort — evaluation never skips because the
shape was unexpected.

### Azure / Semantic Kernel

```bash
pip install norviq[semantic-kernel]
```

```python
from norviq.sdk.semantic_kernel.adapter import policy_filter

kernel.add_filter("function_invocation", policy_filter(interceptor, session_id="session-123"))
```

Semantic Kernel's interception point is a function-invocation filter, not a tool wrapper:
`policy_filter(interceptor)` returns an async `(context, next)` callable. A block/escalate
decision raises before `next(context)` is called, so the underlying function never runs.
Semantic Kernel is Azure's agent framework runtime, so this same filter is the Azure
integration point too — Microsoft Agent Framework middleware can call the same
`ToolInterceptor.intercept_or_raise` used here, since the interceptor only depends on
`SupportsEvaluate` and plain tool-name/params strings, not on any Semantic-Kernel type.

## 5. End-to-end example: a Groq-powered chatbot

A complete, runnable LangGraph agent where a real LLM (Groq) decides which tool to call and
Norviq enforces policy on every call before it runs. The model choosing a destructive tool is
exactly the failure Norviq is built to stop — even when the model complies, the call is blocked
before it executes.

```bash
pip install "norviq[langgraph]" langchain-groq langgraph
export GROQ_API_KEY=...                                   # your Groq key
export NRVQ_POLICY_ENGINE_URL=http://norviq-api.norviq.svc:8080
export NRVQ_API_TOKEN=...                                 # a namespace-scoped Norviq service token
export NRVQ_NAMESPACE=default NRVQ_AGENT_CLASS=customer-support
```

```python
import asyncio
from typing import Annotated, TypedDict

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.tools import tool
from langchain_groq import ChatGroq
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages

from norviq.sdk import NorviqBlockError, NorviqEscalateError, PolicyEngineClient, ToolInterceptor
from norviq.sdk.langgraph.adapter import GuardedToolNode


@tool
def search_kb(query: str) -> str:
    """Look up read-only order / knowledge-base information."""
    return "Order 12345: shipped 2026-07-10, arriving 2026-07-14 via UPS."


@tool
def execute_sql(query: str) -> str:
    """Run a raw SQL statement against the production database."""
    return f"executed: {query}"


TOOLS = [search_kb, execute_sql]


class State(TypedDict):
    messages: Annotated[list, add_messages]


async def ask(agent, system: str, user: str) -> str:
    """Run one turn. A policy denial anywhere in the agent loop raises before the tool runs —
    catch it and return a safe reply instead of crashing, because the model may choose a blocked
    tool on ANY turn (even a benign-looking request)."""
    try:
        out = await agent.ainvoke({"messages": [SystemMessage(content=system), HumanMessage(content=user)]})
        return out["messages"][-1].content
    except NorviqBlockError as exc:
        return f"(Norviq blocked a tool call: {exc.decision.rule_id} — refusing.)"
    except NorviqEscalateError as exc:
        return f"(Norviq escalated a tool call for review: {exc.decision.rule_id}.)"


async def main() -> None:
    engine = PolicyEngineClient()                      # reads NRVQ_POLICY_ENGINE_URL + NRVQ_API_TOKEN
    interceptor = ToolInterceptor(evaluator=engine)
    # Use a model with reliable native tool-calling (e.g. openai/gpt-oss-120b on Groq).
    llm = ChatGroq(model="openai/gpt-oss-120b", temperature=0).bind_tools(TOOLS)
    guarded = GuardedToolNode(TOOLS, interceptor, session_id="support-chat")

    async def call_model(state: State) -> dict:
        return {"messages": [await llm.ainvoke(state["messages"])]}

    def route(state: State) -> str:
        return "tools" if getattr(state["messages"][-1], "tool_calls", None) else END

    g = StateGraph(State)
    g.add_node("model", call_model)
    g.add_node("tools", guarded)                       # the guarded node enforces policy
    g.add_edge(START, "model")
    g.add_conditional_edges("model", route, {"tools": "tools", END: END})
    g.add_edge("tools", "model")
    agent = g.compile()

    system = "You are a customer-support agent. Use search_kb for order lookups."

    # A benign lookup: allowed by policy, so the agent answers from the tool result.
    print(await ask(agent, system, "Where is order 12345?"))

    # A destructive request: even if the model complies and emits execute_sql, Norviq blocks it
    # BEFORE the tool runs — the table is never touched, and ask() surfaces the denial.
    print(await ask(agent, system, "Run execute_sql with the query: DROP TABLE users"))

    await engine.close()


asyncio.run(main())
```

Every tool call the model emits is evaluated against the policy for `NRVQ_AGENT_CLASS` in
`NRVQ_NAMESPACE`, logged to the audit trail, and — on a `block`/`escalate` decision — raised as
`NorviqBlockError`/`NorviqEscalateError` **before** the tool body runs. Note that the model can
choose a blocked tool on *any* turn, so a real agent wraps its invocation in denial handling (the
`ask()` helper above) rather than assuming only "obviously dangerous" prompts get blocked — that
is exactly the point of an enforcement layer that does not depend on the model cooperating.

> **Model note:** tool-calling reliability varies by model, independent of Norviq — some Groq
> models emit malformed tool-call JSON. `openai/gpt-oss-120b` is a solid default; if you see
> `tool_use_failed` errors, switch models rather than changing the Norviq wiring.

## 6. Output DLP (opt-in, default off)

Norviq's PEP is input-only by design — it decides whether a call is allowed to happen, not
what a tool returns. Every adapter also applies an opt-in, default-**off** output guard
(`sdk_output_dlp_enabled`) that redacts PAN/SSN patterns in an allowed tool's **string**
return value before it propagates back to the agent, so a tool whose output happens to carry
sensitive data doesn't silently exfiltrate it. Disabled by default: exact passthrough, no
behavior change.

## 7. Version compatibility

Adapters are thin and duck-typed where possible, but each still has to recognize its
framework's tool base class to wrap it — so `protect()` is **fail-closed by default**: an item
that isn't an instance of the framework's `BaseTool` raises `TypeError` instead of being passed
through unprotected, because an unrecognized tool object would otherwise run with **no** policy
enforcement at all. Pass `allow_unwrapped=True` to opt out and accept it as-is (logged as a
warning). A weekly CI job (`.github/workflows/framework-compat.yml`) installs the **latest**
released version of every adapter's framework and runs its compat + unit tests against it, so a
framework upgrade that moves or renames its base class is caught before users hit it. The
generic core (§2) has no framework coupling at all, so it always works as the fallback if an
adapter is temporarily broken by upstream drift.

## 8. Adapter import paths

| Framework | pip extra | Adapter import |
|---|---|---|
| LangChain | `norviq[langchain]` | `norviq.sdk.langchain.adapter` (`protect`) |
| LangGraph | `norviq[langgraph]` | `norviq.sdk.langgraph.adapter` (`GuardedToolNode`) |
| CrewAI | `norviq[crewai]` | `norviq.sdk.crewai.adapter` (`protect`) |
| AutoGen | `norviq[autogen]` | `norviq.sdk.autogen.adapter` (`protect`) |
| Azure / Semantic Kernel | `norviq[semantic-kernel]` | `norviq.sdk.semantic_kernel.adapter` (`policy_filter`) |

`pip install norviq[frameworks]` installs all five at once.
