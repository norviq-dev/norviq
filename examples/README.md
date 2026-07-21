<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Norviq Contributors -->
# Examples

Runnable code that puts Norviq in front of a real agent. The docs under `docs/guides/` explain the
model and show excerpts; the full working versions live here.

The `chatbot/` example is the **same** Groq-backed customer-support agent (six tools in
[`chatbot/tools.py`](chatbot/tools.py)) wired for **every supported framework** — proving the block
is enforced at the tool boundary regardless of which framework picks the tool. Each `agent_*.py`
mirrors the LangChain [`agent.py`](chatbot/agent.py) with that framework's Norviq adapter:

| Framework module | Adapter / interception point | What it demonstrates |
|---|---|---|
| [`chatbot/agent.py`](chatbot/agent.py) | LangChain — `langchain.adapter.protect` wraps `BaseTool._run`/`_arun` | The default agent behind FastAPI ([`app.py`](chatbot/app.py)); the LLM picks the tool, Norviq blocks the dangerous ones before the body runs |
| [`chatbot/agent_langgraph.py`](chatbot/agent_langgraph.py) | LangGraph — `langgraph.adapter.GuardedToolNode` (drop-in for `ToolNode`) | The same agent as a hand-assembled ReAct graph; the guarded tool node blocks before running any call in the batch |
| [`chatbot/agent_crewai.py`](chatbot/agent_crewai.py) | CrewAI — `crewai.adapter.protect` wraps the sync `BaseTool._run` | An Agent + Task + Crew on the Groq LLM (via LiteLLM); a blocked tool is refused before its body runs |
| [`chatbot/agent_autogen.py`](chatbot/agent_autogen.py) | AutoGen — `autogen.adapter.protect` wraps `FunctionTool.run()` | An `AssistantAgent` on a Groq OpenAI-compatible client; the wrapped async `run()` is stopped before execution |
| [`chatbot/agent_semantic_kernel.py`](chatbot/agent_semantic_kernel.py) | Semantic Kernel / Azure — `semantic_kernel.adapter.policy_filter` (a function-invocation filter) | `@kernel_function` tools on a Groq-backed kernel; the filter runs on every invocation and blocks before the function body |

Run any of them with the framework-switchable server: `NRVQ_CHATBOT_FRAMEWORK=crewai uvicorn serve:app`
(one of `langchain`, `langgraph`, `crewai`, `autogen`, `semantic_kernel`) serves that framework's
protected agent behind the same chat page. See [`chatbot/README.md`](chatbot/README.md).

> **Note on framework behavior when a tool is blocked.** LangChain/LangGraph propagate the block as a
> `NorviqBlockError` the caller sees directly. CrewAI, AutoGen, and Semantic Kernel instead *catch* a
> tool's raised exception and feed it back to the model as a tool-error observation (the model then
> declines) — the destructive tool body still never runs, and the **block is recorded in the audit log
> either way** (the evaluate call happens before the framework catches the raise). The audit trail, not
> the framework's own error surface, is the authoritative record of enforcement.

## Prerequisites (all examples)

- **A running Norviq API** with Postgres and Redis behind it. Locally:
  `docker compose -f docker-compose.dev.yml up -d`, then
  `python -m uvicorn norviq.api.main:app --port 8080` — see [CONTRIBUTING.md](../CONTRIBUTING.md).
  In a cluster, see [docs/getting-started.md](../docs/getting-started.md).
- **A policy loaded for the scope you evaluate against.** Norviq is deny-by-default:
  `no_policy_decision` (`norviq/config.py`) defaults to `"deny"`, so an unconfigured namespace in
  `block` mode denies every call. `python scripts/seed-local-policies.py` seeds `comprehensive.rego`
  for `(default, customer-support)`.
- **A bearer token.** `POST /api/v1/evaluate` requires one — `POST /api/v1/auth/login` returns an
  `access_token`. Without it the SDK client fails closed (`sdk_fallback_mode`, default `"block"`).
- **The SDK, from this checkout**: `pip install -e ".[langchain,langgraph]"` from the repo root.
  Framework extras are declared in `pyproject.toml`.

## What an example is meant to prove

Not that the agent behaves — that the agent *cannot* misbehave. Each example is built so the
interesting case is the one where the model **complies** with a dangerous request: it emits the
destructive tool call, and the call is still stopped, by a layer that never asked the model's
opinion. A run that only shows allowed calls has proved nothing.

Concretely, in every example you should be able to see all three of:

1. the tool body never executing (the simulated side effect does not happen),
2. a `NorviqBlockError`/`NorviqEscalateError` carrying the `rule_id` that fired, and
3. the decision in the audit trail (`GET /api/v1/audit/records?range=1h`).

## Which enforcement path to copy

Norviq has two (see [docs/guides/integrating-agents.md](../docs/guides/integrating-agents.md) §1):

- **SDK** — in-process interception, what `chatbot/` uses. Pick it when you want the block to raise
  inside your agent process, or you're running outside Kubernetes.
- **Sidecar** — the mutating webhook injects an enforcement sidecar into pods in any namespace
  labelled `norviq-injection=enabled`; no application code changes. Covered in
  [docs/getting-started.md](../docs/getting-started.md).

Both produce the same `allow`/`block`/`escalate`/`audit` decisions from the same policy.

## Adding an example

Keep the runnable code here and the prose in `docs/guides/`, not both. A guide should carry a short
illustrative snippet plus a link to the example; duplicating the full listing into a guide means one
of the two copies is wrong within a release. New examples need a `README.md` that names every
environment variable the code actually reads, and a row in the table above.
