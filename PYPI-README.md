<!-- SPDX-License-Identifier: Apache-2.0 -->
<!--
  This is the PyPI long description, not the repo landing page (README.md).

  Two reasons it is separate. (1) PyPI cannot resolve relative links or images, so every README.md
  link would render dead on pypi.org — every URL below is absolute. (2) The audiences differ: someone
  on pypi.org came for the Python SDK, whereas README.md opens with `git clone` + `helm install`,
  which is the wrong first instruction for them.

  Keep it short and keep the links absolute.
-->

# Norviq

**Runtime policy enforcement for LLM agent tool calls.**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/norviq-dev/norviq/blob/main/LICENSE)
[![Docs](https://img.shields.io/badge/docs-docs.norviq.dev-00a576)](https://docs.norviq.dev)

Norviq is a policy enforcement point (PEP) that sits between an agent's reasoning loop and the tools
it can call. Every tool call is evaluated against OPA/Rego policy and then **allowed, blocked,
escalated, or audited** — *before* the tool function runs. It turns "the model decided to call
`execute_sql`" from implicit trust into an enforced, auditable decision.

This package is the **Python SDK**: it wraps your existing tools so enforcement happens in-process.
The full platform (control plane, console, Kubernetes admission webhook, sidecar injection) is
installed with the Helm chart — see the [documentation](https://docs.norviq.dev).

## Install

```bash
pip install "norviq[langchain]"      # LangChain / LangGraph
pip install "norviq[crewai]"         # CrewAI
pip install "norviq[autogen]"        # AutoGen
pip install "norviq[semantic-kernel]" # Semantic Kernel
pip install "norviq[frameworks]"     # all of the above
```

## Use

```python
from norviq.sdk import PolicyEngineClient, ToolInterceptor
from norviq.sdk.langchain.adapter import protect

engine = PolicyEngineClient()                      # NRVQ_POLICY_ENGINE_URL + NRVQ_API_TOKEN
interceptor = ToolInterceptor(evaluator=engine)

# Every tool is wrapped: policy runs before the tool body, on every call the model makes.
tools = protect([search_kb, execute_sql, delete_record], interceptor, session_id="session-1")
```

A blocked call raises `NorviqBlockError`, which carries the full `PolicyDecision` — including the
`rule_id` that fired and a human-readable `reason` — so you can surface a refusal instead of
performing the action:

```python
from norviq.sdk import NorviqBlockError

try:
    result = agent.invoke({"messages": [("user", "delete all customer records")]})
except NorviqBlockError as exc:
    print(f"blocked by {exc.decision.rule_id}: {exc.decision.reason}")
```

Two things to know before your first run, because either one makes a correct setup look broken:

- **Norviq is deny-by-default.** With no policy loaded for the scope you evaluate against, the
  decision is `deny`. Load a policy for your namespace/agent-class first.
- **`POST /api/v1/evaluate` requires a bearer token.** Without one the client fails closed.

## Links

- **Documentation** — https://docs.norviq.dev
- **Integration guide** (all supported frameworks) —
  https://github.com/norviq-dev/norviq/blob/main/docs/guides/integrating-agents.md
- **Runnable examples** — https://github.com/norviq-dev/norviq/blob/main/examples/README.md
- **Source** — https://github.com/norviq-dev/norviq
- **Security policy** — https://github.com/norviq-dev/norviq/blob/main/SECURITY.md

Apache 2.0 licensed.
