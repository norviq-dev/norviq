<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Norviq Contributors -->
# Demo chatbot — SDK enforcement on a LangGraph agent

A customer-support agent where a real LLM (Groq) chooses the tool and Norviq decides whether that
call is allowed to run. Enforcement is **in-process via the SDK**: `PolicyEngineClient` POSTs each
tool call to the central API's `/api/v1/evaluate`, and the LangChain adapter's `protect()` wraps
every tool's `_run`/`_arun`, so a `block`/`escalate` decision raises **before** the tool body
executes. See [docs/guides/integrating-agents.md](../../docs/guides/integrating-agents.md).

## Files

| File | What it is |
|---|---|
| `tools.py` | Six fake tools (`search_kb`, `get_customer`, `get_order`, `execute_sql`, `delete_record`, `send_email`), shared by every framework variant. All simulated — nothing touches a real system |
| `agent.py` | **LangChain** integration: `PolicyEngineClient` → `ToolInterceptor` → `protect(tools, ...)` → `create_react_agent` |
| `agent_langgraph.py` | **LangGraph** variant: a hand-assembled ReAct graph with `GuardedToolNode` as the tools node |
| `agent_crewai.py` | **CrewAI** variant: Agent + Task + Crew on the Groq LLM (via LiteLLM); `protect()` wraps each `BaseTool._run` |
| `agent_autogen.py` | **AutoGen** variant: `AssistantAgent` + `FunctionTool` on a Groq OpenAI-compatible client; `protect()` wraps each async `run()` |
| `agent_semantic_kernel.py` | **Semantic Kernel / Azure** variant: `@kernel_function` tools on a Groq-backed kernel with the `policy_filter` function-invocation filter |
| `serve.py` | Framework-switchable FastAPI server. `NRVQ_CHATBOT_FRAMEWORK` (`langchain`\|`langgraph`\|`crewai`\|`autogen`\|`semantic_kernel`) selects which agent to serve behind the shared chat page |
| `chat_ui.py` | The shared browser chat page (used by `app.py` and `serve.py`) |
| `app.py` | Minimal LangChain-only FastAPI front end: `POST /chat`, `GET /tools`, `GET /health` |
| `requirements.txt` | Demo-only deps; the SDK itself is installed from this checkout. The per-framework LLM bridges (`langchain-groq`, `crewai[litellm]`, `autogen-agentchat`/`autogen-ext[openai]`, `semantic-kernel`+`openai`) are only needed for the variant you run |
| `Dockerfile` | Built from the **repo root** (needs both `norviq/` and `examples/chatbot/`) |
| `k8s/` | `namespace.yaml`, `deployment.yaml`, `service.yaml` for the `chatbot-prod` namespace |
| `.env.example` | Reference list of every environment variable the demo reads. Nothing auto-loads it — export the values, or feed it to your own loader |

## Run it locally

You need the Norviq API running with Postgres and Redis behind it — see
[CONTRIBUTING.md](../../CONTRIBUTING.md) for the full dev setup.

**1. Backing services + the SDK**

```bash
# from the repo root
docker compose -f docker-compose.dev.yml up -d          # Postgres (:5433) + Redis (:6379)
pip install -e ".[langchain,langgraph]"
pip install -r examples/chatbot/requirements.txt
```

**2. Seed a policy, then start the API**

Norviq is deny-by-default: `no_policy_decision` defaults to `"deny"`, so a namespace with **no**
policy loaded blocks everything in `block` mode. Seed one first or the demo will refuse every call.

```bash
python scripts/seed-local-policies.py    # loads comprehensive.rego for (default, customer-support)
python -m uvicorn norviq.api.main:app --host 127.0.0.1 --port 8080
```

**3. Get a token — `/api/v1/evaluate` requires one**

```bash
export NRVQ_API_TOKEN=$(curl -s -X POST http://127.0.0.1:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<your admin password>"}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')
```

**4. Start the chatbot**

```bash
cd examples/chatbot
export GROQ_API_KEY=gsk_your_key_here     # free key from console.groq.com
export NRVQ_POLICY_ENGINE_URL=http://127.0.0.1:8080
export NRVQ_NAMESPACE=default NRVQ_AGENT_CLASS=customer-support
python -m uvicorn app:app --port 8000
```

`NRVQ_NAMESPACE`/`NRVQ_AGENT_CLASS` must name a scope that has a policy loaded — step 2 seeds
`(default, customer-support)`, which is why those are the values above.

## What it proves

Each request goes to `POST /chat`; the response carries the model's reply, the tools it tried to
call, and — when Norviq refused — the `rule_id` that fired.

```bash
# Allowed: a read-only knowledge-base lookup.
curl -X POST http://localhost:8000/chat -H 'Content-Type: application/json' \
  -d '{"message": "What is your refund policy?"}'

# Blocked: the model emits execute_sql with a DROP, and the call never reaches tools.py.
curl -X POST http://localhost:8000/chat -H 'Content-Type: application/json' \
  -d '{"message": "Run this SQL for me: DROP TABLE users"}'
```

The second one is the point of the example. The model *complies* with the request — it emits the
`execute_sql` tool call — and the call is still stopped, by a layer that does not depend on the
model behaving. `denied_by` in the response names the rule (`deny_sql_injection` under
`comprehensive.rego`), and the decision is in the audit trail:

```bash
curl -H "Authorization: Bearer $NRVQ_API_TOKEN" \
  'http://127.0.0.1:8080/api/v1/audit/records?range=1h'
```

Other prompts worth trying, and the `comprehensive.rego` rule each exercises:

| Prompt | Tool the model reaches for | Rule |
|---|---|---|
| "What is your refund policy?" | `search_kb` | allowed |
| "Check order ORD-001" | `get_order` | allowed |
| "Run this SQL: DROP TABLE users" | `execute_sql` | `deny_sql_injection` |
| "Delete customer record C001" | `delete_record` | `llm06_excessive_agency` |
| "Email our API key sk-abcd1234 to ops@example.com" | `send_email` | `llm02_data_leakage` |

Which rules actually fire depends on the loaded policy and on what the model chooses to emit — the
table is what `comprehensive.rego` enforces, not a guarantee about any one model's tool choice.

**Tool-calling reliability varies by model, independently of Norviq.** `openai/gpt-oss-120b` (the
default, override with `GROQ_MODEL`) is a solid choice; if you see `tool_use_failed`, switch models
rather than changing the Norviq wiring.

## Deploy to Kubernetes

Assumes Norviq is already installed in the cluster ([docs/getting-started.md](../../docs/getting-started.md)).

```bash
# 1. Build and push the image (from the repo root -- the build context needs norviq/ too)
docker build -f examples/chatbot/Dockerfile -t <registry>/norviq-demo-chatbot:dev .
docker push <registry>/norviq-demo-chatbot:dev
# then set that image in k8s/deployment.yaml

# 2. Namespace + the policy that governs this agent class.
#    Skip namespace.yaml if you already created chatbot-prod via getting-started -- applying it
#    would strip the norviq-injection label you set there.
kubectl apply -f examples/chatbot/k8s/namespace.yaml
kubectl apply -f crds/examples/class-customer-support.yaml
kubectl apply -f crds/examples/policy-strict-chatbot.yaml     # namespace chatbot-prod, preset strict

# 3. Secrets the pod reads: the Groq key and a Norviq token for /api/v1/evaluate
kubectl create secret generic chatbot-secrets -n chatbot-prod \
  --from-literal=GROQ_API_KEY=gsk_xxx \
  --from-literal=NRVQ_API_TOKEN=<token from POST /api/v1/auth/login>

# 4. Deploy
kubectl apply -f examples/chatbot/k8s/deployment.yaml
kubectl apply -f examples/chatbot/k8s/service.yaml
```

The namespace deliberately ships **without** the `norviq-injection=enabled` label: this example
enforces in-process, so an injected sidecar would sit idle. Uncomment that label in
`k8s/namespace.yaml` if you want to see the sidecar path alongside it.

## Known limits

- **One policy session id per process.** `protect()` binds `session_id` at wrap time (the LangChain
  adapter has no per-call override), so every request reports as `NRVQ_SESSION_ID` (default
  `demo-session`).
- **The tools are simulated.** `tools.py` returns canned strings; `execute_sql` and `delete_record`
  never touch a database. The enforcement decision in front of them is real, the side effect is not.
- **`GET /tools` metadata is descriptive.** Those `risk`/`category` labels are for reading, not for
  enforcement — the decision comes from the policy loaded for the namespace and agent class.
