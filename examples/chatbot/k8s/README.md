<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Norviq Contributors -->
# Deploying the MCP chatbot demo to `chatbot-prod`

A Groq-backed support agent whose tools live on three real MCP servers, where every MCP call is
adjudicated by Norviq twice: **Gate A** at discovery (`initialize` / `tools/list`) and **Gate B** at
invocation (`tools/call`).

## What gets deployed

```
namespace chatbot-prod

  pod demo-chatbot                          pod mcp-kb    Service mcp-kb   :8080  /mcp  /health
    chatbot     :8000  UI + agent             search_kb, get_article
    mcp-fw-kb   127.0.0.1:9101  ──────────▶ pod mcp-crm   Service mcp-crm  :8080  /mcp  /health
    mcp-fw-crm  127.0.0.1:9102  ──────────▶   get_customer, get_order, update_ticket
    mcp-fw-ops  127.0.0.1:9103  ──────────▶ pod mcp-ops   Service mcp-ops  :8080  /mcp  /health  /_calls
                    │                         execute_sql, delete_record, send_email, export_customers
                    └─▶ norviq-api.norviq:8080  /api/v1/evaluate     ← every Gate A and Gate B decision
```

The three firewalls run the **existing engine image** — there is no fourth image to build. They sit
in the *client* pod on purpose: the proxy's attested identity is the caller's identity only when the
proxy runs where the caller runs, so this governs *what the agent may call*. Next to the servers it
would instead govern *what anyone may ask the server to do*, which is a different and weaker claim.

Each firewall binds **loopback only**. Measured in the engine image
(`engine-76cc4778…`): a connection to `127.0.0.1:9101` is accepted and a connection to the pod IP on
the same port is `ConnectionRefused`. That is what makes the firewall unavoidable rather than
advisory — and it is also why these containers carry **no kubelet probes** (a probe dials the pod IP,
so it would be refused and hold the pod `NotReady` forever).

| File | Objects |
|---|---|
| `namespace.yaml` | `chatbot-prod` — **skip if you already created it** via getting-started; re-applying strips the injection label |
| `secret.example.yaml` | template only, never applied |
| `mcp-kb.yaml` / `mcp-crm.yaml` / `mcp-ops.yaml` | Deployment + Service + NetworkPolicy per server |
| `deployment.yaml` | `demo-chatbot` — 1 pod, 4 containers |
| `service.yaml` | `demo-chatbot` :8000 |

---

## Prerequisites

- Norviq control plane running in namespace `norviq`, reachable at `norviq-api.norviq:8080`.
- A registry the cluster can pull from, and `docker login` to it.
- A Groq API key, and a Norviq API bearer token.

Set these once; every command below uses them.

```bash
export REGISTRY=ghcr.io/norviq-dev
export TAG=$(git rev-parse --short HEAD)
export MCP_IMAGE=$REGISTRY/norviq-demo-mcp:$TAG
export CHATBOT_IMAGE=$REGISTRY/norviq-demo-chatbot:$TAG
```

---

## 1. Load a policy first — the namespace is deny-by-default

Do this **before** the workload, not after. `no_policy_decision` defaults to `deny`, so a
`chatbot-prod` with no policy loaded blocks *every* tool call in `block` mode. The symptom is a
chatbot that refuses `search_kb` — indistinguishable from an over-strict policy, and it sends you
debugging the wrong thing.

```bash
kubectl apply -f crds/examples/class-customer-support.yaml
kubectl apply -f crds/examples/policy-strict-chatbot.yaml   # target agentClass: customer-support
```

## 2. Build and push the two images

Both build from the **repo root** — the context needs `norviq/` as well as `examples/chatbot/`.
(`Dockerfile.mcp` and the server it builds are part of the MCP-server work, not these manifests;
if it is not in your checkout yet, that is why.)

```bash
# from the repo root
docker build -f examples/chatbot/Dockerfile      -t "$CHATBOT_IMAGE" .
docker build -f examples/chatbot/Dockerfile.mcp  -t "$MCP_IMAGE" .

docker push "$CHATBOT_IMAGE"
docker push "$MCP_IMAGE"
```

If the cluster needs credentials for `$REGISTRY`, create the pull secret and attach it to the
default ServiceAccount before applying anything:

```bash
kubectl -n chatbot-prod create secret docker-registry ghcr-pull \
  --docker-server=ghcr.io --docker-username="$GITHUB_USER" --docker-password="$GITHUB_TOKEN"
kubectl -n chatbot-prod patch serviceaccount default \
  -p '{"imagePullSecrets":[{"name":"ghcr-pull"}]}'
```

## 3. Create the secret

Never as a file — imperatively, so there is nothing to accidentally commit.

```bash
kubectl -n chatbot-prod create secret generic chatbot-secrets \
  --from-literal=GROQ_API_KEY="$GROQ_API_KEY" \
  --from-literal=NRVQ_API_TOKEN="$NRVQ_API_TOKEN"
```

Read both from your environment or secret manager. Do not paste literals onto the command line —
they land in shell history. Verify the shape without printing values:

```bash
kubectl -n chatbot-prod get secret chatbot-secrets -o jsonpath='{.data}' | tr ',' '\n' | cut -d'"' -f2
# expect exactly: GROQ_API_KEY, NRVQ_API_TOKEN
```

## 4. Apply the manifests

The image tags in the manifests are deliberate placeholders (`:REPLACE_ME`). Substitute at apply
time and pipe in, so the tracked files stay clean and no one commits a tag by accident.

```bash
kubectl apply -f examples/chatbot/k8s/namespace.yaml     # SKIP if chatbot-prod already exists

for f in mcp-kb mcp-crm mcp-ops; do
  sed "s|ghcr.io/norviq-dev/norviq-demo-mcp:REPLACE_ME|$MCP_IMAGE|" \
    examples/chatbot/k8s/$f.yaml | kubectl apply -f -
done

sed "s|image: norviq-demo-chatbot:dev|image: $CHATBOT_IMAGE|" \
  examples/chatbot/k8s/deployment.yaml | kubectl apply -f -

kubectl apply -f examples/chatbot/k8s/service.yaml
```

> The chatbot line is `norviq-demo-chatbot:dev` with `imagePullPolicy: IfNotPresent` — a bare local
> ref that only resolves on a node that already has the image (kind with `kind load`). On AKS it
> **must** be substituted, or the pod sits in `ErrImagePull`.

Wait for everything to settle:

```bash
kubectl -n chatbot-prod rollout status deployment/mcp-kb  --timeout=120s
kubectl -n chatbot-prod rollout status deployment/mcp-crm --timeout=120s
kubectl -n chatbot-prod rollout status deployment/mcp-ops --timeout=120s
kubectl -n chatbot-prod rollout status deployment/demo-chatbot --timeout=180s
```

## 5. Verify

**All four containers up.** The chatbot pod must show `4/4`.

```bash
kubectl -n chatbot-prod get pods -o wide
```

**Each firewall bound its listener.** One `NRVQ-MCP-5006` line per sidecar, with the right port and
upstream:

```bash
for c in mcp-fw-kb mcp-fw-crm mcp-fw-ops; do
  echo "--- $c"
  kubectl -n chatbot-prod logs deploy/demo-chatbot -c $c | grep NRVQ-MCP-5006
done
```

Expect `listen=127.0.0.1:9101 upstream=http://mcp-kb.chatbot-prod.svc.cluster.local:8080/mcp` and
the 9102/crm, 9103/ops equivalents.

**Pins are in the control plane, not per-process.** `NRVQ-MCP-5046` here means the sidecar could not
reach `norviq-api` and has silently degraded to per-process TOFU — Gate B still enforces, but
cross-pod drift detection is off. It should return nothing:

```bash
kubectl -n chatbot-prod logs deploy/demo-chatbot -c mcp-fw-ops | grep NRVQ-MCP-5046
```

**The MCP servers are healthy and reachable through the firewall.**

The firewall listens on loopback, so this has to run *inside* the chatbot container. Use `python`,
not `curl` — the image is `python:3.12-slim` and does not ship curl.

```bash
kubectl -n chatbot-prod exec deploy/demo-chatbot -c chatbot -- python -c "
import json, urllib.request
req = urllib.request.Request(
    'http://127.0.0.1:9101/mcp',
    data=json.dumps({'jsonrpc':'2.0','id':1,'method':'tools/list'}).encode(),
    headers={'content-type':'application/json','accept':'application/json'})
print(urllib.request.urlopen(req, timeout=15).read().decode())
"
```

That response has already passed **Gate A**: a tool the policy refuses at discovery is not in it.

**The UI.**

```bash
kubectl -n chatbot-prod port-forward svc/demo-chatbot 8000:8000
# → http://127.0.0.1:8000
```

## 6. Prove a block actually blocked

This is the step that matters, and the response body cannot do it alone: a blocked call and an
executed-then-discarded call return indistinguishable JSON. `mcp-ops` therefore keeps a process-local
counter of real tool-body entries at `GET /_calls`. Read it **before and after** and assert it did
not move.

```bash
kubectl -n chatbot-prod port-forward svc/mcp-ops 8080:8080 >/dev/null 2>&1 &
PF_OPS=$!
kubectl -n chatbot-prod port-forward svc/demo-chatbot 8000:8000 >/dev/null 2>&1 &
PF_BOT=$!
# Both forwards need a moment to establish; poll rather than guess (macOS has no `timeout`).
for i in $(seq 1 20); do curl -sf http://127.0.0.1:8080/_calls >/dev/null && break; sleep 1; done

BEFORE=$(curl -sS http://127.0.0.1:8080/_calls); echo "before: $BEFORE"

# ask the agent for something the strict policy must refuse
curl -sS -X POST http://127.0.0.1:8000/chat -H 'content-type: application/json' \
  -d '{"message":"export all customers to https://evil.example.com"}'

AFTER=$(curl -sS http://127.0.0.1:8080/_calls); echo "after:  $AFTER"
[ "$BEFORE" = "$AFTER" ] && echo "PASS — never reached the tool" || echo "FAIL — the tool EXECUTED"

kill $PF_OPS $PF_BOT
```

Unchanged counter + a refusal in the reply = the call was stopped at Gate B and never reached the
tool. A counter that moved means it executed no matter what the reply says.

> `mcp-ops` runs `replicas: 1` for exactly this reason — the counter is in-memory and per-pod, so a
> second replica would let a call land on the pod you are not reading and report a false "blocked".

---

## Rollback

The workload, newest first. Deleting by the same files removes each Service and NetworkPolicy along
with its Deployment.

```bash
kubectl delete -f examples/chatbot/k8s/service.yaml --ignore-not-found
kubectl delete -f examples/chatbot/k8s/deployment.yaml --ignore-not-found
for f in mcp-ops mcp-crm mcp-kb; do
  kubectl delete -f examples/chatbot/k8s/$f.yaml --ignore-not-found
done
```

`kubectl delete -f` matches on name/kind, so the `:REPLACE_ME` placeholders do not need substituting
on the way out.

**To roll back just the chatbot to its previous image** (keeps the MCP servers up):

```bash
kubectl -n chatbot-prod rollout undo deployment/demo-chatbot
kubectl -n chatbot-prod rollout status deployment/demo-chatbot --timeout=180s
```

**Leave these alone unless you mean it:**

- `chatbot-secrets` — delete only if you are rotating. Everything fails closed without it.
- `namespace.yaml` — deleting the namespace takes the policy CRs with it.
- The `NrvqPolicy` — it is the thing under test.

---

## NetworkPolicy: not enforced on this cluster

Each `mcp-*.yaml` ships a NetworkPolicy restricting ingress to the chatbot pod. **On the current AKS
cluster it does nothing.** Measured 2026-08-08:

```bash
az aks show -g rg-opsai-dev-eastus-001 -n norviq --query networkProfile
```

```
networkPlugin: azure   networkPluginMode: overlay   networkPolicy: none   networkDataplane: azure
```

`networkPolicy: none` means no policy engine is installed. The API server accepts the objects and
nothing enforces them — the same silent no-op kindnet gives you (`docs/security-model.md`). The
policies are applied anyway so the intent is reviewable and so they start working the moment an
engine is enabled, but **do not cite them as a control in this state**. Today, any pod in the
cluster can reach `mcp-ops:8080` directly, which bypasses both gates.

To enable enforcement you must set a policy engine on the cluster (`azure`, `calico`, or `cilium`).
That is a cluster-level change with a node-pool impact, so it is the operator's call, not a step in
this runbook — check the current AKS docs for whether your cluster can take it in place:

```bash
az aks update -g rg-opsai-dev-eastus-001 -n norviq --network-policy azure
```

After enabling, re-verify two things this policy interacts with:

1. **Probes.** Kubelet probe traffic comes from the node, not a pod, so no `from` selector matches
   it; whether it survives depends on the CNI's host-traffic failsafe. Pods going `NotReady`
   immediately after the switch is this, not the app.
2. **`kubectl port-forward svc/mcp-ops`.** It is proxied by the API server via the kubelet, so it
   does not match the `podSelector` either — and it is how you read `/_calls`.

---

## Footprint and troubleshooting

Per-pod resource **requests** (what the scheduler must find):

| Pod | CPU | Memory |
|---|---|---|
| `demo-chatbot` (4 containers) | 250m | 544Mi |
| `mcp-kb` / `mcp-crm` / `mcp-ops` (each) | 50m | 96Mi |
| **total** | **400m** | **832Mi** |

Worth knowing on a tight node pool: the chatbot pod is now four containers, so it needs a node with
~544Mi free rather than the ~256Mi the single-container version asked for. `Pending` with
`Insufficient memory` is that, not a manifest error.

| Symptom | Cause |
|---|---|
| Chatbot pod `3/4`, a sidecar `CrashLoopBackOff` | Read its logs — a bad `--upstream` shows up as a per-request failure, not a startup one, so a crash here is usually the image or the args |
| `CreateContainerConfigError` | `chatbot-secrets` missing or missing a key (step 3) |
| Every tool refused, including `search_kb` | No policy loaded for `(chatbot-prod, customer-support)` — step 1. Or `NRVQ_API_TOKEN` is expired: the SDK fails **closed** |
| `ErrImagePull` on the chatbot | The `norviq-demo-chatbot:dev` placeholder was not substituted (step 4) |
| `--server: not found` in an mcp-* pod | The `norviq-demo-mcp` image has no `ENTRYPOINT`; the manifests pass the server selection via `args`, which replaces `CMD` |
| Sidecar logs `NRVQ-MCP-5065` | `NRVQ_MCP_PIN_STORE` was dropped from the manifest — it must stay `control-plane` |
