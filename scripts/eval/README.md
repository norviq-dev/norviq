# Customer-eval — local environment (kind)

Stands up Norviq the way the "Lumina Retail SecOps" persona would try it: **two local
clusters** (to test the multi-cluster claim) running the Norviq **core** (api + engine + ui +
postgres + redis), a seeded policy, and real benign+attack traffic — so the scout fleet has a
live system to evaluate instead of guessing from code.

## Prerequisites (macOS)
- Docker Desktop running (allocate **≥ 6 GB** — two clusters of ~10 pods each)
- `kind`, `kubectl`, `helm`, `python3` on PATH (`node` too if the UI scout uses Playwright)
  ```bash
  brew install kind kubectl helm node
  ```
- Internet access for the **first** Option-A build (the api image downloads the OPA binary; the ui
  image runs `npm ci`). After images are built they're cached.

## Run order
```bash
bash scripts/eval/00-bootstrap-local.sh     # clusters + helm + seed policy + traffic
bash scripts/eval/20-portforward.sh         # leave running in its own terminal (UI+API for scouts)
# ... scouts do their recon ...
bash scripts/eval/10-generate-traffic.sh    # (optional) re-run to add more data
bash scripts/eval/99-teardown-local.sh      # delete the kind clusters when done
```

`kind` runs **real upstream Kubernetes as Docker containers** on this machine — genuine k8s
(API server, scheduler, kubelet, RBAC), just local.

**Default = Option A: builds your LOCAL code into images** (api+ui), `kind load`s them, and
evaluates that code — no Docker Hub round-trip. The engine pod is disabled (the API evaluates
in-process), which skips a build and saves RAM.

Options (env vars):
- `EVAL_PULL=1` — skip building; pull published `sanman97/norviq-engine:*-latest` instead. Use
  this **only after** pushing the fixed images to Docker Hub, otherwise you'd evaluate stale code.
- `SKIP_CLUSTER_B=1` — deploy only `lumina-a` (lightest; skips the multi-cluster test target).

Footprint (Mac mini): cluster A = pg+redis+api+ui, cluster B = pg+redis+api (no ui/engine).
Give Docker Desktop **≥6 GB**; if RAM is tight, use `SKIP_CLUSTER_B=1`.

### Data seeded (minimal, ~30 calls — kept light for the Mac mini)
`10-generate-traffic.sh` (run automatically) creates a representative dataset on cluster A:
4 agents across 2 namespaces with a **trust spread** (high `support-bot`, low `rogue-bot`,
medium `mixed-bot`, frozen `kiosk-bot`), benign+attack decisions in the audit log, and a
`attack-paths/compute` call — so Dashboard, Agents, Audit Log, and Attack Graph render with
real data instead of empty states.

## What the scouts consume
`00-bootstrap-local.sh` writes **`.reviews/customer-eval/env.json`**:
```jsonc
{
  "clusters":  {"a":"lumina-a","b":"lumina-b"},
  "contexts":  {"a":"kind-lumina-a","b":"kind-lumina-b"},
  "namespace": "norviq",
  "urls":      {"api_a":"http://127.0.0.1:18080","ui_a":"http://127.0.0.1:18081","api_b_hint":"..."},
  "tokens":    {"admin":"<jwt>","viewer":"<jwt>"},
  "secret_used":"change-me-in-production"
}
```
- **API scouts** → `urls.api_a` + `Authorization: Bearer <tokens.admin>` (use `tokens.viewer` for the
  namespace-authZ / RBAC test).
- **UI scout (Chromium)** → open `urls.ui_a`, set `localStorage.nrvq_token = <tokens.admin>`, reload.
- **Ops scout** → use `contexts.a` / `contexts.b` with `kubectl`/`helm`; the **multi-cluster test**
  is: with Norviq on BOTH contexts, can one console/API see/manage both? (Expected: no.)
- Scouts write findings to `.reviews/customer-eval/findings/<scout>.md` (orchestrator reads them).

## Known local friction (this is itself R1 "onboarding" evidence — record what happens)
The overlay (`values-local.yaml`) intentionally disables, for the laptop sim:
- **sidecar webhook injection** — needs a TLS cert + caBundle bootstrap (not turnkey). So the
  chatbot's protection is exercised via the **API** (`/api/v1/evaluate`) + seeded policy, not via
  auto-injected sidecars. *A real buyer would hit the cert-bootstrap gap — note it.*
- **validating admission policy** (needs k8s ≥1.30 CEL), **baseline cluster policy** (needs the
  controller that ships in the webhook), and the **OTel collector**.
- `dbSslMode=disable` — in-cluster postgres has no TLS (the chart defaults to `require`, which
  fails locally — also a finding for prod-config ergonomics).

## Safety
Read-only/non-destructive except the throwaway kind clusters. No commits. The JWTs here are signed
with a throwaway eval secret — never reuse this pattern for a real deployment. The default
`api.secretKey` shipping as `change-me-in-production` is itself an R8 finding for the security scout.
