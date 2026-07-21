# Contributing to Norviq

Thanks for your interest in contributing. This guide covers how to get set up, how to run the same
checks CI runs, and how to get a change merged.

By participating you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## Ways to contribute

- **Report bugs** — open an issue with a clear repro. For **security** issues, follow
  [SECURITY.md](SECURITY.md) instead (do not open a public issue).
- **Improve docs** — the `docs/` tree and this README are always improvable.
- **Fix or build features** — please open (or comment on) an issue first for anything non-trivial, so
  we can agree on the approach before you invest time.

## The stack

Norviq is a small polyglot monorepo:

| Component | Language / tooling | Location |
|-----------|--------------------|----------|
| Enforcement engine + API | Python 3.11+, FastAPI, OPA/Rego | `norviq/` |
| Console UI | React 18 + Vite, TypeScript | `ui/` |
| Admission webhook | Go 1.26 | `webhook/` |
| Deployment | Helm, Kubernetes CRDs | `helm/norviq` |
| Policies | Rego | `comprehensive.rego`, `policies/` |
| Tests | pytest, vitest, `go test` | `tests/`, `ui/src/**/*.test.tsx`, `webhook/` |

## Development setup

```bash
# Python backend + tooling (requires-python = ">=3.11"; CI runs 3.11, images build on 3.12)
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"          # pytest, pytest-asyncio, httpx, ruff

# Console UI (Node.js 20+)
cd ui && npm ci

# Go webhook (Go 1.26+)
cd webhook && go build ./...
```

You also need the **`opa`** binary on your `PATH` — a large part of the test suite shells out to it
to evaluate real Rego (there is no stub evaluator).

### Backing services

`docker-compose.dev.yml` (repo root) brings up the Postgres and Redis the API and the integration
tests expect. Postgres is on host port **5433** (not 5432, so it doesn't collide with a local
install); Redis on 6379.

```bash
docker compose -f docker-compose.dev.yml up -d
```

### Running the stack locally

```bash
python scripts/seed-local-policies.py                                  # seed policies so the console has data
python -m uvicorn norviq.api.main:app --host 127.0.0.1 --port 8080     # API
curl http://127.0.0.1:8080/healthz                                     # expect 200

cd ui && npm run dev -- --port 5173 --strictPort                       # console; proxies /api + /ws to :8080
```

## Running the checks

### What actually runs

```bash
# Python — 1400+ tests. `make test` and `make lint` are thin aliases for the first two.
pytest tests/ -v --tb=short
ruff check norviq/ tests/

# Console UI
cd ui && npx tsc --noEmit && npm run test:run     # test:run = `vitest run`

# Go webhook
cd webhook && go test ./... && gofmt -l . && go vet ./...
# `gofmt -l` currently lists two pre-existing files with struct-alignment drift
# (config.go, handler_injection_integrity_test.go) — not caused by your change.

# Rego — the shipped baseline policy must parse
opa check --v0-compatible comprehensive.rego

# Helm chart
helm lint helm/norviq
helm template norviq ./helm/norviq --set-json 'policyQuotaNamespaces=["default"]'
```

`helm template` **fails by design** with no `policyQuotaNamespaces` — that is the chart's
fail-closed guard (an empty list would render zero baseline policies and silently leave every agent
class ungoverned), not a bug. Pass the flag above to render.

> `make build` and `make docker-build` in the `Makefile` are stale and reference paths that no
> longer exist (`norviq/webhook`, `norviq/cli` as Go builds, `Dockerfile.sidecar`). Use the explicit
> commands above; build images with `docker build -f Dockerfile.api .` etc.

### What needs infrastructure

Most of `tests/` is hermetic. Two groups are not:

- **`tests/integration/`** — expects a running API at `NRVQ_API_URL` (default
  `http://127.0.0.1:8080`) and Postgres at `NRVQ_PG_URL` (default the `docker-compose.dev.yml`
  instance on 5433). Start both before running this directory.
- **`tests/helm/`** — pure `helm template` rendering assertions (chart hardening, container-runtime
  contract, network-exposure matrix, OPA loopback bind). Needs `helm` on `PATH`, no cluster.

Neither touches a real cluster.

## CI gates

These run on **pull requests** ([`.github/workflows/`](.github/workflows/)). Knowing what each one
fails on is how you get a green PR on the first try.

| Workflow | Job | Fails on |
|---|---|---|
| `security.yml` | `secrets` | gitleaks over the PR commit range, **fail-closed** |
| `security.yml` | `python-sast` | `bandit -ll` on changed `norviq/**/*.py` **and** `semgrep` diff-aware vs the PR base, **fail-closed** |
| `security.yml` | `ts-sast` | eslint (security rules) on changed `ui/src` |
| `security.yml` | `deps-audit`, `iac` | nothing yet — report-only while the baseline is triaged (see [docs/engineering/security-baseline.md](docs/engineering/security-baseline.md)) |
| `fossa.yml` | `fossa` | dependency **vulnerability / malware** issues (license findings are uploaded but not gated) |
| `framework-compat.yml` | `compat` | only runs on PRs touching `norviq/sdk/**` or `tests/sdk/compat/**` |

Two things that catch contributors out:

- **`fossa.yml` is skipped on fork PRs** — it needs a repo secret. A maintainer runs it after merge
  to `main`, so a dependency bump can still be rejected post-review.
- **Image scanning is not a PR gate.** Trivy scans the four built images in `build.yml`, which only
  runs on push to `main` (the images don't exist at PR time). The `iac` job's Trivy pass is
  *config/filesystem* only, and report-only.

### Suppressing a SAST finding

Bandit and semgrep are **separate tools with separate comment syntax**, and `python-sast` runs both.
Suppressing one does not suppress the other — a line that trips both needs both markers:

```python
text(f"SELECT ... FROM policies {where}"),  # nosec B608 (constant WHERE fragments; user value bound as :ns) # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
```

- `# nosec <ID>` — bandit. Always name the check ID and give the reason in the same comment.
- `# nosemgrep: <rule-id>` — semgrep. `# nosec` alone will **not** silence semgrep.

Semgrep is **diff-aware** (`--baseline-commit`), so it only flags findings your PR introduces. If it
fires, your change introduced it — suppress only with a justification a reviewer can check, never to
silence a real finding.

## Standards

- **Match the surrounding code** — naming, comment density, and idiom. Don't reformat unrelated code.
- **Fail closed.** This is a security product: on any error in the enforcement/auth path, deny — never
  fail open. New security-relevant code needs a test proving the block/deny path.
- **Tests are required** for behavior changes. No new test failures against the baseline suite.
- **Policies must validate** — any Rego must define `decision` / `rule_id` / `reason` and a
  `default decision`, and must not use network/environment builtins (see
  [docs/guides/writing-policies.md](docs/guides/writing-policies.md)).
- **SPDX headers.** New Python, Go, and workflow files start with
  `# SPDX-License-Identifier: Apache-2.0`.
- **No secrets, personal data, or hardcoded hosts/ports** in committed code.
- **Conventional commits** — a typed, scoped subject: `fix(helm): …`, `feat(engine): …`,
  `test(e2e): …`, `docs(sdk): …`.

## Pull requests

1. Fork and branch from `main`.
2. Keep PRs focused; describe the change and how you tested it.
3. Run the checks above locally, and confirm CI is green.
4. A maintainer will review. For enforcement/auth/policy changes, expect a careful security review.

## License

By contributing, you agree that your contributions are licensed under the [Apache 2.0](LICENSE) license.
