# Contributing to Norviq

Thanks for your interest in contributing. This guide covers how to get set up, the standards we hold
code to, and how to get a change merged.

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
| Enforcement engine + API | Python 3.12, FastAPI, OPA/Rego | `norviq/` |
| Console UI | React 18 + Vite, TypeScript | `ui/` |
| Admission webhook | Go | `webhook/` |
| Deployment | Helm, Kubernetes CRDs | `helm/`, `crds/` |
| Policies | Rego | `comprehensive.rego`, `policies/` |

## Development setup

```bash
# Python backend + tooling (needs Python 3.12+)
pip install -e ".[dev]"

# Console UI (needs Node.js 20+)
cd ui && npm install

# Go webhook (needs Go 1.26+)
cd webhook && go build ./...
```

You'll need a local **PostgreSQL** and **Redis** for the backend tests that touch them (a
`docker-compose.dev.yml` is provided), and the **`opa`** binary on your `PATH` for policy tests.

## Running the checks

Please make sure the relevant checks pass before opening a PR:

```bash
make test         # ruff + pytest + vitest + opa (the full gate)
make lint         # ruff + tsc + go vet + gofmt

# or per-component:
ruff check norviq tests
cd ui && npx tsc --noEmit && npx vitest run
cd webhook && go test ./... && gofmt -l . && go vet ./...
opa check --v0-compatible comprehensive.rego
```

## Standards

- **Match the surrounding code** — naming, comment density, and idiom. Don't reformat unrelated code.
- **Fail closed.** This is a security product: on any error in the enforcement/auth path, deny — never
  fail open. New security-relevant code needs a test proving the block/deny path.
- **Tests are required** for behavior changes. No new test failures against the baseline suite.
- **Policies must validate** — any Rego must define `decision` / `rule_id` / `reason` and a
  `default decision`, and must not use network/environment builtins (see
  [docs/guides/writing-policies.md](docs/guides/writing-policies.md)).
- **No secrets, personal data, or hardcoded hosts/ports** in committed code.
- **Conventional-ish commits** — a short, typed subject (`fix(sec): …`, `feat(engine): …`, `docs: …`).

## Pull requests

1. Fork and branch from `main`.
2. Keep PRs focused; describe the change and how you tested it.
3. Ensure `make test` and `make lint` pass, and CI is green (the FOSSA + Trivy + SAST gates run on PRs).
4. A maintainer will review. For enforcement/auth/policy changes, expect a careful security review.

## License

By contributing, you agree that your contributions are licensed under the [Apache 2.0](LICENSE) license.
