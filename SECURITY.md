# Security Policy

Norviq is a security product, and we take vulnerabilities in it seriously. Thank you for helping keep
Norviq and its users safe.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security reports.**

Report privately through either channel:

- **GitHub Private Vulnerability Reporting** — on this repository, go to the **Security** tab →
  **Report a vulnerability**. This is the preferred channel.
- **Email** — `security@norviq.dev`. Encrypt with our PGP key if the report is sensitive (key available
  on request).

Please include, where possible:

- A description of the issue and its impact.
- The affected component (engine, API, webhook, console UI, Helm chart, SDK) and version / commit.
- Steps to reproduce, or a proof-of-concept.
- Any suggested remediation.

## What to expect

- **Acknowledgement** within **3 business days**.
- An initial assessment and severity rating within **10 business days**.
- We practice **coordinated disclosure**: we'll agree on a disclosure timeline with you, fix the issue,
  and credit you in the advisory unless you prefer to remain anonymous.
- Please give us a reasonable window to release a fix before any public disclosure.

## Scope

In scope:

- The enforcement engine and policy evaluation path (`norviq/engine`, OPA integration).
- The API and authentication/authorization (`norviq/api`).
- The admission webhook and sidecar injection (`webhook/`).
- The console UI (`ui/`).
- The Helm chart and default configuration (`helm/`).
- The agent SDK (`norviq/sdk`).

Out of scope (report to the upstream project instead):

- Vulnerabilities in third-party dependencies with no Norviq-specific exposure (we track these via
  automated scanning; a dependency CVE that Norviq materially exposes **is** in scope).
- Findings that require a pre-existing cluster-admin compromise.
- Denial of service from unbounded self-inflicted configuration.

## Supported versions

Norviq is pre-1.0. Security fixes are released against the latest `main`. Pin to a released tag and
watch releases for security updates.

## Hardening posture

For operators, the current threat-model notes and operator responsibilities are documented in
[`docs/security-model.md`](docs/security-model.md) and
[`docs/engineering/security-baseline.md`](docs/engineering/security-baseline.md). In particular, review
the production checklist (`api.secretKey`, `config.requireStrongSecret`, TLS, image provenance, and the
sidecar-injection trust model) in [`docs/configuration.md`](docs/configuration.md) before deploying.

## Accepted dependency exceptions

Our FOSSA dependency-vulnerability gate (`.github/workflows/fossa.yml`) fails CI on any known dependency
CVE. The exceptions below are the only vulnerabilities we knowingly carry. **None of them are present in
the shipped container images** — the `engine`, `api`, `ui`, and `webhook` images install only the core
runtime (`.[spiffe]`). All three live exclusively in the **optional SDK framework-adapter extras**
(`norviq[frameworks]` / `[crewai]` / `[semantic-kernel]`), which a deployment must explicitly opt into,
and each cannot be closed by a version bump today. The allow-list in the gate is kept in lockstep with
this table; a CVE a bump *can* fix is bumped, not listed here (e.g. `werkzeug>=3.1.6` in `pyproject.toml`
closes CVE-2025-66221 / CVE-2026-21860 / CVE-2026-27199).

| CVE | Package (source) | Why unfixable-by-bump | Why not exploitable here |
|-----|------------------|-----------------------|--------------------------|
| CVE-2026-45829 | `chromadb` (via `crewai`) | No fixed release exists — the latest version is still affected. | It is a pre-auth RCE in the **ChromaDB HTTP server**; CrewAI uses chromadb as an **embedded client**, so the vulnerable server path is never started. |
| CVE-2026-26030 | `semantic-kernel` | The fix (`>=1.39.4`) pulls a **pre-release** `azure-ai-agents` dependency, which we will not ship in a lockfile. | RCE is in the `InMemoryVectorStore` filter-lambda path, which the Norviq semantic-kernel adapter does not use. |
| CVE-2026-25592 | `semantic-kernel` | This is a **.NET** CVE (fixed in .NET Core `1.71.0`); FOSSA maps it onto the pip package, where no release clears it. | The affected `[KernelFunction] DownloadFileAsync` helper exists only in the .NET SDK, not the Python package we depend on. |

These are reviewed each release; we will drop an exception and bump the moment upstream ships a fixed
release reachable without a pre-release dependency.
