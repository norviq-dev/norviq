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
