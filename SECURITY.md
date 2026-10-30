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
CVE. The exceptions below are the only vulnerabilities we knowingly carry, and each is listed because a
version bump cannot close it today — a CVE a bump *can* fix is bumped, not listed here (e.g. the
`werkzeug>=3.1.9` constraint in `pyproject.toml`, which closes CVE-2025-66221 / CVE-2026-21860 /
CVE-2026-27199 / CVE-2026-102598, and the `mcp>=1.30.0,<2` floor on the `crewai`/`mcp`/`frameworks`
extras, which closes CVE-2026-59950 — a WebSocket server transport that validated neither `Host` nor
`Origin` — and CVE-2026-59951 / CVE-2026-116684 / -116685 / -116686. The other optional-extra floors
added on 2026-10-30 (litellm, pillow, filelock, dnspython, oauthlib, langgraph, crewai) are listed with
their CVEs in `pyproject.toml`).
The gate's allow-list — `ACCEPTED` in `scripts/check_fossa_issues.py` — names exactly the ids in this
table's first column, and `tests/test_check_fossa_issues.py` fails the build when the two differ.

Where a floor is declared is a decision, not a formality: `mcp` is a **direct** dependency of an extra
we declare, so its floor lives in `[project.optional-dependencies]` where `pip install '.[crewai]'`
will honour it. `werkzeug` is reachable only transitively (semantic-kernel → openapi-core), with no
extra of ours to attach it to, so it can only be a `[tool.uv]` constraint — which binds `uv.lock` and
therefore the FOSSA scan, but *not* a pip install. See the `cryptography` note below for the case where
that distinction decides whether a shipped image is actually patched.

FOSSA scans **three** dependency graphs, and it is worth being explicit about which, because auditing
only one gives false confidence: Python (the runtime closure, exported from `uv.lock` into
`requirements-runtime.txt` by the workflow), Node (`ui/package.json`), and Go (`webhook/go.mod`).
`pip-audit` alone covers the first. For ten weeks the CI job scanned only two: `.fossa.yml` named the
Python target `type: pip`, which is not a fossa-cli type, so nothing matched and every run read
"2 projects scanned". It is `setuptools` now, and the workflow fails if any of the three graphs is
missing from the scan summary. The optional extras are outside this scan by design; they are audited
with `uv export --extra <name>` and the floors in `pyproject.toml`.

The Python graph is scoped by `[tool.uv] environments` to the interpreters this project claims (3.11 /
3.12 — see `classifiers`; both images are `python:3.12-slim`). That is a security decision, not a
packaging one. `requires-python = ">=3.11"` has no ceiling, so uv will otherwise also resolve a python
**3.14 fork** of the optional framework extras; because those upstreams do not support 3.14 yet, the
resolver satisfies it by walking them *backwards* — pinning `instructor` 1.12 and `semantic-kernel` 1.8
and dragging in `diskcache` (CVE-2025-69872, pickle deserialization, **no fixed release exists**). None
of it is installable by anyone, nothing builds or tests it, and yet the gate scores us on it. Auditing
a dependency graph that ships nowhere is not extra rigour; it costs real attention and buys nothing.
Widen the setting when 3.13/3.14 are supported for real — tested and in `classifiers` — not before.

The Python entries below (litellm, chromadb, semantic-kernel) are **not in any shipped container image**
— `Dockerfile.api` and `Dockerfile.engine` install `.[spiffe]` and nothing else, and `webhook/Dockerfile`
is a Go binary on `distroless/static` with no Python at all — because they live exclusively in the
**optional SDK framework-adapter extras** (`norviq[frameworks]` / `[crewai]` / `[semantic-kernel]`),
which a deployment must explicitly opt into. The k8s.io row is in a shipped binary, the webhook, and is
carried because the matches are spurious, not because the code is absent.

**`cryptography>=50.0.0`** is the other such floor, and unlike `werkzeug` it *is* in the shipped image —
so it is declared in `[project] dependencies`, not in `[tool.uv] constraint-dependencies`. The images
install with **pip**, which reads neither `uv.lock` nor uv's constraints; a floor kept only in the uv
config would have left the published images on a vulnerable version while every local check looked green.
It closes **GHSA-537c-gmf6-5ccf** (HIGH, CVSS 7.5): `cryptography` wheels statically link OpenSSL, and
every wheel below 48.0.1 bundles the OpenSSL affected by the
[2026-06-09 advisory](https://openssl-library.org/news/secadv/20260609.txt). The floor was then raised
from 48.0.1 to 50.0.0 for CVE-2026-69247, which affects 49.0.0 and has no 49.x fix; `pyopenssl>=26.4.0`
is declared alongside it because 26.3.0 caps `cryptography<50`. `cryptography` reaches us
transitively through `pyjwt`, `spiffe`, `azure-identity` and `pyopenssl`, so it is on the JWT-verification
and SPIFFE paths rather than in an optional extra.

Reaching that floor required declaring `spiffe` and the framework extras as **conflicting** (see
`[tool.uv] conflicts`). The old lock pinned `spiffe 0.2.x`, which caps `cryptography<47`; `spiffe>=0.3`
lifts the cap but needs `protobuf>=6.31.1`, while every `autogen-core>=0.4` needs protobuf 4.x/5.x. The
two cannot co-resolve — a property of their upstreams, not a choice. Nothing installs both: the images
take `.[spiffe]`, and `framework-compat.yml` installs one framework at a time.

| CVE | Package (source) | Why unfixable-by-bump | Why not exploitable here |
|-----|------------------|-----------------------|--------------------------|
| CVE-2024-6825 | `litellm` (via `crewai[litellm]`) | There is no bump to make. The advisory (GHSA-53gh-p8jc-7rg8) covers litellm **1.40.3.dev2 through 1.40.12**; the lock is at **1.100.4**. FOSSA matched it against 1.96.x, i.e. without that upper bound, so this is a spurious match carried like the k8s.io row. (The old reason here — "1.96.1 is the newest release and has no cp311 wheel" — went stale: 1.100.4 ships cp310-abi3 wheels. The bump to it closed litellm's real advisories on 1.96.0, CVE-2026-84377 and CVE-2026-114612.) | Outside the advisory's affected range. Also reachable only through the **optional** `norviq[crewai]` extra and in **no shipped image**. |
| CVE-2026-45829, CVE-2026-45830, CVE-2026-45831, CVE-2026-45833 | `chromadb` (via `crewai`) | No fixed release exists — 1.5.9, the latest, is affected by all four. | All four are in the **ChromaDB HTTP server**: a pre-auth (45829) and an authenticated (45833) code injection through `trust_remote_code` on the collections endpoints, and two missing tenant checks in the server's authorization layer (45830; `SimpleRBACAuthorizationProvider` for 45831). CrewAI uses chromadb as an **embedded client**, so no server, endpoint or authorization provider is ever started. |
| CVE-2026-26030 | `semantic-kernel` | The fix (`>=1.39.4`), like every release after the locked 1.36.0 up to the current 1.46.0, requires `azure-ai-agents>=1.2.0b3`. No stable `azure-ai-agents` 1.2 exists (1.1.0 is the newest stable, 1.2.0b6 the newest pre-release, checked 2026-10-30), and we will not ship a pre-release in a lockfile. | RCE is in the `InMemoryVectorStore` filter-lambda path. The Norviq semantic-kernel adapter imports nothing from `semantic_kernel` at all: it is an invocation filter that duck-types the context object. |
| CVE-2026-25592 | `semantic-kernel` | The advisory describes the **.NET** SDK (fixed in `Microsoft.SemanticKernel.Plugins.Core` 1.71.0), but its PyPI record (GHSA-2ww3-72rp-wpp4) marks the pip package fixed in 1.39.3. That release needs the same pre-release `azure-ai-agents` as the row above. | The affected `SessionsPythonPlugin` `DownloadFileAsync` helper is .NET code; the Norviq adapter uses no semantic-kernel plugin of either language. |
| CVE-2018-1002105, CVE-2019-11250, CVE-2020-8565 | `k8s.io/apimachinery`, `k8s.io/client-go` (admission webhook) | A bump cannot satisfy a match that has no upper bound. FOSSA flags these against any v0.x; the webhook pins **v0.37.0**, twenty minors past the latest fix (client-go 0.17.0 / 0.19.6). | The code has never had them. Per the advisory database, CVE-2018-1002105 is against `kubernetes/kubernetes` < 1.12.3 — an API-server aggregation bug, not a library; the other two are client-go credential-logging bugs fixed in 0.17.0 and 0.19.6. Spurious matches, reviewed each release like the rest. |

These are reviewed each release; we will drop an exception and bump the moment upstream ships a fixed
release reachable without a pre-release dependency.

> **The React Router row (`GHSA-qwww-vcr4-c8h2`) was removed on 2026-10-30, because 7.18.2 is no longer
> inside it.** The row said the RSC-mode CSRF bypass was fixed only in 8.3.0 (a React 19 migration). The
> advisory has since been revised to `>=7.12.0 <7.18.2`, which makes the pinned 7.18.2 the first
> patched release (npm advisory feed, 2026-10-30). `npm audit --omit=dev` on `ui/` reports 0, and FOSSA's
> 2026-10-27 scan of the console raised no vulnerability issue. An exception for a version the
> advisory no longer covers only disarms the gate if the advisory is revised back.
>
> One lesson from that row's history still holds. It was once written into this table but never into
> the gate's allow-list, so the gate kept failing on a vulnerability this document had already accepted.
> That is why the allow-list matches **GHSA ids as well as CVE ids** (that advisory had no CVE), and
> why a test now holds the table and the allow-list to the same set.

The Python entries were marked **Ignored** in the FOSSA project UI (reason: *vulnerable code not in
execute path*, scoped to this project and the dependency versions of the time), so FOSSA's own "Security
Analysis" check reflected this acceptance rather than a bare red. Because that ignore is version-scoped,
a bump re-surfaces the CVE for review, and the 2026-10-30 relock does exactly that: chromadb moved
1.1.1 → 1.5.9 and litellm 1.96.0 → 1.100.4, and the table now lists three chromadb CVEs
(45830/45831/45833) it did not list before. A maintainer with FOSSA access has to re-review all of them
in the UI.

**`GHSA-337j-9hxr-rhxg` is not what the "Security Analysis" badge reports, and it is worth being precise
about that, because assuming otherwise wasted real time.** `npm audit` and FOSSA do not draw from the
same advisory database, so the same lockfile yields different findings. React Router showed up in
`npm audit`; the FOSSA badge was reporting **`GHSA-mh99-v99m-4gvg` in `brace-expansion` 5.0.7** (HIGH,
CVSS 7.5 — DoS via unbounded expansion), a transitive dependency of `minimatch`. That one had a patch
fix and was simply bumped to 5.0.8, not accepted. Two lessons: reading one scanner's output tells you
nothing about another's, and a red badge should be opened and read rather than attributed to whichever
known issue is nearest to hand.

The remaining divergence is structural: the `fossa` CI gate honours this repo's allow-list while the
badge reflects the FOSSA project UI, and only a maintainer with FOSSA access can reconcile them. Treat a
red badge as **unreviewed until opened**. A genuinely new CVE and a known accepted one look identical
from the outside, so the finding has to be read in the FOSSA UI — the per-revision view at
`Projects → norviq → <branch>/<sha> → Issues → Vulnerability` names the package and the advisory.
