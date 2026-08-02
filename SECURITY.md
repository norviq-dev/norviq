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
`werkzeug>=3.1.6` constraint in `pyproject.toml`, which resolves to 3.1.8 and closes CVE-2025-66221 /
CVE-2026-21860 / CVE-2026-27199, and the `mcp>=1.28.1,<2` floor on the `crewai`/`frameworks` extras,
which closes CVE-2026-59950 — a WebSocket server transport that validated neither `Host` nor `Origin`).
The allow-list in the gate is kept in lockstep with this table.

Where a floor is declared is a decision, not a formality: `mcp` is a **direct** dependency of an extra
we declare, so its floor lives in `[project.optional-dependencies]` where `pip install '.[crewai]'`
will honour it. `werkzeug` is reachable only transitively (semantic-kernel → openapi-core), with no
extra of ours to attach it to, so it can only be a `[tool.uv]` constraint — which binds `uv.lock` and
therefore the FOSSA scan, but *not* a pip install. See the `cryptography` note below for the case where
that distinction decides whether a shipped image is actually patched.

FOSSA scans **three** dependency graphs, and it is worth being explicit about which, because auditing
only one gives false confidence: Python (`pyproject.toml` + `uv.lock`), Node (`ui/package.json`), and Go
(`webhook/go.mod`). `pip-audit` alone covers the first.

The Python graph is scoped by `[tool.uv] environments` to the interpreters this project claims (3.11 /
3.12 — see `classifiers`; both images are `python:3.12-slim`). That is a security decision, not a
packaging one. `requires-python = ">=3.11"` has no ceiling, so uv will otherwise also resolve a python
**3.14 fork** of the optional framework extras; because those upstreams do not support 3.14 yet, the
resolver satisfies it by walking them *backwards* — pinning `instructor` 1.12 and `semantic-kernel` 1.8
and dragging in `diskcache` (CVE-2025-69872, pickle deserialization, **no fixed release exists**). None
of it is installable by anyone, nothing builds or tests it, and yet the gate scores us on it. Auditing
a dependency graph that ships nowhere is not extra rigour; it costs real attention and buys nothing.
Widen the setting when 3.13/3.14 are supported for real — tested and in `classifiers` — not before.

The first three entries below are **not in any shipped container image** — `Dockerfile.api` and
`Dockerfile.engine` install `.[spiffe]` and nothing else, and `webhook/Dockerfile` is a Go binary on
`distroless/static` with no Python at all — because they live exclusively in the **optional SDK
framework-adapter extras** (`norviq[frameworks]` / `[crewai]` / `[semantic-kernel]`), which a deployment
must explicitly opt into.

The React Router entry is different and should not be read as one of those: it **is** in a shipped image,
the console bundle built by `Dockerfile.ui`. It is carried because the vulnerable code path does not
exist in this application, not because the dependency is absent. That is a weaker form of "not
exploitable" than the other three, so it is scheduled for a real fix (see the note under the table)
rather than treated as permanently accepted.

**`cryptography>=48.0.1`** is the other such floor, and unlike `werkzeug` it *is* in the shipped image —
so it is declared in `[project] dependencies`, not in `[tool.uv] constraint-dependencies`. The images
install with **pip**, which reads neither `uv.lock` nor uv's constraints; a floor kept only in the uv
config would have left the published images on a vulnerable version while every local check looked green.
It closes **GHSA-537c-gmf6-5ccf** (HIGH, CVSS 7.5): `cryptography` wheels statically link OpenSSL, and
every wheel below 48.0.1 bundles the OpenSSL affected by the
[2026-06-09 advisory](https://openssl-library.org/news/secadv/20260609.txt). `cryptography` reaches us
transitively through `pyjwt`, `spiffe`, `azure-identity` and `pyopenssl`, so it is on the JWT-verification
and SPIFFE paths rather than in an optional extra.

Reaching that floor required declaring `spiffe` and the framework extras as **conflicting** (see
`[tool.uv] conflicts`). The old lock pinned `spiffe 0.2.x`, which caps `cryptography<47`; `spiffe>=0.3`
lifts the cap but needs `protobuf>=6.31.1`, while every `autogen-core>=0.4` needs protobuf 4.x/5.x. The
two cannot co-resolve — a property of their upstreams, not a choice. Nothing installs both: the images
take `.[spiffe]`, and `framework-compat.yml` installs one framework at a time.

| CVE | Package (source) | Why unfixable-by-bump | Why not exploitable here |
|-----|------------------|-----------------------|--------------------------|
| CVE-2026-45829 | `chromadb` (via `crewai`) | No fixed release exists — the latest version is still affected. | It is a pre-auth RCE in the **ChromaDB HTTP server**; CrewAI uses chromadb as an **embedded client**, so the vulnerable server path is never started. |
| CVE-2026-26030 | `semantic-kernel` | The fix (`>=1.39.4`) pulls a **pre-release** `azure-ai-agents` dependency, which we will not ship in a lockfile. | RCE is in the `InMemoryVectorStore` filter-lambda path, which the Norviq semantic-kernel adapter does not use. |
| CVE-2026-25592 | `semantic-kernel` | This is a **.NET** CVE (fixed in .NET Core `1.71.0`); FOSSA maps it onto the pip package, where no release clears it. | The affected `[KernelFunction] DownloadFileAsync` helper exists only in the .NET SDK, not the Python package we depend on. |
| GHSA-qwww-vcr4-c8h2 | `react-router` / `react-router-dom` (console UI) | Fixed only in **8.3.0**, which requires **React >= 19.2.7** and **Node >= 22.22.0** and drops `react-router-dom` entirely — a React 18→19 migration, not a bump. Downgrading is not an escape either: the only versions below the affected range (`>=7.12.0 <8.3.0`) are back inside the **7.17.0-and-below** range of the advisories this entry replaces. | The flaw is a CSRF bypass in **RSC mode**, letting an action execute before a 400 response. The console never enters RSC mode: [`ui/src/main.tsx`](ui/src/main.tsx) renders with `ReactDOM.createRoot` under a plain `BrowserRouter`, there is no server runtime, no `@vitejs/plugin-rsc`, no `unstable_RSC*` API in `ui/src`, and `Dockerfile.ui` builds a static bundle served by nginx. |

These are reviewed each release; we will drop an exception and bump the moment upstream ships a fixed
release reachable without a pre-release dependency.

**React Router is a scheduled fix, not a permanent exception.** The other three entries are blocked on
upstream; this one is blocked only on our own migration effort, which is a different kind of reason and
should not be allowed to age quietly into "accepted". Two things would change the calculus immediately
and should be treated as a trigger to prioritise the React 19 / router v8 migration:

- the console gaining **any** server-side rendering, prerendering, or React Server Components step,
  which would put the vulnerable path into the executed code — the reason for the exception disappears
  the moment that changes, and it is the kind of change that arrives as a performance or SEO
  improvement rather than as a security decision;
- the project moving to React 19 for an unrelated reason, which removes the migration cost entirely.

Until then the residual risk is bounded: the console is authenticated, served as static assets, and the
advisory requires an RSC request flow that no code path here produces.

> **This entry was rewritten when the router was upgraded 6.30.4 → 7.18.2**, which closed
> CVE-2026-53668 / -53669 / -53666 (`GHSA-337j-9hxr-rhxg` and the two open-redirect advisories) —
> those were the three the FOSSA gate was actually failing on, and 6.30.4 was the last 6.x, so there
> was no patch on that line. The upgrade needed **no code changes**: the console uses only
> `MemoryRouter`/`BrowserRouter`, `Routes`/`Route`, `Link`/`NavLink`, `Navigate`, `useNavigate`,
> `useLocation` and `useSearchParams` — no data-router APIs, no loaders/actions, no `json()`/`defer()`,
> and no splat routes for `v7_relativeSplatPath` to affect.
>
> A NOTE ON WHY THE GATE WENT RED ANYWAY, because it cost time: the old React Router row was written
> into this table but **never added to `ACCEPTED_CVES` in `.github/workflows/fossa.yml`**, so the gate
> kept failing on a vulnerability this document had already accepted. The two are supposed to be in
> lockstep and were not. The gate now matches **GHSA ids as well as CVE ids** — this advisory has no
> CVE assigned, so a CVE-only matcher could never have accepted it.

The three Python entries are also marked **Ignored** in the FOSSA project UI (reason: *vulnerable code
not in execute path*, scoped to this project and the current dependency versions), so FOSSA's own
"Security Analysis" check reflects this acceptance rather than a bare red. Because that ignore is
version-scoped, a future bump of `chromadb` or `semantic-kernel` re-surfaces the CVE for review —
matching the exit condition above.

**`GHSA-337j-9hxr-rhxg` is not what the "Security Analysis" badge reports, and it is worth being precise
about that, because assuming otherwise wasted real time.** `npm audit` and FOSSA do not draw from the
same advisory database, so the same lockfile yields different findings. React Router shows up in
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
