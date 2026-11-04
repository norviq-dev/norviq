# Roadmap

_Last updated 2026-11-04._

What is next, at the granularity the project can actually commit to. Near-term items are tracked in
issues or in `docs/design/BACKLOG.md`, where each carries its verification status — a roadmap item
that does not reproduce is refuted, not deferred. This is not a promise of dates; there is one
maintainer.

## Next release (0.2.6)

Done on the 0.2.6 candidate; most are listed under `[Unreleased]` in [CHANGELOG.md](CHANGELOG.md).
What remains is the version bump and the cut.

- **The namespace baseline blocks by default** (`baselineClusterPolicy.enforcementMode: block`), and
  a class policy can no longer loosen it. Read the CHANGELOG's upgrade impact before upgrading.
- **Every third-party image is pinned by digest by default** (`global.thirdPartyImageDigests`; an
  overridden tag renders without a pin), and `global.imageRegistry` now relocates the busybox init
  image, so air-gapped installs no longer stall in `Init:0/2`.
- **The `existingSecret` wait behaviour is decided.** With `existingSecret` and no `host` the chart
  renders no wait container; the api and the embedded engine now retry Postgres and Redis at startup
  (5 attempts over about 15 s) and then fail, and the docs say so.
- **Security fixes.** Their advisories publish with the release.

The four items this section listed before (busybox relocation, the `deny_shell_execution` caveat,
the stdio pin-store warning, a chart-defaults fix) have all landed and ship in 0.2.6.

## Near term

- **Required-review gate on `main`**, the day a second maintainer exists — see `GOVERNANCE.md`.
- **Opt-in telemetry** — version and cluster count only, default-off, documented. "Clusters actually
  running Norviq" is the metric that matters and is currently unmeasurable. Design first; not built.

## Security lane

A dependency chain, in order:

1. [#4](https://github.com/norviq-dev/norviq/issues/4) — policy/rego content propagation to running
   clusters (the re-seed path; closes the F-02 homoglyph gap on AKS).
2. [#79](https://github.com/norviq-dev/norviq/issues/79) — repo rego has no propagation path to a
   manually seeded policy; the real remainder of #4.
3. [#80](https://github.com/norviq-dev/norviq/issues/80) — close the attested-namespace residual in
   workload-api mode via the internal mTLS peer certificate.

## Longer

- **CNCF Sandbox.** Norviq intends to apply once the repository is six months old (created
  2026-05-28). Governance files, prose-parity tests, lint and audit gates that can fail, and a
  licensing inventory are what make an application creditable. They do not make one eligible sooner.
- **OpenSSF Best Practices badge.** Not registered yet.
- **A security self-assessment** against the CNCF TAG Security abbreviated template, written from
  the code at the moment of writing and published in the repo regardless of what any foundation does
  with it.

## Not planned

- Rewriting git history to add DCO sign-off to existing commits. Over 700 commits, 17 release tags
  and published references cite current SHAs; the DCO applies from the day the DCO check is enabled.
