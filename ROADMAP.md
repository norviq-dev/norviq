# Roadmap

What is next, at the granularity the project can actually commit to. Near-term items are tracked in
issues or in `docs/design/BACKLOG.md`, where each carries its verification status — a roadmap item
that does not reproduce is refuted, not deferred. This is not a promise of dates; there is one
maintainer.

## Next release (0.2.6)

- **`busybox:1.36` is not relocatable.** `global.imageRegistry` moves every third-party image except
  the dependency-wait initContainers, so air-gapped installs sit in `Init:0/2`. Verified with a
  control. The helper fix and the release are one unit: a fix on `main` that no published chart
  carries changes nothing for anyone installing.
- **The `deny_shell_execution` caveat** the console serves describes a false-positive rate fixed in
  0.2.1 as if current. Landed; ships with the cut.
- **The stdio MCP proxy degraded its pin store in silence** on the path the quickstart recommends.
  Fixed; ships with the cut.
- **Two security booleans fell back to OFF in the chart** for any overlay that nulled the key, while
  the code defaults them ON. Fixed; ships with the cut.

## Near term

- **Decide the `existingSecret` wait-container behaviour.** External datastores configured by Secret
  only render no dependency gate for api/engine (measured: 5 busybox refs bundled, 1 external).
  Either intended — the app retries — or `existingSecret` grows an optional `host`. The docs are held
  until that is decided rather than reworded twice.
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

- **CNCF Sandbox.** The repository is age-blocked until late November 2026 (created 2026-05-28;
  Sandbox requires six months). Governance files, prose-parity tests, lint and audit gates that can
  fail, and a licensing inventory are what make an application creditable then. They do not make
  one eligible sooner.
- **A security self-assessment** against the CNCF TAG Security abbreviated template, written from
  the code at the moment of writing and published in the repo regardless of what any foundation does
  with it.

## Not planned

- Rewriting git history to add DCO sign-off to existing commits. 529 commits, 18 tags and published
  references cite current SHAs; the DCO applies from a stated date forward.
