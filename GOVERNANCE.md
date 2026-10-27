# Governance

This document describes how Norviq is run **today**. It is deliberately short, because the project is
deliberately small: one maintainer, no committees, no vote that has ever needed taking. A governance
document that describes a process the project does not follow is the same defect as a doc that
claims fail-closed on an audit-mode chart, and this project has shipped enough of those.

## Roles

**Maintainer** — listed in [MAINTAINERS.md](MAINTAINERS.md). Merges pull requests, cuts releases,
triages issues, holds the signing identity for release artifacts, and answers security reports. There
is one.

**Contributor** — anyone who has had a pull request merged, filed a reproducible issue, or improved
the documentation. No formal status; the git history is the record.

## How decisions are made

**Lazy consensus on the issue or pull request.** A change is proposed where it will land — an issue
for a behaviour or design question, a pull request for code — and discussed there. If nobody objects
within a reasonable window (a few days for small changes, longer for anything touching enforcement,
authentication or policy semantics), it proceeds. Silence is consent; a stated objection is not.

**The maintainer decides** where consensus does not form. With one maintainer that is every
unresolved question, and there is no appeal beyond the discussion itself. This is stated plainly
rather than dressed up as a process.

**What is not decided by discussion:** whether a control enforces what it claims to. That is decided
by reproduction. A claim that something works is not accepted on the strength of the claim — see the
house rule in [CONTRIBUTING.md](CONTRIBUTING.md) on control-testing every gate.

## How code lands

A pull request is merged by the maintainer once CI passes and the maintainer has reviewed it.
**There is currently no required-review gate on `main`**: branch protection is not enabled, and
across the project's first hundred pull requests no review has been formally submitted, including on
the maintainer's own. That is an accurate description, not an aspiration. For changes to enforcement,
authentication or policy semantics a second pair of eyes is *asked for*; it cannot yet be guaranteed,
because there is nobody to guarantee it. When a second maintainer exists this section changes and
branch protection is switched on the same day.

Commit messages say what changed and why it was wrong before. See CONTRIBUTING.md.

## Becoming a maintainer

The bar is sustained, reviewable work — not volume. Concretely, someone who over roughly three
months has:

- landed several non-trivial pull requests that were merged substantially as submitted,
- shown, in review comments or issues, that they reproduce before they assert — the discipline this
  project's own history shows it needs most,
- and is willing to hold the responsibilities above, including being reachable for security reports.

An existing maintainer nominates by opening a pull request that adds the person to
[MAINTAINERS.md](MAINTAINERS.md). Any existing maintainer may object within two weeks; absent
objection it merges. The first such nomination will, unavoidably, be a single maintainer nominating
a second — that is fine, and the pull request is the record.

## Stepping back

A maintainer who expects to be unavailable for a while says so in an issue. One who has made no
commit, review or issue comment for six months is moved to an *emeritus* line in MAINTAINERS.md by
another maintainer — or, if they are the only one, the project is at that point unmaintained and the
README should say so rather than leave the appearance of activity. Emeritus maintainers keep their
name and lose merge rights; they can return by the nomination path above.

## Conduct

Contributors are expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md). Reports go to
conduct@norviq.dev.

## Changing this document

By pull request, like anything else. Since it describes what the project actually does, changes to
it should follow changes in practice, not precede them.
