# Governance

This document describes how Norviq is run **today**. It is deliberately short, because the project is
deliberately small: one maintainer, no committees, no vote that has ever needed taking. A governance
document that describes a process the project does not follow is the same defect as a doc that
claims fail-closed on an audit-mode chart, and this project has shipped enough of those.

## Scope

Norviq is a policy enforcement point for LLM agent tool calls on Kubernetes: an engine and API that
evaluate each call against OPA/Rego policy for the workload's identity, an admission webhook that
injects the sidecar, an SDK, a console, an MCP proxy and a Helm chart. The components and the
adversaries the project defends against are listed in [SECURITY.md](SECURITY.md) and
[docs/security-model.md](docs/security-model.md); a change that widens either is decided the way
any other change is, below.

## Values

- **Fail closed.** On an error in the enforcement or authentication path, deny. The configured
  exceptions are named in [CONTRIBUTING.md](CONTRIBUTING.md).
- **Reproduce before asserting.** A claim that a control works is accepted when it reproduces, with a
  control that shows the check can fail.
- **Documents describe what the code does today.** This one included.

## Roles

**Maintainer** — listed in [MAINTAINERS.md](MAINTAINERS.md). Merges pull requests, cuts releases,
triages issues, holds the signing identity for release artifacts, and answers security reports. There
is one.

**Contributor** — anyone who has had a pull request merged, filed a reproducible issue, or improved
the documentation. No formal status; the git history is the record.

There is no separate reviewer role. Review is done by the maintainer; what a review checks is in
[REVIEWING.md](REVIEWING.md).

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
house rule in [CONTRIBUTING.md](CONTRIBUTING.md) on control-testing every check.

**Design proposals** start as an issue, as CONTRIBUTING.md asks for anything non-trivial, and are
discussed there before code is written. There is no separate proposal document or template.

## How code lands

A pull request is merged by the maintainer once CI passes and the maintainer has reviewed it.
**There is currently no required-review gate on `main`**: branch protection is not enabled, and
across the project's first hundred pull requests no review has been formally submitted, including on
the maintainer's own. That is an accurate description, not an aspiration. For changes to enforcement,
authentication or policy semantics a second pair of eyes is *asked for*; it cannot yet be guaranteed,
because there is nobody to guarantee it. When a second maintainer exists this section changes and
branch protection is switched on the same day.

Commit messages say what changed and why it was wrong before. See CONTRIBUTING.md.

## Releases

The maintainer cuts releases. How, and what a release publishes, is in [RELEASES.md](RELEASES.md).

## Security response

Vulnerability reports follow [SECURITY.md](SECURITY.md). The maintainer receives them, assesses
them, prepares the fix and publishes the advisory. There is no second responder today, so a report
depends on one person being available. SECURITY.md states the response times.

## Meetings

None are held. Discussion happens in issues, pull requests and
[GitHub Discussions](https://github.com/norviq-dev/norviq/discussions), where it stays on the record.

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
commit, review or issue comment for six months is moved to the *Emeritus maintainers* section of
MAINTAINERS.md by another maintainer — or, if they are the only one, the project is at that point
unmaintained and the README should say so rather than leave the appearance of activity. Emeritus
maintainers keep their name and lose merge rights; they can return by the nomination path above.

## Conduct

Norviq follows the [CNCF Code of Conduct](https://github.com/cncf/foundation/blob/main/code-of-conduct.md);
see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Reports go to conduct@norviq.dev, which reaches the
maintainer. Norviq is not a CNCF project; if and when it is accepted, reports can also go to the CNCF
Code of Conduct Committee at conduct@cncf.io. There is no contact outside the project yet for a report
that concerns the maintainer.

## Changing this document

By pull request, like anything else. Since it describes what the project actually does, changes to
it should follow changes in practice, not precede them.
