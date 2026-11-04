# Reviewing

How pull requests are reviewed today. There is one maintainer and no separate reviewer role (see
[GOVERNANCE.md](GOVERNANCE.md)), so this describes what the maintainer checks. The rules behind each
check are in [CONTRIBUTING.md](CONTRIBUTING.md).

## Who reviews

The maintainer reviews and merges once CI is green. There is no required-review gate on `main`. For
changes to enforcement, authentication or policy semantics a second reviewer is asked for; with one
maintainer it cannot be guaranteed. That changes when a second maintainer exists.

## What a review checks

- **CI is green.** The gates and what each fails on are listed in
  [CONTRIBUTING.md](CONTRIBUTING.md#ci-gates). `fossa.yml` does not run on fork pull requests, so the
  maintainer runs it after merge.
- **The claim reproduces.** A pull request that says it fixes something shows the test failing with
  the fix reverted and passing with it. A reviewer who doubts a claim asks for a reproduction rather
  than arguing about it.
- **Fail closed.** On an error in the enforcement or authentication path, the change denies, apart
  from the configured exceptions CONTRIBUTING names. New security-relevant code has a test for the
  block or deny path.
- **Tests for behaviour changes**, and no new failures against the existing suite.
- **Suppressions are justified.** A `# nosec` or `# nosemgrep` names the check and gives a reason a
  reviewer can verify.
- **Commits.** CONTRIBUTING asks for conventional-commit subjects; most commits in the history do
  not use them and no check enforces it, so a review does not hold a pull request on it. CONTRIBUTING
  also asks for a `Signed-off-by` matching the author on every commit (see [CONTRIBUTING.md](CONTRIBUTING.md#developer-certificate-of-origin));
  no check enforces it yet.

## Security reports

Never reviewed in public. Reports follow [SECURITY.md](SECURITY.md).
