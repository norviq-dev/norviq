<!-- Security fixes do not go in a public pull request. See SECURITY.md. -->

**What this changes and why**

**How it was tested**

<!-- For a fix or a new check: show that the test fails with the change reverted and passes with it
(CONTRIBUTING.md, "Control-test every check"). -->

**Checklist**

- [ ] Every commit is signed off (`git commit -s`), as described in CONTRIBUTING.md, "Developer
      Certificate of Origin".
- [ ] The commit subject follows the conventional-commit form, for example `fix(helm): …`.
- [ ] Tests cover the behaviour change, and the checks in CONTRIBUTING.md, "Running the checks", pass.
- [ ] Docs, `CHANGELOG.md` and the Helm chart README are updated where the change affects them.
- [ ] New Python, Go and workflow files start with `# SPDX-License-Identifier: Apache-2.0`.
