# Norviq Prompt Archive

Record of significant Claude prompts driving Norviq development — for
reproducibility and engineering-process documentation (NIW/CNCF evidence).

Each prompt file contains: prompt text, outcome (commit SHA, result), date.

## Index

| Date | File | Work item | Commit | Result |
|------|------|-----------|--------|--------|
| 2026-06-15 | [P0-D-namespace-scoping.md](P0-D-namespace-scoping.md) | P0-D namespace scoping (agents + policies-list) | `96d060e` | Done — agents+policies ns-scoped; verified local + AKS (policies 1/0/0, agents 1/1/0); 66/66 held |

## Convention
- One file per significant work item (P0/P1 fix, feature, major diagnosis)
- Filename: {item-id}-{short-name}.md
- Include: prompt text, outcome summary, commit SHA, date
- Update the index table when adding a file
