# MCP Tooling Protocol — Serena + Memory

Two MCP servers are wired into Claude Code for this repo. They are not optional helpers — they are
the **default** path for code search and for cross-session recall. This document is the full
reference; the short, always-loaded version lives in `CLAUDE.md`, and a Serena-side copy lives in
`.serena/memories/mcp_workflow.md`.

## The two servers

| Server | What it is | Use it for |
|--------|-----------|------------|
| **serena** | Code-intelligence toolkit (language servers for Python / TypeScript / Go / Rego) **+** per-project memory files under `.serena/memories/`. | Navigating and understanding code by symbol; reading the curated project memories. |
| **memory** | `@modelcontextprotocol/server-memory` — a persistent knowledge graph (entities + relations + observations) stored at `.mcp-memory/memory.json`. | Durable, queryable facts about the system that survive across sessions and tasks. |

Both are registered as **local (project-scoped)** stdio servers in `~/.claude.json` for this
directory. After adding/changing them you must restart Claude Code (or re-run `/mcp`) for the tools
to appear in-session.

## Rule 1 — Code search & navigation: Serena first

When you need to find or understand code, reach for Serena's symbolic tools **before** blind
`grep`/`Read`. They resolve real definitions and references instead of guessing from text.

| Need | Serena tool |
|------|-------------|
| A file's top-level shape before reading it | `get_symbols_overview` |
| Jump to a class / function / method definition | `find_symbol` |
| Every caller / usage of a symbol (impact analysis before editing) | `find_referencing_symbols` |
| Project-wide regex when you need text, not symbols | `search_for_pattern` |
| Locate files / browse dirs | `find_file`, `list_dir` |
| Surgical edits by symbol | `replace_symbol_body`, `insert_after_symbol`, `insert_before_symbol` |

Fall back to the built-in `Read` / `Grep` / `Glob` only for non-code files (Markdown, YAML, Rego
data, `.env`) or when the language server can't resolve a symbol.

## Review Step 0 — freshness (staleness guard, ENFORCED; reviewer-owned)

In the dual-tool workflow (Cursor authors, Claude reviews — see `docs/WORKFLOW.md`), the code under
review was just written by **Cursor**, so the Serena index and the project memories are assumed
**BEHIND git HEAD**. Before the reviewer trusts any memory, it MUST:

1. **Reindex / confirm freshness vs HEAD** — run `scripts/serena-refresh.sh` (reindex + memory
   health-check). This re-resolves symbols against the code Cursor just wrote, not a stale index.
2. **Memory health-check** — for each memory it will rely on, confirm the named symbols / files /
   flags still resolve (the script checks file references; verify live symbols via Serena
   `find_symbol`). Any dangling memory → **refresh or discard BEFORE acting on it.** Never quote a
   memory whose referents no longer exist.

`scripts/serena-refresh.sh --memories-only` runs just the health-check (pure git+grep, no Serena
binary needed). This is the enforced counterpart to Rule 4 ("memories are point-in-time").

## Rule 2 — Recall & context: query the memory graph at task start

Before researching a subsystem from scratch, query the knowledge graph for what's already known:
- `search_nodes("<feature id | subsystem | class | error code>")`
- `open_nodes([...])` to expand specific entities and their relations.
- Also `read_memory` the relevant Serena memory (`project_overview`, `codebase_structure`,
  `architecture_and_flow`, `dev_setup_and_run`, `conventions_and_review`).

This avoids re-deriving facts that are already captured and keeps you aligned with prior decisions.

## Rule 3 — After every new feature or significant change: update BOTH (required)

This is the same discipline the repo already enforces with `registry/` and `architecture/`; the MCP
memory layer is the fast, queryable index over those artifacts. When a feature lands:

**Serena memories**
- `write_memory` to refresh the affected memory: new symbols/files/flows go into
  `codebase_structure` and `architecture_and_flow`, or add a dedicated `feature_F0xx.md` memory.

**Memory graph**
- `create_entities` for the new feature and its key classes (entityType `feature` / `class` / `subsystem`).
- `create_relations` to wire it up: `depends_on`, `uses`, `consumed_by`, `part_of`.
- `add_observations` for design decisions, new `NRVQ-XXX-NNNN` error codes, and any gotchas.
- Delete or replace observations that became false (`delete_observations`, `delete_entities`).

The completion checklist in `.serena/memories/task_completion_checklist.md` includes these steps —
work through it before reporting a feature done.

### Review Step N — write-back is REVIEWER-owned
In the dual-tool workflow the write-back above is done by the **REVIEWER (Claude)** on PASS, not by
the author. The author (Cursor) never writes Serena memory, the graph, `_bug-catalog.md`, or
`bug-patterns.md`. On a passing review the reviewer also appends each finding to
`tests/.history/_bug-catalog.md` and promotes durable ones to `docs/engineering/bug-patterns.md`
(the learning loop — see `docs/WORKFLOW.md` Part F), and **deletes observations that became false**.

## Rule 4 — Source of truth & hygiene

- The repo's own files are authoritative: `registry/{FEAT}.md`, `architecture/{FEAT}.*.mmd`,
  `docs/error-codes.md`, `specs/{FEAT}.md`. If memory diverges from them, **the files win** —
  refresh the memory.
- Memories are point-in-time. If a memory names a file, symbol, or flag, confirm it still exists
  (via Serena) before acting on it.
- Store pointers and non-obvious facts (gotchas, decisions), not verbatim copies of existing docs.

## Quick reference — re-add the servers

```bash
# Serena (code intelligence + project memory), rooted at repo/
claude mcp add serena -- uvx --from git+https://github.com/oraios/serena \
  serena start-mcp-server --context ide-assistant \
  --project /Users/san/Documents/Development/norviq/norviq-migration/repo

# Memory knowledge graph, persisted to a stable file
claude mcp add memory -e MEMORY_FILE_PATH=/Users/san/Documents/Development/norviq/norviq-migration/.mcp-memory/memory.json \
  -- npx -y @modelcontextprotocol/server-memory

claude mcp list   # both should report ✓ Connected
```

Seeded state shipped with the repo: Serena memories in `.serena/memories/` and an initial knowledge
graph in `.mcp-memory/memory.json` (core components, subsystems, dependencies, and the
known gotchas). Extend them as the system evolves.
