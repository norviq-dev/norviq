# MCP Tooling Protocol — Serena + Memory

Two MCP servers are wired into Claude Code for this repo. Use them as the default path,
not an afterthought. Full reference: `docs/mcp-workflow.md`.

## Roles
- **Serena** = code intelligence + per-project memory (these `.serena/memories/*.md` files).
  Symbolic navigation over Python / TypeScript / Go / Rego.
- **memory** (knowledge graph, `@modelcontextprotocol/server-memory`) = durable, queryable
  facts about the system across sessions (components, features, decisions, error codes, gotchas).

## 1. Code search & navigation → Serena FIRST
Prefer Serena's symbolic tools over blind `grep`/`Read`:
- `get_symbols_overview` — a file's top-level shape before reading it whole.
- `find_symbol` — jump to a class/function/method definition.
- `find_referencing_symbols` — find all callers/usages before changing something.
- `search_for_pattern` — project-wide regex when you need text, not symbols.
- `list_dir` / `find_file` — locate files.
Fall back to `Read`/`Grep`/`Glob` only for non-code files or when the language server can't resolve.

## 2. Recall & context → query the memory graph at task start
Before researching from scratch, `search_nodes` / `open_nodes` for the feature ID, subsystem,
class, or error code you're about to touch. Read the relevant Serena memory too.

## 3. After every new feature / significant change → UPDATE BOTH (non-negotiable)
This mirrors the existing registry/architecture discipline; the memory layer is the fast index over it.
- **Serena:** `write_memory` to update the affected memory (new symbols, files, flows) — e.g.
  refresh `codebase_structure`, `architecture_and_flow`, or add a feature-specific memory.
- **memory graph:** `create_entities` for the new feature + key classes; `create_relations`
  to wire `depends_on` / `consumed_by`; `add_observations` for decisions, new NRVQ error codes,
  and gotchas. Delete/replace observations that became false.
- Keep it consistent with `registry/{FEAT}.md`, `architecture/{FEAT}.*.mmd`, `docs/error-codes.md`.
  Those files are the source of truth; if they diverge from memory, the files win — refresh memory.

## 4. Hygiene
- Memories reflect a point in time. If a memory names a file/symbol/flag, verify it still exists
  before acting on it (use Serena to confirm).
- Don't duplicate the repo's own docs into memory verbatim — store the *index/pointers* and the
  non-obvious facts (gotchas, decisions) that aren't already written down.

See also: [[task_completion_checklist]].
