#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
set -uo pipefail

# ═══════════════════════════════════════════════════════════════════════════
# Serena staleness guard (macOS) — Review Step 0 entrypoint (see CLAUDE.md / docs/mcp-workflow.md).
#
# Because CURSOR authored the change, the Serena index + project memories are assumed BEHIND git
# HEAD. Run this BEFORE trusting any memory in review:
#   1. Reindex Serena vs HEAD (so symbolic lookups resolve against the code Cursor just wrote).
#   2. Memory health-check: for each .serena/memories/*.md, verify the file paths it references still
#      exist. Memories with DANGLING references are stale → refresh or discard before acting on them.
#
# Usage:  scripts/serena-refresh.sh [--memories-only]   (default: reindex + health-check)
# The health-check is pure git+grep and always runs. The reindex needs `uvx` (Serena); if absent it
# prints the command to run.
# ═══════════════════════════════════════════════════════════════════════════

ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
MEM_DIR=".serena/memories"
MODE="${1:-full}"

say(){ printf '\n\033[1m▶ %s\033[0m\n' "$*"; }
ok(){  printf '  \033[32m✔ %s\033[0m\n' "$*"; }
bad(){ printf '  \033[31m✗ %s\033[0m\n' "$*"; }
note(){ printf '  \033[33m• %s\033[0m\n' "$*"; }

# ─── 1. Reindex Serena vs HEAD ─────────────────────────────────────────────
reindex() {
  say "Reindex Serena vs git HEAD ($(git rev-parse --short HEAD 2>/dev/null || echo '?'))"
  if command -v uvx >/dev/null 2>&1; then
    uvx --from git+https://github.com/oraios/serena serena project index --project "$ROOT" \
      && ok "Serena project reindexed" \
      || note "serena index returned non-zero — re-run onboarding in-session if symbols don't resolve"
  else
    note "uvx/Serena not on PATH. In the Claude session, re-run onboarding or a targeted re-index."
    note "  (Serena MCP resolves symbols live; this script's value is the memory health-check below.)"
  fi
}

# ─── 2. Memory health-check: dangling file references = stale memory ────────
# Build the set of tracked repo paths once, then for each memory extract candidate paths and check.
healthcheck() {
  say "Memory health-check — do referenced files still exist post-HEAD?"
  [ -d "$MEM_DIR" ] || { bad "no $MEM_DIR"; return 1; }
  local tracked; tracked="$(git ls-files 2>/dev/null)"
  local stale_total=0

  for mem in "$MEM_DIR"/*.md; do
    [ -e "$mem" ] || continue
    # Candidate referents: things that look like real repo paths (dir/…​.ext).
    local cands missing=0 miss_list=""
    cands="$(grep -oE '[A-Za-z0-9_./-]+\.(py|tsx?|ts|rego|ya?ml|go|sh|mmd)' "$mem" 2>/dev/null \
             | sort -u | grep -vE '^https?://' || true)"
    while IFS= read -r p; do
      [ -z "$p" ] && continue
      # normalize a leading ./ ; ignore bare filenames with no dir (too ambiguous to verify)
      p="${p#./}"
      case "$p" in
        */*/*/*) continue ;;   # concatenated prose tokens (a/b/c/d) — too ambiguous, skip
      esac
      # Skip "file.ext/file.ext" prose lists: an extension immediately followed by "/" means two
      # distinct filenames got joined in prose, not a real nested path.
      case "$p" in
        *.sh/*|*.py/*|*.ts/*|*.tsx/*|*.rego/*|*.yaml/*|*.yml/*|*.go/*|*.mmd/*) continue ;;
      esac
      case "$p" in */*) : ;; *) continue ;; esac
      # Memories use shorthand relative paths (routers/evaluate.py == norviq/api/routers/evaluate.py).
      # A reference RESOLVES if any tracked file equals it OR ends with "/<p>".
      local esc; esc="$(printf '%s' "$p" | sed 's/[.[\*^$]/\\&/g')"
      if [ -e "$p" ] || printf '%s\n' "$tracked" | grep -qE "(^|/)${esc}$"; then
        :
      else
        missing=$((missing+1)); miss_list="${miss_list} ${p}"
      fi
    done <<< "$cands"

    if [ "$missing" -eq 0 ]; then
      ok "$(basename "$mem") — all referenced paths resolve"
    else
      stale_total=$((stale_total+1))
      bad "$(basename "$mem") — ${missing} dangling reference(s):${miss_list}"
    fi
  done

  echo ""
  if [ "$stale_total" -eq 0 ]; then
    ok "All memories reference live paths. (Symbols/flags still need a live Serena check in-session.)"
  else
    note "${stale_total} memory file(s) have dangling references — REFRESH or DISCARD before relying on them."
    note "Reviewer owns the write-back (CLAUDE.md Review Step N): fix the memory or delete stale observations."
  fi
  return 0
}

case "$MODE" in
  --memories-only) healthcheck ;;
  full|*)          reindex; healthcheck ;;
esac
