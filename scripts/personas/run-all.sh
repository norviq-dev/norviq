#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
#
# Run the four industry personas and aggregate their findings.
#
# SEQUENTIALLY, AND THAT IS A FINDING, NOT A LIMITATION OF THIS SCRIPT. The console has exactly one
# admin identity (`auth_admin_username`), resettable only by an in-pod CLI — there is no endpoint that
# creates a second operator. So "each persona sets its own password" can only be true one persona at a
# time: persona N takes ownership of the credential, does its work, and hands the console to N+1.
# Four teams in one company cannot hold their own console logins today. That is recorded as a
# feature-request in the aggregate report rather than worked around silently here.
#
# Usage:
#   GROQ_API_KEY=... bash scripts/personas/run-all.sh
#   GROQ_API_KEY=... bash scripts/personas/run-all.sh healthcare fintech

set -uo pipefail        # NOT -e: a persona that dies must not abort the other three. Its report is
                        # the deliverable, and a crashed persona is itself a finding.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BASE_URL="${NRVQ_BASE_URL:-http://localhost:3400}"
KUBE_CTX="${NRVQ_KUBE_CONTEXT:-kind-norviq-local}"
OUT_DIR="${NRVQ_PERSONA_OUT:-/tmp/persona-out}"
PERSONAS=("$@")
[ ${#PERSONAS[@]} -eq 0 ] && PERSONAS=(healthcare fintech ecommerce legal)

[ -n "${GROQ_API_KEY:-}" ] || { echo "GROQ_API_KEY not set" >&2; exit 2; }
mkdir -p "$OUT_DIR"

echo "personas: ${PERSONAS[*]}"
echo "console:  ${BASE_URL}   context: ${KUBE_CTX}"

rc=0
for p in "${PERSONAS[@]}"; do
  "${REPO_ROOT}/.venv/bin/python" "${REPO_ROOT}/scripts/personas/persona.py" \
    --industry "$p" --base-url "$BASE_URL" --kube-context "$KUBE_CTX" \
    --out "${OUT_DIR}/${p}.json"
  # A persona exits 0 even when it finds blockers — it reports, it does not gate. A NONZERO exit means
  # the persona itself crashed, which is a different and worse thing, so it is surfaced separately.
  [ $? -ne 0 ] && { echo "  !! persona ${p} CRASHED (not a finding — a harness failure)"; rc=1; }
done

echo
echo "=============================== AGGREGATE ==============================="
"${REPO_ROOT}/.venv/bin/python" "${REPO_ROOT}/scripts/personas/report.py" "$OUT_DIR"
agg=$?
exit $(( rc || agg ))
