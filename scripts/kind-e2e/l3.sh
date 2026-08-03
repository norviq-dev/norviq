#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
#
# L3 — the API/middleware layer, run against the LIVE kind cluster.
#
# `tests/integration` (18 files) and `tests/attacks` (13 files) are excluded from the PR gate because
# they need a running cluster. Excluded is fine; excluded and never run anywhere is not — these are
# the only tests that exercise the real evaluate path, the real Postgres and the real Redis.
#
# ⚠ THE TRAP THIS SCRIPT EXISTS TO CLOSE. `tests/attacks/conftest.py` calls `pytest.xfail(...)` when
# the API is unreachable, and `tests/integration/conftest.py` calls `pytest.skip(...)`. Both make
# pytest EXIT 0. A run against a dead backend therefore prints "31 xfailed, 42 skipped" and returns
# success — indistinguishable from a green run to any CI that only checks the exit code, and the
# failure mode is silent: the suite that proves enforcement works reports that it worked without
# having asked anything.
#
# So this script asserts a NONZERO passed count per suite, and fails loudly if a suite passed nothing.
#
# Usage:
#   scripts/kind-e2e/l3.sh                    # port-forwards, runs both suites, tears down
#   NRVQ_API_URL=... scripts/kind-e2e/l3.sh   # against an already-reachable API

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NS="${NRVQ_NAMESPACE:-norviq}"
PY="${REPO_ROOT}/.venv/bin/python"

# Minimum PASSED tests per suite. Not a coverage target — a tripwire, and the thresholds are set from
# MEASURED numbers rather than guessed:
#
#            live cluster   dead API
#   integration      63          11    <- 11 tests need no backend at all
#   attacks          99           0
#
# So a threshold of 5 would have caught a dead API for `attacks` and MISSED it entirely for
# `integration`. These sit between the two observed values. If a legitimate change moves them, the
# failure message says exactly what to check — which is the behaviour wanted from a tripwire.
MIN_INTEGRATION="${MIN_INTEGRATION:-40}"
MIN_ATTACKS="${MIN_ATTACKS:-50}"

PIDS=()
cleanup() {
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT

stage() { printf '\n\033[1;36m▶ %s\033[0m\n' "$*"; }
fail()  { printf '\033[1;31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

# --- preconditions ------------------------------------------------------------------------------
stage "Preconditions"
[ -x "$PY" ] || fail "no venv at $PY — the repo venv lives at the REPO ROOT, not in ui/"
# opa on PATH is not optional: without it the rego-backed tests SKIP, and a skip reads as a pass.
command -v opa >/dev/null || fail "opa not on PATH — rego-backed tests would silently skip and the suite would print green"
echo "  opa   $(opa version | head -1)"
echo "  python $("$PY" --version)"

# --- port-forwards ------------------------------------------------------------------------------
if [ -z "${NRVQ_API_URL:-}" ]; then
  stage "Port-forwarding the cluster"
  kubectl -n "$NS" port-forward svc/norviq-api 18080:8080 >/tmp/nrvq-l3-api.log 2>&1 &
  PIDS+=($!)
  kubectl -n "$NS" port-forward svc/norviq-postgresql 15432:5432 >/tmp/nrvq-l3-pg.log 2>&1 &
  PIDS+=($!)
  kubectl -n "$NS" port-forward svc/norviq-redis 16379:6379 >/tmp/nrvq-l3-redis.log 2>&1 &
  PIDS+=($!)
  export NRVQ_API_URL="http://127.0.0.1:18080"
  export NRVQ_PG_URL="${NRVQ_PG_URL:-postgresql://norviq:norviq@127.0.0.1:15432/norviq}"
  export NRVQ_REDIS_URL="${NRVQ_REDIS_URL:-redis://127.0.0.1:16379/0}"

  # Poll, never sleep-once: a forward that is not up yet is indistinguishable from a dead API, and
  # THAT is exactly the state the xfail turns into a false green.
  for _ in $(seq 1 40); do
    curl -sf -o /dev/null "${NRVQ_API_URL}/healthz" && break
    sleep 0.5
  done
  curl -sf -o /dev/null "${NRVQ_API_URL}/healthz" \
    || fail "API never became reachable at ${NRVQ_API_URL} — see /tmp/nrvq-l3-api.log"
  echo "  api   ${NRVQ_API_URL} healthy"
fi

# The API's OWN signing key. `tests/integration/test_auth_hardening.py` mints a viewer token to prove
# an authenticated non-admin gets 403; signed with this process's local default instead, the API
# rejects it at the signature with 401 and the authorization check under test is never reached.
if [ -z "${NRVQ_JWT_SECRET:-}" ]; then
  NRVQ_JWT_SECRET="$(kubectl -n "$NS" get secret norviq-secrets \
    -o go-template='{{index .data "NRVQ_API_SECRET_KEY" | base64decode}}' 2>/dev/null || true)"
  [ -n "$NRVQ_JWT_SECRET" ] && export NRVQ_JWT_SECRET
fi

# The attack suite needs an admin token; mint one from the running pod if we were not given one.
if [ -z "${NRVQ_API_TOKEN:-}" ]; then
  if [ -r /tmp/nrvq-signin-token.txt ]; then
    NRVQ_API_TOKEN="$(cat /tmp/nrvq-signin-token.txt)"
  else
    api_pod="$(kubectl -n "$NS" get pods -o name | grep api | head -1)"
    NRVQ_API_TOKEN="$(kubectl -n "$NS" exec "${api_pod#pod/}" -c api -- python -m norviq.api.token_mint --ttl 7200 | tail -1)"
  fi
  export NRVQ_API_TOKEN
fi

# --- run, and MEASURE ----------------------------------------------------------------------------
# Counts come from a JUnit XML rather than from grepping the terminal summary: the summary line's
# wording varies between pytest versions, and a parser that silently matches nothing would reintroduce
# the very failure this script exists to prevent.
run_suite() {
  local name="$1" path="$2" minimum="$3"
  local xml="/tmp/nrvq-l3-${name}.xml"
  stage "L3 · ${name}"
  set +e
  "$PY" -m pytest "$path" -q --junit-xml="$xml" --override-ini=addopts=
  local status=$?
  set -e

  [ -f "$xml" ] || fail "${name}: pytest produced no report at ${xml}"

  # The guard's own exit code MUST be captured. `set -e` is suppressed throughout a function whose
  # result is consumed by `|| rc=$?` at the call site, so an unchecked `"$PY" - ...` here prints the
  # failure and returns 0 — this script committing the exact defect it exists to catch. Caught by
  # running it against a dead API and reading the exit code instead of the message.
  set +e
  "$PY" - "$xml" "$minimum" "$name" <<'PYEOF'
import sys, xml.etree.ElementTree as ET
xml, minimum, name = sys.argv[1], int(sys.argv[2]), sys.argv[3]
suite = ET.parse(xml).getroot()
if suite.tag == "testsuites":
    suite = suite[0]
total = int(suite.get("tests", 0))
failures = int(suite.get("failures", 0)) + int(suite.get("errors", 0))
skipped = int(suite.get("skipped", 0))   # pytest counts xfail here too
passed = total - failures - skipped
print(f"  {name}: {passed} passed · {skipped} skipped/xfailed · {failures} failed (of {total})")
if failures:
    sys.exit(f"✗ {name}: {failures} genuine failures")
if passed < minimum:
    # THE POINT OF THIS SCRIPT. Every test skipping or xfailing exits 0 and prints a green-looking
    # summary; only the passed count can tell a healthy backend from an absent one.
    sys.exit(
        f"✗ {name}: only {passed} tests actually PASSED (expected >= {minimum}).\n"
        f"  {skipped} were skipped or xfailed — against a dead API that is what a 'green' run looks like.\n"
        f"  Check the API/Postgres/Redis are reachable rather than trusting the exit code."
    )
PYEOF
  local guard=$?
  set -e
  [ "$guard" -ne 0 ] && return "$guard"
  return $status
}

rc=0
run_suite integration "${REPO_ROOT}/tests/integration" "$MIN_INTEGRATION" || rc=$?
run_suite attacks "${REPO_ROOT}/tests/attacks" "$MIN_ATTACKS" || rc=$?

stage "L3 complete"
exit "$rc"
