#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
#
# The machine-checkable form of docs/design/EXIT-STATE.md. One gate per section, same letters.
#
# WHY THIS EXISTS RATHER THAN A CHECKLIST. Every gate here can pass VACUOUSLY — a collection error
# exits 0 with zero tests, `pytest.skip` and `pytest.xfail` both exit 0, a chaos scenario that cannot
# inject its fault reports "nothing broke", and a persona that never reached the product files no
# findings. So no gate below is satisfied by an exit code alone: each one asserts a floor on the work
# actually done. That is the whole design.
#
#   NRVQ_KUBE_CONTEXT=kind-norviq-local bash scripts/kind-e2e/exit-state.sh
#   bash scripts/kind-e2e/exit-state.sh --only G1,G7      # a subset
#
# Exit 0 only when every selected gate is MET. Anything else is a release blocker.

set -uo pipefail        # NOT -e: every gate must run so the report is complete. A gate that fails
                        # must not hide the state of the ones after it.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PY="${REPO_ROOT}/.venv/bin/python"
KUBE_CTX="${NRVQ_KUBE_CONTEXT:-kind-norviq-local}"
BASE_URL="${NRVQ_BASE_URL:-http://localhost:3400}"
PERSONA_OUT="${NRVQ_PERSONA_OUT:-/tmp/persona-out}"
ONLY="all"
[ "${1:-}" = "--only" ] && ONLY="${2:-all}"

RESULTS=()
FAILED=0

stage() { printf '\n\033[1;36m▶ %s\033[0m\n' "$*"; }
met()   { printf '\033[1;32m  ✓ %s\033[0m\n' "$*"; RESULTS+=("MET      $*"); }
unmet() { printf '\033[1;31m  ✗ %s\033[0m\n' "$*"; RESULTS+=("NOT MET  $*"); FAILED=1; }

selected() {
  [ "$ONLY" = "all" ] && return 0
  case ",${ONLY}," in *",$1,"*) return 0 ;; *) return 1 ;; esac
}

# --- G1 · hermetic gates ---------------------------------------------------------------------------
g1() {
  stage "G1 · Hermetic gates"
  command -v opa >/dev/null || { unmet "G1: opa not on PATH — rego-backed tests would silently skip"; return; }

  local out passed
  out="$("$PY" -m pytest "${REPO_ROOT}/tests" --ignore="${REPO_ROOT}/tests/integration" \
        --ignore="${REPO_ROOT}/tests/attacks" -q 2>&1 | tail -3)"
  passed="$(echo "$out" | grep -oE '[0-9]+ passed' | head -1 | grep -oE '[0-9]+')"
  if echo "$out" | grep -q "failed\|error"; then
    unmet "G1 pytest: failures present — ${out##*$'\n'}"
  elif [ "${passed:-0}" -lt 1900 ]; then
    # The floor, not the exit code: a collection error exits 0 having run nothing.
    unmet "G1 pytest: only ${passed:-0} passed (floor 1900) — a collection error exits 0 with 0 tests"
  else
    met "G1 pytest: ${passed} passed"
  fi

  out="$(cd "${REPO_ROOT}/ui" && npx vitest run 2>&1 | tail -6)"
  passed="$(echo "$out" | grep -oE 'Tests +[0-9]+ passed' | grep -oE '[0-9]+' | head -1)"
  if echo "$out" | grep -qE '[0-9]+ failed'; then
    unmet "G1 vitest: failures present"
  elif [ "${passed:-0}" -lt 750 ]; then
    unmet "G1 vitest: only ${passed:-0} passed (floor 750)"
  else
    met "G1 vitest: ${passed} passed"
  fi

  (cd "${REPO_ROOT}/ui" && npx tsc --noEmit >/dev/null 2>&1) \
    && met "G1 tsc: clean" || unmet "G1 tsc: type errors"
  (cd "${REPO_ROOT}/ui" && npx eslint src --max-warnings=0 >/dev/null 2>&1) \
    && met "G1 eslint: clean" || unmet "G1 eslint: warnings or errors"
  (cd "${REPO_ROOT}/ui" && npm run build >/dev/null 2>&1) \
    && met "G1 build: succeeds" || unmet "G1 build: failed"
}

# --- G2 · cluster suites ---------------------------------------------------------------------------
g2() {
  stage "G2 · Cluster suites (L3)"
  local log; log="$(mktemp)"
  NRVQ_KUBE_CONTEXT="$KUBE_CTX" bash "${REPO_ROOT}/scripts/kind-e2e/l3.sh" >"$log" 2>&1
  local rc=$?
  local integ attacks xf
  integ="$(grep -oE 'integration: [0-9]+ passed' "$log" | grep -oE '[0-9]+')"
  attacks="$(grep -oE 'attacks: [0-9]+ passed' "$log" | grep -oE '[0-9]+')"
  xf="$(grep -oE 'attacks: [0-9]+ passed · [0-9]+ skipped' "$log" | grep -oE '· [0-9]+' | grep -oE '[0-9]+')"

  [ "$rc" -eq 0 ] || unmet "G2 l3.sh exited ${rc} — see ${log}"
  if [ "${integ:-0}" -lt 40 ]; then
    unmet "G2 integration: only ${integ:-0} passed (floor 40) — conftest skips into exit 0 on a dead API"
  else
    met "G2 integration: ${integ} passed"
  fi
  if [ "${attacks:-0}" -lt 50 ]; then
    unmet "G2 attacks: only ${attacks:-0} passed (floor 50)"
  else
    met "G2 attacks: ${attacks} passed"
  fi
  # The xfail bar is ZERO, not "few". Two security tests xfailed silently for the life of the project
  # because the suite had no Redis credential; xfail renders as "expected failure", i.e. green.
  if [ "${xf:-1}" -ne 0 ]; then
    unmet "G2 attacks: ${xf} xfailed — every xfail is a control that was NOT exercised"
  else
    met "G2 attacks: 0 xfailed"
  fi
}

# --- G3 · browser suite ----------------------------------------------------------------------------
g3() {
  stage "G3 · Browser suite (L4)"
  local log; log="$(mktemp)"
  # DELEGATE to scripts/e2e.sh. This used to invoke playwright directly and reported 4 failures against
  # a tree that runs 0 twice back to back — because calling playwright straight skips everything e2e.sh
  # does first: exporting NRVQ_API_URL (four specs otherwise hit an unforwarded 127.0.0.1:18080),
  # resetting and re-seeding, verifying the admin token is still live, clearing the login lockout and
  # the rate-limit buckets, and running the login gate when the supplied password is rejected.
  #
  # e2e.sh carries a comment saying exactly this, and the checker written to enforce the gate ignored
  # it — producing the one thing a gate must never produce: a failure that belongs to the harness and
  # reads as a failure of the product.
  #
  # NRVQ_E2E_PASSWORD is deliberately NOT forced here. e2e.sh verifies whatever it is given and falls
  # back to the login gate; pinning a stale literal is what silently disabled that gate before.
  NRVQ_KUBE_CONTEXT="$KUBE_CTX" NRVQ_BASE_URL="$BASE_URL" \
    bash "${REPO_ROOT}/scripts/e2e.sh" >"$log" 2>&1
  local rc=$?
  local failed notrun passed
  # Playwright prints NO "N failed" line when there are none, so a missing value means ZERO — this
  # defaulted it to 1 and reported "? failed" against a run of 183 passed and nothing failed. A gate
  # that reads the absence of bad news as bad news is as useless as one that reads it as good news.
  #
  # Absence is only safe to read as zero because the two guards below make a CRASHED run
  # distinguishable from a clean one: e2e.sh must have exited 0, and the passed count must clear its
  # floor. A run that died before reporting has neither.
  failed="$(grep -oE '^ *[0-9]+ failed' "$log" | grep -oE '[0-9]+' | head -1)"
  notrun="$(grep -oE '^ *[0-9]+ did not run' "$log" | grep -oE '[0-9]+' | head -1)"
  passed="$(grep -oE '^ *[0-9]+ passed' "$log" | grep -oE '[0-9]+' | head -1)"
  if [ "$rc" -ne 0 ] && [ -z "$passed" ]; then
    unmet "G3 browser: e2e.sh exited ${rc} without a summary — the suite never reported. ${log}"
  elif [ "${failed:-0}" -ne 0 ] || [ "${notrun:-0}" -ne 0 ]; then
    unmet "G3 browser: ${failed:-0} failed, ${notrun:-0} did not run (${passed:-0} passed) — ${log}"
  elif [ "${passed:-0}" -lt 140 ]; then
    unmet "G3 browser: only ${passed:-0} passed (floor 140) — a config error runs almost nothing"
  else
    met "G3 browser: ${passed} passed, 0 failed, 0 did not run"
  fi
}

# --- G4 · latency ----------------------------------------------------------------------------------
g4() {
  stage "G4 · Enforcement latency and capacity"
  # IN-CLUSTER. A port-forward adds a uniform hop that reads as product latency, and the numbers it
  # produces describe the laptop's network, not the enforcement path.
  local pod
  pod="$(kubectl --context "$KUBE_CTX" -n norviq get pods -l app.kubernetes.io/component=api \
    -o jsonpath='{range .items[*]}{.metadata.name}|{.metadata.deletionTimestamp}|{.status.phase}{"\n"}{end}' \
    | awk -F'|' '$2 == "" && $3 == "Running" { print $1; exit }')"
  [ -n "$pod" ] || { unmet "G4: no Running api pod to measure inside"; return; }

  kubectl --context "$KUBE_CTX" -n norviq cp "${REPO_ROOT}/scripts/kind-e2e/latency.py" \
    "${pod}:/tmp/latency.py" -c api >/dev/null 2>&1
  kubectl --context "$KUBE_CTX" -n norviq exec "$pod" -c api -- \
    sh -c 'python -m norviq.api.token_mint --ttl 3600 2>/dev/null | tail -1 > /tmp/tok.txt' >/dev/null 2>&1

  local log; log="$(mktemp)"
  kubectl --context "$KUBE_CTX" -n norviq exec "$pod" -c api -- python /tmp/latency.py \
    --base-url http://127.0.0.1:8080 --token-file /tmp/tok.txt --n 200 --concurrency 8 >"$log" 2>&1
  local rc=$?
  if [ "$rc" -eq 0 ]; then
    met "G4 @ concurrency 8: within budget and decided correctly"
  else
    # Report p50 next to the breach. The budget is on p95, but p95 alone cannot distinguish "the
    # enforcement path got slower" from "this host was busy" — and on a contended machine those look
    # identical in the summary while being opposite conclusions. A real regression moves p50 too, and
    # breaches the SAME scenario every run. Host contention leaves p50 flat and the breach wanders
    # between scenarios from run to run. Measured here: three consecutive runs of identical code
    # breached sql-injection, then benign, then nothing, with p50 steady at ~200ms throughout.
    # Do NOT raise the budget to make this green. Re-run on a quiet host, or measure p50.
    # Only the scenario table rows: seven columns whose second is the p50 number. Without the numeric
    # test this also scrapes the '✗ benign: p95 ...' lines and the cold-call footer, and the diagnostic
    # meant to make the summary readable makes it worse.
    local p50s; p50s="$(awk 'NF==7 && $2 ~ /^[0-9]+\.?[0-9]*$/ {printf "%s=%s ", $1, $2}' "$log")"
    unmet "G4 @ concurrency 8: $(grep -m2 '✗' "$log" | tr '\n' ' ')— p50 was [ ${p50s}] (flat p50 + a breach that moves between runs means the host, not the code)"
  fi

  # The real gate: a fast WRONG answer is worse than a slow right one.
  kubectl --context "$KUBE_CTX" -n norviq exec "$pod" -c api -- python /tmp/latency.py \
    --base-url http://127.0.0.1:8080 --token-file /tmp/tok.txt --n 200 --concurrency 16 >"$log" 2>&1
  if grep -q "WRONG DECISION" "$log"; then
    unmet "G4 @ concurrency 16: $(grep -m1 'WRONG DECISION' "$log")"
  else
    met "G4 @ concurrency 16: every scenario decided correctly"
  fi
}

# --- G5 · chaos ------------------------------------------------------------------------------------
g5() {
  stage "G5 · Chaos"
  local log; log="$(mktemp)"
  "$PY" "${REPO_ROOT}/scripts/kind-e2e/chaos.py" --kube-context "$KUBE_CTX" --base-url "$BASE_URL" >"$log" 2>&1
  local rc=$?
  # NOT-INJECTED counts as unmet, deliberately: a fault that could not be injected proves nothing, and
  # "nothing broke" is indistinguishable from a pass.
  if grep -qE "NOT INJECTED|UNVERIFIED" "$log"; then
    unmet "G5: a fault could not be injected — $(grep -m1 -oE '(NOT INJECTED|UNVERIFIED)[^.]*' "$log")"
  elif [ "$rc" -eq 0 ]; then
    met "G5: all 5 faults degraded correctly and legibly"
  else
    # NEVER report an empty reason. chaos.py can exit non-zero without printing a '✗' — it died
    # before its first check, or died on a traceback — and this branch then rendered `✗ G5:` with
    # nothing after the colon. A gate that fails without saying why is worse than one that does not
    # run: the operator cannot tell a real regression from a flake, and the log was a mktemp that is
    # already gone by the time anyone reads the summary. So: prefer the '✗' lines, fall back to the
    # tail of the log, and always name the exit code. Keep the log when it failed.
    local why; why="$(grep -m2 '✗' "$log" | tr '\n' ' ')"
    [ -n "${why// }" ] || why="no '✗' line — last output: $(tail -n 3 "$log" | tr '\n' ' ')"
    local kept="${ARTIFACT_DIR:-/tmp}/chaos-failed.log"
    cp "$log" "$kept" 2>/dev/null && why="$why [full log: $kept]"
    unmet "G5 (chaos.py exit ${rc}): $why"
  fi
  grep -q "FAILED OPEN" "$log" && unmet "G5: FAILED OPEN somewhere — a release blocker, not a bug"
}

# --- G6 · personas ---------------------------------------------------------------------------------
g6() {
  stage "G6 · Industry personas"
  if [ ! -d "$PERSONA_OUT" ] || [ -z "$(ls -A "$PERSONA_OUT"/*.json 2>/dev/null)" ]; then
    unmet "G6: no persona reports in ${PERSONA_OUT} — run scripts/personas/run-all.sh (needs GROQ_API_KEY)"
    return
  fi
  local log; log="$(mktemp)"
  "$PY" "${REPO_ROOT}/scripts/personas/report.py" "$PERSONA_OUT" >"$log" 2>&1
  if [ $? -eq 0 ]; then
    met "G6: $(grep -m1 'G6 MET' "$log" | sed 's/G6 MET · //')"
  else
    unmet "G6: $(grep -m2 '✗' "$log" | tr '\n' ' ')"
  fi
}

# --- G7 · release hygiene --------------------------------------------------------------------------
g7() {
  stage "G7 · Release hygiene"
  if [ -z "$(git -C "$REPO_ROOT" status --porcelain)" ]; then
    met "G7 working tree: clean"
  else
    unmet "G7 working tree: $(git -C "$REPO_ROOT" status --porcelain | wc -l | tr -d ' ') uncommitted change(s)"
  fi

  # Chart renders under BOTH profiles. The light profile is the one that broke: it overrode memory
  # without overriding api.workers, and nothing caught it until the pods OOMKilled in the cluster.
  local ok=1
  helm template norviq "${REPO_ROOT}/helm/norviq" --set "policyQuotaNamespaces={default}" >/dev/null 2>&1 || ok=0
  helm template norviq "${REPO_ROOT}/helm/norviq" -f "${REPO_ROOT}/helm/norviq/values-light.yaml" \
    --set "policyQuotaNamespaces={default}" >/dev/null 2>&1 || ok=0
  [ "$ok" -eq 1 ] && met "G7 chart: renders under default and light profiles" \
                  || unmet "G7 chart: helm template failed"

  # And the guard that stops the two settings drifting apart again must still FIRE.
  if helm template norviq "${REPO_ROOT}/helm/norviq" -f "${REPO_ROOT}/helm/norviq/values-light.yaml" \
       --set "policyQuotaNamespaces={default}" --set api.workers=4 >/dev/null 2>&1; then
    unmet "G7 chart: the workers-vs-memory guard did NOT fire on a known-bad combination"
  else
    met "G7 chart: the workers-vs-memory guard still fires"
  fi

  if command -v gitleaks >/dev/null 2>&1; then
    # PR range only: full history has known, already-rotated secrets and would always report dirty.
    if gitleaks detect --source "$REPO_ROOT" --log-opts="main..HEAD" --no-banner >/dev/null 2>&1; then
      met "G7 gitleaks: clean over main..HEAD"
    else
      unmet "G7 gitleaks: findings in main..HEAD"
    fi
  else
    unmet "G7 gitleaks: not installed — cannot prove no key was committed"
  fi

  [ -f "${REPO_ROOT}/.github/workflows/kind-e2e.yml" ] \
    && met "G7 CI: kind-e2e workflow present" || unmet "G7 CI: .github/workflows/kind-e2e.yml missing"
}

# RUN ORDER IS NOT LETTER ORDER, deliberately. EXIT-STATE.md's own G7 row requires "L3 after L4", and
# this loop ran G2 (L3) first — so the browser suite inherited whatever L3 had just done to the
# cluster. L3's attacks suite writes ~101 tests' worth of `framework=redteam` audit rows immediately
# beforehand, and `audit-filters-and-volume.spec.ts` counts rows: it failed inside the full check with
# "unfiltered total must include the test rows" while passing 0-failed standalone, twice.
#
# The document said which way round to do it and the script that enforces the document did the
# opposite. G3 now runs first, matching both EXIT-STATE.md and the CI job.
for g in G1 G3 G2 G4 G5 G6 G7; do
  selected "$g" && "$(echo "$g" | tr 'A-Z' 'a-z')"
done

printf '\n%s\n' "======================================================================"
for r in "${RESULTS[@]}"; do printf '  %s\n' "$r"; done
printf '%s\n' "======================================================================"
if [ "$FAILED" -eq 0 ]; then
  printf '\033[1;32mEXIT STATE MET — ready to cut a version.\033[0m\n'
  printf 'Cutting it is still the operator'"'"'s call: no merge, no tag, no PR happens here.\n'
else
  printf '\033[1;31mEXIT STATE NOT MET.\033[0m\n'
fi
exit "$FAILED"
