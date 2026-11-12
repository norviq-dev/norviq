# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Red-team catalog mapping + efficacy roll-up — pure, DB-free, unit-testable.

An attack's MITRE ATLAS techniques and OWASP LLM controls are looked up from the rule it expects to fire
(``expected_rule``) in the mapping Compliance reads (``norviq/api/framework_mapping.py`` over
``policies/mitre_mapping.json`` + ``policies/owasp_llm_mapping.json``). An attack counts under every
technique and control that lists its rule, which is exactly the set of techniques Compliance credits when
that rule blocks real traffic. A rule no technique lists is reported as unmapped, never under a made-up id.

Given the result rows from a suite run, compute a caught-vs-got-through efficacy roll-up — overall and per
ATLAS technique + per OWASP control. Only "block-expected" attacks count toward the proven-blocking ratio (an
attack whose expected decision is ``allow`` is a runtime/intent control case, reported separately, never counted
as a miss). Synthetic / probe target identities are EXCLUDED so the number reflects real deployed posture.
"""

from __future__ import annotations

from typing import Any

from norviq.api.framework_mapping import techniques_for_rule
from norviq.api.routers.system_health import non_policy_rule_for  # a fault or a throttle is not a detection
from norviq.api.synthetic import is_synthetic_identity
from norviq.redteam.attacks import get_attack_by_id
from norviq.redteam.vectors import VECTORS_BY_ID, EVALUATE_REACHABLE, coverage_denominators

# The ATLAS bucket for a block-expected attack whose rule no technique lists. It names the condition
# instead of posing as a technique, and it sorts after every AML.T id.
UNMAPPED_TECHNIQUE = "unmapped"
UNMAPPED_TECHNIQUE_NAME = "No ATLAS technique maps this rule"


def attack_mapping(attack: Any) -> dict[str, Any]:
    """Every ATLAS technique and OWASP control the shared mapping lists ``attack.expected_rule`` under."""
    rule = getattr(attack, "expected_rule", "") or ""
    return {
        "atlas": [{"technique_id": t, "technique_name": n} for t, n in techniques_for_rule(rule, "atlas")],
        "owasp": [{"control_id": c, "control_name": n} for c, n in techniques_for_rule(rule, "owasp")],
    }


def mapping_fields(attack: Any) -> dict[str, Any]:
    """The framework fields a catalog entry and a result row carry.

    The lists are the mapping. The single ``atlas_technique`` / ``owasp_control`` fields are the first
    entry of each list (None when the list is empty), kept for readers written before an attack could
    map to more than one technique.
    """
    m = attack_mapping(attack)
    atlas, owasp = m["atlas"], m["owasp"]
    return {
        "atlas_techniques": atlas,
        "owasp_controls": owasp,
        "atlas_technique": atlas[0]["technique_id"] if atlas else None,
        "atlas_technique_name": atlas[0]["technique_name"] if atlas else None,
        "owasp_control": owasp[0]["control_id"] if owasp else None,
        "owasp_control_name": owasp[0]["control_name"] if owasp else None,
    }


def catalog_entry(attack: Any) -> dict[str, Any]:
    """One enriched catalog row (attack fields + resolved ATLAS/OWASP mapping)."""
    return {
        "attack_id": attack.id,
        "name": attack.name,
        "category": attack.category.value,
        "description": attack.description,
        "severity": attack.severity,
        "tool_name": attack.tool_name,
        "expected_decision": attack.expected_decision,
        "expected_rule": attack.expected_rule,
        "tags": list(attack.tags),
        **mapping_fields(attack),
        "mcp_vector": getattr(attack, "mcp_vector", "") or None,
        "mcp_vector_title": (
            VECTORS_BY_ID[attack.mcp_vector].title
            if getattr(attack, "mcp_vector", "") in VECTORS_BY_ID
            else None
        ),
    }


def with_current_mapping(results: list[dict[str, Any]] | None) -> list[dict[str, Any]] | None:
    """Copies of stored result rows with their framework fields re-read from the current mapping.

    A stored run keeps the mapping it was written with, and every run written before the mapping was
    shared carries the old per-attack literals: its prompt injections under External Harms and its
    supply-chain attacks under LLM05:2025. The newest run per namespace is the one the console shows
    and it always keeps its rows, so those rows are re-mapped on the way out. A row whose attack is no
    longer in the catalog keeps what it was written with.
    """
    if results is None:
        return None
    out = []
    for r in results:
        attack = get_attack_by_id(str(r.get("attack_id") or ""))
        out.append({**r, **mapping_fields(attack)} if attack is not None else dict(r))
    return out


# The parts of an efficacy blob counted from the result rows. `vector_coverage` is not one of them:
# its denominators come from the catalog and are stored on the run on purpose (`_vector_coverage`).
ROW_COUNTED_FIELDS = (
    "overall", "by_technique", "by_owasp", "by_vector", "non_enforcement", "sector_not_enabled",
    "excluded_synthetic",
)


def with_current_breakdowns(efficacy: Any, results: list[dict[str, Any]] | None) -> Any:
    """A stored efficacy blob with every row-counted part recounted from ``results``.

    Pass rows that went through ``with_current_mapping``. Only ``by_technique`` / ``by_owasp`` used to
    be recounted, while ``overall`` was served as stored. ``row_outcome`` has changed since runs were
    first stored (a throttled or faulted block is no longer caught, a monitored detection is
    would_block), so a stored ``overall`` could disagree with the breakdowns served beside it. Every
    part is now counted by the same pass. A run whose rows were pruned keeps what it was written with.
    """
    if not isinstance(efficacy, dict) or not results:
        return efficacy
    fresh = compute_efficacy(results)
    return {**efficacy, **{k: fresh[k] for k in ROW_COUNTED_FIELDS}}


def _row_frameworks(r: dict[str, Any], plural: str, single: str, name_key: str, id_key: str) -> list[tuple[str, str]]:
    """(id, name) pairs a row is credited to. A row stored before the lists existed has only the
    single field, so that is read when the list is absent."""
    entries = r.get(plural)
    if isinstance(entries, list):
        return [(str(e.get(id_key)), str(e.get(name_key) or e.get(id_key))) for e in entries
                if isinstance(e, dict) and e.get(id_key)]
    one = r.get(single)
    return [(str(one), str(r.get(f"{single}_name") or one))] if one else []


# Decisions that actually STOP the call. `escalate` belongs here: the firewall holds the call for human
# approval, the SDK interceptor raises NorviqEscalateError, and the sidecar proxy drops anything that is
# not `is_allowed()`. The attack did not reach the tool, which is what "caught" claims.
_ENFORCED_DECISIONS = frozenset({"block", "escalate"})


def _blank_bucket() -> dict[str, int]:
    return {"total": 0, "caught": 0, "would_block": 0, "got_through": 0}


def _row_outcome(r: dict[str, Any]) -> str:
    """caught | would_block | got_through, for a row that expected a block.

    The scorer read `passed` — which is `actual == expected` — so ONLY a hard block counted. Every
    baseline control now ships on `monitor`, and a monitored control is implemented by emitting an
    `audits[]` head, so a control that DETECTED the attack and recorded it scored identically to one
    that never fired. Measured on the shipped default: a run where two of four attacks were detected
    and audited reported proven_blocking_pct 25.0 with both audits in `got_through`.

    Three outcomes rather than two, because collapsing them either way is a lie an operator would act
    on. Counting an audit as caught would claim a defence while the call proceeded — the same mistake
    as BUG-018, arriving from the other side. Counting it as got-through says nothing detected it,
    when something did and the operator can promote that control to Enforce in one click.

    `proven_blocking_pct` deliberately stays caught/total: what it claims is PROVEN blocking, and a
    monitored detection has not proven it.

    An engine fault is never a detection. A fail-closed `block` carrying `evaluator_timeout` is the
    engine failing, not a control working, and scoring it as caught inflates the headline number with
    an outage — so faults are tested BEFORE the enforced check and left in the red bucket.

    A THROTTLE is never a detection either, for the same reason and with a nastier failure mode. The
    engine's rate limiter fires only on a decision that already resolved to `allow`, so a
    `block / rate_limit_exceeded` row is a call the policy stack examined and permitted, refused
    afterwards on volume alone. Scoring it as caught made `proven_blocking_pct` a function of how hard
    the suite was driven rather than of policy quality — and, worse, made it rise as coverage got
    WORSE, since only an allow is eligible to be throttled. The check is `non_policy_rule_for`, which
    covers faults and the throttle together.
    """
    rule_id = str(r.get("rule_id") or "")
    if non_policy_rule_for(rule_id) is not None:
        return "got_through"
    actual = str(r.get("actual") or "")
    if actual in _ENFORCED_DECISIONS:
        return "caught"
    # `audit` with a rule behind it means a control fired and the call was let through on purpose.
    # `default_allow` is the absence of a match, which is a genuine miss.
    if actual == "audit" and rule_id and rule_id != "default_allow":
        return "would_block"
    return "got_through"


# The three outcomes `compute_efficacy` scores, i.e. the buckets that sum to `total`.
SCORED_OUTCOMES = ("caught", "would_block", "got_through")


def row_outcome(r: dict[str, Any]) -> str:
    """The ONE per-row verdict, served on every result row and the only input to `compute_efficacy`.

    caught | would_block | got_through for a row the roll-up scores, otherwise the reason it is not
    scored: synthetic (a probe identity), non_enforcement (the attack does not expect a block) or
    not_enabled (its sector pack / opt-in guardrail is not loaded here). The tests run in that order,
    so a row carries exactly one of the six.

    The console used to re-derive this per row as `!passed && applicable !== false`, which disagrees
    with the roll-up in both directions. A throttled or faulted block has `passed` true (actual block
    == expected block), so the table hid it while the scorecard counted it as got_through; a monitored
    detection has `passed` false, so the table painted it red while the scorecard counted it as
    would_block. Measured on a kind run: 17 red-team audit rows `block / rate_limit_exceeded`, and the
    scorecard said "got through > 0" over a got-through filter that listed none. Throttling depends
    on timing, so the e2e spec that checks the two agree failed intermittently.
    """
    if is_synthetic_identity(r.get("agent_class")):
        return "synthetic"
    if r.get("expected") != "block":
        return "non_enforcement"
    # A sector attack whose enforcing rule isn't loaded (pack not enabled) is out of scope for THIS
    # deployment — it must not deflate proven-blocking, exactly like an un-enabled coverage category.
    if r.get("applicable") is False:
        return "not_enabled"
    return _row_outcome(r)


def attack_passed(expected: Any, actual: Any, rule_id: Any) -> bool:
    """`passed` on a result row, in the console and in `norviq redteam run`: the decision is the one the
    attack expected AND a policy made it.

    It was `actual == expected` alone, so a throttled or faulted block met a block expectation by
    accident. The scorecard has counted those rows as got_through since v0.2.1 (`_row_outcome`), while
    the same rows raised the console's "Suite pass-rate" and passed in the CLI. Against an evaluator
    that throttles every call, a suite read 32/34 passed beside a scorecard of 0 caught. Same resolver
    as `_row_outcome`, so the two cannot disagree about what a throttle is. A row that records no
    expectation proves nothing, so it does not pass either.
    """
    return bool(expected) and actual == expected and non_policy_rule_for(str(rule_id or "")) is None


def pass_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    """total / passed / failed / pass_rate over result rows, counted by `attack_passed`.

    The one formula for a run's pass figures: the suite builds its report with it, and the read
    routes re-derive them with it whenever the rows are still stored.
    """
    total = len(results)
    passed = sum(1 for r in results if attack_passed(r.get("expected"), r.get("actual"), r.get("rule_id")))
    return {
        "total": total,
        "passed": passed,
        "failed": total - passed,
        "pass_rate": round(passed / total * 100, 1) if total else 0,
    }


def with_outcomes(results: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """Copies of `results`, each annotated with its `row_outcome` and its current `passed`, to serve.

    Computed on read and never persisted, so a run stored before this field existed gets it too, and
    a stored row can never carry a verdict that disagrees with the current roll-up. `passed` is
    re-derived for the same reason: a row written while it was `actual == expected` says a throttled
    block passed, beside an `outcome` of got_through.
    """
    return [
        {**r, "passed": attack_passed(r.get("expected"), r.get("actual"), r.get("rule_id")), "outcome": row_outcome(r)}
        for r in results or []
    ]


def _finalize(bucket: dict[str, Any]) -> dict[str, Any]:
    total, caught = bucket["total"], bucket["caught"]
    bucket["proven_blocking_pct"] = round(caught / total * 100, 1) if total else 0.0
    # What the controls SAW, enforced or not. Reported beside the proven number rather than folded
    # into it: on the shipped all-monitor default these differ by design, and an operator reading a
    # 0% proven score needs to know whether that is "nothing detected it" or "everything detected it
    # and nothing is promoted yet" — two opposite situations with two opposite next actions.
    detected = caught + bucket["would_block"]
    bucket["detected_pct"] = round(detected / total * 100, 1) if total else 0.0
    return bucket


def _vector_coverage(exercised: set[str]) -> dict[str, Any]:
    """What this run measured of the MCP/tool surface, and — the point — what it did not.

    Without this block a scorecard reading 100% across two vectors is indistinguishable from full MCP
    coverage, while thirty catalogued vectors went untouched. That is the "the console says covered,
    and it is not" failure the whole product exists to prevent, so the denominator travels with the
    numerator rather than being available on request.

    The denominators come from the CATALOG, not from the rows, and they are STORED on the run. Only the
    newest run per namespace keeps its result rows (`redteam_detail_keep_runs`), so a block re-derived
    from rows would silently vanish from every older run while the rest of the efficacy summary
    survived. `exercised` counts DISTINCT vectors seen, not rows: five attacks across two vectors is
    two, because the question is surface coverage, not attack volume.

    PROXY-only vectors are not failures and must never read as such. Most are enforced, several
    provably (Gate A stripping, the content-hash pin) — they are simply decided before the policy
    engine, which is the one thing this suite can score.
    """
    d = coverage_denominators()
    return {
        **d,
        "exercised": len(exercised),
        "unexercised_reachable": sorted(EVALUATE_REACHABLE - exercised),
    }


def compute_efficacy(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Caught-vs-got-through roll-up over the suite's result rows.

    - Synthetic / probe target identities are excluded (``is_synthetic_identity``).
    - Only rows whose EXPECTED decision is ``block`` count toward the proven-blocking ratio. A ``caught`` row was
      stopped by a policy (NOT ``passed``, which a throttle or a fault also satisfies); a ``got_through`` row
      expected a block and no policy gave one. ``_row_outcome`` has the full rule.
    - Rows whose expected decision is not ``block`` (runtime/intent-only control cases) are tallied under
      ``non_enforcement`` and never counted as a miss.

    Every bucket is a count of `row_outcome` over the rows — the same verdict each served row carries —
    so a table filtered on a row's `outcome` cannot disagree with the number above it.
    """
    overall = _blank_bucket()
    by_technique: dict[str, dict[str, Any]] = {}
    by_owasp: dict[str, dict[str, Any]] = {}
    by_vector: dict[str, dict[str, Any]] = {}
    non_enforcement = 0
    sector_not_enabled = 0  # sector-pack attacks whose pack isn't enabled — out of scope, NOT a miss
    excluded_synthetic = 0

    for r in results:
        outcome = row_outcome(r)
        if outcome == "synthetic":
            excluded_synthetic += 1
            continue
        if outcome == "non_enforcement":
            non_enforcement += 1
            continue
        if outcome == "not_enabled":
            sector_not_enabled += 1
            continue
        overall["total"] += 1
        overall[outcome] += 1

        # An attack counts under EVERY technique and control its rule is mapped to, as Compliance credits
        # a block to every technique that lists the rule. So the per-technique totals can sum to more
        # than `overall.total`. A row with no technique goes to the named unmapped bucket, so the ATLAS
        # table still accounts for every scored attack; a row with no OWASP control is left out of
        # `by_owasp`, as before.
        techniques = _row_frameworks(r, "atlas_techniques", "atlas_technique", "technique_name", "technique_id")
        for tid, tname in techniques or [(UNMAPPED_TECHNIQUE, UNMAPPED_TECHNIQUE_NAME)]:
            tb = by_technique.setdefault(tid, {**_blank_bucket(), "technique_id": tid, "technique_name": tname})
            tb["total"] += 1
            tb[outcome] += 1

        for cid, cname in _row_frameworks(r, "owasp_controls", "owasp_control", "control_name", "control_id"):
            ob = by_owasp.setdefault(cid, {**_blank_bucket(), "control_id": cid, "control_name": cname})
            ob["total"] += 1
            ob[outcome] += 1

        # SKIPPED when absent, following `by_owasp` and NOT `by_technique`. `by_technique` keeps an
        # explicit unmapped bucket so the ATLAS table accounts for every scored attack. An MCP vector is
        # legitimately absent for every attack that predates the dimension — bucketing those as
        # "unknown" would assert they exercise an unidentified MCP vector, which is false, and would
        # render one row of ~29xN attacks that dominates the table and means nothing.
        vid = r.get("mcp_vector")
        if vid:
            vb = by_vector.setdefault(vid, {**_blank_bucket(), "vector_id": vid,
                                            "vector_title": r.get("mcp_vector_title") or vid})
            vb["total"] += 1
            vb[outcome] += 1

    return {
        "overall": _finalize(overall),
        "by_technique": [_finalize(v) for v in sorted(by_technique.values(), key=lambda x: x["technique_id"])],
        "by_owasp": [_finalize(v) for v in sorted(by_owasp.values(), key=lambda x: x["control_id"])],
        "by_vector": [_finalize(v) for v in sorted(by_vector.values(), key=lambda x: x["vector_id"])],
        "vector_coverage": _vector_coverage(set(by_vector)),
        "non_enforcement": non_enforcement,
        "sector_not_enabled": sector_not_enabled,
        "excluded_synthetic": excluded_synthetic,
    }
