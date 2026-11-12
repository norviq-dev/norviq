# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Red Team and Compliance read one rule -> technique/control mapping.

Red Team used to carry a literal ATLAS id per attack and cut the OWASP id out of the category's enum
name. Nothing compared either with the mapping Compliance reads, and they disagreed on most attack
families: the prompt injections were scored under AML.T0048 External Harms, the destructive-tool
attacks under AML.T0051 Prompt Injection, and the supply-chain attacks under LLM05:2025, which is a
2023 number (2025's LLM05 is Improper Output Handling).
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from fastapi.testclient import TestClient

from norviq.api.redteam_efficacy import (
    UNMAPPED_TECHNIQUE,
    catalog_entry,
    compute_efficacy,
)
from norviq.redteam.attacks import ATTACKS, get_attack_by_id

_ROOT = Path(__file__).resolve().parents[2]

# The rules the suite expects that no ATLAS technique and no OWASP control lists. Named here so a new
# attack cannot quietly land in the unmapped bucket: map its rule in policies/, or add it here on
# purpose. default_allow is the "expects allow" cases (RL-001, CE-002). The rest are a runtime limit
# and opt-in sector-pack and MCP-guardrail rules that the Compliance mapping does not cover.
_UNMAPPED_RULES = {
    "default_allow",
    "chain_depth_limit",
    "sod_violation",
    "phi_export_exfil_blocked",
    "ot_control_command_blocked",
    "mcp_unapproved_write_server",
    "mcp_tool_not_approved",
}

# The official OWASP Top 10 for LLM Applications 2025, ids and names.
_OWASP_2025 = {
    "LLM01:2025": "Prompt Injection",
    "LLM02:2025": "Sensitive Information Disclosure",
    "LLM03:2025": "Supply Chain",
    "LLM04:2025": "Data and Model Poisoning",
    "LLM05:2025": "Improper Output Handling",
    "LLM06:2025": "Excessive Agency",
    "LLM07:2025": "System Prompt Leakage",
    "LLM08:2025": "Vector and Embedding Weaknesses",
    "LLM09:2025": "Misinformation",
    "LLM10:2025": "Unbounded Consumption",
}


def _file(name: str) -> dict:
    # Read straight from disk, not through norviq.api.framework_mapping, so this is an independent
    # reading of the shipped table rather than the code under test checking itself.
    return json.loads((_ROOT / "policies" / name).read_text(encoding="utf-8"))


def _listed_under(table: dict, rule: str) -> dict[str, str]:
    return {tid: info["name"] for tid, info in table.items() if rule in (info.get("policies") or [])}


def test_the_owasp_table_uses_the_2025_ids_and_names():
    assert {cid: info["name"] for cid, info in _file("owasp_llm_mapping.json").items()} == _OWASP_2025


def test_every_attack_mapping_resolves_in_the_shared_table():
    atlas, owasp = _file("mitre_mapping.json"), _file("owasp_llm_mapping.json")
    for attack in ATTACKS:
        entry = catalog_entry(attack)
        want_atlas = _listed_under(atlas, attack.expected_rule)
        want_owasp = _listed_under(owasp, attack.expected_rule)
        got_atlas = {t["technique_id"]: t["technique_name"] for t in entry["atlas_techniques"]}
        got_owasp = {c["control_id"]: c["control_name"] for c in entry["owasp_controls"]}
        assert got_atlas == want_atlas, (attack.id, attack.expected_rule)
        assert got_owasp == want_owasp, (attack.id, attack.expected_rule)
        # A name is never the bare id standing in for one.
        assert all(name and name != tid for tid, name in {**got_atlas, **got_owasp}.items()), attack.id
        if not want_atlas and not want_owasp:
            assert attack.expected_rule in _UNMAPPED_RULES, (
                f"{attack.id}: rule {attack.expected_rule!r} is in no technique or control; map it in "
                "policies/ or list it in _UNMAPPED_RULES on purpose"
            )
        # The single fields older readers use are the first of each list.
        assert entry["atlas_technique"] == (entry["atlas_techniques"][0]["technique_id"] if got_atlas else None)
        assert entry["owasp_control"] == (entry["owasp_controls"][0]["control_id"] if got_owasp else None)


def test_the_families_that_used_to_disagree_now_map_where_compliance_puts_their_rule():
    def ids(attack_id: str) -> tuple[set[str], set[str]]:
        e = catalog_entry(get_attack_by_id(attack_id))
        return {t["technique_id"] for t in e["atlas_techniques"]}, {c["control_id"] for c in e["owasp_controls"]}

    # Prompt injection was scored as External Harms, which Compliance marks out of scope.
    atlas, owasp = ids("PI-001")
    assert "AML.T0051" in atlas and "AML.T0048" not in atlas and owasp == {"LLM01:2025"}
    assert ids("PB-001") == ids("PI-001")
    # Destructive tools were scored as Prompt Injection.
    assert ids("EA-001") == ({"AML.T0053"}, {"LLM06:2025"})
    # SQL injection was a Jailbreak with no OWASP control.
    assert ids("SQL-001") == ({"AML.T0049"}, {"LLM05:2025"})
    # Supply chain was LLM05:2025 (a 2023 number). 2025's LLM03 Supply Chain is out of scope here.
    assert ids("SC-001") == ({"AML.T0053"}, set())
    assert ids("CT-001") == ({"AML.T0012"}, set())
    assert ids("MCP-05") == ({"AML.T0012"}, set())
    # MCP identity attacks named AML.T0010, which no table has, so its name was the bare id.
    assert ids("MCP-01") == (set(), set())


def _admin_client(rego: str) -> TestClient:
    from norviq.api.auth import get_current_user
    from norviq.api.db.session import get_session
    from norviq.api.main import create_app

    class _Result:
        def all(self):
            return []

    class _Session:
        async def execute(self, *a, **k):
            return _Result()

        async def scalar(self, *a, **k):
            return None

        def add(self, *a, **k):
            return None

        async def commit(self):
            return None

    app = create_app()
    app.state.loader = SimpleNamespace(_policies={"__cluster__:__baseline__": {"rego": rego}})
    app.dependency_overrides[get_current_user] = lambda: {"role": "admin", "sub": "tester", "namespace": None}
    app.dependency_overrides[get_session] = lambda: _Session()
    return TestClient(app, raise_server_exceptions=False)


def test_red_team_and_compliance_agree_through_their_own_routes():
    """Each side as its route serves it: the Compliance coverage payload's technique -> policies lists,
    and the Red Team catalog. An attack must be credited to exactly the techniques and controls whose
    Compliance row lists its rule, under the name Compliance shows."""
    rules = sorted({a.expected_rule for a in ATTACKS})
    rego = "package norviq.strict\n\n" + "\n".join(f'blocks["{r}"] {{ input.tool_name == "x" }}' for r in rules)
    client = _admin_client(rego)

    catalog = client.get("/api/v1/redteam/catalog")
    assert catalog.status_code == 200, catalog.text
    by_attack = {e["attack_id"]: e for e in catalog.json()}

    for framework, field, id_key, name_key in (
        ("atlas", "atlas_techniques", "technique_id", "technique_name"),
        ("owasp", "owasp_controls", "control_id", "control_name"),
    ):
        resp = client.get(f"/api/v1/compliance/{framework}/coverage?range=24h")
        assert resp.status_code == 200, resp.text
        rows = resp.json()["techniques"]
        assert rows, framework
        for attack in ATTACKS:
            want = {t["technique_id"]: t["name"] for t in rows if attack.expected_rule in t["policies"]}
            got = {x[id_key]: x[name_key] for x in by_attack[attack.id][field]}
            assert got == want, (framework, attack.id, attack.expected_rule)


def test_an_attack_counts_under_every_technique_its_rule_maps_to_and_unmapped_is_named():
    def row(attack_id: str, actual: str) -> dict:
        a = get_attack_by_id(attack_id)
        return {"attack_id": a.id, "agent_class": "billing", "namespace": "default", "expected": "block",
                "actual": actual, "rule_id": a.expected_rule if actual == "block" else "default_allow",
                **catalog_entry(a)}

    eff = compute_efficacy([row("PI-001", "block"), row("SH-001", "allow"), row("CE-001", "block")])
    by_t = {b["technique_id"]: b for b in eff["by_technique"]}
    assert eff["overall"]["total"] == 3
    # llm01_prompt_injection is listed under T0051 and T0054; deny_shell_execution under T0054 and T0050.
    assert (by_t["AML.T0051"]["total"], by_t["AML.T0051"]["caught"]) == (1, 1)
    assert (by_t["AML.T0054"]["total"], by_t["AML.T0054"]["caught"], by_t["AML.T0054"]["got_through"]) == (2, 1, 1)
    assert (by_t["AML.T0050"]["total"], by_t["AML.T0050"]["got_through"]) == (1, 1)
    # chain_depth_limit is in no technique: the bucket says so instead of naming a technique.
    unmapped = by_t[UNMAPPED_TECHNIQUE]
    assert unmapped["total"] == 1 and unmapped["technique_name"] != UNMAPPED_TECHNIQUE
    assert not any(b["technique_id"] == b["technique_name"] for b in eff["by_technique"])
    by_o = {b["control_id"]: b for b in eff["by_owasp"]}
    assert set(by_o) == {"LLM01:2025", "LLM06:2025"}


def test_a_row_stored_with_only_the_single_fields_is_still_counted():
    eff = compute_efficacy([{
        "attack_id": "OLD-1", "agent_class": "billing", "expected": "block", "actual": "block",
        "rule_id": "deny_sql_injection", "atlas_technique": "AML.T0049",
        "atlas_technique_name": "Exploit Public-Facing Application", "owasp_control": None,
    }])
    assert [(b["technique_id"], b["total"]) for b in eff["by_technique"]] == [("AML.T0049", 1)]
    assert eff["by_owasp"] == []


def test_a_stored_run_is_served_under_the_current_mapping():
    """A run written before the mapping was shared stored PI-001 under AML.T0048 and SC-001 under
    LLM05:2025. The console shows the newest stored run, so reading it back must not repeat that."""
    from norviq.api.routers.redteam import _run_to_dict

    stale = [
        {"attack_id": "PI-001", "agent_class": "billing", "namespace": "default", "expected": "block",
         "actual": "block", "rule_id": "llm01_prompt_injection", "passed": True,
         "atlas_technique": "AML.T0048", "atlas_technique_name": "External Harms",
         "owasp_control": "LLM01:2025", "owasp_control_name": "Prompt Injection"},
        {"attack_id": "SC-001", "agent_class": "billing", "namespace": "default", "expected": "block",
         "actual": "block", "rule_id": "llm05_supply_chain", "passed": True,
         "atlas_technique": "AML.T0053", "atlas_technique_name": "LLM Plugin Compromise",
         "owasp_control": "LLM05:2025", "owasp_control_name": "Improper Output Handling"},
    ]
    stored_eff = {**compute_efficacy(stale), "vector_coverage": {"catalogued": 99}}
    assert "AML.T0048" in {b["technique_id"] for b in stored_eff["by_technique"]}  # the premise

    run = SimpleNamespace(id="r1", created_at=datetime.now(timezone.utc), namespace="default",
                          targets=["billing"], total=2, passed=2, failed=0, pass_rate=100.0,
                          results=stale, efficacy=stored_eff)
    out = _run_to_dict(run)

    rows = {r["attack_id"]: r for r in out["results"]}
    assert {t["technique_id"] for t in rows["PI-001"]["atlas_techniques"]} == {"AML.T0051", "AML.T0054"}
    assert rows["SC-001"]["owasp_controls"] == [] and rows["SC-001"]["owasp_control"] is None
    techniques = {b["technique_id"] for b in out["efficacy"]["by_technique"]}
    assert "AML.T0048" not in techniques and "AML.T0051" in techniques
    assert {b["control_id"] for b in out["efficacy"]["by_owasp"]} == {"LLM01:2025"}
    # The catalog denominators were stored on purpose and stay; the row counts are recounted.
    assert out["efficacy"]["vector_coverage"] == {"catalogued": 99}
    assert out["efficacy"]["overall"] == stored_eff["overall"]


def test_a_stored_run_serves_its_overall_counted_like_its_breakdowns():
    """`with_current_breakdowns` recounted by_technique / by_owasp with the current `row_outcome` and
    served the stored `overall` beside them. A run stored while a throttled block still counted as
    caught then read 100% proven-blocking over a technique table that said 0 caught, and the history
    list showed the same stale 100%."""
    from norviq.api.routers.redteam import _run_summary, _run_to_dict

    rows = [
        {"attack_id": "EA-001", "agent_class": "billing", "namespace": "default", "expected": "block",
         "actual": "block", "rule_id": "rate_limit_exceeded", "passed": True},
        {"attack_id": "PI-001", "agent_class": "billing", "namespace": "default", "expected": "block",
         "actual": "block", "rule_id": "llm01_prompt_injection", "passed": True},
        {"attack_id": "RL-001", "agent_class": "billing", "namespace": "default", "expected": "allow",
         "actual": "allow", "rule_id": "default_allow", "passed": True},
    ]
    # What a run written under the old verdict stored: the throttle as a catch.
    stale_overall = {"total": 2, "caught": 2, "would_block": 0, "got_through": 0,
                     "proven_blocking_pct": 100.0, "detected_pct": 100.0}
    stored_eff = {**compute_efficacy(rows), "overall": stale_overall, "non_enforcement": 0,
                  "vector_coverage": {"catalogued": 99}}
    run = SimpleNamespace(id="r2", created_at=datetime.now(timezone.utc), namespace="default",
                          targets=["billing"], total=3, passed=3, failed=0, pass_rate=100.0,
                          results=rows, efficacy=stored_eff)

    eff = _run_to_dict(run)["efficacy"]
    overall = eff["overall"]
    assert (overall["total"], overall["caught"], overall["got_through"]) == (2, 1, 1)
    assert overall["proven_blocking_pct"] == 50.0
    assert eff["non_enforcement"] == 1
    # The overall and the per-technique table come from one count: every scored row is in the ATLAS
    # table, and the caught rows there are the caught rows overall.
    caught_ids = {b["technique_id"] for b in eff["by_technique"] if b["caught"]}
    assert caught_ids == {"AML.T0051", "AML.T0054"}
    assert {b["technique_id"] for b in eff["by_technique"] if b["got_through"]} == {"AML.T0053"}
    assert eff["vector_coverage"] == {"catalogued": 99}

    summary = _run_summary(run)
    assert (summary["proven_blocking_pct"], summary["caught"], summary["got_through"]) == (50.0, 1, 1)


def test_every_also_cross_reference_resolves_with_or_without_rules():
    """The console renders `also` as "Same enforcing rule also satisfies <id>". AML.T0053 said
    LLM07:2025, the 2023 number for Insecure Plugin Design, which in 2025 is System Prompt Leakage, a
    control with no rule at all. LLM05:2025 named AML.T0050, which shares none of its rules.

    This test used to skip every entry with an empty `policies` list, so it never read LLM10:2025's
    `also`, which named AML.T0034, a technique the ATLAS table does not have. Every cross-reference in
    both tables is checked now. One with rules must share a rule with its target. One without rules
    is shown as a correspondence with no rule behind it, so its target must have none either and must
    be the same kind of control."""
    tables = {"MITRE ATLAS": _file("mitre_mapping.json"), "OWASP LLM": _file("owasp_llm_mapping.json")}
    every_also = [(lbl, tid) for lbl, t in tables.items() for tid, info in t.items() if info.get("also")]
    checked = []
    for source_label, source in tables.items():
        for tid, info in source.items():
            also = info.get("also")
            if not also:
                continue
            label, sep, other_id = also.partition(" · ")
            assert sep and label in tables and label != source_label, (tid, also)
            other = tables[label].get(other_id)
            assert other is not None, f"{tid} cross-references {also}, which the {label} table does not list"
            rules, other_rules = set(info.get("policies") or []), set(other.get("policies") or [])
            if rules:
                assert rules & other_rules, (tid, also)
            else:
                assert not other_rules, (tid, also)
                assert other.get("scope") == info.get("scope"), (tid, also)
            checked.append((source_label, tid))
    assert checked == every_also and len(checked) >= 9


def test_no_rule_reason_names_a_bare_owasp_number():
    """A reason is shown in the audit log. Without a year a reader takes the 2025 list, and two of these
    were 2023 numbers: `OWASP LLM08` on chain_depth_limit (2025: Vector and Embedding Weaknesses) and
    `OWASP LLM05` on llm05_supply_chain (2025: Improper Output Handling)."""
    bare = re.compile(r'"[^"\n]*OWASP LLM\d{2}(?!:\d{4})[^"\n]*"')
    files = [_ROOT / "comprehensive.rego", *sorted((_ROOT / "webhook" / "presets").glob("*.rego"))]
    assert len(files) >= 2
    hits = [(f.name, m.group(0)) for f in files for m in bare.finditer(f.read_text(encoding="utf-8"))]
    # The catalog's descriptions are shown beside the attack in the console.
    hits += [(a.id, a.description) for a in ATTACKS if bare.search(f'"{a.description}"')]
    assert hits == []


def test_the_policies_readme_lists_each_rule_where_the_mapping_does():
    """policies/README.md carried a third, hand-written copy of the mapping, with the same errors Red
    Team had: prompt injection under AML.T0048, destructive tools under AML.T0051, cross-tenant under
    AML.T0049, supply chain under LLM05."""
    atlas, owasp = _file("mitre_mapping.json"), _file("owasp_llm_mapping.json")
    readme = (_ROOT / "policies" / "README.md").read_text(encoding="utf-8")
    rows = re.findall(r"^\| `([a-z0-9_]+)` \|.*\| ([^|]*) \|$", readme, flags=re.MULTILINE)
    assert len(rows) >= 10
    for rule, column in rows:
        got = set(re.findall(r"AML\.T\d{4}(?:\.\d{3})?|LLM\d{2}:\d{4}", column))
        assert not re.search(r"LLM\d{2}(?!:\d{4})", column), (rule, column)
        assert got == set(_listed_under(atlas, rule)) | set(_listed_under(owasp, rule)), (rule, column)


def test_the_attack_graph_threat_intent_capabilities_and_red_team_agree_on_a_tool():
    """Red Team credits an attack to the techniques its rule is listed under. The attack graph, the
    threat-path inspector and the capability registry name a technique from a tool instead, and each
    kept a table of its own: delete_record and drop_table were AML.T0048 External Harms on all three,
    while Red Team scored EA-001 and EA-003, attacks on those tools, under AML.T0053.

    For every attack whose rule is the one its tool's name resolves to, all four must name the same
    techniques, and the single descriptor the inspector shows must be Red Team's first one."""
    from norviq.api.framework_mapping import rule_for_tool
    from norviq.api.threat_intent import mitre_for_tool
    from norviq.engine.attack_graph import AttackGraphEngine
    from norviq.engine.attack_graph_models import AttackStep
    from norviq.engine.capability.source_registry import Verb, classify_source

    engine = AttackGraphEngine(evaluator=None)
    capability = {
        "llm06_excessive_agency": {f.verb: f.technique for f in classify_source("postgresql")}[Verb.DELETE],
        "llm02_data_leakage": {f.verb: f.technique for f in classify_source("smtp")}[Verb.SEND],
    }
    compared = set()
    for attack in ATTACKS:
        if rule_for_tool(attack.tool_name) != attack.expected_rule:
            continue
        red = [t["technique_id"] for t in catalog_entry(attack)["atlas_techniques"]]
        assert red, attack.id
        step = AttackStep(step_num=1, node_id="t", node_name=attack.tool_name, node_type="tool",
                          action="call", policy_check="would_allow", matched_rule="default_allow")
        assert engine._extract_mitre_techniques([step]) == sorted(red), attack.id
        assert mitre_for_tool(attack.tool_name).split(" · ")[0] == red[0], attack.id
        if attack.expected_rule in capability:
            assert capability[attack.expected_rule] == red[0], attack.id
        compared.add(attack.id)
    # The comparison is not vacuous: these are the families whose tool decides their rule.
    assert {"EA-001", "EA-002", "EA-003", "TM-001", "SC-001", "SC-002", "SH-001", "SQL-001", "DL-001",
            "DL-002", "DL-003", "MCP-04"} <= compared
    assert "AML.T0048" not in {mitre_for_tool(t).split(" · ")[0] for t in ("delete_record", "drop_table")}


def test_a_path_step_a_mapped_rule_decided_is_credited_like_red_team():
    """A step the evaluator decided with a mapped rule is credited to that rule's techniques, which is
    how Red Team credits an attack, not to whatever the tool's name suggests."""
    from norviq.engine.attack_graph import AttackGraphEngine
    from norviq.engine.attack_graph_models import AttackStep

    step = AttackStep(step_num=1, node_id="t", node_name="get_customer", node_type="tool",
                      action="call", policy_check="would_block", matched_rule="cross_tenant_access")
    want = sorted(t["technique_id"] for t in catalog_entry(get_attack_by_id("CT-001"))["atlas_techniques"])
    assert AttackGraphEngine(evaluator=None)._extract_mitre_techniques([step]) == want == ["AML.T0012"]


def _rego_set(rego: str, name: str) -> set[str]:
    m = re.search(rf"^{name} = \{{([^}}]*)\}}", rego, flags=re.MULTILINE)
    assert m, name
    return set(re.findall(r'"([^"]+)"', m.group(1)))


def test_the_tool_name_sets_are_the_baseline_s_own():
    """`rule_for_tool` resolves a tool to a rule with copies of comprehensive.rego's name-keyed sets.
    Read them back out of the rego so a change there cannot leave the technique lookups behind."""
    from norviq.api import framework_mapping as fm

    rego = (_ROOT / "comprehensive.rego").read_text(encoding="utf-8")
    assert _rego_set(rego, "supply_chain_tools") == fm.SUPPLY_CHAIN_TOOLS
    assert _rego_set(rego, "destructive_tools") == fm.DESTRUCTIVE_TOOLS
    assert _rego_set(rego, "destructive_name_tokens") == fm.DESTRUCTIVE_NAME_TOKENS
    assert _rego_set(rego, "elevated_tools") == fm.ELEVATED_TOOLS
    assert _rego_set(rego, "exec_name_tokens") == fm.EXEC_NAME_TOKENS
    assert _rego_set(rego, "external_tools") == fm.EXTERNAL_TOOLS
    assert _rego_set(rego, "secret_read_tools") == fm.SECRET_READ_TOOLS
    assert _rego_set(rego, "egress_action_tokens") == fm.EGRESS_ACTION_TOKENS
    m = re.search(r'prefixes := \[([^\]]*)\]', rego)
    assert m and tuple(re.findall(r'"([^"]+)"', m.group(1))) == fm.EGRESS_PREFIXES
    assert 'input.tool_name == "execute_sql"' in rego and fm.SQL_TOOLS == {"execute_sql"}
    # Every rule `rule_for_tool` can return is one the rego blocks under.
    for rule in ("llm05_supply_chain", "llm06_excessive_agency", "deny_shell_execution",
                 "deny_sql_injection", "llm02_data_leakage"):
        assert f'blocks["{rule}"]' in rego, rule
