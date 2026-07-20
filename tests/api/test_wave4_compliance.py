# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Wave-4 (graph classifier) + Compliance (MITRE ATLAS) unit/integration tests.

- The synthetic classifier catches the leaked identities (evtrace/scorer/…) and never a real class.
- The ATLAS mapping names are correct (verified against atlas.mitre.org) + every technique has a scope.
- Coverage math derives enforced/gap/out_of_scope + the enforced/(enforceable) headline; the evidence PDF is
  valid; the GAP→generate endpoint validates (admin, enforceable, non-synthetic) before creating a draft.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from norviq.api.synthetic import is_synthetic_identity


# --------------------------------------------------------------------------------------------------
# Synthetic classifier completeness
# --------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("cls", [
    "allowlist-probe-d5e5", "e2e-intent-99", "probe-abc", "policy-tester", "scorer",
    "evtrace-1783266533", "effecttest", "smoke-1", "canary-2", "wave4e2e-123",
])
def test_synthetic_prefixes_are_hidden(cls):
    assert is_synthetic_identity(cls), cls


@pytest.mark.parametrize("cls", [
    "customer-support", "deploy-bot", "report-runner", "hr-chatbot", "billing-assistant",
    "payments", "pipeline", "hr-assistant", "brand-new-agent",
])
def test_real_classes_are_shown(cls):
    assert not is_synthetic_identity(cls), cls


def test_synthetic_marker_wins_over_naming():
    assert is_synthetic_identity("load-generator", properties={"synthetic": True})
    assert is_synthetic_identity("load-generator", properties={"norviq.io/synthetic": "true"})
    assert not is_synthetic_identity("load-generator")


def test_classifier_parses_class_from_spiffe():
    assert is_synthetic_identity(None, "spiffe://norviq/ns/default/sa/evtrace-1")
    assert not is_synthetic_identity(None, "spiffe://norviq/ns/default/sa/customer-support")


# --------------------------------------------------------------------------------------------------
# ATLAS mapping correctness (names verified against atlas.mitre.org / MISP ATLAS galaxy)
# --------------------------------------------------------------------------------------------------

# Ground-truth official ATLAS names for the IDs we map (source: atlas.mitre.org + MISP misp-galaxy).
_OFFICIAL = {
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0054": "LLM Jailbreak",
    "AML.T0057": "LLM Data Leakage",
    "AML.T0053": "LLM Plugin Compromise",
    "AML.T0050": "Command and Scripting Interpreter",
    "AML.T0049": "Exploit Public-Facing Application",
    "AML.T0012": "Valid Accounts",
    "AML.T0055": "Unsecured Credentials",
    "AML.T0056": "LLM Meta Prompt Extraction",
    "AML.T0061": "LLM Prompt Self-Replication",
    "AML.T0024": "Exfiltration via ML Inference API",
    "AML.T0048": "External Harms",
    "AML.T0020": "Poison Training Data",
    "AML.T0018": "Backdoor ML Model",
    "AML.T0031": "Erode ML Model Integrity",
}


def _mapping() -> dict:
    return json.loads((Path(__file__).resolve().parents[2] / "policies" / "mitre_mapping.json").read_text())


def test_every_technique_name_matches_official_atlas():
    mapping = _mapping()
    for tid, info in mapping.items():
        assert tid in _OFFICIAL, f"{tid} not in the verified official table"
        assert info["name"] == _OFFICIAL[tid], f"{tid} name '{info['name']}' != official '{_OFFICIAL[tid]}'"


def test_every_technique_has_a_valid_scope_and_description():
    for tid, info in _mapping().items():
        assert info.get("scope") in ("enforceable", "out_of_scope"), f"{tid} missing/invalid scope"
        assert info.get("description"), f"{tid} missing description"


def test_mapping_has_all_three_states():
    mapping = _mapping()
    scopes = [i["scope"] for i in mapping.values()]
    # enforceable techniques with a mapped rule (enforced-capable) + enforceable without (gaps) + out-of-scope
    assert scopes.count("out_of_scope") >= 3
    enforceable = [i for i in mapping.values() if i["scope"] == "enforceable"]
    assert any(i["policies"] for i in enforceable), "expected some enforceable techniques WITH mapped rules"
    assert any(not i["policies"] for i in enforceable), "expected some enforceable GAP techniques (no rule yet)"


# --------------------------------------------------------------------------------------------------
# Coverage math + status derivation + evidence PDF + generate validation
# --------------------------------------------------------------------------------------------------

def test_evidence_pdf_is_valid():
    from norviq.api.routers.mitre import _evidence_pdf

    pack = {
        "framework": "MITRE ATLAS", "framework_id": "atlas",
        "namespace": None, "range": "24h", "generated_at": "2026-07-05T00:00:00+00:00",
        "coverage_pct": 70, "enforced": 7, "enforceable_total": 10, "gap": 3, "out_of_scope": 5,
        "blocked_over_range": 1240, "synthetic_excluded": 0,
        "controls": [{"technique_id": "AML.T0051", "name": "LLM Prompt Injection", "status": "enforced",
                      "blocked": 842, "enforcing_policies": ["llm01_prompt_injection"]}],
    }
    pdf = _evidence_pdf(pack)
    assert pdf.startswith(b"%PDF-1.4")
    assert pdf.rstrip().endswith(b"%%EOF")
    assert b"AML.T0051" in pdf
    # P4(a): the title reflects the pack's framework, not a hardcoded ATLAS.
    assert b"MITRE ATLAS Evidence Pack" in pdf
    # P4(b): no exclusion line when nothing was excluded.
    assert b"excluded" not in pdf


def test_evidence_pdf_titles_owasp_and_states_exclusion():
    """The OWASP export must be titled for OWASP (not mis-titled 'MITRE ATLAS'), and — matching the console's
    'real traffic only' promise — the PDF must state how many synthetic/simulated events were excluded."""
    from norviq.api.routers.mitre import _evidence_pdf

    pack = {
        "framework": "OWASP LLM Top 10 (2025)", "framework_id": "owasp",
        "namespace": None, "range": "24h", "generated_at": "2026-07-05T00:00:00+00:00",
        "coverage_pct": 60, "enforced": 6, "enforceable_total": 10, "gap": 4, "out_of_scope": 0,
        "blocked_over_range": 12, "synthetic_excluded": 7,
        "controls": [{"technique_id": "LLM01", "name": "Prompt Injection", "status": "enforced",
                      "blocked": 12, "enforcing_policies": ["llm01_prompt_injection"]}],
    }
    pdf = _evidence_pdf(pack)
    # the PDF content stream escapes '(' and ')', so match the paren-free segments of the title.
    assert b"OWASP LLM Top 10" in pdf
    assert b"Evidence Pack" in pdf
    assert b"MITRE ATLAS" not in pdf
    # · is U+00B7 → survives the latin-1 PDF encoding as a single byte 0xB7.
    assert "Real traffic only · 7 synthetic/simulated events excluded".encode("latin-1") in pdf


class _StubResult:
    def all(self):
        return []


class _StubSession:
    """Minimal async session: audit queries return nothing (0 activity), writes are no-ops — lets the coverage
    endpoint compute scope/status purely from the loaded rego with no real DB."""
    async def execute(self, *a, **k):
        return _StubResult()

    async def scalar(self, *a, **k):
        return None

    def add(self, *a, **k):
        return None

    async def commit(self):
        return None


class _StubLoader:
    def __init__(self, rego: str):
        # the enforced rules are present in the loaded rego blob under the cluster baseline
        self._policies = {"__cluster__:__baseline__": {"rego": rego}}


def _coverage_client(rego: str) -> TestClient:
    from norviq.api.db.session import get_session
    from norviq.api.auth import get_current_user
    from norviq.api.main import create_app

    app = create_app()
    app.state.loader = _StubLoader(rego)
    app.dependency_overrides[get_current_user] = lambda: {"role": "admin", "sub": "tester", "namespace": None}
    app.dependency_overrides[get_session] = lambda: _StubSession()
    return TestClient(app, raise_server_exceptions=False)


def test_coverage_scope_status_and_headline():
    # A rego blob that contains SOME of the enforced rules (prompt-injection + data-leakage), so those
    # techniques are "enforced" and other enforceable ones are "gap".
    rego = "package norviq.strict\n llm01_prompt_injection deny_shell_execution llm02_data_leakage base64_decoded_threat"
    client = _coverage_client(rego)
    resp = client.get("/api/v1/mitre/coverage?range=24h")
    assert resp.status_code == 200
    body = resp.json()
    by_id = {t["technique_id"]: t for t in body["techniques"]}
    # enforced (rule in the blob)
    assert by_id["AML.T0051"]["status"] == "enforced" and by_id["AML.T0051"]["scope"] == "enforceable"
    assert by_id["AML.T0057"]["status"] == "enforced"
    # T0055 now maps llm02_data_leakage (secret-read block — the rule its description always named), so the
    # blob covers it too; AML.T0049 (deny_sql_injection, not in the blob) is the gap example instead.
    assert by_id["AML.T0055"]["status"] == "enforced"
    # gap (enforceable but no rule in the blob)
    assert by_id["AML.T0049"]["status"] == "gap" and by_id["AML.T0049"]["scope"] == "enforceable"
    # out-of-scope (never counted)
    assert by_id["AML.T0024"]["status"] == "out_of_scope" and by_id["AML.T0024"]["scope"] == "out_of_scope"
    # headline: enforced / enforceable, OOS not counted
    assert body["enforced"] >= 3
    assert body["enforceable_total"] == sum(1 for t in body["techniques"] if t["scope"] == "enforceable")
    assert body["oos"] == sum(1 for t in body["techniques"] if t["scope"] == "out_of_scope")
    expected_pct = round(body["enforced"] / body["enforceable_total"] * 100)
    assert body["coverage_pct"] == expected_pct
    # OOS must NOT be inside the enforceable denominator
    assert body["enforceable_total"] + body["oos"] == len(body["techniques"])


class _ActivityStubSession:
    """Stub session that returns per-rule audit activity so the per-framework blocked math can be exercised.
    Distinguishes the two coverage queries by their SQL: the affected-class query selects `agent_class`."""

    def __init__(self, blocked_by_rule: dict[str, int], cls: str = "customer-support"):
        self._blocked = blocked_by_rule
        self._cls = cls

    async def execute(self, stmt, *a, **k):
        sql = str(stmt)
        # _activity_by_rule also selects framework (to drop redteam/synthetic events),
        # so distinguish the two queries by "framework" — only the activity query references it.
        if "framework" in sql:  # _activity_by_rule → (rule_id, decision, agent_class, framework, count)
            rows = [(rid, "block", self._cls, "", n) for rid, n in self._blocked.items()]
        else:  # _blocked_by_rule_class → (rule_id, agent_class, count)
            rows = [(rid, self._cls, n) for rid, n in self._blocked.items()]
        return _Rows(rows)

    async def scalar(self, *a, **k):
        return None

    def add(self, *a, **k):
        return None

    async def commit(self):
        return None


class _Rows:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows


def _coverage_client_with_activity(rego: str, blocked_by_rule: dict[str, int]) -> TestClient:
    from norviq.api.db.session import get_session
    from norviq.api.auth import get_current_user
    from norviq.api.main import create_app

    app = create_app()
    app.state.loader = _StubLoader(rego)
    app.dependency_overrides[get_current_user] = lambda: {"role": "admin", "sub": "tester", "namespace": None}
    app.dependency_overrides[get_session] = lambda: _ActivityStubSession(blocked_by_rule)
    return TestClient(app, raise_server_exceptions=False)


def _framework_rules(mapping: dict) -> set[str]:
    return {p for info in mapping.values() for p in info.get("policies", []) if p}


def test_f1_blocked_is_per_framework_distinct_rules_not_global():
    """Each framework's headline `blocked` = sum over ITS distinct mapped rule_ids (deduped), NOT the global
    audit total. ATLAS and OWASP show different, correct numbers; a rule in neither framework never leaks in; a
    rule mapped to several techniques of one framework is counted once."""
    atlas = _mapping()
    owasp = _owasp_mapping()
    atlas_rules = _framework_rules(atlas)
    owasp_rules = _framework_rules(owasp)
    # ATLAS has rules OWASP doesn't (e.g. cross_tenant_access) so their totals differ; a rule mapped to several
    # techniques of ONE framework (base64_decoded_threat ∈ OWASP LLM02 & LLM05) must be counted once (dedup).
    atlas_only = sorted(atlas_rules - owasp_rules)
    assert atlas_only, "fixture needs at least one ATLAS-only rule so the two frameworks differ"
    all_mapped = sorted(atlas_rules | owasp_rules)
    blocked = {r: (i + 1) * 10 for i, r in enumerate(all_mapped)}  # distinct block count per rule
    blocked["totally_unmapped_noise_rule"] = 9_999  # in NEITHER framework — must never be counted

    rego = "package p\n" + " ".join(all_mapped)  # every mapped rule is "loaded"
    client = _coverage_client_with_activity(rego, blocked)

    a = client.get("/api/v1/mitre/coverage?range=24h&framework=atlas").json()
    o = client.get("/api/v1/mitre/coverage?range=24h&framework=owasp").json()

    expected_atlas = sum(blocked[r] for r in atlas_rules)   # distinct set → each rule once
    expected_owasp = sum(blocked[r] for r in owasp_rules)
    assert a["blocked"] == expected_atlas
    assert o["blocked"] == expected_owasp
    assert a["blocked"] != o["blocked"], "the two frameworks must show DIFFERENT blocked totals"
    # the noise rule (mapped to neither) is excluded from BOTH
    assert a["blocked"] < 9_999 and o["blocked"] < 9_999
    # DEDUP proof: the naive per-technique sum double-counts a rule shared across an OWASP framework's techniques,
    # so the deduped headline is strictly smaller when such a rule exists (base64_decoded_threat ∈ LLM02 & LLM05).
    naive_owasp = sum(blocked.get(p, 0) for info in owasp.values() for p in info.get("policies", []))
    assert expected_owasp < naive_owasp, "distinct-rule headline must not double-count a multi-technique rule"


def test_generate_rejects_out_of_scope_and_synthetic():
    client = _coverage_client("package norviq.strict")
    # out-of-scope technique → 422
    r1 = client.post("/api/v1/mitre/coverage/generate",
                     json={"technique_id": "AML.T0024", "namespace": "default", "agent_class": "customer-support"})
    assert r1.status_code == 422
    # synthetic class → 422
    r2 = client.post("/api/v1/mitre/coverage/generate",
                     json={"technique_id": "AML.T0055", "namespace": "default", "agent_class": "evtrace-1"})
    assert r2.status_code == 422
    # unknown technique → 404
    r3 = client.post("/api/v1/mitre/coverage/generate",
                     json={"technique_id": "AML.T9999", "namespace": "default", "agent_class": "customer-support"})
    assert r3.status_code == 404


# --------------------------------------------------------------------------------------------------
# OWASP LLM Top 10 (2025) as a 2nd LIVE framework — real rego-computed coverage (follow-up)
# --------------------------------------------------------------------------------------------------

_OWASP_OFFICIAL = {
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


def _owasp_mapping() -> dict:
    return json.loads((Path(__file__).resolve().parents[2] / "policies" / "owasp_llm_mapping.json").read_text())


def test_owasp_mapping_matches_official_2025_names_and_scopes():
    m = _owasp_mapping()
    assert set(m) == set(_OWASP_OFFICIAL), "OWASP mapping must have exactly LLM01..LLM10:2025"
    for lid, info in m.items():
        assert info["name"] == _OWASP_OFFICIAL[lid], f"{lid} name '{info['name']}' != official"
        assert info["scope"] in ("enforceable", "out_of_scope")
        assert info.get("description")
    # the 4 model-lifecycle controls are out-of-scope (LLM03/04/08/09)
    oos = {lid for lid, i in m.items() if i["scope"] == "out_of_scope"}
    assert oos == {"LLM03:2025", "LLM04:2025", "LLM08:2025", "LLM09:2025"}


def test_owasp_coverage_is_real_rego_computed_not_the_mock():
    # Loaded rego has the four rules that make LLM01/02/05/06 enforced; LLM07/LLM10 have no rule → gaps.
    rego = "package norviq.strict llm01_prompt_injection llm02_data_leakage llm06_excessive_agency deny_shell_execution deny_sql_injection base64_decoded_threat"
    client = _coverage_client(rego)
    body = client.get("/api/v1/mitre/coverage?framework=owasp&range=24h").json()
    assert body["framework"] == "owasp"
    by = {t["technique_id"]: t["status"] for t in body["techniques"]}
    assert by["LLM01:2025"] == "enforced" and by["LLM02:2025"] == "enforced"
    assert by["LLM05:2025"] == "enforced" and by["LLM06:2025"] == "enforced"
    assert by["LLM07:2025"] == "gap" and by["LLM10:2025"] == "gap"      # real gaps (no rule), NOT the mock's enforced
    assert by["LLM03:2025"] == "out_of_scope"
    assert body["enforced"] == 4 and body["enforceable_total"] == 6 and body["coverage_pct"] == 67
    assert body["oos"] == 4  # shown, not counted


def test_atlas_still_works_and_unknown_framework_404():
    client = _coverage_client("package norviq.strict llm01_prompt_injection")
    atlas = client.get("/api/v1/mitre/coverage?framework=atlas").json()
    assert atlas["framework"] == "atlas" and atlas["techniques"][0]["technique_id"].startswith("AML.T")
    # default (no framework) == atlas
    default = client.get("/api/v1/mitre/coverage").json()
    assert default["framework"] == "atlas"
    # unknown framework → 404
    assert client.get("/api/v1/mitre/coverage?framework=nope").status_code == 404


def test_generate_works_for_owasp_gap():
    client = _coverage_client("package norviq.strict")
    # LLM01 is enforceable AND maps to a runtime rule (llm01_prompt_injection) → generate emits a
    # control-specific draft. (LLM07 is enforceable but maps to NO runtime rule → escalate, see below.)
    ok = client.post("/api/v1/mitre/coverage/generate",
                     json={"technique_id": "LLM01:2025", "namespace": "default", "agent_class": "customer-support", "framework": "owasp"})
    assert ok.status_code == 200 and ok.json()["draft_id"].startswith("dmitre")
    # a control with no runtime-expressible rule (empty mapping policies) ESCALATES — it is NOT
    # faked with a vacuous per-class deny-all.
    esc = client.post("/api/v1/mitre/coverage/generate",
                      json={"technique_id": "LLM07:2025", "namespace": "default", "agent_class": "customer-support", "framework": "owasp"})
    assert esc.status_code == 200 and esc.json()["status"] == "escalate" and esc.json()["draft_id"] is None
    # LLM03 is out-of-scope → 422
    oos = client.post("/api/v1/mitre/coverage/generate",
                      json={"technique_id": "LLM03:2025", "namespace": "default", "agent_class": "customer-support", "framework": "owasp"})
    assert oos.status_code == 422


def test_f3_framework_neutral_routes_match_mitre_and_alias_holds():
    """/api/v1/compliance/{framework}/* returns the same data as /mitre?framework=…; /mitre stays ATLAS-default
    (back-compat alias); an unknown framework in the path 404s."""
    rego = "package p\n llm01_prompt_injection deny_shell_execution llm02_data_leakage base64_decoded_threat"
    client = _coverage_client(rego)

    def strip_volatile(body: dict) -> dict:
        return {k: v for k, v in body.items() if k != "last_exported"}  # last_exported timing is non-deterministic

    for fw in ("atlas", "owasp"):
        neutral = client.get(f"/api/v1/compliance/{fw}/coverage?range=24h")
        legacy = client.get(f"/api/v1/mitre/coverage?range=24h&framework={fw}")
        assert neutral.status_code == 200 and legacy.status_code == 200
        assert strip_volatile(neutral.json()) == strip_volatile(legacy.json()), f"{fw} neutral==legacy"
        assert neutral.json()["framework"] == fw

    # /mitre/coverage with NO framework is still ATLAS byte-identical to /compliance/atlas/coverage
    default = client.get("/api/v1/mitre/coverage?range=24h")
    assert default.json()["framework"] == "atlas"
    assert strip_volatile(default.json()) == strip_volatile(client.get("/api/v1/compliance/atlas/coverage?range=24h").json())

    # trend + export neutral routes work; unknown framework in the path 404s
    assert client.get("/api/v1/compliance/owasp/trend?range=30d").status_code == 200
    assert client.get("/api/v1/compliance/owasp/export?range=24h&format=json").status_code == 200
    assert client.get("/api/v1/compliance/nope/coverage").status_code == 404
    # generate via the neutral route: the PATH framework wins over the body framework (LLM01 maps to a real
    # runtime rule → a control-specific draft, proving the path framework routed the mapping lookup)
    gen = client.post("/api/v1/compliance/owasp/generate",
                      json={"technique_id": "LLM01:2025", "namespace": "default",
                            "agent_class": "customer-support", "framework": "atlas"})
    assert gen.status_code == 200 and gen.json()["framework"] == "owasp" and gen.json()["status"] == "draft"


def test_f2_generate_is_control_scoped_and_traceable():
    """A generated draft is TAGGED with its framework + control and SCOPED to the given real
    class (LLM06 maps to real runtime rules → a control-specific draft)."""
    client = _coverage_client("package norviq.strict")
    r = client.post("/api/v1/mitre/coverage/generate",
                    json={"technique_id": "LLM06:2025", "namespace": "default",
                          "agent_class": "customer-support", "framework": "owasp"})
    assert r.status_code == 200
    b = r.json()
    assert b["status"] == "draft"
    assert b["cls"] == "customer-support"                        # scoped to the real class, NOT "default"
    assert b["framework"] == "owasp"
    assert b["technique_id"] == "LLM06:2025"
    assert b["control_name"] == "Excessive Agency"              # traceable to the originating control
    assert b["draft_id"].startswith("dmitre")
    # The draft carries the CONTROL's mapped rule_ids (traceability), not a generic toggle set.
    assert "llm06_excessive_agency" in b["mapped_rules"]


def test_f2_no_real_class_creates_no_vacuous_default_draft():
    """When there is genuinely no real affected/active class (empty audit, no explicit class), the endpoint
    refuses to emit a 'default' deny-all — it returns no_affected_classes and creates NOTHING."""
    client = _coverage_client("package norviq.strict")  # _StubSession → zero audit activity
    # LLM01 maps to a runtime rule, so generation reaches the class-resolution step (where, with no real
    # class, it must refuse a vacuous 'default' deny-all rather than escalate on the rule).
    r = client.post("/api/v1/mitre/coverage/generate",
                    json={"technique_id": "LLM01:2025", "namespace": "default", "framework": "owasp"})
    assert r.status_code == 200
    b = r.json()
    assert b["status"] == "no_affected_classes"
    assert b["draft_id"] is None
    assert "nothing to remediate" in b["message"].lower()


def test_comp_gen_01_two_controls_yield_different_control_specific_rego():
    """Two DIFFERENT controls for the SAME class produce DIFFERENT,
    control-specific rego — not a byte-identical per-class deny-all. Proven at the generator level +
    that each names its own control in a distinct remediation package."""
    from norviq.api.threat_intent import generate_remediation_rego

    sql = generate_remediation_rego("owasp", "LLM05:2025", "Improper Output Handling", "customer-support",
                                    ["deny_sql_injection", "base64_decoded_threat"])
    inj = generate_remediation_rego("owasp", "LLM01:2025", "Prompt Injection", "customer-support",
                                    ["llm01_prompt_injection"])
    assert sql != inj, "two different controls must NOT produce byte-identical rego"
    # Distinct per-control packages so drafts never collide, and the mapped rule appears in each.
    assert "package norviq.remediation.owasp.llm05_2025" in sql
    assert "package norviq.remediation.owasp.llm01_2025" in inj
    assert "deny_sql_injection" in sql and "deny_sql_injection" not in inj
    assert "llm01_prompt_injection" in inj and "llm01_prompt_injection" not in sql


def test_comp_gen_02_overlay_accumulates_controls_never_overwrites():
    """The per-class remediation overlay holds the UNION of EVERY applied
    control. A full-replace of the single "<class>__remediation__" key would drop earlier controls —
    flipping control B to 'enforced' while silently reverting control A to 'gap' (false coverage).
    Proven at the parse/union/render level: a manifest round-trips, and merging a second control keeps the
    first's rule (incl. an OWASP control id with a ':' — "LLM05:2025" — the manifest, not block-key parsing,
    is the source of truth)."""
    from norviq.api.threat_intent import (generate_remediation_rego, generate_remediation_overlay_rego,
                                          parse_remediation_controls, union_remediation_controls)

    draft_a = generate_remediation_rego("atlas", "AML.T0049", "Exploit Public-Facing Application", "data-analyst",
                                        ["deny_sql_injection"])
    draft_b = generate_remediation_rego("owasp", "LLM05:2025", "Improper Output Handling", "data-analyst",
                                        ["llm01_prompt_injection"])
    # each per-control draft carries a parseable manifest naming exactly its own control
    ca, cb = parse_remediation_controls(draft_a), parse_remediation_controls(draft_b)
    assert [c["control_id"] for c in ca] == ["AML.T0049"]
    assert [c["control_id"] for c in cb] == ["LLM05:2025"]  # colon id survives the manifest round-trip

    # apply A -> overlay {A}; then apply B ON TOP -> UNION {A, B}, not a replace
    overlay_a = generate_remediation_overlay_rego("data-analyst", ca)
    merged = union_remediation_controls(parse_remediation_controls(overlay_a), cb)
    overlay_ab = generate_remediation_overlay_rego("data-analyst", merged)

    assert {c["control_id"] for c in parse_remediation_controls(overlay_ab)} == {"AML.T0049", "LLM05:2025"}
    assert "deny_sql_injection" in overlay_ab, "control A's rule must SURVIVE control B being applied"
    assert "llm01_prompt_injection" in overlay_ab, "control B's rule must be present"
    # re-applying an already-present control is idempotent (union keyed by (framework, control_id))
    twice = union_remediation_controls(merged, ca)
    assert len(twice) == 2, "re-applying a control must not duplicate it"


def test_comp_gen_02_non_remediation_rego_is_left_untouched():
    """Safety: the accumulate path only recognizes regos carrying the compliance-remediation
    manifest. An arbitrary operator/guardrail rego parses to NO controls, so the apply path leaves it
    byte-identical (never rewrites a manual __remediation__-suffixed load into an empty overlay)."""
    from norviq.api.threat_intent import parse_remediation_controls

    assert parse_remediation_controls("package norviq.strict\n\ndefault decision = \"allow\"\n") == []
    assert parse_remediation_controls("") == []
    # a corrupt manifest line degrades to 'unrecognized' rather than raising
    assert parse_remediation_controls("# nrvq:remediation-manifest {not json") == []


def test_comp_gen_01_no_runtime_rule_escalates_not_faked():
    """A control whose mapping has NO runtime-expressible rule (empty policies) ESCALATES instead
    of emitting a generic deny-all — via the real endpoint (LLM07 = System Prompt Leakage, policies=[])."""
    client = _coverage_client("package norviq.strict")
    r = client.post("/api/v1/mitre/coverage/generate",
                    json={"technique_id": "LLM07:2025", "namespace": "default",
                          "agent_class": "customer-support", "framework": "owasp"})
    assert r.status_code == 200
    b = r.json()
    assert b["status"] == "escalate" and b["draft_id"] is None
    assert "bespoke" in b["message"].lower()  # message explains it needs a bespoke (non-auto-generatable) control


def test_f4_dedup_key_is_framework_control_class():
    """Re-generating the same control for the same class is idempotent (ONE draft id); two DIFFERENT controls
    for the same class produce TWO distinct drafts."""
    client = _coverage_client("package norviq.strict")

    def gid(tid):
        return client.post("/api/v1/mitre/coverage/generate",
                           json={"technique_id": tid, "namespace": "default",
                                 "agent_class": "customer-support", "framework": "owasp"}).json()["draft_id"]

    # LLM01 + LLM06 both map to runtime rules → both generate real drafts (LLM07/LLM10 escalate now).
    a1 = gid("LLM01:2025")
    a2 = gid("LLM01:2025")
    assert a1 == a2, "LLM01 twice for the same class must map to ONE draft id (idempotent)"
    b = gid("LLM06:2025")
    assert b != a1, "LLM01 and LLM06 for the same class must be TWO distinct drafts"


def test_comp_gen_01_batch_fans_out_over_techniques_and_reports_escalations():
    """Multi-select: generate-batch creates ONE control-specific draft per (technique × class),
    reuses the dedup key, and reports a no-rule control as an ESCALATION (not a draft) rather than aborting."""
    client = _coverage_client("package norviq.strict")
    # class_mode = a specific real class so the stub session (no audit activity) still scopes deterministically.
    r = client.post("/api/v1/mitre/coverage/generate-batch",
                    json={"technique_ids": ["LLM01:2025", "LLM06:2025", "LLM07:2025"],
                          "namespace": "default", "class_mode": "customer-support", "framework": "owasp"})
    assert r.status_code == 200
    b = r.json()
    assert b["requested"] == 3
    by_tid = {item["technique_id"]: item for item in b["results"]}
    # two with-rule controls → two DISTINCT control-specific drafts scoped to the chosen class
    assert by_tid["LLM01:2025"]["status"] == "draft" and by_tid["LLM06:2025"]["status"] == "draft"
    assert by_tid["LLM01:2025"]["cls"] == "customer-support"
    assert by_tid["LLM01:2025"]["draft_id"] != by_tid["LLM06:2025"]["draft_id"]
    # the no-rule control is surfaced as an escalation, and the rollup counts only the real drafts
    assert by_tid["LLM07:2025"]["status"] == "escalate"
    assert b["drafts_created"] == 2


def test_comp_gen_01_batch_all_mode_never_fabricates_a_default_draft():
    """Multi-select: class_mode="all" with no real affected/active class does NOT invent a vacuous
    'default' draft — each item honestly reports no_affected_classes, and nothing is created."""
    client = _coverage_client("package norviq.strict")  # _StubSession → no audit activity, no affected class
    r = client.post("/api/v1/mitre/coverage/generate-batch",
                    json={"technique_ids": ["LLM01:2025", "LLM06:2025"], "namespace": "default",
                          "class_mode": "all", "framework": "owasp"})
    assert r.status_code == 200
    b = r.json()
    assert b["drafts_created"] == 0
    assert all(item["status"] == "no_affected_classes" for item in b["results"])


class _MixedActivitySession:
    """Session returning a MIX of real + synthetic + red-team activity for one rule, so the evidence
    exclusion can be proven: only real events count toward observed/blocked, and the
    excluded total is reported."""

    def __init__(self, rule_id: str) -> None:
        self._rid = rule_id

    async def execute(self, stmt, *a, **k):
        sql = str(stmt)
        if "framework" in sql:  # _activity_by_rule → (rule_id, decision, agent_class, framework, count)
            rows = [
                (self._rid, "block", "customer-support", "", 5),   # REAL → counts
                (self._rid, "block", "evtrace-1", "", 4),          # synthetic identity → excluded
                (self._rid, "block", "billing-bot", "redteam", 3), # red-team framework → excluded
            ]
        else:  # _blocked_by_rule_class
            rows = [(self._rid, "customer-support", 5)]
        return _Rows(rows)

    async def scalar(self, *a, **k):
        return None

    def add(self, *a, **k):
        return None

    async def commit(self):
        return None


def test_evidence_excludes_synthetic_and_redteam_events_and_reports_the_count():
    """An audit-evidence pack counts REAL traffic only. Synthetic/probe
    identities and red-team framework events are excluded from observed/blocked, and the excluded count is
    surfaced so the pack can state the exclusion explicitly."""
    from norviq.api.db.session import get_session
    from norviq.api.auth import get_current_user
    from norviq.api.main import create_app

    atlas = _mapping()
    rid = next(iter(_framework_rules(atlas)))
    rego = "package p\n" + rid  # the rule is loaded → enforced

    app = create_app()
    app.state.loader = _StubLoader(rego)
    app.dependency_overrides[get_current_user] = lambda: {"role": "admin", "sub": "tester", "namespace": None}
    app.dependency_overrides[get_session] = lambda: _MixedActivitySession(rid)
    client = TestClient(app, raise_server_exceptions=False)

    body = client.get("/api/v1/mitre/coverage?range=24h&framework=atlas").json()
    # Only the 5 REAL blocks count — the 4 synthetic + 3 red-team are NOT in the headline.
    assert body["blocked"] == 5
    assert body["observed"] == 5
    # …and the pack states how many were excluded (4 synthetic + 3 red-team = 7).
    assert body["synthetic_excluded"] == 7
