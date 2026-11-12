# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""A policy labelled tighten-only must never allow a call a namespace-tier policy blocks.

The Visual Builder's "Tighten-only rules" mode and the New Policy composer emit a module whose default
is `allow` and whose rules only block, escalate or audit. Base tiers resolve by priority, so that allow
beat a lower-priority `namespace:<ns>` policy that blocked the call: a class policy at 100 that was only
meant to add a block switched off the namespace tier's block at 50.

These tests evaluate the generators' real output (tests/fixtures/builder_composition, pinned to the
TypeScript generators by ui/src/lib/builderCompositionFixtures.test.ts) through `OPAEvaluator.evaluate`
and the real `opa` binary. Only the stores around the evaluator are stubbed.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path

import pytest

from norviq.config import settings
from norviq.engine.composition import attached_builder_graph, declares_tighten_only, fnv1a_hex
from norviq.engine.evaluator import OPAEvaluator
from norviq.engine.trust.models import TrustResult
from norviq.sdk.core.events import AgentIdentity, ToolCallEvent
from norviq.sdk.core.trust import TrustScore

_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "builder_composition"
needs_opa = pytest.mark.skipif(shutil.which("opa") is None, reason="needs the opa binary")

NS = "default"
CLS = "support-agent"

# A namespace-tier policy that blocks one tool and allows the rest. Hand-written, like the shipped
# `policy-namespace-baseline.yaml` example, at a priority below the class policy's.
NS_TIER_REGO = """package norviq.custom.ns_default
default decision = "allow"
default rule_id = "ns_default_allow"
default reason = "namespace tier: allowed"
decision = "block" { input.tool_name == "export_data" }
rule_id = "ns_no_export" { input.tool_name == "export_data" }
reason = "namespace tier: export_data is blocked here" { input.tool_name == "export_data" }
"""


def _fixture(name: str) -> dict:
    return json.loads((_FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


@dataclass
class _Loader:
    _policies: dict

    async def load_from_db(self, namespace: str, agent_class: str) -> dict | None:
        return None

    async def namespaces_for_class(self, agent_class: str) -> list[str]:
        return sorted({k.split(":", 1)[0] for k in self._policies if k.split(":", 1)[1] == agent_class})


class _Cache:
    async def get_eval(self, *_a):
        return None

    async def set_eval(self, *_a) -> None:
        return None

    async def get_trust(self, _spiffe: str) -> TrustScore | None:
        return None

    async def set_trust(self, *_a) -> None:
        return None

    async def incr_call_count(self, *_a, **_k) -> int:
        return 1

    async def get_ns_settings(self, _namespace: str):
        return None


@pytest.fixture
def engine(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "opa_mode", "subprocess")
    ev = OPAEvaluator(_Cache())  # type: ignore[arg-type]

    async def _trust(*_a, **_k) -> TrustResult:
        return TrustResult(score=0.9, category="High", signals={}, weights={}, dominant_signal="",
                           recommendation="allow")

    async def _persist(*_a, **_k) -> None:
        return None

    monkeypatch.setattr(ev, "_compute_trust", _trust)
    monkeypatch.setattr(ev, "_persist_behavior", _persist)

    def bind(policies: dict) -> OPAEvaluator:
        ev.bind_loader(_Loader(policies))
        return ev

    return bind


def _event(tool: str, workload: str = "") -> ToolCallEvent:
    return ToolCallEvent(
        tool_name=tool, tool_params={},
        agent_identity=AgentIdentity(spiffe_id=f"spiffe://norviq/ns/{NS}/sa/{CLS}", namespace=NS,
                                     agent_class=CLS, workload=workload),
        session_id="composition-test",
    )


def _ns_tier(priority: int = 50) -> dict:
    return {f"{NS}:namespace:{NS}": {"rego": NS_TIER_REGO, "priority": priority}}


# --- recognition -------------------------------------------------------------------------------------


@pytest.mark.parametrize("path", sorted(_FIXTURES.glob("*.json")), ids=lambda p: p.stem)
def test_each_generated_module_is_recognised_as_its_fixture_says(path: Path) -> None:
    fx = json.loads(path.read_text(encoding="utf-8"))
    assert declares_tighten_only(fx["rego"]) is fx["tighten_only"]


def test_the_python_hash_is_the_builders_hash() -> None:
    """The fixtures were hashed by builderCompile.ts; an attached graph is read back only if they agree."""
    for name in ("rules_allow_default_class", "rules_block_default_class", "allowlist_class"):
        assert attached_builder_graph(_fixture(name)["rego"]) is not None, name
    assert fnv1a_hex("") == "811c9dc5"


def test_a_hand_edited_builder_module_is_not_recognised() -> None:
    """Detached from its graph, the module is hand-written rego and keeps priority semantics."""
    rego = _fixture("rules_allow_default_class")["rego"].replace(
        'default reason = "No builder rule matched"', 'default reason = "edited"')
    assert attached_builder_graph(rego) is None
    assert declares_tighten_only(rego) is False


def test_an_unreadable_graph_blob_is_not_recognised_and_says_so() -> None:
    """The blob sits in the header, outside the hashed body, so it can be damaged while the body still
    matches. The engine cannot tell the mode then; it keeps priority semantics and logs NRVQ-ENG-2072."""
    from structlog.testing import capture_logs

    rego = _fixture("rules_allow_default_class")["rego"].replace("# nrvq-builder-graph/v1: ey", "# nrvq-builder-graph/v1: !!")
    with capture_logs() as logs:
        assert declares_tighten_only(rego) is False
    assert [entry.get("code") for entry in logs] == ["NRVQ-ENG-2072"]


# --- the engine --------------------------------------------------------------------------------------


@needs_opa
async def test_a_namespace_tier_block_survives_a_tighten_only_class_policy(engine) -> None:
    """THE defect. Class policy at 100, namespace tier at 50 blocking export_data."""
    ev = engine({f"{NS}:{CLS}": {"rego": _fixture("rules_allow_default_class")["rego"], "priority": 100},
                 **_ns_tier(50)})
    decision = await ev.evaluate(_event("export_data"))
    assert (decision.decision, decision.rule_id) == ("block", "ns_no_export")


@needs_opa
async def test_a_tighten_only_class_policy_still_adds_its_own_block(engine) -> None:
    ev = engine({f"{NS}:{CLS}": {"rego": _fixture("rules_allow_default_class")["rego"], "priority": 100},
                 **_ns_tier(50)})
    decision = await ev.evaluate(_event("delete_record"))
    assert (decision.decision, decision.rule_id) == ("block", "support_no_delete")
    allowed = await ev.evaluate(_event("search_kb"))
    assert allowed.decision == "allow"


@needs_opa
async def test_the_composer_policy_is_tighten_only_too(engine) -> None:
    ev = engine({f"{NS}:{CLS}": {"rego": _fixture("composer_class")["rego"], "priority": 100}, **_ns_tier(50)})
    decision = await ev.evaluate(_event("export_data"))
    assert (decision.decision, decision.rule_id) == ("block", "ns_no_export")


@needs_opa
async def test_a_tighten_only_workload_policy_cannot_loosen_the_namespace_tier(engine) -> None:
    ev = engine({f"{NS}:deployment:checkout": {"rego": _fixture("rules_allow_default_workload")["rego"],
                                               "priority": 900},
                 **_ns_tier(50)})
    decision = await ev.evaluate(_event("export_data", workload="checkout"))
    assert (decision.decision, decision.rule_id) == ("block", "ns_no_export")


@needs_opa
async def test_an_audit_mode_tighten_only_policy_only_records_its_block(engine) -> None:
    """Kept a trial: its own block is softened, and it still cannot loosen the namespace tier."""
    ev = engine({f"{NS}:{CLS}": {"rego": _fixture("rules_allow_default_class")["rego"], "priority": 100,
                                 "enforcement_mode": "audit"},
                 **_ns_tier(50)})
    trial = await ev.evaluate(_event("delete_record"))
    assert trial.decision == "audit"
    assert trial.rule_id.endswith("support_no_delete")
    blocked = await ev.evaluate(_event("export_data"))
    assert (blocked.decision, blocked.rule_id) == ("block", "ns_no_export")


@needs_opa
async def test_a_policy_that_decides_still_wins_by_priority(engine) -> None:
    """Unchanged on purpose: an allowlist at 100 is written to decide for its class, and it allows export_data."""
    ev = engine({f"{NS}:{CLS}": {"rego": _fixture("allowlist_class")["rego"], "priority": 100}, **_ns_tier(50)})
    decision = await ev.evaluate(_event("export_data"))
    assert decision.decision == "allow"


@needs_opa
async def test_a_hand_edited_tighten_only_module_keeps_priority_semantics(engine) -> None:
    rego = _fixture("rules_allow_default_class")["rego"].replace(
        'default reason = "No builder rule matched"', 'default reason = "edited"')
    ev = engine({f"{NS}:{CLS}": {"rego": rego, "priority": 100}, **_ns_tier(50)})
    decision = await ev.evaluate(_event("export_data"))
    assert decision.decision == "allow"


@needs_opa
async def test_the_effective_stack_reports_the_tighten_only_policy_as_an_overlay(engine) -> None:
    """/policies/effective reads `_collect_candidates`; the console renders an overlay as tighten-only."""
    ev = engine({f"{NS}:{CLS}": {"rego": _fixture("rules_allow_default_class")["rego"], "priority": 100},
                 **_ns_tier(50)})
    by_key = {c["key"]: c for c in await ev._collect_candidates(_event("x"))}
    assert by_key[f"{NS}:{CLS}"].get("overlay") is True
    assert not by_key[f"{NS}:namespace:{NS}"].get("overlay")


# --- the server's blocks-only drafts -----------------------------------------------------------------
#
# A capability defense ("make Postgres delete-safe") and a compliance remediation are default-allow
# modules that only add blocks, and say "TIGHTEN-ONLY" in their headers. A capability draft is applied at
# the class key at the baseline's priority, 1, so as a base tier it lost to ANY namespace-tier policy at
# a higher priority: the namespace's allow discarded the block the draft was applied to add.


def _capability_rego() -> str:
    from norviq.api.threat_intent import generate_capability_rego

    return generate_capability_rego("postgres", "Postgres", CLS, ["delete"], ["drop_table"], "cap_no_delete",
                                    "Postgres deletes are blocked for this class", verb_frags=["drop"])


def test_the_servers_blocks_only_drafts_are_recognised_and_its_allowlist_is_not() -> None:
    from norviq.api.threat_intent import Intent, generate_intent_rego, generate_remediation_overlay_rego

    assert declares_tighten_only(_capability_rego()) is True
    overlay = generate_remediation_overlay_rego(CLS, [{"framework": "owasp", "control_id": "LLM06",
                                                       "control_name": "Excessive agency",
                                                       "rule_ids": ["llm06_excessive_agency"]}])
    assert declares_tighten_only(overlay) is True
    allowlist = generate_intent_rego(CLS, ["search_kb"], Intent())
    assert declares_tighten_only(allowlist) is False
    # ...and it no longer calls itself tighten-only: against a namespace tier, priority decides.
    assert "TIGHTEN-ONLY" not in allowlist
    assert "NOT tighten-only against a namespace- or workload-tier policy" in allowlist


@needs_opa
async def test_a_capability_block_survives_a_higher_priority_namespace_tier(engine) -> None:
    ns_allows_all = NS_TIER_REGO.replace('input.tool_name == "export_data"', 'input.tool_name == "__none__"')
    ev = engine({f"{NS}:{CLS}": {"rego": _capability_rego(), "priority": 1},
                 f"{NS}:namespace:{NS}": {"rego": ns_allows_all, "priority": 50}})
    decision = await ev.evaluate(_event("drop_table"))
    assert (decision.decision, decision.rule_id) == ("block", "cap_no_delete")


@needs_opa
async def test_a_capability_allow_does_not_undo_a_lower_priority_namespace_block(engine) -> None:
    ev = engine({f"{NS}:{CLS}": {"rego": _capability_rego(), "priority": 1}, **_ns_tier(0)})
    decision = await ev.evaluate(_event("export_data"))
    assert (decision.decision, decision.rule_id) == ("block", "ns_no_export")
