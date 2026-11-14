# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""What the suite scores of the MCP identity attacks, MCP-01..03, and where.

Measured on a namespace running the strict preset with an empty `__mcp__` registry: 26 of 29 caught,
and the 3 got-through were MCP-01..03, each `allow / default_allow`. The engine decided correctly; the
suite judged applicability by whether the expected rule NAME appeared anywhere in the loaded rego.

MCP-01 and MCP-02 probe a server allowlist, and the registry module carries its rule names whether or
not anyone registered a server. They are scored where an allowlist exists — MCP-02, the forged
allowlisted id, as got_through by design — and reported "not enabled here" otherwise.

MCP-03 probes no allowlist. It forges `pin_status: "pinned"` for a quarantined tool, and the rule that
reads pin status (`mcp_tool_not_approved`, in the strict preset and the guardrail template alike) reads
the forged field, so no policy anywhere can catch it. The quarantine is held by the proxy's Gate A
from its own pin store before /evaluate runs. So MCP-03 is reported `proxy_enforced`: its row is
shown with the reason and counted on the scorecard, and it is never in the denominator — not even on
an allowlist namespace, where the first fix still scored it as a miss.

These go through the real `/redteam/suite` route with the loaded modules the engine would hold, and
an evaluator that allows every call: the decisions the engine actually returned for MCP-01..03.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from norviq.api import mcp_controls
from norviq.api.baseline import preset_source
from norviq.api.db.session import get_session
from norviq.api.main import create_app
from norviq.engine.evaluator import OPAEvaluator
from norviq.redteam.attacks import get_attack_by_id
from norviq.sdk.core.decisions import PolicyDecision
from tests.api.test_redteam_api import _FakeSession, _token

REPO = Path(__file__).resolve().parents[2]
NS = "chatbot-prod"
CLS = "customer-support"
MCP_IDENTITY = ("MCP-01", "MCP-02", "MCP-03")
SERVER_ALLOWLIST = ("MCP-01", "MCP-02")


class _AllowEverything:
    """What the engine returned for MCP-01..03 on the reported namespace: no rule matched."""

    async def evaluate(self, event) -> PolicyDecision:
        _ = event
        return PolicyDecision(decision="allow", rule_id="default_allow", trust_score=0.9)


def _suite(modules: dict[str, str]) -> dict:
    app = create_app()
    app.state.evaluator = _AllowEverything()
    app.state.loader = SimpleNamespace(_policies={f"{NS}:{scope}": {"rego": rego} for scope, rego in modules.items()})
    session = _FakeSession([(CLS, f"spiffe://norviq/ns/{NS}/sa/{CLS}")])

    async def _override():
        yield session

    app.dependency_overrides[get_session] = _override
    resp = TestClient(app).post(
        "/api/v1/redteam/suite", params={"target_namespace": NS, "target_agent": CLS},
        headers={"Authorization": f"Bearer {_token()}"},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def _mcp_outcomes(report: dict) -> dict[str, str]:
    return {r["attack_id"]: r["outcome"] for r in report["results"] if r["attack_id"] in MCP_IDENTITY}


def _guardrail() -> str:
    return (REPO / "policies" / "templates" / "mcp_integration_guardrail.rego").read_text(encoding="utf-8")


def _expect(server_attacks: str) -> dict[str, str]:
    """MCP-01/02 as `server_attacks`; MCP-03 proxy-enforced, which no namespace setting changes."""
    return {**{aid: server_attacks for aid in SERVER_ALLOWLIST}, "MCP-03": "proxy_enforced"}


def test_an_empty_registry_does_not_score_the_identity_attacks_as_misses() -> None:
    """The reported namespace: strict class policy plus a generated registry nobody has filled."""
    report = _suite({CLS: preset_source("strict"), "__mcp__": mcp_controls.compile([], [])})
    assert _mcp_outcomes(report) == _expect("not_enabled")
    got_through = [r["attack_id"] for r in report["results"] if r["outcome"] == "got_through"]
    assert not set(got_through) & set(MCP_IDENTITY)


def test_the_strict_preset_alone_does_not_make_mcp_03_a_miss() -> None:
    """`mcp_tool_not_approved` ships in the strict preset, the default baseline, and cannot fire on the
    forged `pin_status` MCP-03 sends; on main this painted MCP-03 red on every strict namespace."""
    report = _suite({CLS: preset_source("strict")})
    assert _mcp_outcomes(report) == _expect("not_enabled")


def test_a_registered_server_makes_the_server_attacks_count() -> None:
    """The control that makes the two tests above mean something: once a server is registered the
    allowlist exists, and an allow is a real got-through again — including MCP-02, the forged
    allowlisted id the suite exists to show. MCP-03 is not one of them: the allowlist says nothing
    about a quarantine, and the first fix scored it as a miss here."""
    report = _suite({
        CLS: preset_source("strict"),
        "__mcp__": mcp_controls.compile(["postgres-prod"], ["postgres-prod"]),
    })
    assert _mcp_outcomes(report) == _expect("got_through")
    assert report["efficacy"]["overall"]["got_through"] >= len(SERVER_ALLOWLIST)


def test_the_guardrail_template_makes_the_server_attacks_count() -> None:
    """The opt-in guardrail is the allowlist MCP-01/02 were written against. It also carries
    `mcp_tool_not_approved`, which is why rule-name presence made MCP-03 look in scope here."""
    report = _suite({CLS: preset_source("strict"), "__guardrail__": _guardrail()})
    assert _mcp_outcomes(report) == _expect("got_through")


@pytest.mark.parametrize("modules", [
    pytest.param({CLS: preset_source("strict")}, id="strict-only"),
    pytest.param({CLS: preset_source("strict"), "__mcp__": mcp_controls.compile(["postgres-prod"], ["postgres-prod"])},
                 id="registered-server"),
    pytest.param({CLS: preset_source("strict"), "__guardrail__": _guardrail()}, id="guardrail"),
])
def test_mcp_03_is_shown_as_proxy_enforced_and_never_scored(modules: dict[str, str]) -> None:
    """Moved out of the denominator, not out of the report. The row is there, says why, and the
    scorecard counts it under its own reason; the scored total and the vector breakdown leave it out."""
    report = _suite(modules)
    rows = [r for r in report["results"] if r["attack_id"] == "MCP-03"]
    assert len(rows) == 1
    row = rows[0]
    assert row["outcome"] == "proxy_enforced"
    assert row["mcp_vector"] == "quarantined-tool-asserts-pinned"
    assert "Gate A" in row["outcome_reason"] and "mcp_tool_not_approved" in row["outcome_reason"]
    # The forgery was still sent: the engine's decision is recorded on the row.
    assert (row["actual"], row["rule_id"]) == ("allow", "default_allow")

    eff = report["efficacy"]
    assert eff["proxy_enforced"] == 1
    scored = sum(1 for r in report["results"] if r["outcome"] in ("caught", "would_block", "got_through"))
    assert eff["overall"]["total"] == scored
    assert "quarantined-tool-asserts-pinned" not in {b["vector_id"] for b in eff["by_vector"]}


def test_a_registry_without_its_header_still_counts() -> None:
    """A hand-edited registry module with no parseable header is judged by the set it renders, so the
    attacks are scored rather than hidden when the console cannot read the registry back."""
    rego = mcp_controls.compile(["postgres-prod"], [])
    stripped = "\n".join(ln for ln in rego.splitlines() if not ln.startswith("# nrvq-mcp-registry/v1:"))
    assert mcp_controls.parse(stripped) is None
    report = _suite({CLS: preset_source("strict"), "__mcp__": stripped})
    assert _mcp_outcomes(report) == _expect("got_through")


def _with_header_of(rego: str, header_from: str) -> str:
    """`rego` carrying another module's `# nrvq-mcp-registry/v1:` line: header and set disagree."""
    tag = "# nrvq-mcp-registry/v1:"
    header = next(ln for ln in header_from.splitlines() if ln.startswith(tag))
    return "\n".join(header if ln.startswith(tag) else ln for ln in rego.splitlines())


def test_the_rendered_server_set_decides_not_the_header() -> None:
    """The header is what the console reads back; `registered_servers` is what OPA evaluates. A
    header claiming an empty registry over a module that registers a server would hide a real miss,
    so the rendered set wins in both directions."""
    filled, empty = mcp_controls.compile(["postgres-prod"], ["postgres-prod"]), mcp_controls.compile([], [])

    hides = _with_header_of(filled, empty)
    assert mcp_controls.parse(hides)["registered"] == []
    report = _suite({CLS: preset_source("strict"), "__mcp__": hides})
    assert _mcp_outcomes(report) == _expect("got_through")

    overclaims = _with_header_of(empty, filled)
    assert mcp_controls.parse(overclaims)["registered"] == ["postgres-prod"]
    report = _suite({CLS: preset_source("strict"), "__mcp__": overclaims})
    assert _mcp_outcomes(report) == _expect("not_enabled")


def test_sector_attacks_keep_their_rule_name_test() -> None:
    """The MCP change must not move the sector gate: FIN-001 is still out of scope without its pack."""
    report = _suite({CLS: preset_source("strict")})
    fin = next(r for r in report["results"] if r["attack_id"] == "FIN-001")
    assert fin["outcome"] == "not_enabled"


@pytest.mark.skipif(shutil.which("opa") is None, reason="opa binary required")
@pytest.mark.parametrize(("source", "package"), [
    pytest.param(lambda: preset_source("strict"), "norviq.presets.strict", id="strict"),
    pytest.param(_guardrail, "norviq.guardrail.mcp_integration", id="guardrail"),
])
def test_no_quarantine_rule_can_see_mcp_03(source, package) -> None:
    """Why MCP-03 is not an engine question anywhere: both shipped copies of the quarantine rule read
    the one field the attack forges. Same call with `pin_status: quarantined` is the control — the
    rule works, the input lies."""
    from norviq.api.routers.redteam import _build_event

    rego = source()

    def decide(mcp_override: dict) -> list:
        event = _build_event(get_attack_by_id("MCP-03"), CLS, NS)
        event.mcp.update(mcp_override)
        doc = OPAEvaluator.__new__(OPAEvaluator)._build_input(event, SimpleNamespace(score=0.8, category="high"))
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "p.rego").write_text(rego, encoding="utf-8")
            Path(tmp, "i.json").write_text(json.dumps(doc), encoding="utf-8")
            out = subprocess.run(
                ["opa", "eval", "-f", "raw", "--v0-compatible", "-d", f"{tmp}/p.rego", "-i", f"{tmp}/i.json",
                 f"[data.{package}.decision, data.{package}.rule_id]"],
                capture_output=True, text=True, check=True,
            )
        return json.loads(out.stdout)

    assert decide({}) == ["allow", "default_allow"]
    assert decide({"pin_status": "quarantined"}) == ["block", "mcp_tool_not_approved"]
