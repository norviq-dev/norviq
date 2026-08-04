# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""One notion of "sink": the engine's classification and the policy's must not disagree.

Norviq classified `slack_post_message` as (SEND, HIGH) on the hot path and published it as
`input.derived.verb` — and then enforced against a DIFFERENT, narrower notion: three literal tool
names plus fourteen name PREFIXES in the baseline, and eighteen literals in the intent toggle.
`grep derived comprehensive.rego` returned nothing.

The disagreement was exploitable with one byte-identical payload, measured against the shipped policy
with real `opa`:

    send_email          -> ("block", "llm02_data_leakage")
    slack_post_message  -> ("allow", "default_allow")

`slack_post_message` does not START with `post_`; it starts with `slack_`. So the exfiltration path
was chosen by whichever SaaS the customer happens to use, and the sink's name belongs to the vendor
rather than the attacker.

These run the REAL policy through REAL opa. A unit test over the prefix list would have passed
throughout — the list was never wrong about itself, it was wrong about being the only list.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from norviq.engine.capability.source_registry import classify_tool
from norviq.engine.evaluator import OPAEvaluator

REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY = REPO_ROOT / "comprehensive.rego"

# The canonical AWS key pair the policy's own detectors match perfectly. Only the SINK differs
# between the cases below — never the payload — so any difference in verdict is a difference in what
# the policy considers an egress sink.
CREDENTIAL_PAYLOAD = {
    "channel": "C0ATTACKER",
    "text": "deploy notes: AKIAIOSFODNN7EXAMPLE wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
}

pytestmark = pytest.mark.skipif(
    subprocess.run(["which", "opa"], capture_output=True).returncode != 0,
    reason="needs the opa binary — a skipped rego test proves nothing and must not read as green",
)


def _derived(tool_name: str, params: object) -> dict:
    class _Event:
        pass

    event = _Event()
    event.tool_name = tool_name
    event.tool_params = params
    event.agent_identity = None
    return OPAEvaluator.__new__(OPAEvaluator)._derived_input(event)


def _decide(tmp_path: Path, tool_name: str, params: dict) -> tuple[str, str]:
    doc = {
        "tool_name": tool_name,
        "tool_params": params,
        "agent": {"namespace": "analytics", "agent_class": "support-agent"},
        "agent_identity": {"namespace": "analytics", "agent_class": "support-agent"},
        "derived": _derived(tool_name, params),
        "trust_category": "high",
    }
    input_path = tmp_path / "input.json"
    input_path.write_text(json.dumps(doc))
    out = subprocess.run(
        ["opa", "eval", "-f", "raw", "--v0-compatible", "-d", str(POLICY), "-i", str(input_path),
         "[data.norviq.strict.decision, data.norviq.strict.rule_id]"],
        capture_output=True, text=True, check=True,
    )
    decision, rule_id = json.loads(out.stdout.strip())
    return decision, rule_id


# Ordinary vendor / domain tool names the registry classifies as SEND and the literal lists miss.
VENDOR_SINKS = ["slack_post_message", "forward_ticket", "relay_case", "dispatch_report", "share_summary"]


@pytest.mark.parametrize("tool_name", VENDOR_SINKS)
def test_the_registry_already_calls_these_sinks(tool_name: str) -> None:
    """The premise. If this ever stops holding, the parity test below is passing for the wrong reason."""
    verb, _risk = classify_tool(tool_name)
    assert verb.value == "send"


@pytest.mark.parametrize("tool_name", VENDOR_SINKS)
def test_a_credential_is_refused_through_every_tool_the_engine_calls_a_sink(tmp_path: Path, tool_name: str) -> None:
    decision, rule_id = _decide(tmp_path, tool_name, CREDENTIAL_PAYLOAD)
    assert decision == "block", f"{tool_name} exfiltrated a credential — the sink lists disagree again"
    assert rule_id == "llm02_data_leakage"


def test_the_named_sink_still_blocks(tmp_path: Path) -> None:
    """The case that always worked — pinned so a change here is visible as a REGRESSION, not a fix."""
    assert _decide(tmp_path, "send_email", CREDENTIAL_PAYLOAD) == ("block", "llm02_data_leakage")


@pytest.mark.parametrize(
    "tool_name,params",
    [
        ("run_query", {"query": "select 1"}),
        ("search_kb", {"q": "how do I reset a password"}),
        ("read_thread", {"channel": "C123"}),
    ],
)
def test_reading_tools_are_not_swept_up(tmp_path: Path, tool_name: str, params: dict) -> None:
    """The cost side. Widening what counts as a sink must not turn every read into a refusal —
    including one whose text mentions the word "password"."""
    decision, _rule = _decide(tmp_path, tool_name, params)
    assert decision == "allow"
