# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""`classify_tool` publishes ONE verb, and both baseline policies key egress on it.

`input.derived.verb` is the only handle a policy has on the capability classifier, so a verb the
classifier decides not to report is not merely under-displayed — it is unsayable. Two ways that
silence was reachable, both measured through real `opa` against the two shipped baselines:

* A more-destructive token elsewhere in the name outranked the egress token. Every exec/destroy token
  is CRITICAL and every egress token is HIGH, so `invoke_send_pipeline`, `run_export`, `exec_upload`,
  `run_publish`, `restart_sync` and `eval_dispatch` all reported `delete` and the credential left.
* Ordinary egress verbs were simply absent from the lexicon, so `deliver_report`, `transmit_payload`,
  `broadcast_alert` and friends reported `unknown` — which neither the fourteen name prefixes nor the
  webhook/exfil substrings rescue.

The cost side is tested here too. Widening what counts as a sink must not turn reads into refusals,
and the control-plane actuation grade must survive the re-ranking.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from norviq.engine.capability.source_registry import Verb, classify_tool
from norviq.engine.evaluator import OPAEvaluator
from norviq.engine.graph.models import RiskLevel

REPO_ROOT = Path(__file__).resolve().parents[2]
_OPA = shutil.which("opa")

# BOTH copies: this OPA cannot import across packages, so the horizontal policy ships as two guarded
# copies and `webhook/presets/strict.rego` is the one the bootstrap pushes as the cluster baseline.
POLICIES = {
    "comprehensive": REPO_ROOT / "comprehensive.rego",
    "strict (SHIPPED as the cluster baseline)": REPO_ROOT / "webhook" / "presets" / "strict.rego",
}

# The canonical AWS key pair the policy's own detectors match perfectly. Only the SINK NAME differs
# between cases — never the payload — so any difference in verdict is a difference in what the policy
# considers a sink.
CREDENTIAL_PAYLOAD = {
    "channel": "C0ATTACKER",
    "text": "deploy notes: AKIAIOSFODNN7EXAMPLE wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
}

# An exec/destructive token sharing the name with an egress token. Each of these leaked.
EXEC_SHADOWED_SINKS = [
    "invoke_send_pipeline", "run_export", "execute_export", "exec_upload",
    "run_publish", "restart_sync", "eval_dispatch",
]

# Ordinary vendor egress verbs that were missing from the SEND lexicon entirely.
UNLEXICONED_SINKS = [
    "deliver_report", "transmit_payload", "submit_form", "broadcast_alert",
    "escalate_case", "ship_logs", "outbound_message", "cc_manager", "bcc_audit", "egress_blob",
]


def _package(policy: Path) -> str:
    for line in policy.read_text(encoding="utf-8").splitlines():
        if line.startswith("package "):
            return line.split(None, 1)[1].strip()
    raise AssertionError(f"no package declaration in {policy}")


def _derived(tool_name: str, params: object) -> dict:
    class _Event:
        pass

    event = _Event()
    event.tool_name = tool_name
    event.tool_params = params
    event.agent_identity = None
    return OPAEvaluator.__new__(OPAEvaluator)._derived_input(event)


def _decide(policy: Path, tool_name: str, params: dict) -> tuple[str, str]:
    doc = {
        "tool_name": tool_name,
        "tool_params": params,
        "agent": {"namespace": "analytics", "agent_class": "support-agent"},
        "agent_identity": {"namespace": "analytics", "agent_class": "support-agent"},
        "derived": _derived(tool_name, params),
        "trust_category": "high",
    }
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "input.json"
        path.write_text(json.dumps(doc), encoding="utf-8")
        out = subprocess.run(
            ["opa", "eval", "-f", "raw", "--v0-compatible", "-d", str(policy), "-i", str(path),
             f"[data.{_package(policy)}.decision, data.{_package(policy)}.rule_id]"],
            capture_output=True, text=True, check=True,
        )
    decision, rule_id = json.loads(out.stdout.strip())
    return decision, rule_id


# ── the verb the classifier reports ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("tool_name", EXEC_SHADOWED_SINKS)
def test_an_exec_token_does_not_erase_the_send_evidence(tool_name: str) -> None:
    """The name literally contains `send`/`upload`/`publish`/`export`/`sync`/`dispatch`."""
    verb, _risk = classify_tool(tool_name)
    assert verb is Verb.SEND, f"{tool_name} reported {verb.value} — the egress evidence was discarded"


@pytest.mark.parametrize("tool_name", EXEC_SHADOWED_SINKS)
def test_the_critical_grade_the_exec_token_earned_is_kept(tool_name: str) -> None:
    """Reporting the egress verb must not downgrade the risk — the console still shows CRITICAL.

    Verb and risk are ranked separately for exactly this reason: the verb is what policy can act on,
    the risk is what the operator is shown.
    """
    _verb, risk = classify_tool(tool_name)
    assert risk is RiskLevel.CRITICAL


@pytest.mark.parametrize("tool_name", UNLEXICONED_SINKS)
def test_ordinary_egress_verbs_are_in_the_lexicon(tool_name: str) -> None:
    """`unknown` is a universal bypass for anything named unrecognisably — the evaluator says so."""
    verb, risk = classify_tool(tool_name)
    assert (verb, risk) == (Verb.SEND, RiskLevel.HIGH)


@pytest.mark.parametrize("tool_name", ["open_relay", "close_relay", "open_breaker", "set_valve"])
def test_control_plane_actuation_keeps_its_destructive_grade(tool_name: str) -> None:
    """An actuation noun under a control verb is a whole-NAME determination, not one token among many.

    `open_relay` is an electrical relay being thrown. `relay` is also an egress token, so ranking it
    as one more candidate would report an ICS command as `send` — losing the control-plane grade and
    feeding a physical actuation to the egress detectors.
    """
    assert classify_tool(tool_name) == (Verb.DELETE, RiskLevel.CRITICAL)


# A destruction verb standing next to an EGRESS NOUN. These are ordinary vendor tools — `delete_email`
# is Gmail's, `remove_webhook` is GitHub's and Slack's — and every one of them is a delete.
DESTRUCTION_BESIDE_AN_EGRESS_NOUN = [
    "delete_email", "delete_mail", "remove_email", "remove_webhook", "revoke_share", "expire_share",
    "purge_mail_queue", "invalidate_push_token", "delete_upload", "erase_post", "destroy_share",
    "truncate_export", "terminate_transfer", "drop_publish", "delete_export_job",
]


@pytest.mark.parametrize("tool_name", DESTRUCTION_BESIDE_AN_EGRESS_NOUN)
def test_an_egress_noun_does_not_erase_the_destruction_evidence(tool_name: str) -> None:
    """The mirror image of `test_an_exec_token_does_not_erase_the_send_evidence`, and the reason the
    fix is "demote the exec QUALIFIERS" rather than "SEND outranks DELETE".

    Ranking SEND above DELETE outright also fixes the seven exec-shadowed sinks — and takes every one
    of these with it. `verb` is unsayable in whichever direction it loses: reported as "send",
    `delete_email` tells the asset graph's per-verb inventory that an agent holding a mailbox-delete
    grant cannot delete, silences `tool-allowlist-perimeter.rego`'s "unlisted tool attempted a delete"
    reason, and gets refused under an egress refinement it has nothing to do with.
    """
    verb, risk = classify_tool(tool_name)
    assert verb is Verb.DELETE, f"{tool_name} reported {verb.value} — the destruction evidence was discarded"
    assert risk is RiskLevel.CRITICAL


@pytest.mark.parametrize("tool_name", ["run_query", "exec_search", "execute_sql", "invoke_lambda"])
def test_an_exec_qualifier_still_outranks_the_read_it_governs(tool_name: str) -> None:
    """The qualifier is demoted below SEND, NOT below everything.

    `run_query` executes arbitrary SQL; reporting it as `read` would hand it every read-only allowance
    in the product, including `read-only-intent-deny-by-default.rego`'s `verb == "read"` allow arm.
    """
    verb, risk = classify_tool(tool_name)
    assert (verb, risk) == (Verb.DELETE, RiskLevel.CRITICAL)


@pytest.mark.parametrize("tool_name,expected", [
    # Pinned so the re-ranking cannot quietly reclassify the single-verb names.
    ("aws_s3_delete", Verb.DELETE),
    ("execute_sql", Verb.DELETE),
    ("invoke_lambda", Verb.DELETE),
    ("terminate_pod", Verb.DELETE),
    ("delete_after_read", Verb.DELETE),
    ("s3_put_object", Verb.WRITE),
    ("rotate_key", Verb.WRITE),
    ("describe_instances", Verb.READ),
    ("gcs_bucket_list", Verb.READ),
    ("read_meter", Verb.READ),
    ("send_email", Verb.SEND),
    ("transfer_funds", Verb.SEND),
])
def test_single_verb_names_are_unchanged(tool_name: str, expected: Verb) -> None:
    assert classify_tool(tool_name)[0] is expected


def test_ambiguous_nouns_are_deliberately_absent_from_the_send_lexicon() -> None:
    """`route`/`stream`/`copy` are at least as often reads or intra-boundary writes.

    A SEND token beats a READ token, so registering them would reclassify `get_route`/`read_stream` as
    egress sinks and refuse them. The residual is real and deliberate; this pins the decision so it is
    revisited rather than drifted into.
    """
    for read_name in ("get_route", "list_route", "read_stream", "get_stream"):
        assert classify_tool(read_name)[0] is Verb.READ, read_name


# ── what the shipped policies actually decide ─────────────────────────────────────────────────────

pytestmark_opa = pytest.mark.skipif(
    _OPA is None,
    reason="needs the opa binary — a skipped rego test proves nothing and must not read as green",
)


@pytestmark_opa
@pytest.mark.parametrize("policy_name,policy", POLICIES.items(), ids=list(POLICIES))
@pytest.mark.parametrize("tool_name", EXEC_SHADOWED_SINKS + UNLEXICONED_SINKS)
def test_a_credential_is_refused_through_every_newly_classified_sink(
    tool_name: str, policy_name: str, policy: Path
) -> None:
    decision, rule_id = _decide(policy, tool_name, CREDENTIAL_PAYLOAD)
    assert (decision, rule_id) == ("block", "llm02_data_leakage"), (
        f"{tool_name} exfiltrated a credential through {policy_name}"
    )


@pytestmark_opa
@pytest.mark.parametrize("policy_name,policy", POLICIES.items(), ids=list(POLICIES))
@pytest.mark.parametrize("tool_name,params", [
    ("run_query", {"query": "select 1"}),
    ("search_kb", {"q": "how do I reset a password"}),
    ("read_thread", {"channel": "C123"}),
    ("get_order", {"order_id": "1"}),
    ("list_tickets", {"status": "open"}),
    ("describe_instances", {"region": "eu-west-1"}),
    ("get_route", {"route_id": "r1"}),
])
def test_reads_are_not_swept_up_by_the_wider_lexicon(
    tool_name: str, params: dict, policy_name: str, policy: Path
) -> None:
    """The cost side. Widening what counts as a sink must not turn a read into a refusal."""
    decision, _rule = _decide(policy, tool_name, params)
    assert decision == "allow", f"{tool_name} was newly refused by {policy_name}"
