# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""Source capability registry.

The asset graph tells you an agent *calls a tool* that *reaches a data source*. That is
already-known info. The value this module adds is a model of what a SOURCE can *do* — the verb
surface a datastore / egress / object-store exposes — so the console can distinguish a read hop from a
destructive one, flag verbs that are reachable-but-unguarded (undefended), and flag grants that are
never exercised (dormant, a least-privilege gap).

Design (per the phased plan, decision c):
  * Model the SOURCE CLASS (datastore / egress / object-store) from day one so egress
    (send_email/webhook/upload — first-class agent-exfil risk, already in comprehensive.rego) and
    object-stores slot in without a refactor.
  * Ship Elasticsearch + PostgreSQL (wave 1). SMTP/webhook (egress) and S3 (object-store) are modelled
    here too but marked wave 2 — their verb specs exist so the classifier already works on them.
  * This module is PURE (no I/O, no graph coupling): callers pass in the sets of granted / observed /
    policy-referenced verbs and get back per-verb findings. That keeps it unit-testable and lets both
    the asset-graph and attack-graph routes reuse one classifier. The one read is a verb's ATLAS
    technique, which comes from the shared mapping file (cached) the first time it is asked for.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from norviq.api.framework_mapping import techniques_for_tool
from norviq.engine.confusables import skeleton
from norviq.engine.graph.models import RiskLevel


class SourceClass(str, Enum):
    """The kind of resource a data node represents. Drives which verbs are even meaningful."""

    DATASTORE = "datastore"        # queryable store: postgres, elasticsearch, mongo…
    EGRESS = "egress"              # outbound channel: smtp, webhook, http-post (data LEAVES)
    OBJECT_STORE = "object_store"  # blob store: s3, gcs, filesystem
    UNKNOWN = "unknown"


class Verb(str, Enum):
    """The abstract operation a tool performs against a source. The registry maps concrete tool-name
    fragments to these; severity/technique attach at the verb level, not the tool level."""

    READ = "read"      # search / get / list / query — reconnaissance & exfiltration-by-query
    WRITE = "write"    # insert / update / index / put — integrity risk (e.g. RAG-KB poisoning)
    DELETE = "delete"  # delete / drop / truncate / purge — availability / destruction
    SEND = "send"      # egress only: the act of transmitting data outward
    UNKNOWN = "unknown"


class CapabilityStatus(str, Enum):
    """Per-verb posture, worst-first. 'Open' verbs (undefended/observed-undefended) are the finding."""

    UNDEFENDED = "undefended"                # observed in traffic AND no policy rule guards it — live gap
    # Observed, and calls were logged as would-block, but none was stopped: a Monitor/audit-mode
    # namespace or policy softens block/escalate to `audit` and the call runs. Not DEFENDED (nothing
    # was enforced) and not UNDEFENDED ("author a rule" when one is already matching).
    MONITORED = "monitored"
    DORMANT_GRANT = "dormant_grant"          # granted/reachable but never exercised — least-privilege gap
    DEFENDED = "defended"                    # observed AND a policy rule references it — covered
    LATENT = "latent"                        # the source exposes it, but nothing grants/observes it — informational
    NOT_EXPOSED = "not_exposed"              # this source class doesn't have this verb


@dataclass(frozen=True)
class _VerbSpec:
    verb: Verb
    risk: RiskLevel
    label: str
    # Tool-name fragments (lowercased substring match) that indicate this verb.
    tool_fragments: tuple[str, ...]
    # Verb-specific remediation fragment ("… for {class}"), composed by callers into a full suggestion.
    fix: str

    @property
    def technique(self) -> str | None:
        """The ATLAS technique for this verb, read from the one mapping Red Team and Compliance read.

        The verb is resolved to the baseline rule that guards it the way a tool name is
        (`rule_for_tool`: `delete` is llm06_excessive_agency, `send` is llm02_data_leakage), and the
        technique is the first one the ATLAS table lists that rule under. None when no rule guards the
        verb; the UI then shows the label alone, never a made-up id. Each spec used to carry a literal:
        deletes under AML.T0048 External Harms, sends under AML.T0040 ML Model Inference API Access,
        index writes under AML.T0018 Backdoor ML Model, none of which Red Team or Compliance use for
        these rules. Resolved on read so the hot-path classifier never loads the mapping file.
        """
        found = techniques_for_tool(self.verb.value)
        return found[0][0] if found else None


@dataclass(frozen=True)
class _SourceSpec:
    source_type: str
    source_class: SourceClass
    display: str
    wave: int  # 1 = shipped/validated, 2 = modelled-but-not-yet-primary
    verbs: tuple[_VerbSpec, ...]


@dataclass
class VerbFinding:
    """One verb of one source, classified against the join of grants/observations/policy."""

    verb: Verb
    risk: RiskLevel
    technique: str | None
    label: str
    status: CapabilityStatus
    granted: bool
    observed: bool
    defended: bool
    recommendation: str = ""
    monitored: bool = False  # calls logged as would-block that ran (Monitor/audit) — never a defence

    def as_dict(self) -> dict[str, object]:
        return {
            "verb": self.verb.value,
            "risk": self.risk.value,
            "technique": self.technique,
            "label": self.label,
            "status": self.status.value,
            "granted": self.granted,
            "observed": self.observed,
            "defended": self.defended,
            "monitored": self.monitored,
            "recommendation": self.recommendation,
        }


# ── the registry ──────────────────────────────────────────────────────────────────────────────────
# No ATLAS id is written here: `_VerbSpec.technique` reads it from the shared mapping through the rule
# that guards the verb, and is None where no rule does (plain reads and writes).

_READ = _VerbSpec(
    Verb.READ, RiskLevel.LOW, "read / search",
    ("search", "read", "get", "list", "query", "fetch", "select", "scan"),
    "keep read-only and namespace-scoped",
)


def _es_specs() -> tuple[_VerbSpec, ...]:
    return (
        _READ,
        _VerbSpec(
            Verb.WRITE, RiskLevel.HIGH, "write / index (knowledge poisoning)",
            ("index", "write", "update", "put", "upsert", "bulk"),
            "block writes to the retrieval index — a poisoned KB steers every downstream agent",
        ),
        _VerbSpec(
            Verb.DELETE, RiskLevel.CRITICAL, "delete / drop (availability)",
            ("delete", "drop", "purge", "truncate", "clear"),
            "block destructive verbs — deletion of the index is an availability attack",
        ),
    )


def _pg_specs() -> tuple[_VerbSpec, ...]:
    return (
        _READ,
        _VerbSpec(
            Verb.WRITE, RiskLevel.HIGH, "write / update",
            ("insert", "write", "update", "put", "upsert", "modify"),
            "constrain writes to the intended tables/columns",
        ),
        _VerbSpec(
            Verb.DELETE, RiskLevel.CRITICAL, "delete / drop / truncate",
            ("delete", "drop", "truncate", "purge"),
            "block destructive SQL (DROP/DELETE/TRUNCATE) for this class",
        ),
    )


def _egress_specs() -> tuple[_VerbSpec, ...]:
    # Egress has one meaningful verb — the act of sending data outward is itself the risk (LLM02 /
    # exfiltration). comprehensive.rego already treats send_email/post_webhook/upload_file as external.
    return (
        _VerbSpec(
            Verb.SEND, RiskLevel.HIGH, "send / egress (data exfiltration)",
            ("send", "post", "upload", "publish", "webhook", "http", "email", "sms", "export"),
            "restrict egress to allowed destinations and scan payloads for secrets/PII",
        ),
    )


def _object_store_specs() -> tuple[_VerbSpec, ...]:
    return (
        _READ,
        _VerbSpec(
            Verb.WRITE, RiskLevel.HIGH, "put / upload",
            ("put", "write", "upload", "post"),
            "constrain object writes to intended buckets/prefixes",
        ),
        _VerbSpec(
            Verb.DELETE, RiskLevel.CRITICAL, "delete object",
            ("delete", "remove", "purge"),
            "block object deletion for this class",
        ),
    )


_REGISTRY: dict[str, _SourceSpec] = {
    "elasticsearch": _SourceSpec("elasticsearch", SourceClass.DATASTORE, "Elasticsearch", 1, _es_specs()),
    "postgresql": _SourceSpec("postgresql", SourceClass.DATASTORE, "PostgreSQL", 1, _pg_specs()),
    # Wave-2, modelled so the classifier already works when these sources appear:
    "smtp": _SourceSpec("smtp", SourceClass.EGRESS, "SMTP / email", 2, _egress_specs()),
    "webhook": _SourceSpec("webhook", SourceClass.EGRESS, "Webhook", 2, _egress_specs()),
    "s3": _SourceSpec("s3", SourceClass.OBJECT_STORE, "S3", 2, _object_store_specs()),
    "filesystem": _SourceSpec("filesystem", SourceClass.OBJECT_STORE, "Filesystem", 2, _object_store_specs()),
}

# Aliases: real deployments name the same source-type differently.
_ALIASES = {
    "postgres": "postgresql", "psql": "postgresql", "pg": "postgresql",
    "es": "elasticsearch", "opensearch": "elasticsearch",
    "mail": "smtp", "email": "smtp", "ses": "smtp",
    "http": "webhook", "https": "webhook",
    "gcs": "s3", "blob": "s3", "minio": "s3",
    "fs": "filesystem", "file": "filesystem",
}

_RISK_ORDER = {RiskLevel.LOW: 0, RiskLevel.MEDIUM: 1, RiskLevel.HIGH: 2, RiskLevel.CRITICAL: 3}


def source_type_of(data_uri: str) -> str:
    """The registry key for a data URI like 'postgresql/users' or 'es://kb' → 'postgresql'/'elasticsearch'.
    Returns '' when the source type is unknown (caller renders it as an unclassified source)."""
    if not data_uri:
        return ""
    head = data_uri.split("://", 1)[0] if "://" in data_uri else data_uri.split("/", 1)[0]
    head = head.strip().lower()
    if head in _REGISTRY:
        return head
    return _ALIASES.get(head, "")


def verb_of_tool(tool_name: str, source_type: str) -> Verb:
    """Best-effort verb for a concrete tool name against a source type (substring match on the source's
    verb fragments; DELETE/WRITE win over READ when a name matches several, so 'delete_record' isn't READ)."""
    spec = _REGISTRY.get(source_type)
    if not spec:
        return Verb.UNKNOWN
    name = (tool_name or "").lower()
    # Match most-destructive first so a name containing both (rare) resolves to the higher risk.
    for spec_verb in sorted(spec.verbs, key=lambda v: _RISK_ORDER[v.risk], reverse=True):
        if any(frag in name for frag in spec_verb.tool_fragments):
            return spec_verb.verb
    return Verb.UNKNOWN


# ── DYNAMIC, SOURCE-AGNOSTIC tool classification ──────────────────────────────────────────────────
# In a real k8s deployment a tool may hit ANY backend — AWS, Azure, GCS, an open-source service, a
# control-plane — with arbitrary names: aws_s3_DeleteObject, azure_blob_read, gcs.bucket.list,
# open_breaker, invoke_lambda, rotate_key, transfer_funds. classify_tool must identify what ANY of them
# DOES so the operator's allow/deny decision is informed. It does NOT rely on a fixed source registry.
#
# Approach (name-structural, not substring-soup):
#   1. TOKENIZE the name: split on non-alphanumerics AND camelCase (DeleteObject → [delete, object]),
#      lowercase. This avoids the classic substring bug (‘put’ inside ‘input’, ‘get’ inside ‘widget’) —
#      we match whole VERB TOKENS, not fragments.
#   2. Look each token up in a VERB LEXICON (token → (verb, risk)). Easily extended: add a token, done.
#   3. An ACTUATION noun (breaker/valve/relay/…) present with any control verb ⇒ critical control-plane.
#   4. When the name is inconclusive, optionally inspect tool_params (a SQL statement, an http/destination
#      field) to recover the operation.
#   5. Pick the WORST (most destructive) match. Unknown ⇒ (UNKNOWN, None) so the UI flags "review", never
#      silently "safe".

# token → (Verb, RiskLevel). Destruction/exec/actuation are CRITICAL (a security operator must never see a
# destructive capability mislabelled benign). Egress + writes are HIGH. Reads are LOW.
_VERB_LEXICON: dict[str, tuple[Verb, RiskLevel]] = {}


def _reg(verb: Verb, risk: RiskLevel, *tokens: str) -> None:
    for t in tokens:
        _VERB_LEXICON[t] = (verb, risk)


# destruction
_reg(Verb.DELETE, RiskLevel.CRITICAL,
     "delete", "del", "drop", "truncate", "purge", "destroy", "remove", "rm", "erase", "wipe", "revoke",
     "terminate", "kill", "deprovision", "teardown", "uninstall", "expire", "invalidate", "flush")
# code-exec / lifecycle (also critical — an exec is not a mere write).
#
# These are QUALIFIERS: they say the call is executed/started/stopped, not what it does to data.
# `run_export` is an export, `invoke_send_pipeline` is a send, `restart_sync` is a sync. Kept in their
# own named set because the verb ranking below has to treat them differently from a token that names
# the operation itself — see _enforcement_rank.
_EXEC_TOKENS = frozenset({
    "exec", "execute", "eval", "invoke", "run", "spawn", "shell", "sh", "bash", "cmd", "system",
    "actuate", "trip", "detonate", "fire", "launch", "reboot", "restart", "shutdown", "halt", "detach",
})
_reg(Verb.DELETE, RiskLevel.CRITICAL, *sorted(_EXEC_TOKENS))

# ...and of those, the three that name NO operation of their own. `run X`, `execute X`, `invoke X` all
# mean "carry out X": the token after them is the operation, and they add nothing to it. `run_query`
# runs a query exactly as `query`, `sql_query` and `read_query` do — all three already classified
# `read` — and ranking `run` above the read it governs made the verb of a SELECT depend on which
# synonym the tool's author picked. Measured, before this set existed: run_query, run_search,
# run_sql_query, run_lookup, execute_query, get_run_status and list_run_logs all reported `delete`, so
# a policy gating on `derived.verb == "delete"` refused them, and an admin promotion could not reach
# them because a resolved name beats a promotion (7.10).
#
# That rank was not worthless, though, and dropping it alone gave something away: its `delete` also
# refused every UPDATE/INSERT/GRANT/ALTER sent through run_query under the rules that ask for
# `verb == "read"`. So a qualifier that yields keeps `read` only when the payload is POSITIVELY a read,
# and fails closed to the pre-7.10 reading otherwise — see `_payload_write_signal` and the end of
# classify_tool.
#
# The rest of _EXEC_TOKENS are not qualifiers in this sense and keep their rank. `shell`, `bash`,
# `sh`, `cmd`, `eval`, `exec`, `spawn`, `system` name an interpreter the call hands a string to —
# that IS the operation, whatever the string is for, so `shell_get_env` stays a code execution. The
# lifecycle tokens (`restart`, `shutdown`, `launch`, …) are operations on a running system. The split
# is the one both baselines already draw: their `exec_name_tokens` (the names on which a shell
# metacharacter counts as injection) carry `exec`/`eval`/`shell` and deliberately not
# `run`/`execute`/`invoke`. Measured through both: a prose `;` in a note blocks `exec_report` and
# `shell_report` as `deny_shell_execution` and allows `run_report`, `execute_report`, `invoke_report`.
_RUN_QUALIFIERS = frozenset({"run", "execute", "invoke"})

# What a qualifier can be told to run that makes the call a code execution after all. Only consulted
# when a qualifier is present, so `get_script` / `get_command_invocation` (reads of a definition) are
# untouched; it keeps `run_command_get_output` and `execute_script_read_result` the exec they are
# instead of the read their trailing token would otherwise make them. The vocabulary is the baselines'
# `exec_name_tokens` that the lexicon above does not already carry, plus `script`/`code`/`program`,
# the commonest objects of `run_` in real tool names, and the plurals the tokenizer does not fold.
#
# Over-inclusion here can only keep a name at the classification it had before the qualifier rule —
# `run_code_search` still reports `delete` — never add a refusal; under-inclusion lets an executing
# tool with a read token in its name report `read`. So it errs wide.
#
# The second and third lines are the runtimes and the units of code they run. The first line alone
# left `run_python_get_output`, `run_javascript_get_result`, `run_powershell_get`, `run_node_list`,
# `run_sandbox_get_output`, `run_repl_read`, `run_cell_get_output`, `run_notebook_get_output`,
# `execute_process_read_output`, `execute_snippet_view` and `invoke_lambda_get_result` reporting
# `read` — each one runs code and hands back what it printed, which is exactly the shape the trailing
# read token disguises. `test` because a test suite is code the call runs: `run_load_test` read as a
# `load` (the lexicon's read token) and reported `read`.
_EXECUTION_OBJECTS = frozenset({
    "command", "commands", "script", "scripts", "code", "program", "programs",
    "subprocess", "terminal", "console", "zsh",
    "python", "python3", "js", "javascript", "typescript", "node", "nodejs", "deno", "powershell", "pwsh",
    "ruby", "perl", "php", "lua", "process", "processes", "kernel", "sandbox", "repl",
    "notebook", "notebooks", "cell", "cells", "snippet", "snippets", "lambda", "function", "functions",
    "test", "tests",
})
# writes / mutations
_reg(Verb.WRITE, RiskLevel.HIGH,
     "write", "update", "insert", "put", "upsert", "patch", "modify", "set", "create", "add", "append",
     "grant", "approve", "issue", "provision", "mint", "sign", "rotate", "enable", "disable", "configure",
     "register", "attach", "bind", "apply", "commit", "save", "store", "tag", "label")
# egress / exfiltration (data leaving)
#
# The second line is the same class of verb as the first, and its absence was not cosmetic: a tool the
# lexicon does not resolve gets `derived.verb == "unknown"`, and both baseline policies key their
# egress detector on `verb == "send"` — so `deliver_report`, `transmit_payload`, `broadcast_alert` and
# `escalate_case` carried a credential to `("allow", "default_allow")` through comprehensive.rego AND
# webhook/presets/strict.rego, measured. `cc`/`bcc`/`outbound`/`egress` are the mail- and
# network-vocabulary spellings of the same act.
#
# DELIBERATELY NOT ADDED: `route`, `stream`, `copy`. Each is at least as often a NOUN or a read in real
# tool names (`get_route`, `list_routes`, `read_stream`, `stream_logs`, `copy_object` within one
# bucket), and a SEND token beats a READ token in the ranking below — so adding them would reclassify
# ordinary reads as egress sinks and refuse them. `route_message`/`stream_events` therefore remain
# unresolved; that residual is real and is the reason this lexicon is not the only defence (the
# policies keep their name-prefix and substring bodies alongside `verb == "send"`).
#
# THE COST OF THE LINE ABOVE, MEASURED — and it is not zero. The ambiguity test applied to
# route/stream/copy was NOT applied to the tokens that were added, and several of them collide the
# same way. Through real `opa` against comprehensive.rego, each of these ordinary NON-egress tools
# carrying an ordinary pagination cursor under the key `token` went from ("allow", "default_allow") at
# the previous lexicon to ("block", "llm02_data_leakage"):
#
#   submit_job, submit_query, submit_batch   (`submit` is AWS Batch's / Databricks' verb for a job)
#   escalate_incident, escalate_ticket       (escalation is a workflow state change, not egress)
#   ship_order, deliver_package              (physical fulfilment — `ecommerce` is a shipped sector pack)
#   broadcast_config                         (a cluster-wide write)
#
# Kept anyway, and the direction is deliberate: this is a policy enforcement point, these are not
# reads (reads are the traffic whose over-refusal gets a baseline switched off, and they are pinned
# against in tests/engine/test_capability.py), and a missed credential sink is the worse error. But it
# is a real cost on real deployments, it is NOT the "no read tool was reclassified" that a sweep of
# repo identifiers suggests, and a narrower rule — `submit_form`/`ship_logs` as whole NAMES rather than
# `submit`/`ship` as tokens — would carry the audit's cases without it. Recorded so it is revisited.
_reg(Verb.SEND, RiskLevel.HIGH,
     "send", "post", "upload", "publish", "webhook", "email", "mail", "sms", "notify", "export",
     "transfer", "push", "sync", "forward", "relay", "emit", "dispatch", "share", "leak", "exfiltrate",
     "deliver", "transmit", "submit", "broadcast", "escalate", "ship", "outbound", "egress", "exfil",
     "cc", "bcc")
# reads (low)
_reg(Verb.READ, RiskLevel.LOW,
     "read", "get", "list", "search", "query", "fetch", "scan", "describe", "select", "lookup", "view",
     "show", "find", "count", "head", "exists", "meter", "monitor", "watch", "tail", "retrieve", "load",
     "peek", "download", "poll", "check", "inspect", "status")

# actuation NOUNS — with a control verb (open/close/set/toggle) these mean a physical/control-plane command.
_ACTUATION_NOUNS = {"breaker", "valve", "relay", "switch", "actuator", "damper", "motor", "pump", "throttle",
                    "circuit", "grid", "turbine", "reactor", "solenoid", "contactor"}
_CONTROL_VERBS = {"open", "close", "toggle", "set", "adjust", "override", "reset", "engage", "disengage"}

_VERB_ORDER = {Verb.DELETE: 3, Verb.SEND: 2, Verb.WRITE: 1, Verb.READ: 0, Verb.UNKNOWN: -1}

# Which verb a name that matched SEVERAL tokens is reported as. NOT the same ordering as risk — see
# classify_tool. It agrees with _VERB_ORDER on the operation tokens (destruction is still the worst
# thing a name can say); the whole re-ranking lives in _enforcement_rank, which demotes the EXEC
# QUALIFIERS below SEND without demoting the destruction tokens with them.
_ENFORCEMENT_ORDER = {Verb.DELETE: 4, Verb.SEND: 3, Verb.WRITE: 1, Verb.READ: 0, Verb.UNKNOWN: -1}

# An exec token ranks between SEND and WRITE: below the egress token it merely accompanies
# (`run_export` is an export), above a read or write it governs (`shell_get_env` hands a string to a
# shell and is not a read).
_EXEC_QUALIFIER_RANK = 2

# A RUN qualifier (`_RUN_QUALIFIERS`) ranks below every token that names an operation, READ included:
# it is the reported verb only when nothing else in the name says what is being run — `run`,
# `run_report`, `run_job`, `execute_sql`, `invoke_lambda` — and there it is still `delete`/critical,
# because a name that says "something is executed" and nothing more must not read as harmless. Below
# _ENFORCEMENT_ORDER's READ (0); UNKNOWN shares the number but is never a match.
_RUN_QUALIFIER_RANK = -1


def _enforcement_rank(verb: "Verb", token: str | None, executes_code: bool) -> int:
    """How strongly this single match claims the right to BE the reported verb.

    `token` is the name token that matched, or None for a match recovered from the payload.
    `executes_code` is whether the name ALSO says the thing being run is code (_EXECUTION_OBJECTS).

    An exec token is evidence about how the call runs, not about what it does, so it must not outrank
    a token that names the operation. Ranking it as a full DELETE is what erased the send evidence;
    ranking SEND above DELETE outright (the first attempt at this fix) instead erased the DELETE
    evidence for every ordinary `delete_email` / `remove_webhook` / `revoke_share`, which the console's
    capability inventory and the perimeter template's "attempted a delete" reason both read.

    A run qualifier goes one step further down, beneath READ, for the reason recorded on
    _RUN_QUALIFIERS — unless the name says it runs code, in which case it is an exec token like any
    other and keeps that rank.
    """
    if token in _RUN_QUALIFIERS and not executes_code:
        return _RUN_QUALIFIER_RANK
    if token in _EXEC_TOKENS:
        return _EXEC_QUALIFIER_RANK
    return _ENFORCEMENT_ORDER[verb]

_CAMEL_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def _tokenize_tool(name: str) -> list[str]:
    """Split a tool name into lowercased word tokens on non-alphanumerics AND camelCase boundaries, so
    'aws_s3_DeleteObject', 's3:DeleteObject', 'delete-record' all yield ['delete', …]. Whole-token matching
    avoids substring false positives ('put' in 'input', 'get' in 'budget').

    TOKENISED FROM THE CONFUSABLE SKELETON (F-046). The evaluator already computes `skeleton(name)` for
    Rego name-matching but classified the RAW name here, so the two disagreed on exactly the input an
    attacker controls: with `deny { input.derived.verb == "delete" }` in force, `delete_records` and the
    synonym `remove_records` both blocked while `dеlete_records` — one Cyrillic е — classified UNKNOWN
    and was not caught by the verb rule at all. Folding here rather than at the call sites means every
    consumer of the classification agrees, which is the property that was missing.

    Only names containing confusables change: a pure-ASCII name is its own skeleton, so this cannot move
    an existing classification. It is also strictly tightening — a homoglyph name that resolved to
    nothing now resolves to what it is impersonating.

    Deliberately NOT extended to leetspeak (`de1ete_records`). `skeleton()` is Unicode-TR39-aligned, and
    folding digits to letters would mean `s3_get_object` and `md5_hash` no longer tokenise as themselves
    — a change to ordinary vendor names in exchange for one evasion. See F-046's note in FINDINGS.
    """
    # ORDER IS LOAD-BEARING: camelCase split FIRST, skeleton SECOND. `skeleton()` casefolds, and
    # `_CAMEL_RE` finds boundaries by looking for an uppercase letter — so folding first erases every
    # boundary. Measured over a 36-name corpus when it was written the wrong way round:
    # `aws_s3_DeleteObject` -> ['aws','s3','deleteobject'] and stopped classifying as `delete`, along
    # with `chat.postMessage`, `SES:SendRawEmail`, `getMail` and `sendEmail`. That is the camelCase
    # argument recorded in strict.rego reappearing here, in the direction that loses enforcement.
    spaced = skeleton(_CAMEL_RE.sub(" ", name or ""))
    return [t.lower() for t in re.split(r"[^A-Za-z0-9]+", spaced) if t and not t.isdigit()]


def _classify_params(tool_params: object) -> tuple[Verb, RiskLevel] | None:
    """Recover the operation from tool_params when the NAME is inconclusive: a SQL statement's leading verb,
    or an egress signal (a destination/recipient/url field). Best-effort, string-walking, None if nothing."""
    if not isinstance(tool_params, dict):
        return None
    egress_keys = {"destination", "recipient", "to", "url", "endpoint", "webhook", "email", "callback"}
    for key, val in tool_params.items():
        if isinstance(key, str) and key.lower() in egress_keys:
            return Verb.SEND, RiskLevel.HIGH
        if isinstance(val, str):
            low = val.strip().lower()
            if low.startswith(("drop ", "delete ", "truncate ")) or "; drop" in low or "; delete" in low:
                return Verb.DELETE, RiskLevel.CRITICAL
            if low.startswith(("insert ", "update ", "merge ", "alter ", "create ")):
                return Verb.WRITE, RiskLevel.HIGH
            if low.startswith("select "):
                return Verb.READ, RiskLevel.LOW
            if low.startswith(("http://", "https://")):
                return Verb.SEND, RiskLevel.HIGH
    return None


# ── Is the payload POSITIVELY a read? (BACKLOG 7.10, fail-closed) ─────────────────────────────────
#
# A run qualifier that yielded to a read token (`run_query`, `execute_query`, `run_cypher_query`) may
# report `read` ONLY when the payload proves it: no string anywhere carries a statement/mutation
# keyword. Anything else keeps the pre-7.10 reading — DELETE/critical for a destructive keyword,
# WRITE for any other mutation keyword — so nothing 90b9f49 (every run_* = delete) blocked is allowed
# now unless it is genuinely a read.
#
# WHY A KEYWORD DENY-LIST AND NOT A STATEMENT READER. The first cut of this fix enumerated the write
# SHAPES it recognised (UPDATE needs SET, DROP needs an object kind, …) and fell to `read` on anything
# it did not recognise. An independent review ran the gap on a real PostgreSQL 16 and on three MCP
# dialects: `SELECT '--'; /* x */UPDATE/**/users/**/SET/**/role='admin'`, `DO E'…EXECUTE …'`,
# `WITH x AS (UPDATE … RETURNING 1) SELECT 1`, `DELETE customers` (T-SQL, no FROM), `INSERT … SET`
# (MySQL), LOAD/REASSIGN/IMPORT/SHUTDOWN/KILL/BULK/RESTORE/BACKUP/INSTALL/RESET/PURGE, Cypher
# `MATCH … DETACH DELETE`, GraphQL `mutation { deleteUser }`, Mongo `deleteMany`, an ES `script` — all
# EXECUTED as writes and all classified `read`, then allowed by the three `verb == "read"` controls.
# A reader that enumerates writes fails open on the write it has not yet seen. So the test is inverted:
# prove READ, deny everything else. The proof does not depend on parsing SQL — a keyword appearing
# ANYWHERE, inside a comment or a literal or a `$$…$$` body, is enough to deny.
#
# TOKENS. Each string is split on non-alphanumerics and camelCase boundaries, and the token set is
# checked. Underscore is NOT a split boundary, deliberately against the letter of the review: splitting
# it reclassifies the review's own keep-as-read columns `update_count`, `result_set`, `delete_flag` and
# the delivery column `drop_off`, whose segments are keywords. Kept whole they do not match, while the
# camelCase split still catches `deleteMany`/`findOneAndUpdate`/`bulkWrite` and the non-alphanumeric
# split still catches `/**/UPDATE/**/`, `DETACH DELETE` and `mutation {`. The few ES REST endpoints
# that carry a leading-underscore keyword (`_update`, `_delete_by_query`, `_bulk`) are listed as whole
# tokens, and KEYS are scanned as well as values, so the ES `script` operator (a key, with no keyword
# in its value) is caught. Residual, accepted: a write verb packed into a single snake_case value with
# no camelCase, no delimiter and not an ES endpoint (`force_update_now`) reads as a read — but real SQL
# and real API payloads carry delimiters, and the key/camelCase paths cover the real operation names.
#
# PRECISION, STATED. Past-tense column words (`created`, `updated`, `deleted`) are not the keywords
# (`create`, `update`, `delete`), so `created_at`/`updated_at`/`deleted` stay read. `settings`,
# `description`, `mindset`, `payload`, `download`, `address` are single tokens that are not keywords.
# The cost, accepted and matching 90b9f49's own behaviour for these names: a SELECT with a standalone
# keyword WORD in a literal (`WHERE subject = 'login; password reset'` → `reset`; `FOR UPDATE` →
# `update`), and free-text search prose carrying a keyword (`"how do I reset…"`, `"call mom"`) classify
# non-read. None is a regression against 90b9f49, which classified every run_* name delete regardless
# of payload; it is a loss of the precision the first (failed) cut bought by failing open.
#
# WHAT STAYS READ AND IS NOT CHECKED. `query` / `sql_query` (no run qualifier) report `read` whatever
# they carry — the pre-existing limit of a name classifier, and why the SQL-allowlist template exists.
# A base64-wrapped statement is not decoded here (the baselines' base64 detector covers the shell case).

# Destructive statement keywords -> delete/critical (the pre-7.10 reading for a run_<read> name).
_PAYLOAD_DESTRUCTIVE = frozenset({
    "delete", "drop", "truncate", "destroy", "remove", "purge", "erase", "wipe", "revoke", "kill",
    "shutdown", "reassign", "detach", "terminate", "deprovision", "discard", "flush", "reconfigure",
    "dbcc", "restore", "backup", "reset", "exec", "execute", "call", "do", "sp", "xp",
    "_delete_by_query", "delete_by_query",
})
# Other mutation keywords -> write. Covers SQL DML/DDL/DCL, Cypher, GraphQL, Mongo and ES write ops.
_PAYLOAD_WRITE = frozenset({
    "update", "insert", "set", "create", "alter", "merge", "replace", "upsert", "copy", "load",
    "grant", "into", "lock", "notify", "vacuum", "cluster", "reindex", "refresh", "comment", "rename",
    "install", "import", "bulk", "add", "modify", "write", "mutation", "script",
    "_update", "_bulk", "_update_by_query", "update_by_query",
})
_PAYLOAD_KEYWORDS = _PAYLOAD_DESTRUCTIVE | _PAYLOAD_WRITE
# The longest keyword decides: `_delete_by_query` is destructive even though it contains `delete`.


_HAS_UPPER_RE = re.compile(r"[A-Z]")


def _payload_tokens(text: str) -> set[str]:
    """Lowercased tokens of one string: split on camelCase boundaries and on every non-alphanumeric
    run EXCEPT underscore, which stays inside a token (so `update_count` is one token, `deleteMany` is
    two). Whole snake_case tokens are also returned, so a listed endpoint like `_delete_by_query` can
    match as itself."""
    # The camelCase pass only matters when there is an uppercase letter; the `[A-Z]` test short-circuits
    # (C-level) so an all-lowercase payload — the common and the large case — takes a single split.
    spaced = _CAMEL_RE.sub(" ", text) if _HAS_UPPER_RE.search(text) else text
    return {t.lower() for t in re.split(r"[^A-Za-z0-9_]+", spaced) if t}


def _payload_write_signal(tool_params: object) -> "Verb | None":
    """The strongest write signal in ANY string of `tool_params` — keys and values, at any depth — or
    None when no string carries a statement/mutation keyword (the payload is positively a read).

    Iterative with a visited set, so a deeply nested body cannot raise RecursionError on the enforcement
    path and an in-process caller's self-referencing dict cannot spin it."""
    worst: Verb | None = None
    stack: list[object] = [tool_params]
    seen: set[int] = set()
    while stack:
        node = stack.pop()
        if isinstance(node, (dict, list, tuple)):
            if id(node) in seen:
                continue
            seen.add(id(node))
        if isinstance(node, str):
            toks = _payload_tokens(node)
            if toks & _PAYLOAD_DESTRUCTIVE:
                return Verb.DELETE
            if worst is None and toks & _PAYLOAD_WRITE:
                worst = Verb.WRITE
        elif isinstance(node, dict):
            for k, v in node.items():
                if isinstance(k, str):
                    ktoks = _payload_tokens(k)
                    if ktoks & _PAYLOAD_DESTRUCTIVE:
                        return Verb.DELETE
                    if worst is None and ktoks & _PAYLOAD_WRITE:
                        worst = Verb.WRITE
                stack.append(v)
        elif isinstance(node, (list, tuple)):
            stack.extend(node)
    return worst


def classify_tool(tool_name: str, tool_params: object = None) -> tuple[Verb, RiskLevel | None]:
    """Dynamic (verb, risk) for ANY tool — cloud, opensource, control-plane — with no source-registry
    dependency. Tokenizes the name, matches whole verb tokens against the lexicon, recognises control-plane
    actuations, and falls back to inspecting tool_params. Returns the WORST RISK found paired with the
    most consequential VERB, or (UNKNOWN, None) when genuinely inconclusive (the UI then flags it
    'unclassified — review', never 'safe'). Extend by adding a token to the lexicon — the classifier
    stays dynamic and data-driven.

    RISK AND VERB ARE RANKED SEPARATELY, and that is the whole point of the two loops below.

    Ranking both by risk together — `max(matches, key=(risk, verb))` — silently DISCARDED the send
    evidence whenever a more-destructive token shared the name, because every exec/destroy token is
    CRITICAL and every egress token is HIGH. `invoke_send_pipeline` classified (DELETE, CRITICAL); so
    did `run_export`, `exec_upload`, `run_publish`, `restart_sync`, `eval_dispatch`. `derived.verb` was
    then "delete", both baseline policies' `egress_verb_tool { derived.verb == "send" }` was false, and
    an AWS key went out through all seven names as ("allow", "default_allow") — the exact vendor-named
    sink the prefix list already missed.

    `verb` is published as ONE value and is the only handle a policy has on this classification, so a
    verb that loses the ranking is not under-displayed — it is UNSAYABLE. That cuts BOTH ways, and the
    fix is not "SEND outranks DELETE".

    What actually shadowed the egress evidence is that the exec tokens are QUALIFIERS. `run`, `invoke`,
    `exec`, `eval`, `restart` say the call is executed, not what it does to data — so `run_export` is an
    export and `restart_sync` is a sync, and letting the qualifier BE the verb throws away the only
    token in the name that named an operation. Demoting the qualifier is therefore enough, and it is all
    that is done: `_EXEC_TOKENS` rank below SEND (the token they accompany) but still above READ and
    WRITE (`shell_get_env` is a shell, not a read).

    The three RUN qualifiers go further, beneath READ: `run`/`execute`/`invoke` name no operation at
    all, so `run_query` is the query it runs and `run_update` the update. Ranking `run` above READ
    bought a `delete` verb on every `run_<read>` tool and no way for an admin promotion to correct it
    (BACKLOG 7.10). A qualifier with nothing to govern (`run`, `run_report`, `execute_sql`), or
    governing code (`run_command_get_output`), keeps the exec reading.

    What the old rank DID buy, and must not be given back with it: `run_query` executes whatever
    statement it is handed, so its `delete` refused an UPDATE, INSERT, GRANT or ALTER sent through it
    under every rule that asks for `verb == "read"` (the read-only intent template's allow arm, the MCP
    registry's and the integration guardrail's unapproved-write rules). The baselines' destructive-SQL
    detector does not replace that: it knows DROP/DELETE/TRUNCATE and nothing that merely writes. So a
    run qualifier that yielded to a READ keeps that `read` ONLY when the payload is POSITIVELY a read —
    no statement/mutation keyword in any string, keys or values, at any depth (`_payload_write_signal`).
    Anything else FAILS CLOSED to the pre-7.10 reading: a destructive keyword -> delete, any other
    mutation keyword -> write. A select through `run_query` stays `read`; an UPDATE is `write`; a DROP,
    a Cypher `DETACH DELETE`, a GraphQL `mutation { deleteUser }` or a comment-obfuscated
    `/* x */UPDATE/**/SET` is delete or write and refused. A qualifier that already resolved to WRITE
    (`run_update`) is only ever RAISED by the payload (a DROP makes it delete), never lowered to read.
    `query` and `sql_query`, which never had the qualifier, are untouched — the payload is consulted
    only where the NAME itself says it runs something, and with no payload the name's `read` stands (a
    name-only caller — the console, the rate limiter, the asset graph — gets `read`, which is the fix).

    Ranking SEND above DELETE outright would fix the same seven names and break far more. `delete_email`,
    `remove_webhook`, `delete_mail`, `revoke_share`, `expire_share`, `purge_mail_queue` and
    `invalidate_push_token` all carry an egress NOUN beside a destruction verb; reporting them as "send"
    makes the asset graph's per-verb inventory state that an agent holding a mailbox-delete grant cannot
    delete, silences `tool-allowlist-perimeter.rego`'s "unlisted tool attempted a delete" reason, and
    refuses them under an egress refinement they have nothing to do with. Destruction stays the worst
    thing a NAME can say; only the qualifier moves.

    The risk keeps the critical grade the exec token earned either way — the console still shows
    `invoke_send_pipeline` as critical, it just no longer tells the policy the call sends nothing."""
    tokens = _tokenize_tool(tool_name)
    tset = set(tokens)
    # (verb, risk, the name token that matched — None when recovered from the payload)
    matches: list[tuple[Verb, RiskLevel, str | None]] = []

    # control-plane actuation: an actuation noun + a control verb ⇒ critical (open_breaker, set_valve).
    #
    # DECISIVE rather than one more candidate. This is a whole-NAME structural determination — a noun
    # from the actuation vocabulary governed by a control verb — not a single token that happens to
    # appear somewhere in the name. `open_relay` is an electrical relay being thrown, not a mail relay,
    # and `relay` is also an egress token; deciding here keeps an ICS command out of the egress
    # detectors no matter how the lexicon is later extended. (With the ranking below this is currently
    # also what the ranking would conclude — DELETE from a non-qualifier match is the top rank — so the
    # early return is a guard against lexicon drift, not a thumb on the scale.)
    if tset & _ACTUATION_NOUNS and tset & _CONTROL_VERBS:
        return Verb.DELETE, RiskLevel.CRITICAL

    for t in tokens:
        hit = _VERB_LEXICON.get(t)
        if hit:
            matches.append((hit[0], hit[1], t))

    # NOT consulted for a name that matched only a run qualifier. `run` / `run_report` already resolved
    # (to the exec reading), and letting an agent-supplied `{"query": "select 1"}` turn that into `read`
    # would trade the name for a payload the caller chooses even more freely — the hole the evaluator's
    # rate-limit exemption documents. The payload may fill in a name that says nothing; it may not
    # talk a name that says "executes" down.
    if not matches:
        params_hit = _classify_params(tool_params)
        if params_hit:
            # Recovered from the payload, not from a qualifier token: a DROP statement in `run_report`'s
            # params is the operation itself and must rank as one.
            matches.append((params_hit[0], params_hit[1], None))

    if not matches:
        return Verb.UNKNOWN, None
    # The grade is the worst any matched token carries — an exec token still makes the call critical,
    # and that includes a run qualifier that lost the VERB ranking: `run_query` reports `read` and is
    # still shown critical, the same split `run_export` (send, critical) already makes.
    risk = max((m[1] for m in matches), key=lambda r: _RISK_ORDER[r])
    # The verb is the one enforcement can act on. Ties inside a rank fall back to _VERB_ORDER so the
    # result stays deterministic for a name that matched two tokens of the same enforcement weight.
    executes_code = bool(tset & _EXECUTION_OBJECTS)
    verb = max(matches, key=lambda m: (_enforcement_rank(m[0], m[2], executes_code), _VERB_ORDER[m[0]]))[0]
    # A run qualifier yielded to the read or write it governs (it outranks both otherwise). Fail closed:
    # it may stay `read` only if the payload proves a read, and whatever it says, the verb only ever
    # moves UP from here. With no payload the name's reading stands — name-only callers get the fix's
    # `read`; the enforcement path always carries tool_params, which is where the smuggled write is.
    if tool_params is not None and verb in (Verb.READ, Verb.WRITE) and tset & _RUN_QUALIFIERS:
        stated = _payload_write_signal(tool_params)
        if stated is not None and _VERB_ORDER[stated] > _VERB_ORDER[verb]:
            verb = stated
    return verb, risk


def verb_reads_payload(tool_name: str) -> bool:
    """Whether `classify_tool(tool_name, params)` can depend on `params` for this tool NAME.

    The two places `classify_tool` reads the payload, and nowhere else:

    * the name matches no verb token (and is not a control-plane actuation), so the verb is recovered
      from the payload — `acme_widget` is `unknown` with no payload and `delete` with a DROP in it;
    * a run qualifier yielded to the read or write it governs (`run_query`), so the payload may raise
      the verb — a select stays `read`, an UPDATE is `write`.

    So `derived.verb` is a fact about the arguments for such a tool, not only about its name: a call
    replayed without its argument values may publish a different verb than the real call did. The
    dry runs use this to tell "refused on the verb" from "the record cannot say what the verb was".
    `tests/engine/test_capability.py` holds this to `classify_tool` itself.
    """
    tokens = _tokenize_tool(tool_name)
    tset = set(tokens)
    if tset & _ACTUATION_NOUNS and tset & _CONTROL_VERBS:
        return False
    if not any(_VERB_LEXICON.get(t) for t in tokens):
        return True
    verb, _risk = classify_tool(tool_name)
    return verb in (Verb.READ, Verb.WRITE) and bool(tset & _RUN_QUALIFIERS)


_DEFAULT_VERB_RISK = {
    Verb.READ: RiskLevel.LOW,
    Verb.WRITE: RiskLevel.HIGH,
    Verb.SEND: RiskLevel.HIGH,
    Verb.DELETE: RiskLevel.CRITICAL,
}


def default_risk_of_verb(verb: Verb) -> RiskLevel | None:
    """The canonical risk a verb carries absent source-specific context (read=low, write/send=high,
    delete=critical) — used when an admin PROMOTES an observed tool to a verb: the promotion names the
    verb, the risk follows from this map so it can never be under-declared. None for UNKNOWN."""
    return _DEFAULT_VERB_RISK.get(verb)


def verb_risk(source_type: str, verb: Verb) -> RiskLevel | None:
    """The RiskLevel a source assigns to a verb (e.g. DELETE on postgres = CRITICAL, READ = LOW), or None
    when the source type or verb isn't in the registry. Lets callers colour a hop by its real operation risk."""
    spec = _REGISTRY.get(source_type)
    if not spec:
        return None
    for vs in spec.verbs:
        if vs.verb == verb:
            return vs.risk
    return None


def classify_source(
    source_type: str,
    *,
    granted_verbs: set[Verb] | None = None,
    observed_verbs: set[Verb] | None = None,
    defended_verbs: set[Verb] | None = None,
    monitored_verbs: set[Verb] | None = None,
) -> list[VerbFinding]:
    """Classify every verb a source EXPOSES against the join of what is granted / observed / policy-defended.

    granted   = a tool reaching this source that maps to the verb is registered/allowed
    observed  = real traffic exercised the verb
    defended  = a policy ENFORCED on the verb's tool (a block or an escalation)
    monitored = calls were logged as would-block but ran (Monitor / audit mode); ignored where defended

    Returns findings worst-first (UNDEFENDED → MONITORED → DORMANT_GRANT → DEFENDED → LATENT), each
    with a verb-specific recommendation. Callers derive per-source/per-path severity via worst_open_verb()."""
    spec = _REGISTRY.get(source_type)
    if not spec:
        return []
    granted = granted_verbs or set()
    observed = observed_verbs or set()
    defended = defended_verbs or set()
    monitored = monitored_verbs or set()

    findings: list[VerbFinding] = []
    for vs in spec.verbs:
        is_granted = vs.verb in granted or vs.verb in observed
        is_observed = vs.verb in observed
        is_defended = vs.verb in defended
        if is_observed and not is_defended and vs.verb in monitored:
            status = CapabilityStatus.MONITORED
        elif is_observed and not is_defended:
            status = CapabilityStatus.UNDEFENDED
        elif is_granted and not is_observed:
            status = CapabilityStatus.DORMANT_GRANT
        elif is_observed and is_defended:
            status = CapabilityStatus.DEFENDED
        else:
            status = CapabilityStatus.LATENT

        rec = ""
        if status == CapabilityStatus.UNDEFENDED:
            rec = f"{vs.fix} — {spec.display}"
        elif status == CapabilityStatus.MONITORED:
            rec = (
                f"calls were logged as would-block but ran (Monitor) — nothing stopped {vs.verb.value} on "
                f"{spec.display}; enforce the policy or namespace to block it"
            )
        elif status == CapabilityStatus.DORMANT_GRANT:
            rec = f"grant is unused — revoke {vs.verb.value} on {spec.display} (least privilege)"
        findings.append(
            VerbFinding(
                verb=vs.verb, risk=vs.risk, technique=vs.technique, label=vs.label,
                status=status, granted=is_granted, observed=is_observed, defended=is_defended,
                recommendation=rec, monitored=vs.verb in monitored,
            )
        )

    findings.sort(key=lambda f: (_STATUS_ORDER[f.status], -_RISK_ORDER[f.risk]))
    return findings


_STATUS_ORDER = {
    CapabilityStatus.UNDEFENDED: 0,
    CapabilityStatus.MONITORED: 1,
    CapabilityStatus.DORMANT_GRANT: 2,
    CapabilityStatus.DEFENDED: 3,
    CapabilityStatus.LATENT: 4,
    CapabilityStatus.NOT_EXPOSED: 5,
}

#: Statuses where the verb is reachable and nothing stops it. MONITORED is open: its calls ran.
_OPEN_STATUSES = (CapabilityStatus.UNDEFENDED, CapabilityStatus.MONITORED, CapabilityStatus.DORMANT_GRANT)


def worst_open_verb(findings: list[VerbFinding]) -> VerbFinding | None:
    """The highest-risk verb that is 'open' (undefended, monitored only, or a dormant grant) — the severity
    a path/source should carry. Returns None when everything is defended or latent (nothing actionable).
    Within one risk level the worse status wins (undefended, then monitored, then dormant)."""
    open_findings = [f for f in findings if f.status in _OPEN_STATUSES]
    if not open_findings:
        return None
    return max(open_findings, key=lambda f: (_RISK_ORDER[f.risk], -_STATUS_ORDER[f.status]))


def source_meta(source_type: str) -> dict[str, object] | None:
    """Display metadata for a source type (class + label + wave), or None if unknown."""
    spec = _REGISTRY.get(source_type)
    if not spec:
        return None
    return {"source_type": spec.source_type, "source_class": spec.source_class.value, "display": spec.display, "wave": spec.wave}


# ── capability → policy bridge helpers ──────────────────────────────────────────────────────────────
# The OPA evaluate input carries no data-source field (only tool_name + agent), so a "block WRITE on
# Elasticsearch" defense cannot match on the source at enforce time. It is instead resolved to a concrete
# tool-name set AT GENERATION TIME (the tools that reach the source with the target verb) — these helpers
# provide the verb metadata; the router joins it against the live asset graph.

# Verbs that MUTATE or EXFILTRATE (the ones a "make read-only" defense should block); read is the
# legitimate use and is never blocked.
_MUTATING = (Verb.WRITE, Verb.DELETE, Verb.SEND)


def verb_display(verb: Verb) -> str:
    return {Verb.READ: "read", Verb.WRITE: "write", Verb.DELETE: "delete", Verb.SEND: "send"}.get(verb, "?")


def mutating_verbs_of(source_type: str) -> list[Verb]:
    """The mutating/egress verbs this source EXPOSES — the set a 'make read-only' defense blocks."""
    spec = _REGISTRY.get(source_type)
    if not spec:
        return []
    exposed = {vs.verb for vs in spec.verbs}
    return [v for v in _MUTATING if v in exposed]


def verb_fragments(source_type: str, verbs: list[Verb]) -> list[str]:
    """The tool-name fragments that identify ``verbs`` for ``source_type`` (e.g. delete → drop/purge/
    truncate). A capability defense blocks any tool whose name matches one of these at a word boundary —
    so the policy is a FORWARD GUARD (it catches a delete tool that appears LATER, and a renamed
    delete_records/drop_table), not just the exact tool names observed at generation time. READ is never
    included. Deduped, sorted longest-first so a broader fragment can't shadow a longer one."""
    spec = _REGISTRY.get(source_type)
    if not spec:
        return []
    want = {v for v in verbs if v in _MUTATING}
    frags: set[str] = set()
    for vs in spec.verbs:
        if vs.verb in want:
            frags.update(f.strip().lower() for f in vs.tool_fragments if f.strip())
    return sorted(frags, key=lambda f: (-len(f), f))


def defense_meta(source_type: str, verbs: list[Verb]) -> dict[str, object] | None:
    """Metadata for a capability defense that blocks ``verbs`` on ``source_type``: a stable rule_id token,
    a human reason, and the worst risk among the verbs (for the draft's severity). Returns None for an
    unknown source or an empty/READ-only verb set (reads are never blocked — nothing to defend)."""
    spec = _REGISTRY.get(source_type)
    if not spec:
        return None
    by_verb = {vs.verb: vs for vs in spec.verbs}
    targets = [v for v in verbs if v in by_verb and v in _MUTATING]
    if not targets:
        return None
    targets.sort(key=lambda v: _RISK_ORDER[by_verb[v].risk], reverse=True)
    worst = by_verb[targets[0]]
    verb_names = "/".join(verb_display(v) for v in targets)
    reason = f"Blocked: {verb_names} on {spec.display} for this class (capability policy — least privilege)"
    return {
        "verbs": [v.value for v in targets],
        "rule_id": f"capability:{source_type}:{'+'.join(verb_display(v) for v in targets)}",
        "reason": reason,
        "risk": worst.risk.value,
        "technique": worst.technique,
        "source_display": spec.display,
        # blocking ALL of the source's mutating verbs == making the class read-only (set compare — targets
        # is risk-sorted, mutating_verbs_of is in fixed order).
        "read_only": set(targets) == set(mutating_verbs_of(source_type)),
    }
