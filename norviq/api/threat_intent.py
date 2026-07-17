# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Positive-security INTENT policy generator + coverage for the Attack Graph (feat/attack-graph).

The headline of the Attack Graph is "allow the intended behaviour, block every possible scenario". A
handful of intent toggles (read-only / namespace-scoped / rate-limit / no-egress) GENERATE a
**default-deny** Rego policy for one agent class: every tool call is blocked unless it matches ALL the
enabled intended-behaviour constraints. This is the durable, positive-security fix — the inverse of the
exploratory per-hop what-if.

Safety (auditor): this module only GENERATES and dry-run-EVALUATES rego — it never persists or enforces
anything (the draft/apply path in routers/threats.py is a separate, gated, dry-run DRAFT). The generated
rego is DEFAULT-DENY and its allow carve-out is the read-only / in-scope / non-egress subset the
comprehensive baseline already permits, so it can only ADD denials — it is tighten-only by construction.
`test_threat_intent.py` + `policies/threat_intent_test.rego` prove the canonical baseline-blocked attacks
(delete / SQL exec / egress / cross-tenant) stay BLOCKED under a generated policy.

The generated rego reads the REAL evaluator OPA input schema (norviq/engine/evaluator.py `_build_input`):
``input.tool_name`` (+ ``input.tool_name_normalized``), ``input.tool_params``, ``input.agent.namespace``,
``input.agent.agent_class``, ``input.call_depth`` — so a drafted policy enforces correctly if an operator
later applies it. There is no ``input.action``/``input.resource`` in that schema, so intent is classified
by the tool-name verb + agent namespace, not by a synthetic action field.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from norviq.engine.confusables import skeleton

# --- tool-name verb classification (matches how the console + baseline reason about tools) -----------
# A "read" tool's name starts with one of these verbs (search_kb, get_user, list_invoices, …).
READ_VERBS: tuple[str, ...] = (
    "read", "get", "list", "search", "fetch", "describe", "query", "lookup", "view", "find", "scan", "count",
)
# Egress sinks — a call that can move data OUT of the trust boundary (email/webhook/object-store/etc).
EGRESS_TOOLS: tuple[str, ...] = (
    "send_email", "send_sms", "send_message", "http_post", "http_request", "webhook", "post_webhook",
    "upload", "upload_file", "export", "export_data", "s3_put", "put_object", "publish", "smtp",
    "notify_external", "call_api", "fetch_url",
)
# Verbs that mutate / exfiltrate — used only to describe the recommended fix; enforcement is the
# default-deny (anything not matching the allow carve-out is blocked), not an explicit block-list.
WRITE_VERBS: tuple[str, ...] = (
    "delete", "drop", "update", "insert", "write", "create", "modify", "execute", "truncate", "grant",
    "revoke", "transfer", "refund", "send", "issue", "approve", "purge", "alter",
)

# The four toggles the intent modal exposes. `key` matches the UI; `enforceable` marks the ones that
# actually constrain a stateless OPA decision (rate-limit is throttle-layer, advisory here — see below).
INTENT_TOGGLES: tuple[str, ...] = ("readonly", "scope", "rate", "egress")


@dataclass(frozen=True)
class Intent:
    """The intent-modal selection for one agent class."""

    readonly: bool = False
    scope: bool = False
    rate: bool = False
    egress: bool = False

    @classmethod
    def from_dict(cls, data: dict | None) -> "Intent":
        d = data or {}
        return cls(
            readonly=bool(d.get("readonly")),
            scope=bool(d.get("scope")),
            rate=bool(d.get("rate")),
            egress=bool(d.get("egress")),
        )

    @property
    def any_enabled(self) -> bool:
        return self.readonly or self.scope or self.rate or self.egress

    def enabled_keys(self) -> list[str]:
        return [k for k in INTENT_TOGGLES if getattr(self, k)]


def sanitize_class(agent_class: str) -> str:
    """A rego-package-safe token for an agent class ("customer-support" -> "customer_support")."""
    token = re.sub(r"[^a-zA-Z0-9_]", "_", agent_class.strip() or "agent")
    if not re.match(r"[a-zA-Z_]", token):
        token = f"c_{token}"
    return token


def _rego_str_set(name: str, values: tuple[str, ...]) -> str:
    items = ", ".join(f'"{v}"' for v in values)
    return f"{name} := {{{items}}}"


def _rego_quoted_set(name: str, values: list[str]) -> str:
    items = ", ".join(f'"{v}"' for v in values)
    return f"{name} := {{{items}}}"


def generate_capability_rego(
    source_type: str, source_display: str, agent_class: str, verbs: list[str],
    tool_names: list[str], rule_id: str, reason: str, verb_frags: list[str] | None = None,
) -> str:
    """CAPABILITY→POLICY bridge: a tighten-only DRY-RUN rego that blocks a set of VERBS on a data SOURCE
    for one agent class. The OPA evaluate input carries no data-source field, so the block cannot match on
    the source at enforce time. It is resolved two ways, UNIONed:
      1. VERB PATTERN (``verb_frags``, from the registry) — any tool whose name matches a verb fragment at
         a word boundary (delete/drop/truncate, write/update/index, …). This is the FORWARD GUARD: it
         blocks a destructive tool that appears LATER, or a renamed delete_records/drop_table, so a
         'make read-only' defense is real even when no such tool is observed yet.
      2. The concrete observed tool NAMES (``tool_names``) the CALLER resolved from the live asset graph —
         exact belt-and-suspenders coverage for the tools seen today.
    Mirrors generate_remediation_rego's shape (default-allow, class-scoped block set, resolver tail) so it
    satisfies validate_policy_create and is tighten-only at baseline priority. READ is never a target.

    Read is never blocked; a benign read tool ("get_report", "search_kb") never matches the mutating-verb
    fragments, so this cannot over-block legitimate reads."""
    src_tok = _control_token(source_type)
    cls_tok = sanitize_class(agent_class)
    verb_tok = "_".join(verbs)
    safe_reason = (reason or "").replace('"', "'")
    names = sorted({t.strip() for t in tool_names if t and t.strip()})
    tool_set = _rego_quoted_set("cap_tools", names)

    # RE2 alternation of the verb fragments, matched at a NON-alphanumeric word boundary so "delete" hits
    # delete_record / drop_table / hard_delete but never "deleted_flag" or "input" (the 'put' fragment).
    frags = sorted({f.strip().lower() for f in (verb_frags or []) if f and f.strip()}, key=lambda f: (-len(f), f))
    pattern_block = ""
    if frags:
        alt = "|".join(re.escape(f) for f in frags)
        pat = f"(^|[^a-z0-9])({alt})([^a-z0-9]|$)"
        pattern_block = f"""
cap_verb_pattern := "{pat}"
# Forward guard: block any tool whose name (or its confusable-normalized form) matches a target verb.
blocks["{rule_id}"] {{ is_capability_class; regex.match(cap_verb_pattern, lower(input.tool_name)) }}
blocks["{rule_id}"] {{ is_capability_class; regex.match(cap_verb_pattern, lower(input.tool_name_normalized)) }}"""

    return f"""package norviq.remediation.capability.{src_tok}_{verb_tok}_{cls_tok}

# CAPABILITY POLICY — GENERATED, DRY-RUN DRAFT. Makes {source_display} {"/".join(verbs)}-safe for agent
# class "{agent_class}": blocks any tool that performs those verbs (by verb-name pattern — a FORWARD GUARD
# for tools not yet seen — plus the concrete tools observed reaching it). The OPA input has no data-source
# field, so the source is resolved to verbs/tools at generation time. TIGHTEN-ONLY at baseline priority —
# only ADDS denials. NEVER auto-enforces — the operator reviews + applies via the gated Policies flow.

default decision = "allow"
default rule_id  = "capability_noop"
default reason   = "Allowed"

is_capability_class {{ input.agent.agent_class == "{agent_class}" }}

{tool_set}

blocks["{rule_id}"] {{ is_capability_class; cap_tools[input.tool_name] }}
# Evasion parity: also match the confusable-skeleton of the tool name (homoglyph/zero-width).
blocks["{rule_id}"] {{ is_capability_class; cap_tools[input.tool_name_normalized] }}{pattern_block}

block_fired {{ blocks[_] }}
decision = "block" {{ block_fired }}
rule_id = sort([id | blocks[id]])[0] {{ block_fired }}
reason = "{safe_reason}" {{ block_fired }}
"""


def generate_intent_rego(
    agent_class: str,
    allow_tools: list[str],
    intent: Intent,
    learned_verbs: dict[str, str] | None = None,
) -> str:
    """Generate a DEFAULT-DENY positive-security rego policy for `agent_class` from an explicit ALLOWLIST
    of intended tools + coarse refinement toggles.

    A call is ALLOWED only when it is the class AND the tool is in the allowlist AND every enabled toggle
    holds; everything else (every non-allowlisted tool, every other class routed here) falls through to the
    default block. The allowlist is matched EVASION-NORMALIZED — the lower-cased name AND the confusable
    `skeleton()` (the same normalization behind `input.tool_name_normalized`) — so homoglyph / zero-width /
    case tricks can't smuggle a non-intended tool past the allow. rate-limit stays advisory (real throttle
    is the F-03 layer).

    LEARNED VERBS (`learned_verbs`, tool → read/write/send/delete): the admin-PROMOTED classifications
    flow into the toggles, overriding the name heuristic — a tool promoted as delete/write/send is NEVER
    treated as a read by the Read-only toggle no matter what its name says ("warehouse_task"), a tool
    promoted as read passes Read-only even with an opaque name, and a tool promoted as send counts as an
    egress sink. Only entries for allowlisted tools are emitted (everything else is default-denied anyway).

    Each helper vocabulary (read_verbs / egress_tools / in_scope / rate_within) is emitted ONLY when its
    toggle is enabled — a draft never carries dead rule text that reads like it means something.

    TIGHTEN-ONLY: applied at a priority EQUAL to the comprehensive baseline, `_resolve_precedence`'s
    most-restrictive tie-break makes a baseline `block` always win over this policy's `allow` — so it can
    only ADD denials, never turn a baseline block into allow (proven by test_threat_intent + the
    baseline-precedence pytest).
    """
    token = sanitize_class(agent_class)
    names = sorted({t.strip().lower() for t in (allow_tools or []) if t and t.strip()})
    skels = sorted({skeleton(t.strip()) for t in (allow_tools or []) if t and t.strip()})
    enabled = intent.enabled_keys()

    # Learned (admin-promoted) verbs, restricted to the allowlist — keyed by lower name AND skeleton so
    # the toggle checks match evasion-normalized, same as the allowlist itself.
    learned = {
        t.strip().lower(): v.strip().lower()
        for t, v in (learned_verbs or {}).items()
        if t and t.strip().lower() in names and v and v.strip().lower() in {"read", "write", "send", "delete"}
    }

    def _learned_set(rego_name: str, verbs: set[str]) -> tuple[str, list[str]]:
        entries = sorted({key for t, v in learned.items() if v in verbs for key in (t, skeleton(t))})
        return (_rego_quoted_set(rego_name, entries) if entries else "", entries)

    # allow_intent body: class guard, allowlist membership, then one line per enabled refinement toggle.
    guards = [f'    input.agent.agent_class == "{agent_class}"', "    in_allowlist"]
    if intent.readonly:
        guards.append("    is_read           # read-only refinement: read verb (learned verb overrides the name)")
    if intent.egress:
        guards.append("    not is_egress     # no external egress sink")
    if intent.scope:
        guards.append("    in_scope          # resource stays inside the agent's namespace")
    if intent.rate:
        guards.append("    rate_within       # advisory throttle proxy (real limit = F-03 throttle layer)")

    # Toggle-specific helper blocks — emitted only when the toggle needs them.
    helper_blocks: list[str] = []
    if intent.readonly:
        learned_read_set, learned_read = _learned_set("learned_read", {"read"})
        learned_mut_set, learned_mut = _learned_set("learned_mutating", {"write", "send", "delete"})
        block = f"""{_rego_str_set("read_verbs", READ_VERBS)}
tool_verb := split(lower(input.tool_name), "_")[0]
tool_verb_norm := split(lower(input.tool_name_normalized), "_")[0]"""
        if learned_mut:
            block += f"""
{learned_mut_set}
# A verb the admin PROMOTED as write/send/delete makes the tool NON-read regardless of its name.
is_learned_mutating {{ learned_mutating[lower(input.tool_name)] }}
is_learned_mutating {{ learned_mutating[input.tool_name_normalized] }}
is_read {{ read_verbs[tool_verb]; not is_learned_mutating }}
is_read {{ read_verbs[tool_verb_norm]; not is_learned_mutating }}"""
        else:
            block += """
is_read { read_verbs[tool_verb] }
is_read { read_verbs[tool_verb_norm] }"""
        if learned_read:
            block += f"""
{learned_read_set}
# A verb the admin PROMOTED as read passes Read-only even when the tool name says nothing.
is_read {{ learned_read[lower(input.tool_name)] }}
is_read {{ learned_read[input.tool_name_normalized] }}"""
        helper_blocks.append(block)
    if intent.egress:
        learned_egr_set, learned_egr = _learned_set("learned_egress", {"send"})
        block = f"""{_rego_str_set("egress_tools", EGRESS_TOOLS)}
is_egress {{ egress_tools[lower(input.tool_name)] }}
is_egress {{ egress_tools[lower(input.tool_name_normalized)] }}"""
        if learned_egr:
            block += f"""
{learned_egr_set}
# A verb the admin PROMOTED as send is an egress sink regardless of its name.
is_egress {{ learned_egress[lower(input.tool_name)] }}
is_egress {{ learned_egress[input.tool_name_normalized] }}"""
        helper_blocks.append(block)
    if intent.scope:
        helper_blocks.append("""# in_scope: any namespace-bearing tool_params field must equal the agent's own namespace (no cross-tenant).
in_scope { not _cross_namespace }
_cross_namespace {
    some k
    ns := input.tool_params[k]
    is_string(ns)
    _looks_like_namespace_key(k)
    ns != input.agent.namespace
}
_looks_like_namespace_key(k) { lower(k) == "namespace" }
_looks_like_namespace_key(k) { lower(k) == "ns" }
_looks_like_namespace_key(k) { lower(k) == "tenant" }""")
    if intent.rate:
        helper_blocks.append("""# rate_within: advisory only — a stateless policy cannot count calls/min; the real limiter is the F-03 layer.
rate_within { input.call_depth <= 8 }""")
    helpers = ("\n\n" + "\n\n".join(helper_blocks)) if helper_blocks else ""

    learned_note = ""
    if learned:
        learned_note = "\n# Learned verbs (admin-promoted, override the name heuristic): " + ", ".join(
            f"{t}={v}" for t, v in sorted(learned.items())
        )

    header = f"""package norviq.intent.{token}

# Positive-security INTENT policy for agent class "{agent_class}" — GENERATED, DRY-RUN DRAFT.
# DEFAULT-DENY: a call is BLOCKED unless it is this class AND the tool is in the intended allowlist AND
# every enabled refinement toggle holds. The allowlist is matched evasion-normalized (lower + skeleton).
# TIGHTEN-ONLY at baseline priority (most-restrictive tie-break) — only ADDS denials, never weakens a block.
# Allowlist ({len(names)} tools): {", ".join(names) or "(empty — denies everything for the class)"}
# Refinements: {", ".join(enabled) or "(none)"}{learned_note}

default decision = "block"
default rule_id = "intent_default_deny"
default reason = "Blocked: tool is not in the intended allowlist for {agent_class}"

{_rego_quoted_set("allow_names", names)}
{_rego_quoted_set("allow_skeletons", skels)}

# Allowlist membership — matched on BOTH the lower-cased name and the confusable skeleton (== the
# evaluator's input.tool_name_normalized), so homoglyph/zero-width/case evasion can't dodge the allow.
in_allowlist {{ allow_names[lower(input.tool_name)] }}
in_allowlist {{ allow_skeletons[input.tool_name_normalized] }}{helpers}
"""

    allow_block = "allow_intent {{\n{body}\n}}".format(body="\n".join(guards))
    tail = f"""
{allow_block}

# a class call that is NOT in the intended allowlist, OR that IS allowlisted but fails an enabled
# refinement toggle, is denied
denied {{ input.agent.agent_class == "{agent_class}"; not allow_intent }}

decision = "allow" {{ allow_intent }}
rule_id = "intent_allow_{token}" {{ allow_intent }}
reason = "Allowed: tool in the intended allowlist for {agent_class}" {{ allow_intent }}

# HONEST REASON for the self-contradictory case: the tool IS in the allowlist but an enabled refinement
# toggle (readonly / no-egress / scope / rate) still fails it — e.g. an egress tool allowlisted while "No
# external egress" is on. Ordered BEFORE the generic default-deny rule below so an operator/auditor
# inspecting the block is told the TRUE cause, not a false "not in the allowlist" claim. Tighten-only: the
# decision stays "block" either way — only rule_id/reason change to reflect which guard actually failed.
decision = "block" {{ denied; in_allowlist }}
rule_id = "intent_refinement_mismatch" {{ denied; in_allowlist }}
reason = sprintf("Blocked: %s is allowlisted for {agent_class} but fails an enabled refinement (e.g. no-external-egress)", [input.tool_name]) {{ denied; in_allowlist }}

# Explicit reachable block rule for the genuinely-not-allowlisted case — semantically identical to the
# default-deny, but present as a rule so the policy validator accepts the draft on apply (it requires
# `decision = "block" {{ ... }}`).
decision = "block" {{ denied; not in_allowlist }}
rule_id = "intent_default_deny" {{ denied; not in_allowlist }}
reason = "Blocked: tool is not in the intended allowlist for {agent_class}" {{ denied; not in_allowlist }}
"""
    return header + "\n" + tail


# --------------------------------------------------------------------------------------------------
# Batch B (COMP-GEN-01) — CONTROL-SPECIFIC compliance remediation generation.
#
# The compliance "Generate enforcing policy" used to emit generate_intent_rego(class, [], intent): a
# per-CLASS default-deny allowlist keyed only on the class + a coarse readonly/egress toggle. Two
# different controls for one class produced BYTE-IDENTICAL rego — the control never entered the policy.
#
# generate_remediation_rego() instead assembles a rego DRAFT from the technique's mapped rule_ids (the
# `policies` list in mitre_mapping.json / owasp_llm_mapping.json — the same rule_ids comprehensive.rego
# enforces). Each mapped rule contributes a control-specific, class-scoped `blocks[...]` clause; two
# different controls reference different rule_ids → different rego (the COMP-GEN-01 fix).
#
# INVARIANTS (kept identical to the intent path):
#   • DRY-RUN only — the draft lives in intent_drafts and NEVER auto-enforces; apply is gated (Policies).
#   • TIGHTEN-ONLY at baseline priority — the policy is `default decision = "allow"` and only ADDS blocks;
#     under _resolve_precedence's most-restrictive tie-break a baseline block always wins, so applying a
#     remediation can only turn allow→block for the control's risky call, never block→allow.
#   • SELF-CONTAINED — the block conditions below MIRROR comprehensive.rego's detection (same tool sets /
#     param patterns) but are independent copies used ONLY for draft generation; comprehensive.rego and
#     the /evaluate hot path are untouched (opa/attacks baselines unchanged).
#
# _REMEDIATION_RULES maps a mapped rule_id -> (helper rego lines, block condition). A rule_id we don't
# have a runtime template for is skipped (the control still gets its other mapped rules); a control whose
# mapping is `remediation: bespoke` is escalated upstream and never reaches here.
# --------------------------------------------------------------------------------------------------

# rule_id -> (helper lines defined once per rule, block-condition predicate/expr). Class scoping is added
# by the caller via the shared `is_remediation_class` guard, so conditions here are class-agnostic.
_REMEDIATION_RULES: dict[str, tuple[tuple[str, ...], str]] = {
    # Excessive agency → block destructive tools (mirrors comprehensive.rego destructive_tools).
    "llm06_excessive_agency": (
        ('rem_destructive_tools := {"delete_record", "drop_table", "truncate"}',),
        "rem_destructive_tools[input.tool_name]",
    ),
    # Supply chain → block untrusted code/plugin load (mirrors supply_chain_tools).
    "llm05_supply_chain": (
        ('rem_supply_chain_tools := {"load_plugin", "download_script", "eval", "install_package"}',),
        "rem_supply_chain_tools[input.tool_name]",
    ),
    # Data leakage → block secret-read tools (mirrors secret_read_tools).
    "llm02_data_leakage": (
        ('rem_secret_read_tools := {"read_env", "getenv", "get_secret", "read_secret", "fetch_secret"}',),
        "rem_secret_read_tools[input.tool_name]",
    ),
    # Cross-tenant access → block a resource whose tenant/namespace differs from the caller's (mirrors
    # cross_tenant_detected).
    "cross_tenant_access": (
        (
            "rem_cross_tenant { input.tool_params.tenant_id; input.tool_params.tenant_id != input.agent.namespace }",
            "rem_cross_tenant { input.tool_params.namespace; input.tool_params.namespace != input.agent.namespace }",
        ),
        "rem_cross_tenant",
    ),
    # Shell / command execution → block a param carrying shell metacharacters (mirrors shell_injection_detected).
    "deny_shell_execution": (
        (
            'rem_shell_patterns := ["; ", "&&", "$(", "`", "| ", "|| "]',
            "rem_shell_hit { walk(input.tool_params, [_, v]); is_string(v); contains(v, rem_shell_patterns[_]) }",
        ),
        "rem_shell_hit",
    ),
    # SQL injection → block execute_sql carrying an injection pattern (mirrors sql_injection_detected).
    "deny_sql_injection": (
        (
            'rem_sql_patterns := ["OR 1=1", "DROP TABLE", "UNION SELECT", "; --", "\' OR \'"]',
            "rem_sql_hit { input.tool_name == \"execute_sql\"; walk(input.tool_params, [_, v]); is_string(v); "
            "contains(upper(v), rem_sql_patterns[_]) }",
        ),
        "rem_sql_hit",
    ),
    # Prompt injection → block a param carrying an instruction-override pattern (mirrors injection_detected).
    "llm01_prompt_injection": (
        (
            'rem_injection_patterns := ["ignore previous", "ignore all previous", "disregard the above", "system prompt"]',
            "rem_injection_hit { walk(input.tool_params, [_, v]); is_string(v); "
            "contains(lower(v), rem_injection_patterns[_]) }",
        ),
        "rem_injection_hit",
    ),
    # Base64-obfuscated threat → decode base64-looking params and block on a decoded threat token
    # (mirrors base64_decoded_threat; guarded by a base64 shape so base64.decode never errors).
    "base64_decoded_threat": (
        (
            "rem_b64_candidate[v] { walk(input.tool_params, [_, v]); is_string(v); "
            "regex.match(`^[A-Za-z0-9+/]{16,}={0,2}$`, v) }",
            'rem_b64_tokens := ["drop table", "union select", "rm -rf", "$(", "; --"]',
            "rem_b64_hit { d := lower(base64.decode(rem_b64_candidate[_])); contains(d, rem_b64_tokens[_]) }",
        ),
        "rem_b64_hit",
    ),
}


def remediation_generatable_rules(rule_ids: list[str]) -> list[str]:
    """The subset of a technique's mapped rule_ids we can emit a runtime remediation clause for, in a
    stable order. Empty → the control has no runtime-expressible rule (caller escalates instead)."""
    seen: list[str] = []
    for rid in rule_ids or []:
        if rid in _REMEDIATION_RULES and rid not in seen:
            seen.append(rid)
    return seen


# --------------------------------------------------------------------------------------------------
# COMP-GEN-02 (accumulate): a per-class remediation OVERLAY holds the UNION of every applied control, not
# just the last one. The single overlay key ("<class>__remediation__") stores ONE rego, and apply is a
# full-replace UPSERT — so without accumulation, applying control B silently erased control A (a false-
# coverage bug). Each generated rego therefore carries a machine-readable MANIFEST comment naming every
# control it encodes; the gated apply path (policies.create_policy) parses the incoming draft + the existing
# overlay, UNIONS their controls, and re-materializes one combined rego. The manifest is the source of truth
# (block keys alone are ambiguous for control ids that contain ':' e.g. OWASP "LLM05:2025"); it is a rego
# COMMENT, invisible to OPA and untouched by the evaluator's package rewrite.
# --------------------------------------------------------------------------------------------------

_REMEDIATION_MANIFEST_TAG = "nrvq:remediation-manifest"


def _manifest_line(controls: list[dict]) -> str:
    """One-line JSON manifest naming each control (framework, id, name, usable rule_ids) an overlay encodes."""
    payload = [
        {"fw": c["framework"], "id": c["control_id"], "name": c.get("control_name") or c["control_id"],
         "rules": remediation_generatable_rules(list(c.get("rule_ids") or []))}
        for c in controls
    ]
    return f"# {_REMEDIATION_MANIFEST_TAG} " + json.dumps(payload, separators=(",", ":"), ensure_ascii=True)


def parse_remediation_controls(rego: str) -> list[dict]:
    """Recover the control list a remediation rego encodes, from its manifest comment. Returns a list of
    {framework, control_id, control_name, rule_ids}; empty when the rego is not a recognized compliance
    remediation overlay (so the apply path leaves any other rego byte-identical)."""
    prefix = f"# {_REMEDIATION_MANIFEST_TAG} "
    for line in (rego or "").splitlines():
        s = line.strip()
        if not s.startswith(prefix):
            continue
        try:
            data = json.loads(s[len(prefix):])
        except (ValueError, TypeError):
            return []
        out: list[dict] = []
        for c in data if isinstance(data, list) else []:
            rules = remediation_generatable_rules(list(c.get("rules") or []))
            cid = str(c.get("id") or "")
            if cid and rules:
                out.append({"framework": str(c.get("fw") or ""), "control_id": cid,
                            "control_name": str(c.get("name") or cid), "rule_ids": rules})
        return out
    return []


def union_remediation_controls(existing: list[dict], incoming: list[dict]) -> list[dict]:
    """UNION two control lists keyed by (framework, control_id); a re-applied control (same key) takes the
    incoming rule set, and existing controls keep their position so a stable rego is produced."""
    by_key: dict[tuple[str, str], dict] = {}
    order: list[tuple[str, str]] = []
    for c in list(existing) + list(incoming):
        k = (c.get("framework", ""), c["control_id"])
        if k not in by_key:
            order.append(k)
        by_key[k] = c
    return [by_key[k] for k in order]


def _framework_token(framework: str) -> str:
    return re.sub(r"[^a-z0-9_]", "_", (framework or "fw").strip().lower()) or "fw"


def _control_token(control_id: str) -> str:
    token = re.sub(r"[^a-zA-Z0-9_]", "_", (control_id or "control").strip().lower())
    if not re.match(r"[a-zA-Z_]", token):
        token = f"c_{token}"
    return token


def generate_remediation_rego(
    framework: str, control_id: str, control_name: str, agent_class: str, rule_ids: list[str],
) -> str:
    """CONTROL-SPECIFIC tighten-only DRY-RUN remediation rego for one (framework, control, class).

    Emits `package norviq.remediation.<framework>.<control_id>` — a default-ALLOW policy that adds one
    class-scoped block clause per mapped rule_id (from _REMEDIATION_RULES), with a `remediation:<fw>:
    <control>:<rule_id>` rule_id + a control-naming reason for audit traceability. Two different controls
    (different mapped rule_ids) produce DIFFERENT rego — the COMP-GEN-01 fix.

    Raises ValueError when NONE of the mapped rule_ids is runtime-expressible (the caller escalates rather
    than emitting a vacuous deny). The result validates under validate_policy_create (partial sets +
    resolver) and is tighten-only under the baseline-priority most-restrictive tie-break.
    """
    usable = remediation_generatable_rules(rule_ids)
    if not usable:
        raise ValueError(f"no runtime-expressible remediation rule for {framework} {control_id}")

    fw_tok = _framework_token(framework)
    ctrl_tok = _control_token(control_id)
    safe_name = (control_name or control_id).replace('"', "'")

    helper_lines: list[str] = []
    seen_helpers: set[str] = set()
    block_lines: list[str] = []
    for rid in usable:
        helpers, cond = _REMEDIATION_RULES[rid]
        for h in helpers:
            if h not in seen_helpers:
                seen_helpers.add(h)
                helper_lines.append(h)
        block_lines.append(
            f'blocks["remediation:{fw_tok}:{control_id}:{rid}"] {{ is_remediation_class; {cond} }}'
        )

    header = f"""package norviq.remediation.{fw_tok}.{ctrl_tok}

# CONTROL-SPECIFIC remediation for {framework} · {control_id} {safe_name} — GENERATED, DRY-RUN DRAFT.
# Closes the runtime gap by asserting this control's mapped block rule(s) for agent class "{agent_class}".
# TIGHTEN-ONLY at baseline priority (most-restrictive tie-break) — only ADDS denials, never weakens a
# baseline block. NEVER auto-enforces — the operator reviews + applies via the gated Policies flow.
# Mapped rules: {", ".join(usable)}
{_manifest_line([{"framework": framework, "control_id": control_id, "control_name": control_name, "rule_ids": usable}])}

default decision = "allow"
default rule_id  = "remediation_noop"
default reason   = "Allowed"

is_remediation_class {{ input.agent.agent_class == "{agent_class}" }}
"""

    helpers_block = "\n".join(helper_lines)
    blocks_block = "\n".join(block_lines)
    tail = f"""
{helpers_block}

{blocks_block}

block_fired {{ blocks[_] }}
decision = "block" {{ block_fired }}
rule_id = sort([id | blocks[id]])[0] {{ block_fired }}
reason = "{framework} {control_id} {safe_name} — remediation block" {{ block_fired }}
"""
    return header + tail


def generate_remediation_overlay_rego(agent_class: str, controls: list[dict]) -> str:
    """COMP-GEN-02: the COMBINED per-class remediation overlay — one rego encoding the UNION of every applied
    control. Used only by the gated apply path (policies.create_policy) when accumulating drafts into the
    single `"<class>__remediation__"` key; drafts themselves stay per-control via generate_remediation_rego.

    Emits `package norviq.remediation.overlay.<class>` (class-scoped — it spans controls/frameworks; the
    evaluator detects+rewrites the package, so the name is free) with one class-scoped block clause per
    (control, mapped rule), a manifest naming every control, and the shared decision resolver. Tighten-only,
    default-allow. `controls` is a list of {framework, control_id, control_name, rule_ids}; raises ValueError
    when none contributes a runtime-expressible rule (the caller then leaves the incoming rego untouched)."""
    norm: list[dict] = []
    for c in controls:
        rules = remediation_generatable_rules(list(c.get("rule_ids") or []))
        if rules:
            norm.append({"framework": str(c.get("framework") or ""), "control_id": str(c["control_id"]),
                         "control_name": str(c.get("control_name") or c["control_id"]), "rule_ids": rules})
    if not norm:
        raise ValueError("no runtime-expressible remediation rule across the supplied controls")

    class_tok = _control_token(agent_class)
    safe_class = agent_class.replace('"', "'")
    helper_lines: list[str] = []
    seen_helpers: set[str] = set()
    block_lines: list[str] = []
    for c in norm:
        fw_tok = _framework_token(c["framework"])
        for rid in c["rule_ids"]:
            helpers, cond = _REMEDIATION_RULES[rid]
            for h in helpers:
                if h not in seen_helpers:
                    seen_helpers.add(h)
                    helper_lines.append(h)
            block_lines.append(
                f'blocks["remediation:{fw_tok}:{c["control_id"]}:{rid}"] {{ is_remediation_class; {cond} }}'
            )
    control_summary = ", ".join(f'{c["framework"]} {c["control_id"]}' for c in norm)

    header = f"""package norviq.remediation.overlay.{class_tok}

# COMPLIANCE remediation OVERLAY for agent class "{safe_class}" — GENERATED, DRY-RUN until applied.
# Accumulates the UNION of every applied compliance control (one block per control × mapped rule); applying
# another control UNIONS into this same overlay instead of replacing it (COMP-GEN-02). TIGHTEN-ONLY at
# baseline priority (most-restrictive tie-break) — only ADDS denials, never weakens a baseline block.
# Controls: {control_summary}
{_manifest_line(norm)}

default decision = "allow"
default rule_id  = "remediation_noop"
default reason   = "Allowed"

is_remediation_class {{ input.agent.agent_class == "{safe_class}" }}
"""
    helpers_block = "\n".join(helper_lines)
    blocks_block = "\n".join(block_lines)
    tail = f"""
{helpers_block}

{blocks_block}

block_fired {{ blocks[_] }}
decision = "block" {{ block_fired }}
rule_id = sort([id | blocks[id]])[0] {{ block_fired }}
reason = sprintf("compliance remediation block: %s", [sort([id | blocks[id]])[0]]) {{ block_fired }}
"""
    return header + tail


def opa_input_for_step(tool_name: str, namespace: str, agent_class: str, tool_params: dict | None = None,
                       call_depth: int = 0) -> dict:
    """Build the evaluator-shaped OPA input for one kill-chain step so coverage uses the SAME schema a
    live decision would. Mirrors evaluator._build_input (the fields the generated rego reads)."""
    return {
        "tool_name": tool_name,
        # Mirror the real evaluator: the normalized name is the confusable skeleton, so the generated
        # policy's skeleton-based allow match behaves identically in coverage as it will live.
        "tool_name_normalized": skeleton(tool_name),
        "tool_params": dict(tool_params or {}),
        "tool_params_normalized": dict(tool_params or {}),
        "agent": {"spiffe_id": "", "namespace": namespace, "agent_class": agent_class},
        "trust_score": 0.0,
        "trust_category": "Low",
        "session_id": "",
        "call_depth": call_depth,
    }


def recommended_fix(chokepoint_tool: str) -> str:
    """The minimal constraint the inspector recommends for a path, from its chokepoint tool's verb."""
    tool = (chokepoint_tool or "").lower()
    verb = tool.split("_")[0]
    if tool in EGRESS_TOOLS:
        return f"Deny external egress for this class (no-egress) — '{chokepoint_tool}' can exfiltrate data."
    if verb in WRITE_VERBS:
        return f"Constrain this class to read-only — '{chokepoint_tool}' is a mutating/exfil verb."
    if verb in READ_VERBS:
        return "Scope reads to the agent's namespace (namespace-scoped) to stop cross-tenant reach."
    return f"Restrict '{chokepoint_tool}' to the declared intent for this class (default-deny)."


# --- MITRE mapping (extends engine.attack_graph.MITRE_BY_TOOL_TYPE with human labels) ----------------
_MITRE: dict[str, tuple[str, str]] = {
    "delete_record": ("AML.T0048", "External Harms · Data Destruction"),
    "drop_table": ("AML.T0048", "External Harms · Data Destruction"),
    "truncate_table": ("AML.T0048", "External Harms · Data Destruction"),
    "execute_sql": ("AML.T0049", "Discovery · Exfiltration via Query"),
    "run_query": ("AML.T0049", "Discovery · Exfiltration via Query"),
    "send_email": ("AML.T0040", "Exfiltration · ML Inference / Egress"),
    "send_sms": ("AML.T0040", "Exfiltration · Egress"),
    "http_post": ("AML.T0040", "Exfiltration · Egress"),
    "webhook": ("AML.T0057", "Exfiltration · LLM Data Leakage"),
    "upload": ("AML.T0025", "Exfiltration · Data from Local System"),
    "export_data": ("AML.T0025", "Exfiltration · Data from Local System"),
    "issue_refund": ("AML.T0051", "Impact · Financial Fraud"),
    "transfer_funds": ("AML.T0051", "Impact · Financial Fraud"),
    # A read/search tool is reconnaissance/discovery — there is no single ATLAS TECHNIQUE that fits, so we
    # label the TACTIC honestly rather than emit a fabricated "AML.T0000" (not a real ATLAS id) that the
    # console rendered as if it were a real technique.
    "search_kb": ("Reconnaissance", "read/search — no specific ATLAS technique"),
}


def mitre_for_tool(tool_name: str) -> str:
    """A "T#### · Label" MITRE ATLAS descriptor for a chokepoint tool (best-effort by name/verb)."""
    tool = (tool_name or "").lower()
    if tool in _MITRE:
        code, label = _MITRE[tool]
        return f"{code} · {label}"
    verb = tool.split("_")[0]
    if verb in ("send", "http", "webhook", "upload", "export", "publish"):
        return "AML.T0040 · Exfiltration · Egress"
    if verb in ("delete", "drop", "truncate", "purge"):
        return "AML.T0048 · External Harms · Data Destruction"
    if verb in ("execute", "run", "query"):
        return "AML.T0049 · Discovery · Exfiltration via Query"
    if verb in READ_VERBS:
        # Honest tactic label, not a fabricated technique id (see the search_kb note above).
        return "Reconnaissance · read/search — no specific ATLAS technique"
    return "AML.T0051 · Impact · Excessive Agency"
