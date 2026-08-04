# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""Intent endpoints — observe → propose → dry-run → draft.

    POST /api/v1/intents/compile   validate + compile to Rego. Nothing is stored.
    POST /api/v1/intents/propose   build a candidate intent from what a class actually did.
    POST /api/v1/intents/dry-run   replay recorded calls against a candidate. Nothing is stored.
    POST /api/v1/intents/drafts    persist a NON-ENFORCING draft for the gated Policies flow.
    GET  /api/v1/intents/drafts    list pending drafts.

There is no apply endpoint here, deliberately. A draft is persisted to ``intent_drafts`` — the
dedicated table the evaluator's ``_collect_candidates`` never reads — and applying it stays the
existing gated Policies flow. Adding a second path to ``policies`` would mean two ways to start
enforcing, one of which nobody reviews.

Relationship to ``/threats/intent-*``: those endpoints generate the original tool-allowlist intent
and count attack-path coverage. These compile the richer per-argument intent of DESIGN-NOTE §13 and
replay it against real traffic. Both write the same table and are applied the same way.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from norviq.api.auth import get_current_user, require_admin
from norviq.api.db.models import AuditLogEntry, IntentDraft
from norviq.api.db.session import get_session
from norviq.api.routers.graphs import _resolve_namespaces
from norviq.engine.evaluator import OPAEvaluator
from norviq.engine.intent import IntentError, compile_intent, dry_run, propose_intent

# The one regex that decides whether `param_paths.<path>` is an addressable field. IMPORTED rather
# than re-spelled: an observed argument name that fails it compiles to an IntentError, so a proposal
# that emitted one would hand the operator a candidate the very next request (compile) rejects.
# Importing keeps the two in lockstep; a private copy would drift silently in the fail-open direction.
from norviq.engine.intent.schema import _PARAM_PATH_RE

# THE argument-name derivation, borrowed rather than re-implemented. This module used to carry its
# own key-only walk, and a second walk over the same grammar is a second answer to "what is an
# argument path" — the contract's "ONE notion of an argument path" is not a style preference, it is
# the thing that stops the authoring surface naming paths the enforcement layer does not use. The
# local copy also lost three properties the capture path has and this one needs, each of them a
# defect on its own: it published a PAN sitting in a KEY position verbatim (mask_params masks values
# and preserves keys, by design, so `{"balances": {"4111111111111111": 25.0}}` reached the response
# intact); it CLIPPED an over-long key to 256 characters and reported the clipped spelling as if it
# were the name traffic carried, with no truncation flag and two long keys landing on one name; and
# it never folded homoglyph twins, so `amount` and Cyrillic-`amоunt` rendered as one name to the
# operator with nothing saying they were two.
from norviq.api.routers.evaluate import _param_key_set

log = structlog.get_logger()
router = APIRouter()

# Managed scopes that are not agent classes. Mirrors threats.py; drafting against one would target a
# policy row the catalog owns.
_RESERVED_CLASSES = {"__baseline__", "__pack__", "__pack_override__", "__pack_weaken__", "__guardrail__"}

_MAX_SAMPLE_CALLS = 2000
_DRAFT_TTL_DAYS = 14

# --- argument-name evidence ----------------------------------------------------------------------
#
# Three states, not two. `params_available` (a bool, unchanged) answers "are VALUES present"; this
# answers "how much do we know about the arguments at all", and the middle rung is the new one:
#   none    nothing was recorded about arguments. NOT "the call had no arguments".
#   keys    argument NAMES were recorded, values were not. A name is a schema fact, not payload.
#   masked  values are present (masked on a recorded row, verbatim on a caller-supplied one).
_PARAMS_NONE = "none"
_PARAMS_KEYS = "keys"
_PARAMS_MASKED = "masked"
_DETAIL_RANK = {_PARAMS_NONE: 0, _PARAMS_KEYS: 1, _PARAMS_MASKED: 2}

# Bounds on what the RESPONSE carries. The engine bounds ONE call's walk; a proposal unions up to
# `limit` calls, so the union has to be bounded again — 2000 rows x 256 paths is half a million
# attacker-chosen strings rendered in a console. Same ceilings as the engine's walk, applied to the
# union, and every cut is REPORTED: an operator shown 12 of 400 argument names who believes that is
# all of them is worse off than one shown none.
_MAX_KEYS_PER_TOOL = OPAEvaluator._MAX_PATHS
_MAX_KEY_LEN = OPAEvaluator._MAX_PATH_KEY_LEN
_MAX_TOOLS_REPORTED = OPAEvaluator._MAX_PATHS
# Mirrors propose.py's `_MAX_TOOLS_PER_RULE`: the ceiling is what one human can read in one rule, not
# what the compiler can emit.
_MAX_EXISTENCE_PER_RULE = 40
# "any value" — the predicate constrains NOTHING about the value. What makes it load-bearing is the
# derivation guard the compiler AND-s onto every `param_paths.*` operator: the path must be present
# and unambiguously derived. So this compiles to "this argument must be there", which is precisely
# what a proposal built from key names alone is entitled to assert.
_ANY_VALUE = ".*"


def _safe_key(name: object) -> bool:
    """Whether an observed argument name may be reported and pinned.

    Argument names come from the agent, which is to say from whoever compromised it. Two hard rules:
    a control character is never legitimate in an argument name and is the exact character class that
    escaped a generated policy's header comment before (see `builderCompile.ts`), and a name longer
    than the engine's own key bound is a name the engine never derived under that spelling.
    """
    return (
        isinstance(name, str)
        and bool(name)
        and len(name) <= _MAX_KEY_LEN
        and not any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in name)
    )


@dataclass
class _ValueEvidence:
    """What a set of REAL (or masked) argument values shows about the arguments, KEYS ONLY."""

    keys: set[str] = field(default_factory=set)
    pinnable: set[str] = field(default_factory=set)
    ambiguous: set[str] = field(default_factory=set)
    truncated: bool = False
    dropped: int = 0


def _value_bearing_keys(params: object, derived: dict) -> _ValueEvidence:
    """Argument PATH NAMES carried by a value-bearing call, in the engine's path grammar.

    No value is read into the result, compared, or returned. That is a STRUCTURAL guarantee here
    rather than a promise: ``_param_key_set`` type-erases every leaf to a one-byte token before the
    engine's flattener ever sees the object, so there is no value present for a name to be derived
    from, and it puts the derived NAMES through the same PAN/SSN masker the value capture uses —
    which matters because `mask_params` masks values and preserves keys, so a PAN that arrived in a
    KEY position is still sitting verbatim on the audit row.

    TWO derivations are AND-ed for pinnability, and neither alone is sufficient:

    * the shadow walk sees every leaf TYPE, so it names `amount: 25.0` (the argument the fintech
      report is about) and knows it is not a string and therefore not pinnable. It cannot see a value
      CLIPPED at the engine's value bound.
    * the walk over the real values — already done to build the policy input — does see the clip, and
      flags that path ambiguous exactly as the enforcement path will. A predicate over an ambiguous
      path is refused by the compiler's derivation guard, so proposing one proposes a rule that never
      matches, which under `default decision = "block"` is an outage.

    So `pinnable` is the intersection minus every flag either walk raised.
    """
    names, flagged, pinnable, truncated = _param_key_set(OPAEvaluator, params)
    if names is None:
        # The derivation failed. VALUES are present, so `params_available` is unchanged — but the
        # NAME set is unknown, and an empty list here would read as "this call carried no arguments".
        # `truncated` is the one word that says "what you are being shown is not the whole set".
        return _ValueEvidence(truncated=True)
    keys = {n for n in names if _safe_key(n)}
    ambiguous = {n for n in flagged if _safe_key(n)}
    ambiguous |= {p for p in (derived.get("param_paths_ambiguous") or []) if _safe_key(p)}
    return _ValueEvidence(
        keys=keys,
        pinnable=({p for p in pinnable if _safe_key(p)} & _pinnable_paths(derived)) - ambiguous,
        ambiguous=ambiguous,
        truncated=truncated,
        dropped=len(names) - len(keys),
    )


def _declared_keys(raw: object) -> tuple[set[str], bool, int]:
    """The audit row's ``param_keys`` as a validated key set: (keys, truncated, dropped).

    `param_keys` is written by the capture path as the flattened argument-path key set, KEYS ONLY.
    It arrives here as untrusted text and is treated as such: non-strings and names carrying a
    control character are DROPPED and COUNTED, never rendered, never turned into a predicate.
    """
    if not isinstance(raw, list):
        return set(), False, 0
    keys: set[str] = set()
    dropped = 0
    truncated = False
    for name in raw:
        if not _safe_key(name):
            dropped += 1
            continue
        if len(keys) >= _MAX_KEYS_PER_TOOL:
            truncated = True
            break
        keys.add(str(name))
    return keys, truncated, dropped


@dataclass
class _ToolEvidence:
    """What traffic showed about ONE tool's arguments."""

    calls: int = 0
    detail: str = _PARAMS_NONE
    # Every argument name observed, whatever the leaf type. This is what the console renders and
    # compares against the rule being authored.
    keys: set[str] = field(default_factory=set)
    # The subset whose VALUE the engine actually derives, unambiguously — the only paths a rule can
    # constrain. `amount: 25.0` is in `keys` and not here, and those two facts must not be conflated.
    pinnable: set[str] = field(default_factory=set)
    # Names a caller can MINT: the path grammar uses `.` and `[i]` as structure, so another route
    # through the payload can reach the same name and whichever the caller ordered last wins. A rule
    # pinned on one of these is a trap, so they are shown and never asserted.
    ambiguous: set[str] = field(default_factory=set)
    # Pinnable paths present on EVERY observed call. None until the first call is seen, which is not
    # the same as the empty set: "nothing observed yet" vs "observed, and nothing is universal".
    always: set[str] | None = None
    truncated: bool = False
    dropped: int = 0

    def observe(self, keys: set[str], pinnable: set[str], detail: str, truncated: bool,
                dropped: int, ambiguous: set[str]) -> None:
        self.calls += 1
        self.detail = max(self.detail, detail, key=lambda d: _DETAIL_RANK.get(d, 0))
        self.truncated = self.truncated or truncated
        self.dropped += dropped
        self.ambiguous.update(ambiguous)
        for name in sorted(keys):
            if name in self.keys:
                continue
            if len(self.keys) >= _MAX_KEYS_PER_TOOL:
                self.truncated = True  # the union is larger than what is reported — say so
                break
            self.keys.add(name)
        self.pinnable.update(p for p in pinnable if p in self.keys)
        self.pinnable -= self.ambiguous
        self.always = set(pinnable) if self.always is None else (self.always & set(pinnable))
        # Never assert a path that was cut from the REPORTED key set, and never one a caller can
        # mint. A predicate over a name the operator was not shown is a rule they cannot review; a
        # predicate over a forgeable name is the trap this whole derivation-guard machinery exists to
        # refuse. One call flagging a name is enough to disqualify it for the whole sample.
        self.always &= self.keys
        self.always -= self.ambiguous

    def as_dict(self) -> dict:
        return {
            # "none" with an empty key list means NOTHING WAS CAPTURED; "keys" with an empty key list
            # means the call genuinely carries no arguments. Rendering those the same way is this
            # project's recurring defect, so they are two different values here, not one absence.
            "detail": self.detail,
            "keys": sorted(self.keys),
            "pinnable": sorted(self.pinnable),
            "ambiguous": sorted(self.ambiguous & self.keys),
            "calls": self.calls,
            # A name REJECTED as unsafe to render is a name the operator will not be shown, which is
            # the same sentence as "this list is incomplete" — so it sets `truncated` too, rather
            # than being silently filtered behind a count only a careful reader looks at. `dropped`
            # keeps the precise reason for anyone who wants it.
            "truncated": self.truncated or self.dropped > 0,
            "dropped": self.dropped,
        }


@dataclass
class _ParamEvidence:
    """Argument-name evidence across the whole sample, plus the legacy boolean it must not disturb."""

    # UNCHANGED MEANING: masked/real VALUES were present on at least one call. Existing tests and the
    # console read it; `params_detail` is the field that carries the new middle state.
    params_available: bool = False
    tools: dict[str, _ToolEvidence] = field(default_factory=dict)
    # Calls whose arguments are known by NAME only. A replay of these cannot satisfy ANY value-level
    # predicate, so a dry run over them over-reports blocking — fail-closed, but it has to be named.
    calls_without_values: int = 0
    tools_truncated: bool = False

    def observe(self, tool_name: str, keys: set[str], pinnable: set[str], detail: str,
                truncated: bool, dropped: int = 0, ambiguous: set[str] | None = None) -> None:
        if detail == _PARAMS_KEYS:
            self.calls_without_values += 1
        name = str(tool_name or "")
        entry = self.tools.get(name)
        if entry is None:
            if len(self.tools) >= _MAX_TOOLS_REPORTED:
                self.tools_truncated = True
                return
            entry = self.tools[name] = _ToolEvidence()
        entry.observe(keys, pinnable, detail, truncated, dropped, ambiguous or set())

    @property
    def detail(self) -> str:
        """The best evidence held about ANY tool. Never better than what was actually recorded."""
        best = _PARAMS_NONE
        for entry in self.tools.values():
            if _DETAIL_RANK.get(entry.detail, 0) > _DETAIL_RANK.get(best, 0):
                best = entry.detail
        return best

    @property
    def truncated(self) -> bool:
        return (self.tools_truncated
                or any(t.truncated or t.dropped > 0 for t in self.tools.values()))

    def observed(self) -> dict:
        return {name: entry.as_dict() for name, entry in sorted(self.tools.items())}


def _pinnable_paths(derived: dict) -> set[str]:
    """Paths the engine derived AND vouches for, from an already-built policy input document.

    A path the engine flagged ambiguous is excluded: the compiler's derivation guard refuses to let
    any constraint hold over one, so proposing a predicate on it would be proposing a rule that can
    never match — a deny-by-default outage wearing the costume of a tighter policy.
    """
    ambiguous = set(derived.get("param_paths_ambiguous") or [])
    return {p for p in (derived.get("param_paths") or {}) if _safe_key(p) and p not in ambiguous}


def _rule_tools(rule: dict) -> list[str]:
    """Tool names a proposed rule admits. Mirrors the compiler's `_scoped_tool_names` for one rule."""
    spec = (rule.get("match") or {}).get("tool_name")
    if isinstance(spec, str):
        return [spec]
    if not isinstance(spec, dict):
        return []
    names = [spec["equals"]] if isinstance(spec.get("equals"), str) else []
    names.extend(v for v in (spec.get("in") or []) if isinstance(v, str))
    return names


def _add_existence_predicates(intent: dict, evidence: _ParamEvidence) -> tuple[dict, bool]:
    """Assert, on each proposed rule, that the arguments its traffic ALWAYS carried are present.

    This is the difference between a rule that names `issue_refund` and a rule that mentions `amount`.
    It is bounded by three things, each of which is the difference between a tighter rule and an
    outage:

    * only paths observed on EVERY call of every tool the rule admits. A path some calls carry would
      make the rule refuse the calls that do not — a proposal must never be narrower than the traffic
      it was proposed from.
    * only PINNABLE paths — ones the engine's own flattener derives and does not flag ambiguous,
      whether that was established here from recorded values or by the capture path and carried on
      the row as `param_keys_pinnable`. `amount: 25.0` is visible to the operator and is deliberately
      NOT pinned: `input.derived.param_paths` never carries a numeric leaf, so the predicate could
      not hold in production either, and a rule that never matches under deny-by-default is an
      outage rather than a tighter policy.
    * only paths the intent schema can address, and never a field the proposal already constrains
      (the schema rejects a field set in both `match` and `require`).

    Returns (rule id -> fields added, whether any rule hit the per-rule bound).
    """
    added: dict[str, list[str]] = {}
    bounded = False
    for rule in intent.get("call") or []:
        if not isinstance(rule, dict):
            continue
        tools = _rule_tools(rule)
        if not tools:
            continue  # a rule that does not scope by tool name cannot be attributed to traffic
        universal: set[str] | None = None
        for name in tools:
            entry = evidence.tools.get(name)
            seen = set() if entry is None or entry.always is None else set(entry.always)
            universal = seen if universal is None else (universal & seen)
        if not universal:
            continue
        already = set(rule.get("match") or {}) | set(rule.get("require") or {})
        fields = [f"param_paths.{p}" for p in sorted(universal)]
        fields = [f for f in fields if f not in already and _PARAM_PATH_RE.match(f)]
        if not fields:
            continue
        if len(fields) > _MAX_EXISTENCE_PER_RULE:
            fields = fields[:_MAX_EXISTENCE_PER_RULE]
            bounded = True
        require = rule.get("require")
        if not isinstance(require, dict):
            require = rule["require"] = {}
        for name in fields:
            # `require`, not `match`: this is a condition of permission, not a selector, and the
            # near-miss explainer labels the two differently.
            require[name] = {"matches": _ANY_VALUE}
        added[str(rule.get("id", ""))] = fields
    return added, bounded


def _params_notes(evidence: _ParamEvidence, added: dict, bounded: bool) -> list[str]:
    """What the proposal did about arguments, in the operator's words. Silence is not an answer."""
    notes: list[str] = []
    detail = evidence.detail
    if detail == _PARAMS_NONE:
        notes.append(
            "No call arguments were recorded for this class — neither values nor argument names — so "
            "these rules can only name tools and the operation they perform. That is an absence of "
            "evidence, not evidence that these tools take no arguments."
        )
    elif detail == _PARAMS_KEYS:
        notes.append(
            "Recorded traffic carries argument NAMES only; no value, masked or otherwise, was stored. "
            "Every name is shown so this rule can be checked against them by eye. A name can be "
            "asserted to be PRESENT where capture recorded that the engine derives a path from it "
            "(listed under `pinnable`); no value can be constrained without masked parameter capture, "
            "and a name outside `pinnable` — a numeric argument like `amount`, or a forgeable one — "
            "is never asserted, because `input.derived.param_paths` would not carry it at enforcement "
            "time and a rule that never matches refuses every call to that tool."
        )
    if added:
        count = sum(len(v) for v in added.values())
        notes.append(
            f"Added {count} existence predicate(s) across {len(added)} rule(s) over argument paths "
            "observed on EVERY recorded call of the tools each rule admits. Each requires the "
            "argument to be PRESENT and unambiguously derived; none constrains a value."
        )
    if bounded:
        notes.append(
            f"At least one rule carried more universally-observed argument paths than the "
            f"{_MAX_EXISTENCE_PER_RULE}-per-rule bound; the remainder were not asserted."
        )
    if evidence.truncated:
        notes.append(
            "The observed argument-name set was TRUNCATED at a capture or aggregation bound. More "
            "argument names exist than are listed here."
        )
    forgeable = sorted({k for t in evidence.tools.values() for k in (t.ambiguous & t.keys)})
    if forgeable:
        notes.append(
            f"{len(forgeable)} observed argument name(s) can be reached by more than one route "
            "through the payload, so a caller chooses which value answers them. A rule pinned on one "
            "is answered by whichever the caller ordered last — none was asserted, and each is "
            "listed under `ambiguous`."
        )
    # Every tool whose arguments were observed AT ALL, not only the value-bearing ones: a key-only
    # row reports `pinnable` too, so the gap between "shown" and "constrainable" exists there as well
    # and is exactly where `amount` sits. A tool at detail "none" is excluded — nothing was observed,
    # so `keys - pinnable` there is a blind spot, not a finding, and reporting it as one would be the
    # very conflation this feature exists to end.
    unpinnable = sorted({k for t in evidence.tools.values()
                         if t.detail != _PARAMS_NONE for k in (t.keys - t.pinnable - t.ambiguous)})
    if unpinnable:
        notes.append(
            f"{len(unpinnable)} observed argument path(s) carry no value this engine can constrain "
            "(a non-string leaf, or a path flagged ambiguous). They are listed under `keys` and "
            "omitted from `pinnable`: visible to the operator, and deliberately not pinned by a rule "
            "that could never match."
        )
    if evidence.calls_without_values:
        notes.append(
            f"{evidence.calls_without_values} of the sampled call(s) carry no recorded argument "
            "VALUES, so a dry run over them cannot satisfy any argument-level predicate and will "
            "over-report blocking. Turn on masked parameter capture before reading a dry-run "
            "argument refusal as a real one."
        )
    return notes


class SampleCall(BaseModel):
    """One call to replay. `tool_params` is optional — see `params_detail` on the response."""

    tool_name: str = Field(max_length=255)
    tool_params: dict = Field(default_factory=dict)
    server: str = Field(default="", max_length=255)


class CompileRequest(BaseModel):
    intent: dict


class ProposeRequest(BaseModel):
    ns: str = "all"
    cls: str = Field(max_length=255)
    name: str = Field(default="proposed-intent", max_length=63)
    limit: int = Field(default=500, ge=1, le=_MAX_SAMPLE_CALLS)
    # Callers may supply calls directly when audit param capture is off (the default).
    calls: list[SampleCall] = Field(default_factory=list)


class DryRunRequest(BaseModel):
    ns: str = "all"
    cls: str = Field(max_length=255)
    intent: dict
    limit: int = Field(default=500, ge=1, le=_MAX_SAMPLE_CALLS)
    calls: list[SampleCall] = Field(default_factory=list)


class DraftRequest(BaseModel):
    ns: str = Field(max_length=255)
    cls: str = Field(max_length=255)
    intent: dict


def _policy_input(tool_name: str, tool_params: dict, agent_class: str, namespace: str, server: str = "") -> dict:
    """Build the same document the evaluator builds, so a replay exercises the real contract."""
    ev = OPAEvaluator.__new__(OPAEvaluator)  # only the pure derived-input helpers are used
    event = type("E", (), {"tool_name": tool_name, "tool_params": tool_params, "agent_identity": None})()
    return {
        "tool_name": tool_name,
        "tool_params": tool_params,
        "derived": ev._derived_input(event),
        "agent": {"agent_class": agent_class, "namespace": namespace},
        "trust_category": "high",
        "mcp": {"server": server} if server else {},
        "direction": "call",
    }


async def _recorded_calls(
    session: AsyncSession, namespaces: list[str] | None, agent_class: str, limit: int
) -> tuple[list[dict], _ParamEvidence]:
    """Recent audit rows for a class, as policy input documents, plus what they show about arguments.

    Returns (calls, evidence). The honest ceiling this docstring has always described is now a
    THREE-state one, because two of those states used to be spelled the same way:

    * ``masked``  — ``audit_capture_masked_params`` is on. Values are present and MASKED. Recipient
      domains, data classes and SQL tables are reachable, which is what makes a destination-level
      rule proposable at all.
    * ``keys``    — ``audit_capture_param_keys`` is on (the default). The row carries the flattened
      argument-path KEY SET and no values. A proposal cannot constrain a value, but it can name the
      arguments traffic actually carries — and that is the fact an operator needs to notice that the
      rule they are about to save never mentions ``amount``.
    * ``none``    — neither. Nothing is known about arguments. An OLD row, written before
      ``param_keys`` existed, lands here: absent is ``none``, never ``keys``, because reporting an
      empty key set as complete would assert "this tool takes no arguments" from no evidence at all.

    ``params_available`` keeps its original meaning exactly — VALUES present — because the console
    and existing tests read it. It is deliberately NOT widened to cover the ``keys`` state:
    ``params_detail`` carries that, and repurposing the boolean would make every existing reader
    silently wrong about what it was told.
    """
    stmt = select(AuditLogEntry).where(AuditLogEntry.agent_class == agent_class)
    if namespaces is not None:
        stmt = stmt.where(AuditLogEntry.namespace.in_(namespaces))
    stmt = stmt.order_by(desc(AuditLogEntry.timestamp_utc)).limit(limit)
    rows = (await session.execute(stmt)).scalars().all()

    calls: list[dict] = []
    evidence = _ParamEvidence()
    for row in rows:
        payload = row.payload if isinstance(row.payload, dict) else {}
        masked = payload.get("masked_params")
        params = masked if isinstance(masked, dict) and masked else {}
        mcp = payload.get("mcp")
        server = str((mcp or {}).get("server", "")) if isinstance(mcp, dict) else ""
        document = _policy_input(row.tool_name, params, agent_class, row.namespace, server)
        calls.append(document)

        # `param_keys` is written independently of masked capture, so a row may carry either, both or
        # neither. Whether it is PRESENT — not whether it is non-empty — is what separates "captured,
        # and there are no arguments" from "nothing was captured".
        declared, declared_truncated, dropped = _declared_keys(payload.get("param_keys"))
        declared_present = isinstance(payload.get("param_keys"), list)
        flagged, flagged_truncated, flagged_dropped = _declared_keys(payload.get("param_keys_ambiguous"))
        # A NAME THE ROW ITSELF VOUCHES FOR AS PINNABLE. The capture path runs the engine's own
        # flattener over a type-erased shadow, so it knows per path which leaf TYPE stood at the end
        # of it, and publishes the POSITIVE subset — the paths `input.derived.param_paths` will carry
        # at enforcement time, minus the forgeable ones. That is the fact that makes an existence
        # predicate sound from a name-only row, and it is why the field is published as the positive
        # set: a reader that does not find it pins NOTHING, whereas one subtracting an absent
        # "unpinnable" list would treat every name as safe to assert.
        vouched, vouched_truncated, vouched_dropped = _declared_keys(payload.get("param_keys_pinnable"))
        # A vouched name that is not in the key set was never SHOWN, and a rule may not assert what
        # the operator was not shown. Ambiguity wins over vouching in both directions.
        vouched = (vouched & declared) - flagged
        # An ambiguity or vouching list that was itself cut short is a list that may be MISSING a
        # flag, so it is reported as truncation too rather than read as complete.
        row_truncated = (bool(payload.get("param_keys_truncated"))
                         or declared_truncated or flagged_truncated or vouched_truncated)
        row_dropped = dropped + flagged_dropped + vouched_dropped
        if params:
            evidence.params_available = True
            observed = _value_bearing_keys(params, document.get("derived") or {})
            evidence.observe(
                row.tool_name,
                # `declared` adds NAMES the value walk could not reach (a row whose masked_params were
                # themselves truncated). It never adds pinnability on this branch: the engine's own
                # derivation over the real values is strictly better evidence and already ran.
                keys=observed.keys | declared,
                pinnable=observed.pinnable - flagged,
                detail=_PARAMS_MASKED,
                truncated=row_truncated or observed.truncated,
                dropped=row_dropped + observed.dropped,
                ambiguous=flagged | observed.ambiguous,
            )
        elif declared_present:
            evidence.observe(
                row.tool_name,
                keys=declared,
                # A NAME ALONE VOUCHES FOR NOTHING; `param_keys_pinnable` is not a name alone.
                #
                # The distinction is the difference between a tighter rule and a total outage, so it
                # is worth being exact about. `param_keys` is deliberately type-BLIND — it names
                # `amount` in `{"txn_id": "TXN-8891", "amount": 25.0}` because that numeric argument
                # is the entire reason this feature exists. At enforcement time
                # `input.derived.param_paths` carries STRING leaves only, so a rule requiring
                # `param_paths.amount` to be present could never match, and a rule that never matches
                # under `default decision = "block"` refuses EVERY call to that tool. The dry run
                # cannot catch it either: over name-only rows a replay reconstructs no `param_paths`
                # at all, so every argument predicate fails and a poisonous one is indistinguishable
                # from a sound one.
                #
                # What makes `amount` safe to SHOW and unsafe to ASSERT is knowing which of the two it
                # is — and the capture path recorded exactly that, separately, in
                # `param_keys_pinnable`. So `txn_id` is asserted and `amount` is not, from a row that
                # stores no values at all. Reporting `pinnable: []` here instead would tell the
                # console that nothing on this tool can be constrained, which is false and is the
                # blind spot this work exists to remove.
                pinnable=vouched,
                detail=_PARAMS_KEYS,
                truncated=row_truncated,
                dropped=row_dropped,
                ambiguous=flagged,
            )
        else:
            evidence.observe(row.tool_name, keys=set(), pinnable=set(), detail=_PARAMS_NONE,
                             truncated=row_truncated, dropped=row_dropped, ambiguous=flagged)
    return calls, evidence


def _sample_calls(body_calls: list[SampleCall], agent_class: str, namespace: str,
                  evidence: _ParamEvidence) -> list[dict]:
    """Caller-supplied calls as policy input documents, recording their argument evidence too.

    A supplied call is the one case where the arguments arrive UNMASKED, so its evidence is `masked`
    (the rung means "values present") when it carries any — and `keys` when it carries none, because
    an explicitly supplied empty argument object IS an observation that the call takes no arguments.
    That is the distinction an absent audit payload cannot make.

    Unmasked is also why the names go through the SAME derivation the capture path uses: this is the
    one route by which a raw, unmasked payload reaches this module, so a PAN sitting in a key
    position would otherwise be echoed straight back into `observed_params` and into the console.
    """
    documents: list[dict] = []
    for call in body_calls:
        document = _policy_input(call.tool_name, call.tool_params, agent_class, namespace, call.server)
        documents.append(document)
        observed = _value_bearing_keys(call.tool_params, document.get("derived") or {})
        evidence.observe(
            call.tool_name,
            keys=observed.keys,
            pinnable=observed.pinnable,
            detail=_PARAMS_MASKED if call.tool_params else _PARAMS_KEYS,
            truncated=observed.truncated,
            dropped=observed.dropped,
            ambiguous=observed.ambiguous,
        )
    return documents


async def _opa_evaluator(request_scope_id: str):
    """An evaluator backed by the shared OPA server, loading the candidate under a scratch package.

    The module is removed afterwards. It is never written to ``policies``, so it cannot be picked up
    by the policy loader even transiently.
    """
    from norviq.engine.opa_client import OpaClient, rewrite_package

    client = OpaClient()
    package = f"norviq.intent_dryrun.{request_scope_id}"
    module_id = f"intent-dryrun-{request_scope_id}"

    async def evaluate(rego: str, payload: dict) -> dict:
        return await client.query(package, payload) or {}

    async def load(rego: str) -> None:
        await client.push_policy(module_id, rewrite_package(rego, package))

    async def unload() -> None:
        await client.delete_policy(module_id)

    return evaluate, load, unload, client


@router.post("/intents/compile")
async def compile_endpoint(body: CompileRequest, user: dict = Depends(get_current_user)):
    """Validate and compile. Returns the Rego an operator would be asked to approve."""
    try:
        compiled = compile_intent(body.intent)
    except IntentError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {
        "rego": compiled.rego,
        "rule_ids": list(compiled.rule_ids),
        "labels": compiled.labels,
        "sha256": hashlib.sha256(compiled.rego.encode()).hexdigest(),
    }


@router.post("/intents/propose")
async def propose_endpoint(
    body: ProposeRequest,
    session: AsyncSession = Depends(get_session),
    user: dict = Depends(get_current_user),
):
    """Propose a candidate intent from what the class actually did. Nothing is stored."""
    if body.cls in _RESERVED_CLASSES:
        raise HTTPException(status_code=422, detail=f"'{body.cls}' is a managed scope, not an agent class.")
    namespaces = _resolve_namespaces(user, body.ns)
    calls, evidence = await _recorded_calls(session, namespaces, body.cls, body.limit)
    if body.calls:
        ns = (namespaces or [""])[0]
        calls.extend(_sample_calls(body.calls, body.cls, ns, evidence))
        # Unchanged: supplying calls has always set this true. `params_detail` and `observed_params`
        # are the fields that stay honest when the supplied calls carry no arguments.
        evidence.params_available = True
    if not calls:
        raise HTTPException(
            status_code=422,
            detail=f"no recorded traffic for class '{body.cls}'; run it in monitor mode first, or supply calls",
        )
    intent = propose_intent(body.name, body.cls, calls)
    added, bounded = _add_existence_predicates(intent, evidence)
    log.info("nrvq.api.intent.proposed", cls=body.cls, rules=len(intent["call"]),
             sampled=len(calls), params_available=evidence.params_available,
             params_detail=evidence.detail, existence_predicates=sum(len(v) for v in added.values()),
             code="NRVQ-API-7110")
    return {
        "intent": intent,
        "sampled": len(calls),
        "params_available": evidence.params_available,
        "params_detail": evidence.detail,
        # tool -> what its traffic showed about arguments. The console renders this against the rule
        # being authored and flags a name that is in traffic and not in the rule.
        "observed_params": evidence.observed(),
        # ONE fact, two spellings, deliberately: "the argument-name set you are being shown is not
        # complete". `observed_params_truncated` is the name the console reads; `params_truncated`
        # reads better beside `params_detail` for an API caller. They are always equal — and the flag
        # covers the one truncation with no per-tool home, which is running out of room for TOOLS.
        "observed_params_truncated": evidence.truncated,
        "params_truncated": evidence.truncated,
        # What the proposal DID about arguments, as data and as sentences.
        "existence_predicates": added,
        "params_notes": _params_notes(evidence, added, bounded),
    }


@router.post("/intents/dry-run")
async def dry_run_endpoint(
    body: DryRunRequest,
    session: AsyncSession = Depends(get_session),
    user: dict = Depends(get_current_user),
):
    """Replay recorded calls against a candidate intent. Enforces nothing, stores nothing."""
    if body.cls in _RESERVED_CLASSES:
        raise HTTPException(status_code=422, detail=f"'{body.cls}' is a managed scope, not an agent class.")
    namespaces = _resolve_namespaces(user, body.ns)
    try:
        compiled = compile_intent(body.intent)
    except IntentError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    calls, evidence = await _recorded_calls(session, namespaces, body.cls, body.limit)
    if body.calls:
        ns = (namespaces or [""])[0]
        calls.extend(_sample_calls(body.calls, body.cls, ns, evidence))
        evidence.params_available = True
    if not calls:
        raise HTTPException(status_code=422, detail=f"no recorded traffic for class '{body.cls}' to replay")

    # Letter-prefixed: a Rego package segment may not start with a digit, and a raw hex scope starts
    # with one about 62% of the time — which presents as an intermittent "illegal number format"
    # parse error rather than anything that points at the package name.
    scope = "s" + uuid.uuid4().hex[:12]
    evaluate, load, unload, client = await _opa_evaluator(scope)
    try:
        await load(compiled.rego)
        # dry_run is sync; the OPA call is async, so the replay is driven here and the pure
        # accounting is reused rather than duplicated.
        # The OPA call is async and dry_run() is sync, so the replay is driven here and the pure
        # accounting is reused rather than duplicated. The closure hands back the pre-computed result
        # for each call in order.
        results = [await evaluate(compiled.rego, payload) for payload in calls]
        cursor = {"i": 0}

        def _replay(_rego: str, _payload: dict) -> dict:
            result = results[cursor["i"]]
            cursor["i"] += 1
            return result

        report = dry_run(compiled, calls, evaluator=_replay)
    finally:
        try:
            await unload()
        finally:
            await client.stop()

    log.info("nrvq.api.intent.dry_run", cls=body.cls, total=report.total,
             would_block=report.would_block, params_detail=evidence.detail, code="NRVQ-API-7111")
    out = report.as_dict()
    out["params_available"] = evidence.params_available
    out["params_detail"] = evidence.detail
    out["observed_params"] = evidence.observed()
    # THE REPLAY'S OWN CEILING, reported as a count rather than folded into `would_block`. A row that
    # recorded argument NAMES and no values reconstructs to an input document with no `param_paths`,
    # so every argument-level predicate reads as unsatisfied and the call replays as a block. That is
    # fail-closed and therefore the right direction — but a refusal caused by what the AUDIT LOG
    # lacks is not a refusal the candidate policy would make in production, and the two must not be
    # reported as the same number.
    out["replayed_without_values"] = evidence.calls_without_values
    out["params_notes"] = _params_notes(evidence, {}, False)
    return out


@router.post("/intents/drafts")
async def create_draft(
    body: DraftRequest,
    session: AsyncSession = Depends(get_session),
    user: dict = Depends(get_current_user),
):
    """Persist a NON-ENFORCING draft. Never writes to ``policies``; applying stays the gated flow."""
    require_admin(user)
    if body.cls in _RESERVED_CLASSES:
        raise HTTPException(status_code=422, detail=f"'{body.cls}' is a managed scope — draft a real agent class.")
    namespaces = _resolve_namespaces(user, body.ns)
    if namespaces is not None and body.ns not in namespaces:
        raise HTTPException(status_code=403, detail="namespace not permitted for this caller")
    try:
        compiled = compile_intent(body.intent)
    except IntentError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    draft_id = f"intent-{uuid.uuid4().hex[:16]}"
    session.add(
        IntentDraft(
            id=draft_id,
            namespace=body.ns,
            agent_class=body.cls,
            rego_source=compiled.rego,
            # `allow_tools` is the pre-existing column the Policy Catalog renders. The full intent
            # rides in `toggles` so the console can round-trip and re-edit it rather than being left
            # with generated Rego it cannot map back to the sentences that produced it.
            allow_tools={"rule_ids": list(compiled.rule_ids)},
            toggles={"intent": body.intent, "kind": "intent-v2"},
            priority=1,
            created_by=str(user.get("sub", "")),
            expires_at=datetime.now(UTC) + timedelta(days=_DRAFT_TTL_DAYS),
        )
    )
    await session.commit()
    log.info("nrvq.api.intent.draft_created", draft=draft_id, cls=body.cls,
             ns=body.ns, rules=len(compiled.rule_ids), code="NRVQ-API-7112")
    return {"draft_id": draft_id, "rule_ids": list(compiled.rule_ids), "enforcing": False}


def _mapping(value: object) -> dict:
    """The JSONB column as a mapping, whatever shape the row actually holds.

    `IntentDraft.toggles` / `.allow_tools` are typed `dict | None` and are ALSO written as lists by
    `threats.py` and `mitre.py`. Anything that is not a mapping yields an empty one, so a reader
    asking for a key gets the default instead of an AttributeError.
    """
    return value if isinstance(value, dict) else {}


@router.get("/intents/drafts")
async def list_drafts(
    ns: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    session: AsyncSession = Depends(get_session),
    user: dict = Depends(get_current_user),
):
    """Pending intent drafts. Reads the dedicated table, never ``policies``."""
    namespaces = _resolve_namespaces(user, ns if ns is not None else "all")
    stmt = select(IntentDraft)
    if namespaces is not None:
        stmt = stmt.where(IntentDraft.namespace.in_(namespaces))
    stmt = stmt.order_by(desc(IntentDraft.created_at)).limit(limit)
    rows = (await session.execute(stmt)).scalars().all()
    return {
        "drafts": [
            {
                "draft_id": r.id,
                "namespace": r.namespace,
                "agent_class": r.agent_class,
                # `toggles` and `allow_tools` are typed `dict | None`, but THREE other producers
                # legitimately store a LIST in them: threats.py's intent generator (`enabled_keys()`),
                # its verb-promotion path (`verbs`), and mitre.py's control mapping (`usable` rule
                # ids). `threats.py` reads those back as `list(r["toggles"] or [])`, so both shapes
                # are real and long-standing.
                #
                # `(r.toggles or {}).get(...)` therefore raised AttributeError on any list-shaped row
                # — and because this is a LIST endpoint, one such row 500'd the whole drafts inbox for
                # every caller and every namespace. Creating a draft from the Attack Graph or from
                # MITRE permanently broke the inbox. Observed on AKS: a plain GET returned 500.
                #
                # Read defensively at the boundary rather than migrating the column: the list shape is
                # in use by shipped features and in existing rows, so narrowing it would be a breaking
                # change to fix a display default.
                "kind": _mapping(r.toggles).get("kind", "intent"),
                "rule_ids": _mapping(r.allow_tools).get("rule_ids", []),
                "would_block": r.would_block,
                "total": r.total,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "enforcing": False,
            }
            for r in rows
        ]
    }
