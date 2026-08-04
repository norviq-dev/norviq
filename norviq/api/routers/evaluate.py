# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Evaluation route for policy decisions."""

from __future__ import annotations

import re
from functools import partial
from time import perf_counter

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, ValidationError

from norviq.api.audit_hub import audit_record
from norviq.api.auth import attested_namespace, get_current_user, scoped_identity, scoped_namespace
from norviq.config import settings
from norviq.engine.capability import Verb, classify_tool
from norviq.engine.evaluator import OPAEvaluator
from norviq.engine.masking import mask_params, mask_text
from norviq.sdk.core.decisions import PolicyDecision
from norviq.sdk.core.events import ToolCallEvent
from norviq.telemetry.metrics import record_path_phase

log = structlog.get_logger()

router = APIRouter()


# --- argument-NAME capture -------------------------------------------------------------------
#
# An audit row records that `issue_refund` ran; it has never recorded what it ran WITH unless
# audit_capture_masked_params was on, and that is off by default because it stores VALUES. So a rule
# proposed from recorded traffic could only ever name tools, and the control that actually matters
# for a refund tool is on the ARGUMENTS — which is precisely the thing traffic could not express.
#
# Key names are not payload data. mask_params() has always PRESERVED keys while masking values, so
# the names were available all along and were simply never persisted. What is stored here is KEYS
# ONLY, and the leaf-token substitution below makes that a structural guarantee rather than a
# promise: the flattener is never shown a real value, so there is no value for it to publish.

# The shadow's leaf stand-ins. Non-empty (the flattener only emits a path for a non-empty string
# leaf), one byte of type, and short enough that the flattener's value-length bound is never in play.
# NUL-prefixed so they cannot collide with anything a caller could legitimately send.
_LEAF_TOKENS = {
    str: "\x00s",
    bool: "\x00b",
    int: "\x00i",
    float: "\x00f",
    type(None): "\x00n",
}
_LEAF_TOKEN_OTHER = "\x00?"
_LEAF_TOKEN_STR = _LEAF_TOKENS[str]

# A KEY IS NOT ALWAYS A SCHEMA FACT. The premise of this whole field is that a key name is something
# the operator wrote and a value is something the model chose — true for `{"amount": 25.0}`, false
# the moment an argument is a MAP KEYED BY DATA: `{"balances": {"4111111111111111": 25.0}}` puts a
# PAN in a key position, and `{"rows": {"123-45-6789": ...}}` puts an SSN there. Type-erasing the
# leaves does nothing about that — the leak arrives through the key, which is copied verbatim by
# design. Left alone this field would persist PAN/SSN into every audit row BY DEFAULT on an install
# that has value capture deliberately switched OFF, which is a strictly worse privacy posture than
# the opt-in masked_params it sits beside.
#
# So derived NAMES are put through the codebase's existing `mask_text` — the same PAN/SSN masker the
# opt-in value capture uses, not a second notion of what is sensitive. A name it rewrites is no
# longer the engine's path, so it can never be pinned by a rule (see `param_keys_pinnable`).
#
# The prefilter is a pure cost guard and is deliberately WIDER than what it guards: every pattern
# mask_text can rewrite (a 16-digit PAN, a 13-19 digit run, an SSN) needs at least three consecutive
# digits, so a name with no such run cannot be changed by it. Ordinary argument names have none,
# which keeps the masker off the hot path for real traffic.
_NAME_MAY_CARRY_DATA = re.compile(r"\d{3}")


def _safe_name(name: str) -> str:
    """One derived argument NAME, with any payload that arrived through a key position masked."""
    return mask_text(name) if _NAME_MAY_CARRY_DATA.search(name) else name


# `_walk_paths` reads nothing but class-level bounds, so the CLASS is a valid `self`. This is the
# fallback for an app.state.evaluator that does not expose it (a test double, a mis-wired state):
# the capture then still behaves identically instead of silently disappearing, which would show up
# in the console as "this call carried no arguments" — the one thing it must never say by accident.
_CLASS_WALK_PATHS = partial(OPAEvaluator._walk_paths, OPAEvaluator)


def _param_key_shadow(node: object, max_depth: int, max_leaves: int, max_nodes: int) -> tuple[object, bool]:
    """A type-erased copy of tool_params: same keys, same shape, every LEAF replaced by a token.

    THIS IS NOT A SECOND FLATTENER, and the distinction is the whole point. It produces no paths,
    applies no path grammar and names nothing; it only strips values so that the ONE flattener
    (`OPAEvaluator._walk_paths`) can be run over a structure that is safe to derive names from.
    Every question about what an argument path IS — the dot/`[i]` grammar, the depth and count caps,
    which keys are forgeable — is still answered in exactly one place, by the engine. If the two
    disagreed, an operator would be authoring against paths the enforcement layer does not use, which
    is the two-components-keyed-differently defect this codebase has been bitten by before.

    IT ALSO FIXES A REAL GAP. `_walk_paths` emits a path only for a STRING leaf — correct for its own
    job, since matching the string "1" against an integer 1 matches a coincidence of formatting. But
    `{"txn_id": "TXN-8891", "amount": 25.0}` would then report `txn_id` and stay silent about
    `amount`: the numeric argument, the one the money moves through, and exactly the argument the
    operator's rule failed to mention. Type-erasing every leaf to a token means the name is reported
    whatever the value's type, while the value itself never leaves this function.

    Returns the shadow and whether anything was DROPPED reaching it. Truncation is reported rather
    than absorbed: a key-set cut short and silently presented as complete is the fail-open shape this
    project keeps rediscovering — an operator shown 12 of 400 argument names, believing that is all
    of them, is worse off than one shown none.

    BOUNDED ON NODES, NOT ONLY ON LEAVES, and that is not a detail. A leaf budget bounds nothing on
    `{"a": [[], [], [], ...]}`: empty containers cost no leaves, so the walk runs to the end of the
    body and this function additionally MATERIALISES a copy of it. Measured on the enforcement hot
    path, 400k empty lists — around a megabyte of JSON — cost 1.7 s and 26 MB inside this call alone,
    all of it synchronous in the event loop, i.e. an availability defect handed to every other
    request in flight rather than only to the one that asked for it.

    `max_nodes` is not a new bound: it is the engine's own two, multiplied. A leaf has at most
    `max_depth` ancestors and there are at most `max_leaves` of them, so any structure that can still
    contribute a name fits inside `max_leaves * max_depth` nodes. Exceeding it therefore means the
    excess is containers holding nothing nameable — dropped, and SAID to be dropped, because a
    caller who can shrink the reported key-set must not also be able to make it look complete.
    """
    truncated = False
    leaves = 0
    nodes = 0

    def shadow(value: object, depth: int) -> object:
        nonlocal truncated, leaves, nodes
        nodes += 1
        # The engine drops anything past its depth cap. Say so, and stop descending: returning the
        # token here costs nothing, because the flattener applies the SAME cap to the same shape and
        # will drop it again. The engine stays the authority on what is in the set.
        if depth > max_depth:
            truncated = True
            return _LEAF_TOKEN_OTHER
        if isinstance(value, dict):
            out: dict = {}
            for key, child in value.items():
                if leaves >= max_leaves or nodes >= max_nodes:
                    truncated = True
                    break
                # Keys are copied VERBATIM, including non-string keys, so `_walk_paths` sees the
                # same dict `_mints_a_path` would have seen on the real params and its forgery test
                # (is this key's first segment also a sibling?) still answers correctly.
                out[key] = shadow(child, depth + 1)
            return out
        if isinstance(value, (list, tuple)):
            items: list = []
            for child in value:
                if leaves >= max_leaves or nodes >= max_nodes:
                    truncated = True
                    break
                items.append(shadow(child, depth + 1))
            return items
        leaves += 1
        return _LEAF_TOKENS.get(type(value), _LEAF_TOKEN_OTHER)

    return shadow(node, 0), truncated


def _param_key_set(evaluator: object, params: object) -> tuple[list[str] | None, list[str], list[str], bool]:
    """(argument names, the untrustworthy ones, the PINNABLE ones, whether the set was cut short).

    A `None` name-list means the set could not be derived at all — the caller must then write
    NOTHING, because an empty list is the positive claim "this call carried no arguments" and a
    failed derivation has not earned it.

    AMBIGUOUS NAMES ARE PUBLISHED, NOT DROPPED. The path grammar uses `.` and `[i]` as structure, so
    a caller-supplied key can mint a name that some other route also reaches — and an operator who
    writes a rule against a forged name has been walked into a trap by the very screen that was
    meant to protect them. Dropping such names would be worse (the console would show a shorter,
    confident list); rewriting them would make the screen disagree with the policy. So they are
    listed AND named, exactly as the engine does for `param_paths_ambiguous`.

    A NAME BEING OBSERVED IS NOT THE SAME FACT AS A RULE BEING ABLE TO CONSTRAIN IT, and a row that
    records only the first invites the second. Type-erasing the leaves means
    `{"txn_id": "TXN-8891", "amount": 25.0}` reports BOTH names — the entire point, because `amount`
    is the argument the money moves through. What it cannot report is that `amount` was a NUMBER,
    and at enforcement time `input.derived.param_paths` carries STRING leaves only. The compiler
    AND-s every `param_paths.*` predicate with
    `object.get(input.derived.param_paths, "amount", null) != null`, so a predicate over `amount` is
    false on every call that carries a numeric amount. Under `default decision = "block"` an intent
    is a set of ALLOW arms, so that does not leak the call — it refuses EVERY call to the tool, a
    total outage the operator did not author. Nor does the dry run catch it: a replay over key-only
    rows has no `param_paths` at all, so every argument predicate fails and the poisonous one is
    indistinguishable from the sound ones.

    So the row records the two facts SEPARATELY: `param_keys` is everything traffic carried (show it
    all — visibility is the deliverable), and `param_keys_pinnable` is the subset the engine's own
    flattener would have derived from a real value, minus anything it flagged as forgeable. The
    POSITIVE set is published rather than its complement so the failure mode is closed: a reader
    that finds the field absent — an older row, a partial derivation — pins nothing, whereas a
    reader subtracting an absent "unpinnable" list would treat every name as safe to assert.

    WHAT PINNABLE DOES NOT PROMISE. It says the engine derives this path from a value of the shape
    this call carried; it cannot say no FUTURE call flags it. A string longer than
    `_MAX_PATH_VALUE_LEN`, or a second route arriving at the path with a different value, is named
    ambiguous at enforcement time from the VALUE — which this derivation deliberately never sees.
    The guard then refuses to hold over it, which is the compiler's existing behaviour and the safe
    direction; it is a property of proposing from recorded traffic, not something this field cures.
    """
    walk = getattr(evaluator, "_walk_paths", None)
    bounds: object = evaluator
    # It must be a BOUND method, not merely callable. `app.state.evaluator` holding a CLASS (or any
    # unbound function) passes a `callable()` test and then receives the shadow as its own `self`,
    # which fails on every single request — and the failure is invisible, because the safe branch
    # writes nothing and the console renders that as "this call carried no arguments".
    if getattr(walk, "__self__", None) is None:
        walk, bounds = _CLASS_WALK_PATHS, OPAEvaluator
    try:
        # Bounds are READ FROM THE ENGINE rather than restated here. A second copy of "256" in this
        # file is a second bound that drifts on the first tuning change.
        max_depth = int(getattr(bounds, "_MAX_PATH_DEPTH", OPAEvaluator._MAX_PATH_DEPTH))
        max_paths = int(getattr(bounds, "_MAX_PATHS", OPAEvaluator._MAX_PATHS))
        shadow, truncated = _param_key_shadow(params, max_depth, max_paths, max_paths * max_depth)
        paths, ambiguous = walk(shadow)
        # The shadow's leaf TOKEN is the discriminator, so pinnability costs no second walk: the
        # flattener has already reported, per path, which type stood at the end of it.
        flagged = {_safe_name(str(name)) for name in ambiguous}
        names = {_safe_name(name) for name in paths}
        pinnable = {
            safe
            for name, token in paths.items()
            # A name the masker rewrote is no longer the path the engine derives, so it is a name to
            # SHOW and never one to assert — same rule as a non-string leaf, for the same reason.
            if token == _LEAF_TOKEN_STR and (safe := _safe_name(name)) == name and safe not in flagged
        }
    except Exception as exc:
        # Fire-and-forget audit enrichment must never fail a tool call, and must never degrade into
        # a confident empty answer. Reported by type only: the exception text could quote a key.
        log.warning("nrvq.audit.param_keys_failed", error_type=type(exc).__name__, code="NRVQ-AUD-6009")
        return None, [], [], False
    # `len(paths) >= max_paths` cannot distinguish "filled exactly" from "stopped early", so it is
    # read as stopped early. Over-reporting truncation tells an operator there may be more names;
    # under-reporting tells them there are none. Only one of those is safe.
    return sorted(names), sorted(flagged), sorted(pinnable), bool(truncated or len(paths) >= max_paths)


class EvaluateRequest(BaseModel):
    """Payload for a tool evaluation call."""

    tool_name: str
    tool_params: dict = Field(default_factory=dict)
    agent_identity: dict
    session_id: str = ""
    trust_score: float = 0.0
    call_depth: int = 0
    framework: str = "redteam"
    # Optional MCP protocol context (server id, transport, pin status, Gate-A scan severity). Absent
    # for every non-MCP caller, so this is additive: an existing sidecar/SDK body is unchanged and
    # every existing policy still sees exactly the input document it saw before.
    mcp: dict = Field(default_factory=dict)


class EvaluateResponse(BaseModel):
    """Flattened evaluation result payload."""

    decision: str
    rule_id: str
    trust_score: float


@router.post("/evaluate")
async def evaluate_tool_call(
    payload: EvaluateRequest,
    request: Request,
    user: dict = Depends(get_current_user),
) -> EvaluateResponse:
    """Evaluate one tool call against active policies."""
    # Handler-level attribution. The evaluator reports its own phases and the outermost ASGI timer
    # reports the total, but between them sat ~32ms that NOTHING measured: FastAPI routing and
    # dependency resolution, request/response model validation, and the post-decision audit work. The
    # phases below close that, and `route_total` vs the outer `total_asgi` is the framework's own cost
    # — the part no application-level timer can see.
    _t_handler = perf_counter()
    # Bind the evaluated namespace to the CALLER, not the client-supplied body. scoped_namespace()
    # already gives a service credential (sidecar/SDK/break-glass) the trusted hot path: an EMPTY namespace
    # claim on a service token is treated as authorized for any requested namespace, while a NON-empty
    # claim must match. A HUMAN token (admin/viewer) must be authorized for the namespace it asks to
    # evaluate — admin = any, non-admin → 403 on mismatch (matches every other tenant-scoped route).
    # Calling this unconditionally (instead of skipping it for role=service) closes a cross-tenant hole
    # where a sidecar token scoped to namespace A could evaluate as namespace B.
    effective_ns = scoped_namespace(user, (payload.agent_identity or {}).get("namespace"))
    # ...and resolve the SIBLING identity fields in the same dict from the credential too. `agent_class`
    # selects which Rego program is enforced, `spiffe_id` keys the trust score + the agent_frozen:
    # kill-switch, and `workload` pulls in the workload tier — so binding only `namespace` left an
    # intra-namespace escalation. Note this REWRITES the identity rather than just validating it: an
    # omitted/empty field is as powerful as a substituted one (dropping agent_class silently falls back
    # to the looser __baseline__), so the credential's value is written back over the body's.
    identity = scoped_identity(user, payload.agent_identity)
    # Finally, prefer the namespace ATTESTED by the caller's own SVID over both the body and an absent
    # claim. scoped_namespace above still lets a machine principal with an EMPTY namespace claim take the
    # body's namespace — necessary latitude for the hot path, but it means an unbound service token could
    # evaluate as any tenant. A Norviq SVID encodes its namespace (spiffe://norviq/ns/<ns>/sa/<sa>) and
    # spiffe_id is already credential-bound, so the workload names its own namespace and the body cannot
    # choose it. Returns "" when nothing is attestable, leaving the prior behaviour exactly as it was.
    attested_ns = attested_namespace(user, (payload.agent_identity or {}).get("namespace"))
    if attested_ns:
        effective_ns = attested_ns
    if effective_ns:
        identity["namespace"] = effective_ns
    # A malformed agent_identity (e.g. missing the required spiffe_id) is a client error — return
    # 422, not a raw 500 from the downstream model validation.
    try:
        event = ToolCallEvent.model_validate(
            {**payload.model_dump(exclude={"trust_score"}), "agent_identity": identity}
        )
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=f"invalid agent_identity / tool call: {exc.errors()}") from exc
    record_path_phase("api", "route_identity", (perf_counter() - _t_handler) * 1000.0)
    _t = perf_counter()
    decision: PolicyDecision = await request.app.state.evaluator.evaluate(event)
    record_path_phase("api", "route_evaluate", (perf_counter() - _t) * 1000.0)
    _t = perf_counter()
    # Fire-and-forget audit emission (DB write + OTel span). emit() schedules its own
    # background task, holds the reference, and swallows write errors — so this never
    # blocks the response or fails the tool call (hot-path safe). The audit record carries
    # event.agent_identity.namespace, so audit data is tenant-scoped like everything else.
    emitter = getattr(request.app.state, "emitter", None)
    if emitter is not None:
        # Opt-in (default OFF): persist MASKED tool_params for event reconstruction (PCI 10.3) without
        # storing raw PAN/PII. Off by default so the audit payload is unchanged for everyone who hasn't opted in.
        audit_payload = None
        if settings.audit_capture_masked_params:
            audit_payload = {"masked_params": mask_params(event.tool_params)}
        # Argument NAMES, independently of the masked-VALUE switch above (see
        # audit_capture_param_keys). This is the only record of what a call was called with on a
        # default install, and it is what lets a proposal say "traffic on issue_refund carries
        # `amount`, and your rule does not mention it" while the operator can still act on it.
        #
        # Written as three fields, and the third exists for the same reason the second does: a reader
        # must be able to tell "no arguments were captured" (fields ABSENT — capture off, or the
        # derivation failed) from "arguments were captured and there were none" (`param_keys: []`).
        # Rendering those identically is this project's recurring defect, so the empty set is written
        # explicitly rather than skipped, and the flags are written even when they are empty/false —
        # "we checked and found none" must not be spelled the same way as "we never looked".
        #
        # HOT PATH: bounded in-memory walks over params the request already holds, no I/O, and the
        # whole thing sits inside the fire-and-forget audit block whose result nothing awaits.
        if settings.audit_capture_param_keys:
            param_keys, param_keys_ambiguous, param_keys_pinnable, param_keys_truncated = _param_key_set(
                request.app.state.evaluator, event.tool_params
            )
            if param_keys is not None:
                audit_payload = {
                    **(audit_payload or {}),
                    # KEYS ONLY. No value, masked or otherwise, may ever appear here — including the
                    # values that arrive through a KEY position (see _NAME_MAY_CARRY_DATA).
                    "param_keys": param_keys,
                    # Names another route can also reach, so a rule pinned on one is answered by
                    # whichever twin the caller ordered last. Authoring against one of these is a trap.
                    "param_keys_ambiguous": param_keys_ambiguous,
                    # The subset a rule can actually be pinned to: paths `input.derived.param_paths`
                    # carries at enforcement time. SHOW every name, ASSERT only these — a predicate
                    # over a name outside this set is false on every call, and under
                    # `default decision = "block"` an allow arm that never matches refuses every call
                    # to the tool. Published as the POSITIVE set so an absent field pins nothing.
                    "param_keys_pinnable": param_keys_pinnable,
                    # The set was cut short by the engine's path bounds — it is a SAMPLE, not the
                    # tool's argument surface, and must not be presented as complete.
                    "param_keys_truncated": param_keys_truncated,
                }
        # Verb OBSERVATION phase (tool-classification lifecycle): when the tool NAME is unclassifiable
        # but its PARAMS reveal the operation (a SQL body, a destination field), record that verb as
        # evidence on the audit row — /threats/tool-verbs aggregates it so an admin can PROMOTE the tool
        # to a defined verb. Pure in-memory token/dict classification — hot-path safe, no I/O.
        # MCP provenance on the audit row: which server served this tool, over which transport, and
        # what Gate A knew about its definition at the time. Without it an operator reading the audit
        # log sees `send_email  block` with no way to tell WHICH of four MCP integrations it came
        # from — the first question anyone asks when a chatbot has several. Stored under its own key
        # so it can never collide with masked_params or the verb-observation fields below.
        if event.mcp:
            audit_payload = {**(audit_payload or {}), "mcp": event.mcp}
        name_verb, _ = classify_tool(event.tool_name)
        if name_verb is Verb.UNKNOWN:
            param_verb, param_risk = classify_tool(event.tool_name, event.tool_params)
            if param_verb is not Verb.UNKNOWN:
                audit_payload = {
                    **(audit_payload or {}),
                    "op": param_verb.value,
                    "op_risk": param_risk.value if param_risk else None,
                    "op_src": "params",
                }
        emitter.emit(event, decision, payload=audit_payload)
    record_path_phase("api", "route_audit", (perf_counter() - _t) * 1000.0)
    _t = perf_counter()
    # Fan the decision out to live /ws/audit subscribers (in-process, non-blocking).
    hub = getattr(request.app.state, "audit_hub", None)
    if hub is not None:
        hub.publish(audit_record(event, decision))
    record_path_phase("api", "route_fanout", (perf_counter() - _t) * 1000.0)
    response = EvaluateResponse(
        decision=decision.decision, rule_id=decision.rule_id, trust_score=decision.trust_score
    )
    # Recorded LAST so it covers the whole handler. FastAPI still has to validate and serialise this
    # response afterwards, which is precisely why `total_asgi - route_total` is the number to read
    # rather than assuming the handler is the request.
    record_path_phase("api", "route_total", (perf_counter() - _t_handler) * 1000.0)
    return response
