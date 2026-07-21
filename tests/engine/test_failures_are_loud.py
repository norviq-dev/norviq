# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Security-relevant failures must be OBSERVABLE — never swallowed into silence.

WHY THIS GUARD EXISTS
---------------------
The audit-partition blocker was not dangerous because audit writes would fail; it was dangerous
because they would fail *quietly*. ``AuditEmitter._write_db`` and ``SidecarProxy._process_request``
both wrap their audit path in ``try/except`` so an audit outage can never break enforcement — which
is correct — but that same wrapper is exactly what would have let a total, cluster-wide loss of the
audit trail run for weeks with nothing an operator looks at ever turning red. A control that fails
silently is indistinguishable from a control that is working.

THE BUG CLASS THIS CATCHES
--------------------------
1. ``except ...: pass`` (or ``continue`` / ``return None``) on a security-relevant code path — the
   error is discarded and control proceeds as if nothing happened. Detected with ``ast`` (not regex)
   so the check is precise about handler *bodies*, and gated by an explicit allow-list in which every
   entry names the file, the function, and WHY swallowing is correct there. A new silent handler on
   the PEP/PDP surface fails this suite until someone justifies it in writing.
2. A broad ``except Exception`` in the enforcement DATA PLANE (the injected sidecar) or in the audit
   emitter that logs nothing, or logs without a stable ``code="NRVQ-..."`` identifier. Operators
   alert on codes, not on prose — an error line with no code is not actionable and would not have
   surfaced blocker #3 either. This tier has NO allow-list on purpose.
3. Fail-OPEN on the error path. Both sidecar surfaces document "a processing error must DROP, never
   forward". Behavioural tests drive real failures through ``_process_request`` and assert the
   response is a drop, and that the failure was also logged with its NRVQ code.

Tiers 1 and 2 are pure ``ast`` over source and need no application imports; the behavioural tests
skip cleanly if the application import chain is unavailable in the running environment.
"""

from __future__ import annotations

import ast
import json
import pathlib
import uuid

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_PKG_ROOT = _REPO_ROOT / "norviq"


# --------------------------------------------------------------------------------------------------
# Scope: which source counts as "security relevant"
# --------------------------------------------------------------------------------------------------
# Everything under the PEP (sidecar) and the PDP (engine) is in scope wholesale, so a newly added
# module inside them is covered the day it lands rather than the day someone remembers to list it.
# From the control plane only the modules that actually make or record a security decision are in
# scope — auth, lockout/throttling, rate limiting, request-size limiting, audit fan-out/retention/
# forwarding, and the SSRF guard.
_SECURITY_DIR_PREFIXES = ("sidecar/", "engine/")
_SECURITY_MODULES = frozenset(
    {
        "api/api_keys.py",
        "api/audit_hub.py",
        "api/audit_retention.py",
        "api/body_limit.py",
        "api/main.py",
        "api/passwords.py",
        "api/rate_limit.py",
        "api/siem.py",
        "fleet/ssrf_guard.py",
    }
)

# The enforcement data plane proper: the code that actually runs inside an injected agent pod, plus
# the audit emitter it (in embedded mode) writes through. This is the surface where blocker #3 hid,
# so it gets the strict no-allow-list treatment.
_DATA_PLANE_MODULES = ("sidecar/", "engine/audit_emitter.py")

# Names that count as "this handler made a noise". Deliberately narrow: generic mutators like
# ``add``/``set``/``record`` are excluded because they are overwhelmingly ordinary data-structure
# calls, and counting them as observability would let a genuinely silent handler pass.
_LOGGING_METHODS = frozenset({"debug", "info", "warning", "warn", "error", "exception", "critical", "fatal"})
_OBSERVABILITY_METHODS = frozenset({"inc", "increment", "observe", "record_exception", "set_status"})


# --------------------------------------------------------------------------------------------------
# The allow-list: every place Norviq intentionally discards an exception on a security surface.
#
# Keyed by (path relative to norviq/, enclosing qualname) rather than line number so ordinary edits
# above a handler don't churn this list. Each entry states why silence is the correct behaviour.
# Adding to this list is a deliberate, reviewable act — that is the point.
# --------------------------------------------------------------------------------------------------
_JUSTIFIED_SILENT_HANDLERS: dict[tuple[str, str], str] = {
    ("api/api_keys.py", "_record_authfail"): (
        "Best-effort failed-auth counter. The throttle is defense-in-depth layered on top of the real "
        "API-key check; a Redis hiccup must not turn into an auth outage. The auth decision itself is "
        "made (and logged) by authenticate_api_key, which does not swallow."
    ),
    ("api/api_keys.py", "_is_authfail_locked"): (
        "Reads the same best-effort counter and fails OPEN by design: a cache outage must never lock "
        "legitimate API keys out of the platform. Documented in the function's own docstring."
    ),
    ("api/passwords.py", "verify_password"): (
        "bcrypt.checkpw raises on malformed/non-ascii stored hashes; returning False is the correct "
        "security answer (deny), not a swallowed failure. The caller logs the failed login."
    ),
    ("api/passwords.py", "is_locked_out"): (
        "Login lockout is defense-in-depth over password verification and fails OPEN on cache loss so "
        "a Redis outage cannot lock every user out. The password check itself still runs."
    ),
    ("api/passwords.py", "register_failure"): (
        "Incrementing the lockout counter is best-effort; the login has already been denied by the "
        "time this runs, so losing the count degrades throttling only, never the auth decision."
    ),
    ("api/passwords.py", "clear_failures"): (
        "Resets the lockout counter after a SUCCESSFUL login. Failing to clear can only leave a stale "
        "count that expires on its own window — it cannot grant access."
    ),
    ("api/audit_hub.py", "AuditHub.publish"): (
        "Live-UI fan-out only. A full subscriber queue drops that subscriber's copy of the event; the "
        "DURABLE audit record is the Postgres row written by AuditEmitter, which is not best-effort."
    ),
    ("api/audit_retention.py", "RetentionPruner._run"): (
        "asyncio.TimeoutError here is the sleep-until-next-sweep expiring, i.e. the normal loop tick. "
        "Real prune failures are caught separately one block above and logged as NRVQ-AUD-6012."
    ),
    ("api/audit_retention.py", "RetentionPruner.stop"): (
        "Draining an already-cancelled background task during graceful shutdown; the exception IS the "
        "cancellation we asked for."
    ),
    ("api/siem.py", "AuditForwarder._run"): (
        "Same shape as the retention loop: TimeoutError is the poll interval elapsing. Forwarding "
        "failures are caught separately and logged as NRVQ-SIEM-14001."
    ),
    ("api/body_limit.py", "BodySizeLimitMiddleware.__call__"): (
        "A malformed Content-Length header cannot be trusted to short-circuit, so it deliberately "
        "falls through to the read-time byte counter, which DOES enforce the cap and log NRVQ-API-7050."
    ),
    ("api/main.py", "lifespan"): (
        "Draining the cancelled policy-sync task on shutdown; the exception is the cancellation itself."
    ),
    ("api/main.py", "create_app.ws_audit"): (
        "WebSocketDisconnect is a client closing the audit stream — the ordinary end of the request. "
        "The finally block still logs NRVQ-API-7041."
    ),
    ("api/rate_limit.py", "_unverified_sub"): (
        "Peeks at unverified JWT claims purely to pick a rate-limit bucket. A garbage token yields no "
        "subject and the limiter falls back to IP keying; the token is separately verified for real by "
        "the auth dependency, which does not swallow."
    ),
    ("engine/cache.py", "RedisCache.listen_policy_mutations"): (
        "Skips a single undecodable frame on the policy-mutation pubsub channel so one corrupt message "
        "cannot kill the listener for every subsequent (valid) policy update. NOTE: a dropped frame "
        "means one propagation event is missed silently — see the report accompanying this suite; the "
        "reconciling path is the periodic loader refresh, not this channel."
    ),
    ("engine/evaluator.py", "OPAEvaluator._track_dryrun_module"): (
        "Best-effort eviction of an ephemeral dry-run OPA module past the LRU cap. OPA overwrites by "
        "module_id, so a failed delete cannot leave a stale policy in the evaluation path."
    ),
    ("engine/evaluator.py", "OPAEvaluator._extract_opa_value"): (
        "Pure shape-parsing of an OPA response envelope. Returning None on a missing key is the "
        "'no value' answer the caller is written to handle; the caller decides fail-closed."
    ),
    ("engine/identity.py", "SPIFFEResolver._resolve_workload_api"): (
        "Best-effort close() of the workload-API channel in a finally block, AFTER the SVID was already "
        "obtained. Failures resolving the identity itself are logged NRVQ-IDT-10006 and re-raised."
    ),
    ("engine/opa_client.py", "_ManagedServer._wait_healthy"): (
        "A single failed readiness probe inside a bounded retry loop. Exhausting the loop raises "
        "RuntimeError('managed OPA server did not become healthy in time') — loud where it matters."
    ),
    ("engine/opa_client.py", "_ManagedServer.terminate"): (
        "ProcessLookupError means the managed OPA process is already gone, which is the goal state."
    ),
    ("engine/opa_client.py", "OpaClient.health"): (
        "Boolean readiness probe: any failure to reach OPA IS the 'unhealthy' answer, and returning "
        "False is what degrades the health surface. Silence here is the signal."
    ),
    ("engine/trust/history.py", "AgentHistoryStore.get_history"): (
        "Skips one corrupt row in an agent's rolling behaviour history so a single bad entry cannot "
        "make trust computation unavailable for that agent."
    ),
    ("fleet/ssrf_guard.py", "is_safe_url"): (
        "The bool wrapper around assert_safe_url: catching SSRFBlockedError and returning False IS the "
        "block decision being reported to the caller, not a swallowed error."
    ),
    ("sidecar/__main__.py", "main"): (
        "KeyboardInterrupt/SystemExit is the container being asked to stop; the finally block still "
        "runs proxy.stop(), which logs NRVQ-SDC-3005."
    ),
    ("sidecar/remote_evaluator.py", "_build_mtls_context"): (
        "Unlinking the transient mTLS cert/key files in a finally block after the SSL context has "
        "already loaded them. The file being gone is the desired end state."
    ),
}


# --------------------------------------------------------------------------------------------------
# ast helpers
# --------------------------------------------------------------------------------------------------
def _iter_security_sources() -> list[tuple[str, ast.Module]]:
    """Yield (path-relative-to-norviq/, parsed module) for every in-scope source file."""
    out: list[tuple[str, ast.Module]] = []
    for path in sorted(_PKG_ROOT.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        rel = path.relative_to(_PKG_ROOT).as_posix()
        if not (rel.startswith(_SECURITY_DIR_PREFIXES) or rel in _SECURITY_MODULES):
            continue
        # utf-8-sig: at least one module in the tree carries a BOM, and a hard parse failure here
        # would silently shrink the scanned surface — exactly the kind of quiet gap this file guards.
        out.append((rel, ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))))
    return out


def _walk_handlers(module: ast.Module):
    """Yield (ExceptHandler, enclosing qualname) for every handler in the module."""

    def _descend(node: ast.AST, qual: str):
        for child in ast.iter_child_nodes(node):
            child_qual = qual
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                child_qual = f"{qual}.{child.name}" if qual else child.name
            if isinstance(child, ast.ExceptHandler):
                yield child, qual
            yield from _descend(child, child_qual)

    yield from _descend(module, "")


def _makes_noise(handler: ast.ExceptHandler) -> bool:
    """True if the handler re-raises, logs, or touches an observability primitive."""
    for node in ast.walk(handler):
        if isinstance(node, ast.Raise):
            return True
        func = getattr(node, "func", None)
        if isinstance(node, ast.Call) and isinstance(func, ast.Attribute):
            if func.attr in _LOGGING_METHODS or func.attr in _OBSERVABILITY_METHODS:
                return True
    return False


def _body_is_inert(handler: ast.ExceptHandler) -> bool:
    """True if the handler body only discards the error and moves on.

    Inert == pass / a bare docstring-or-ellipsis expression / continue / break / return of a literal.
    Anything that constructs a value, closes a socket, or flips a flag is a deliberate degradation
    with observable consequences, not silence, and is out of scope for this check.
    """
    for stmt in handler.body:
        if isinstance(stmt, ast.Pass):
            continue
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
            continue
        if isinstance(stmt, (ast.Continue, ast.Break)):
            continue
        if isinstance(stmt, ast.Return) and (stmt.value is None or isinstance(stmt.value, ast.Constant)):
            continue
        return False
    return True


def _is_broad(handler: ast.ExceptHandler) -> bool:
    """True for a bare `except:` or one catching Exception/BaseException (incl. inside a tuple)."""
    if handler.type is None:
        return True
    caught = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
    return any(isinstance(n, ast.Name) and n.id in ("Exception", "BaseException") for n in caught)


def _has_stable_nrvq_code(handler: ast.ExceptHandler) -> bool:
    """True if some logging call in the handler carries a literal ``code="NRVQ-..."`` keyword."""
    for node in ast.walk(handler):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        if node.func.attr not in _LOGGING_METHODS:
            continue
        for kw in node.keywords:
            if kw.arg == "code" and isinstance(kw.value, ast.Constant) and str(kw.value.value).startswith("NRVQ-"):
                return True
    return False


# --------------------------------------------------------------------------------------------------
# Tier 1 — no unjustified silent handler anywhere on the security surface
# --------------------------------------------------------------------------------------------------
def test_no_unjustified_silent_exception_handlers() -> None:
    """A security-relevant `except` must not simply discard the error.

    An `except ...: pass` on the PEP/PDP surface is how a control stops working without anyone
    finding out. Every intentional case has to be written down in _JUSTIFIED_SILENT_HANDLERS with a
    reason; anything else is a defect.
    """
    offenders: list[str] = []
    for rel, module in _iter_security_sources():
        for handler, qual in _walk_handlers(module):
            if _makes_noise(handler) or not _body_is_inert(handler):
                continue
            if (rel, qual) in _JUSTIFIED_SILENT_HANDLERS:
                continue
            caught = ast.unparse(handler.type) if handler.type is not None else "BARE except"
            offenders.append(f"norviq/{rel}:{handler.lineno} in {qual or '<module>'} — except {caught}")

    assert not offenders, (
        "Security-relevant exception handler(s) discard the error without logging, re-raising, or "
        "degrading anything observable. Either make the failure loud, or add a justified entry to "
        "_JUSTIFIED_SILENT_HANDLERS in this file:\n  " + "\n  ".join(offenders)
    )


def test_silent_handler_allowlist_has_no_stale_entries() -> None:
    """The allow-list must describe reality.

    A stale entry is a pre-approved hiding place: it would let a future silent handler slip into an
    already-blessed (file, function) slot without review. Entries are removed when their handler is
    made loud, so this keeps the exemption surface honest and minimal.
    """
    live = {
        (rel, qual)
        for rel, module in _iter_security_sources()
        for handler, qual in _walk_handlers(module)
        if _body_is_inert(handler) and not _makes_noise(handler)
    }
    stale = sorted(f"{rel}::{qual}" for rel, qual in _JUSTIFIED_SILENT_HANDLERS if (rel, qual) not in live)
    assert not stale, "Allow-list entries no longer match any silent handler — delete them:\n  " + "\n  ".join(stale)


def test_every_allowlist_entry_states_a_reason() -> None:
    """An exemption without a written justification is not an exemption, it is a TODO."""
    thin = sorted(f"{rel}::{qual}" for (rel, qual), why in _JUSTIFIED_SILENT_HANDLERS.items() if len(why.strip()) < 40)
    assert not thin, "Allow-list entries need a real justification, not a placeholder:\n  " + "\n  ".join(thin)


# --------------------------------------------------------------------------------------------------
# Tier 2 — the data plane must fail with a STABLE, ALERTABLE identifier (no allow-list)
# --------------------------------------------------------------------------------------------------
def test_data_plane_broad_handlers_log_a_stable_nrvq_code() -> None:
    """Every broad `except Exception` in the sidecar / audit emitter must log a `code="NRVQ-..."`.

    This is the tier that would have caught blocker #3's blast radius. The sidecar swallows audit
    errors on purpose so enforcement survives an audit outage — which is only acceptable if the
    outage is *announced*. Operators alert on stable codes, so an error logged as prose alone is
    effectively still silent. Re-raising also satisfies this: the caller then owns the noise.
    """
    offenders: list[str] = []
    for rel, module in _iter_security_sources():
        if not rel.startswith(_DATA_PLANE_MODULES):
            continue
        for handler, qual in _walk_handlers(module):
            if not _is_broad(handler):
                continue
            # A handler that re-raises has not hidden anything — the failure keeps travelling.
            if any(isinstance(n, ast.Raise) for n in ast.walk(handler)):
                continue
            if _has_stable_nrvq_code(handler):
                continue
            offenders.append(f"norviq/{rel}:{handler.lineno} in {qual or '<module>'}")

    assert not offenders, (
        "Broad exception handler(s) in the enforcement data plane neither re-raise nor log a stable "
        'code="NRVQ-..." identifier, so the failure is not alertable:\n  ' + "\n  ".join(offenders)
    )


def test_data_plane_scan_actually_covered_the_sidecar() -> None:
    """Meta-guard: the tier-2 scan must have real files under it.

    If a refactor moves or renames the sidecar package, the scans above would trivially pass over an
    empty set and report green while checking nothing. Assert the surface is non-empty and that the
    two modules named in the blocker report are among the files scanned.
    """
    scanned = {rel for rel, _ in _iter_security_sources()}
    assert "sidecar/proxy.py" in scanned, f"sidecar/proxy.py not scanned; found: {sorted(scanned)}"
    assert "engine/audit_emitter.py" in scanned, f"engine/audit_emitter.py not scanned; found: {sorted(scanned)}"
    data_plane = {rel for rel in scanned if rel.startswith(_DATA_PLANE_MODULES)}
    assert len(data_plane) >= 4, f"data-plane scan surface suspiciously small: {sorted(data_plane)}"


# --------------------------------------------------------------------------------------------------
# Behavioural — drive the real failure and watch it make noise / fail closed
# --------------------------------------------------------------------------------------------------
try:  # pragma: no cover - import availability is environmental, not behavioural
    import structlog
    from structlog.testing import capture_logs

    from norviq.engine.audit_emitter import AuditEmitter
    from norviq.sdk.core.audit import AuditRecord
    from norviq.sdk.core.decisions import PolicyDecision
    from norviq.sdk.core.events import AgentIdentity, ToolCallEvent
    from norviq.sidecar.proxy import SidecarProxy

    _IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover - only on a lean env missing app deps
    _IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

_needs_app = pytest.mark.skipif(_IMPORT_ERROR is not None, reason=f"norviq app imports unavailable ({_IMPORT_ERROR})")


def _event() -> "ToolCallEvent":
    return ToolCallEvent(
        event_id=str(uuid.uuid4()),
        tool_name="kubectl.delete",
        tool_params={"kind": "Secret"},
        agent_identity=AgentIdentity(
            spiffe_id="spiffe://norviq/ns/prod/sa/agent",
            namespace="prod",
            agent_class="planner",
        ),
        session_id="sess-loudness",
    )


def _codes(logs: list[dict], level: str = "error") -> set[str]:
    """Collect the NRVQ codes structlog saw at a given level."""
    return {str(entry.get("code")) for entry in logs if entry.get("log_level") == level and entry.get("code")}


@_needs_app
async def test_audit_db_write_failure_is_logged_as_an_error_with_its_code() -> None:
    """A failed audit INSERT must surface as an ERROR carrying NRVQ-AUD-6004.

    This is blocker #3 reduced to its essence: on the 1st of an unpartitioned month every audit
    write raises inside this handler. The handler is allowed to swallow (enforcement must not break)
    but it is NOT allowed to be quiet — this is the one line that would have made the outage visible.
    """
    emitter = AuditEmitter()

    async def _pg_is_down():
        raise RuntimeError('no partition of relation "audit_log" found for row')

    emitter._acquire_session = _pg_is_down  # type: ignore[method-assign]
    record = AuditRecord.from_event_and_decision(_event(), PolicyDecision(decision="block", rule_id="r"))

    with capture_logs() as logs:
        await emitter._write_db_locked(record)  # must not raise — swallowing is intended here

    assert "NRVQ-AUD-6004" in _codes(logs), f"audit write failure was not logged with its code: {logs}"
    assert any(e.get("event") == "nrvq.audit.db_failed" for e in logs), f"no db_failed event: {logs}"


@_needs_app
async def test_audit_span_export_failure_is_logged_as_an_error_with_its_code() -> None:
    """The OTel half of the audit trail must announce its own failure too (NRVQ-AUD-6006).

    An operator whose only audit view is the tracing backend deserves the same signal as one reading
    Postgres; a span exporter that dies quietly reproduces the exact blocker-#3 failure mode on the
    other leg of the trail.
    """
    emitter = AuditEmitter()

    class _BrokenTracer:
        def start_as_current_span(self, *_: object, **__: object):
            raise RuntimeError("otlp collector unreachable")

    emitter._tracer = _BrokenTracer()  # type: ignore[assignment]

    with capture_logs() as logs:
        await emitter._emit_span(_event(), PolicyDecision(decision="allow", rule_id="r"))

    assert "NRVQ-AUD-6006" in _codes(logs), f"span export failure was not logged with its code: {logs}"


def _proxy_with(interceptor: object, emitter: object = None) -> "SidecarProxy":
    """A SidecarProxy wired to stubs, without starting a socket listener."""
    proxy = SidecarProxy(socket_path="/dev/null/not-bound")
    proxy._interceptor = interceptor  # type: ignore[assignment]
    proxy._emitter = emitter  # type: ignore[assignment]
    return proxy


class _StubInterceptor:
    """Returns a fixed decision, or raises, on intercept()."""

    def __init__(self, decision: "PolicyDecision | None" = None, boom: Exception | None = None) -> None:
        self._decision = decision
        self._boom = boom

    async def intercept(self, *_: object, **__: object) -> "PolicyDecision":
        if self._boom is not None:
            raise self._boom
        assert self._decision is not None
        return self._decision


@_needs_app
async def test_allowed_call_is_forwarded() -> None:
    """Control case: the happy path really does forward.

    Without this, every 'must drop' assertion below would still pass against a proxy that dropped
    unconditionally — a broken PEP would look like a well-behaved one.
    """
    proxy = _proxy_with(_StubInterceptor(PolicyDecision(decision="allow", rule_id="default_allow")))
    response = json.loads(await proxy._process_request(json.dumps({"tool_name": "kubectl.get", "session_id": "s"})))
    assert response["action"] == "forward"


@_needs_app
async def test_blocked_call_is_dropped() -> None:
    """A block decision must translate into a drop on the wire, not merely be recorded."""
    proxy = _proxy_with(_StubInterceptor(PolicyDecision(decision="block", rule_id="deny_destructive")))
    response = json.loads(await proxy._process_request(json.dumps({"tool_name": "kubectl.delete", "session_id": "s"})))
    assert response["action"] == "drop"


@_needs_app
async def test_interceptor_error_fails_closed_and_is_logged() -> None:
    """A processing error must DROP the tool call and say so with NRVQ-SDC-3003.

    Fail-open here is the worst outcome in the product: any exception on the evaluation path would
    silently become a permitted tool call, and the enforcement gap would be invisible in the logs.
    """
    proxy = _proxy_with(_StubInterceptor(boom=RuntimeError("OPA unreachable")))

    with capture_logs() as logs:
        response = json.loads(await proxy._process_request(json.dumps({"tool_name": "kubectl.delete"})))

    assert response["action"] == "drop", f"FAIL-OPEN: interceptor error did not drop the call: {response}"
    assert response["action"] != "forward"
    assert "NRVQ-SDC-3003" in _codes(logs), f"fail-closed drop was not logged with its code: {logs}"


@_needs_app
@pytest.mark.parametrize(
    "raw",
    [
        "not json at all",
        '{"tool_name": "kubectl.delete"',  # truncated object
        "[]",  # valid JSON, wrong shape: no .get
        "null",
        "12345",
    ],
    ids=["garbage", "truncated", "list", "null", "number"],
)
async def test_malformed_request_fails_closed(raw: str) -> None:
    """Every undecodable / wrong-shaped request must DROP, never forward.

    A JSON body that parses but is not an object has no ``.get``, so the coercion raises — that error
    path has to land on the same fail-closed answer as outright garbage.
    """
    proxy = _proxy_with(_StubInterceptor(PolicyDecision(decision="allow", rule_id="default_allow")))

    with capture_logs() as logs:
        response = json.loads(await proxy._process_request(raw))

    assert response["action"] == "drop", f"FAIL-OPEN on malformed input {raw!r}: {response}"
    assert "NRVQ-SDC-3003" in _codes(logs), f"malformed-request drop was not logged with its code: {logs}"


@_needs_app
async def test_audit_emit_failure_is_loud_but_does_not_break_enforcement() -> None:
    """An audit outage must be logged AND must not change the enforcement answer.

    Both halves matter, and they are in tension — which is precisely why blocker #3 survived. The
    'must not break enforcement' half is why the try/except exists; the 'must be logged' half is the
    part that was load-bearing and untested.
    """
    proxy = _proxy_with(_StubInterceptor(PolicyDecision(decision="allow", rule_id="default_allow")))

    async def _audit_is_down(*_: object, **__: object) -> None:
        raise RuntimeError("audit_log partition missing for row")

    proxy._emit_audit = _audit_is_down  # type: ignore[method-assign]

    with capture_logs() as logs:
        response = json.loads(await proxy._process_request(json.dumps({"tool_name": "kubectl.get"})))

    assert response["action"] == "forward", "an audit outage must not change the enforcement decision"
    assert "NRVQ-SDC-3003" in _codes(logs), f"audit outage was silent — the blocker-#3 failure mode: {logs}"


@_needs_app
def test_capture_logs_actually_observes_the_module_loggers() -> None:
    """Meta-guard: if structlog capture ever stopped working, every assertion above would still pass.

    ``_codes()`` returns an empty set when nothing is captured, and `'X' in set()` is False — so a
    broken capture would fail loudly rather than silently. This asserts the positive direction: a
    logger obtained the way the product obtains one is visible to capture_logs.
    """
    with capture_logs() as logs:
        structlog.get_logger().error("nrvq.test.probe", code="NRVQ-TEST-0000")
    assert _codes(logs) == {"NRVQ-TEST-0000"}, f"structlog capture is not observing product loggers: {logs}"
