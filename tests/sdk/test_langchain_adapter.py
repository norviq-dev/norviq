# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Tests for LangChain adapter wrappers."""

from __future__ import annotations

import functools
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
import os
from typing import Any
import uuid

import pytest
import structlog.testing
from pydantic import BaseModel, create_model

from norviq.engine.cache import RedisCache
from norviq.engine.evaluator import OPAEvaluator
from norviq.engine.identity import SPIFFEResolver
from norviq.exceptions import NorviqBlockError
from norviq.sdk.core.decisions import PolicyDecision
from norviq.sdk.core.interceptor import ToolInterceptor
from norviq.sdk.core.wrapping import _run_sync
from norviq.sdk.langchain.adapter import (
    MAX_DECLARED_PARAM_KEYS,
    declared_tool_schemas,
    forget_declared_tool_schemas,
    ingest_declared_schema,
    protect,
)
from tests.conftest import flush_runtime

try:
    from langchain_core.tools import BaseTool
except ImportError:  # pragma: no cover - fallback for older langchain.
    from langchain.tools import BaseTool


class _TestTool(BaseTool):
    """Simple sync/async tool for adapter tests."""

    name: str = "search_kb"
    description: str = "test tool"

    def _run(self, query: str = "") -> str:
        """Execute sync tool body."""
        return f"sync:{query}"

    async def _arun(self, query: str = "") -> str:
        """Execute async tool body."""
        return f"async:{query}"


@pytest.fixture
def redis_url() -> str:
    """Return Redis URL from environment."""
    value = os.getenv("NRVQ_REDIS_URL")
    if not value:
        pytest.fail("NRVQ_REDIS_URL must be set for Redis integration tests")
    return value


@pytest.fixture
async def interceptor(redis_url: str, seeded_loader) -> AsyncIterator[ToolInterceptor]:
    """Create ToolInterceptor for adapter tests (comprehensive.rego cluster baseline)."""
    cache = RedisCache(url=redis_url)
    await cache.connect()
    await flush_runtime(cache)  # isolate trust/cache from the prior block test in this file
    evaluator = OPAEvaluator(cache)
    evaluator.bind_loader(seeded_loader)
    resolver = SPIFFEResolver()
    yield ToolInterceptor(evaluator=evaluator, resolver=resolver)
    # Sync-path tests evaluate on _run_sync's persistent background loop, so the evaluator's audit
    # tasks and the redis connections it used live THERE and can't be awaited/closed from the pytest
    # loop — drain each on the loop it was created on. (Same documented sharp edge as the adapter
    # docstring: loop-bound in-process evaluators prefer the async path.)
    try:
        await evaluator.close()
    except RuntimeError:
        _run_sync(evaluator.close())
    try:
        await cache.close()
    except RuntimeError:
        _run_sync(cache.close())


def _session() -> str:
    """Create isolated session id."""
    return uuid.uuid4().hex


@dataclass
class _FakeInterceptor:
    """Track intercepted tool calls without a real evaluator (used for the passthrough/raise tests,
    which never reach an evaluator and so don't need the Redis-backed fixture above)."""

    calls: list[tuple[str, dict[str, Any], str]] = field(default_factory=list)

    async def intercept_or_raise(
        self, tool_name: str, tool_params: dict[str, Any], session_id: str = "", framework: str = ""
    ) -> PolicyDecision:
        """Record call; never raises in this fake."""
        self.calls.append((tool_name, tool_params, framework))
        return PolicyDecision(decision="allow")


async def test_protect_blocked_tool_raises(interceptor: ToolInterceptor) -> None:
    """Blocked calls should raise before original tool body executes."""
    tool = _TestTool(name="execute_sql")
    wrapped = protect([tool], interceptor, session_id=_session())
    with pytest.raises(NorviqBlockError):
        await wrapped[0]._arun(query="DROP TABLE users")


async def test_protect_allowed_tool_executes(interceptor: ToolInterceptor) -> None:
    """Allowed calls should execute wrapped sync body."""
    tool = _TestTool(name="search_kb")
    wrapped = protect([tool], interceptor, session_id=_session())
    assert wrapped[0]._run(query="hello") == "sync:hello"


async def test_protect_async_tool_executes(interceptor: ToolInterceptor) -> None:
    """Allowed calls should execute wrapped async body."""
    tool = _TestTool(name="search_kb")
    wrapped = protect([tool], interceptor, session_id=_session())
    assert await wrapped[0]._arun(query="hello") == "async:hello"


def test_protect_passthrough_for_non_base_tool_when_allowed() -> None:
    """Non-BaseTool objects pass through unwrapped only when allow_unwrapped=True, loudly."""
    interceptor = _FakeInterceptor()
    sentinel = object()
    with structlog.testing.capture_logs() as cap_logs:
        protected = protect([sentinel], interceptor, allow_unwrapped=True)  # type: ignore[arg-type]
    assert protected == [sentinel]
    assert interceptor.calls == []
    assert any(
        entry["event"] == "nrvq.langchain.unwrapped"
        and entry["log_level"] == "warning"
        and entry["code"] == "NRVQ-SDK-1044"
        for entry in cap_logs
    )


def test_protect_default_raises_on_non_base_tool_and_evaluates_nothing() -> None:
    """Fail-closed default: an unrecognized item raises TypeError and nothing is evaluated."""
    interceptor = _FakeInterceptor()
    sentinel = object()
    with pytest.raises(TypeError, match="object"):
        protect([sentinel], interceptor)  # type: ignore[arg-type]
    assert interceptor.calls == []


# ── positional arguments reach the engine WITH THEIR NAMES ──────────────────────────────────────
#
# `_tool_params` returned `{"args": [...]}` for any positionally-invoked tool, and that is a hole in
# enforcement rather than a cosmetic difference. Every per-argument control Norviq offers addresses a
# parameter BY NAME — `param_paths.to`, a builder constraint on `query`, a `destinations.emails` fact
# derived from the value under a recipient key. Against `{"args": ["collector@attacker.example"]}`
# none of them can fire, whatever the operator wrote: the rule does not FAIL, it is simply never
# about this call, and under a tighten-only policy the call proceeds.


class _RecordingInterceptor:
    """Captures the params the engine WOULD have evaluated."""

    def __init__(self) -> None:
        self.params: dict[str, Any] = {}

    async def intercept_or_raise(self, *, tool_name: str, tool_params: dict, session_id: str,
                                 framework: str) -> None:
        self.params = tool_params


class _PositionalTool(BaseTool):
    """A tool whose arguments are POSITIONAL — the shape that lost its names."""

    name: str = "send_email"
    description: str = "sends mail"

    def _run(self, to: str = "", body: str = "") -> str:
        return f"sent:{to}"


class _VarargsTool(BaseTool):
    name: str = "varargs_tool"
    description: str = "takes anything"

    def _run(self, first: str = "", *rest: Any) -> str:
        return "ok"


def test_positional_arguments_are_bound_to_their_names() -> None:
    """The names come from the tool's OWN `_run`, so they are the names the tool itself uses."""
    rec = _RecordingInterceptor()
    wrapped = protect([_PositionalTool()], rec, session_id=_session())
    wrapped[0]._run("ops@acme.com", "quarterly figures")
    # NOT {"args": [...]} — the recipient is addressable, so `param_paths.to` can fire at all.
    assert rec.params == {"to": "ops@acme.com", "body": "quarterly figures"}


def test_an_explicit_keyword_wins_over_a_positional_binding() -> None:
    """Mixing the two must not let a positional silently overwrite what the caller named."""
    rec = _RecordingInterceptor()
    wrapped = protect([_PositionalTool()], rec, session_id=_session())
    wrapped[0]._run("ops@acme.com", body="figures")
    assert rec.params == {"to": "ops@acme.com", "body": "figures"}


def test_keyword_invocation_is_unchanged() -> None:
    """The path that always worked, pinned so the binding cannot regress it."""
    rec = _RecordingInterceptor()
    wrapped = protect([_PositionalTool()], rec, session_id=_session())
    wrapped[0]._run(to="ops@acme.com")
    assert rec.params == {"to": "ops@acme.com"}


def test_arguments_beyond_the_known_names_keep_the_args_list() -> None:
    """`*args` genuinely has no name to bind to. Inventing `arg3` would let an operator scope a name
    the tool has never heard of — a rule that looks enforced and can never match."""
    rec = _RecordingInterceptor()
    wrapped = protect([_VarargsTool()], rec, session_id=_session())
    wrapped[0]._run("a", "b", "c")
    assert rec.params == {"first": "a", "args": ["b", "c"]}


# ── a WRONG name is worse than no name ──────────────────────────────────────────────────────────
#
# Binding positional args by zipping a name list against the argument tuple looked like the obvious
# implementation and is the dangerous one. A decorator that injects a leading argument — a tenant,
# retry or audit wrapper, all commonplace — shifts every name by one, and `functools.wraps` makes
# `inspect.signature` report the signature UNDERNEATH the decorator while the caller uses the
# decorated convention.
#
# The engine is then told `{"tenant": "collector@attacker.example", "to": "ops@acme.com"}` while the
# tool sends to the attacker: the operator's `param_paths.to` pin inspects a compliant value and
# ALLOWS. Under the deny-by-default policy the intent compiler emits, a MISSING name is fail-closed
# (the rule never matches); a WRONG name is fail-open, and it also lies to the near-miss explainer.
#
# So binding goes through `Signature.bind`, which REFUSES rather than guesses, and the signature is
# read with follow_wrapped=False so a wrapper's own `(self, *a, **k)` yields no usable names.

def _tenant_decorator(tenant: str):
    def deco(fn):
        @functools.wraps(fn)
        def inner(self, *a, **k):
            return fn(self, tenant, *a, **k)
        return inner
    return deco


class _ShiftedTool(BaseTool):
    """A tool whose decorator injects a leading argument the caller never passes."""

    name: str = "send_email"
    description: str = "sends mail"

    @_tenant_decorator("acme")
    def _run(self, tenant: str = "", to: str = "", body: str = "") -> str:
        return f"sent:{to}"


def test_a_shifted_signature_claims_no_name_rather_than_the_wrong_one() -> None:
    rec = _RecordingInterceptor()
    wrapped = protect([_ShiftedTool()], rec, session_id=_session())
    wrapped[0]._run("collector@attacker.example", "ops@acme.com")

    # The attacker's address must NOT be filed under some other name while a compliant value sits
    # under the one the operator pinned — that is the shape that turns a pin into a rubber stamp.
    assert rec.params.get("to") != "ops@acme.com", "a shifted signature produced a WRONG name binding"
    # Unnamed is the correct degradation: no per-argument rule can match, and under deny-by-default
    # that is a refusal rather than a silent allow.
    assert "args" in rec.params


def test_an_honest_tool_is_unaffected_by_the_stricter_binding() -> None:
    """The cost side: refusing to guess must not stop ordinary tools from being named."""
    rec = _RecordingInterceptor()
    wrapped = protect([_PositionalTool()], rec, session_id=_session())
    wrapped[0]._run("ops@acme.com", "quarterly figures")
    assert rec.params == {"to": "ops@acme.com", "body": "quarterly figures"}


# ── the DECLARED argument schema is ingested at wrap time ───────────────────────────────────────
#
# The framework already holds a statement of what arguments a tool takes — LangChain publishes
# `args_schema` to the model on every call. The adapter read `.name` off the tool and threw that
# schema away, so Norviq knew a tool called `issue_refund` existed and nothing whatsoever about the
# `amount` argument it takes. Two operators authored rules that named only the tool and were
# surprised, in production, by an argument they were never shown.
#
# Ingestion is OBSERVATIONAL: it must never change what the engine evaluates (that payload is built
# by `_tool_params` from the actual call), and it must never break wrapping — a framework whose tools
# stop working because Norviq could not parse a schema is worse than one that records no schema.


class _RefundArgs(BaseModel):
    """The schema a real LangChain tool declares."""

    txn_id: str
    amount: float


class _RefundTool(BaseTool):
    """A tool that declares its arguments the way the framework asks it to."""

    name: str = "issue_refund"
    description: str = "issues a refund"
    args_schema: type[BaseModel] = _RefundArgs

    def _run(self, txn_id: str = "", amount: float = 0.0) -> str:
        return "ok"


class _NoArgumentTool(BaseTool):
    """A REAL tool that genuinely takes no arguments — not the same thing as an unknown schema."""

    name: str = "ping"
    description: str = "takes nothing"

    def _run(self) -> str:
        return "pong"


@pytest.fixture(autouse=True)
def _isolate_declared_schemas() -> Any:
    """The declared-schema registry is process-global; no test may inherit another's entries."""
    forget_declared_tool_schemas()
    yield
    forget_declared_tool_schemas()


def test_protect_ingests_the_argument_names_the_framework_already_declares() -> None:
    """The operator moment: `issue_refund` is now known to carry an argument called `amount`."""
    tool = _RefundTool()
    protect([tool], _RecordingInterceptor(), session_id=_session())

    record = declared_tool_schemas()[("langchain", "issue_refund")]
    assert record.schema_available is True
    assert record.param_keys == ("amount", "txn_id")  # sorted, de-duplicated, keys only
    assert record.param_keys_truncated is False
    assert record.source == "args_schema"
    # ...and it travels WITH the tool, so whoever holds the tool can read what Norviq ingested.
    assert tool._norviq_declared_schema.param_keys == ("amount", "txn_id")


def test_a_tool_with_no_readable_schema_is_not_spelled_like_one_that_takes_no_arguments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The defect this project keeps hitting: "we know nothing" rendered as "there is nothing".

    An operator told "this tool declares no arguments" stops looking. An operator told "no schema was
    readable" keeps looking. Those are opposite instructions and must not share a spelling.
    """

    class _Opaque:
        """A tool object that declares no schema at all (no args_schema, no args)."""

        name = "opaque_tool"

        def _run(self, **kwargs: Any) -> str:
            return "ok"

    monkeypatch.setattr("norviq.sdk.langchain.adapter._get_base_tool", lambda: _Opaque)
    protect([_Opaque()], _RecordingInterceptor(), session_id=_session())
    unknown = declared_tool_schemas()[("langchain", "opaque_tool")]

    monkeypatch.undo()
    protect([_NoArgumentTool()], _RecordingInterceptor(), session_id=_session())
    empty = declared_tool_schemas()[("langchain", "ping")]

    assert unknown.schema_available is False
    assert unknown.param_keys is None
    assert unknown.unavailable_reason  # names WHY, and is non-empty
    assert empty.schema_available is True
    assert empty.param_keys == ()
    assert empty.unavailable_reason == ""
    assert unknown.as_dict() != empty.as_dict()


def test_a_schema_whose_SHAPE_we_cannot_read_is_unknown_and_never_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The third way this goes wrong, and the one that reads most like success: a schema IS present,
    and it is not a shape we can take names from. Reporting that as "declares no arguments" is a
    fail-open answer — the tool has arguments and the operator is told to stop looking."""

    class _OpaqueSchema:
        """Present, non-empty, and not a shape any of the readers understand."""

        arbitrary = "not a field map"

    class _Tool:
        name = "opaque_schema_tool"
        args_schema = _OpaqueSchema()

        def _run(self, **kwargs: Any) -> str:
            return "ok"

    monkeypatch.setattr("norviq.sdk.langchain.adapter._get_base_tool", lambda: _Tool)
    protect([_Tool()], _RecordingInterceptor(), session_id=_session())
    record = declared_tool_schemas()[("langchain", "opaque_schema_tool")]

    assert record.schema_available is False
    assert record.param_keys is None
    assert record.unavailable_reason == "schema_shape_unknown"


def test_no_argument_VALUE_reaches_the_ingested_schema() -> None:
    """KEYS ONLY. A declared default is a value, and a value must never enter this record."""

    class _CredentialArgs(BaseModel):
        api_key: str = "sk-live-DEADBEEF0000"
        endpoint: str = "https://collector.attacker.example"

    class _CredentialTool(BaseTool):
        name: str = "call_api"
        description: str = "calls an api"
        args_schema: type[BaseModel] = _CredentialArgs

        def _run(self, api_key: str = "", endpoint: str = "") -> str:
            return "ok"

    protect([_CredentialTool()], _RecordingInterceptor(), session_id=_session())
    record = declared_tool_schemas()[("langchain", "call_api")]

    assert record.param_keys == ("api_key", "endpoint")
    rendered = repr(record.as_dict())
    assert "sk-live-DEADBEEF0000" not in rendered
    assert "collector.attacker.example" not in rendered


def test_nested_arguments_are_flattened_to_the_engines_path_syntax() -> None:
    """One notion of an argument path: dots for object keys, exactly like `input.derived.param_paths`."""

    class _Money(BaseModel):
        amount: float
        currency: str

    class _NestedArgs(BaseModel):
        txn_id: str
        payload: _Money

    class _NestedTool(BaseTool):
        name: str = "refund_nested"
        description: str = "refunds"
        args_schema: type[BaseModel] = _NestedArgs

        def _run(self, txn_id: str = "", payload: Any = None) -> str:
            return "ok"

    protect([_NestedTool()], _RecordingInterceptor(), session_id=_session())
    record = declared_tool_schemas()[("langchain", "refund_nested")]
    assert record.param_keys == ("payload.amount", "payload.currency", "txn_id")


def test_a_list_of_nested_objects_names_what_it_can_and_admits_the_rest() -> None:
    """`items: list[LineItem]` declares names a traffic path spells `items[0].sku`. A declared schema
    has no index to put there, so minting `items[].sku` would publish a path form nothing else in
    this system produces — an operator could pin it and it could never match. We name `items` and
    say the set is incomplete."""

    class _LineItem(BaseModel):
        sku: str
        qty: int

    class _OrderArgs(BaseModel):
        order_id: str
        items: list[_LineItem]

    class _OrderTool(BaseTool):
        name: str = "place_order"
        description: str = "orders"
        args_schema: type[BaseModel] = _OrderArgs

        def _run(self, order_id: str = "", items: Any = None) -> str:
            return "ok"

    protect([_OrderTool()], _RecordingInterceptor(), session_id=_session())
    record = declared_tool_schemas()[("langchain", "place_order")]

    assert record.param_keys == ("items", "order_id")
    assert not any(key.startswith("items[") for key in record.param_keys)
    assert record.param_keys_truncated is True  # "there is more here", not a complete answer


def test_an_enormous_schema_is_bounded_AND_says_that_it_was_cut_short() -> None:
    """A partial key-set reported as complete is the fail-open class this codebase keeps hitting:
    an operator shown 256 of 400 argument names, believing that is all of them, is worse off than
    one shown none."""
    big = create_model("_BigArgs", **{f"field_{i:04d}": (str, "") for i in range(400)})  # type: ignore[call-overload]

    class _BigTool(BaseTool):
        name: str = "wide_tool"
        description: str = "many arguments"
        args_schema: type[BaseModel] = big

        def _run(self, **kwargs: Any) -> str:
            return "ok"

    protect([_BigTool()], _RecordingInterceptor(), session_id=_session())
    record = declared_tool_schemas()[("langchain", "wide_tool")]

    assert len(record.param_keys) == MAX_DECLARED_PARAM_KEYS
    assert MAX_DECLARED_PARAM_KEYS < 400
    assert record.param_keys_truncated is True


def test_a_schema_that_explodes_on_access_does_not_break_wrapping_or_enforcement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """These are third-party objects. A tool that stops working because Norviq could not read its
    schema is a worse outcome than a tool whose schema is unknown — and enforcement must still run."""

    class _Hostile:
        """A tool whose schema attribute raises on access."""

        name = "hostile_tool"

        @property
        def args_schema(self) -> Any:
            raise RuntimeError("schema access exploded")

        def _run(self, query: str = "") -> str:
            return "ran"

    monkeypatch.setattr("norviq.sdk.langchain.adapter._get_base_tool", lambda: _Hostile)
    rec = _RecordingInterceptor()
    wrapped = protect([_Hostile()], rec, session_id=_session())

    assert wrapped[0]._run(query="hello") == "ran"          # the tool still works
    assert rec.params == {"query": "hello"}                  # ...and policy still ran on the real call
    record = declared_tool_schemas()[("langchain", "hostile_tool")]
    assert record.schema_available is False
    assert record.param_keys is None


def test_ingestion_does_not_change_the_payload_the_engine_evaluates() -> None:
    """Observational only: the declared schema must not leak into the evaluate payload, which is
    built from the ACTUAL call by `_tool_params` and stays exactly what it was."""
    rec = _RecordingInterceptor()
    wrapped = protect([_RefundTool()], rec, session_id=_session())
    wrapped[0]._run(txn_id="TXN-8891", amount=25.0)
    assert rec.params == {"txn_id": "TXN-8891", "amount": 25.0}


# ── a declared NAME can lie about which argument it is ──────────────────────────────────────────
#
# A schema is third-party text — an MCP server, a pip-installed tool package — so its key names are
# attacker-influenced, and the console renders them. `evaluator._walk_paths` already closed both of
# these on the TRAFFIC side by publishing `param_paths_ambiguous`; a declared schema can produce the
# same two lies and must answer for them the same way.


def _ingest_schema(schema: Any, name: str = "wire_transfer") -> Any:
    """Ingest a raw declaration the way a framework would hand one over, and return the record."""

    class _Tool:
        pass

    tool = _Tool()
    tool.args_schema = schema  # type: ignore[attr-defined]
    return ingest_declared_schema(tool, tool_name=name, framework="langchain", attrs=("args_schema",))


def test_two_declared_arguments_that_flatten_to_one_name_are_not_reported_as_one_argument() -> None:
    """`{"wire": {"destination": ...}, "wire.destination": ...}` DECLARES TWO arguments and renders
    as one path. Deduplicating them into a single key and calling the set complete is a partial
    answer wearing the costume of a whole one — and `wire.destination` is exactly the name the
    operator would have pinned a rule to."""
    record = _ingest_schema(
        {
            "type": "object",
            "properties": {
                "wire": {"type": "object", "properties": {"destination": {"type": "string"}}},
                "wire.destination": {"type": "string"},
            },
        }
    )

    assert record.param_keys == ("wire.destination",)
    # Two ways of saying it, because a consumer may only read one of them.
    assert record.param_keys_truncated is True          # the set is SHORTER than the declaration
    assert record.param_keys_ambiguous == ("wire.destination",)
    assert record.as_dict()["param_keys_ambiguous"] == ["wire.destination"]


def test_a_minted_key_is_named_but_an_ordinary_dotted_key_stays_scopable() -> None:
    """The engine's exact restraint, because over-flagging costs as much as under-flagging: an
    OpenTelemetry-style `http.method` argument with no `http` sibling names only itself, and calling
    it ambiguous would make the name the operator SEES permanently unscopable. It is dangerous only
    when a sibling provides a second route to the same path."""
    ordinary = _ingest_schema(
        {"type": "object", "properties": {"http.method": {"type": "string"}, "body": {"type": "string"}}},
        name="ordinary",
    )
    forged = _ingest_schema(
        {
            "type": "object",
            "properties": {
                "http": {"type": "object", "properties": {"x": {"type": "string"}}},
                "http.method": {"type": "string"},
            },
        },
        name="forged",
    )

    assert ordinary.param_keys == ("body", "http.method")
    assert ordinary.param_keys_ambiguous == ()
    assert "http.method" in forged.param_keys_ambiguous


def test_two_declared_names_that_RENDER_identically_are_named_as_such() -> None:
    """`amount` beside Cyrillic-а `аmount` is two arguments the console prints as one word. An
    operator authoring against what they were shown binds whichever twin the reader resolves, so the
    record has to say the name is not unique to one argument."""
    homoglyph = _ingest_schema(
        {"type": "object", "properties": {"amount": {"type": "number"}, "аmount": {"type": "number"}}},
        name="homoglyph",
    )
    case_twins = _ingest_schema(
        {"type": "object", "properties": {"To": {"type": "string"}, "to": {"type": "string"}}},
        name="case_twins",
    )

    assert len(homoglyph.param_keys) == 2  # both are kept; neither is rewritten
    assert "аmount" in homoglyph.param_keys_ambiguous
    assert set(case_twins.param_keys_ambiguous) == {"To", "to"}


def test_a_single_script_non_latin_argument_name_is_not_called_ambiguous() -> None:
    """The other half of the same restraint. A legitimately Cyrillic argument name impersonates
    nothing, and flagging every non-ASCII name would make non-Latin tools unscopable — the exact
    over-reach `norviq/engine/confusables.py` documents itself against."""
    record = _ingest_schema(
        {"type": "object", "properties": {"сумма": {"type": "number"},
                                          "amount": {"type": "number"}}},
        name="cyrillic",
    )
    assert record.param_keys_ambiguous == ()


def test_a_second_declared_source_is_consulted_when_the_first_one_explodes() -> None:
    """`attrs` are INDEPENDENT statements of the same fact: LangChain answers `.args` (derived from
    the tool's own `_run`) even when `args_schema` is a lazily-fetched property that raises. Giving
    up on the first failure reports "unknown" for a tool whose argument names are right there — the
    operator is told to keep looking at a screen that could have shown them `amount`."""

    class _LazyFailure:
        name = "issue_refund"

        @property
        def args_schema(self) -> Any:
            raise RuntimeError("deferred schema fetch failed")

        args = {"txn_id": {"type": "string"}, "amount": {"type": "number"}}

    record = ingest_declared_schema(
        _LazyFailure(),
        tool_name="issue_refund",
        framework="langchain",
        attrs=("args_schema", "args"),
    )
    assert record.schema_available is True
    assert record.param_keys == ("amount", "txn_id")
    assert record.source == "args"


def test_every_source_failing_is_still_UNREADABLE_and_never_empty() -> None:
    """Falling through must not turn "all sources exploded" into "the tool takes no arguments"."""

    class _AllExplode:
        name = "hostile"

        @property
        def args_schema(self) -> Any:
            raise RuntimeError("boom")

        @property
        def args(self) -> Any:
            raise RuntimeError("boom")

    record = ingest_declared_schema(
        _AllExplode(), tool_name="hostile", framework="langchain", attrs=("args_schema", "args")
    )
    assert record.schema_available is False
    assert record.param_keys is None
    assert record.unavailable_reason == "schema_unreadable"
