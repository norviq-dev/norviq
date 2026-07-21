# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""LangChain adapter for Norviq tool interception."""

import inspect
from typing import Any, get_type_hints

import structlog

from norviq.sdk.core.interceptor import ToolInterceptor
from norviq.sdk.core.wrapping import _output_dlp, _run_sync, _tool_params

log = structlog.get_logger()


def _mirror_signature(wrapper: Any, original: Any) -> None:
    """Make ``wrapper`` present ``original``'s call signature *and type hints* to introspection.

    LangChain/LangGraph decide which extra kwargs (``config``, ``run_manager``) to inject into
    ``_run``/``_arun`` by inspecting the target. Our wrapper is ``(*args, **kwargs)``, so without this
    LangChain injects nothing and the *original* ``StructuredTool._run`` — which requires a keyword-only
    ``config`` on langchain-core 1.x — then fails with "missing argument 'config'".

    It uses *two* detection mechanisms, and both must see the original's shape:
      * ``run_manager`` via ``inspect.signature(func).parameters`` — honored by ``__signature__``;
      * ``config`` via ``typing.get_type_hints(func)`` (it looks for the ``RunnableConfig``-typed
        parameter) — honored by ``__annotations__``, NOT ``__signature__``.
    So we mirror both. The hints are resolved in the *original's* module globals here (turning string
    annotations like ``"RunnableConfig"`` into the real type) so the wrapper carries concrete types the
    caller's ``get_type_hints`` can read without needing those names imported in this module.

    We deliberately do NOT set ``__wrapped__``: a ``__wrapped__`` attribute lets ``inspect.unwrap``
    reach the original callable directly, which would let a framework call the tool body *bypassing*
    Norviq's interception — a silent enforcement bypass. Mirroring keeps the wrapper on the call path.
    """
    try:
        wrapper.__signature__ = inspect.signature(original)
    except (ValueError, TypeError):  # some builtins/callables have no introspectable signature
        pass
    try:
        wrapper.__annotations__ = dict(get_type_hints(original))
    except Exception:  # noqa: BLE001 — unresolvable/absent hints must not break wrapping
        pass


def _get_base_tool() -> type[Any]:
    """Load LangChain BaseTool class lazily."""
    try:
        from langchain_core.tools import BaseTool
    except ImportError:
        from langchain.tools import BaseTool
    return BaseTool


def protect(
    tools: list[Any], interceptor: ToolInterceptor, session_id: str = "", *, allow_unwrapped: bool = False
) -> list[Any]:
    """Wrap LangChain tools so policy runs before execution.

    In sync-in-async usage, prefer `_arun` because async Redis clients are event-loop bound.

    Fail-closed by default: a framework upgrade that moves/renames `BaseTool` (or a caller that
    hands in something that was never a `BaseTool`) must be a loud startup error, not a silently
    unprotected tool — an item Norviq doesn't recognize as a `BaseTool` cannot be wrapped, so
    letting it through unwrapped means it runs with NO policy enforcement at all. Pass
    `allow_unwrapped=True` to downgrade this to a logged warning and accept the item as-is.
    """
    base_tool = _get_base_tool()
    protected: list[Any] = []
    for tool in tools:
        if not isinstance(tool, base_tool):
            if not allow_unwrapped:
                raise TypeError(
                    f"norviq.sdk.langchain.adapter.protect: {type(tool).__name__!r} is not a "
                    f"{base_tool.__name__} instance and cannot be wrapped — fail-closed protection: "
                    "this tool would run WITHOUT policy enforcement. Pass allow_unwrapped=True to "
                    "permit it deliberately."
                )
            log.warning(
                "nrvq.langchain.unwrapped",
                tool_type=type(tool).__name__,
                code="NRVQ-SDK-1044",
            )
            protected.append(tool)
            continue
        original_run = tool._run
        original_arun = getattr(tool, "_arun", None)

        def sync_wrapper(*args: Any, _name: str = tool.name, _orig: Any = original_run, **kwargs: Any) -> Any:
            _run_sync(
                interceptor.intercept_or_raise(
                    tool_name=_name,
                    tool_params=_tool_params(args, kwargs),
                    session_id=session_id,
                    framework="langchain",
                )
            )
            log.info("nrvq.langchain.allowed", tool=_name, code="NRVQ-SDK-1030")
            return _output_dlp(_name, _orig(*args, **kwargs))

        _mirror_signature(sync_wrapper, original_run)
        tool._run = sync_wrapper  # type: ignore[method-assign]
        if original_arun is not None:

            async def async_wrapper(
                *args: Any, _name: str = tool.name, _orig: Any = original_arun, **kwargs: Any
            ) -> Any:
                await interceptor.intercept_or_raise(
                    tool_name=_name,
                    tool_params=_tool_params(args, kwargs),
                    session_id=session_id,
                    framework="langchain",
                )
                log.info("nrvq.langchain.allowed", tool=_name, code="NRVQ-SDK-1030")
                return _output_dlp(_name, await _orig(*args, **kwargs))

            _mirror_signature(async_wrapper, original_arun)
            tool._arun = async_wrapper  # type: ignore[method-assign]
        protected.append(tool)
        log.debug("nrvq.langchain.protected", tool=tool.name, code="NRVQ-SDK-1031")
    log.info("nrvq.langchain.protect", count=len(protected), code="NRVQ-SDK-1032")
    return protected
