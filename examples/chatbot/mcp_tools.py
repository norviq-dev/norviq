# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""MCP client + LangChain tool adapter for the demo chatbot.

Enforcement path: the Norviq MCP action-firewall, NOT the in-process SDK. The agent never talks to
an MCP server directly — every endpoint in `servers_from_env()` is a `python -m norviq.mcp --http`
sidecar on loopback, and the real server sits behind it:

    agent -> 127.0.0.1:910X (norviq.mcp firewall) -> mcp-{kb,crm,ops}.chatbot-prod.svc:8080/mcp

So `initialize`/`tools/list` are adjudicated at Gate A and `tools/call` at Gate B, and the tool body
runs on the far side of a decision this process cannot skip. That is the difference from `agent.py`:
there, `protect()` wraps a Python function in THIS process and an unwrapped call path would bypass
it; here the enforcement point is a separate process that owns the only route to the tool.

Discovery is dynamic on purpose. Hardcoding the tool list would mean the demo never issues a real
`tools/list`, so Gate A — definition scanning, pinning, rug-pull detection — would never run and the
half of the product that governs DISCOVERY would be untested by the thing built to demonstrate it.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
from collections.abc import Iterator, Sequence
from contextlib import asynccontextmanager, contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any

from langchain_core.tools import StructuredTool
from mcp import ClientSession
# The MCP SDK renamed this symbol (`streamablehttp_client` -> `streamable_http_client`) inside the 1.x
# range this file's requirements allow, so a fresh build of this example crash-looped on ImportError
# while an older lockfile kept working. Accept both spellings rather than pinning to one and breaking
# on the other edge of the supported range.
try:  # SDKs from the rename onward
    from mcp.client.streamable_http import streamable_http_client as streamablehttp_client
except ImportError:  # older SDKs, still inside the supported floor
    from mcp.client.streamable_http import streamablehttp_client
from mcp.shared.exceptions import McpError

# The contract's sidecar ports. Overridable so the same module runs against a local `--listen` proxy
# during development without editing code, but the DEFAULTS are the deployed topology — a missing
# env var must not silently point the agent somewhere else.
_DEFAULT_ENDPOINTS: tuple[tuple[str, str], ...] = (
    ("kb", "http://127.0.0.1:9101/mcp"),
    ("crm", "http://127.0.0.1:9102/mcp"),
    ("ops", "http://127.0.0.1:9103/mcp"),
)

# Norviq's own JSON-RPC error code for a policy refusal (norviq/mcp/protocol.py:E_POLICY_DENIED).
# Most refusals arrive as `isError` tool results instead — see `_denial_from_result` — but the
# transport-header guard answers with a protocol error, and that is still a policy denial.
_E_POLICY_DENIED = -32001


@dataclass(frozen=True)
class McpServer:
    """One firewall endpoint. `server_id` matches the sidecar's `--server-id`, so it is the same
    string the firewall stamps into `_meta.norviq.server` and into its audit records."""

    server_id: str
    url: str


@dataclass(frozen=True)
class McpDenial:
    """A refusal the Norviq firewall issued, in the shape the firewall actually emits.

    Field-for-field from `_meta.norviq` (norviq/mcp/firewall.py). Nothing here is invented: `gate`
    is "A" for a discovery-time denial carried over to the call, "B" for the policy decision or a
    schema-conformance refusal; `rule_id` is empty for the Gate A and schema paths because no policy
    rule fired — the definition itself was refused.
    """

    server_id: str
    tool: str
    gate: str
    decision: str
    rule_id: str
    reason: str
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def label(self) -> str:
        """What the UI badge should say when there is no rule id to name."""
        if self.rule_id:
            return self.rule_id
        if self.detail.get("schema_violations"):
            return "schema-conformance"
        if self.gate == "A":
            return f"gate-A:{self.detail.get('pin_status') or 'withheld'}"
        return "policy"


@dataclass
class McpCall:
    """One `tools/call` this process attempted, and how it ended."""

    tool: str
    server_id: str
    denial: McpDenial | None = None


# Per-turn recorder. The firewall answers a blocked call with `isError` rather than an exception (see
# `tool_error_result` in norviq/mcp/protocol.py — a JSON-RPC error would make some hosts tear down
# the session, turning one denial into an outage), and we honour that: the refusal text goes back to
# the model as tool output. But then NOTHING propagates for the HTTP layer to report, so the denial
# would be invisible to the caller and to the UI. This is the same problem serve.py solves with
# `capture_decisions` for the SDK path, and it is solved the same way here.
_CALLS: ContextVar[list[McpCall] | None] = ContextVar("nrvq_mcp_calls", default=None)


@contextmanager
def capture_mcp_calls() -> Iterator[list[McpCall]]:
    """Record every MCP tool call made inside the block. Reentrant-safe via ContextVar tokens."""
    calls: list[McpCall] = []
    token = _CALLS.set(calls)
    try:
        yield calls
    finally:
        _CALLS.reset(token)


def _record(call: McpCall) -> None:
    calls = _CALLS.get()
    if calls is not None:
        calls.append(call)


def servers_from_env() -> list[McpServer]:
    """The three firewall endpoints, each overridable by `CHATBOT_MCP_<ID>_URL`.

    NOT `NRVQ_MCP_<ID>_URL`, which is the tempting name and the wrong one. `NRVQ_MCP_*` is the
    namespace `norviq/config.py` already owns (`NRVQ_MCP_PIN_STORE`, `NRVQ_MCP_PIN_MODE`, …), bound
    with `env_prefix="NRVQ_"` and `extra="ignore"`. A demo variable parked in that namespace reads
    like an SDK setting, and anyone who later moved this lookup onto `settings` would find the value
    silently swallowed — configured-looking and doing nothing. k8s/deployment.yaml sets these names.
    """
    return [
        McpServer(server_id=sid, url=os.getenv(f"CHATBOT_MCP_{sid.upper()}_URL", default_url))
        for sid, default_url in _DEFAULT_ENDPOINTS
    ]


@asynccontextmanager
async def _session(url: str):
    """One initialized MCP session, opened and closed inside a single task.

    A session is deliberately NOT held open across requests. `streamablehttp_client` and
    `ClientSession` are anyio task groups, and an anyio cancel scope may only be exited by the task
    that entered it — so a session opened in FastAPI's lifespan and used from a request task raises
    "Attempted to exit cancel scope in a different task" the moment anything is cancelled. That
    failure is intermittent and shows up as a wedged request, which is the worst kind to debug.

    The cost is one `initialize` per operation. For this demo that is not merely acceptable, it is
    the point: every call re-runs Gate A, so a server that changes a tool definition between two
    turns is caught on the second one instead of at process start and never again.
    """
    async with streamablehttp_client(url) as (read, write, _get_session_id):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session


async def discover(server: McpServer) -> list[Any]:
    """`initialize` + `tools/list` through the firewall. Returns whatever Gate A let through.

    A tool the firewall WITHHELD (poisoned description, drifted definition) simply is not in this
    list — that is Gate A working, not an error, so an empty or short list is reported, not raised.
    """
    async with _session(server.url) as session:
        return list((await session.list_tools()).tools)


def _text_of(result: Any) -> str:
    """Flatten a CallToolResult's content blocks into the string a LangChain tool must return."""
    parts: list[str] = []
    for block in getattr(result, "content", None) or []:
        text = getattr(block, "text", None)
        if text:
            parts.append(text)
        else:  # image/audio/resource blocks — name the type rather than dropping it silently
            parts.append(f"[{getattr(block, 'type', 'content')}]")
    return "\n".join(parts) if parts else "(no content)"


def _denial_from_result(server_id: str, tool: str, result: Any) -> McpDenial | None:
    """Read the firewall's structured refusal off a `tools/call` result, or return None.

    `isError` alone does NOT mean Norviq refused — a tool that genuinely failed sets it too. The
    discriminator is `_meta.norviq`, which only the firewall writes. Mapping on `isError` alone
    would relabel every upstream bug as a policy block and make the demo lie in the safe direction.
    """
    if not getattr(result, "isError", False):
        return None
    meta = getattr(result, "meta", None) or {}
    norviq = meta.get("norviq") if isinstance(meta, dict) else None
    if not isinstance(norviq, dict):
        return None
    return McpDenial(
        server_id=str(norviq.get("server") or server_id),
        tool=tool,
        gate=str(norviq.get("gate") or ""),
        # Gate A and schema refusals carry no `decision` key: the definition was refused before any
        # policy ran. "block" is the honest summary for the UI — the call did not execute.
        decision=str(norviq.get("decision") or "block"),
        rule_id=str(norviq.get("rule_id") or ""),
        reason=_text_of(result),
        detail=dict(norviq),
    )


async def _invoke(server: McpServer, wire_name: str, arguments: dict[str, Any]) -> str:
    """Call one tool through the firewall and return what the model should see.

    A denial is returned as text, not raised. That is a faithful mapping of the firewall's own
    choice: it answers with `isError` so the refusal lands in the model's context, where the agent
    reads "blocked by rule X", stops retrying and routes around it. Raising here would convert a
    targeted denial into a dead agent turn and lose the behaviour the enforcement point was designed
    to produce. The structured decision is not lost — it goes to the recorder for the UI.
    """
    call = McpCall(tool=wire_name, server_id=server.server_id)
    try:
        async with _session(server.url) as session:
            result = await session.call_tool(wire_name, arguments)
    except McpError as exc:
        # The other refusal shape: a JSON-RPC error. The firewall uses it for the transport-header
        # guard (NRVQ-MCP-5063), where the ARGUMENTS themselves are the attack, so there is no
        # sensible tool result to return.
        error = exc.error
        if getattr(error, "code", None) == _E_POLICY_DENIED:
            call.denial = McpDenial(
                server_id=server.server_id,
                tool=wire_name,
                gate="B",
                decision="block",
                rule_id="",
                reason=str(error.message),
                detail={"jsonrpc_code": _E_POLICY_DENIED},
            )
            _record(call)
            return str(error.message)
        _record(call)
        return f"(MCP error from '{server.server_id}': {error.message})"
    call.denial = _denial_from_result(server.server_id, wire_name, result)
    _record(call)
    return _text_of(result)


def _to_langchain_tool(server: McpServer, spec: Any, exposed_name: str) -> StructuredTool:
    """Wrap one discovered MCP tool as a LangChain tool.

    `exposed_name` is what the MODEL sees; `spec.name` is what goes on the wire. They differ only
    when `_resolve_names` had to disambiguate a collision — see the note there.
    """
    wire_name = spec.name
    schema = dict(spec.inputSchema or {"type": "object", "properties": {}})
    description = (spec.description or f"{wire_name} (via MCP server '{server.server_id}')").strip()

    async def _run(**kwargs: Any) -> str:
        return await _invoke(server, wire_name, kwargs)

    return StructuredTool(
        name=exposed_name,
        description=description,
        args_schema=schema,
        coroutine=_run,
        # Sync path refused rather than faked. `asyncio.run` inside a running loop raises, and a
        # thread-hopped loop would open the MCP session on a different task than it closes — the
        # exact cancel-scope failure `_session` exists to avoid. The agent is invoked with
        # `ainvoke`, so this path is unreachable in the demo; make it loud if that ever changes.
        func=_sync_unsupported,
    )


def _sync_unsupported(**_: Any) -> str:
    raise NotImplementedError("MCP-backed tools are async-only; invoke the agent with ainvoke()")


def _resolve_names(discovered: list[tuple[McpServer, Any]]) -> dict[int, str]:
    """Decide the name each discovered tool is exposed to the model under.

    The contract's tool names are unique across kb/crm/ops today, so nothing below changes anything
    for the demo. It is here because two MCP servers CAN advertise the same name — this repo's own
    seeder ships a `read_file` collision precisely as a test case — and LangChain binds tools into
    one flat namespace, so a silent last-wins overwrite would make one server's tool unreachable and
    route its calls to the other server. That is a security-relevant confusion, not a cosmetic one.

    CHOICE: on collision, EVERY colliding tool is exposed as `<server_id>__<name>` and the bare name
    is retired. Not "first one wins": that is order-dependent, so which server owns `read_file`
    would depend on discovery timing, and a rug-pulled server could grab a name by answering faster.
    Retiring the bare name makes the outcome identical no matter what order discovery completed in.

    WHAT IS NOT RENAMED: the wire name. `tools/call` still carries the server's own `read_file`, and
    the firewall still evaluates `read_file`, because that is the name the POLICY is written against
    — norviq/mcp/__main__.py keeps `--tool-name-prefix` off by default for exactly this reason ("it
    breaks the 1:1 mapping onto the engine's contract"). Prefixing here would therefore be worse
    than useless: the model would call `ops__read_file`, the engine would still see `read_file`, and
    a policy author reading the audit trail could not tell the two servers apart anyway. If policy
    genuinely must distinguish them, turn `--tool-name-prefix` on AT THE FIREWALL, where both the
    decision and the audit record change together — do not fake the distinction on this side.
    """
    counts: dict[str, int] = {}
    for _, spec in discovered:
        counts[spec.name] = counts.get(spec.name, 0) + 1
    return {
        index: (f"{server.server_id}__{spec.name}" if counts[spec.name] > 1 else spec.name)
        for index, (server, spec) in enumerate(discovered)
    }


async def load_mcp_tools(servers: Sequence[McpServer] | None = None) -> tuple[list[StructuredTool], list[str]]:
    """Discover every tool the firewalls expose and return them as LangChain tools.

    Returns `(tools, problems)`. A server that is down yields a problem string rather than an
    exception: three sidecars start independently of the agent container, and refusing to serve any
    tools because one of them is slow would make the demo look like a Norviq failure when it is a
    startup race. What must NEVER be degraded to a warning is a DENIAL — those come from a server
    that answered, and they are absences in the catalog, which is Gate A working as designed.
    """
    targets = list(servers) if servers is not None else servers_from_env()
    results = await asyncio.gather(*(discover(s) for s in targets), return_exceptions=True)

    discovered: list[tuple[McpServer, Any]] = []
    problems: list[str] = []
    for server, outcome in zip(targets, results):
        if isinstance(outcome, BaseException):
            problems.append(f"{server.server_id} ({server.url}): {type(outcome).__name__}: {outcome}")
            continue
        discovered.extend((server, spec) for spec in outcome)

    names = _resolve_names(discovered)
    tools = [_to_langchain_tool(server, spec, names[index]) for index, (server, spec) in enumerate(discovered)]
    return tools, problems


async def probe(servers: Sequence[McpServer] | None = None) -> dict[str, Any]:
    """Discovery report for `/tools` and for debugging: what each firewall let through.

    Deliberately NOT a static table like the SDK demo's `/tools`. This is the live Gate A result, so
    a tool missing here is a tool the firewall withheld.
    """
    targets = list(servers) if servers is not None else servers_from_env()
    out: dict[str, Any] = {"servers": []}
    for server in targets:
        entry: dict[str, Any] = {"server_id": server.server_id, "url": server.url}
        try:
            specs = await discover(server)
        except Exception as exc:  # noqa: BLE001 — a report must describe a broken endpoint, not die on it
            entry["error"] = f"{type(exc).__name__}: {exc}"
            entry["tools"] = []
        else:
            entry["tools"] = [{"name": s.name, "description": (s.description or "").strip()[:160]} for s in specs]
        out["servers"].append(entry)
    return out


async def aclose() -> None:
    """No-op kept for symmetry with `agent.py`'s `engine.close()`.

    Sessions are per-operation (see `_session`), so there is no pool to drain — but app.py's
    lifespan should not have to know that, and a future connection-reusing implementation would
    need exactly this hook.
    """
    with contextlib.suppress(Exception):
        await asyncio.sleep(0)
