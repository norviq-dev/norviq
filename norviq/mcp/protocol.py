# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""JSON-RPC 2.0 / MCP wire helpers for the action-firewall proxy.

Deliberately hand-rolled rather than built on the ``mcp`` SDK. A proxy is not a client and not a
server: it must forward messages it does not understand (future methods, vendor extensions,
experimental capabilities) BYTE-FOR-BYTE, and an SDK that parses into typed models would either
reject them or silently normalise them. Faithfulness to the wire is the correctness property here,
so this module models exactly as much as the firewall needs to make a decision and treats the rest
as opaque.

The MCP stdio transport frames messages as newline-delimited JSON: one complete JSON value per
line, no embedded newlines. That is the only framing this module encodes/decodes; the
streamable-HTTP driver reuses the same message helpers over a different frame.
"""

from __future__ import annotations

import json
from typing import Any

# --- methods the firewall reasons about --------------------------------------------------------
# Everything NOT listed here is forwarded untouched. The list is deliberately short: each entry is
# a surface we have a defensible enforcement story for (see the design note's scope section).
M_INITIALIZE = "initialize"
M_TOOLS_LIST = "tools/list"
M_TOOLS_CALL = "tools/call"
M_RESOURCES_LIST = "resources/list"
M_RESOURCES_READ = "resources/read"
M_PROMPTS_LIST = "prompts/list"
M_PROMPTS_GET = "prompts/get"
M_SAMPLING_CREATE = "sampling/createMessage"

# ---- 2026-07-28 -------------------------------------------------------------------------------
# The protocol went STATELESS: sessions, the initialize handshake and server-INITIATED requests are
# all gone. Sampling/roots/elicitation are deprecated and their capability is now carried by Multi
# Round-Trip Requests — a server answers with `resultType: "input_required"` and the requests it
# needs, and the client RETRIES the original call with the answers attached.
#
# These constants are added rather than substituted: the 2025-06-18 codec still ships, and a proxy
# must speak whatever the pair in front of it speaks. See DESIGN-NOTE-MCP-FIREWALL.md §12.
M_SERVER_DISCOVER = "server/discover"
M_SUBSCRIPTIONS_LISTEN = "subscriptions/listen"

RESULT_TYPE = "resultType"
RESULT_COMPLETE = "complete"
RESULT_INPUT_REQUIRED = "input_required"
INPUT_REQUESTS = "inputRequests"
INPUT_RESPONSES = "inputResponses"
REQUEST_STATE = "requestState"
STRUCTURED_CONTENT = "structuredContent"

# `_meta` keys every request now carries in place of the handshake. They are POLICY inputs and never
# TRUST inputs — identity still comes from the caller's SVID and never from an MCP message (§3).
META_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion"
META_CLIENT_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"
META_CLIENT_INFO = "io.modelcontextprotocol/clientInfo"
META_SERVER_INFO = "io.modelcontextprotocol/serverInfo"
# Tags every notification on the single opted-in server->client stream (`subscriptions/listen`).
META_SUBSCRIPTION_ID = "io.modelcontextprotocol/subscriptionId"

# Tool parameters may now set HTTP headers on the outbound request. Model-controlled input reaching
# the header layer is header injection, auth-token smuggling and SSRF pivoting in one feature, and it
# is specified behaviour rather than a bug — so it is governed, not assumed benign (§12.4).
X_MCP_HEADER = "x-mcp-header"
N_TOOLS_CHANGED = "notifications/tools/list_changed"
N_PROMPTS_CHANGED = "notifications/prompts/list_changed"
N_RESOURCES_CHANGED = "notifications/resources/list_changed"

# JSON-RPC 2.0 reserved error codes (spec §5.1). -32000..-32099 is the implementation-defined band;
# Norviq uses -32001 so a policy refusal is distinguishable from a genuine protocol error.
# Protocol revisions this codec speaks. The proxy must handle whatever the pair in front of it
# negotiates, so both are live — `SPEC_2026` is not a migration target that retires `SPEC_2025`.
SPEC_2025 = "2025-06-18"
SPEC_2026 = "2026-07-28"
KNOWN_SPECS = (SPEC_2025, SPEC_2026)

E_PARSE = -32700
E_INVALID_REQUEST = -32600
E_METHOD_NOT_FOUND = -32601
E_INTERNAL = -32603
E_POLICY_DENIED = -32001

# 2026-07-28 partitions the JSON-RPC server-error range and RENUMBERS the codes introduced in the
# draft: -32000..-32019 stays implementation-defined (E_POLICY_DENIED above is grandfathered there),
# -32020..-32099 is reserved for the specification.
E_HEADER_MISMATCH = -32020
E_MISSING_REQUIRED_CLIENT_CAPABILITY = -32021
E_UNSUPPORTED_PROTOCOL_VERSION = -32022


class JsonRpcMessage:
    """One JSON-RPC 2.0 message, kept alongside the EXACT bytes it was decoded from.

    Holding ``raw`` is the point: an allowed message is re-emitted from the original bytes rather
    than re-serialised from ``data``. That is both a fidelity guarantee (key order, number
    formatting, and any field this proxy does not model survive the hop unchanged) and the single
    largest hot-path saving — a forwarded ``tools/call`` costs one parse, never a parse plus a dump.
    """

    __slots__ = ("data", "raw")

    def __init__(self, data: Any, raw: bytes) -> None:
        self.data = data
        self.raw = raw

    @property
    def framed(self) -> bytes:
        """``raw`` plus the transport's frame delimiter — what a pass-through must actually emit.

        ``raw`` is the STRIPPED payload, which is the right thing to hash, log and re-parse but the
        wrong thing to write: forwarding it verbatim concatenates every message into one unbounded
        line and the peer's readline() never returns. That is a silent hang, not an error, and it is
        exactly the bug this property exists to make impossible to write by accident.
        """
        return self.raw + b"\n"

    # -- shape predicates. A JSON-RPC message is a request (method + id), a notification (method,
    # no id), or a response (id + result/error). Anything else is malformed.
    @property
    def is_batch(self) -> bool:
        return isinstance(self.data, list)

    @property
    def method(self) -> str:
        return self.data.get("method", "") if isinstance(self.data, dict) else ""

    @property
    def id(self) -> Any:
        return self.data.get("id") if isinstance(self.data, dict) else None

    @property
    def has_id(self) -> bool:
        return isinstance(self.data, dict) and "id" in self.data and self.data["id"] is not None

    @property
    def is_request(self) -> bool:
        return bool(self.method) and self.has_id

    @property
    def is_notification(self) -> bool:
        return bool(self.method) and not self.has_id

    @property
    def is_response(self) -> bool:
        return isinstance(self.data, dict) and not self.method and "id" in self.data

    @property
    def params(self) -> dict:
        p = self.data.get("params") if isinstance(self.data, dict) else None
        return p if isinstance(p, dict) else {}

    @property
    def result(self) -> dict:
        r = self.data.get("result") if isinstance(self.data, dict) else None
        return r if isinstance(r, dict) else {}

    # ---- 2026-07-28 shapes -----------------------------------------------------------------
    # Every accessor below is safe against a 2025-06-18 message: the field is simply absent and the
    # default is the pre-2026 meaning. That is what lets one codec speak both revisions without a
    # mode flag — a proxy that had to be TOLD which spec it was on would be wrong the moment a peer
    # upgraded.

    @property
    def meta(self) -> dict:
        """`_meta` from params (requests) or result (responses).

        This is where the handshake went: a stateless request carries its own protocol version,
        client identity and capabilities. It is attacker-authorable, so it is POLICY input and never
        TRUST input — identity still comes from the attested SVID (§3).
        """
        for holder in (self.params, self.result):
            meta = holder.get("_meta")
            if isinstance(meta, dict):
                return meta
        return {}

    @property
    def protocol_version(self) -> str:
        """The revision this message declares, or "" when it declares none (i.e. 2025-06-18)."""
        value = self.meta.get(META_PROTOCOL_VERSION)
        return value if isinstance(value, str) else ""

    @property
    def result_type(self) -> str:
        """`complete` | `input_required`.

        A result from an earlier-protocol server omits the field and MUST be treated as complete —
        the spec says so explicitly, and defaulting the other way would make every 2025-06-18 result
        look like a demand for input.
        """
        if not self.is_response:
            return ""
        value = self.result.get(RESULT_TYPE)
        return value if isinstance(value, str) else RESULT_COMPLETE

    @property
    def is_input_required(self) -> bool:
        return self.result_type == RESULT_INPUT_REQUIRED

    @property
    def input_requests(self) -> list:
        """The questions a server is asking the client, from an `input_required` result."""
        value = self.result.get(INPUT_REQUESTS)
        return value if isinstance(value, list) else []

    @property
    def input_responses(self) -> Any:
        """The answers a client is attaching to a retry, or None for an ordinary call."""
        value = self.params.get(INPUT_RESPONSES)
        return value if value not in (None, {}, []) else None

    @property
    def cache_hints(self) -> dict:
        """`ttlMs` / `cacheScope` from a list result (2026-07-28 CacheableResult).

        `cacheScope: "public"` matters to a firewall beyond performance: a poisoned `tools/list` may
        legitimately be cached and re-served by a shared intermediary the proxy never sees again, so
        Gate A's pin is the only thing that still detects it downstream.
        """
        out = {}
        ttl = self.result.get("ttlMs")
        scope = self.result.get("cacheScope")
        if isinstance(ttl, (int, float)) and not isinstance(ttl, bool):
            out["ttl_ms"] = ttl
        if isinstance(scope, str):
            out["cache_scope"] = scope
        return out

    def __repr__(self) -> str:  # pragma: no cover - diagnostics only
        return f"<JsonRpcMessage method={self.method!r} id={self.id!r}>"


def decode(line: bytes) -> JsonRpcMessage | None:
    """Decode one framed line. Returns None when the line is blank or not valid JSON.

    A None return is a FAIL-CLOSED signal for the caller, not a "pass it through": a proxy that
    forwards bytes it could not parse cannot claim to have enforced anything on them.
    """
    stripped = line.strip()
    if not stripped:
        return None
    try:
        return JsonRpcMessage(json.loads(stripped), stripped)
    except (ValueError, UnicodeDecodeError):
        return None


def encode(payload: Any) -> bytes:
    """Frame one message for the stdio transport (compact JSON + newline).

    ``ensure_ascii`` stays on: the stdio transport is byte-oriented and a peer that decodes with a
    non-UTF-8 locale would otherwise mangle non-Latin content. Escaping is lossless.
    """
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8") + b"\n"


def error_response(msg_id: Any, code: int, message: str, data: dict | None = None) -> dict:
    """A JSON-RPC error response object."""
    err: dict[str, Any] = {"code": code, "message": message}
    if data:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": msg_id, "error": err}


def tool_error_result(msg_id: Any, text: str, meta: dict | None = None) -> dict:
    """A ``tools/call`` refusal expressed as an MCP TOOL error, not a JSON-RPC protocol error.

    MCP draws the line deliberately: a JSON-RPC ``error`` means the protocol interaction failed,
    while ``result.isError`` means the tool ran and reported a failure. A policy block is neither,
    so the choice is a judgement call and this is the reasoning for landing on ``isError``:

      * A JSON-RPC error is handled by the CLIENT's transport layer. Several hosts treat a
        server-originated error on a tool call as a session fault and tear the connection down —
        one blocked call would kill the whole agent run, turning a targeted denial into an outage.
      * ``isError`` puts the refusal in the model's context as tool output, which is exactly where
        it is useful: the agent reads "blocked by rule X", stops retrying, and can route around it.
        That is the difference between an enforcement point and a crash.

    The block is still absolute — the upstream server never sees the call. Only the SHAPE of the
    refusal is friendly. ``_meta`` carries the machine-readable decision for hosts that want it.
    """
    result: dict[str, Any] = {
        "content": [{"type": "text", "text": text}],
        "isError": True,
    }
    if meta:
        result["_meta"] = {"norviq": meta}
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}
