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
N_TOOLS_CHANGED = "notifications/tools/list_changed"
N_PROMPTS_CHANGED = "notifications/prompts/list_changed"
N_RESOURCES_CHANGED = "notifications/resources/list_changed"

# JSON-RPC 2.0 reserved error codes (spec §5.1). -32000..-32099 is the implementation-defined band;
# Norviq uses -32001 so a policy refusal is distinguishable from a genuine protocol error.
E_PARSE = -32700
E_INVALID_REQUEST = -32600
E_METHOD_NOT_FOUND = -32601
E_INTERNAL = -32603
E_POLICY_DENIED = -32001


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
