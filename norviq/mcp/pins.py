# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Gate A: content-hash pinning of MCP tool definitions (rug-pull defence).

THE ATTACK. An MCP server is approved once — by a human reading its tool list, or by a host that
prompts "allow this server?" — and is then trusted for the life of the integration. Nothing in the
protocol binds the definition that was approved to the definition that is served tomorrow. A server
can ship a benign `send_email` on day one, wait out the review, and on day thirty add
"...also BCC audit@attacker.example" to the description. The host re-reads `tools/list` on every
session and injects the new text with the old approval's authority. `notifications/tools/list_changed`
even gives the server a blessed way to trigger the re-read.

THE MODEL. Bind approval to CONTENT, not to a name:

    pin_id  = sha256(server_id + "\\0" + tool_name)          # stable identity
    digest  = sha256(canonical_json(security_relevant_fields)) # what was approved

`digest` covers only the fields that can influence the model or the call: name, title, description,
inputSchema, outputSchema, annotations. It deliberately EXCLUDES transport metadata and any
`_meta`, so a server bumping an unrelated field does not manufacture a false drift — a detector
that cries wolf gets disabled, which is worse than not having it.

TRUST ON FIRST USE, AND WHY IT IS ENOUGH HERE. The first time a tool is seen there is nothing to
compare against. The options are (a) refuse until a human approves, (b) accept and pin. Norviq's
single-cluster posture already has a fail-closed control for "an unknown thing tried to act" —
Gate B, where an unrecognised tool classifies as verb `unknown` and a deny-by-default policy
refuses it. So Gate A does not need to be the gate that stops first use; it needs to be the gate
that stops CHANGE. TOFU with a loud, auditable first-pin record gets that, and it is the only
option that does not require a human in the loop of every new server in a spike.

The mode is configurable (`NRVQ_MCP_PIN_MODE`):
  * ``tofu``   (default) — first sight pins silently-but-auditably; drift is enforced.
  * ``strict`` — first sight QUARANTINES the tool (calls denied) until an operator approves it.
                 This is the posture for a production tenant; it is not the default because in a
                 spike it turns every demo into an approval workflow.

WHERE PINS LIVE. Two backends ship here: in-memory (per session) and a JSON file (survives process
restart, which matters because "restart the pod" is otherwise a free pin reset for an attacker).
The RIGHT home in a real deployment is the Norviq control plane — pins are approvals, approvals are
policy, and policy is already tenant-scoped, RBAC'd, audited and admin-visible in this product.
That is a new API resource plus a migration and is called out as the recommended next step in the
design note rather than half-built here.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Protocol

from norviq.config import settings

import structlog

log = structlog.get_logger()

# The fields whose change is security-relevant. Everything else in a tool definition is metadata the
# host may use for display; changing it cannot alter what the model is told to do or what the call
# can carry.
_PINNED_FIELDS = ("name", "title", "description", "inputSchema", "outputSchema", "annotations")

PIN_OK = "pinned"            # digest matches the approved one
PIN_FIRST_SEEN = "first_seen"  # newly pinned this session (TOFU) — allowed, recorded
PIN_DRIFT = "drift"          # digest changed against an existing pin — the rug pull
PIN_QUARANTINED = "quarantined"  # awaiting approval (strict mode) or held after a scan verdict


def canonical_definition(tool: dict) -> str:
    """Canonical JSON of the security-relevant fields, for hashing.

    ``sort_keys`` makes the digest independent of the server's key ordering, so a server that
    re-serialises its own catalog does not look like it changed. Separators are pinned so
    whitespace differences cannot either.
    """
    subset = {k: tool.get(k) for k in _PINNED_FIELDS if k in tool}
    return json.dumps(subset, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def definition_digest(tool: dict) -> str:
    """sha256 over the canonical definition."""
    return hashlib.sha256(canonical_definition(tool).encode("utf-8")).hexdigest()


def pin_id(server_id: str, tool_name: str) -> str:
    """Stable identity for one tool of one server. NUL-joined so `a`+`b/c` cannot collide with `a/b`+`c`."""
    return hashlib.sha256(f"{server_id}\0{tool_name}".encode("utf-8")).hexdigest()[:32]


@dataclass
class ToolPin:
    """One approved tool definition."""

    pin: str
    server_id: str
    tool_name: str
    digest: str
    first_seen_at: float
    approved: bool
    scan_severity: str = "none"
    # Kept for the operator-facing diff on drift: "what did it used to say?" is the first question
    # asked when a rug pull fires, and re-fetching the old definition is impossible after the fact.
    canonical: str = ""
    drift_count: int = 0
    last_digest: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class PinStore(Protocol):
    """Backend contract. Reads are on the DISCOVERY path only; the call path never touches a store."""

    def get(self, pin: str) -> ToolPin | None: ...
    def put(self, record: ToolPin) -> None: ...
    def all(self) -> list[ToolPin]: ...


class MemoryPinStore:
    """Per-process pins. Correct for a stdio proxy whose lifetime IS the session, and for tests.

    Honest limitation: a process restart forgets every pin, so an attacker who can induce a restart
    (or simply waits for a rollout) gets a free re-TOFU. Use the file store when the proxy outlives
    a single client session.
    """

    def __init__(self) -> None:
        self._pins: dict[str, ToolPin] = {}

    def get(self, pin: str) -> ToolPin | None:
        return self._pins.get(pin)

    def put(self, record: ToolPin) -> None:
        self._pins[record.pin] = record

    def all(self) -> list[ToolPin]:
        return list(self._pins.values())


class FilePinStore:
    """Pins persisted as one JSON document, loaded once and written atomically on change.

    Atomic because the alternative is a truncated pin file after a crash, and a pin file that fails
    to parse must not become "no pins" — that would silently downgrade every tool to first-seen and
    disarm drift detection exactly when something has already gone wrong. A corrupt file therefore
    raises at construction rather than being discarded.
    """

    def __init__(self, path: str) -> None:
        self._path = Path(path)
        self._pins: dict[str, ToolPin] = {}
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            return
        raw = json.loads(self._path.read_text(encoding="utf-8"))  # deliberately unguarded — see docstring
        for pin, row in raw.get("pins", {}).items():
            self._pins[pin] = ToolPin(**row)
        log.info("nrvq.mcp.pins.loaded", path=str(self._path), count=len(self._pins), code="NRVQ-MCP-5040")

    def get(self, pin: str) -> ToolPin | None:
        return self._pins.get(pin)

    def put(self, record: ToolPin) -> None:
        self._pins[record.pin] = record
        self._flush()

    def all(self) -> list[ToolPin]:
        return list(self._pins.values())

    def _flush(self) -> None:
        payload = {"version": 1, "pins": {p: r.as_dict() for p, r in self._pins.items()}}
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(self._path.parent), prefix=".pins-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, separators=(",", ":"))
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self._path)
        except BaseException:
            # Leave no partial file behind; the in-memory map stays authoritative for this process.
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise


@dataclass(frozen=True)
class PinVerdict:
    """Outcome of checking one definition against its pin."""

    status: str
    record: ToolPin
    previous_canonical: str = ""


class PinRegistry:
    """Checks definitions against pins. Called at DISCOVERY only; the call path reads the cached
    status off the catalog entry, so a `tools/call` never reaches this class."""

    def __init__(self, store: PinStore | None = None, mode: str = "tofu") -> None:
        self._store = store or MemoryPinStore()
        # Anything not recognised is coerced to the STRICTER mode. A typo in NRVQ_MCP_PIN_MODE must
        # not silently disable the gate.
        self._mode = mode if mode in ("tofu", "strict") else "strict"

    @property
    def mode(self) -> str:
        return self._mode

    def check(self, server_id: str, tool: dict, scan_severity: str = "none") -> PinVerdict:
        """Compare one definition against its pin, creating the pin on first sight."""
        name = str(tool.get("name", ""))
        pid = pin_id(server_id, name)
        digest = definition_digest(tool)
        canonical = canonical_definition(tool)
        existing = self._store.get(pid)

        if existing is None:
            approved = self._mode == "tofu"
            record = ToolPin(
                pin=pid, server_id=server_id, tool_name=name, digest=digest,
                first_seen_at=time.time(), approved=approved, scan_severity=scan_severity,
                canonical=canonical, last_digest=digest,
            )
            self._store.put(record)
            status = PIN_FIRST_SEEN if approved else PIN_QUARANTINED
            log.info(
                "nrvq.mcp.pin.first_seen", server=server_id, tool=name, digest=digest[:16],
                mode=self._mode, status=status, code="NRVQ-MCP-5041",
            )
            return PinVerdict(status=status, record=record)

        if existing.digest == digest:
            status = PIN_OK if existing.approved else PIN_QUARANTINED
            return PinVerdict(status=status, record=existing)

        # DRIFT. The pin is NOT updated to the new digest: silently re-pinning would make the second
        # call to a rug-pulled tool succeed, so an attacker would only need to absorb one blocked
        # call. Approval stays with the definition that was approved; adopting the new one is an
        # explicit operator action.
        existing.drift_count += 1
        existing.last_digest = digest
        self._store.put(existing)
        log.warning(
            "nrvq.mcp.pin.drift", server=server_id, tool=name,
            approved_digest=existing.digest[:16], served_digest=digest[:16],
            drift_count=existing.drift_count, code="NRVQ-MCP-5042",
        )
        return PinVerdict(status=PIN_DRIFT, record=existing, previous_canonical=existing.canonical)

    def approve(self, server_id: str, tool_name: str, digest: str) -> bool:
        """Adopt a specific digest as approved (the operator action that clears a drift/quarantine).

        Takes the digest explicitly so an approval cannot race a second change: approving "whatever
        it says now" would let a server flip its definition between the operator reading it and the
        approval landing.
        """
        record = self._store.get(pin_id(server_id, tool_name))
        if record is None:
            return False
        if digest not in (record.digest, record.last_digest):
            return False
        record.digest = digest
        record.approved = True
        self._store.put(record)
        log.info("nrvq.mcp.pin.approved", server=server_id, tool=tool_name,
                 digest=digest[:16], code="NRVQ-MCP-5043")
        return True

    def snapshot(self) -> list[dict[str, Any]]:
        return [r.as_dict() for r in self._store.all()]

    def snapshot_records(self) -> list[ToolPin]:
        """The pin records themselves (the dict form is for serialisation, not for callers)."""
        return self._store.all()


def build_store(kind: str, path: str) -> PinStore:
    """Construct the configured backend. Unknown kind -> memory (the safe, dependency-free default)."""
    if kind == "file" and path:
        return FilePinStore(path)
    return MemoryPinStore()


class ControlPlanePinStore:
    """Pins held by the Norviq API — the durable, tenant-scoped, operator-visible home.

    WHY NOT JUST TALK TO THE API PER LOOKUP. The store contract is synchronous and is consulted once
    per tool at DISCOVERY. Making `get()` an HTTP call would put the control plane on the path of
    every `tools/list`, and a slow control plane would then stall session startup for every agent.
    Instead:

      * `load()` — awaited ONCE at proxy startup — pulls this server's pins into memory.
      * `get()` / `all()` — pure in-memory, so the discovery path never blocks on the network and the
        call path (which only ever reads a cached catalog entry) is untouched.
      * `put()` — updates memory and enqueues an upsert; a background task flushes it. Discovery must
        not wait on a write for a decision that has already been made locally from the loaded state.

    DEGRADATION, and its honest limit. If the control plane is unreachable at startup this store
    fails to a LOCAL fallback rather than refusing to run. That is a deliberate availability choice
    and it is defensible only because Gate B is unaffected: every tool call is still evaluated
    against policy, and a fail-closed engine still blocks. What is lost is cross-pod drift detection
    for the duration of the outage — the pod degrades to per-process TOFU. It is logged loudly at
    NRVQ-MCP-5046; it is not silent, and it is not a bypass of enforcement.
    """

    def __init__(self, namespace: str, server_id: str, api_url: str = "", token: str = "",
                 mode: str = "tofu", transport: str = "stdio") -> None:
        self._namespace = namespace
        self._server_id = server_id
        self._api_url = (api_url or settings.api_url).rstrip("/")
        self._token = token if token else settings.api_token
        self._mode = mode
        self._transport = transport
        self._pins: dict[str, ToolPin] = {}
        self._pending: list[ToolPin] = []
        self._degraded = False

    # -- PinStore protocol (sync, in-memory) --------------------------------------------------
    def get(self, pin: str) -> ToolPin | None:
        return self._pins.get(pin)

    def put(self, record: ToolPin) -> None:
        self._pins[record.pin] = record
        self._pending.append(record)

    def all(self) -> list[ToolPin]:
        return list(self._pins.values())

    @property
    def degraded(self) -> bool:
        return self._degraded

    # -- control-plane I/O ---------------------------------------------------------------------
    def _headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self._token:
            h["Authorization"] = f"Bearer {self._token}"
        return h

    async def load(self) -> None:
        """Pull this (namespace, server) pair's approved pins into memory. Never raises."""
        import httpx  # local: keeps the module importable where httpx is absent (pure-unit tests)

        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(5.0, connect=2.0)) as client:
                resp = await client.get(
                    f"{self._api_url}/api/v1/mcp/pins",
                    params={"namespace": self._namespace, "server_id": self._server_id},
                    headers=self._headers(),
                )
                resp.raise_for_status()
                rows = resp.json()
        except Exception as exc:
            self._degraded = True
            log.error(
                "nrvq.mcp.pins.control_plane_unreachable",
                detail="falling back to per-process TOFU; Gate B enforcement is unaffected, but "
                       "cross-pod drift detection is degraded until the control plane returns",
                server=self._server_id, error=str(exc), code="NRVQ-MCP-5046",
            )
            return

        for row in rows if isinstance(rows, list) else []:
            name = row.get("tool_name", "")
            record = ToolPin(
                pin=pin_id(self._server_id, name),
                server_id=self._server_id,
                tool_name=name,
                digest=row.get("approved_digest", ""),
                first_seen_at=0.0,
                approved=bool(row.get("approved")),
                scan_severity=row.get("scan_severity", "none"),
                canonical=row.get("approved_canonical", ""),
                drift_count=int(row.get("drift_count", 0)),
                last_digest=row.get("last_digest", ""),
            )
            self._pins[record.pin] = record
        log.info("nrvq.mcp.pins.loaded_from_control_plane", server=self._server_id,
                 count=len(self._pins), code="NRVQ-MCP-5047")

    async def flush(self, tools: list[dict] | None = None) -> None:
        """Report the observed catalog to the control plane. Never raises.

        Sends the whole observed catalog rather than a diff: the server-side verdict needs to see
        what is being served NOW, and a per-tool diff would lose the "this tool disappeared" signal
        that a full snapshot preserves for free.
        """
        if self._degraded or not self._pending:
            self._pending.clear()
            return
        import httpx

        payload = {
            "namespace": self._namespace,
            "server_id": self._server_id,
            "transport": self._transport,
            "mode": self._mode,
            "tools": tools if tools is not None else [
                {
                    "tool_name": r.tool_name, "digest": r.last_digest or r.digest,
                    "canonical": r.canonical, "scan_severity": r.scan_severity, "findings": [],
                }
                for r in self._pending
            ],
        }
        self._pending.clear()
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(5.0, connect=2.0)) as client:
                resp = await client.post(
                    f"{self._api_url}/api/v1/mcp/pins/observe",
                    json=payload, headers=self._headers(),
                )
                resp.raise_for_status()
        except Exception as exc:
            # A failed report is a VISIBILITY loss, not an enforcement loss: the local decision was
            # already made from the loaded state and the call path is unaffected.
            log.warning("nrvq.mcp.pins.report_failed", server=self._server_id,
                        error=str(exc), code="NRVQ-MCP-5048")
