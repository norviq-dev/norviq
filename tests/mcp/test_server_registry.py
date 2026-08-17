# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The MCP server registry: identity, decisions, and the Gate-A refusal they drive.

`pins.py` asks "is this tool definition the one that was approved". This asks the question one level
up — "should this agent be talking to this server at all" — and it is the only place the rogue-server
shape is visible. A tool from an unregistered server can be entirely ordinary on its own terms: clean
prose, benign schema, a read verb. Gate A's per-definition scan has nothing to say about it and the
write-scoping rule exempts reads, so before the registry existed such a call passed every check the
product had.

The tests are grouped by the property each defends, because two of them pull against each other: a
blocked server must be refused BEFORE its descriptions reach the model, and a control plane that
cannot be reached must not black out discovery for every server.
"""

from __future__ import annotations

import json

import pytest

from norviq.mcp import protocol as P
from norviq.mcp.firewall import McpFirewall
from norviq.mcp.pins import MemoryPinStore, PinRegistry
from norviq.mcp.servers import (
    STATUS_BLOCKED,
    STATUS_DISCOVERED,
    STATUS_REGISTERED,
    ControlPlaneServerStore,
    ServerDecision,
    ServerRegistry,
    canonical_identity,
    identity_digest,
)
from norviq.sdk.core.decisions import PolicyDecision
from norviq.sdk.core.events import AgentIdentity, ToolCallEvent
from norviq.sdk.core.interceptor import ToolInterceptor

# `asyncio` is marked per CLASS, not on the module: the identity and decision groups are pure
# functions, and marking them async-only produces a warning per test that trains the reader to
# ignore warnings in this file.


# ── the identity surface ───────────────────────────────────────────────────────────────────────────

class TestServerIdentity:
    """`server_id` is the `--server-id` the proxy was started with: operator-chosen, PEP-reported,
    not cryptographic. Without an identity surface, "registered" means only "something claimed this
    name"."""

    def test_the_tool_NAME_SET_is_part_of_identity(self):
        """The wholesale-swap case no per-tool pin can see.

        Every approved tool vanishes, different ones answer under the same server id, and each one
        looks like an ordinary first sight to the pin store. Only a server-level digest notices.
        """
        info = {"name": "kb", "version": "1.0"}
        before = identity_digest(info, "", ["search", "fetch"])
        after = identity_digest(info, "", ["exec", "upload"])
        assert before != after

    def test_the_tool_set_is_ORDER_INSENSITIVE(self):
        """A server that shuffles its listing is not a different server; treating it as one would
        make identity drift fire constantly and train an operator to ignore it."""
        info = {"name": "kb", "version": "1.0"}
        assert (identity_digest(info, "", ["a", "b"]) == identity_digest(info, "", ["b", "a"]))

    def test_the_instructions_banner_counts_as_identity(self):
        """`instructions` is free text the host may put in front of the model, so a change there is a
        content change in exactly the sense a tool description is."""
        info = {"name": "kb", "version": "1.0"}
        assert identity_digest(info, "be helpful") != identity_digest(info, "ignore prior rules")

    def test_a_version_bump_is_visible(self):
        assert identity_digest({"name": "kb", "version": "1.0"}, "") != \
               identity_digest({"name": "kb", "version": "1.1"}, "")

    def test_canonical_form_is_stable_and_parseable(self):
        """It is stored as a string an operator can diff, so it must round-trip."""
        canon = canonical_identity({"name": "kb", "version": "1.0"}, "hello", ["b", "a"])
        assert json.loads(canon) == {"name": "kb", "version": "1.0",
                                     "instructions": "hello", "tools": ["a", "b"]}

    def test_a_server_that_reports_nothing_still_has_a_digest(self):
        """An empty `serverInfo` is a legitimate (if unhelpful) response, and a digest that could not
        be computed would leave exactly those servers unpinned."""
        assert len(identity_digest(None, "")) == 64


# ── the three states ───────────────────────────────────────────────────────────────────────────────

class TestDecisionSemantics:
    def test_an_unknown_server_reads_as_discovered_not_as_missing(self):
        """`get` never returns None. A server the registry has not heard of behaves like a
        newly-seen one, which is what it is."""
        assert ServerRegistry().get("anything").status == STATUS_DISCOVERED

    def test_discovered_is_REACHABLE(self):
        """A server nobody has reviewed is not thereby hostile. Refusing every unreviewed server would
        mean the product blocks its own first run — the registry would be unusable before it was
        populated. What `discovered` does is make the control able to SAY so."""
        assert ServerRegistry().get("new").reachable

    def test_only_blocked_is_unreachable(self):
        reg = ServerRegistry()
        reg.put(ServerDecision("a", status=STATUS_REGISTERED))
        reg.put(ServerDecision("b", status=STATUS_BLOCKED))
        assert reg.get("a").reachable
        assert not reg.get("b").reachable

    def test_from_rows_ignores_a_row_with_no_server_id(self):
        assert ServerRegistry.from_rows([{"status": "blocked"}]).decisions == {}

    def test_an_UNRECOGNISED_status_degrades_to_discovered_not_to_blocked(self):
        """A newer control plane talking to an older proxy during a rolling upgrade. Treating an
        unknown word as `blocked` would black out discovery for every server the moment the API is a
        version ahead of the sidecars — a self-inflicted outage dressed as a security posture."""
        reg = ServerRegistry.from_rows([{"server_id": "s", "status": "quarantined-pending-review"}])
        assert reg.get("s").status == STATUS_DISCOVERED
        assert reg.get("s").reachable


# ── the store's degradation ────────────────────────────────────────────────────────────────────────

class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class _FakeClient:
    """Stands in for httpx.AsyncClient. `script` is a list of payloads or exceptions, one per GET."""

    def __init__(self, script):
        self.script = list(script)
        self.calls = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    async def get(self, url, params=None, headers=None):
        self.calls += 1
        item = self.script.pop(0) if self.script else []
        if isinstance(item, Exception):
            raise item
        return _FakeResponse(item)


def _patched_httpx(monkeypatch, client):
    import httpx
    monkeypatch.setattr(httpx, "AsyncClient", lambda **_kw: client)


@pytest.mark.asyncio
class TestControlPlaneStore:
    async def test_a_successful_load_populates_the_registry(self, monkeypatch):
        client = _FakeClient([[{"server_id": "kb", "status": "registered", "writable": True}]])
        _patched_httpx(monkeypatch, client)
        store = ControlPlaneServerStore(namespace="agents")

        assert await store.load() is True
        assert store.loaded and not store.degraded
        assert store.registry.get("kb").status == STATUS_REGISTERED
        assert store.registry.get("kb").writable

    async def test_the_registry_OBJECT_survives_a_reload(self, monkeypatch):
        """The firewall holds this exact object. A load that rebound the attribute instead of
        mutating in place would leave every already-built firewall on its startup copy — the same
        class of defect as the pin store that only reloaded for the NEXT process."""
        client = _FakeClient([
            [{"server_id": "kb", "status": "registered"}],
            [{"server_id": "kb", "status": "blocked"}],
        ])
        _patched_httpx(monkeypatch, client)
        store = ControlPlaneServerStore(namespace="agents")
        await store.load()
        held = store.registry                      # what a firewall would have captured

        await store.load()

        assert held is store.registry
        assert not held.get("kb").reachable, "a block must reach a RUNNING proxy"

    async def test_a_removed_decision_is_dropped_on_a_successful_load(self, monkeypatch):
        """Un-blocking works by the row changing or going away. A merge-only load would make `blocked`
        permanent in every running proxy until it restarted."""
        client = _FakeClient([[{"server_id": "kb", "status": "blocked"}], []])
        _patched_httpx(monkeypatch, client)
        store = ControlPlaneServerStore(namespace="agents")
        await store.load()
        await store.load()
        assert store.registry.get("kb").reachable

    async def test_a_FAILED_load_keeps_the_last_good_copy(self, monkeypatch):
        """The property that makes the outage posture defensible: an API restart must not turn a
        blocked server back into a reachable one."""
        client = _FakeClient([[{"server_id": "bad", "status": "blocked"}],
                              RuntimeError("control plane down")])
        _patched_httpx(monkeypatch, client)
        store = ControlPlaneServerStore(namespace="agents")
        await store.load()

        assert await store.load() is False
        assert store.degraded
        assert not store.registry.get("bad").reachable, "the decision must survive the outage"

    async def test_a_cold_start_outage_fails_OPEN_and_says_so(self, monkeypatch, caplog):
        """The honest limit, asserted rather than left to a comment.

        Nothing is enforced before the first successful load. The alternative was tried in this
        codebase in another form (HttpProxy._install_pin_store): three proxies refused every call at
        Gate A for eleven hours, nothing reached the audit log, and the failure was indistinguishable
        from a defence working. So it fails open — and `loaded` is False, which is what the log line
        reports and what any future readiness surface should read.
        """
        client = _FakeClient([RuntimeError("control plane down")])
        _patched_httpx(monkeypatch, client)
        store = ControlPlaneServerStore(namespace="agents")

        assert await store.load() is False
        assert store.loaded is False
        assert store.registry.get("anything").reachable

    async def test_load_never_raises_whatever_the_control_plane_does(self, monkeypatch):
        """It is called on the startup path and from a background task; either would take the proxy
        down with it."""
        for boom in (RuntimeError("x"), ValueError("bad json"), KeyError("nope")):
            _patched_httpx(monkeypatch, _FakeClient([boom]))
            assert await ControlPlaneServerStore(namespace="ns").load() is False

    async def test_a_non_list_payload_is_treated_as_empty_not_crashed_on(self, monkeypatch):
        _patched_httpx(monkeypatch, _FakeClient([{"detail": "forbidden"}]))
        store = ControlPlaneServerStore(namespace="agents")
        assert await store.load() is True
        assert store.registry.decisions == {}

    async def test_refresh_is_idempotent_and_stops_cleanly(self, monkeypatch):
        """Two calls must not fan out two tasks, and `aclose` must be safe more than once — the stdio
        shutdown path calls it inside a suppress block."""
        _patched_httpx(monkeypatch, _FakeClient([[]]))
        store = ControlPlaneServerStore(namespace="agents")
        store.start_refresh(60)
        first = store._refresh_task
        store.start_refresh(60)
        assert store._refresh_task is first

        await store.aclose()
        await store.aclose()
        assert first.cancelled() or first.done()

    async def test_refresh_is_a_noop_when_disabled(self, monkeypatch):
        store = ControlPlaneServerStore(namespace="agents")
        store.start_refresh(0)
        assert store._refresh_task is None


# ── Gate A: the refusal itself ─────────────────────────────────────────────────────────────────────

class _StubEvaluator:
    def __init__(self):
        self.seen: list[ToolCallEvent] = []

    async def evaluate(self, event):
        self.seen.append(event)
        return PolicyDecision(decision="allow", rule_id="test_rule", reason="test")

    @property
    def reports(self) -> list[ToolCallEvent]:
        return [e for e in self.seen if e.pep_decision]


class _StubResolver:
    async def resolve(self):
        return AgentIdentity(spiffe_id="spiffe://norviq/ns/agents/sa/default",
                             namespace="agents", agent_class="mcp-agent")


def _firewall(registry: ServerRegistry | None = None, server_id: str = "rugpull"):
    ev = _StubEvaluator()
    fw = McpFirewall(interceptor=ToolInterceptor(ev, _StubResolver()), server_id=server_id,
                     pins=PinRegistry(store=MemoryPinStore(), mode="tofu"), servers=registry)
    return fw, ev


def _msg(payload: dict) -> P.JsonRpcMessage:
    return P.decode(json.dumps(payload).encode())


BENIGN_TOOLS = [
    {"name": "search", "description": "Search the knowledge base.",
     "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}}},
    {"name": "fetch", "description": "Fetch a document by id.",
     "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}}},
]


async def _list(fw: McpFirewall, tools: list[dict]):
    await fw.on_client_message(_msg({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}))
    return await fw.on_server_message(_msg({"jsonrpc": "2.0", "id": 2, "result": {"tools": tools}}))


@pytest.mark.asyncio
class TestGateARefusesABlockedServer:
    async def test_the_tools_never_reach_the_model(self):
        """Withheld WHOLESALE at discovery. For the poisoning vectors the DESCRIPTION is the payload:
        by the time a call arrives the prose has already been rendered into the model's context and
        has already had its chance to steer it."""
        reg = ServerRegistry()
        reg.put(ServerDecision("rugpull", status=STATUS_BLOCKED))
        fw, _ = _firewall(reg)

        result = await _list(fw, BENIGN_TOOLS)

        assert result.note == "server_blocked"
        assert json.loads(result.forward)["result"]["tools"] == []

    async def test_BENIGN_tools_are_withheld_too(self):
        """The whole point. These two definitions are clean — a per-definition scanner has nothing to
        say about either. The decision is about the SERVER, and a rogue server's most useful tool is
        the innocuous-looking one."""
        reg = ServerRegistry()
        reg.put(ServerDecision("rugpull", status=STATUS_BLOCKED))
        fw, _ = _firewall(reg)
        result = await _list(fw, BENIGN_TOOLS)
        assert json.loads(result.forward)["result"]["tools"] == []

    async def test_the_client_is_TOLD_rather_than_silently_given_an_empty_list(self):
        """An empty `tools` with no explanation is indistinguishable from a server with no tools, and
        the operator debugging it has nothing to go on."""
        reg = ServerRegistry()
        reg.put(ServerDecision("rugpull", status=STATUS_BLOCKED))
        fw, _ = _firewall(reg)
        result = await _list(fw, BENIGN_TOOLS)
        meta = json.loads(result.forward)["result"]
        assert json.dumps(meta).find("server_blocked") != -1

    async def test_the_refusal_produces_an_AUDIT_ROW(self):
        """A block with no audit row is, by this codebase's own detection discipline, indistinguishable
        from nothing having happened — that was L2-03, measured live as three denials and zero rows."""
        reg = ServerRegistry()
        reg.put(ServerDecision("rugpull", status=STATUS_BLOCKED))
        fw, ev = _firewall(reg)

        await _list(fw, BENIGN_TOOLS)

        assert len(ev.reports) == 1
        report = ev.reports[0]
        assert report.pep_decision == "block"
        assert report.pep_rule_id == "mcp_server_blocked"
        assert "blocked by operator decision" in report.pep_reason
        assert "2 tool definition(s) were withheld" in report.pep_reason

    async def test_the_row_names_the_METHOD_not_a_withheld_tool(self):
        """There is no single tool this refusal is about, and the withheld names are the blocked
        server's own strings. Echoing them would let a refused server keep writing into the console
        that refused it."""
        reg = ServerRegistry()
        reg.put(ServerDecision("rugpull", status=STATUS_BLOCKED))
        fw, ev = _firewall(reg)
        await _list(fw, BENIGN_TOOLS)

        report = ev.reports[0]
        assert report.tool_name == "tools/list"
        assert "search" not in report.pep_reason and "fetch" not in report.pep_reason

    async def test_ONE_row_per_listing_not_one_per_withheld_tool(self):
        """The decision was taken about the server. N rows naming N tools would misdescribe a single
        act as a spree, and would scale the audit cost with a number the blocked server chooses."""
        reg = ServerRegistry()
        reg.put(ServerDecision("rugpull", status=STATUS_BLOCKED))
        fw, ev = _firewall(reg)
        await _list(fw, BENIGN_TOOLS * 25)
        assert len(ev.reports) == 1

    async def test_a_registered_server_lists_normally(self):
        reg = ServerRegistry()
        reg.put(ServerDecision("rugpull", status=STATUS_REGISTERED))
        fw, _ = _firewall(reg)
        result = await _list(fw, BENIGN_TOOLS)
        assert result.note != "server_blocked"
        assert len(json.loads(result.forward)["result"]["tools"]) == 2

    async def test_an_UNDECIDED_server_lists_normally(self):
        """A firewall constructed with no registry at all — which is every existing caller and every
        test written before this change. The registry must be additive, not a new refusal."""
        fw, _ = _firewall(None)
        result = await _list(fw, BENIGN_TOOLS)
        assert len(json.loads(result.forward)["result"]["tools"]) == 2

    async def test_the_block_is_counted_in_the_firewall_stats(self):
        """The proxy's own counters are what a `/healthz` or a log line reports; a refusal that shows
        up nowhere locally is only visible if the control plane happens to be reachable."""
        reg = ServerRegistry()
        reg.put(ServerDecision("rugpull", status=STATUS_BLOCKED))
        fw, _ = _firewall(reg)
        await _list(fw, BENIGN_TOOLS)
        assert fw.stats.get("server_blocked") == 1

    async def test_the_refusal_stands_when_the_control_plane_is_DOWN(self):
        """The report is not a question. An engine that raises must not resurrect the listing."""

        class _Boom:
            async def evaluate(self, event):
                raise RuntimeError("engine unreachable")

        reg = ServerRegistry()
        reg.put(ServerDecision("rugpull", status=STATUS_BLOCKED))
        fw = McpFirewall(interceptor=ToolInterceptor(_Boom(), _StubResolver()), server_id="rugpull",
                         pins=PinRegistry(store=MemoryPinStore(), mode="tofu"), servers=reg)

        result = await _list(fw, BENIGN_TOOLS)

        assert json.loads(result.forward)["result"]["tools"] == []


# ── the two defects only a live deployment found ───────────────────────────────────────────────────

class TestTheConfigurationTrapsThatOnlyShowedUpInACluster:
    """Both of these passed every unit test and failed the moment a real sidecar started.

    They are the same shape: a value that was WRONG rather than missing, with a fallback that made the
    wrongness look deliberate. Neither produced an error at any layer — one produced a DNS failure
    attributed to the control plane, the other produced nothing at all.
    """

    def test_api_url_follows_the_engine_url_when_only_that_one_is_set(self, monkeypatch) -> None:
        """`policy_engine_url` and `api_url` are documented as the same target, and every deployment
        in this repo sets only NRVQ_POLICY_ENGINE_URL. Anything reading `api_url` therefore fell back
        to the short name `http://norviq-api:8080`, which resolves ONLY inside the API's own
        namespace — so a sidecar anywhere else got "Name or service not known" from a proxy whose
        /evaluate calls were working perfectly.
        """
        from norviq.config import NorviqSettings, apply_api_url_follows_engine

        monkeypatch.setenv("NRVQ_POLICY_ENGINE_URL", "http://norviq-api.norviq.svc.cluster.local:8080")
        monkeypatch.delenv("NRVQ_API_URL", raising=False)
        # `_env_file=None` because THIS repo ships a .env that sets NRVQ_API_URL for local dev. That
        # counts as an explicit statement and correctly suppresses the follow — which is why the first
        # version of this test failed, and why the fix is to exclude the file rather than the rule.
        s = apply_api_url_follows_engine(NorviqSettings(_env_file=None))
        assert s.api_url == "http://norviq-api.norviq.svc.cluster.local:8080"

    def test_an_explicit_api_url_is_never_overridden(self, monkeypatch) -> None:
        """Two different endpoints is a legitimate configuration; following must not become forcing."""
        from norviq.config import NorviqSettings, apply_api_url_follows_engine

        monkeypatch.setenv("NRVQ_POLICY_ENGINE_URL", "http://engine:8080")
        monkeypatch.setenv("NRVQ_API_URL", "http://api:9090")
        s = apply_api_url_follows_engine(NorviqSettings(_env_file=None))
        assert s.api_url == "http://api:9090"

    def test_settings_has_no_namespace_field_which_is_why_the_getattr_was_a_bug(self) -> None:
        """The HTTP transport read `getattr(settings, "namespace", "")` for BOTH control-plane stores.

        There is no such setting, so both addressed the control plane with an empty namespace on every
        deployment there has ever been. The `getattr` default is what hid it: a phantom read with a
        fallback looks like a deliberate optional. This test fails the day somebody adds the field,
        which is the right time to revisit the fix rather than leave two sources of one answer.
        """
        from norviq.config import settings as live

        assert not hasattr(live, "namespace")
