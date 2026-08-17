# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The two MCP controls that need the customer's own server registry.

The other five read only `input.mcp.*` and are ordinary heads in the preset. These two are compiled
from a per-namespace list, so they get a generated sibling module on a reserved scope — the shape
`norviq/api/egress_allowlist.py` established.

The lesson from that precedent is the first thing this file tests: `egress_allowlist` has a complete
compiler, engine-side collection, and NO ROUTER. Its only importer is its own test, so the control has
never been reachable by a customer. A generated module that nothing regenerates is indistinguishable
from a feature that was never built, which is why `test_the_module_is_regenerated_by_the_write_path`
matters more than any of the rego assertions below it.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from norviq.api import mcp_controls

_OPA = shutil.which("opa")
opa_required = pytest.mark.skipif(_OPA is None, reason="opa binary required to evaluate the module")


def _eval(rego: str, payload: dict, query: str = "data.norviq.mcp_registry.decision") -> str:
    with tempfile.TemporaryDirectory() as td:
        module = Path(td) / "mcp.rego"
        module.write_text(rego, encoding="utf-8")
        out = subprocess.run(  # noqa: S603 — fixed argv, opa from PATH
            ["opa", "eval", "--v0-compatible", "-d", str(module), "-I", "--format", "raw", query],
            input=json.dumps(payload), capture_output=True, text=True, check=False,
        )
        return out.stdout.strip()


def _call(server: str, verb: str = "read") -> dict:
    return {
        "tool_name": "do_thing", "tool_params": {},
        "agent": {"namespace": "agents", "agent_class": "support"},
        "mcp": {"server": server, "surface": "tools/call", "direction": "call",
                "transport": "http", "pin_status": "pinned", "scan_severity": "none",
                "definition_seen": True},
        "derived": {"verb": verb},
    }


class TestEntryValidation:
    def test_a_server_id_that_could_never_match_is_REFUSED(self):
        """Not dropped. A typo'd entry that is silently discarded leaves the operator believing a
        server is registered while every call through it is flagged — and once they promote the
        control, blocked. The point of entry is the only place this is cheap to fix."""
        with pytest.raises(mcp_controls.InvalidServerId):
            mcp_controls.normalise(["http://kb.example.com/mcp"])

    def test_case_is_PRESERVED_unlike_the_egress_domains(self):
        """A domain is case-insensitive by specification; a server id is an arbitrary operator-chosen
        string the PEP reports verbatim. Folding case would make `Reporting-KB` in the console
        silently fail to match `reporting-kb` on the wire — configured, and matching nothing."""
        assert mcp_controls.normalise(["Reporting-KB"]) == ["Reporting-KB"]

    def test_entries_are_deduplicated_and_sorted(self):
        assert mcp_controls.normalise(["b", "a", "b", " a "]) == ["a", "b"]

    def test_there_is_a_size_cap(self):
        with pytest.raises(mcp_controls.InvalidServerId):
            mcp_controls.normalise([f"s{i}" for i in range(mcp_controls.MAX_SERVERS + 1)])

    def test_writable_is_intersected_with_registered(self):
        """A server that is writable but not registered is a state the API cannot produce, and
        honouring it would create a second, contradictory answer to "is this allowed at all"."""
        rego = mcp_controls.compile(["kb"], ["kb", "ghost"])
        assert '"ghost"' not in rego.split("writable_servers")[1].split("\n")[0]

    def test_the_registry_round_trips_through_the_embedded_header(self):
        """The console reads the registry back from the module, exactly as the egress view does."""
        rego = mcp_controls.compile(["kb", "orders"], ["orders"])
        assert mcp_controls.parse(rego) == {
            "registered": ["kb", "orders"], "writable": ["orders"],
            "unregistered_decision": "audit", "write_decision": "block",
        }

    def test_a_hand_edited_module_degrades_to_None_rather_than_raising(self):
        """This is called to DISPLAY what an operator configured. A truncated module should read as
        "we cannot show you the registry", not 500 the page they would use to fix it."""
        assert mcp_controls.parse("package norviq.mcp_registry") is None
        assert mcp_controls.parse(f"{mcp_controls._HEADER} not-base64\n") is None


@opa_required
class TestTheGeneratedModule:
    def test_an_EMPTY_registry_is_inert(self):
        """The default posture, and the opposite of the egress module's discovery-first choice.

        An empty egress allowlist flags destinations, which is informative and interrupts nothing. An
        empty SERVER registry would flag every MCP call on a fresh install, and the first thing an
        operator would do is switch the control off. The registry fills as servers are discovered;
        registering one is what gives this control something to say.
        """
        rego = mcp_controls.compile([], [])
        assert _eval(rego, _call("anything")) == "allow"
        assert _eval(rego, _call("anything", verb="write")) == "allow"

    def test_a_registered_server_passes(self):
        rego = mcp_controls.compile(["kb"], ["kb"])
        assert _eval(rego, _call("kb")) == "allow"

    def test_an_unregistered_server_is_flagged_once_the_registry_is_populated(self):
        rego = mcp_controls.compile(["kb"], ["kb"])
        assert _eval(rego, _call("rogue")) == "audit"
        assert _eval(rego, _call("rogue"), "data.norviq.mcp_registry.rule_id") == \
            mcp_controls.RULE_UNREGISTERED

    def test_an_unregistered_server_AUDITS_by_default_rather_than_blocking(self):
        """Registration is housekeeping that lags reality. Blocking on it would break an estate every
        time somebody stands up a new integration before telling the console."""
        assert _eval(mcp_controls.compile(["kb"], []), _call("rogue")) == "audit"

    def test_a_write_through_a_read_only_server_BLOCKS(self):
        """The opposite default, for the opposite reason: the operator has already said which servers
        may be written through, so a write anywhere else is an integration they considered and
        declined."""
        rego = mcp_controls.compile(["kb"], [])
        assert _eval(rego, _call("kb", verb="write")) == "block"
        assert _eval(rego, _call("kb", verb="write"), "data.norviq.mcp_registry.rule_id") == \
            mcp_controls.RULE_UNAPPROVED_WRITE

    def test_a_write_through_a_WRITABLE_server_passes(self):
        assert _eval(mcp_controls.compile(["kb"], ["kb"]), _call("kb", verb="write")) == "allow"

    def test_a_READ_through_a_read_only_server_passes(self):
        """The whole point of the separate axis: a read-only knowledge base is an ordinary shape."""
        assert _eval(mcp_controls.compile(["kb"], []), _call("kb", verb="read")) == "allow"

    def test_an_UNKNOWN_verb_is_not_treated_as_a_write(self):
        """The classifier saying "I cannot tell" is not evidence of a write. Treating it as one would
        refuse ordinary reads it merely failed to label — the same over-classification trap the
        preset's destructive-name control documents at length."""
        assert _eval(mcp_controls.compile(["kb"], []), _call("kb", verb="unknown")) == "allow"

    def test_a_NON_MCP_call_is_untouched(self):
        """The negative control. Every SDK, sidecar and webhook call in the estate has no `input.mcp`,
        and a module that fired on them would take an entire estate down the moment it materialized."""
        rego = mcp_controls.compile(["kb"], ["kb"])
        assert _eval(rego, {"tool_name": "x", "tool_params": {}, "derived": {"verb": "write"}}) == "allow"

    def test_the_unregistered_finding_wins_over_the_write_finding(self):
        """A server that is neither registered nor writable is ONE problem, not two. Reporting the
        write rule would send an operator to grant a write on a server they have not registered."""
        rego = mcp_controls.compile(["kb"], ["kb"])
        assert _eval(rego, _call("rogue", verb="write"), "data.norviq.mcp_registry.rule_id") == \
            mcp_controls.RULE_UNREGISTERED

    def test_the_reason_NAMES_the_server(self):
        rego = mcp_controls.compile(["kb"], ["kb"])
        assert "rogue" in _eval(rego, _call("rogue"), "data.norviq.mcp_registry.reason")

    def test_promotion_to_enforcing_is_expressible(self):
        rego = mcp_controls.compile(["kb"], ["kb"], unregistered_decision="block")
        assert _eval(rego, _call("rogue")) == "block"

    def test_a_decision_that_is_not_audit_or_block_is_refused(self):
        with pytest.raises(ValueError):
            mcp_controls.compile(["kb"], [], unregistered_decision="allow")


# ── the router: the property `egress_allowlist` does not have ─────────────────────────────────────

class _RecordingLoader:
    """Captures what the write path materializes."""

    def __init__(self) -> None:
        self.created: list[dict] = []
        self._cache = None

    async def create(self, namespace, key, rego, **kw):
        self.created.append({"namespace": namespace, "key": key, "rego": rego, **kw})


class _Row:
    def __init__(self, server_id, status, writable=False):
        self.namespace, self.server_id, self.status, self.writable = "agents", server_id, status, writable


class _Scalars:
    def __init__(self, rows): self._rows = rows
    def all(self): return self._rows
    def first(self): return self._rows[0] if self._rows else None


class _Session:
    """Minimal session: `scalars` returns the registry rows regardless of the statement."""

    def __init__(self, rows): self.rows = rows
    async def scalars(self, _stmt): return _Scalars(self.rows)


@pytest.mark.asyncio
class TestTheWritePathRegeneratesTheModule:
    """`egress_allowlist.py` is a complete compiler with engine-side collection and NO ROUTER — its
    only importer is its own test, so the control has never been reachable by a customer. That is the
    failure this class exists to make impossible for the MCP registry."""

    async def _materialize(self, rows):
        from norviq.api.routers import mcp as mcp_router

        class _Req:
            class app:  # noqa: N801 — matching Starlette's attribute shape
                class state:
                    loader = None

        loader = _RecordingLoader()
        _Req.app.state.loader = loader
        count = await mcp_router._materialize_mcp_registry(_Req(), _Session(rows), "agents")
        return loader, count

    async def test_a_decision_regenerates_the_module_on_the_reserved_scope(self):
        loader, count = await self._materialize([_Row("kb", "registered", True)])
        assert count == 1
        assert loader.created and loader.created[0]["key"] == mcp_controls.SCOPE
        assert loader.created[0]["namespace"] == "agents"

    async def test_the_generated_module_carries_the_registry_it_was_built_from(self):
        loader, _ = await self._materialize(
            [_Row("kb", "registered", True), _Row("orders", "registered", False),
             _Row("rogue", "blocked"), _Row("seen", "discovered")]
        )
        parsed = mcp_controls.parse(loader.created[0]["rego"])
        # Only REGISTERED servers are in the set. `discovered` is not an approval and `blocked` is a
        # refusal — putting either in the registered set would make the control say the opposite of
        # what the operator decided.
        assert parsed["registered"] == ["kb", "orders"]
        assert parsed["writable"] == ["kb"]

    async def test_it_is_written_in_BLOCK_mode(self):
        """The module carries each control's own decision in its generated heads, exactly as the
        baseline compiler does. Softening the whole module would make the per-control choice
        unreachable — the same collapse the controls tier documents."""
        loader, _ = await self._materialize([_Row("kb", "registered", True)])
        assert loader.created[0]["enforcement_mode"] == "block"

    async def test_a_materialize_failure_never_raises_into_the_caller(self):
        """The decision is already committed and is the durable record; the module is derived from it.
        A failure means the control is stale until the next write, not that a decision was lost."""
        from norviq.api.routers import mcp as mcp_router

        class _Boom(_RecordingLoader):
            async def create(self, *a, **kw): raise RuntimeError("loader down")

        class _Req:
            class app:
                class state:
                    loader = _Boom()

        assert await mcp_router._materialize_mcp_registry(
            _Req(), _Session([_Row("kb", "registered", True)]), "agents") == -1
