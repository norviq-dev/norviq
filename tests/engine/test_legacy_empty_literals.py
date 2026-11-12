# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Policies an older release stored keep deciding after the OPA 1.21 upgrade.

Every release up to 0.2.5 stored generated policies holding a bare `{}`, `set()`, `[]` or `[][_]`
wherever an operator list was empty — an allowlist with no tools, an MCP namespace with no writable
server, a builder graph using one decision set (norviq/engine/empty_literals.py has the measurements).
OPA 1.21 refuses to compile them, and a module that does not compile blocks every call it governs as
`evaluator_error`. Those rows are still in Postgres after the upgrade, so the evaluator rewrites exactly
the lines those generators wrote, on the way into OPA, and nowhere else.

tests/fixtures/legacy_empty_literals.json holds the modules exactly as 0.2.5 wrote them. Each is
stored in a real Postgres the way 0.2.5 stored it, loaded through every path that hands a stored policy
to the evaluator — startup warm, lazy load, a peer replica's upsert event, the embedded engine's reload,
a signed fleet bundle (for the class-scoped modules: a bundle never applies a reserved scope such as
`__mcp__` or `__egress__`), and the subprocess (`opa eval`) rollback mode — and judged by the DECISION
the engine returns. The expected decisions are 0.2.5's on OPA 1.19.1 for the ORIGINAL text: this file
passes with the rewrite disabled and 1.19.1 on PATH, and with the rewrite disabled and 1.21.4 on PATH
every one of those decisions is `evaluator_error`.

Needs NRVQ_PG_URL and NRVQ_REDIS_URL (real Postgres and Redis), and `opa` on PATH.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

import pytest
from sqlalchemy import text
from structlog.testing import capture_logs

from norviq.api.db.session import close_db, create_tables, init_db
from norviq.config import settings
from norviq.engine.cache import RedisCache
from norviq.engine.empty_literals import LEGACY_SHAPES, upgrade_legacy
from norviq.engine.evaluator import OPAEvaluator
from norviq.engine.policy_loader import PolicyLoader
from norviq.fleet.bundle import RESERVED_SCOPES, sign_bundle
from norviq.sdk.core.events import AgentIdentity, ToolCallEvent
from norviq.sidecar.proxy import SidecarProxy
from tests.engine.test_priority_enforcement import FakeCache, _healthy_trust
from tests.fleet.test_fleet_puller import _bundle, _FakeHub, _gen_rsa_pem, _puller

REPO = Path(__file__).resolve().parents[2]
_FIXTURE_DOC = json.loads((REPO / "tests" / "fixtures" / "legacy_empty_literals.json").read_text(encoding="utf-8"))
LEGACY: dict[str, dict] = _FIXTURE_DOC["modules"]
CAPABILITIES = REPO / "norviq" / "engine" / "opa-capabilities.json"
needs_opa = pytest.mark.skipif(shutil.which("opa") is None, reason="opa binary required")

_CLS = "report-gen"

# The shapes `upgrade_legacy` must find in each stored module — no more, no fewer.
EXPECTED_SHAPES: dict[str, tuple[str, ...]] = {
    "builder_rules_block_only": ("builder_unused_decision_set",),
    "builder_allowlist_empty": ("intent_allowlist_empty",),
    "composer_no_keywords": ("composer_keywords_empty",),
    "intent_allowlist_empty": ("intent_allowlist_empty",),
    "capability_no_tools": ("capability_tools_empty",),
    "intent_compiled_in_empty": ("intent_compiler_in_empty",),
    "mcp_registry_no_writable": ("mcp_registry_empty",),
    "mcp_registry_empty": ("mcp_registry_empty",),
    "egress_exact_only": ("egress_suffix_empty",),
    "egress_suffix_only": ("egress_exact_empty",),
    "egress_empty": ("egress_exact_empty", "egress_suffix_empty"),
}

# A class policy for the overlay scenarios: `__mcp__` and `__egress__` are floors over the class's own
# decision, so the namespace needs one. It allows everything and is not legacy-shaped.
_BASE = (
    "package norviq.custom.report_gen\n"
    'default decision = "allow"\ndefault rule_id = "base_allow"\ndefault reason = "base policy"\n'
    'decision = "block" { input.tool_name == "never_called" }\n'
)


def _call(tool: str, params: dict | None = None, mcp: dict | None = None) -> dict:
    return {"tool": tool, "params": params or {}, "mcp": mcp or {}}


# scenario -> (scope the module is stored under, calls and the (decision, rule_id) each must get).
SCENARIOS: dict[str, tuple[str, list[tuple[dict, tuple[str, str]]]]] = {
    "builder_rules_block_only": (
        _CLS,
        [
            (_call("drop_table"), ("block", "r_drop")),
            (_call("get_report"), ("allow", "builder_default_report_gen")),
        ],
    ),
    "builder_allowlist_empty": (
        _CLS,
        [
            (_call("get_report"), ("block", "intent_default_deny")),
        ],
    ),
    "composer_no_keywords": (
        _CLS,
        [
            (_call("get_report", {"q": "the secret token"}), ("allow", "composer_allow_report_gen")),
        ],
    ),
    "intent_allowlist_empty": (
        _CLS,
        [
            (_call("get_report"), ("block", "intent_default_deny")),
        ],
    ),
    "capability_no_tools": (
        _CLS,
        [
            (_call("delete_record"), ("block", "capability:postgresql:delete+write")),
            (_call("get_report"), ("allow", "capability_noop")),
        ],
    ),
    "intent_compiled_in_empty": (
        _CLS,
        [
            (_call("search_kb"), ("allow", "r-search")),
            (_call("delete_record"), ("block", "intent_no_match")),
        ],
    ),
    "mcp_registry_no_writable": (
        "__mcp__",
        [
            (_call("read_document", mcp={"server": "kb"}), ("allow", "base_allow")),
            (_call("update_document", mcp={"server": "kb"}), ("block", "mcp_unapproved_write_server")),
            (_call("read_document", mcp={"server": "unknown-srv"}), ("audit", "mcp_unregistered_server")),
        ],
    ),
    "mcp_registry_empty": (
        "__mcp__",
        [
            (_call("update_document", mcp={"server": "unknown-srv"}), ("allow", "base_allow")),
        ],
    ),
    "egress_exact_only": (
        "__egress__",
        [
            (_call("send_email", {"to": "bob@acme.com", "body": "hi"}), ("allow", "base_allow")),
            (_call("send_email", {"to": "x@evil.example", "body": "hi"}), ("block", "customer_data_egress")),
        ],
    ),
    "egress_suffix_only": (
        "__egress__",
        [
            (_call("send_email", {"to": "ann@mail.acme.com", "body": "hi"}), ("allow", "base_allow")),
            (_call("send_email", {"to": "x@evil.example", "body": "hi"}), ("block", "customer_data_egress")),
        ],
    ),
    "egress_empty": (
        "__egress__",
        [
            (_call("send_email", {"to": "bob@acme.com", "body": "hi"}), ("audit", "customer_data_egress")),
        ],
    ),
}

PATHS = ("warm_cache", "lazy_load_from_db", "peer_upsert_event", "embedded_reload", "fleet_bundle", "subprocess_mode")

# A fleet bundle never applies a reserved scope (fleet_puller skips `__egress__`, `__mcp__` and the other
# RESERVED_SCOPES: a hub must not replace a cluster's own baseline or registry), so a legacy MCP or egress
# module cannot arrive that way and those combinations are not a load path at all.
DECISION_CASES = [
    (name, path)
    for name in sorted(SCENARIOS)
    for path in PATHS
    if not (path == "fleet_bundle" and SCENARIOS[name][0] in RESERVED_SCOPES)
]


class _OldReleaseEvaluator:
    """The replica that wrote the rows. Its evaluator is irrelevant; only what reaches Postgres matters."""

    def bind_loader(self, loader: object) -> None:
        return None

    def load_policy(self, *_a, **_k) -> None:
        return None

    def reload_policy(self, *_a, **_k) -> None:
        return None


@pytest.fixture
async def redis_cache() -> RedisCache:
    url = os.getenv("NRVQ_REDIS_URL")
    if not url:
        pytest.fail("NRVQ_REDIS_URL must be set: these tests load policies through the real Redis-backed loader")
    cache = RedisCache(url=url)
    await cache.connect()
    yield cache
    await cache.close()


@pytest.fixture
async def _schema() -> None:
    pg_url = (os.getenv("NRVQ_PG_URL") or "").strip().strip("\"'")
    if not pg_url:
        pytest.fail("NRVQ_PG_URL must be set: the point is rows stored in a real Postgres")
    old_url = settings.pg_url
    settings.pg_url = pg_url
    await init_db()
    await create_tables()
    try:
        yield
    finally:
        await close_db()
        settings.pg_url = old_url


@pytest.fixture
async def cluster(redis_cache: RedisCache, _schema: None, tmp_path):
    """A namespace of its own, the 0.2.5 replica that stored the rows, and a fresh 0.2.6 engine."""
    namespace = f"legacy-{uuid.uuid4().hex[:12]}"
    old_release = PolicyLoader(redis_cache, _OldReleaseEvaluator())  # type: ignore[arg-type]
    engine_eval = OPAEvaluator(FakeCache())  # type: ignore[arg-type]
    _healthy_trust(engine_eval)
    engine = PolicyLoader(redis_cache, engine_eval)
    proxy = SidecarProxy(socket_path=str(tmp_path / "nrvq.sock"))
    proxy._evaluator = engine_eval
    try:
        yield {
            "ns": namespace,
            "old_release": old_release,
            "engine": engine,
            "engine_eval": engine_eval,
            "proxy": proxy,
            "cache": redis_cache,
        }
    finally:
        try:
            async with old_release._db_engine().begin() as conn:
                await conn.execute(
                    text(
                        "DELETE FROM policy_versions WHERE policy_id IN (SELECT id FROM policies WHERE namespace = :ns)"
                    ),
                    {"ns": namespace},
                )
                await conn.execute(text("DELETE FROM policies WHERE namespace = :ns"), {"ns": namespace})
        finally:
            for scope in (_CLS, "__mcp__", "__egress__"):
                await redis_cache.delete_policy(namespace, scope)
            await engine_eval.close()
            await engine.close()
            await old_release.close()


def _rows(name: str) -> list[tuple[str, str]]:
    scope, _calls = SCENARIOS[name]
    rows = [(scope, LEGACY[name]["rego"])]
    if scope != _CLS:
        rows.append((_CLS, _BASE))
    return rows


async def _store_and_load(cluster, name: str, path: str, monkeypatch) -> None:
    ns, engine = cluster["ns"], cluster["engine"]
    rows = _rows(name)
    if path == "fleet_bundle":
        # The spoke's real puller, verifying a real signed bundle, applying through the real loader.
        priv = _gen_rsa_pem()
        policies = [
            {
                "namespace": ns,
                "agent_class": scope,
                "rego_source": rego,
                "priority": 100,
                "enforcement_mode": "block",
                "version": 1,
            }
            for scope, rego in rows
        ]
        hub = _FakeHub(sign_bundle(_bundle(7, policies=policies), priv))
        out = await _puller(priv, hub, engine, monkeypatch=monkeypatch).pull_once()
        assert out == {"applied": True, "version": 7}, out
        return
    for scope, rego in rows:
        await cluster["old_release"].create(
            ns, scope, rego, saved_by="norviq-0.2.5", priority=100, enforcement_mode="block"
        )
    if path in ("warm_cache", "subprocess_mode"):
        await engine.warm_cache()
    elif path == "peer_upsert_event":
        for scope, _rego in rows:
            await engine.apply_remote_event("upsert", ns, scope)
    elif path == "embedded_reload":
        for scope, _rego in rows:
            await cluster["proxy"]._on_policy_invalidated(f"{ns}:{scope}")
    # lazy_load_from_db: nothing — the evaluator's candidate collection reads the row on first use.


async def _decide(cluster, call: dict) -> tuple[str, str]:
    event = ToolCallEvent(
        event_id=f"evt-{uuid.uuid4().hex[:8]}",
        tool_name=call["tool"],
        tool_params=call["params"],
        agent_identity=AgentIdentity(
            spiffe_id=f"spiffe://norviq/ns/{cluster['ns']}/sa/{_CLS}",
            namespace=cluster["ns"],
            agent_class=_CLS,
        ),
        session_id=f"sess-{uuid.uuid4().hex[:8]}",
        mcp=call["mcp"],
    )
    decision = await cluster["engine_eval"].evaluate(event)
    return decision.decision, decision.rule_id


@needs_opa
@pytest.mark.parametrize(("name", "path"), DECISION_CASES)
async def test_a_policy_stored_by_0_2_5_decides_as_it_did(cluster, name: str, path: str, monkeypatch) -> None:
    if path == "subprocess_mode":
        monkeypatch.setattr(settings, "opa_mode", "subprocess")
    await _store_and_load(cluster, name, path, monkeypatch)
    got = [(call, await _decide(cluster, call)) for call, _want in SCENARIOS[name][1]]
    want = [(call, expected) for call, expected in SCENARIOS[name][1]]
    assert got == want, (
        f"{name} via {path}: a policy 0.2.5 stored no longer decides as it did on OPA 1.19.1. An "
        f"`evaluator_error` here means the stored module did not compile on this opa."
    )


@needs_opa
@pytest.mark.parametrize("opa_mode", ["server", "subprocess"])
async def test_each_rewritten_module_is_reported_once_with_its_shapes(cluster, opa_mode: str, monkeypatch) -> None:
    """NRVQ-ENG-2070 names the policy and what was rewritten, once per module, however often it runs."""
    monkeypatch.setattr(settings, "opa_mode", opa_mode)
    name = "mcp_registry_no_writable"
    await _store_and_load(cluster, name, "warm_cache", monkeypatch)
    with capture_logs() as logs:
        for _ in range(3):
            for call, _want in SCENARIOS[name][1]:
                await _decide(cluster, call)
    upgraded = [entry for entry in logs if entry["event"] == "nrvq.opa.legacy_literals_upgraded"]
    assert [(e["key"], e["shapes"], e["code"], e["log_level"]) for e in upgraded] == [
        (f"{cluster['ns']}:__mcp__", list(EXPECTED_SHAPES[name]), "NRVQ-ENG-2070", "info"),
    ], upgraded
    assert not [entry for entry in logs if entry["event"] == "nrvq.opa.module_rejected"]
    # The stored row and the loader's copy (what the policies API serves) are the 0.2.5 text, untouched.
    assert cluster["engine"].get_current(cluster["ns"], "__mcp__") == LEGACY[name]["rego"]
    async with cluster["old_release"]._db_engine().begin() as conn:
        stored = (
            await conn.execute(
                text("SELECT rego_source FROM policies WHERE namespace = :ns AND agent_class = '__mcp__'"),
                {"ns": cluster["ns"]},
            )
        ).scalar_one()
    assert stored == LEGACY[name]["rego"]


@needs_opa
@pytest.mark.parametrize("opa_mode", ["server", "subprocess"])
async def test_a_module_that_still_does_not_compile_names_itself(cluster, opa_mode: str, monkeypatch) -> None:
    """Not a generated shape, so nothing rewrites it. The call still fails closed, and the log says which
    policy and what OPA said — once — instead of leaving only `evaluator_error` behind."""
    monkeypatch.setattr(settings, "opa_mode", opa_mode)
    ns = cluster["ns"]
    broken = (
        "package norviq.custom.report_gen\n"
        'default decision = "allow"\ndefault rule_id = "hand_allow"\ndefault reason = "hand-written"\n'
        'decision = "block" { never_defined_anywhere }\n'
    )
    await cluster["old_release"].create(ns, _CLS, broken, saved_by="operator", priority=100, enforcement_mode="block")
    await cluster["engine"].warm_cache()
    with capture_logs() as logs:
        first = await _decide(cluster, _call("get_report"))
        second = await _decide(cluster, _call("get_report"))
    assert first == second == ("block", "evaluator_error")
    rejected = [entry for entry in logs if entry["event"] == "nrvq.opa.module_rejected"]
    assert len(rejected) == 1, rejected
    assert rejected[0]["key"] == f"{ns}:{_CLS}"
    assert rejected[0]["code"] == "NRVQ-ENG-2071" and rejected[0]["log_level"] == "error"
    assert "rego_unsafe_var_error" in rejected[0]["error"], rejected[0]["error"]


# --- The rewrite itself, no database ----------------------------------------------------------------


def test_every_fixture_names_a_module_the_rewrite_knows() -> None:
    assert set(LEGACY) == set(EXPECTED_SHAPES) == set(SCENARIOS)
    assert {s for shapes in EXPECTED_SHAPES.values() for s in shapes} == {s.name for s in LEGACY_SHAPES}


@pytest.mark.parametrize("name", sorted(LEGACY))
def test_the_rewrite_touches_exactly_the_generated_lines(name: str) -> None:
    stored = LEGACY[name]["rego"]
    upgraded, shapes = upgrade_legacy(stored)
    assert shapes == EXPECTED_SHAPES[name]
    before, after = stored.splitlines(), upgraded.splitlines()
    assert len(before) == len(after), "the rewrite must preserve line numbers (OPA errors cite them)"
    changed = [(old, new) for old, new in zip(before, after) if old != new]
    assert changed, "nothing was rewritten"
    bare = re.compile(r"\{\}|\[\]|set\(\)")
    for old, new in changed:
        assert bare.search(old) and not re.search(r"(?::=|=)\s*(?:\{\}|\[\]|set\(\))\s*$|\[\]\[_\]|set\(\)", new), (
            old,
            new,
        )
    assert upgrade_legacy(upgraded) == (upgraded, ()), "the rewrite must be idempotent"


@needs_opa
@pytest.mark.parametrize("name", sorted(LEGACY))
def test_a_rewritten_module_passes_the_engines_pre_push_gate(name: str) -> None:
    upgraded, _shapes = upgrade_legacy(LEGACY[name]["rego"])
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "policy.rego"
        path.write_text(upgraded, encoding="utf-8")
        proc = subprocess.run(
            ["opa", "check", "--v0-compatible", f"--capabilities={CAPABILITIES}", str(path)],
            capture_output=True,
            text=True,
        )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def _regenerate(name: str) -> str | None:
    """Today's generator on the fixture's own inputs, for the modules a Python generator wrote."""
    from norviq.api import egress_allowlist, mcp_controls
    from norviq.api.threat_intent import Intent, generate_capability_rego, generate_intent_rego
    from norviq.engine.capability import Verb, defense_meta, verb_fragments
    from norviq.engine.intent.compiler import compile_intent

    inputs = LEGACY[name]["inputs"]
    if name == "intent_allowlist_empty":
        return generate_intent_rego(inputs["agent_class"], inputs["allow_tools"], Intent(**inputs["intent"]))
    if name == "capability_no_tools":
        verbs = [Verb(v) for v in inputs["verbs"]]
        meta = defense_meta(inputs["source_type"], verbs)
        return generate_capability_rego(
            inputs["source_type"],
            inputs["source_display"],
            inputs["agent_class"],
            meta["verbs"],
            inputs["tool_names"],
            meta["rule_id"],
            meta["reason"],
            verb_frags=verb_fragments(inputs["source_type"], verbs),
        )
    if name == "intent_compiled_in_empty":
        return compile_intent(inputs["intent"]).rego
    if name.startswith("mcp_"):
        return mcp_controls.compile(inputs["registered"], inputs["writable"])
    if name.startswith("egress_"):
        return egress_allowlist.compile(inputs["domains"], decision=inputs["decision"])
    return None  # written by the console (TypeScript); its current output is pinned in vitest


def _policy_lines(rego: str) -> list[str]:
    """Every line OPA reads, and every comment a program reads (the `# nrvq...` markers and manifests).

    Leaves out only the prose comments. Those are explanation for a human, and a generator's explanation
    can be corrected between releases: 0.2.8 stopped `generate_intent_rego` calling an allowlist
    "TIGHTEN-ONLY", which it is not against a namespace-tier policy. A byte comparison would pin the
    released prose, so that correction could only land by editing the released module in the fixture.
    """
    return [line for line in rego.splitlines() if not line.startswith("#") or line.startswith("# nrvq")]


@pytest.mark.parametrize("name", sorted(n for n in LEGACY if _regenerate(n) is not None))
def test_a_rewritten_module_is_what_the_generator_writes_today(name: str) -> None:
    """The strongest form of "same policy": line-identical to a fresh generation from the same inputs,
    in every line OPA or a program reads."""
    assert _policy_lines(upgrade_legacy(LEGACY[name]["rego"])[0]) == _policy_lines(_regenerate(name))


@pytest.mark.parametrize(
    "rego",
    [
        # Hand-written: the exact line, but no generator's header or package.
        "package norviq.custom.mine\nallow_names := {}\nescalates[id] { id := [][_] }\n",
        "package norviq.custom.mine\nregistered_servers = {}\nallowed_suffix = []\ncomposer_keywords := set()\n",
        # The generator's header, but a line an operator has edited.
        "package norviq.intent.x\nallow_names := {}  # none yet\n",
        "package norviq.intent.x\nallow_names :=  {}\n",
        "package norviq.custom.x\n# nrvq-builder-graph/v1: e30=\nescalates[x] { x := [][_] }\n",
        "# nrvq-mcp-registry/v1: e30=\npackage norviq.mcp_registry\nwritable_servers := {}\n",
    ],
)
def test_operator_written_rego_is_left_alone(rego: str) -> None:
    assert upgrade_legacy(rego) == (rego, ())


# --- A raw string is data, never a declaration ------------------------------------------------------
#
# The review's three repros, verbatim. Each carries a generator's header or package line and a backtick
# raw string holding an exact legacy line, and decides on the string's content. Rewriting inside the
# string evaluated every one LOOSER than its own text: ('allow', 'loosened') where OPA, on either
# binary, says block. The rewrite must leave them byte-identical, so they decide what their text says.

_RAW_INPUT = {
    "tool_name": "export_all",
    "tool_name_normalized": "export_all",
    "agent": {"agent_class": "support", "namespace": "ns"},
}

RAW_STRING_REPROS: dict[str, tuple[str, tuple[str, str]]] = {
    "intent package, allow_names line in a raw string": (
        """package norviq.intent.support

default decision = "block"
default rule_id = "intent_default_deny"
default reason = "deny"

sentinel := `
allow_names := {}
`
decision = "allow" { sentinel != "\\nallow_names := {}\\n" }
rule_id = "loosened" { sentinel != "\\nallow_names := {}\\n" }
""",
        ("block", "intent_default_deny"),
    ),
    "egress header, allowed_suffix line in a raw string": (
        """# nrvq-egress-allowlist/v1: e30=
package norviq.egress

default decision = "block"
default rule_id = "egress_deny"
default reason = "deny"

doc := `
allowed_suffix = []
`
decision = "allow" { count(doc) != 21 }
rule_id = "loosened" { count(doc) != 21 }
""",
        ("block", "egress_deny"),
    ),
    "builder header, stub line in a raw string": (
        """package norviq.custom.support

# nrvq-builder-graph/v1: e30=
# nrvq-builder-hash: 00000000

default decision = "block"
default rule_id = "b_deny"
default reason = "deny"

t := `
escalates[id] { id := [][_] }
`
decision = "allow" { not contains(t, "[][_]") }
rule_id = "loosened" { not contains(t, "[][_]") }
""",
        ("block", "b_deny"),
    ),
}


def _raw_text_decision(rego: str) -> tuple[str, str]:
    """What OPA itself says about the module's own text — the reference the evaluator must match."""
    package = re.search(r"(?m)^package\s+(\S+)", rego).group(1)
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "p.rego"
        path.write_text(rego, encoding="utf-8")
        out = subprocess.run(
            [
                "opa",
                "eval",
                "--v0-compatible",
                "-d",
                str(path),
                "-I",
                "-f",
                "json",
                f"[data.{package}.decision, data.{package}.rule_id]",
            ],
            input=json.dumps(_RAW_INPUT),
            capture_output=True,
            text=True,
            check=True,
        )
    return tuple(json.loads(out.stdout)["result"][0]["expressions"][0]["value"])


@pytest.mark.parametrize("name", sorted(RAW_STRING_REPROS))
def test_a_legacy_line_inside_a_raw_string_is_not_rewritten(name: str) -> None:
    rego, _expected = RAW_STRING_REPROS[name]
    assert upgrade_legacy(rego) == (rego, ())


@needs_opa
@pytest.mark.parametrize("opa_mode", ["server", "subprocess"])
@pytest.mark.parametrize("name", sorted(RAW_STRING_REPROS))
async def test_a_raw_string_policy_decides_what_its_own_text_says(name: str, opa_mode: str, monkeypatch) -> None:
    monkeypatch.setattr(settings, "opa_mode", opa_mode)
    rego, expected = RAW_STRING_REPROS[name]
    assert _raw_text_decision(rego) == expected
    evaluator = OPAEvaluator(FakeCache())  # type: ignore[arg-type]
    try:
        result = await evaluator._evaluate_opa(f"ns:raw-{uuid.uuid4().hex[:8]}", "ns", "support", _RAW_INPUT, rego)
    finally:
        await evaluator.close()
    assert (result["decision"], result["rule_id"]) == expected, (
        f"{name}: the evaluator decided differently from the policy's own text — the rewrite changed data"
    )


def test_code_lines_follows_rego_strings_and_comments() -> None:
    from norviq.engine.empty_literals import _code_lines

    rego = "\n".join(
        [
            'a := "a ` in a quoted string opens nothing"',  # 0 code
            "b := 1  # nor does a ` after a comment",  # 1 code
            'c := "an escaped \\" quote, then ` still quoted"',  # 2 code
            "d := `opens here",  # 3 not code (opens a raw string)
            'allow_names := {}  # " and # are data in here',  # 4 not code (inside)
            "closes here`",  # 5 not code (closes it)
            "allowed_suffix = []",  # 6 code
            "e := `one line`",  # 7 not code (a raw string on the line)
        ]
    )
    assert _code_lines(rego) == [True, True, True, False, False, False, True, False]


def test_only_code_lines_count_for_the_header_and_the_shape() -> None:
    # A header quoted in a raw string does not make a hand-written module generated.
    quoted_header = "package norviq.custom.x\ns := `\n# nrvq-egress-allowlist/v1: e30=\n`\nallowed_suffix = []\n"
    assert upgrade_legacy(quoted_header) == (quoted_header, ())
    # A real legacy line beside a raw string holding one: the declaration is rewritten, the data is not.
    mixed = "package norviq.intent.x\nallow_names := {}\ns := `\nallow_names := {}\n`\n"
    upgraded, shapes = upgrade_legacy(mixed)
    assert shapes == ("intent_allowlist_empty",)
    assert upgraded.splitlines() == [
        "package norviq.intent.x",
        'allow_names := {k: k | k := ""; false}',
        "s := `",
        "allow_names := {}",
        "`",
    ]


# --- Only a compile error is a "rejected module" ----------------------------------------------------

# What OPA 1.21.4's `PUT /v1/policies/<id>` answers for a module that does not compile (abridged).
_OPA_COMPILE_400 = (
    '{"code": "invalid_parameter", "message": "error(s) occurred while compiling module(s)", '
    '"errors": [{"code": "rego_type_error", "message": "undefined ref: data.t.X[input.k]"}]}'
)


@pytest.mark.parametrize(
    ("status", "body", "rejected"),
    [
        (400, _OPA_COMPILE_400, True),
        (413, "request entity too large", False),
        (400, '{"code": "invalid_parameter", "message": "invalid policy id"}', False),
        (500, '{"code": "internal_error", "message": "storage"}', False),
    ],
)
async def test_only_a_compile_error_is_reported_as_a_module_opa_refused(status, body, rejected, monkeypatch) -> None:
    """NRVQ-ENG-2071 says "OPA refused to compile this policy". A 413 or a 400 about the request is a 4xx
    too, and naming it a compile failure would send the operator to the wrong place."""
    from types import SimpleNamespace

    from norviq.engine import opa_client
    from norviq.engine.opa_client import OpaModuleRejected

    class _Put:
        async def put(self, *_a, **_k):
            return SimpleNamespace(status_code=status, text=body)

    async def _client():
        return _Put()

    async def _no_check(*_a, **_k) -> None:
        return None

    monkeypatch.setattr(settings, "opa_mode", "server")
    monkeypatch.setattr(opa_client, "_check_capabilities", _no_check)  # isolate the PUT's own answer
    evaluator = OPAEvaluator(FakeCache())  # type: ignore[arg-type]
    monkeypatch.setattr(evaluator.opa, "_ensure", _client)
    with capture_logs() as logs, pytest.raises(RuntimeError) as raised:
        await evaluator._ensure_module_pushed("ns:cls", 'package t\ndefault decision = "allow"\n')
    assert isinstance(raised.value, OpaModuleRejected) is rejected
    assert body[:40] in str(raised.value), "OPA's own reason must survive into the message"
    named = [e["key"] for e in logs if e["event"] == "nrvq.opa.module_rejected"]
    assert named == (["ns:cls"] if rejected else [])
