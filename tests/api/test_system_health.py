# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The console's "is something wrong right now?" surface.

A governance product failing is not self-announcing: when the engine is unreachable the sidecars
quietly fail closed, every agent's tool calls stop working, and the operator's first signal is a user
complaining the bot "got dumber". With a fail-open posture it is quieter still — calls are forwarded
UNGOVERNED and nothing visibly changes.

The route reports only what it can prove from decisions the data plane actually recorded, and is
scoped like every other read so one tenant is never shown another tenant's incident.
"""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

from fastapi.testclient import TestClient

from norviq.api.auth import get_current_user
from norviq.api.db.session import get_session
from norviq.api.main import create_app

_ADMIN = {"role": "admin", "namespace": "", "sub": "admin"}
_TENANT = {"role": "viewer", "namespace": "chatbot-prod", "sub": "tenant"}
# The least-privilege floor: authenticated, non-admin, NO namespace claim. Produced by local login
# for every non-admin role (auth_login._namespace_for returns ""), by an unmapped OIDC user, and by
# a minted viewer token.
_NO_CLAIM = {"role": "viewer", "namespace": "", "sub": "unmapped"}
_NOW = datetime(2026, 7, 26, 10, 0, tzinfo=timezone.utc)


class _Session:
    """Yields canned grouped rows, and records the compiled SQL so scoping can be asserted.

    `execute` serves the INFRA-VERDICT query; `scalar` serves the LIVENESS COUNT — two different
    session methods so a test can never accidentally feed one query's canned answer to the other.
    `recorded` is what the deployment wrote in the window: 0 = the data plane recorded nothing (idle
    OR severed), None = the liveness read itself failed."""

    def __init__(self, rows: list, recorded: int | None = 7) -> None:
        self.rows = rows
        self.recorded = recorded
        self.statements: list[str] = []
        self.scalar_statements: list[str] = []

    async def execute(self, stmt):
        self.statements.append(str(stmt))
        return SimpleNamespace(all=lambda: self.rows)

    async def scalar(self, stmt):
        self.scalar_statements.append(str(stmt))
        if self.recorded is None:
            raise RuntimeError("liveness probe failed")
        return self.recorded

    async def close(self) -> None:
        return None


def _row(rule_id: str, n: int = 3, namespaces: list[str] | None = None):
    return SimpleNamespace(rule_id=rule_id, n=n, last_seen=_NOW, namespaces=namespaces or ["chatbot-prod"])


def _client(rows: list, user: dict | None = None, recorded: int | None = 7) -> tuple[TestClient, _Session]:
    app = create_app()
    session = _Session(rows, recorded=recorded)
    app.dependency_overrides[get_current_user] = lambda: user or _ADMIN

    async def _get_session():
        yield session

    app.dependency_overrides[get_session] = _get_session
    return TestClient(app), session


def test_ok_requires_positive_evidence_that_the_data_plane_reached_us() -> None:
    """No infra verdict AND governed calls still arriving = a substantiated all-clear."""
    client, _ = _client([], recorded=412)
    body = client.get("/api/v1/system-health").json()
    assert body["status"] == "ok"
    assert body["issues"] == []
    assert body["decisions_in_window"] == 412
    assert "412" in body["evidence"]


def test_an_empty_window_is_unknown_not_ok() -> None:
    """REWRITTEN (was `test_healthy_when_nothing_was_recorded`, which asserted "ok" here).

    Every record this route reads arrives through the central /evaluate, so a data plane that cannot
    reach the API writes NOTHING — byte-for-byte identical to a healthy idle one. The old assertion
    was the defect: it made "we could not look" render as "we looked and it is fine". The behaviour
    this now asserts is the new one — an empty window is `unknown`, and it still raises no banner,
    because an idle deployment is not an incident and crying wolf teaches operators to ignore it."""
    client, _ = _client([], recorded=0)
    body = client.get("/api/v1/system-health").json()
    assert body["status"] == "unknown"
    assert body["status"] != "ok"
    assert body["issues"] == []  # honest, but not an alarm
    assert body["decisions_in_window"] == 0
    assert "not an all-clear" in body["evidence"]


def test_a_failed_liveness_read_is_unknown_not_ok() -> None:
    """A DB error on the liveness probe must not degrade into a cheerful default."""
    client, _ = _client([], recorded=None)
    body = client.get("/api/v1/system-health").json()
    assert body["status"] == "unknown"
    assert body["decisions_in_window"] is None  # never coerced to 0


def test_liveness_probe_is_scoped_like_the_incident_query() -> None:
    """A tenant's all-clear must be evidenced by THEIR namespace's traffic, not the cluster's."""
    client, session = _client([], user=_TENANT, recorded=5)
    assert client.get("/api/v1/system-health").json()["status"] == "ok"
    assert "audit_log.namespace =" in session.scalar_statements[0]

    client, session = _client([], user=_ADMIN, recorded=5)
    assert client.get("/api/v1/system-health").json()["status"] == "ok"
    assert "audit_log.namespace =" not in session.scalar_statements[0]


def test_engine_outage_is_reported_with_evidence() -> None:
    """The fail-closed case: agents are alive but every tool call is being refused."""
    client, _ = _client([_row("thin_proxy_fail_closed", n=42)])
    body = client.get("/api/v1/system-health").json()
    assert body["status"] == "degraded"
    issue = body["issues"][0]
    assert issue["id"] == "thin_proxy_fail_closed"
    assert issue["severity"] == "critical"
    assert issue["affected_calls"] == 42
    assert issue["namespaces"] == ["chatbot-prod"]
    assert issue["remediation"]  # actionable, not just an alarm


def test_fail_open_is_reported_as_ungoverned() -> None:
    """The quietest failure of all: nothing breaks and nothing is enforced. It must be named plainly."""
    client, _ = _client([_row("thin_proxy_fail_open")])
    issue = client.get("/api/v1/system-health").json()["issues"][0]
    assert "UNGOVERNED" in issue["title"]
    assert issue["severity"] == "critical"


def test_rejected_sidecars_are_not_described_as_an_outage() -> None:
    """A 401/403 is a credential fault. Calling it an outage sends operators to healthy engine pods."""
    client, _ = _client([_row("engine_rejected_request")])
    issue = client.get("/api/v1/system-health").json()["issues"][0]
    assert "token" in issue["remediation"].lower()
    assert "unreachable" not in issue["detail"].lower()


def test_a_tenant_only_sees_their_own_namespace() -> None:
    """Scoped like every other read — one tenant must never see another tenant's incident."""
    client, session = _client([_row("thin_proxy_fail_closed")], user=_TENANT)
    assert client.get("/api/v1/system-health").status_code == 200
    assert "namespace" in session.statements[0]


def test_admin_without_a_namespace_claim_sees_the_whole_deployment() -> None:
    """The operator running the cluster needs the unscoped view."""
    client, session = _client([_row("thin_proxy_fail_closed")], user=_ADMIN)
    assert client.get("/api/v1/system-health").status_code == 200
    # No equality filter on namespace was added for the unscoped admin.
    assert "audit_log.namespace =" not in session.statements[0]


def test_a_viewer_with_no_namespace_claim_gets_no_data() -> None:
    """The gap between the two tests above.

    Scoping was hand-rolled as `if role != "admin" and claim_ns:`. A non-admin with an EMPTY claim
    satisfies neither side, so no filter was applied and this principal — the product's documented
    least-privilege floor — received the unscoped deployment view: every namespace carrying an
    infrastructure verdict, the per-rule affected-call counts, and every namespace's expiring sidecar
    workloads and service-key subjects. The console polls this route for its header banner, so nothing
    unusual had to be done to reach it.

    The suite covered admin (unscoped, correct) and a scoped tenant (filtered, correct). Neither
    exercises the branch where the hand-rolled condition differs from `read_namespace`, which is the
    only branch that was wrong. cluster_info.py guards the same principal with a 403 and a comment
    naming this leak; the two routes must agree.
    """
    client, session = _client([_row("thin_proxy_fail_closed")], user=_NO_CLAIM)
    resp = client.get("/api/v1/system-health")
    assert resp.status_code == 403, (
        f"a no-scope viewer got {resp.status_code} with body {resp.text[:300]}"
    )
    assert resp.json()["detail"] == "No namespace scope"
    assert not session.statements, "the query ran before the scope was resolved"


def test_only_infrastructure_rule_ids_qualify_as_incidents() -> None:
    """A policy doing its job is not an outage. If a normal block could raise the banner, operators
    would learn to ignore it — and then miss the real enforcement outage it exists for.

    Asserted against the constant rather than the compiled SQL: SQLAlchemy renders an IN clause as a
    post-compile placeholder, so string-matching the statement would pass no matter what it filtered."""
    from norviq.api.routers.system_health import _INFRA_RULE_IDS

    assert set(_INFRA_RULE_IDS) == {
        "thin_proxy_fail_closed",
        "thin_proxy_fail_open",
        "engine_rejected_request",
        # The verdicts the ENGINE mints and the API's own emitter persists. Without them this route
        # keyed exclusively on ids no code path can write while the incident is happening, so it could
        # never substantiate an outage at all — see the producer test below.
        "evaluator_error",
        "policy_load_pending",
        # Added later, and the omission mattered: these are the SAME shape as `evaluator_error` — a
        # fail-closed refusal of real traffic with no rule behind it — and they were absent, so the
        # outage an operator is most likely to actually have (the engine slowing under load rather
        # than falling over) was the one the banner could not show.
        "evaluator_timeout",
        "evaluator_fallback",
    }
    # `invalid_spiffe_identity` stays OUT on purpose, and this asserts the judgement rather than
    # leaving it to be re-litigated: it names a CALLER fault, and one spoof attempt raising
    # "Norviq is down" is the misdirection this module's docstring exists to prevent. The fleet-wide
    # version of that failure already has a key here as `engine_rejected_request`.
    assert "invalid_spiffe_identity" not in _INFRA_RULE_IDS
    # Every entry must carry a severity, a title, a detail and a remediation — an alarm with no
    # next step is just noise on a dashboard.
    for rule_id, spec in _INFRA_RULE_IDS.items():
        assert len(spec) == 4, rule_id
        assert all(str(part).strip() for part in spec), rule_id


def test_the_infra_rule_ids_are_the_ones_the_data_plane_actually_mints() -> None:
    """The banner is only as honest as this coupling: if the sidecar/SDK renames a fallback rule_id,
    this route silently stops reporting outages and the console goes quiet during an incident.

    RENAMED from `..._actually_writes`: a rule_id appearing in a source file proves it is MINTED, not
    that it is ever PERSISTED — and for the two thin-proxy ids it is emphatically not (see the next
    test). Asserting minting is still worth doing, because a rename would break the day a producer
    lands; the name just has to stop claiming more than the assertion delivers."""
    from norviq.api.routers.system_health import _INFRA_RULE_IDS
    from norviq.sidecar import remote_evaluator

    source = (
        remote_evaluator.__file__ and open(remote_evaluator.__file__, encoding="utf-8").read()
    ) or ""
    for rule_id in ("thin_proxy_fail_closed", "thin_proxy_fail_open"):
        assert rule_id in _INFRA_RULE_IDS
        assert f'rule_id="{rule_id}"' in source, f"{rule_id} is no longer minted by the sidecar"


def test_at_least_one_infra_rule_id_has_a_producer_that_can_reach_the_audit_log() -> None:
    """THE test the suite was missing, and the reason the route could never report an outage.

    `thin_proxy_fail_open` / `thin_proxy_fail_closed` are minted only by the THIN-PROXY sidecar, whose
    `_emitter` is None by construction (`SidecarProxy.start`), and they fire exactly when the central
    /evaluate — the thing that would have written the record — is unreachable. `engine_rejected_request`
    is the SDK/MCP-gateway twin. So a route keyed ONLY on those three can never match a row, and its
    green "ok" is unfalsifiable.

    At least one key must therefore come from a producer that runs INSIDE the API, whose records reach
    `audit_log` through the API's own emitter. `evaluator_error` and `policy_load_pending` are that:
    engine-minted, fail-closed, and exempt from monitor-mode softening, so they always denote real
    refused traffic rather than a policy decision."""
    from norviq.api.routers.system_health import _INFRA_RULE_IDS
    from norviq.engine import evaluator as engine_evaluator
    from norviq.sidecar import proxy as sidecar_proxy

    api_written = {"evaluator_error", "policy_load_pending"}
    assert api_written <= set(_INFRA_RULE_IDS), (
        "every remaining key is minted where no audit emitter exists, so no row can ever match"
    )

    engine_source = open(engine_evaluator.__file__, encoding="utf-8").read()
    for rule_id in sorted(api_written):
        assert f'"rule_id": "{rule_id}"' in engine_source, f"{rule_id} is no longer minted by the engine"

    # This used to assert `api_written <= _POSTURE_EXEMPT_RULES` — i.e. that these verdicts stay HARD,
    # because a monitor-mode namespace softening them to `audit` would erase the evidence this route
    # reads. The concern was right; the remedy was wrong. Keeping them hard meant an engine fault kept
    # dropping customer traffic in a namespace whose entire configuration said "do not drop traffic".
    #
    # They now soften like everything else, and the route reads the softened forms too. The invariant
    # worth guarding is therefore no longer "these never soften" but "however they are stored, this
    # route still sees them" — which is what the variant map has to cover.
    from norviq.api.routers.system_health import _INFRA_RULE_VARIANTS

    for rule_id in sorted(api_written):
        assert _INFRA_RULE_VARIANTS.get(rule_id) == rule_id
        for prefix in engine_evaluator.WOULD_BLOCK_RULE_PREFIXES:
            softened = f"{prefix}{rule_id}"
            assert _INFRA_RULE_VARIANTS.get(softened) == rule_id, (
                f"a monitor-mode {rule_id} is stored as {softened!r} and would go unseen — "
                "the outage banner would go dark in exactly the namespaces running monitor mode"
            )

    # The premise, asserted rather than assumed: thin-proxy mode has no emitter to write with.
    proxy_source = open(sidecar_proxy.__file__, encoding="utf-8").read()
    assert "self._emitter = None" in proxy_source


def test_the_console_cannot_manufacture_its_own_all_clear() -> None:
    """The liveness count must exclude the traffic THIS API writes to itself.

    Two populations reach `audit_log` with no data plane in the loop, both through the API's own
    in-process emitter: the Policy Tester (the console POSTs /evaluate under an ephemeral
    `policy-tester-<rand>` class) and a red-team run (`framework="redteam"`). Counting either as
    evidence that the data plane reached us means an operator whose sidecars are severed gets a green
    all-clear the moment they open the Policy Tester to work out why nothing is working — the banner
    substantiated by the page the operator is standing on.

    The fake session ignores WHERE (it answers `scalar` with a canned number), so the exclusion is
    asserted on the COMPILED statement — the same way the sibling routers' real-traffic filters are.
    A behavioural assertion here would pass with no predicate at all."""
    from norviq.api.synthetic import SYNTHETIC_CLASS_PREFIXES

    client, session = _client([], recorded=412)
    assert client.get("/api/v1/system-health").json()["status"] == "ok"
    sql = session.scalar_statements[0]
    assert "framework" in sql, "the liveness count does not exclude red-team rows"
    assert "lower(coalesce(audit_log.agent_class" in sql.lower(), \
        "the liveness count does not exclude synthetic/probe identities"
    # the Policy Tester's own class prefix is one of the exclusions, by name.
    assert "policy-tester-" in SYNTHETIC_CLASS_PREFIXES
    assert sql.count("audit_log.agent_class") >= len(SYNTHETIC_CLASS_PREFIXES)


def test_the_liveness_filter_is_the_shared_classifier_not_a_second_copy() -> None:
    """`audit_row_is_non_real` is the ONE shared real-traffic predicate (audit stats, /tools, /mitre,
    the dry-run replay). Forking a second definition here would let this route's "a call happened"
    drift from the Overview's governed-call KPI shown two inches away."""
    from sqlalchemy import func, select

    from norviq.api.db.models import AuditLogEntry
    from norviq.api.routers import system_health as sh

    mine = str(
        select(func.count()).select_from(AuditLogEntry).where(~sh.audit_row_is_non_real(AuditLogEntry))
    )
    client, session = _client([], recorded=1)
    client.get("/api/v1/system-health")
    # every conjunct of the shared predicate appears verbatim in what the route compiled
    for fragment in mine.split("WHERE", 1)[1].split(" AND "):
        assert fragment.strip().strip("()") in session.scalar_statements[0]


def test_an_all_clear_says_which_traffic_it_counted() -> None:
    """Copy must be true of the code beneath it. The number is REAL governed calls, and the empty-window
    sentence has to say plainly that the operator's own Policy-Tester rows were not what it counted —
    otherwise `decisions_in_window: 0` contradicts an Audit Log visibly full of rows."""
    body = _client([], recorded=0)[0].get("/api/v1/system-health").json()
    assert "real governed tool call" in body["evidence"]
    assert "Policy-Tester" in body["evidence"]
    body = _client([], recorded=9)[0].get("/api/v1/system-health").json()
    assert "9 real governed tool calls" in body["evidence"]
