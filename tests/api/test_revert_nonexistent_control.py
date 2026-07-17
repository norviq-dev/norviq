# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""DEF-030: per-control remediation revert must not report a phantom removal.

`DELETE /api/v1/policies/{ns}/{class}__remediation__?confirm_managed=true&control_id=<id>` removes ONE
compliance control from the accumulated overlay. When `control_id` names a control that is NOT in the
overlay (e.g. a typo), the pre-fix code computed `remaining = [every control that isn't <id>]` — the full
untouched set — saw it non-empty, re-materialized an identical overlay (bumping the version), logged a
`remediation_control_reverted` audit line, and returned 200 `{"removed_control": <id>, ...}` — a success
that LIES (a phantom removal + spurious version bump + false compliance audit entry).

Fixed behaviour: a control that was never present is a no-op → 404, no `loader.create` (no version bump),
no audit line.

The harness stubs the loader's DB-authoritative revert surface (`_db_engine().connect()` advisory lock,
`load_from_db`, `create`) so the endpoint's branch runs without a real Postgres; `create` is recorded so we
can assert the phantom re-materialization does NOT happen."""

from __future__ import annotations

from fastapi.testclient import TestClient

from norviq.api.threat_intent import generate_remediation_overlay_rego

# Two real controls, each mapping to a runtime-expressible remediation rule, so the overlay parses to a
# non-empty control set (the exact condition under which the pre-fix phantom-removal bug fires).
_CONTROLS = [
    {"framework": "nist", "control_id": "NIST-AC-3", "control_name": "Access Enforcement",
     "rule_ids": ["llm06_excessive_agency"]},
    {"framework": "nist", "control_id": "NIST-AC-4", "control_name": "Information Flow",
     "rule_ids": ["llm02_data_leakage"]},
]
_OVERLAY_REGO = generate_remediation_overlay_rego("report-gen", _CONTROLS)


class _StubConn:
    """Stands in for the AsyncConnection used only for the pg advisory lock/unlock statements."""

    async def execute(self, *a, **k):
        return None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _StubEngine:
    def connect(self):
        return _StubConn()


class _StubLoader:
    def __init__(self, overlay_rego: str) -> None:
        self._overlay_rego = overlay_rego
        self.create_calls: list[tuple] = []

    def _db_engine(self):
        return _StubEngine()

    async def load_from_db(self, namespace: str, agent_class: str):
        return {"rego": self._overlay_rego, "priority": 1}

    async def create(self, *a, **k):
        # Records the (phantom) re-materialization the pre-fix code performed. A revert of a control that was
        # never in the overlay must NEVER reach here.
        self.create_calls.append((a, k))
        return 99


class _StubSession:
    async def execute(self, *a, **k):
        class _R:
            def all(self):
                return []

        return _R()

    async def scalar(self, *a, **k):
        return None

    def add(self, *a, **k):
        return None

    async def commit(self):
        return None


def _client(loader: _StubLoader) -> TestClient:
    from norviq.api.auth import get_current_user
    from norviq.api.db.session import get_session
    from norviq.api.main import create_app

    app = create_app()
    app.state.loader = loader
    app.dependency_overrides[get_current_user] = lambda: {"role": "admin", "sub": "tester", "namespace": None}
    app.dependency_overrides[get_session] = lambda: _StubSession()
    return TestClient(app, raise_server_exceptions=False)


def test_revert_nonexistent_control_id_is_404_not_a_lying_success():
    loader = _StubLoader(_OVERLAY_REGO)
    client = _client(loader)
    resp = client.delete(
        "/api/v1/policies/default/report-gen__remediation__",
        params={"confirm_managed": "true", "control_id": "NIST-AC-3-typo"},
    )
    # Pre-fix: 200 with removed_control="NIST-AC-3-typo", remaining_controls=[both controls], version bumped.
    assert resp.status_code == 404, resp.text
    body = resp.json()
    assert body.get("removed_control") != "NIST-AC-3-typo"
    assert body.get("deleted") is not True
    # The phantom removal re-materialized (and version-bumped) the overlay via loader.create — must not happen.
    assert loader.create_calls == [], "no re-materialization / version bump for a control that was never present"


def test_revert_existing_control_still_succeeds_and_rematerializes():
    # The 404 guard must be NARROW: reverting a control that IS present still removes it, re-materializes the
    # remaining union, and returns 200 — so the fix can't be "always 404".
    loader = _StubLoader(_OVERLAY_REGO)
    client = _client(loader)
    resp = client.delete(
        "/api/v1/policies/default/report-gen__remediation__",
        params={"confirm_managed": "true", "control_id": "NIST-AC-3"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["removed_control"] == "NIST-AC-3"
    assert body["remaining_controls"] == ["NIST-AC-4"]
    assert len(loader.create_calls) == 1, "the surviving control set is re-materialized exactly once"
