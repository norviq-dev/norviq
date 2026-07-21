# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Time travel: every clock-dependent code path evaluated at "later", not only at "now".

WHY THIS FILE EXISTS
--------------------
A GA blocker shipped green because the whole suite ran at a single instant. ``audit_log`` was
provisioned with only the CURRENT month's partition, so every test passed on the day it ran — and the
first INSERT after the month rolled over would have raised "no partition of relation audit_log found
for row". The sidecar swallows audit-emit errors, so the audit trail of a *security product* would
have gone silent without a single alarm. Nothing caught it because nothing ever asked the code what
it would do TOMORROW.

That is a CLASS of bug, not one bug: any helper that reads the wall clock has a behaviour that
changes with the calendar (month ends, year ends, leap days), and a suite anchored at "now" samples
exactly one point of that behaviour — usually a benign mid-month one.

WHAT THIS FILE GUARDS
---------------------
The wall clock is frozen at hostile calendar positions (last instant of a 31-day month, last instant
of a non-leap February, a leap day, the last instant of a year) and each date-dependent helper is
re-asserted there:

  * ``norviq.api.db.session``  — audit partition look-ahead must always cover *tomorrow*, and enough
    runway that a cluster nobody redeploys keeps writing.
  * ``norviq.api.retention``   — a draft must never be born already expired, and its TTL must survive
    a month/year rollover.
  * ``norviq.api.routers.keys``   — API-key expiry lands in the future at every calendar position, and
    "0 days" means NEVER EXPIRES, not "expired now".
  * ``norviq.api.routers.audit`` / ``agents`` — range tokens reach back the advertised window even when
    that crosses a year boundary.
  * ``norviq.api.routers.redteam`` — retention evaluated a year later still keeps the newest run.
  * ``norviq.engine.trust.signals.time_decay`` — trust bands are exact at their boundaries and a
    SKEWED (future-dated) history entry fails closed instead of granting full trust.
  * ``norviq.fleet.join_token`` — enrollment tokens actually expire, including across a year boundary.

Tests here deliberately assert BEHAVIOUR AT THE BOUNDARY (tomorrow, +30d, exactly-at-TTL,
one-second-past-TTL), never "it returned something today".
"""

from __future__ import annotations

import datetime as dt

import pytest

from norviq.api.db import session as session_mod
from norviq.api.db.session import _month_window

# Calendar positions that a mid-month "now" never exercises. Each one has broken a real date helper
# somewhere: month ends (arithmetic that assumes month+1 is a valid day-of-month), the last instant of
# a year (year rollover), leap day (Feb 29 -> Feb 29 next year does not exist), and the first instant
# of a month (the only position where a single-month look-ahead accidentally looks correct).
_CALENDAR_EDGES = (
    "2027-01-01T00:00:00+00:00",  # first instant of a month AND of a year
    "2027-01-31T23:59:59+00:00",  # last instant of a 31-day month
    "2027-02-28T23:59:59+00:00",  # last day of February, NON-leap year
    "2027-04-30T23:59:59+00:00",  # last instant of a 30-day month
    "2027-11-30T18:00:00+00:00",  # 30-day month, mid-evening
    "2027-12-01T00:00:00+00:00",  # first instant of the final month
    "2027-12-31T23:59:59+00:00",  # last instant of the year
    "2028-02-29T12:00:00+00:00",  # leap day
    "2028-03-01T00:00:00+00:00",  # the day after a leap day
)


class _AnyDatetimeIsInstance(type):
    """Metaclass so ``isinstance(x, <frozen datetime>)`` answers as the REAL ``datetime`` would.

    Without this the test double changes behaviour it is not supposed to touch: production code such
    as ``TimeDecaySignal._to_dt`` branches on ``isinstance(value, datetime)``, and a plain
    ``datetime`` is NOT an instance of a subclass — so freezing the clock would silently push that
    code down its fallback path and the test would "pass" (or fail) for the wrong reason.
    """

    def __instancecheck__(cls, obj: object) -> bool:
        return isinstance(obj, dt.datetime)


def _freeze(monkeypatch: pytest.MonkeyPatch, module: object, when: dt.datetime) -> None:
    """Pin ``module.datetime`` so ``datetime.now(...)`` inside it returns ``when``.

    A subclass (rather than a stub) is used on purpose: the production helpers also call
    ``datetime.fromisoformat`` / ``.replace(...)`` on the same name, so the frozen type has to stay a
    fully functional ``datetime`` — only ``now`` is pinned.
    """

    class _FrozenDatetime(dt.datetime, metaclass=_AnyDatetimeIsInstance):
        @classmethod
        def now(cls, tz: dt.tzinfo | None = None) -> dt.datetime:  # type: ignore[override]
            return when if tz is None else when.astimezone(tz)

        @classmethod
        def utcnow(cls) -> dt.datetime:  # type: ignore[override]
            return when.astimezone(dt.timezone.utc).replace(tzinfo=None)

    monkeypatch.setattr(module, "datetime", _FrozenDatetime)


def _covers(windows: list[tuple[str, str, str]], moment: dt.datetime) -> bool:
    """True when some provisioned partition window contains ``moment``'s calendar date.

    Bounds are ISO ``YYYY-MM-DD`` strings and Postgres range bounds are ``[start, end)``, so a
    lexicographic compare is exactly the range check Postgres will perform on the row.
    """
    target = moment.date().isoformat()
    return any(start <= target < end for _, start, end in windows)


# ---------------------------------------------------------------------------------------------
# audit_log partition provisioning, evaluated AT a future date
# ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize("frozen", _CALENDAR_EDGES)
def test_a_partition_always_covers_tomorrow_whatever_day_it_is(
    monkeypatch: pytest.MonkeyPatch, frozen: str
) -> None:
    """The original blocker, asked at every calendar position instead of only today.

    On the last day of a month, "tomorrow" is in the NEXT month — the exact instant at which a
    current-month-only provisioner starts rejecting every audit INSERT.
    """
    now = dt.datetime.fromisoformat(frozen)
    _freeze(monkeypatch, session_mod, now)
    windows = session_mod._partition_months()
    tomorrow = now + dt.timedelta(days=1)
    assert _covers(windows, tomorrow), (
        f"frozen at {frozen}: no audit_log partition covers tomorrow "
        f"({tomorrow.date().isoformat()}); windows={windows}"
    )


@pytest.mark.parametrize("frozen", _CALENDAR_EDGES)
def test_a_partition_still_covers_today_at_every_calendar_position(
    monkeypatch: pytest.MonkeyPatch, frozen: str
) -> None:
    """Look-ahead must not drift the window FORWARD off the present — today still has to land."""
    now = dt.datetime.fromisoformat(frozen)
    _freeze(monkeypatch, session_mod, now)
    windows = session_mod._partition_months()
    assert _covers(windows, now), f"frozen at {frozen}: today is not covered; windows={windows}"


@pytest.mark.parametrize("frozen", _CALENDAR_EDGES)
def test_partitions_give_a_cluster_a_month_of_runway_without_a_redeploy(
    monkeypatch: pytest.MonkeyPatch, frozen: str
) -> None:
    """Partitions are provisioned at STARTUP only, so the window has to outlast an idle cluster.

    30 days from the last day of a 31-day month lands two months out, which is the worst case and the
    one a "current month + next month" fix silently fails.
    """
    now = dt.datetime.fromisoformat(frozen)
    _freeze(monkeypatch, session_mod, now)
    windows = session_mod._partition_months()
    horizon = now + dt.timedelta(days=30)
    assert _covers(windows, horizon), (
        f"frozen at {frozen}: a pod running for 30 more days would write at "
        f"{horizon.date().isoformat()} with no partition; windows={windows}"
    )


def test_lookahead_holds_across_every_month_boundary_of_a_leap_year_cycle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sweep the last instant of all 24 months of a normal + leap year, not a hand-picked few."""
    for year in (2027, 2028):
        for month in range(1, 13):
            first_next = dt.datetime(
                year + (1 if month == 12 else 0),
                1 if month == 12 else month + 1,
                1,
                tzinfo=dt.timezone.utc,
            )
            last_instant = first_next - dt.timedelta(seconds=1)
            _freeze(monkeypatch, session_mod, last_instant)
            windows = session_mod._partition_months()
            assert _covers(windows, last_instant + dt.timedelta(days=1)), (
                f"{last_instant.isoformat()}: rolling into the next month has no partition; {windows}"
            )
            # Contiguity has to hold under a frozen clock too — a gap between two provisioned months
            # is the same outage as a missing month, just harder to see.
            for earlier, later in zip(windows, windows[1:]):
                assert earlier[2] == later[1], f"gap between {earlier} and {later} at {last_instant}"


@pytest.mark.parametrize("frozen", _CALENDAR_EDGES)
def test_partition_months_normalizes_to_the_first_of_the_month(
    monkeypatch: pytest.MonkeyPatch, frozen: str
) -> None:
    """Windows must be anchored on day 1.

    ``_month_window`` advances a month with ``start.replace(month=...)``. If the anchor is not
    normalized to day 1 first, the 31st of January becomes "31 February" and raises ValueError — a
    crash that only happens on 7 days of the year, i.e. exactly the kind of date-triggered fault this
    file exists to catch.
    """
    now = dt.datetime.fromisoformat(frozen)
    _freeze(monkeypatch, session_mod, now)
    windows = session_mod._partition_months()
    for _, start, _end in windows:
        assert start.endswith("-01"), f"window start {start} is not the 1st of a month"
    assert windows[0][1] == now.date().replace(day=1).isoformat()


def test_year_rollover_is_provisioned_before_it_happens(monkeypatch: pytest.MonkeyPatch) -> None:
    """Standing on 31 Dec, January of the NEXT year must already exist as a partition."""
    _freeze(monkeypatch, session_mod, dt.datetime(2027, 12, 31, 23, 59, 59, tzinfo=dt.timezone.utc))
    windows = session_mod._partition_months()
    names = [name for name, _, _ in windows]
    assert "audit_log_2027_12" in names, names
    assert "audit_log_2028_01" in names, f"January of the next year is not provisioned: {names}"
    assert len(set(names)) == len(names), f"duplicate partition names across the year edge: {names}"


def test_month_window_bounds_are_a_half_open_calendar_month() -> None:
    """[start, end) must be exactly one month — an off-by-one here silently drops a day of audit."""
    for month, expected_end in ((1, "2028-02-01"), (2, "2028-03-01"), (12, "2029-01-01")):
        name, start, end = _month_window(dt.datetime(2028, month, 1, tzinfo=dt.timezone.utc))
        assert name == f"audit_log_2028_{month:02d}"
        assert start == f"2028-{month:02d}-01"
        assert end == expected_end


def test_partition_months_is_anchored_on_the_clock_not_on_a_constant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Provisioning must follow the clock: a different "now" must produce different partitions.

    Guards against a regression where the window is computed once (module import, cached constant) —
    a long-lived pod would then keep provisioning the month it booted in, forever.
    """
    _freeze(monkeypatch, session_mod, dt.datetime(2027, 5, 10, tzinfo=dt.timezone.utc))
    may = [name for name, _, _ in session_mod._partition_months()]
    _freeze(monkeypatch, session_mod, dt.datetime(2027, 9, 10, tzinfo=dt.timezone.utc))
    september = [name for name, _, _ in session_mod._partition_months()]
    assert may[0] == "audit_log_2027_05" and september[0] == "audit_log_2027_09"
    assert not set(may) & set(september), f"windows did not move with the clock: {may} vs {september}"


def test_partition_helpers_agree_with_each_other_under_a_frozen_clock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The single-window helper and the look-ahead list must not drift apart at a month edge."""
    _freeze(monkeypatch, session_mod, dt.datetime(2028, 2, 29, 23, 59, 59, tzinfo=dt.timezone.utc))
    assert session_mod._partition_bounds() == session_mod._partition_months()[0]
    assert session_mod._partition_bounds()[0] == "audit_log_2028_02"


# ---------------------------------------------------------------------------------------------
# Draft TTL (norviq.api.retention) — a draft must never be born expired
# ---------------------------------------------------------------------------------------------

from norviq.api.retention import draft_expiry  # noqa: E402  (grouped with its own section)


@pytest.mark.parametrize("frozen", _CALENDAR_EDGES)
@pytest.mark.parametrize("agent_class", ("customer-support", "probe-alpha"))
def test_a_draft_is_never_born_already_expired(frozen: str, agent_class: str) -> None:
    """``gc_expired_drafts`` deletes rows with ``expires_at < now``.

    If the TTL arithmetic ever lands on or before its own creation instant at some calendar position,
    a brand-new draft is garbage-collected on the very next sweep and the user's work vanishes with
    no error. Asserted for a real class (day TTL) and a synthetic class (hour TTL).
    """
    now = dt.datetime.fromisoformat(frozen)
    expires = draft_expiry(agent_class, now=now)
    assert expires > now, f"{agent_class} draft created at {frozen} expires at {expires} (<= creation)"


def test_draft_ttl_crosses_a_month_and_year_boundary_exactly() -> None:
    """A 14-day TTL started in late December must land in January of the next year, to the second."""
    created = dt.datetime(2027, 12, 28, 9, 30, tzinfo=dt.timezone.utc)
    expires = draft_expiry("customer-support", now=created)
    assert expires == created + dt.timedelta(days=14)
    assert (expires.year, expires.month, expires.day) == (2028, 1, 11), expires


def test_draft_ttl_spanning_a_leap_day_counts_the_extra_day() -> None:
    """29 Feb is a real day: a TTL crossing it must not silently short-change the window."""
    created = dt.datetime(2028, 2, 20, tzinfo=dt.timezone.utc)
    expires = draft_expiry("customer-support", now=created)
    assert expires == created + dt.timedelta(days=14)
    assert (expires.month, expires.day) == (3, 5), f"leap day mishandled: {expires}"


@pytest.mark.parametrize("frozen", _CALENDAR_EDGES)
def test_synthetic_drafts_always_expire_before_real_ones(frozen: str) -> None:
    """The fast test/e2e window must stay strictly shorter than the real one at every date.

    If the two windows ever cross, seeded probe drafts outlive real ones and the Policy Catalog fills
    with test noise that retention will not clear.
    """
    now = dt.datetime.fromisoformat(frozen)
    assert draft_expiry("probe-alpha", now=now) < draft_expiry("customer-support", now=now)


# ---------------------------------------------------------------------------------------------
# API-key expiry, audit/agent range windows, red-team retention (need the FastAPI import chain)
# ---------------------------------------------------------------------------------------------

try:  # pragma: no cover - import guard
    from norviq.api.routers import agents as agents_mod
    from norviq.api.routers import audit as audit_mod
    from norviq.api.routers import keys as keys_mod
    from norviq.api.routers.redteam import plan_retention

    _ROUTERS_IMPORTED = True
except Exception as exc:  # pragma: no cover - lean env
    _ROUTERS_IMPORTED = False
    _ROUTERS_IMPORT_ERROR = str(exc)

routers_required = pytest.mark.skipif(
    not _ROUTERS_IMPORTED,
    reason="API router import chain unavailable in this env"
    + (f" ({_ROUTERS_IMPORT_ERROR})" if not _ROUTERS_IMPORTED else ""),
)


@routers_required
@pytest.mark.parametrize("frozen", _CALENDAR_EDGES)
def test_api_key_expiry_lands_in_the_future_at_every_calendar_position(
    monkeypatch: pytest.MonkeyPatch, frozen: str
) -> None:
    """A key issued on 31 Dec must expire in the NEXT year, not wrap or land in the past.

    ``verify`` rejects a key whose ``expires_at <= now``, so an expiry computed at or before issuance
    means the key is dead on arrival — an outage that only appears on certain dates.
    """
    now = dt.datetime.fromisoformat(frozen)
    _freeze(monkeypatch, keys_mod, now)
    expires = keys_mod._resolve_expiry(90)
    assert expires is not None
    assert expires == now + dt.timedelta(days=90), f"frozen at {frozen}: got {expires}"
    assert expires > now


@routers_required
def test_zero_ttl_means_never_expires_not_expires_immediately(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``expires_in_days=0`` is the documented "never expires" choice for service keys.

    Returning ``now`` (or any concrete timestamp) instead of ``None`` would revoke every service key
    the instant it is minted.
    """
    _freeze(monkeypatch, keys_mod, dt.datetime(2027, 12, 31, 23, 59, 59, tzinfo=dt.timezone.utc))
    assert keys_mod._resolve_expiry(0) is None


@routers_required
def test_default_api_key_ttl_is_a_real_multi_month_window(monkeypatch: pytest.MonkeyPatch) -> None:
    """An omitted TTL must fall back to the server default and still be far in the future.

    Pinned to "at least 30 days" rather than the exact setting so tuning the default does not break
    the guard, while a units regression (days -> hours/minutes) still does.
    """
    now = dt.datetime(2028, 2, 29, tzinfo=dt.timezone.utc)
    _freeze(monkeypatch, keys_mod, now)
    expires = keys_mod._resolve_expiry(None)
    assert expires is not None
    assert expires - now >= dt.timedelta(days=30), f"default key TTL collapsed to {expires - now}"


@routers_required
def test_a_one_day_key_is_valid_before_its_ttl_and_expired_after(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Walk the clock across a key's own expiry and assert the verify predicate flips exactly once.

    ``api_keys.verify`` rejects when ``expires_at <= now``; this re-evaluates that comparison from
    both sides of the boundary instead of only at issuance time.
    """
    issued = dt.datetime(2027, 12, 31, 12, 0, tzinfo=dt.timezone.utc)
    _freeze(monkeypatch, keys_mod, issued)
    expires = keys_mod._resolve_expiry(1)
    assert expires is not None
    assert not (expires <= issued + dt.timedelta(hours=23)), "key rejected 23h into a 24h TTL"
    assert expires <= issued + dt.timedelta(hours=25), "key still accepted 25h into a 24h TTL"


@routers_required
@pytest.mark.parametrize(
    ("token", "hours"), (("1h", 1), ("6h", 6), ("24h", 24), ("7d", 168), ("30d", 720))
)
def test_audit_range_tokens_reach_back_the_advertised_window_across_a_year_edge(
    monkeypatch: pytest.MonkeyPatch, token: str, hours: int
) -> None:
    """"Last 30 days" on 1 January must reach into the previous YEAR.

    A dropped/renamed token silently falls back to 24h, so the console would show an almost-empty
    audit view that looks like "no activity" rather than "wrong window".
    """
    now = dt.datetime(2028, 1, 1, 0, 30, tzinfo=dt.timezone.utc)
    _freeze(monkeypatch, audit_mod, now)
    since = audit_mod._since_for_range(token)  # type: ignore[arg-type]
    assert since == now - dt.timedelta(hours=hours), f"{token}: got {since}"
    if token in ("7d", "30d"):
        assert since.year == 2027, f"{token} on 1 Jan must cross into the previous year, got {since}"


@routers_required
def test_agent_range_window_matches_the_audit_tokens_across_a_year_edge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The agents view uses its own copy of the range map; the two must not drift apart."""
    now = dt.datetime(2028, 1, 1, 0, 30, tzinfo=dt.timezone.utc)
    _freeze(monkeypatch, agents_mod, now)
    _freeze(monkeypatch, audit_mod, now)
    for token in ("1h", "6h", "24h", "7d", "30d"):
        assert agents_mod._since_for_range(token) == audit_mod._since_for_range(token), token  # type: ignore[arg-type]


@routers_required
def test_redteam_retention_never_deletes_the_latest_run_however_old_it_gets() -> None:
    """Evaluate retention a YEAR after the last run: the newest one must still survive intact.

    ``/redteam/results/latest`` is the console's efficacy source. If age-based retention is allowed to
    reach the newest run, a namespace that stops running the suite loses its posture evidence — and
    the UI shows "never tested" for a namespace that WAS tested.
    """
    last_run = dt.datetime(2027, 1, 15, tzinfo=dt.timezone.utc)
    runs = [("newest", last_run), ("older", last_run - dt.timedelta(days=3))]
    delete, prune = plan_retention(
        runs,
        now=last_run + dt.timedelta(days=365),
        detail_runs=1,
        detail_ttl=dt.timedelta(days=7),
        summary_runs=20,
        summary_ttl=dt.timedelta(days=30),
    )
    assert "newest" not in delete, "the latest run was deleted by age-based retention"
    assert "newest" not in prune, "the latest run's detail was pruned by age-based retention"
    assert "older" in delete, "a year-old non-latest run should be gone entirely"


@routers_required
def test_redteam_detail_ttl_flips_exactly_at_the_boundary_not_before() -> None:
    """A run EXACTLY at the detail TTL is still within the window; one second past it is not."""
    now = dt.datetime(2027, 6, 1, tzinfo=dt.timezone.utc)
    common = {
        "now": now,
        "detail_runs": 5,
        "detail_ttl": dt.timedelta(days=7),
        "summary_runs": 20,
        "summary_ttl": dt.timedelta(days=30),
    }
    at_ttl = [("newest", now), ("edge", now - dt.timedelta(days=7))]
    _, prune_at = plan_retention(at_ttl, **common)  # type: ignore[arg-type]
    assert "edge" not in prune_at, "a run exactly at the detail TTL was pruned early"

    past_ttl = [("newest", now), ("edge", now - dt.timedelta(days=7, seconds=1))]
    _, prune_past = plan_retention(past_ttl, **common)  # type: ignore[arg-type]
    assert "edge" in prune_past, "a run one second past the detail TTL kept its detail"


# ---------------------------------------------------------------------------------------------
# Trust time-decay (engine) — banding on wall-clock age, including a skewed clock
# ---------------------------------------------------------------------------------------------

try:  # pragma: no cover - import guard
    from norviq.engine.trust.models import TrustInput
    from norviq.engine.trust.signals import time_decay as decay_mod
    from norviq.engine.trust.signals.time_decay import TimeDecaySignal

    _ENGINE_IMPORTED = True
except Exception as exc:  # pragma: no cover - lean env
    _ENGINE_IMPORTED = False
    _ENGINE_IMPORT_ERROR = str(exc)

engine_required = pytest.mark.skipif(
    not _ENGINE_IMPORTED,
    reason="engine trust import chain unavailable in this env"
    + (f" ({_ENGINE_IMPORT_ERROR})" if not _ENGINE_IMPORTED else ""),
)

_NOW = dt.datetime(2027, 12, 31, 12, 0, tzinfo=dt.timezone.utc)


def _trust_input() -> object:
    """A minimal TrustInput; TimeDecaySignal ignores everything except the history it is handed."""
    return TrustInput(
        spiffe_id="spiffe://norviq/ns/prod/sa/customer-support",
        namespace="prod",
        agent_class="customer-support",
        tool_name="read_ticket",
        tool_params={},
        session_id="s-1",
        chain_depth=0,
        timestamp=_NOW,
    )


@engine_required
@pytest.mark.parametrize(
    ("age", "expected"),
    (
        (dt.timedelta(days=400), 1.0),  # ancient
        (dt.timedelta(hours=24), 1.0),  # exactly at the forgiveness boundary
        (dt.timedelta(hours=23, minutes=59), 0.8),  # one minute short of it
        (dt.timedelta(hours=12), 0.8),
        (dt.timedelta(hours=11, minutes=59), 0.6),
        (dt.timedelta(hours=6), 0.6),
        (dt.timedelta(hours=5, minutes=59), 0.4),
        (dt.timedelta(hours=1), 0.4),
        (dt.timedelta(minutes=59), 0.2),
        (dt.timedelta(minutes=10), 0.2),
        (dt.timedelta(minutes=9), 0.1),  # just blocked — least trusted
    ),
)
async def test_time_decay_bands_are_exact_at_their_boundaries(
    monkeypatch: pytest.MonkeyPatch, age: dt.timedelta, expected: float
) -> None:
    """Trust recovery is a step function of wall-clock age, so each step must be probed on BOTH sides.

    Tested at a year boundary (31 Dec) so a band computed from a date component rather than an elapsed
    duration cannot pass by accident.
    """
    _freeze(monkeypatch, decay_mod, _NOW)
    history = [{"decision": "block", "timestamp": (_NOW - age).isoformat()}]
    score = await TimeDecaySignal().compute(_trust_input(), history, {})  # type: ignore[arg-type]
    assert score == pytest.approx(expected), f"age={age} -> {score}, expected {expected}"


@engine_required
async def test_a_future_dated_block_from_clock_skew_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A block timestamped in the FUTURE (skewed pod clock, or a forged history entry) must not
    read as "so old it is forgiven".

    Negative age falls through every band to the most-distrusting score. If it were ever normalized
    with abs() or clamped upward, an attacker who can nudge a timestamp forward would hand themselves
    full trust immediately after being blocked.
    """
    _freeze(monkeypatch, decay_mod, _NOW)
    history = [{"decision": "block", "timestamp": (_NOW + dt.timedelta(hours=48)).isoformat()}]
    score = await TimeDecaySignal().compute(_trust_input(), history, {})  # type: ignore[arg-type]
    assert score == pytest.approx(0.1), f"future-dated block scored {score}; must fail closed"


@engine_required
async def test_naive_history_timestamps_are_read_as_utc_rather_than_crashing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Older audit rows carry NAIVE timestamps.

    Subtracting a naive datetime from an aware "now" raises TypeError, which the trust calculator
    would surface as a failed signal — degrading trust scoring cluster-wide the moment a legacy row
    is read. The normalizer must treat naive values as UTC.
    """
    _freeze(monkeypatch, decay_mod, _NOW)
    naive = (_NOW - dt.timedelta(hours=13)).replace(tzinfo=None)
    for entry in ({"decision": "block", "timestamp": naive}, {"decision": "block", "timestamp": naive.isoformat()}):
        score = await TimeDecaySignal().compute(_trust_input(), [entry], {})  # type: ignore[arg-type]
        assert score == pytest.approx(0.8), f"naive timestamp {entry['timestamp']!r} -> {score}"


@engine_required
async def test_only_the_most_recent_block_drives_decay_across_a_year_edge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A stale block from LAST year must not out-vote a fresh one from this year."""
    _freeze(monkeypatch, decay_mod, dt.datetime(2028, 1, 1, 6, 0, tzinfo=dt.timezone.utc))
    history = [
        {"decision": "block", "timestamp": "2027-01-01T06:00:00+00:00"},  # a year old
        {"decision": "block", "timestamp": "2027-12-31T23:00:00+00:00"},  # 7h old, across the edge
    ]
    score = await TimeDecaySignal().compute(_trust_input(), history, {})  # type: ignore[arg-type]
    assert score == pytest.approx(0.6), f"latest block ignored: {score}"


# ---------------------------------------------------------------------------------------------
# Fleet join token — enrollment credentials must actually expire
# ---------------------------------------------------------------------------------------------

from norviq.fleet import join_token as join_mod  # noqa: E402  (grouped with its own section)

_JOIN_SECRET = "unit-test-not-a-real-secret"  # nosec B105 - fixed HMAC input for a pure-arithmetic test


def _mint_at(monkeypatch: pytest.MonkeyPatch, when: dt.datetime, ttl_s: int = 600) -> str:
    _freeze(monkeypatch, join_mod, when)
    token, _payload = join_mod.mint_join_token(
        secret=_JOIN_SECRET,
        hub_url="https://hub.invalid",
        cluster_id="spoke-1",
        bundle_pubkey="-----BEGIN PUBLIC KEY-----\nnot-a-key\n-----END PUBLIC KEY-----\n",
        ttl_s=ttl_s,
    )
    return token


def test_join_token_is_still_valid_just_inside_its_ttl(monkeypatch: pytest.MonkeyPatch) -> None:
    minted_at = dt.datetime(2027, 6, 1, 12, 0, tzinfo=dt.timezone.utc)
    token = _mint_at(monkeypatch, minted_at, ttl_s=600)
    _freeze(monkeypatch, join_mod, minted_at + dt.timedelta(seconds=599))
    payload = join_mod.verify_join_token(token, _JOIN_SECRET)
    assert payload["cid"] == "spoke-1"


def test_join_token_is_rejected_once_its_ttl_has_passed(monkeypatch: pytest.MonkeyPatch) -> None:
    """A cluster-enrollment credential that never expires is a permanent skeleton key.

    Expiry is invisible to a suite that verifies at mint time, so the clock is advanced past the TTL.
    """
    minted_at = dt.datetime(2027, 6, 1, 12, 0, tzinfo=dt.timezone.utc)
    token = _mint_at(monkeypatch, minted_at, ttl_s=600)
    _freeze(monkeypatch, join_mod, minted_at + dt.timedelta(seconds=601))
    with pytest.raises(ValueError, match="expired"):
        join_token_payload = join_mod.verify_join_token(token, _JOIN_SECRET)
        assert join_token_payload  # unreachable; keeps the assertion explicit if the raise regresses


def test_join_token_minted_seconds_before_new_year_still_verifies_after_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A TTL that straddles a year boundary must be compared as elapsed SECONDS, not by date.

    Minted 23:59:50 on 31 Dec, verified 00:05 on 1 Jan — inside a 10-minute TTL, but "a different
    year", which is exactly where a date-component comparison would wrongly reject (or wrongly accept).
    """
    minted_at = dt.datetime(2027, 12, 31, 23, 59, 50, tzinfo=dt.timezone.utc)
    token = _mint_at(monkeypatch, minted_at, ttl_s=600)
    _freeze(monkeypatch, join_mod, dt.datetime(2028, 1, 1, 0, 5, 0, tzinfo=dt.timezone.utc))
    assert join_mod.verify_join_token(token, _JOIN_SECRET)["cid"] == "spoke-1"

    _freeze(monkeypatch, join_mod, dt.datetime(2028, 1, 1, 0, 10, 0, tzinfo=dt.timezone.utc))
    with pytest.raises(ValueError, match="expired"):
        join_mod.verify_join_token(token, _JOIN_SECRET)
