# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""audit_log must always have somewhere to write — including next month.

Startup used to create ONLY the current month's partition. Nothing failed at the time, so every test
and every live check passed — but the first INSERT after the month rolled over would hit
"no partition of relation audit_log found for row". Worse, the sidecar wraps its audit emit in
try/except (proxy.py), so the audit trail of a *security product* would have died SILENTLY while tool
calls kept flowing.

Nothing caught it because retention was modelled entirely as DELETION (see test_retention.py: "gc only
deletes expired drafts", "prune never touches the current enforcing version") and nothing ever asked
whether there was somewhere to write NEXT month. It is also a date-triggered fault — invisible until
the clock crosses a boundary.

These guards assert the look-ahead window and the DEFAULT backstop.
"""

from __future__ import annotations

import datetime as dt

from norviq.api.db.session import (
    PARTITION_LOOKAHEAD_MONTHS,
    _month_window,
    _partition_bounds,
    _partition_months,
)


def test_lookahead_provisions_more_than_the_current_month() -> None:
    windows = _partition_months()
    assert PARTITION_LOOKAHEAD_MONTHS >= 2, "a single-month window is the original time bomb"
    assert len(windows) == PARTITION_LOOKAHEAD_MONTHS


def test_partitions_cover_a_date_past_the_current_month() -> None:
    """The regression: a row written 60 days from now must have a partition to land in."""
    target = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=60)).date().isoformat()
    windows = _partition_months()
    assert any(start <= target < end for _, start, end in windows), (
        f"no audit_log partition covers {target}; windows={windows}"
    )


def test_partition_windows_are_contiguous_with_no_gaps() -> None:
    windows = _partition_months(6)
    for earlier, later in zip(windows, windows[1:]):
        assert earlier[2] == later[1], f"gap between {earlier} and {later}"


def test_partition_windows_roll_the_year_over_correctly() -> None:
    """December must hand off to January of the NEXT year."""
    december = dt.datetime(2026, 12, 1, tzinfo=dt.timezone.utc)
    name, start, end = _month_window(december)
    assert name == "audit_log_2026_12"
    assert start == "2026-12-01"
    assert end == "2027-01-01"


def test_partition_names_are_unique_and_month_shaped() -> None:
    windows = _partition_months(12)
    names = [w[0] for w in windows]
    assert len(set(names)) == len(names), f"duplicate partition names: {names}"
    for name, _, _ in windows:
        assert name.startswith("audit_log_")
        year, month = name.removeprefix("audit_log_").split("_")
        assert len(year) == 4 and 1 <= int(month) <= 12


def test_partition_bounds_still_returns_the_current_month() -> None:
    """Back-compat: the single-window helper must agree with the first look-ahead window."""
    assert _partition_bounds() == _partition_months()[0]


def test_startup_creates_a_default_partition_backstop() -> None:
    """Even if look-ahead maintenance lapses, writes must never be rejected.

    Asserted against the source of create_tables so the guard holds without a live Postgres.
    """
    import inspect

    from norviq.api.db import session as session_mod

    src = inspect.getsource(session_mod.create_tables)
    assert "PARTITION OF audit_log DEFAULT" in src, (
        "create_tables must provision a DEFAULT partition as the hard backstop"
    )
    assert "_partition_months()" in src, "create_tables must provision the rolling look-ahead window"
