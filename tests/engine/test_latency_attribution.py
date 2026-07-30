# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Per-phase latency attribution: correct, cheap, and never able to break an enforcement call.

The engine stamped ONE number — total server-side `latency_ms`. Measured on 2-node AKS the warm read path
was p50 3.2 ms against a 1.4 ms floor with a p99 of ~62 ms: a 44x spread, which is variance rather than
work. With a single timer there was no way to say from data whether that tail was Redis, the OPA query, the
eval-slot semaphore, or a GC pause — so any optimisation would have been a guess. These tests cover the
attribution itself; the numbers it produces are Phase 2.

The two properties that matter most here are the last two: this sits on the enforcement hot path, so it
must not change a decision and must not be able to raise.
"""

from __future__ import annotations

from time import perf_counter, sleep

from norviq.engine.latency import KNOWN_PHASES, PHASE_OPA, PhaseTimer


def test_a_phase_records_roughly_the_time_it_wrapped() -> None:
    t = PhaseTimer()
    with t.phase(PHASE_OPA):
        sleep(0.02)
    ms = t.phases_ms()[PHASE_OPA]
    # Generous bounds: a shared CI runner can stretch a sleep, but it cannot compress it.
    assert 15.0 <= ms <= 200.0, f"expected ~20ms attributed to the phase, got {ms}"


def test_repeated_phases_accumulate_rather_than_overwrite() -> None:
    """The multi-candidate path queries OPA once per candidate; the useful number is the total.

    If this overwrote, a policy with five candidates would report only the last query and the OPA cost
    would look five times cheaper than it is — which is exactly the wrong direction for a tail hunt.
    """
    t = PhaseTimer()
    for _ in range(3):
        with t.phase(PHASE_OPA):
            sleep(0.005)
    assert t.phases_ms()[PHASE_OPA] >= 12.0


def test_a_raising_phase_still_attributes_its_cost() -> None:
    """An exception here is the fail-closed route. Its cost is worth seeing, not discarding."""
    t = PhaseTimer()
    try:
        with t.phase(PHASE_OPA):
            sleep(0.01)
            raise RuntimeError("opa blew up")
    except RuntimeError:
        pass
    assert t.phases_ms().get(PHASE_OPA, 0.0) >= 5.0


def test_unattributed_is_reported_not_hidden() -> None:
    """The residual is a first-class result: if it dominates, no phase wraps the real cost."""
    t = PhaseTimer()
    sleep(0.02)  # time inside the evaluation but outside every phase
    with t.phase(PHASE_OPA):
        pass
    assert t.unattributed_ms() >= 15.0


def test_unattributed_never_goes_negative() -> None:
    """Phases measure wall clock and can overlap via the event loop, so the naive subtraction can go
    negative. A negative latency in a histogram is worse than a zero — it is not a number an operator can
    reason about, and some backends reject it outright."""
    t = PhaseTimer()
    with t.phase(PHASE_OPA):
        sleep(0.01)
    with t.phase("other"):
        sleep(0.01)
    assert t.unattributed_ms() >= 0.0


def test_phase_names_are_a_bounded_set() -> None:
    """Phase is a metric LABEL. An unbounded set would blow up cardinality on a shared Prometheus."""
    assert len(KNOWN_PHASES) == len(set(KNOWN_PHASES))
    assert all(isinstance(p, str) and p for p in KNOWN_PHASES)
    assert "unattributed" not in KNOWN_PHASES  # emitted separately; must not collide


def test_overhead_is_negligible_against_the_measured_floor() -> None:
    """Instrumentation that costs a meaningful slice of the thing it measures defeats itself.

    The floor this has to disappear against is 1.4 ms (the measured minimum of the whole server-side path).
    The bound is deliberately loose — 5% — because this runs on shared CI where absolute timing is noisy;
    it is here to catch a regression of the ORDER of magnitude, e.g. someone reintroducing per-phase I/O,
    logging, or @contextmanager's generator frame.
    """
    iterations = 20_000
    t0 = perf_counter()
    for _ in range(iterations):
        timer = PhaseTimer()
        for name in KNOWN_PHASES:
            with timer.phase(name):
                pass
        timer.phases_ms()
        timer.unattributed_ms()
    per_eval_ms = (perf_counter() - t0) / iterations * 1000.0
    assert per_eval_ms < 1.4 * 0.05, (
        f"instrumentation costs {per_eval_ms*1000:.1f}us per evaluation, over 5% of the 1.4ms floor"
    )


def test_recorders_never_raise_even_with_telemetry_uninitialised() -> None:
    """Telemetry is never load-bearing. A metrics failure must not fail a tool call.

    Both recorders run on the enforcement path, and `norviq.telemetry.metrics` leaves its handles as None
    until `init` runs (and permanently so when prometheus_client is absent). If either raised there, a
    missing optional dependency would become a blocked tool call.
    """
    from norviq.telemetry.metrics import record_eval_phases, record_interception_latency

    record_eval_phases("default", {PHASE_OPA: 1.0}, 0.5)
    record_eval_phases("default", {}, 0.0)
    record_interception_latency("sidecar", "total", 3.3)
    record_interception_latency("sidecar_proxy", "upstream", 2.2)
    # Hostile input: the recorders must swallow, not propagate.
    record_eval_phases("default", {PHASE_OPA: float("nan")}, -1.0)  # type: ignore[arg-type]
