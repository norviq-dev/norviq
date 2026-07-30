# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Per-phase latency attribution for the enforcement hot path.

The engine already stamps ONE number — total server-side `latency_ms` (`evaluator.evaluate`). That is
enough to know the path is slow and useless for knowing WHY. Measured on 2-node AKS, the warm read path
with the in-process cache on was p50 3.2 ms against a floor of 1.4 ms and a p99 of ~62 ms: a 44x spread
between best and worst case. A spread that wide is variance, not work — but with a single timer there is
no way to say from data whether the tail is Redis, the OPA query, the eval-slot semaphore, or a GC pause.
Optimising on that basis is guessing, so this splits the total into named phases first.

Wall-clock, deliberately. A phase that awaits will include time the event loop spent running OTHER tasks,
so phases are not additive CPU costs — they are "how long did the caller wait across this step", which is
exactly the quantity a p95 target is written against. Queueing on a semaphore or a saturated loop shows up
here as latency, which is the point; a CPU-time measurement would hide precisely the tail being chased.

Cost, measured rather than assumed: ~2.5 us per fully-instrumented evaluation (all eight
phases, 200k iterations), i.e. 0.18% of the 1.4 ms floor and less than that against a 3.2 ms p50.
There is no I/O and nothing is allocated per phase beyond the accumulator dict, so this is safe to leave on
by default — sampling would only reintroduce blind spots in the tail, which is the region of interest.
"""

from __future__ import annotations

from time import perf_counter

# Phase names. Fixed set, so the metric's label cardinality is bounded no matter what the caller passes.
PHASE_POSTURE = "posture"          # namespace posture resolve (Redis or in-proc)
PHASE_TRUST_FETCH = "trust_fetch"  # stored trust read
PHASE_CACHE = "cache"              # eval-cache + the ALWAYS-FRESH freeze/cap read
PHASE_TRUST_COMPUTE = "trust_compute"
PHASE_CANDIDATES = "candidates"    # policy candidate collection
PHASE_OPA_WAIT = "opa_wait"        # queueing on the eval slot, NOT the query itself
PHASE_OPA = "opa"                  # the OPA query/queries
PHASE_PERSIST = "persist"          # behaviour persistence on the decision path

KNOWN_PHASES = (
    PHASE_POSTURE, PHASE_TRUST_FETCH, PHASE_CACHE, PHASE_TRUST_COMPUTE,
    PHASE_CANDIDATES, PHASE_OPA_WAIT, PHASE_OPA, PHASE_PERSIST,
)


class _Phase:
    """One timed phase. Records on exit, including when the block raises — an exception on the hot path is
    the fail-closed route and its cost is worth seeing."""

    __slots__ = ("_ms", "_name", "_t0")

    def __init__(self, ms: dict[str, float], name: str) -> None:
        self._ms = ms
        self._name = name

    def __enter__(self) -> None:
        self._t0 = perf_counter()

    def __exit__(self, *_exc: object) -> None:
        name = self._name
        self._ms[name] = self._ms.get(name, 0.0) + (perf_counter() - self._t0) * 1000.0


class PhaseTimer:
    """Accumulates wall-clock time per named phase for ONE evaluation.

    Accumulates rather than overwrites, because the multi-candidate path queries OPA once per candidate
    and the interesting number is the total spent in OPA for this call, not the last query.
    """

    __slots__ = ("_ms", "_start")

    def __init__(self) -> None:
        self._ms: dict[str, float] = {}
        self._start = perf_counter()

    def phase(self, name: str) -> "_Phase":
        """Time a block. Safe around `await` inside an async function — see the wall-clock note above.

        Returns a tiny reusable context manager rather than using @contextmanager: the decorator builds a
        generator frame per use, which measured 3x the cost of a plain __enter__/__exit__ pair across the
        eight phases this wraps. At this call frequency that difference is worth the extra class.
        """
        return _Phase(self._ms, name)

    def total_ms(self) -> float:
        return (perf_counter() - self._start) * 1000.0

    def phases_ms(self) -> dict[str, float]:
        return dict(self._ms)

    def unattributed_ms(self) -> float:
        """Total minus the sum of the phases.

        The residual is a first-class result, not rounding noise. If it dominates, the time is going
        somewhere no phase wraps — validation, model construction, serialisation, or the event loop not
        scheduling this coroutine — and the next instrumentation step should target it rather than
        micro-tuning a phase that was never the problem.
        """
        return max(0.0, self.total_ms() - sum(self._ms.values()))
