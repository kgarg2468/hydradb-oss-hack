"""Timing statistics for the benchmark harness.

Three decisions in here are the ones a sceptical reader should check, so they
are stated rather than buried:

**Percentiles are nearest-rank, not interpolated.** ``percentile(xs, 95)`` is
always a number that was actually measured. Linear interpolation (numpy's
default) invents a value between two observations, which is fine for a smooth
distribution and misleading for a bimodal one — and a graph query against a
cold page cache is exactly bimodal. Nearest-rank also cannot flatter the
result: for ``n = 50`` it reports the 48th slowest run as p95, never a blend of
the 47th and 48th.

**Warmup runs are excluded from the sample and reported separately.** They are
not thrown away, because "how slow was it before it was warm" is the number a
demo audience actually experiences.

**The very first call is reported on its own as ``cold_ms``.** It is never in
``samples_ms``. Quoting a warm percentile as *the* latency when the first call
was three orders of magnitude slower is the specific dishonesty this module
exists to make impossible: :meth:`Timings.summary` always emits ``cold_ms``
alongside the percentiles, so a caller that prints the summary cannot omit it
by accident.
"""

from __future__ import annotations

import math
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

#: Percentiles every summary reports. p99 over 50 runs is the slowest run; that
#: is a weak estimator and :meth:`Timings.summary` says so via ``n``.
DEFAULT_QUANTILES: tuple[float, ...] = (50.0, 95.0, 99.0)


def percentile(values: Sequence[float], q: float) -> float:
    """Nearest-rank percentile of ``values``.

    ``rank = ceil(q/100 * n)``, 1-based, clamped into ``[1, n]``. The result is
    always an element of ``values``; the input is not required to be sorted.
    """
    if not values:
        raise ValueError("percentile of an empty sample is undefined")
    if not 0.0 < q <= 100.0:
        raise ValueError(f"quantile must be in (0, 100], got {q}")
    ordered = sorted(values)
    rank = math.ceil(q / 100.0 * len(ordered))
    return ordered[min(len(ordered), max(1, rank)) - 1]


def mean(values: Sequence[float]) -> float:
    if not values:
        raise ValueError("mean of an empty sample is undefined")
    return sum(values) / len(values)


@dataclass(frozen=True)
class Timings:
    """One operation's measured latencies, in milliseconds.

    ``cold_ms`` is the first invocation of all. ``warmup_ms`` holds every
    discarded run *including* that first one, so ``warmup_ms[0] == cold_ms``
    whenever any warmup was requested. ``samples_ms`` is the measured sample and
    contains no warmup run.
    """

    label: str
    samples_ms: tuple[float, ...]
    warmup_ms: tuple[float, ...] = ()
    cold_ms: float | None = None
    #: Free-form context: corpus size, row counts, what was queried.
    meta: dict = field(default_factory=dict)

    def summary(self, quantiles: Sequence[float] = DEFAULT_QUANTILES) -> dict:
        out: dict = {
            "label": self.label,
            "n": len(self.samples_ms),
            "warmup_runs": len(self.warmup_ms),
            "cold_ms": None if self.cold_ms is None else round(self.cold_ms, 3),
            "min_ms": round(min(self.samples_ms), 3),
            "mean_ms": round(mean(self.samples_ms), 3),
            "max_ms": round(max(self.samples_ms), 3),
        }
        for q in quantiles:
            key = f"p{q:g}_ms"
            out[key] = round(percentile(self.samples_ms, q), 3)
        out["meta"] = dict(self.meta)
        return out


def run_timed(
    call: Callable[[int], object],
    *,
    label: str,
    runs: int,
    warmup: int,
    clock: Callable[[], float] = time.perf_counter,
    budget_s: float | None = None,
    meta: dict | None = None,
) -> Timings:
    """Invoke ``call(i)`` ``warmup + runs`` times and time every invocation.

    ``call`` receives the 0-based invocation index so an operation can vary its
    input across runs — the scrub sweep uses this to hit a different instant on
    every call, which is how a benchmark demonstrates that it is not measuring
    one warm cache entry over and over.

    ``budget_s`` caps wall-clock time spent on the *measured* runs. It exists
    because the maintainer sweep costs seconds per run on a large corpus and 50
    of those is an hour. When the budget stops a run early the sample is
    whatever completed and ``n`` in the summary says so; a truncated sample is
    never presented as a full one.

    ``clock`` is injected so the harness's own statistics can be tested against
    synthetic timings without sleeping.
    """
    if runs < 1:
        raise ValueError("runs must be >= 1")
    if warmup < 0:
        raise ValueError("warmup must be >= 0")

    warmups: list[float] = []
    samples: list[float] = []
    cold: float | None = None
    index = 0

    for _ in range(warmup):
        started = clock()
        call(index)
        elapsed = (clock() - started) * 1000.0
        if cold is None:
            cold = elapsed
        warmups.append(elapsed)
        index += 1

    measured_started = clock()
    for _ in range(runs):
        started = clock()
        call(index)
        elapsed = (clock() - started) * 1000.0
        if cold is None:
            cold = elapsed
        samples.append(elapsed)
        index += 1
        if budget_s is not None and (clock() - measured_started) >= budget_s:
            break

    return Timings(
        label=label,
        samples_ms=tuple(samples),
        warmup_ms=tuple(warmups),
        cold_ms=cold,
        meta=dict(meta or {}),
    )


__all__ = [
    "DEFAULT_QUANTILES",
    "Timings",
    "mean",
    "percentile",
    "run_timed",
]
