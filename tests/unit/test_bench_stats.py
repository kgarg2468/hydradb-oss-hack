"""The benchmark harness's arithmetic, checked against synthetic timings.

The benchmark itself is not a test: it needs a live node, it writes millions of
edges and it takes twenty minutes. What *is* testable, and what a sceptical
reader of ``benchmarks/RESULTS.md`` actually has to trust, is the code that
turns a list of durations into a p95 — so that is what runs in CI.

Every case here drives :func:`benchmarks.stats.run_timed` with an injected fake
clock, which makes the durations exact integers rather than measured noise. If
warmup runs leaked into the sample, or a percentile were off by one rank, these
assertions would fail by whole milliseconds rather than by rounding.
"""

from __future__ import annotations

import pytest

from benchmarks.stats import Timings, mean, percentile, run_timed


class Timeline:
    """A fake operation plus the fake clock that watches it.

    Time only moves when the *operation* runs, by the next scripted duration.
    Reading the clock is free, which matters: :func:`run_timed` reads it more
    than twice per invocation (there is a budget check), so a clock that
    advanced on every read would silently inflate every measurement and the
    tests below would be asserting against the fixture rather than the code.
    """

    def __init__(self, durations_ms: list[float]) -> None:
        self.durations = list(durations_ms)
        self.now = 1000.0
        self.calls: list[int] = []

    def clock(self) -> float:
        return self.now

    def call(self, index: int) -> None:
        self.calls.append(index)
        self.now += self.durations.pop(0) / 1000.0


def timings(samples, warmup=(), cold=None, label="op"):
    return Timings(
        label=label,
        samples_ms=tuple(samples),
        warmup_ms=tuple(warmup),
        cold_ms=cold,
    )


# ------------------------------------------------------------------ percentile


def test_percentile_is_nearest_rank_and_never_interpolates():
    values = [1.0, 2.0, 3.0, 4.0]
    # ceil(0.5 * 4) = 2 -> the 2nd smallest. An interpolating percentile would
    # answer 2.5, which is a number that was never measured.
    assert percentile(values, 50) == 2.0
    assert percentile(values, 75) == 3.0
    assert percentile(values, 100) == 4.0


def test_percentile_over_1_to_100_hits_the_documented_ranks():
    values = list(range(1, 101))
    assert percentile(values, 50) == 50
    assert percentile(values, 95) == 95
    assert percentile(values, 99) == 99


def test_percentile_over_50_runs_reports_a_measured_run():
    values = [float(i) for i in range(1, 51)]
    # 50 runs: p95 is the 48th slowest (ceil(0.95*50) = 48), p99 the 50th.
    assert percentile(values, 95) == 48.0
    assert percentile(values, 99) == 50.0
    assert percentile(values, 99) == max(values)


def test_percentile_ignores_input_order():
    ordered = [1.0, 5.0, 9.0, 12.0, 40.0]
    shuffled = [40.0, 1.0, 12.0, 5.0, 9.0]
    for q in (50, 95, 99):
        assert percentile(ordered, q) == percentile(shuffled, q)


def test_percentile_of_a_single_sample_is_that_sample():
    assert percentile([7.5], 50) == 7.5
    assert percentile([7.5], 99) == 7.5


@pytest.mark.parametrize("q", [0, -1, 100.1, 1000])
def test_percentile_rejects_quantiles_outside_the_unit_range(q):
    with pytest.raises(ValueError):
        percentile([1.0, 2.0], q)


def test_percentile_and_mean_reject_an_empty_sample():
    with pytest.raises(ValueError):
        percentile([], 50)
    with pytest.raises(ValueError):
        mean([])


# --------------------------------------------------------------------- summary


def test_summary_reports_cold_separately_from_the_percentiles():
    result = timings(samples=[10.0, 11.0, 12.0], warmup=[900.0], cold=900.0)
    summary = result.summary()
    assert summary["cold_ms"] == 900.0
    assert summary["warmup_runs"] == 1
    assert summary["n"] == 3
    # The cold run is nowhere in the warm statistics.
    assert summary["max_ms"] == 12.0
    assert summary["p99_ms"] == 12.0


def test_summary_always_carries_cold_ms_so_it_cannot_be_quietly_dropped():
    assert "cold_ms" in timings([1.0]).summary()


def test_summary_emits_the_three_headline_quantiles():
    summary = timings([float(i) for i in range(1, 51)]).summary()
    assert summary["p50_ms"] == 25.0
    assert summary["p95_ms"] == 48.0
    assert summary["p99_ms"] == 50.0
    assert summary["min_ms"] == 1.0
    assert summary["mean_ms"] == 25.5


# -------------------------------------------------------------------- run_timed


def test_run_timed_excludes_warmup_from_the_sample():
    # 5 warmup runs of 100 ms, then 50 measured runs of 1..50 ms.
    line = Timeline([100.0] * 5 + [float(i) for i in range(1, 51)])
    result = run_timed(line.call, label="op", runs=50, warmup=5, clock=line.clock)

    assert len(line.calls) == 55
    assert result.warmup_ms == pytest.approx((100.0,) * 5)
    assert result.samples_ms == pytest.approx(tuple(float(i) for i in range(1, 51)))
    assert result.cold_ms == pytest.approx(100.0)
    summary = result.summary()
    assert summary["n"] == 50
    assert summary["p50_ms"] == pytest.approx(25.0)
    assert summary["p95_ms"] == pytest.approx(48.0)
    assert summary["p99_ms"] == pytest.approx(50.0)
    assert summary["cold_ms"] == pytest.approx(100.0)
    # The 100 ms warmup runs would have moved every one of these if they had
    # leaked into the sample.
    assert summary["max_ms"] == pytest.approx(50.0)


def test_run_timed_passes_a_monotonic_index_so_an_operation_can_vary_its_input():
    line = Timeline([1.0] * 8)
    run_timed(line.call, label="op", runs=5, warmup=3, clock=line.clock)
    assert line.calls == [0, 1, 2, 3, 4, 5, 6, 7]


def test_run_timed_with_no_warmup_still_reports_the_first_call_as_cold():
    line = Timeline([42.0, 1.0, 2.0])
    result = run_timed(line.call, label="op", runs=3, warmup=0, clock=line.clock)
    assert result.warmup_ms == ()
    assert result.cold_ms == pytest.approx(42.0)
    # The cold run is inside the sample only because no warmup was requested,
    # and the summary still names it.
    assert result.samples_ms == pytest.approx((42.0, 1.0, 2.0))
    assert result.summary()["cold_ms"] == pytest.approx(42.0)


def test_run_timed_budget_truncates_the_sample_and_n_says_so():
    # Ten runs of 100 ms each with a 250 ms budget: the third run is the one
    # that crosses it, so three samples survive.
    line = Timeline([100.0] * 10)
    result = run_timed(
        line.call, label="op", runs=10, warmup=0, clock=line.clock, budget_s=0.25
    )
    assert result.summary()["n"] == 3
    assert result.samples_ms == pytest.approx((100.0, 100.0, 100.0))
    assert len(line.calls) == 3


def test_run_timed_budget_does_not_apply_to_warmup():
    line = Timeline([100.0] * 3 + [10.0] * 2)
    result = run_timed(
        line.call, label="op", runs=2, warmup=3, clock=line.clock, budget_s=0.25
    )
    assert len(result.warmup_ms) == 3
    assert result.samples_ms == pytest.approx((10.0, 10.0))


@pytest.mark.parametrize(("runs", "warmup"), [(0, 5), (-1, 0), (10, -1)])
def test_run_timed_rejects_impossible_plans(runs, warmup):
    with pytest.raises(ValueError):
        run_timed(lambda _: None, label="op", runs=runs, warmup=warmup)


def test_run_timed_meta_survives_into_the_summary():
    line = Timeline([1.0, 1.0])
    result = run_timed(
        line.call,
        label="op",
        runs=2,
        warmup=0,
        clock=line.clock,
        meta={"result_rows_max": 197},
    )
    assert result.summary()["meta"]["result_rows_max"] == 197
