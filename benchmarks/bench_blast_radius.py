#!/usr/bin/env python3
"""Measure Hindsight's incident queries against a live HydraDB node.

    python3 benchmarks/bench_blast_radius.py measure --corpus real
    python3 benchmarks/bench_blast_radius.py seed --size 50
    python3 benchmarks/bench_blast_radius.py measure --corpus 50 --out results.json

Four families of measurement, all against the node, none of them mocked:

``exposure-as-of``
    the headline. *Which repositories in the org had a lockfile resolving this
    package at instant T, and was any of those versions a malicious one.* This
    is the whole org in one answer, not one repository at a time, and it is
    exactly what ``hindsight_web.service.Console.exposure`` runs.

``blast radius``
    the same traversal plus the package's maintainer accounts, shaped into the
    node-link graph the console draws.

``maintainer reach``
    one account's trust radius, and the ranked sweep over every account. The
    sweep is the operation with a three-order-of-magnitude cold/warm gap, so it
    is reported as two separate rows and never as one.

``ingest throughput``
    edges/sec, taken from the run that actually wrote a corpus (see
    :mod:`benchmarks.corpus`). It is not re-measurable on a seeded corpus:
    the ingest is idempotent, so a second run writes nothing.

Honesty rules the harness enforces on itself:

* the first invocation of every operation is reported as ``cold_ms``, on its own
  row, and is never inside the percentile sample;
* an operation whose answer comes from an in-process cache is labelled as a
  cache hit in its own name, so no reader can mistake it for a query;
* ``exposure-as-of (scrub)`` re-runs the headline query at a *different* instant
  every time, which is the direct answer to "you are just measuring one warm
  cache entry";
* every row carries the number of result rows the query actually returned, so a
  fast number that turns out to be a fast empty answer is visible.
"""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.corpus import (  # noqa: E402
    CorpusSpec,
    RealCorpus,
    read_patterns,
    seed,
)
from benchmarks.stats import Timings, run_timed  # noqa: E402
from hindsight.client import HydraClient, HydraError  # noqa: E402
from hindsight_web import queries  # noqa: E402
from hindsight_web.analysis import classify, sort_key, summarize  # noqa: E402
from hindsight_web.incident import load_incident  # noqa: E402
from hindsight_web.paging import DEFAULT_ROW_CAP, fetch_all  # noqa: E402
from hindsight_web.service import RANK_WORKERS  # noqa: E402

#: The instant the demo scrubs to: inside the chalk/debug exposure window, after
#: the wave-1 burst and before public disclosure.
DEFAULT_AT = int(datetime(2025, 9, 8, 14, 5, tzinfo=UTC).timestamp())

#: A wave-1 compromised package, resolved by every repository in the corpus —
#: i.e. the worst case for an org-wide exposure query, not the best.
DEFAULT_PACKAGE = "debug"

#: The scrub sweep's domain. Deliberately the whole ingested span rather than
#: the incident day: instants a day apart mostly return the same rows, and a
#: sweep that cannot change its answer proves nothing about caching.
SCRUB_START = int(datetime(2024, 3, 1, tzinfo=UTC).timestamp())
SCRUB_END = int(datetime(2025, 11, 1, tzinfo=UTC).timestamp())

DEFAULT_RUNS = 50
DEFAULT_WARMUP = 5

#: Wall-clock cap on the measured runs of one operation. The maintainer sweep
#: costs seconds per run on a large corpus; 50 of those is an hour per corpus.
#: When this stops a sample early the summary's ``n`` says so.
DEFAULT_BUDGET_S = 180.0


def iso(ts: int) -> str:
    return datetime.fromtimestamp(ts, UTC).isoformat().replace("+00:00", "Z")


# --------------------------------------------------------------------- runner


@dataclass
class Runner:
    """The console's read path, re-expressed over an arbitrary corpus.

    Every statement comes from :mod:`hindsight_web.queries`, so this measures
    the shapes the product ships rather than benchmark-only Cypher. The only
    thing that differs from :class:`hindsight_web.service.Console` is where the
    anchor ids come from: a synthetic corpus salts its id space (see
    :mod:`benchmarks.corpus`), so ``corpus.package_id`` replaces the module-level
    :func:`hindsight.ids.package_id`.
    """

    client: HydraClient
    corpus: object
    package: str = DEFAULT_PACKAGE
    at: int = DEFAULT_AT
    row_cap: int = DEFAULT_ROW_CAP
    _repos: list[dict] | None = field(default=None, repr=False)
    _accounts: list[dict] | None = field(default=None, repr=False)
    _rank_cache: dict[int, list[dict]] = field(default_factory=dict, repr=False)
    _pool_clients: list[HydraClient] = field(default_factory=list, repr=False)
    truncations: int = 0

    @property
    def schema(self):
        return self.corpus.schema

    def rows(self, query: queries.Query, *, client: HydraClient | None = None) -> list[dict]:
        raw, truncated = fetch_all(
            client or self.client, query.cypher, query.params, row_cap=self.row_cap
        )
        if truncated:
            self.truncations += 1
        return [dict(zip(query.columns, row, strict=False)) for row in raw]

    # ------------------------------------------------------------- directories

    def repositories(self) -> list[dict]:
        if self._repos is None:
            self._repos = self.rows(queries.repo_directory(self.schema))
        return self._repos

    def accounts(self) -> list[dict]:
        if self._accounts is None:
            rows = self.rows(queries.maintainer_directory(self.schema))
            self._accounts = sorted(
                ({"id": int(r["id"]), "name": str(r["name"])} for r in rows if r.get("name")),
                key=lambda a: a["name"],
            )
        return self._accounts

    def pool_clients(self) -> list[HydraClient]:
        if not self._pool_clients:
            self._pool_clients = [
                HydraClient(config=self.client.config) for _ in range(RANK_WORKERS)
            ]
        return self._pool_clients

    # --------------------------------------------------------------- exposure

    def exposure(self, at: int | None = None) -> dict:
        """The headline. Whole-org verdict for one package at one instant."""
        at = self.at if at is None else at
        incident = INCIDENT
        malicious = incident.malicious_versions(self.package)
        pid = self.corpus.package_id(self.package)

        exists = self.rows(queries.package_exists(self.schema, pid))
        hits: list[dict] = []
        if exists:
            hits = self.rows(queries.repos_resolving_package(self.schema, pid, at))

        by_slug: dict[str, list[dict]] = {}
        for row in hits:
            by_slug.setdefault(str(row.get("slug")), []).append(row)

        verdicts = [
            classify(
                str(record.get("slug")),
                by_slug.get(str(record.get("slug")), []),
                malicious,
                incident.window,
                at,
            )
            for record in self.repositories()
        ]
        verdicts.sort(key=sort_key)
        counts = summarize(verdicts)
        return {"rows": len(hits), "counts": counts, "verdicts": verdicts}

    def exposure_engine_only(self, at: int | None = None) -> dict:
        """One statement: the id-anchored two-pattern join, nothing else."""
        at = self.at if at is None else at
        pid = self.corpus.package_id(self.package)
        hits = self.rows(queries.repos_resolving_package(self.schema, pid, at))
        return {"rows": len(hits)}

    def incident_exposure(self, at: int | None = None) -> dict:
        """The same question, entered through version ids instead of a package.

        ``repos_resolving_version`` binds one ``Ver`` node by id and walks its
        incoming RESOLVES edges; ``repos_resolving_package`` binds a ``Pkg`` and
        has the engine expand every version of it. The second shape is the one
        that falls over on the 250-repository corpus, and this is the shape that
        does not — at the cost of one round trip per malicious version rather
        than one for the whole package.

        It is a complete answer to the incident question because the incident
        file names every malicious version, and :mod:`hindsight.ids` derives a
        version id by hashing rather than by lookup. A version with no node was
        never resolved by anything in the org at any instant; that is a proven
        absence and it costs one id probe, which is why the row count below
        matters as much as the latency.
        """
        at = self.at if at is None else at
        rows = 0
        present = 0
        exposed: set[str] = set()
        for malicious in INCIDENT.versions:
            vid = self.corpus.version_id(malicious.package, malicious.version)
            found = self.rows(queries.repos_resolving_version(self.schema, vid, at))
            if found:
                present += 1
                rows += len(found)
                exposed |= {str(r.get("slug")) for r in found}
        return {
            "rows": rows,
            "versions_queried": len(INCIDENT.versions),
            "versions_resolved_by_someone": present,
            "exposed_repos": len(exposed),
        }

    def blast_radius(self, at: int | None = None) -> dict:
        """Exposure plus the package's maintainers, shaped as nodes and edges."""
        at = self.at if at is None else at
        exposure = self.exposure(at)
        pid = self.corpus.package_id(self.package)
        maint = self.rows(queries.maintainers_of_package(self.schema, pid))
        maintainers = sorted({str(r["maintainer"]) for r in maint if r.get("maintainer")})

        nodes = 1 + len(maintainers)
        edges = len(maintainers)
        seen: set[str] = set()
        for repo in exposure["verdicts"]:
            if repo["status"] == "NOT_RESOLVED":
                continue
            nodes += 1
            for version in repo["versions"]:
                key = version["version"]
                if key not in seen:
                    seen.add(key)
                    nodes += 1
                    edges += 1
                edges += 1
        return {
            "rows": exposure["rows"],
            "nodes": nodes,
            "edges": edges,
            "versions": len(seen),
            "maintainers": len(maintainers),
            "counts": exposure["counts"],
        }

    # ------------------------------------------------------- maintainer reach

    def maintainer_reach(self, name: str, at: int | None = None) -> dict:
        at = self.at if at is None else at
        mid = self.corpus.maintainer_id(name)
        owned = self.rows(queries.maintained_packages(self.schema, mid))
        rows = self.rows(queries.maintainer_reach(self.schema, mid, at))
        pairs = {(str(r.get("slug")), str(r.get("package"))) for r in rows}
        return {
            "rows": len(rows),
            "maintains": len(owned),
            "reached_repos": len({slug for slug, _ in pairs}),
            "repo_package_pairs": len(pairs),
        }

    def _score(self, account: dict, at: int, client: HydraClient) -> dict:
        """Score one account, recording an engine refusal rather than raising.

        On a large corpus this query can exceed HydraDB's 30 s query timeout —
        especially under the sweep's own six-way concurrency. That is a result,
        not a crash: an operation that cannot complete has to appear in the
        table as an operation that cannot complete.
        """
        try:
            rows = self.rows(
                queries.maintainer_reach(self.schema, account["id"], at), client=client
            )
        except HydraError as exc:
            return {
                "maintainer": account["name"],
                "rows": 0,
                "reached_repo_count": 0,
                "reached_package_count": 0,
                "repo_package_pairs": 0,
                "error": str(exc)[:160],
            }
        pairs = {(str(r.get("slug")), str(r.get("package"))) for r in rows}
        return {
            "maintainer": account["name"],
            "rows": len(rows),
            "reached_repo_count": len({slug for slug, _ in pairs}),
            "reached_package_count": len({pkg for _, pkg in pairs}),
            "repo_package_pairs": len(pairs),
        }

    def maintainer_ranking(self, at: int | None = None, *, use_cache: bool = True) -> dict:
        """Every account scored and ranked. The expensive one.

        One id-anchored read per account across :data:`RANK_WORKERS` threads —
        the shape ``hindsight_web.service.Console.maintainer_ranking`` settled
        on after measuring the whole-graph join and the fold-client-side
        alternatives against it.
        """
        at = self.at if at is None else at
        cached = self._rank_cache.get(at) if use_cache else None
        if cached is not None:
            return {"cached": True, "accounts": len(cached), "rows": 0}

        accounts = self.accounts()
        clients = self.pool_clients()
        with ThreadPoolExecutor(max_workers=RANK_WORKERS) as pool:
            scored = list(
                pool.map(
                    lambda pair: self._score(pair[1], at, clients[pair[0] % RANK_WORKERS]),
                    enumerate(accounts),
                )
            )
        scored.sort(
            key=lambda s: (-s["repo_package_pairs"], -s["reached_package_count"], s["maintainer"])
        )
        self._rank_cache[at] = scored
        failed = [s for s in scored if s.get("error")]
        return {
            "cached": False,
            "accounts": len(scored),
            "rows": sum(s["rows"] for s in scored),
            "errors": len(failed),
            "first_error": failed[0]["error"] if failed else None,
            "top": scored[0]["maintainer"] if scored else None,
        }


INCIDENT = load_incident()


# ------------------------------------------------------------------ operations


def scrub_instants(count: int) -> list[int]:
    """``count`` distinct instants spread evenly over the ingested span."""
    if count < 2:
        return [DEFAULT_AT]
    step = (SCRUB_END - SCRUB_START) / (count - 1)
    return [int(SCRUB_START + step * i) for i in range(count)]


#: Above this, an operation gets one warmup run instead of five. Five warmup
#: sweeps of a 250-repository corpus is over an hour of wall clock spent on runs
#: that are then discarded.
SLOW_OP_MS = 1000.0

#: Below this many measured runs the sample is not summarised as percentiles at
#: all — it is reported as the handful of observations it is.
MIN_SAMPLE = 3


def plan_from_probe(probe_ms: float, runs: int, warmup: int, budget_s: float) -> tuple[int, int]:
    """How many measured and warmup runs an operation of this cost gets.

    Cheap operations get exactly what was asked for. An operation costing more
    than a second per run gets one warmup and as many measured runs as the
    budget affords — never fewer than :data:`MIN_SAMPLE`, because three
    observations reported as three observations is honest and one percentile
    over one run is not.
    """
    if probe_ms <= SLOW_OP_MS:
        return runs, warmup
    affordable = int(budget_s // (probe_ms / 1000.0))
    return max(MIN_SAMPLE, min(runs, affordable)), 1


def measure_corpus(
    runner: Runner,
    *,
    runs: int,
    warmup: int,
    budget_s: float,
    maintainers: bool = True,
    log=print,
) -> list[Timings]:
    """Run every operation against one corpus and return the raw timings.

    ``maintainers=False`` measures only the exposure and blast-radius family.
    That exists for the controlled re-run: the scaling curve is only a scaling
    curve if every corpus is measured against the *same* node state, and
    re-measuring every corpus in one pass is affordable only without the
    maintainer sweep, which costs five minutes per corpus at the top end.
    """
    results: list[Timings] = []
    sweep = scrub_instants(runs + warmup)
    counters: dict[str, list[int]] = {}

    def record(name: str, value: int) -> None:
        counters.setdefault(name, []).append(value)

    def rowmeta(name: str) -> dict:
        seen = counters.get(name) or [0]
        return {
            "result_rows_min": min(seen),
            "result_rows_max": max(seen),
            "invocations": len(seen),
        }

    top_account = None

    def op_exposure(_: int) -> None:
        record("exposure", runner.exposure()["rows"])

    def op_exposure_scrub(i: int) -> None:
        record("exposure_scrub", runner.exposure(sweep[i % len(sweep)])["rows"])

    def op_engine(_: int) -> None:
        record("engine", runner.exposure_engine_only()["rows"])

    def op_blast(_: int) -> None:
        record("blast", runner.blast_radius()["rows"])

    def op_incident(_: int) -> None:
        record("incident", runner.incident_exposure()["rows"])

    refusals: list[str] = []

    def op_reach(_: int) -> None:
        try:
            record("reach", runner.maintainer_reach(top_account)["rows"])
        except HydraError as exc:
            # The refusal took real time and is part of the distribution.
            refusals.append(str(exc)[:160])
            record("reach", 0)

    def op_rank_cold(i: int) -> None:
        # A different instant every run, so the in-process cache can never
        # answer: this is the true per-request cost when the scrubber moves.
        record("rank_cold", runner.maintainer_ranking(sweep[i % len(sweep)], use_cache=False)["rows"])

    def op_rank_warm(_: int) -> None:
        runner.maintainer_ranking(DEFAULT_AT, use_cache=True)

    # Answer shape first, so a fast-but-empty result is caught before timing.
    probe = runner.exposure()
    blast = runner.blast_radius()
    incident = runner.incident_exposure()
    log(
        f"  corpus {runner.corpus.node_prefix}: {len(runner.repositories())} repos, "
        f"exposure returns {probe['rows']} rows, counts={probe['counts']}"
    )
    log(
        f"  incident sweep: {incident['versions_queried']} malicious versions, "
        f"{incident['versions_resolved_by_someone']} of them resolved by someone, "
        f"{incident['rows']} rows, {incident['exposed_repos']} exposed repos"
    )

    plan = [
        ("exposure-as-of (org-wide, fixed T)", op_exposure, "exposure", runs, warmup),
        ("exposure-as-of (scrub, T varies every run)", op_exposure_scrub, "exposure_scrub", runs, warmup),
        ("exposure-as-of (engine only, one statement)", op_engine, "engine", runs, warmup),
        ("blast radius (repos + versions + maintainers)", op_blast, "blast", runs, warmup),
        ("incident sweep (all malicious versions, version-anchored)", op_incident, "incident", runs, warmup),
    ]
    for label, fn, key, n, w in plan:
        timing = run_timed(
            fn, label=label, runs=n, warmup=w, budget_s=budget_s, meta=rowmeta(key)
        )
        results.append(
            Timings(
                label=timing.label,
                samples_ms=timing.samples_ms,
                warmup_ms=timing.warmup_ms,
                cold_ms=timing.cold_ms,
                meta=rowmeta(key),
            )
        )
        s = results[-1].summary()
        log(
            f"    {label:<48} n={s['n']:<3} cold={s['cold_ms']:>10.3f}  "
            f"p50={s['p50_ms']:>9.3f}  p95={s['p95_ms']:>9.3f}  p99={s['p99_ms']:>9.3f} ms"
        )

    accounts = runner.accounts() if maintainers else []
    if accounts:
        # The sweep's own probe is the expensive one, so it is timed and kept
        # rather than thrown away: on a large corpus it may be the only
        # observation this operation gets.
        sweep_started = time.perf_counter()
        ranked = runner.maintainer_ranking(DEFAULT_AT, use_cache=False)
        sweep_probe_ms = (time.perf_counter() - sweep_started) * 1000
        scored = runner._rank_cache[DEFAULT_AT]
        ok = [s for s in scored if not s.get("error")]
        top_account = ok[0]["maintainer"] if ok else None
        runner._rank_cache.clear()
        log(
            f"    ranked {ranked['accounts']} accounts in {sweep_probe_ms:.0f} ms "
            f"({ranked['errors']} engine refusals); widest reach that completed: {top_account}"
        )
        if ranked["errors"]:
            log(f"    first refusal: {ranked['first_error']}")

        sweep_meta = {
            "accounts": len(accounts),
            "engine_errors": ranked["errors"],
            "first_error": ranked["first_error"],
        }
        if ranked["errors"]:
            # An operation the engine refuses to complete is reported as the
            # single observation it is, never as a percentile over retries.
            results.append(
                Timings(
                    label="maintainer reach (ranked sweep, all accounts, UNCACHED)",
                    samples_ms=(sweep_probe_ms,),
                    warmup_ms=(),
                    cold_ms=sweep_probe_ms,
                    meta=sweep_meta
                    | {
                        "note": (
                            "single observation, not a percentile: the engine "
                            "refused some accounts at this corpus size, so the "
                            "operation does not produce a complete answer here"
                        ),
                        "complete_answer": False,
                    },
                )
            )
            log(
                "    maintainer reach (ranked sweep) INCOMPLETE at this corpus size: "
                f"{ranked['errors']}/{ranked['accounts']} accounts refused, "
                f"one sweep took {sweep_probe_ms:.0f} ms"
            )

        slow_plan: list[tuple] = []
        if top_account is not None:
            reach_started = time.perf_counter()
            try:
                runner.maintainer_reach(top_account)
                reach_error = None
            except HydraError as exc:
                reach_error = str(exc)[:160]
            reach_probe_ms = (time.perf_counter() - reach_started) * 1000
            slow_plan.append(
                (
                    f"maintainer reach (one account: {top_account})",
                    op_reach,
                    "reach",
                    *plan_from_probe(reach_probe_ms, runs, warmup, budget_s),
                    {
                        "probe_ms": round(reach_probe_ms, 3),
                        "account": top_account,
                        "probe_error": reach_error,
                    },
                )
            )
        if not ranked["errors"]:
            slow_plan.append(
                (
                    "maintainer reach (ranked sweep, all accounts, UNCACHED)",
                    op_rank_cold,
                    "rank_cold",
                    *plan_from_probe(sweep_probe_ms, runs, warmup, budget_s),
                    sweep_meta,
                )
            )
        slow_plan.append(
            (
                "maintainer reach (ranked sweep, in-process CACHE HIT)",
                op_rank_warm,
                "rank_warm",
                runs,
                warmup,
                sweep_meta | {"note": "a dict lookup in the web process, not a query"},
            )
        )

        for label, fn, key, n, w, extra in slow_plan:
            timing = run_timed(fn, label=label, runs=n, warmup=w, budget_s=budget_s)
            results.append(
                Timings(
                    label=timing.label,
                    samples_ms=timing.samples_ms,
                    warmup_ms=timing.warmup_ms,
                    cold_ms=timing.cold_ms,
                    meta=rowmeta(key) | extra,
                )
            )
            s = results[-1].summary()
            log(
                f"    {label:<48} n={s['n']:<3} cold={s['cold_ms']:>10.3f}  "
                f"p50={s['p50_ms']:>9.3f}  p95={s['p95_ms']:>9.3f}  p99={s['p99_ms']:>9.3f} ms"
            )

    if refusals:
        for result in results:
            if result.label.startswith("maintainer reach (one account"):
                result.meta["engine_refusals_during_sample"] = len(refusals)
                result.meta["first_refusal"] = refusals[0]
        log(f"    {len(refusals)} engine refusal(s) inside the single-account sample")

    log(
        f"    blast-radius answer: {blast['nodes']} nodes / {blast['edges']} edges, "
        f"{blast['maintainers']} maintainer accounts; row-cap truncations: {runner.truncations}"
    )
    return results


# ------------------------------------------------------------------ environment


def hardware() -> dict:
    def out(cmd: list[str]) -> str:
        try:
            return subprocess.run(
                cmd, capture_output=True, text=True, timeout=30, check=False
            ).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return ""

    chip = ""
    memory = ""
    for line in out(["system_profiler", "SPHardwareDataType"]).splitlines():
        if "Chip:" in line:
            chip = line.split(":", 1)[1].strip()
        if "Memory:" in line:
            memory = line.split(":", 1)[1].strip()
    digest = out(
        [
            "docker",
            "image",
            "inspect",
            "ghcr.io/hydra-db/hydradb:latest",
            "--format",
            "{{index .RepoDigests 0}}",
        ]
    )
    return {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "chip": chip,
        "memory": memory,
        "hydradb_image": digest,
        "docker": out(["docker", "version", "--format", "{{.Server.Version}}"]),
        "docker_cpus_mem": out(["docker", "info", "--format", "{{.NCPU}} cpu / {{.MemTotal}} B"]),
    }


def corpus_stats(client: HydraClient, corpus) -> dict:
    """Node and edge counts for a corpus. The edge count is a scan; it is slow."""
    schema = corpus.schema
    stats: dict = {"node_prefix": corpus.node_prefix}
    for name, label in (
        ("repos", schema.repo),
        ("packages", schema.package),
        ("versions", schema.version),
        ("maintainers", schema.maintainer),
    ):
        rows = client.rows(f"MATCH (n:{label}) RETURN count(*)")
        stats[name] = int(rows[0][0]) if rows and rows[0] else 0

    started = time.perf_counter()
    edges = 0
    ids, _ = fetch_all(client, f"MATCH (r:{schema.repo}) RETURN r.id", {}, row_cap=100_000)
    for (rid,) in ids:
        rows = client.rows(
            f"MATCH (r:{schema.repo} {{id: $rid}})-[e:{schema.resolves}]->"
            f"(v:{schema.version}) WHERE e.valid_from >= 0 RETURN count(*)",
            {"rid": int(rid)},
        )
        edges += int(rows[0][0]) if rows and rows[0] else 0
    stats["resolves_edges"] = edges
    stats["resolves_count_seconds"] = round(time.perf_counter() - started, 2)
    stats["nodes"] = stats["repos"] + stats["packages"] + stats["versions"] + stats["maintainers"]
    return stats


# ------------------------------------------------------------------------ main


def resolve_corpus(name: str):
    if name == "real":
        return RealCorpus()
    return CorpusSpec(repos=int(name))


def restart_node(container: str, *, wait_s: float = 120.0, log=print) -> float:
    """Restart the HydraDB container and block until it answers. Returns seconds.

    This is the only way to measure a genuinely cold read. A fresh Python
    process clears the console's caches but not the engine's, and a benchmark
    that reports "cold" while the node has every relevant page resident is
    reporting a warm number with a cold label.
    """
    started = time.perf_counter()
    subprocess.run(["docker", "restart", container], check=True, capture_output=True)
    client = HydraClient.from_env()
    while time.perf_counter() - started < wait_s:
        try:
            client.query("MATCH (probe:BenchStartupProbe {id: 1}) RETURN probe.id")
            elapsed = time.perf_counter() - started
            log(f"  {container} restarted and answering after {elapsed:.1f}s")
            return elapsed
        except Exception:  # noqa: BLE001 - the node is expected to refuse for a while
            time.sleep(1.0)
    raise SystemExit(f"{container} did not become ready within {wait_s}s")


def cold_start(container: str, corpora: list[str], package: str, at: int) -> dict:
    """One measured call per corpus, immediately after a container restart.

    The order matters and is recorded: the first corpus queried pays whatever
    process-wide startup cost exists, the later ones do not, so a reader can see
    how much of "cold" is the node and how much is the first request of any kind.
    """
    restart_seconds = restart_node(container)
    client = HydraClient.from_env()
    out = []
    for index, name in enumerate(corpora):
        corpus = resolve_corpus(name)
        runner = Runner(client=client, corpus=corpus, package=package, at=at)
        directory_started = time.perf_counter()
        repos = len(runner.repositories())
        directory_ms = (time.perf_counter() - directory_started) * 1000

        started = time.perf_counter()
        answer = runner.exposure()
        cold_ms = (time.perf_counter() - started) * 1000

        started = time.perf_counter()
        runner.exposure()
        second_ms = (time.perf_counter() - started) * 1000
        out.append(
            {
                "corpus": name,
                "query_order": index + 1,
                "repos": repos,
                "repo_directory_ms": round(directory_ms, 3),
                "node_cold_exposure_ms": round(cold_ms, 3),
                "second_call_ms": round(second_ms, 3),
                "result_rows": answer["rows"],
                "counts": answer["counts"],
            }
        )
        print(
            f"  {name:<6} repos={repos:<4} directory={directory_ms:8.2f} ms  "
            f"node-cold exposure={cold_ms:8.2f} ms  second call={second_ms:8.2f} ms"
        )
    return {
        "container": container,
        "restart_to_ready_seconds": round(restart_seconds, 2),
        "at": at,
        "at_iso": iso(at),
        "package": package,
        "corpora": out,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="benchmarks/bench_blast_radius.py")
    sub = parser.add_subparsers(dest="command", required=True)

    seed_cmd = sub.add_parser("seed", help="write a synthetic BenchN<size> corpus")
    seed_cmd.add_argument("--size", type=int, required=True)
    seed_cmd.add_argument("--batch", type=int, default=1000)
    seed_cmd.add_argument("--repo-chunk", type=int, default=20)
    seed_cmd.add_argument("--refresh-patterns", action="store_true")
    seed_cmd.add_argument("--out", type=Path)

    run_cmd = sub.add_parser("measure", help="time the incident queries")
    run_cmd.add_argument("--corpus", default="real", help="'real' or a BenchN size")
    run_cmd.add_argument("--package", default=DEFAULT_PACKAGE)
    run_cmd.add_argument("--at", type=int, default=DEFAULT_AT)
    run_cmd.add_argument("--runs", type=int, default=DEFAULT_RUNS)
    run_cmd.add_argument("--warmup", type=int, default=DEFAULT_WARMUP)
    run_cmd.add_argument("--budget-s", type=float, default=DEFAULT_BUDGET_S)
    run_cmd.add_argument("--skip-edge-count", action="store_true")
    run_cmd.add_argument(
        "--skip-maintainers",
        action="store_true",
        help="measure only the exposure/blast-radius family (for controlled re-runs)",
    )
    run_cmd.add_argument("--out", type=Path)

    cold_cmd = sub.add_parser(
        "coldstart",
        help="restart the node and measure the first query against a cold engine",
    )
    cold_cmd.add_argument("--container", default="hydradb-poc")
    cold_cmd.add_argument("--corpora", nargs="+", default=["real"])
    cold_cmd.add_argument("--package", default=DEFAULT_PACKAGE)
    cold_cmd.add_argument("--at", type=int, default=DEFAULT_AT)
    cold_cmd.add_argument("--out", type=Path)

    args = parser.parse_args(argv)
    client = HydraClient.from_env()

    if args.command == "coldstart":
        payload = cold_start(args.container, args.corpora, args.package, args.at)
        payload["environment"] = hardware()
        if args.out:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(json.dumps(payload, indent=2) + "\n")
            print(f"  wrote {args.out}")
        return 0

    if args.command == "seed":
        patterns = read_patterns(client, refresh=args.refresh_patterns)
        spec = CorpusSpec(repos=args.size)
        report = seed(
            client, spec, patterns, batch=args.batch, repo_chunk=args.repo_chunk
        )
        payload = {"seed": report.as_dict(), "environment": hardware()}
        print(json.dumps(payload["seed"], indent=2))
        if args.out:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(json.dumps(payload, indent=2) + "\n")
        return 0

    corpus = resolve_corpus(args.corpus)
    runner = Runner(client=client, corpus=corpus, package=args.package, at=args.at)
    print(f"benchmark: corpus={corpus.node_prefix} package={args.package} at={iso(args.at)}")

    stats = (
        {"node_prefix": corpus.node_prefix, "resolves_edges": None}
        if args.skip_edge_count
        else corpus_stats(client, corpus)
    )
    print(f"  corpus stats: {stats}")

    started = time.perf_counter()
    timings = measure_corpus(
        runner,
        runs=args.runs,
        warmup=args.warmup,
        budget_s=args.budget_s,
        maintainers=not args.skip_maintainers,
    )
    payload = {
        "generated_at": iso(int(time.time())),
        "corpus": args.corpus,
        "package": args.package,
        "at": args.at,
        "at_iso": iso(args.at),
        "runs_requested": args.runs,
        "warmup": args.warmup,
        "budget_s": args.budget_s,
        "row_cap": runner.row_cap,
        "truncations": runner.truncations,
        "corpus_stats": stats,
        "environment": hardware(),
        "wall_seconds": round(time.perf_counter() - started, 2),
        "measurements": [t.summary() for t in timings],
    }
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(payload, indent=2) + "\n")
        print(f"  wrote {args.out}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
