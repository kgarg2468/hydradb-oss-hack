"""Synthetic benchmark corpora, replayed from real lockfile intervals.

The scaling curve needs orgs of 10, 50, 100 and 250 repositories. Nine real
ones exist. The gap is closed by **replay**: each synthetic repository takes one
real repository's complete interval set — every ``(package, version,
valid_from, valid_to)`` fact its committed lockfiles actually produced — and
shifts the whole timeline by a deterministic per-repo offset, so that synthetic
repositories regenerate their lockfiles at different moments the way real ones
do. Nothing about the *shape* of the data is invented: the closure sizes, the
churn rate, the package co-occurrence and the interval lengths are all
measured, and the repo-size distribution of a synthetic org is exactly the
observed distribution of the nine sources, round-robin.

**This is synthetic data and every label says so.** Corpora live under
``BenchN<size>*`` labels, disjoint from ``Hs*`` (production), ``Dep*`` (the
PoC), ``Replay*`` (the demo) and every ``*Test*`` namespace. Nothing here reads
anything but ``Replay*``, and nothing here deletes.

Ids are salted per corpus
---------------------------
HydraDB has no per-label id space. ``MERGE (n:BenchN250Pkg {id: $x})`` matches
whatever node already carries ``$x`` — under *any* label — and adds
``BenchN250Pkg`` to it. Since :mod:`hindsight.ids` derives ids from names,
seeding a package called ``debug`` under a new label would land on the demo
dataset's ``debug`` node and stamp a benchmark label onto it. Label prefixes
alone are therefore *not* isolation on write.

:class:`SaltedRegistry` closes that: every key is prefixed with the corpus salt
before hashing, so a benchmark corpus occupies a disjoint region of the 63-bit
id space and cannot touch a node it did not create. The collision check that
:class:`~hindsight.ids.IdRegistry` performs is preserved.
"""

from __future__ import annotations

import gzip
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

from hindsight.client import HydraClient
from hindsight.graphbuild import RepoInput, Schema, build_rowsets
from hindsight.history import SENTINEL, Interval
from hindsight.ids import (
    IdRegistry,
    maintainer_key,
    package_key,
    stable_id,
    version_key,
)
from hindsight.ingest import Ingestor
from hindsight_web.paging import fetch_all
from hindsight_web.queries import DEMO_SCHEMA

ROOT = Path(__file__).resolve().parent.parent

#: Where the extracted real intervals are cached. Outside the repository: it is
#: 86,380 rows of derived data that ``--refresh`` can always rebuild.
CACHE_DIR = Path(
    os.environ.get("HINDSIGHT_BENCH_CACHE", "/tmp/hindsight-bench-cache")
)
PATTERN_CACHE = CACHE_DIR / "replay-patterns.json.gz"

#: Read-only source of real intervals. Never written by anything in this module.
SOURCE_SCHEMA = DEMO_SCHEMA

MAINTAINERS_FILE = ROOT / "poc" / "maintainers.json"

#: Per-repository timeline offsets, in seconds, cycled over the synthetic org.
#: Chosen to be coprime-ish and well inside the 2024-01 … 2025-12 span of the
#: source data so that a shifted repository still has coverage at any instant
#: the console can scrub to.
OFFSET_DAYS: tuple[int, ...] = (0, 11, -7, 23, -19, 37, -31, 5, -43, 17, -13, 29)
DAY = 86_400


@dataclass
class SaltedRegistry(IdRegistry):
    """An :class:`~hindsight.ids.IdRegistry` in a disjoint id space.

    Every key is namespaced with ``salt`` before hashing, so no id this registry
    mints can collide with one derived by :mod:`hindsight.ids` for the same
    name. Collision detection is inherited unchanged.
    """

    salt: str = ""

    def mint(self, key: str) -> int:
        return super().mint(f"{self.salt}|{key}")


@dataclass(frozen=True)
class CorpusSpec:
    """One synthetic org: how many repos, and the namespace it occupies."""

    repos: int

    @property
    def node_prefix(self) -> str:
        return f"BenchN{self.repos}"

    @property
    def rel_prefix(self) -> str:
        return f"BENCHN{self.repos}"

    @property
    def salt(self) -> str:
        return f"bench-n{self.repos}"

    @property
    def schema(self) -> Schema:
        return Schema.prefixed(self.node_prefix, self.rel_prefix)

    def package_id(self, name: str) -> int:
        return stable_id(f"{self.salt}|{package_key(name)}")

    def version_id(self, name: str, version: str) -> int:
        return stable_id(f"{self.salt}|{version_key(name, version)}")

    def maintainer_id(self, name: str) -> int:
        return stable_id(f"{self.salt}|{maintainer_key(name)}")


@dataclass(frozen=True)
class RealCorpus:
    """The seeded demo dataset, addressed the way the console addresses it."""

    repos: int = 0

    @property
    def node_prefix(self) -> str:
        return "Replay"

    @property
    def schema(self) -> Schema:
        return SOURCE_SCHEMA

    @property
    def salt(self) -> str:
        return ""

    def package_id(self, name: str) -> int:
        return stable_id(package_key(name))

    def version_id(self, name: str, version: str) -> int:
        return stable_id(version_key(name, version))

    def maintainer_id(self, name: str) -> int:
        return stable_id(maintainer_key(name))


# ------------------------------------------------------------------- extraction


def read_patterns(
    client: HydraClient, *, refresh: bool = False, log=print
) -> dict[str, list[tuple[str, str, int, int]]]:
    """Every ``Replay*`` repository's intervals, cached on disk.

    Id-anchored and paged, one statement per repository — the label-wide form of
    this read is a scan. ~10 s cold for all nine repositories, after which the
    gzip cache answers in well under a second.
    """
    if PATTERN_CACHE.exists() and not refresh:
        with gzip.open(PATTERN_CACHE, "rt") as fh:
            raw = json.load(fh)
        return {
            slug: [(str(p), str(v), int(f), int(t)) for p, v, f, t in rows]
            for slug, rows in raw.items()
        }

    repos, _ = fetch_all(
        client, f"MATCH (r:{SOURCE_SCHEMA.repo}) RETURN r.id, r.slug", {}, page_size=256
    )
    out: dict[str, list[tuple[str, str, int, int]]] = {}
    cypher = (
        f"MATCH (r:{SOURCE_SCHEMA.repo} {{id: $rid}})"
        f"-[e:{SOURCE_SCHEMA.resolves}]->(v:{SOURCE_SCHEMA.version}) "
        "WHERE e.valid_from >= 0 "
        "RETURN v.pkg, v.version, e.valid_from, e.valid_to"
    )
    for rid, slug in sorted(repos, key=lambda row: str(row[1])):
        rows, truncated = fetch_all(
            client, cypher, {"rid": int(rid)}, row_cap=500_000
        )
        if truncated:
            raise SystemExit(f"{slug}: source read hit the row cap; refusing to sample")
        out[str(slug)] = [
            (str(pkg), str(ver), int(vf), int(vt)) for pkg, ver, vf, vt in rows
        ]
        log(f"  {slug:<26} {len(rows):>7,d} intervals")

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    with gzip.open(PATTERN_CACHE, "wt") as fh:
        json.dump({slug: [list(r) for r in rows] for slug, rows in out.items()}, fh)
    return out


def maintainer_overlay() -> dict[str, list[str]]:
    """``poc/maintainers.json`` inverted into maintainer -> packages."""
    if not MAINTAINERS_FILE.exists():
        return {}
    data = json.loads(MAINTAINERS_FILE.read_text())
    out: dict[str, list[str]] = {}
    for package, accounts in (data.get("packages") or {}).items():
        for account in accounts:
            out.setdefault(str(account), []).append(str(package))
    return out


# ----------------------------------------------------------------- synthesis


def shift(intervals: list[tuple[str, str, int, int]], seconds: int) -> tuple[Interval, ...]:
    """Move a whole timeline by ``seconds``, leaving open intervals open.

    A uniform shift preserves every ordering and every duration, so the
    synthetic repository has the same churn behaviour as its source and merely
    does it at a different time. ``SENTINEL`` means "still open" and is not a
    date, so it is never shifted.
    """
    return tuple(
        Interval(pkg, ver, vf + seconds, vt if vt >= SENTINEL else vt + seconds)
        for pkg, ver, vf, vt in intervals
    )


def synthesize(
    patterns: dict[str, list[tuple[str, str, int, int]]], repos: int
) -> list[RepoInput]:
    """``repos`` synthetic repositories, round-robin over the real patterns.

    Slugs are ``bench-org/<source-short-name>-NNNN`` so that every row in a
    result set names the real repository whose history it replays. Deterministic
    end to end: the same ``repos`` always produces byte-identical input, which
    is what makes re-seeding a no-op rather than a second copy of the graph.
    """
    sources = sorted(patterns)
    if not sources:
        raise SystemExit("no source patterns; run with --refresh against a seeded node")
    out: list[RepoInput] = []
    for index in range(repos):
        source = sources[index % len(sources)]
        rows = patterns[source]
        if not rows:
            continue
        offset = OFFSET_DAYS[index % len(OFFSET_DAYS)] * DAY
        intervals = shift(rows, offset)
        short = source.split("/")[-1]
        closed = [iv.valid_to for iv in intervals if iv.valid_to < SENTINEL]
        starts = [iv.valid_from for iv in intervals]
        out.append(
            RepoInput(
                slug=f"bench-org/{short}-{index:04d}",
                name=f"bench-org/{short}-{index:04d}",
                service=f"synthetic-replay-of-{source}",
                intervals=intervals,
                first_ts=min(starts),
                last_ts=max([*closed, *starts]),
                snapshots=len({iv.valid_from for iv in intervals}),
            )
        )
    return out


# -------------------------------------------------------------------- seeding


@dataclass
class SeedReport:
    """What one corpus seed wrote, and how fast."""

    spec_repos: int
    node_prefix: str
    repos: int = 0
    nodes: int = 0
    edges: int = 0
    resolves_edges: int = 0
    seconds: float = 0.0
    edge_seconds: float = 0.0
    chunks: int = 0
    steps: list[dict] = field(default_factory=list)

    @property
    def edges_per_sec(self) -> float:
        return self.edges / self.edge_seconds if self.edge_seconds else 0.0

    def as_dict(self) -> dict:
        return {
            "corpus_repos": self.spec_repos,
            "node_prefix": self.node_prefix,
            "repos_written": self.repos,
            "nodes_written": self.nodes,
            "edges_written": self.edges,
            "resolves_edges_written": self.resolves_edges,
            "wall_seconds": round(self.seconds, 3),
            "edge_write_seconds": round(self.edge_seconds, 3),
            "edges_per_sec": round(self.edges_per_sec, 1),
            "chunks": self.chunks,
            "steps": self.steps,
        }


def seed(
    client: HydraClient,
    spec: CorpusSpec,
    patterns: dict[str, list[tuple[str, str, int, int]]],
    *,
    batch: int = 1000,
    repo_chunk: int = 20,
    log=print,
) -> SeedReport:
    """Write one synthetic corpus, in chunks of repositories.

    Chunked because a 250-repository corpus is ~2.4 M interval rows and holding
    all of them as dicts before the first write is gigabytes of Python objects
    for no benefit. One :class:`SaltedRegistry` spans every chunk, so collision
    detection covers the whole corpus rather than each chunk in isolation.

    Idempotent: ids are deterministic, ``MERGE`` is the write shape, and the
    per-repo watermark suppresses intervals that are already settled. Re-running
    a completed seed writes no new edges — which also means the throughput
    numbers below are only meaningful on the run that actually wrote.
    """
    repos = synthesize(patterns, spec.repos)
    overlay = maintainer_overlay()
    registry = SaltedRegistry(salt=spec.salt)
    report = SeedReport(spec_repos=spec.repos, node_prefix=spec.node_prefix)
    started = time.perf_counter()

    for offset in range(0, len(repos), repo_chunk):
        part = repos[offset : offset + repo_chunk]
        rows = build_rowsets(part, schema=spec.schema, maintainers=overlay, registry=registry)
        ingestor = Ingestor(client, schema=spec.schema, batch=batch)
        result = ingestor.run(rows)
        report.chunks += 1
        report.repos += len(part)
        report.nodes += result.nodes_written
        report.edges += result.edges_written
        for step in result.steps:
            if step.kind == "edge":
                report.edge_seconds += step.seconds
            if step.label == "RESOLVES edges":
                report.resolves_edges += step.rows
            report.steps.append(step.as_dict())
        log(
            f"  {spec.node_prefix} repos {offset + len(part):>4,d}/{spec.repos}  "
            f"+{result.edges_written:>8,d} edges  {result.seconds:6.2f}s"
        )

    report.seconds = time.perf_counter() - started
    return report


__all__ = [
    "CACHE_DIR",
    "OFFSET_DAYS",
    "PATTERN_CACHE",
    "SOURCE_SCHEMA",
    "CorpusSpec",
    "RealCorpus",
    "SaltedRegistry",
    "SeedReport",
    "maintainer_overlay",
    "read_patterns",
    "seed",
    "shift",
    "synthesize",
]
