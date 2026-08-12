"""Batched UNWIND writer.

Only a narrow set of mutation shapes is executable on HydraDB. The ones used
here, all verified against a live node:

    nodes  UNWIND $rows AS row MERGE (n {id: row.id}) SET n:Label, n.p = row.p
    edges  UNWIND $rows AS row
           MATCH (s:L1 {id: row.s}), (d:L2 {id: row.d})
           MERGE (s)-[e:REL {id: row.id}]->(d) SET e.p = row.p

The edge form matters. The PoC used ``CREATE``, which duplicates on re-run and
cannot revise a fact. ``MERGE`` on the relationship is accepted as long as the
pattern carries *only* ``id`` and every other property is applied by a trailing
``SET`` — the engine says so itself ("UNWIND relationship MERGE pattern matches
only id; apply properties with SET"). It costs about a third of the throughput
of ``CREATE`` (8.1k vs 12.1k edges/sec, batch 1000, local node) and buys exact
idempotency plus in-place interval closing, which on an append-only store where
deletes run at ~3/sec is not a close call.

Idempotency therefore rests on two things:

1. deterministic ids (:mod:`hindsight.ids`) — the same fact always mints the
   same id, on any machine, on any run;
2. a per-repo watermark node holding the newest commit timestamp ingested, so a
   re-run resends only the intervals that could still change.

Re-running an unchanged repo writes zero new edges and leaves counts identical.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from .client import HydraClient
from .graphbuild import (
    DEFAULT_SCHEMA,
    RowSets,
    Schema,
    filter_by_watermark,
    stale_repos,
    stamp_tx,
)
from .history import SENTINEL
from .ids import watermark_id

#: HydraDB caps UNWIND at 1024 items.
MAX_BATCH = 1000


def node_upsert(label: str, props: dict[str, str]) -> str:
    sets = ", ".join(f"n.{name} = row.{src}" for name, src in props.items())
    return f"UNWIND $rows AS row MERGE (n {{id: row.id}}) SET n:{label}, {sets}"


def edge_upsert(rel: str, src_label: str, dst_label: str, props: dict[str, str]) -> str:
    head = (
        f"UNWIND $rows AS row "
        f"MATCH (s:{src_label} {{id: row.s}}), (d:{dst_label} {{id: row.d}}) "
        f"MERGE (s)-[e:{rel} {{id: row.id}}]->(d)"
    )
    if not props:
        return head
    sets = ", ".join(f"e.{name} = row.{src}" for name, src in props.items())
    return f"{head} SET {sets}"


@dataclass
class Step:
    label: str
    cypher: str
    rows: list[dict]
    kind: str  # "node" | "edge"


@dataclass
class StepReport:
    label: str
    kind: str
    rows: int
    seconds: float
    batches: int

    @property
    def rows_per_sec(self) -> float:
        return self.rows / self.seconds if self.seconds else 0.0

    def as_dict(self) -> dict:
        return {
            "label": self.label,
            "kind": self.kind,
            "rows": self.rows,
            "seconds": round(self.seconds, 3),
            "rows_per_sec": round(self.rows_per_sec, 1),
            "batches": self.batches,
        }


@dataclass
class IngestReport:
    tx_from: int
    dry_run: bool
    batch: int
    steps: list[StepReport] = field(default_factory=list)
    skipped_resolves: int = 0
    skipped_stale: int = 0
    stale_repos: list[str] = field(default_factory=list)
    watermarks_before: dict[str, int] = field(default_factory=dict)
    watermarks_after: dict[str, int] = field(default_factory=dict)

    @property
    def nodes_written(self) -> int:
        return sum(s.rows for s in self.steps if s.kind == "node")

    @property
    def edges_written(self) -> int:
        return sum(s.rows for s in self.steps if s.kind == "edge")

    @property
    def seconds(self) -> float:
        return sum(s.seconds for s in self.steps)

    def as_dict(self) -> dict:
        return {
            "tx_from": self.tx_from,
            "dry_run": self.dry_run,
            "batch": self.batch,
            "nodes": self.nodes_written,
            "edges": self.edges_written,
            "skipped_resolves": self.skipped_resolves,
            "skipped_stale": self.skipped_stale,
            "stale_repos": self.stale_repos,
            "seconds": round(self.seconds, 3),
            "steps": [s.as_dict() for s in self.steps],
            "watermarks_before": self.watermarks_before,
            "watermarks_after": self.watermarks_after,
        }


def chunks(rows: list[dict], size: int):
    for i in range(0, len(rows), size):
        yield rows[i : i + size]


@dataclass
class Ingestor:
    client: HydraClient
    schema: Schema = DEFAULT_SCHEMA
    batch: int = MAX_BATCH
    progress: object | None = None  # any callable(str) -> None

    def __post_init__(self) -> None:
        self.batch = max(1, min(self.batch, MAX_BATCH))

    # ---------------------------------------------------------------- queries

    def _say(self, message: str) -> None:
        if callable(self.progress):
            self.progress(message)

    def read_watermarks(self, slugs: list[str]) -> dict[str, int]:
        """Newest ingested commit timestamp per repo slug, for slugs that have one."""
        out: dict[str, int] = {}
        for slug in slugs:
            rows = self.client.rows(
                f"MATCH (n:{self.schema.watermark} {{id: $id}}) RETURN n.last_commit_ts",
                {"id": watermark_id(slug)},
            )
            if rows and rows[0] and isinstance(rows[0][0], int):
                out[slug] = rows[0][0]
        return out

    def write_watermarks(self, marks: list[dict]) -> None:
        if not marks:
            return
        cypher = node_upsert(
            self.schema.watermark,
            {
                "slug": "slug",
                "repo_id": "repo_id",
                "last_commit_ts": "last_ts",
                "last_ingest_tx": "txf",
            },
        )
        for part in chunks(marks, self.batch):
            self.client.query(cypher, {"rows": part})

    def count_edges(self, rel: str | None = None) -> int:
        rel = rel or self.schema.resolves
        value = self.client.scalar(
            f"MATCH (r:{self.schema.repo})-[e:{rel}]->(v:{self.schema.version}) "
            "WHERE e.valid_from >= 0 RETURN count(*)",
            default=0,
        )
        return int(value or 0)

    def resolved_as_of(self, repo_id: int, ts: int) -> set[str]:
        """AS-OF read: package versions a repo resolved at ``ts``."""
        rows = self.client.all_rows(
            f"MATCH (r:{self.schema.repo} {{id: $rid}})"
            f"-[e:{self.schema.resolves}]->(v:{self.schema.version}) "
            "WHERE e.valid_from <= $t AND e.valid_to > $t "
            "RETURN v.key",
            {"rid": repo_id, "t": ts},
        )
        return {str(row[0]) for row in rows if row}

    # ----------------------------------------------------------------- plan

    def plan(self, rows: RowSets, tx_from: int | None = None) -> tuple[list[Step], IngestReport]:
        """Resolve watermarks, drop settled intervals and stamp transaction time."""
        tx_from = int(time.time()) if tx_from is None else tx_from
        slugs = sorted(rows.repo_slugs.values())
        before = self.read_watermarks(slugs) if slugs else {}
        by_id = {
            rid: before[slug] for rid, slug in rows.repo_slugs.items() if slug in before
        }
        # A build that saw less history than the store already holds is dropped
        # wholesale: its still-open intervals would otherwise reopen facts a
        # better-informed run had closed.
        stale = stale_repos(rows.repo_last_ts, by_id)
        fresh = [row for row in rows.resolves if row["s"] not in stale]
        skipped_stale = len(rows.resolves) - len(fresh)
        repo_nodes = [row for row in rows.repos if row["id"] not in stale]

        resolves, skipped = filter_by_watermark(fresh, by_id)
        stamp_tx(resolves, tx_from)

        s = self.schema
        steps = [
            Step(
                "repo nodes",
                node_upsert(
                    s.repo,
                    {
                        "slug": "slug",
                        "name": "name",
                        "service": "service",
                        "first_ts": "first_ts",
                        "last_ts": "last_ts",
                        "snapshots": "snapshots",
                    },
                ),
                repo_nodes,
                "node",
            ),
            Step("package nodes", node_upsert(s.package, {"name": "name"}), rows.packages, "node"),
            Step(
                "version nodes",
                node_upsert(
                    s.version,
                    {"pkg": "pkg", "version": "version", "key": "key", "pkg_id": "pkg_id"},
                ),
                rows.versions,
                "node",
            ),
            Step(
                "maintainer nodes",
                node_upsert(s.maintainer, {"name": "name"}),
                rows.maintainers,
                "node",
            ),
            Step(
                "VERSION_OF edges",
                edge_upsert(s.version_of, s.version, s.package, {}),
                rows.version_of,
                "edge",
            ),
            Step(
                "MAINTAINS edges",
                edge_upsert(s.maintains, s.maintainer, s.package, {}),
                rows.maintains,
                "edge",
            ),
            Step(
                "RESOLVES edges",
                edge_upsert(
                    s.resolves,
                    s.repo,
                    s.version,
                    {
                        "valid_from": "vf",
                        "valid_to": "vt",
                        "tx_from": "txf",
                        "tx_to": "txt",
                    },
                ),
                resolves,
                "edge",
            ),
        ]
        steps = [step for step in steps if step.rows]

        after = dict(before)
        for rid, slug in rows.repo_slugs.items():
            last = rows.repo_last_ts.get(rid, 0)
            if last > after.get(slug, 0):
                after[slug] = last

        report = IngestReport(
            tx_from=tx_from,
            dry_run=True,
            batch=self.batch,
            skipped_resolves=skipped,
            skipped_stale=skipped_stale,
            stale_repos=sorted(rows.repo_slugs[rid] for rid in stale),
            watermarks_before=before,
            watermarks_after=after,
        )
        report.steps = [
            StepReport(
                label=step.label,
                kind=step.kind,
                rows=len(step.rows),
                seconds=0.0,
                batches=(len(step.rows) + self.batch - 1) // self.batch,
            )
            for step in steps
        ]
        return steps, report

    # ---------------------------------------------------------------- execute

    def run(
        self, rows: RowSets, tx_from: int | None = None, dry_run: bool = False
    ) -> IngestReport:
        steps, report = self.plan(rows, tx_from)
        if dry_run:
            return report

        report.dry_run = False
        report.steps = []
        for step in steps:
            started = time.perf_counter()
            batches = 0
            for part in chunks(step.rows, self.batch):
                self.client.query(step.cypher, {"rows": part})
                batches += 1
            elapsed = time.perf_counter() - started
            report.steps.append(
                StepReport(step.label, step.kind, len(step.rows), elapsed, batches)
            )
            self._say(
                f"  {step.label:<18} {len(step.rows):>8,d} rows  {elapsed:6.2f}s  "
                f"{len(step.rows) / elapsed if elapsed else 0:>9,.0f}/s"
            )

        # The watermark is written last: if the run dies partway the next one
        # redoes the work rather than skipping it.
        #
        # It is `watermarks_after`, i.e. max(existing, this build), and never
        # this build's own `repo_last_ts`. That number can move *backwards* --
        # a narrower `since:`, a shallow clone, a repo whose newest lockfile
        # commit was rewritten away -- and a watermark that regresses stops
        # suppressing settled intervals, so the next run resends history it has
        # already written. A watermark is a high-water mark or it is nothing.
        self.write_watermarks(
            [
                {
                    "id": watermark_id(slug),
                    "slug": slug,
                    "repo_id": rid,
                    "last_ts": report.watermarks_after.get(slug, 0),
                    "txf": report.tx_from,
                }
                for rid, slug in sorted(rows.repo_slugs.items())
            ]
        )
        return report


__all__ = [
    "MAX_BATCH",
    "SENTINEL",
    "IngestReport",
    "Ingestor",
    "Step",
    "StepReport",
    "chunks",
    "edge_upsert",
    "node_upsert",
]
