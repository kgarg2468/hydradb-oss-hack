#!/usr/bin/env python3
"""Load the demo dataset into HydraDB under ``Replay*`` labels.

    python3 scripts/demo-seed.py                 # plan only, writes nothing
    python3 scripts/demo-seed.py --execute       # write

Everything is written through :mod:`hindsight.graphbuild` and
:mod:`hindsight.ingest` — the same deterministic ids, the same batched ``UNWIND``
writer, the same watermarks as a production ingest. The only thing this script
owns is *where the history comes from*, and it has four answers:

``--source file``
    the committed ``poc/demo-dataset.jsonl.gz``. This is the reproducible,
    offline path and therefore the first choice for ``auto``.

``--source snapshots``
    ``poc/snapshots/<repo>.jsonl.gz`` produced by ``poc/extract_history.py``.
    The direct path: raw per-commit lockfile closures, diffed into intervals by
    :func:`hindsight.history.build_intervals`.

``--source graph``
    the PoC's ``Dep*`` dataset already resident in the node. Re-read (never
    written, never deleted) and re-projected under ``Replay*``. This exists because
    re-walking 5,028 lockfile commits across 8 repositories takes ~40 minutes and
    ~550 MB of clones, and the intervals in that load are the *output* of exactly
    that walk, validated 320/320 against an independent git oracle (Gate 1).

``--source graph-file``
    the ignored ``poc/graph.json.gz`` produced by ``poc/build_graph.py``. This
    explicit regeneration source reproduces the live ``Dep*`` projection without
    requiring a node and is what creates the committed file via ``--export``.

``--source auto`` (default)
    the committed file if it has the current format, else snapshots if present,
    else the graph, else an error naming the commands that regenerate them.

**One repository is synthetic and says so.** None of the eight real repositories
regenerated a lockfile inside the two-hour compromise window — that is the true
and slightly inconvenient finding of the PoC — so a true positive has to be
constructed to be shown at all. ``acme/checkout-web`` is built here from the real
incident file: its "CI reinstalled at 13:41 UTC" commit takes the malicious
version of every incident package whose caret range actually permits it, and
leaves the six that would need a major bump alone. It is written with
``synthetic = 1`` and a provenance string, and the console renders that on the
row. It is never presented as a real repository.
"""

from __future__ import annotations

import argparse
import gzip
import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from hindsight.client import HydraClient, HydraError  # noqa: E402
from hindsight.graphbuild import RepoInput, Schema, build_rowsets  # noqa: E402
from hindsight.history import SENTINEL, Interval, Snapshot, build_intervals  # noqa: E402
from hindsight.ids import IdRegistry  # noqa: E402
from hindsight.ingest import Ingestor, chunks, node_upsert  # noqa: E402
from hindsight_web.incident import load_incident  # noqa: E402
from hindsight_web.paging import fetch_all  # noqa: E402
from hindsight_web.queries import DEMO_SCHEMA  # noqa: E402

POC = ROOT / "poc"
SNAPSHOT_DIR = POC / "snapshots"
MAINTAINERS_FILE = POC / "maintainers.json"
POC_GRAPH = POC / "graph.json.gz"
DEMO_DATASET = POC / "demo-dataset.jsonl.gz"
DATASET_FORMAT = "hindsight-demo-dataset"
DATASET_VERSION = 1

#: The PoC's ``Dep*`` load. Read-only here — this script never writes or deletes
#: under these labels, and nothing else in the repository may either.
SOURCE_LABELS = {
    "repo": "DepRepo",
    "version": "DepPackageVersion",
    "resolves": "DEP_RESOLVES",
}

REAL_REPO = "git-lockfile-history"
SYNTHETIC = "synthetic"


@dataclass(frozen=True)
class RepoMeta:
    """Business-facing metadata the graph cannot derive from git."""

    slug: str
    short: str
    service: str


@dataclass(frozen=True)
class Dataset:
    """Self-contained logical rows from which any schema's rowsets are built."""

    inputs: tuple[RepoInput, ...]
    origins: dict[str, str]
    provenance: dict[str, dict[str, str | int]]
    maintainers: dict[str, tuple[str, ...]]
    source: str


#: The eight PoC repositories. ``short`` is the key used by both PoC artefacts
#: (``snapshots/<short>.jsonl.gz`` and ``DepRepo.slug``); ``slug`` is the
#: org-qualified name the console shows and the one ids are derived from.
REAL_REPOS: tuple[RepoMeta, ...] = (
    RepoMeta("axios/axios", "axios", "http-client"),
    RepoMeta("babel/babel", "babel", "build-toolchain"),
    RepoMeta("facebook/react", "react", "ui-framework"),
    RepoMeta("grafana/grafana", "grafana", "observability-ui"),
    RepoMeta("jitsi/jitsi-meet", "jitsi-meet", "video-conferencing"),
    RepoMeta("apache/superset", "superset", "analytics-ui"),
    RepoMeta("storybookjs/storybook", "storybook", "component-workshop"),
    RepoMeta("webpack/webpack", "webpack", "build"),
)

SYNTHETIC_SLUG = "acme/checkout-web"
SYNTHETIC_SERVICE = "checkout"
SYNTHETIC_ORIGIN = (
    "SYNTHETIC — constructed for the demo, not a real repository. Lockfile "
    "timeline is fabricated; every package name, version string and publish "
    "timestamp it references is real and comes from poc/incident-chalk-debug.json. "
    "It exists because none of the eight real repositories regenerated a lockfile "
    "inside the compromise window, so there is no true positive to show without one."
)

#: Commit instants for the synthetic repository, UTC.
SYN_BASELINE = "2025-07-21T10:14:00Z"
SYN_REINSTALL = "2025-09-08T13:41:52Z"  # CI ran `npm install`, inside the window
SYN_REMEDIATION = "2025-09-08T18:05:33Z"
SYN_ROUTINE = "2025-11-04T09:12:00Z"

#: The synthetic repo's non-incident dependencies. Held flat across the timeline
#: so that the only thing that moves in its history is the incident itself.
SYN_BACKGROUND: dict[str, str] = {
    "express": "4.19.2",
    "react": "18.3.1",
    "react-dom": "18.3.1",
    "typescript": "5.5.4",
    "vite": "5.4.2",
    "zod": "3.23.8",
    "pino": "9.3.2",
    "undici": "6.19.7",
    "semver": "7.6.3",
    "glob": "10.4.5",
    "lru-cache": "10.4.3",
    "minimatch": "9.0.5",
    "ws": "8.18.0",
    "stripe": "16.8.0",
}

#: Pre-incident pins for every wave-1 package, i.e. what the repo resolved before
#: CI reinstalled. Real released versions, all published well before 2025-09-08.
SYN_BASELINE_PINS: dict[str, str] = {
    "ansi-styles": "6.2.1",
    "debug": "4.3.7",
    "chalk": "5.3.0",
    "supports-color": "10.0.0",
    "strip-ansi": "7.1.0",
    "ansi-regex": "6.0.1",
    "wrap-ansi": "9.0.0",
    "color-convert": "2.0.1",
    "color-name": "1.1.4",
    "is-arrayish": "0.3.2",
    "slice-ansi": "7.1.0",
    "error-ex": "1.3.2",
    "color-string": "1.9.1",
    "color": "4.2.3",
    "simple-swizzle": "0.2.2",
    "supports-hyperlinks": "3.1.0",
    "has-ansi": "5.0.1",
    "chalk-template": "1.1.0",
    "backslash": "0.2.0",
}


# --------------------------------------------------------------------- semver


def parse_version(text: str) -> tuple[int, ...] | None:
    """``"6.2.1"`` -> ``(6, 2, 1)``; ``None`` for anything non-numeric."""
    parts = str(text).split("-")[0].split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        return None
    return tuple(int(p) for p in parts)


def caret_allows(current: str, candidate: str) -> bool:
    """Would ``^current`` in package.json resolve to ``candidate``?

    npm's caret keeps the leftmost non-zero component: ``^1.2.3`` admits
    ``<2.0.0``, ``^0.3.2`` admits ``<0.4.0``, ``^0.0.3`` admits only ``0.0.3``.
    This is what decides whether the synthetic repository's reinstall picked up a
    malicious version or was saved by a major-version bound, and getting it right
    is why six of the nineteen wave-1 packages do *not* move in its history.
    """
    cur, cand = parse_version(current), parse_version(candidate)
    if cur is None or cand is None or cand < cur:
        return False
    if cur[0] > 0:
        return cand[0] == cur[0]
    if cur[1] > 0:
        return cand[0] == 0 and cand[1] == cur[1]
    return cand[:3] == cur[:3]


# ------------------------------------------------------------------- sources


def iso_to_epoch(text: str) -> int:
    from datetime import datetime

    return int(datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp())


def from_snapshots(meta: RepoMeta) -> RepoInput | None:
    """Read ``poc/snapshots/<short>.jsonl.gz`` into a :class:`RepoInput`."""
    path = SNAPSHOT_DIR / f"{meta.short}.jsonl.gz"
    if not path.exists():
        return None
    snapshots: list[Snapshot] = []
    with gzip.open(path, "rt") as fh:
        for line in fh:
            record = json.loads(line)
            entries = frozenset(
                (str(name), str(version)) for name, version in record["entries"]
            )
            if not entries:
                continue
            snapshots.append(
                Snapshot(
                    commit=str(record["commit"]),
                    ts=int(record["ts"]),
                    paths=(str(record.get("path") or ""),),
                    entries=entries,
                )
            )
    if not snapshots:
        return None
    snapshots.sort(key=lambda s: (s.ts, s.commit))
    return RepoInput(
        slug=meta.slug,
        name=meta.slug,
        service=meta.service,
        intervals=tuple(build_intervals(snapshots)),
        first_ts=snapshots[0].ts,
        last_ts=snapshots[-1].ts,
        snapshots=len(snapshots),
    )


def from_graph(client: HydraClient, meta: RepoMeta, source_id: int) -> RepoInput | None:
    """Re-read one repository's intervals out of the PoC's ``Dep*`` load.

    Id-anchored and paged. The scan form of this read was measured at ~8 s; the
    anchored form returns 11,314 rows for the largest repository in under a
    second, which is the whole argument for owning the name -> id map.
    """
    cypher = (
        f"MATCH (r:{SOURCE_LABELS['repo']} {{id: $rid}})"
        f"-[e:{SOURCE_LABELS['resolves']}]->(v:{SOURCE_LABELS['version']}) "
        "WHERE e.valid_from >= 0 "
        "RETURN v.pkg, v.version, e.valid_from, e.valid_to"
    )
    rows, truncated = fetch_all(client, cypher, {"rid": source_id}, row_cap=200_000)
    if truncated:
        raise SystemExit(f"{meta.slug}: source read hit the row cap; refusing a partial seed")
    if not rows:
        return None

    intervals = [
        Interval(str(pkg), str(version), int(valid_from), int(valid_to))
        for pkg, version, valid_from, valid_to in rows
    ]
    # The commit instants that changed the closure. That is the honest reading of
    # "snapshots" for a re-projected load: the original per-commit blobs are not
    # in the graph, only the boundaries they produced.
    boundaries = {iv.valid_from for iv in intervals}
    boundaries |= {iv.valid_to for iv in intervals if iv.valid_to != SENTINEL}
    closed = [iv.valid_to for iv in intervals if iv.valid_to != SENTINEL]
    return RepoInput(
        slug=meta.slug,
        name=meta.slug,
        service=meta.service,
        intervals=tuple(intervals),
        first_ts=min(iv.valid_from for iv in intervals),
        last_ts=max([*closed, *(iv.valid_from for iv in intervals)]),
        snapshots=len(boundaries),
    )


def source_repo_ids(client: HydraClient) -> dict[str, int]:
    """``DepRepo.slug`` -> node id, read from the source dataset."""
    rows, _ = fetch_all(
        client, f"MATCH (n:{SOURCE_LABELS['repo']}) RETURN n.id, n.slug", page_size=256
    )
    return {str(slug): int(node_id) for node_id, slug in rows}


def from_graph_export(graph: dict, meta: RepoMeta) -> RepoInput | None:
    """Re-project one repository from ``poc/graph.json.gz`` without a node."""
    source_id = next(
        (
            int(record["id"])
            for record in graph.get("repos", [])
            if record.get("slug") == meta.short
        ),
        None,
    )
    if source_id is None:
        return None
    versions = {
        int(record["id"]): (str(record["pkg"]), str(record["version"]))
        for record in graph.get("versions", [])
    }
    intervals = [
        Interval(*versions[int(record["d"])], int(record["vf"]), int(record["vt"]))
        for record in graph.get("resolves", [])
        if int(record["s"]) == source_id
    ]
    if not intervals:
        return None
    boundaries = {interval.valid_from for interval in intervals}
    boundaries |= {
        interval.valid_to for interval in intervals if interval.valid_to != SENTINEL
    }
    closed = [
        interval.valid_to for interval in intervals if interval.valid_to != SENTINEL
    ]
    return RepoInput(
        slug=meta.slug,
        name=meta.slug,
        service=meta.service,
        intervals=tuple(intervals),
        first_ts=min(interval.valid_from for interval in intervals),
        last_ts=max([*closed, *(interval.valid_from for interval in intervals)]),
        snapshots=len(boundaries),
    )


# --------------------------------------------------------- synthetic repository


def synthetic_repo(incident) -> RepoInput:
    """Build ``acme/checkout-web`` from the real incident file.

    Four commits: a July baseline, the 13:41 UTC reinstall that lands inside the
    window, an 18:05 remediation, and a routine November bump that closes the
    incident-era intervals so the timeline has an end.
    """
    malicious = {v.package: v.version for v in incident.versions if v.wave == 1}
    remediated = {
        v.package: v.remediated_version
        for v in incident.versions
        if v.wave == 1 and v.remediated_version
    }

    baseline = dict(SYN_BACKGROUND) | dict(SYN_BASELINE_PINS)

    reinstalled = dict(baseline)
    for package, bad in malicious.items():
        pinned = SYN_BASELINE_PINS.get(package)
        if pinned and caret_allows(pinned, bad):
            reinstalled[package] = bad

    remediation = dict(reinstalled)
    for package, current in reinstalled.items():
        if current != malicious.get(package):
            continue
        # Where npm published a clean release, take it; where the maintainers
        # only unpublished (debug), roll back to the last known-good pin.
        remediation[package] = remediated.get(package) or SYN_BASELINE_PINS[package]

    routine = dict(remediation)
    routine["stripe"] = "17.2.1"
    routine["typescript"] = "5.6.3"

    stages = (
        (SYN_BASELINE, baseline),
        (SYN_REINSTALL, reinstalled),
        (SYN_REMEDIATION, remediation),
        (SYN_ROUTINE, routine),
    )
    snapshots = [
        Snapshot(
            commit=f"synthetic-{index}",
            ts=iso_to_epoch(when),
            paths=("package-lock.json",),
            entries=frozenset(entries.items()),
        )
        for index, (when, entries) in enumerate(stages)
    ]
    return RepoInput(
        slug=SYNTHETIC_SLUG,
        name=SYNTHETIC_SLUG,
        service=SYNTHETIC_SERVICE,
        intervals=tuple(build_intervals(snapshots)),
        first_ts=snapshots[0].ts,
        last_ts=snapshots[-1].ts,
        snapshots=len(snapshots),
    )


# ------------------------------------------------------------------ maintainers


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


# -------------------------------------------------------- committed dataset


def write_dataset(path: Path, dataset: Dataset, rowset_summary: dict[str, int]) -> None:
    """Write a byte-reproducible gzip JSONL representation of the demo rows."""
    records = [
        {
            "type": "meta",
            "format": DATASET_FORMAT,
            "version": DATASET_VERSION,
            "source": dataset.source,
            "rowsets": rowset_summary,
        }
    ]
    for spec in dataset.inputs:
        stamp = dataset.provenance[spec.slug]
        records.append(
            {
                "type": "repo",
                "slug": spec.slug,
                "name": spec.name,
                "service": spec.service,
                "first_ts": spec.first_ts,
                "last_ts": spec.last_ts,
                "snapshots": spec.snapshots,
                "origin": dataset.origins[spec.slug],
                "provenance": stamp["provenance"],
                "synthetic": stamp["synthetic"],
            }
        )
        for interval in sorted(
            spec.intervals,
            key=lambda item: (
                item.package,
                item.version,
                item.valid_from,
                item.valid_to,
            ),
        ):
            records.append(
                {
                    "type": "interval",
                    "repo": spec.slug,
                    "package": interval.package,
                    "version": interval.version,
                    "valid_from": interval.valid_from,
                    "valid_to": interval.valid_to,
                }
            )
    for account, packages in sorted(dataset.maintainers.items()):
        records.append(
            {
                "type": "maintainer",
                "name": account,
                "packages": sorted(packages),
            }
        )

    # Written beside the destination and moved into place, because the usual
    # destination is the committed artifact and it is the only thing a fresh
    # clone can seed from. An export interrupted halfway -- Ctrl-C, a full disk,
    # a source that raises on the last repository -- would otherwise leave a
    # truncated gzip there, and the failure a user meets is not the export they
    # cancelled but a seed that reads short and demonstrates less than it should.
    path.parent.mkdir(parents=True, exist_ok=True)
    staging = path.with_name(path.name + ".partial")
    try:
        with staging.open("wb") as raw:
            with gzip.GzipFile(
                filename="", mode="wb", fileobj=raw, mtime=0
            ) as compressed:
                for record in records:
                    line = json.dumps(record, sort_keys=True, separators=(",", ":"))
                    compressed.write(line.encode("utf-8") + b"\n")
        staging.replace(path)
    finally:
        staging.unlink(missing_ok=True)


def read_dataset(path: Path) -> Dataset:
    """Load the committed logical rows and preserve their provenance verbatim."""
    repos: dict[str, dict] = {}
    intervals: dict[str, list[Interval]] = {}
    origins: dict[str, str] = {}
    provenance: dict[str, dict[str, str | int]] = {}
    maintainers: dict[str, tuple[str, ...]] = {}
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        header = json.loads(next(fh))
        if (
            header.get("format") != DATASET_FORMAT
            or header.get("version") != DATASET_VERSION
        ):
            raise SystemExit(f"{path} is not a current {DATASET_FORMAT} file")
        for line in fh:
            record = json.loads(line)
            kind = record.get("type")
            if kind == "repo":
                slug = str(record["slug"])
                repos[slug] = record
                intervals[slug] = []
                origins[slug] = str(record["origin"])
                provenance[slug] = {
                    "provenance": str(record["provenance"]),
                    "synthetic": int(record["synthetic"]),
                }
            elif kind == "interval":
                intervals[str(record["repo"])].append(
                    Interval(
                        str(record["package"]),
                        str(record["version"]),
                        int(record["valid_from"]),
                        int(record["valid_to"]),
                    )
                )
            elif kind == "maintainer":
                maintainers[str(record["name"])] = tuple(
                    str(package) for package in record["packages"]
                )
    inputs = tuple(
        RepoInput(
            slug=slug,
            name=str(record["name"]),
            service=str(record["service"]),
            intervals=tuple(intervals[slug]),
            first_ts=int(record["first_ts"]),
            last_ts=int(record["last_ts"]),
            snapshots=int(record["snapshots"]),
        )
        for slug, record in repos.items()
    )
    return Dataset(
        inputs=inputs,
        origins=origins,
        provenance=provenance,
        maintainers=maintainers,
        source=str(header["source"]),
    )


def dataset_is_current(path: Path) -> bool:
    """Whether ``path`` starts with the format/version this loader understands."""
    try:
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            header = json.loads(next(fh))
    except (OSError, EOFError, StopIteration, json.JSONDecodeError):
        return False
    return (
        header.get("format") == DATASET_FORMAT
        and header.get("version") == DATASET_VERSION
    )


class NamespacedIdRegistry(IdRegistry):
    """Salt every id for a collision-free verification load on a shared node."""

    def __init__(self, namespace: str) -> None:
        super().__init__()
        self.namespace = namespace

    def mint(self, key: str) -> int:
        return super().mint(f"demo:{self.namespace}:{key}")


def build_demo_rowsets(
    inputs: tuple[RepoInput, ...],
    schema: Schema,
    maintainers: dict[str, tuple[str, ...]],
    id_namespace: str = "",
):
    """Build rowsets, optionally salting ids and watermark keys for isolation."""
    registry = NamespacedIdRegistry(id_namespace) if id_namespace else None
    rows = build_rowsets(
        list(inputs),
        schema=schema,
        maintainers={name: list(packages) for name, packages in maintainers.items()},
        registry=registry,
    )
    repo_ids = {slug: ident for ident, slug in rows.repo_slugs.items()}
    if id_namespace:
        rows.repo_slugs = {
            ident: f"{id_namespace}:{slug}" for ident, slug in rows.repo_slugs.items()
        }
    return rows, repo_ids


# ------------------------------------------------------------------ provenance


def write_provenance(
    client: HydraClient, schema: Schema, entries: list[dict], batch: int
) -> None:
    """Stamp provenance onto the repository nodes the ingest just wrote.

    A second ``MERGE`` by id onto an existing node with a trailing ``SET`` — the
    only vertex-update shape the engine accepts — so this adds properties the
    shared :class:`~hindsight.graphbuild.Schema` does not model without forking
    it. The console reads them straight back and prints them on the row.

    ``schema`` is a parameter and not a module constant on purpose. An earlier
    version named ``DEMO_SCHEMA.repo`` literally, which meant a ``--node-prefix``
    load stamped its provenance under the *default* label: ``MERGE`` enters
    through the id, matches the node that already exists under the other label,
    and adds this one to it. Ids are global; labels are not a namespace on write.
    """
    cypher = node_upsert(
        schema.repo,
        {"provenance": "provenance", "origin": "origin", "synthetic": "synthetic"},
    )
    for part in chunks(entries, batch):
        client.query(cypher, {"rows": part})


# ------------------------------------------------------------------------ main


def collect(
    source: str,
    client: HydraClient,
    log,
    dataset_path: Path = DEMO_DATASET,
    graph_path: Path = POC_GRAPH,
) -> tuple[Dataset, str]:
    """Gather the demo rows from the reproducible file or a regeneration source."""
    have_file = dataset_is_current(dataset_path)
    have_snapshots = SNAPSHOT_DIR.exists() and any(SNAPSHOT_DIR.glob("*.jsonl.gz"))
    chosen = source
    if source == "auto":
        chosen = "file" if have_file else "snapshots" if have_snapshots else "graph"
    if chosen == "file":
        if not have_file:
            raise SystemExit(
                f"no current demo dataset at {dataset_path}. Regenerate it with:\n"
                "  python3 scripts/demo-seed.py --source graph-file "
                f"--export {dataset_path}"
            )
        log("source: file")
        dataset = read_dataset(dataset_path)
        incident = load_incident()
        for built in dataset.inputs:
            suffix = ""
            if dataset.provenance[built.slug]["synthetic"]:
                # The same line the regeneration path prints, recomputed from the
                # intervals in the file. It is the one number that says the
                # artifact still carries an exposure to find: a demo seeded from
                # a stale or truncated file would load cleanly and show nothing.
                exposed = sorted(
                    iv.package
                    for iv in built.intervals
                    if iv.version in incident.malicious_versions(iv.package)
                )
                suffix = (
                    f"  SYNTHETIC, {len(exposed)} malicious version(s): "
                    f"{', '.join(exposed)}"
                )
            log(
                f"  {built.slug:<26} intervals={len(built.intervals):>7,d} "
                f"commits={built.snapshots:>5,d}{suffix}"
            )
        return dataset, chosen
    if chosen == "snapshots" and not have_snapshots:
        raise SystemExit(
            f"no snapshots in {SNAPSHOT_DIR}. Regenerate them with:\n"
            "  cd poc && ./clone_repos.sh\n"
            '  for r in axios babel grafana jitsi-meet webpack superset react storybook; do \\\n'
            '    SINCE=2024-01-01 UNTIL=2025-12-31 python3 extract_history.py "$r" & done; wait\n'
            "…or seed from the committed artifact: --source file"
        )
    if chosen == "graph-file" and not graph_path.exists():
        raise SystemExit(
            f"no PoC graph export at {graph_path}. Generate it with:\n"
            "  cd poc && python3 build_graph.py"
        )

    log(f"source: {chosen}")
    inputs: list[RepoInput] = []
    origins: dict[str, str] = {}
    ids = source_repo_ids(client) if chosen == "graph" else {}
    graph_export = None
    if chosen == "graph-file":
        with gzip.open(graph_path, "rt", encoding="utf-8") as fh:
            graph_export = json.load(fh)
    for meta in REAL_REPOS:
        if chosen == "snapshots":
            built = from_snapshots(meta)
            origin = (
                f"git lockfile history, re-walked from poc/snapshots/{meta.short}.jsonl.gz"
            )
        elif chosen == "graph-file":
            built = from_graph_export(graph_export, meta)
            origin = (
                "git lockfile history, re-projected from poc/graph.json.gz "
                "(Gate 1: 320/320 agreement with an independent git oracle). "
                "'snapshots' counts closure-changing commit instants."
            )
        else:
            source_id = ids.get(meta.short)
            built = from_graph(client, meta, source_id) if source_id else None
            origin = (
                "git lockfile history, re-projected read-only from the PoC's Dep* "
                "load in this node (Gate 1: 320/320 agreement with an independent "
                "git oracle). 'snapshots' counts closure-changing commit instants."
            )
        if built is None:
            log(f"  {meta.slug:<26} MISSING from {chosen} source — skipped")
            continue
        origins[meta.slug] = origin
        inputs.append(built)
        log(
            f"  {meta.slug:<26} intervals={len(built.intervals):>7,d} "
            f"commits={built.snapshots:>5,d}"
        )
    if not inputs:
        raise SystemExit(f"no repository history found via --source {chosen}")
    return (
        Dataset(
            inputs=tuple(inputs),
            origins=origins,
            provenance={
                spec.slug: {"provenance": REAL_REPO, "synthetic": 0} for spec in inputs
            },
            maintainers={
                name: tuple(packages) for name, packages in maintainer_overlay().items()
            },
            source=chosen,
        ),
        chosen,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="scripts/demo-seed.py",
        description=(
            f"Seed the Hindsight demo dataset into HydraDB under "
            f"{DEMO_SCHEMA.repo.replace('Repo', '')}* labels."
        ),
    )
    parser.add_argument(
        "--source",
        choices=("auto", "file", "snapshots", "graph", "graph-file"),
        default="auto",
        help="where the real repositories' lockfile history comes from",
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=DEMO_DATASET,
        help="compressed JSONL path read by --source file",
    )
    parser.add_argument(
        "--graph-file",
        type=Path,
        default=POC_GRAPH,
        help="PoC graph export read by --source graph-file",
    )
    parser.add_argument(
        "--export",
        type=Path,
        metavar="PATH",
        help=(
            "export the collected demo rows as deterministic compressed JSONL "
            "and exit without reading or writing the output labels"
        ),
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="actually write (the default plans and writes nothing)",
    )
    parser.add_argument("--batch", type=int, default=1000)
    parser.add_argument(
        "--node-prefix",
        default=DEMO_SCHEMA.repo.replace("Repo", ""),
        help=(
            "node label namespace, e.g. ReplayScratch for an isolated load. "
            "Pair it with --rel-prefix: the two are not derived from each other"
        ),
    )
    parser.add_argument("--rel-prefix", default=DEMO_SCHEMA.resolves.split("_")[0])
    parser.add_argument(
        "--id-namespace",
        default="",
        help=(
            "salt every node, edge and watermark id for a collision-free scratch "
            "load; use with fresh --node-prefix and --rel-prefix values"
        ),
    )
    parser.add_argument("--no-synthetic", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    schema = Schema.prefixed(args.node_prefix, args.rel_prefix)

    def log(message: str) -> None:
        if not args.json:
            print(message, flush=True)

    client = HydraClient.from_env()
    incident = load_incident()

    log(f"labels: {schema.repo} / {schema.version} -[{schema.resolves}]->")
    collected, _ = collect(
        args.source,
        client,
        log,
        dataset_path=args.dataset,
        graph_path=args.graph_file,
    )
    inputs = list(collected.inputs)
    origins = dict(collected.origins)
    provenance_by_slug = dict(collected.provenance)

    if args.no_synthetic:
        inputs = [spec for spec in inputs if spec.slug != SYNTHETIC_SLUG]
        origins.pop(SYNTHETIC_SLUG, None)
        provenance_by_slug.pop(SYNTHETIC_SLUG, None)
    elif not any(spec.slug == SYNTHETIC_SLUG for spec in inputs):
        built = synthetic_repo(incident)
        inputs.append(built)
        origins[SYNTHETIC_SLUG] = SYNTHETIC_ORIGIN
        provenance_by_slug[SYNTHETIC_SLUG] = {
            "provenance": SYNTHETIC,
            "synthetic": 1,
        }
        exposed = sorted(
            iv.package
            for iv in built.intervals
            if iv.version in incident.malicious_versions(iv.package)
        )
        log(
            f"  {SYNTHETIC_SLUG:<26} intervals={len(built.intervals):>7,d} "
            f"commits={built.snapshots:>5,d}  SYNTHETIC, "
            f"{len(exposed)} malicious version(s): {', '.join(exposed)}"
        )

    dataset = Dataset(
        inputs=tuple(inputs),
        origins=origins,
        provenance=provenance_by_slug,
        maintainers=collected.maintainers,
        source=collected.source,
    )
    rows, repo_ids = build_demo_rowsets(
        dataset.inputs,
        schema,
        dataset.maintainers,
        id_namespace=args.id_namespace,
    )
    log("")
    log(
        f"built {rows.node_count:,d} nodes / {rows.edge_count:,d} edges "
        f"({len(dataset.maintainers)} maintainer accounts)"
    )
    if args.export:
        write_dataset(args.export, dataset, rows.summary())
        log(f"exported {args.export} ({args.export.stat().st_size:,d} bytes)")
        if args.json:
            print(
                json.dumps(
                    {
                        "exported": str(args.export),
                        "bytes": args.export.stat().st_size,
                        "built": rows.summary(),
                    },
                    indent=2,
                )
            )
        return 0

    ingestor = Ingestor(client, schema=schema, batch=args.batch, progress=log)
    started = time.perf_counter()
    try:
        report = ingestor.run(rows, dry_run=not args.execute)
    except HydraError as exc:
        print(f"hydradb: {exc}", file=sys.stderr)
        return 3
    elapsed = time.perf_counter() - started

    provenance = [
        {
            "id": repo_ids[spec.slug],
            "provenance": dataset.provenance[spec.slug]["provenance"],
            "origin": origins.get(spec.slug, ""),
            "synthetic": dataset.provenance[spec.slug]["synthetic"],
        }
        for spec in inputs
    ]
    if args.execute:
        write_provenance(client, schema, provenance, args.batch)

    payload = report.as_dict()
    payload["built"] = rows.summary()
    payload["repositories"] = [
        {
            "slug": spec.slug,
            "provenance": stamp["provenance"],
            "intervals": len(spec.intervals),
            "commits": spec.snapshots,
        }
        for spec, stamp in zip(inputs, provenance, strict=True)
    ]
    payload["seconds"] = round(elapsed, 3)
    if args.json:
        print(json.dumps(payload, indent=2))
        return 0

    verb = "wrote" if args.execute else "would write"
    log("")
    log(
        f"{verb} {report.nodes_written:,d} nodes and {report.edges_written:,d} edges "
        f"in {elapsed:.2f}s"
    )
    if report.skipped_resolves:
        log(f"skipped {report.skipped_resolves:,d} settled interval(s) below the watermark")
    if not args.execute:
        log("plan only — nothing was written. Re-run with --execute.")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
