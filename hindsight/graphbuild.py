"""Validity intervals -> node and edge rowsets, for a given label schema.

The shape of the graph:

    (:Repo   {id, slug, name, service, first_ts, last_ts, snapshots})
    (:Pkg    {id, name})
    (:Ver    {id, pkg, version, key, pkg_id})
    (:Maint  {id, name})

    (:Repo)-[:RESOLVES {id, valid_from, valid_to, tx_from, tx_to}]->(:Ver)
    (:Ver)-[:VERSION_OF {id}]->(:Pkg)
    (:Maint)-[:MAINTAINS {id}]->(:Pkg)

Label and relationship names are carried by :class:`Schema` rather than
hard-coded, so tests can write into a throwaway ``IngTest*`` namespace on the
same node that holds production data — HydraDB deletes at ~3 nodes/sec, which
makes label namespacing the only workable form of test isolation.

Every timestamp is integer unix seconds; open intervals end at
:data:`hindsight.history.SENTINEL` because there is no ``IS NULL``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .history import SENTINEL, Interval, RepoHistory
from .ids import IdRegistry


@dataclass(frozen=True)
class Schema:
    """Label and relationship-type names for one logical dataset."""

    repo: str
    package: str
    version: str
    maintainer: str
    watermark: str
    resolves: str
    version_of: str
    maintains: str

    @classmethod
    def prefixed(cls, node_prefix: str, rel_prefix: str) -> Schema:
        return cls(
            repo=f"{node_prefix}Repo",
            package=f"{node_prefix}Pkg",
            version=f"{node_prefix}Ver",
            maintainer=f"{node_prefix}Maint",
            watermark=f"{node_prefix}Watermark",
            resolves=f"{rel_prefix}_RESOLVES",
            version_of=f"{rel_prefix}_VERSION_OF",
            maintains=f"{rel_prefix}_MAINTAINS",
        )


#: Production labels. Deliberately disjoint from the PoC's ``Dep*`` dataset.
DEFAULT_SCHEMA = Schema.prefixed("Hs", "HS")

#: Throwaway labels for integration tests against a shared node.
TEST_SCHEMA = Schema.prefixed("IngTest", "INGTEST")


@dataclass(frozen=True)
class RepoInput:
    """One repository's extracted history, ready to be turned into rows."""

    slug: str
    name: str
    service: str
    intervals: tuple[Interval, ...]
    first_ts: int = 0
    last_ts: int = 0
    snapshots: int = 0

    @classmethod
    def from_history(
        cls, history: RepoHistory, name: str | None = None, service: str = ""
    ) -> RepoInput:
        return cls(
            slug=history.slug,
            name=name or history.slug,
            service=service,
            intervals=tuple(history.intervals),
            first_ts=history.first_ts,
            last_ts=history.last_ts,
            snapshots=len(history.snapshots),
        )


@dataclass
class RowSets:
    """Everything one build produced, grouped by write step."""

    repos: list[dict] = field(default_factory=list)
    packages: list[dict] = field(default_factory=list)
    versions: list[dict] = field(default_factory=list)
    maintainers: list[dict] = field(default_factory=list)
    resolves: list[dict] = field(default_factory=list)
    version_of: list[dict] = field(default_factory=list)
    maintains: list[dict] = field(default_factory=list)
    #: repo id -> newest commit timestamp seen for that repo this build
    repo_last_ts: dict[int, int] = field(default_factory=dict)
    #: repo id -> slug, for watermark bookkeeping
    repo_slugs: dict[int, str] = field(default_factory=dict)

    @property
    def node_count(self) -> int:
        return (
            len(self.repos) + len(self.packages) + len(self.versions) + len(self.maintainers)
        )

    @property
    def edge_count(self) -> int:
        return len(self.resolves) + len(self.version_of) + len(self.maintains)

    def summary(self) -> dict[str, int]:
        return {
            "repos": len(self.repos),
            "packages": len(self.packages),
            "versions": len(self.versions),
            "maintainers": len(self.maintainers),
            "resolves": len(self.resolves),
            "version_of": len(self.version_of),
            "maintains": len(self.maintains),
            "nodes": self.node_count,
            "edges": self.edge_count,
        }


def build_rowsets(
    repos: list[RepoInput],
    schema: Schema = DEFAULT_SCHEMA,
    maintainers: dict[str, list[str]] | None = None,
    registry: IdRegistry | None = None,
) -> RowSets:
    """Turn per-repo intervals into the rowsets the ingest writer consumes.

    Ids come from :class:`~hindsight.ids.IdRegistry`, so a collision anywhere in
    the build raises before anything is written to an append-only store.
    """
    # Not `registry or IdRegistry()`: IdRegistry defines __len__, so a caller's
    # freshly created (empty) registry would be falsy and silently discarded.
    reg = IdRegistry() if registry is None else registry
    out = RowSets()

    pkg_seen: dict[str, int] = {}
    ver_seen: dict[tuple[str, str], int] = {}

    for spec in sorted(repos, key=lambda r: r.slug):
        rid = reg.repo(spec.slug)
        out.repo_slugs[rid] = spec.slug
        out.repos.append(
            {
                "id": rid,
                "slug": spec.slug,
                "name": spec.name,
                "service": spec.service,
                "first_ts": spec.first_ts,
                "last_ts": spec.last_ts,
                "snapshots": spec.snapshots,
            }
        )
        out.repo_last_ts[rid] = spec.last_ts

        for iv in spec.intervals:
            if iv.package not in pkg_seen:
                pkg_seen[iv.package] = reg.package(iv.package)
                out.packages.append({"id": pkg_seen[iv.package], "name": iv.package})
            vkey = (iv.package, iv.version)
            if vkey not in ver_seen:
                vid = reg.version(iv.package, iv.version)
                ver_seen[vkey] = vid
                out.versions.append(
                    {
                        "id": vid,
                        "pkg": iv.package,
                        "version": iv.version,
                        "key": f"{iv.package}@{iv.version}",
                        "pkg_id": pkg_seen[iv.package],
                    }
                )
                out.version_of.append(
                    {
                        "id": reg.edge(schema.version_of, vid, pkg_seen[iv.package]),
                        "s": vid,
                        "d": pkg_seen[iv.package],
                    }
                )
            vid = ver_seen[vkey]
            out.resolves.append(
                {
                    "id": reg.edge(schema.resolves, rid, vid, iv.valid_from),
                    "s": rid,
                    "d": vid,
                    "vf": iv.valid_from,
                    "vt": iv.valid_to,
                }
            )

    for maint, packages in sorted((maintainers or {}).items()):
        mid = reg.maintainer(maint)
        out.maintainers.append({"id": mid, "name": maint})
        for pkg in sorted(set(packages)):
            pid = pkg_seen.get(pkg)
            if pid is None:
                continue  # a package this org never resolved
            out.maintains.append(
                {"id": reg.edge(schema.maintains, mid, pid), "s": mid, "d": pid}
            )

    return out


def filter_by_watermark(
    rows: list[dict], watermarks: dict[int, int]
) -> tuple[list[dict], int]:
    """Drop interval edges that are already final on the server.

    A repo's watermark is the newest commit timestamp its last ingest saw. Any
    interval that had already *closed* by then is immutable — later commits can
    never change it — so it does not need to be resent. Intervals that were
    still open at the watermark do need resending, because the run that follows
    may be the one that closes them.

    Returns ``(kept_rows, skipped_count)``.
    """
    if not watermarks:
        return rows, 0
    kept = []
    skipped = 0
    for row in rows:
        mark = watermarks.get(row["s"])
        if mark is not None and row["vt"] <= mark:
            skipped += 1
            continue
        kept.append(row)
    return kept, skipped


def stale_repos(repo_last_ts: dict[int, int], watermarks: dict[int, int]) -> set[int]:
    """Repos whose build horizon is behind what the server already knows.

    A build that only walked history up to H cannot assert anything about the
    timeline after H: its open intervals mean "still open *as of H*", not
    "open forever". Writing them anyway would reopen intervals that a later,
    better-informed run had already closed — the watermark alone does not
    prevent this, because an open interval always sorts above any watermark.

    So a build that knows strictly less than the store is dropped rather than
    merged. Nothing is lost: it has no fact the store does not already hold.
    """
    return {
        rid
        for rid, mark in watermarks.items()
        if repo_last_ts.get(rid, 0) < mark
    }


def stamp_tx(rows: list[dict], tx_from: int, tx_to: int = SENTINEL) -> list[dict]:
    """Attach transaction time to interval edges.

    ``tx_from`` is when this graph learned the *current* form of the fact. For a
    still-open interval that is resent on a later run it therefore moves
    forward; for a closed interval it is pinned by the run that closed it.
    """
    for row in rows:
        row["txf"] = tx_from
        row["txt"] = tx_to
    return rows
