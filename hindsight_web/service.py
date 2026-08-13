"""The console's read path: name -> id, query, shape a JSON answer.

No web framework is imported here. Everything the UI shows is produced by plain
methods on :class:`Console`, so the interesting behaviour — the honesty fields,
the not-exposed explanation, the synthetic-provenance labelling, the maintainer
ranking — is testable by calling functions with a fake client.

The statements come from :mod:`hindsight.queries`, which the MCP server also
composes from: the console and an agent must not be able to give different
answers to the same question, and one set of builders is the cheapest guarantee
of that. What is console-specific is everything below the row — the
classification, the directory join, the JSON.

Three properties this layer is responsible for:

**Every query is id-anchored.** Names are resolved through
:mod:`hindsight.ids`, which derives ids by hash rather than allocating them, so
"resolve the name" is arithmetic and not a lookup. A package the org never
resolved has no node, which the console reports as a proven absence rather than
as a failed query.

**Every repository is named in every answer.** The graph returns rows only for
repositories that resolved something; the console joins those against the full
repository directory so that "eight of nine repositories did not resolve any
malicious version" is a statement about nine known repositories, not about an
empty result set.

**Nothing overstates the evidence.** ``evidence`` and ``caveat`` come from
:mod:`hindsight_web.analysis` and are attached to every result that touches a
RESOLVES edge.

**A negative is a proof only when coverage is known.** The three previous
properties are all worthless against an empty or mis-pointed dataset, where
every count is zero, every repository is NOT_RESOLVED and the answer reads as a
confident all-clear. So :class:`Coverage` travels with every answer, beside
``truncated`` and distinct from it, and decides whether the answer is permitted
to contain a verdict at all.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace

from hindsight import queries
from hindsight.client import HydraClient
from hindsight.graphbuild import Schema
from hindsight.ids import maintainer_id, package_id, version_id
from hindsight.queries import Query

from .analysis import (
    CAVEAT,
    EVIDENCE,
    EXPOSED,
    MAINTAINER_CAVEAT,
    SYNTHETIC_CAVEAT,
    TRUNCATION_CAVEAT,
    Window,
    classify,
    completeness,
    humanize,
    iso,
    sort_key,
    summarize,
)
from .incident import Incident, load_incident
from .paging import fetch_all
from .queries import DEMO_SCHEMA

#: How many maintainer accounts the ranking panel scores per request. The whole
#: overlay is 154 accounts on the demo dataset, so this is not a sample.
MAX_RANKED_MAINTAINERS = 400

#: Parallelism for the ranking sweep. The node is a single local container; more
#: than a handful of concurrent readers buys nothing and muddies the latency
#: numbers the demo quotes.
RANK_WORKERS = 6

#: Why a dataset cannot answer a question at all. Deliberately a short list:
#: these are the ways a read comes back with nothing to *say*, as opposed to the
#: ways it comes back saying "no". They are not verdicts and must never be
#: rendered as one.
EMPTY_DATASET = "empty_dataset"
NO_INGESTED_HISTORY = "no_ingested_history"
UNREACHABLE = "unreachable"

#: The sentence that replaces the proven-negative prose when coverage is absent.
#: These strings are the honest counterpart of
#: :data:`~hindsight_web.analysis.TRUNCATION_CAVEAT` and are held to the same
#: rule: nothing here may imply anything about a running system.
UNANSWERABLE_NOTES = {
    EMPTY_DATASET: (
        "this dataset contains no repositories, so no question can be answered "
        "from it. Nothing was checked against this package and nothing was "
        "found to be absent: the counts below are the size of an empty dataset, "
        "not a result. Point the console at a seeded dataset before reading "
        "anything into them"
    ),
    NO_INGESTED_HISTORY: (
        "this dataset lists repositories but not one of them carries a finished "
        "ingest watermark, so no lockfile history has been loaded for any of "
        "them. Every repository would read as 'did not resolve this package' "
        "purely because its history is missing, which is a gap in coverage and "
        "not a negative result"
    ),
    UNREACHABLE: (
        "the node did not answer, so this dataset could not be read at all. "
        "Nothing below is a statement about this package"
    ),
}


class ConsoleError(Exception):
    """A request the console can explain rather than a stack trace."""


@dataclass(frozen=True)
class Coverage:
    """Whether a dataset is in a position to answer anything at all.

    The console's whole value is the strength of its negative: "no repository
    resolved this, and here is the interval that proves it". That claim is only
    available when the dataset is *known to be populated*. Pointed at an empty
    or mis-pointed label namespace, every count is zero and every repository is
    NOT_RESOLVED, which renders identically to a genuinely clean estate and, for
    an incident responder, converts a configuration mistake into an all-clear.

    So coverage travels with the answer, next to ``truncated`` and distinct from
    it. The two failure modes are not the same shape and must not be collapsed:
    truncation means *we saw some of the graph*, and absent coverage means *we
    saw none of it*. A truncated read still knows how many repositories exist;
    an empty dataset does not know anything.
    """

    answerable: bool
    reason: str | None
    repo_count: int
    ingested_repo_count: int

    @property
    def note(self) -> str | None:
        return UNANSWERABLE_NOTES.get(self.reason) if self.reason else None

    def as_dict(self) -> dict:
        """The fields every answer carries, additive to the existing shape."""
        return {
            "answerable": self.answerable,
            "unanswerable_reason": self.reason,
            "unanswerable_note": self.note,
            "coverage": {
                "repo_count": self.repo_count,
                "ingested_repo_count": self.ingested_repo_count,
            },
        }


def coverage_of(
    repo_count: int, ingested_repo_count: int, *, reachable: bool = True
) -> Coverage:
    """The one place the answerable predicate is decided.

    Identical by construction to ``health()``'s ``seeded``, because a header
    that reads "0 repos" beside an answer strip that reads "not resolved by any
    repository" is the contradiction this function exists to remove.
    """
    if not reachable:
        reason = UNREACHABLE
    elif repo_count <= 0:
        reason = EMPTY_DATASET
    elif ingested_repo_count <= 0:
        reason = NO_INGESTED_HISTORY
    else:
        reason = None
    return Coverage(
        answerable=reason is None,
        reason=reason,
        repo_count=max(0, repo_count),
        ingested_repo_count=max(0, ingested_repo_count),
    )


@dataclass
class RepoRecord:
    """One repository as the console knows it, before any timestamp is applied."""

    id: int
    slug: str
    name: str
    service: str = ""
    first_ts: int = 0
    last_ts: int = 0
    snapshots: int = 0
    provenance: str = "git-lockfile-history"
    origin: str = ""
    synthetic: bool = False

    def as_dict(self) -> dict:
        out = {
            "id": self.id,
            "slug": self.slug,
            "name": self.name,
            "service": self.service,
            "first_ts": self.first_ts,
            "last_ts": self.last_ts,
            "first_ts_iso": iso(self.first_ts) if self.first_ts else None,
            "last_ts_iso": iso(self.last_ts) if self.last_ts else None,
            "snapshots": self.snapshots,
            "provenance": self.provenance,
            "origin": self.origin,
            "synthetic": self.synthetic,
        }
        if self.synthetic:
            out["synthetic_note"] = SYNTHETIC_CAVEAT
        return out


@dataclass
class Console:
    """Read-only view of one HydraDB dataset, for one incident."""

    client: HydraClient = field(default_factory=HydraClient.from_env)
    schema: Schema = DEMO_SCHEMA
    incident: Incident = field(default_factory=load_incident)
    #: The one place a statement reaches the network. Injectable so that unit
    #: tests can drive the whole console — classification, ranking, the honesty
    #: fields — off canned rows without a database, and so that there is exactly
    #: one seam to fake rather than a mock per method.
    reader: Callable[..., tuple[list[list[object]], bool]] = fetch_all
    #: How long a populated dataset read stays good for. The dataset is written
    #: by another process, so every cached answer here is a statement about when
    #: we last looked; this is how long that is allowed to go unsaid. Two
    #: label-scan queries per window, against an exposure read every 55 ms.
    cache_ttl: float = 30.0
    #: Injected so the expiry is testable without sleeping.
    clock: Callable[[], float] = time.monotonic
    #: instant -> ``(ranking, truncated, capped)``. Bounded because the scrubber
    #: can generate a lot of distinct instants in a minute of dragging. The
    #: completeness flags are cached *with* the ranking rather than recomputed,
    #: so a cache hit cannot serve a partial answer as a whole one.
    _rank_cache: dict[int, tuple[list[dict], bool, bool]] = field(
        default_factory=dict, repr=False
    )
    _repos: list[RepoRecord] | None = field(default=None, repr=False)
    _repos_at: float = field(default=0.0, repr=False)
    #: Did the cached repository directory itself hit the row cap? A short
    #: directory is not merely a slow answer: every exposure verdict is a join
    #: against this list, so a truncated one silently drops repositories from
    #: *all* three counts rather than from one of them.
    _repos_truncated: bool = field(default=False, repr=False)
    #: Slugs with a finished ingest watermark, cached like the directory: read
    #: once per console rather than per answer, because coverage is a property
    #: of the dataset and the scrubber issues an exposure read every 55 ms. Both
    #: caches stay empty while the dataset is, so a console outliving an ingest
    #: is not stuck refusing to answer.
    _ingested: set[str] | None = field(default=None, repr=False)
    _ingested_at: float = field(default=0.0, repr=False)
    _watermarks_truncated: bool = field(default=False, repr=False)

    # ------------------------------------------------------------------ plumbing

    def _rows(self, query: Query, *, page_size: int = 4096) -> tuple[list[dict], bool]:
        rows, truncated = self.reader(
            self.client, query.cypher, query.params, page_size=page_size
        )
        return query.shape(rows), truncated

    def _fresh(self, read_at: float) -> bool:
        """Is a cached dataset read still inside its window?"""
        return self.clock() - read_at < self.cache_ttl

    def _fork(self) -> Console:
        """A sibling console sharing configuration but not the HTTP client.

        ``urllib`` opens a fresh connection per request, so the client is safe to
        share, but its ``stats`` counter is not; forking keeps the per-request
        query count in the response honest under the ranking thread pool.
        """
        return replace(
            self,
            client=HydraClient(config=self.client.config),
            _rank_cache={},
            _repos=self._repos,
            _repos_at=self._repos_at,
        )

    # ---------------------------------------------------------------- directory

    def repositories(self, *, refresh: bool = False) -> list[RepoRecord]:
        """Every repository in the dataset, cached once the first read finds one.

        The dataset is loaded by a separate process, so this cache is a claim
        about when we last looked, and it expires: a repository ingested into a
        running console appears within :attr:`cache_ttl` rather than at the next
        restart.

        Nothing is cached at all while the answer is *nothing*. The two stale
        directions are not equivalent — a directory short by one repository
        costs a count, an empty one withholds every answer the console has, as
        no coverage — so the empty read is re-read immediately and does not wait
        out the window. It costs one label scan, and only until the graph has
        anything in it.
        """
        if self._repos is not None and not refresh and self._fresh(self._repos_at):
            return self._repos
        rows, truncated = self._rows(queries.repo_directory(self.schema))
        records = []
        for row in rows:
            slug = str(row.get("slug") or "")
            if not slug:
                continue
            records.append(
                RepoRecord(
                    id=int(row.get("id") or 0),
                    slug=slug,
                    name=str(row.get("name") or slug),
                    service=str(row.get("service") or ""),
                    first_ts=int(row.get("first_ts") or 0),
                    last_ts=int(row.get("last_ts") or 0),
                    snapshots=int(row.get("snapshots") or 0),
                    provenance=str(row.get("provenance") or "git-lockfile-history"),
                    origin=str(row.get("origin") or ""),
                    synthetic=bool(row.get("synthetic")),
                )
            )
        records.sort(key=lambda r: r.slug)
        self._repos = records or None
        self._repos_at = self.clock()
        self._repos_truncated = truncated
        return records

    def ingested_slugs(self, *, refresh: bool = False) -> set[str]:
        """Repositories whose ingest actually finished, cached once one exists.

        The watermark is written *after* a successful run, so its presence is
        evidence that history was loaded rather than that a node exists.
        """
        if self._ingested is not None and not refresh and self._fresh(self._ingested_at):
            return self._ingested
        marks, truncated = self._rows(queries.watermarks(self.schema))
        found = {str(row["slug"]) for row in marks if row.get("slug")}
        # Expires, and is not cached while empty, both for the reasons in
        # :meth:`repositories`: the watermark is written by another process, and
        # "no history yet" is a statement about when we looked.
        self._ingested = found or None
        self._ingested_at = self.clock()
        self._watermarks_truncated = truncated
        return found

    def coverage(self, *, refresh: bool = False) -> Coverage:
        """Can this dataset answer a question, and if not, why not.

        Two cached reads, shared with :meth:`health`, so threading this through
        the answer path costs the scrubber nothing after the first request.
        Errors are *not* swallowed here: a node that refuses the query already
        reaches the browser as a 502, which is itself a refusal to answer.
        :meth:`health` is the one place a failed read becomes a reported state
        rather than an exception.
        """
        repos = self.repositories(refresh=refresh)
        slugs = {r.slug for r in repos}
        ingested = self.ingested_slugs(refresh=refresh)
        return coverage_of(len(repos), len(ingested & slugs))

    def maintainers(self) -> tuple[list[dict], bool]:
        """Every maintainer account, and whether that list is complete."""
        rows, truncated = self._rows(queries.maintainer_directory(self.schema))
        out = [
            {"id": int(row["id"]), "name": str(row["name"])}
            for row in rows
            if row.get("name")
        ]
        out.sort(key=lambda m: m["name"])
        return out, truncated

    # ----------------------------------------------------------------- exposure

    def exposure(self, package: str, at: int) -> dict:
        """Which repositories resolved which versions of ``package`` at ``at``.

        The single query behind the timeline scrubber. It is one id-anchored
        two-pattern join — measured at single-digit milliseconds on the PoC's
        111k-edge graph — which is what lets the slider feel continuous.
        """
        package = (package or "").strip()
        if not package:
            raise ConsoleError("package is required")
        window = self.incident.window
        malicious = self.incident.malicious_versions(package)
        pid = package_id(package)

        # Resolved before the timer so ``elapsed_ms`` stays a measurement of the
        # exposure traversal, and before the answer is shaped because it decides
        # whether this answer is allowed to contain a verdict at all.
        coverage = self.coverage()

        started = time.perf_counter()
        exists_rows, _ = self._rows(queries.package_exists(self.schema, pid))
        rows: list[dict] = []
        truncated = False
        if exists_rows:
            rows, truncated = self._rows(
                queries.repos_resolving_package(self.schema, pid, at)
            )
        elapsed_ms = (time.perf_counter() - started) * 1000

        by_slug: dict[str, list[dict]] = {}
        for row in rows:
            by_slug.setdefault(str(row.get("slug")), []).append(row)

        repos = []
        directory = self.repositories()
        truncated = truncated or self._repos_truncated
        for record in directory:
            verdict = classify(
                record.slug, by_slug.get(record.slug, []), malicious, window, at
            )
            verdict.update(
                {
                    "name": record.name,
                    "service": record.service,
                    "provenance": record.provenance,
                    "origin": record.origin,
                    "synthetic": record.synthetic,
                }
            )
            if record.synthetic:
                verdict["synthetic_note"] = SYNTHETIC_CAVEAT
            repos.append(verdict)
        repos.sort(key=sort_key)

        out = {
            "question": (
                "which repositories had a lockfile resolving this package at this "
                "instant, and was any of those versions a malicious one"
            ),
            "package": package,
            "at": at,
            "at_iso": iso(at),
            "in_exposure_window": window.contains(at),
            "package_in_graph": bool(exists_rows),
            "malicious_versions": sorted(malicious),
            "counts": summarize(repos),
            "repos": repos,
            "elapsed_ms": round(elapsed_ms, 2),
            "evidence": EVIDENCE,
            "caveat": CAVEAT,
            **completeness(truncated),
            **coverage.as_dict(),
        }
        if not coverage.answerable:
            # An absence is only evidence when something was there to be absent
            # from. Without coverage there is no negative to state, proven or
            # otherwise, so the note says what is missing instead of what was
            # found, and the UI refuses to draw a verdict from this payload.
            out["note"] = coverage.note
        elif not exists_rows:
            out["note"] = (
                f"no package node for {package!r} exists in this dataset, so no "
                "repository has ever resolved it at any instant. That is a real "
                "absence, not a lookup failure"
            )
        elif not rows:
            # Only a *complete* empty result is a proven negative. If the read
            # was cut short, an empty page says nothing at all.
            out["note"] = (
                TRUNCATION_CAVEAT
                if truncated
                else "the package is in the graph but no repository resolved any "
                "version of it at this instant — a proven negative for this timestamp"
            )
        return out

    def version_footprint(self, package: str, version: str, at: int) -> dict:
        """Did anything resolve this exact version at this instant?

        The sharpest form of the negative: a malicious version that was never
        resolved by anything has no node in the graph at all, and the console can
        say so after a single id lookup rather than a scan.

        Which is exactly why ``truncated`` has to come back with the answer. The
        whole value of this method is the strength of its negative, and a cut-off
        read produces a *weak* negative wearing a strong one's clothes.
        """
        coverage = self.coverage()
        vid = version_id(package, version)
        exists, _ = self._rows(queries.version_exists(self.schema, vid))
        rows: list[dict] = []
        truncated = False
        if exists:
            rows, truncated = self._rows(
                queries.repos_resolving_version(self.schema, vid, at)
            )
        slugs = sorted({str(r.get("slug")) for r in rows})
        if not coverage.answerable:
            # "No node for this version" is the sharpest negative this product
            # states. In an empty dataset it is also trivially true of every
            # version that has ever existed, which makes it worthless and, said
            # confidently, dangerous.
            note = coverage.note
        elif exists:
            note = TRUNCATION_CAVEAT if truncated else None
        else:
            note = (
                "this version has no node in the graph: no lockfile in the dataset "
                "ever resolved it, at any instant in the ingested history"
            )
        return {
            "package": package,
            "version": version,
            "key": f"{package}@{version}",
            "at": at,
            "at_iso": iso(at),
            "version_in_graph": bool(exists),
            "repo_count": len(slugs),
            # A truncated read can only establish a floor on the footprint.
            "repo_count_is_lower_bound": truncated,
            "repos": slugs,
            "evidence": EVIDENCE,
            "caveat": CAVEAT,
            "note": note,
            **completeness(truncated),
            **coverage.as_dict(),
        }

    # ------------------------------------------------------------- blast radius

    def blast_radius(self, package: str, at: int) -> dict:
        """A node-link view of repo -> version -> package -> maintainer at ``at``.

        Same traversal as :meth:`exposure`, re-shaped for the graph panel, plus
        the package's maintainer accounts. Node ids are strings so the front end
        never has to reason about 63-bit integers in JavaScript, where they would
        silently lose precision.
        """
        exposure = self.exposure(package, at)
        maint_rows, maint_truncated = self._rows(
            queries.maintainers_of_package(self.schema, package_id(package))
        )
        # Either read can be cut, and either way the drawing is missing nodes.
        truncated = bool(exposure["truncated"]) or maint_truncated
        maintainers = sorted({str(r.get("maintainer")) for r in maint_rows if r.get("maintainer")})

        nodes: list[dict] = [
            {
                "id": f"pkg:{package}",
                "kind": "package",
                "label": package,
                "detail": f"{len(maintainers)} maintainer account(s) can publish it",
            }
        ]
        edges: list[dict] = []
        seen_versions: set[str] = set()

        for repo in exposure["repos"]:
            if repo["status"] == "NOT_RESOLVED":
                continue
            repo_node = f"repo:{repo['slug']}"
            nodes.append(
                {
                    "id": repo_node,
                    "kind": "repo",
                    "label": repo["slug"],
                    "status": repo["status"],
                    "synthetic": repo.get("synthetic", False),
                    "detail": repo["basis"],
                }
            )
            for version in repo["versions"]:
                key = f"{package}@{version['version']}"
                version_node = f"ver:{key}"
                if key not in seen_versions:
                    seen_versions.add(key)
                    nodes.append(
                        {
                            "id": version_node,
                            "kind": "version",
                            "label": key,
                            "version": version["version"],
                            "malicious": version["malicious"],
                            "detail": (
                                "on the incident's malicious version list"
                                if version["malicious"]
                                else "not on the incident's malicious version list"
                            ),
                        }
                    )
                    edges.append(
                        {
                            "source": version_node,
                            "target": f"pkg:{package}",
                            "kind": "VERSION_OF",
                        }
                    )
                edges.append(
                    {
                        "source": repo_node,
                        "target": version_node,
                        "kind": "RESOLVES",
                        "malicious": version["malicious"],
                        "valid_from": version["valid_from"],
                        "valid_to": version["valid_to"],
                        "valid_from_iso": version["valid_from_iso"],
                        "valid_to_iso": version["valid_to_iso"],
                        "held_for": version["held_for"],
                    }
                )

        for name in maintainers:
            nodes.append(
                {
                    "id": f"maint:{name}",
                    "kind": "maintainer",
                    "label": name,
                    "detail": "can publish this package today",
                }
            )
            edges.append(
                {"source": f"maint:{name}", "target": f"pkg:{package}", "kind": "MAINTAINS"}
            )

        return {
            "question": "what does this package reach at this instant",
            "package": package,
            "at": at,
            "at_iso": iso(at),
            "counts": exposure["counts"],
            "version_count": len(seen_versions),
            "maintainers": maintainers,
            "nodes": nodes,
            "edges": edges,
            "exposed_repos": [
                r["slug"] for r in exposure["repos"] if r["status"] == EXPOSED
            ],
            "evidence": EVIDENCE,
            "caveat": CAVEAT,
            "maintainer_caveat": MAINTAINER_CAVEAT,
            **completeness(truncated),
            # Cached, and already computed by the exposure read above. A drawing
            # with no nodes is the most confident empty statement on the page.
            **self.coverage().as_dict(),
        }

    # --------------------------------------------------------- maintainer reach

    def maintainer_reach(self, name: str, at: int) -> dict:
        """One account's trust radius: packages owned, packages and repos reached."""
        name = (name or "").strip()
        if not name:
            raise ConsoleError("maintainer name is required")
        mid = maintainer_id(name)
        owned, owned_truncated = self._rows(
            queries.maintained_packages(self.schema, mid)
        )
        rows, reach_truncated = self._rows(
            queries.maintainer_reach(self.schema, mid, at)
        )
        truncated = owned_truncated or reach_truncated

        packages: set[str] = set()
        pairs: set[tuple[str, str]] = set()
        by_repo: dict[str, set[str]] = {}
        for row in rows:
            package = str(row.get("package"))
            slug = str(row.get("slug"))
            packages.add(package)
            pairs.add((slug, package))
            by_repo.setdefault(slug, set()).add(package)

        synthetic = {r.slug for r in self.repositories() if r.synthetic}
        reached = sorted(
            (
                {
                    "slug": slug,
                    "via_packages": sorted(via),
                    "package_count": len(via),
                    "synthetic": slug in synthetic,
                }
                for slug, via in by_repo.items()
            ),
            key=lambda r: (-r["package_count"], r["slug"]),
        )
        return {
            "question": "which packages and repositories does this account reach",
            "maintainer": name,
            "at": at,
            "at_iso": iso(at),
            "exists": bool(owned),
            "maintains_package_count": len(owned),
            "maintains_packages": sorted(str(r.get("package")) for r in owned),
            "reached_package_count": len(packages),
            "reached_packages": sorted(packages),
            "reached_repo_count": len(reached),
            "reached_repos": reached,
            # Repo count saturates once a package is ubiquitous; the finer
            # repo x package surface is what actually ranks accounts apart.
            "repo_package_pairs": len(pairs),
            # Every count above is a floor when this is set.
            "counts_are_lower_bounds": truncated,
            "evidence": EVIDENCE,
            "caveat": CAVEAT,
            "maintainer_caveat": MAINTAINER_CAVEAT,
            **completeness(truncated),
        }

    def maintainer_ranking(self, at: int, limit: int = 12) -> dict:
        """Every account in the overlay, ranked by what it reaches at ``at``.

        Scored with one id-anchored query per account. Three shapes were measured
        against the 86k-edge demo dataset before settling on this one:

        =========================================  ========
        one whole-graph maintainer join (PoC)       4,785 ms
        154 id-anchored ``maintainer_reach`` reads  2,800 ms
        9 per-repo closure reads + a client-side
        fold against a MAINTAINS scan               9,100 ms
        =========================================  ========

        The last is the shape that *looks* cleverest — ten queries instead of a
        hundred and fifty-four — and it is three times slower, because a repo's
        whole live closure is thousands of rows while one account's reach is
        tens. Widening the thread pool does not help either (6, 12 and 20 workers
        all land within 3 % of each other): the node serialises these reads.
        So: many small anchored queries, and a cache, because the answer only
        changes when the instant does.
        """
        cached = self._rank_cache.get(at)
        started = time.perf_counter()
        if cached is None:
            everyone, truncated = self.maintainers()
            # Two separate ways to end up with a short leaderboard: the account
            # list itself was cut, or this policy capped it. Both mean an account
            # that is not on the board may still outrank the one at the top.
            capped = len(everyone) > MAX_RANKED_MAINTAINERS
            accounts = everyone[:MAX_RANKED_MAINTAINERS]
            forks = [self._fork() for _ in range(RANK_WORKERS)]
            with ThreadPoolExecutor(max_workers=RANK_WORKERS) as pool:
                scored = list(
                    pool.map(
                        lambda pair: forks[pair[0] % RANK_WORKERS]._score(pair[1], at),
                        enumerate(accounts),
                    )
                )
            # One account's reach being cut means that account's score is a
            # floor, which means the *order* is not trustworthy either.
            truncated = truncated or capped or any(s["truncated"] for s in scored)
            scored.sort(
                key=lambda s: (
                    -s["repo_package_pairs"],
                    -s["reached_package_count"],
                    s["maintainer"],
                )
            )
            for position, entry in enumerate(scored, start=1):
                entry["rank"] = position
            self._rank_cache[at] = (scored, truncated, capped)
            if len(self._rank_cache) > 64:
                self._rank_cache.pop(next(iter(self._rank_cache)))
            cached = (scored, truncated, capped)
        ranking, truncated, capped = cached
        elapsed_ms = (time.perf_counter() - started) * 1000

        return {
            "question": (
                "if one npm account were phished tomorrow, which one reaches the "
                "most of our repositories"
            ),
            "at": at,
            "at_iso": iso(at),
            "scored_accounts": len(ranking),
            "ranking": ranking[: max(1, int(limit))],
            "ranked_all_accounts": not capped,
            "max_ranked_accounts": MAX_RANKED_MAINTAINERS,
            "cached": bool(elapsed_ms < 1.0),
            "elapsed_ms": round(elapsed_ms, 2),
            "evidence": EVIDENCE,
            "caveat": CAVEAT,
            "maintainer_caveat": MAINTAINER_CAVEAT,
            **completeness(truncated),
        }

    def _score(self, account: dict, at: int) -> dict:
        rows, truncated = self._rows(
            queries.maintainer_reach(self.schema, account["id"], at)
        )
        packages: set[str] = set()
        repos: set[str] = set()
        pairs: set[tuple[str, str]] = set()
        for row in rows:
            package = str(row.get("package"))
            slug = str(row.get("slug"))
            packages.add(package)
            repos.add(slug)
            pairs.add((slug, package))
        return {
            "maintainer": account["name"],
            "reached_package_count": len(packages),
            "reached_repo_count": len(repos),
            "repo_package_pairs": len(pairs),
            "reached_packages": sorted(packages)[:12],
            "reached_repos": sorted(repos),
            "truncated": truncated,
        }

    # ------------------------------------------------------------------- health

    def health(self, *, count_edges: bool = False) -> dict:
        """Is a node reachable, and does it hold a dataset worth showing?

        Answered from two label scans over a handful of nodes — the repository
        directory and the ingest watermarks — because the obvious probe is not
        affordable. Counting RESOLVES edges costs ~9 s on this dataset even
        anchored per repository, and abandoning the read after one row costs the
        same (the engine materialises the match before it limits), so an edge
        count is available only when ``count_edges`` is asked for explicitly.
        A watermark is better evidence anyway: the ingest writes it *after* a
        successful run, so its presence means a seed finished, not merely that
        some edges exist.
        """
        edges = None
        truncated = False
        try:
            repos = self.repositories(refresh=True)
            ingested = self.ingested_slugs(refresh=True)
            truncated = self._repos_truncated or self._watermarks_truncated
            if count_edges:
                edges = 0
                for record in repos:
                    rows, _ = self._rows(
                        queries.resolves_edge_count(self.schema, record.id)
                    )
                    edges += int(rows[0]["edges"]) if rows else 0
            reachable = True
            error = None
        except Exception as exc:  # noqa: BLE001 - reported, never raised, to the UI
            repos, ingested, reachable, error = [], set(), False, str(exc)
        slugs = {r.slug for r in repos}
        coverage = coverage_of(
            len(repos), len(ingested & slugs), reachable=reachable
        )
        return {
            "reachable": reachable,
            "error": error,
            "endpoint": self.client.config.query_url,
            "namespace": self.client.config.namespace,
            "cell": self.client.config.cell,
            "labels": {
                "repo": self.schema.repo,
                "package": self.schema.package,
                "version": self.schema.version,
                "maintainer": self.schema.maintainer,
                "watermark": self.schema.watermark,
                "resolves": self.schema.resolves,
            },
            "repo_count": len(repos),
            "synthetic_repo_count": sum(1 for r in repos if r.synthetic),
            "ingested_repo_count": len(ingested & slugs),
            "unwatermarked_repos": sorted(slugs - ingested),
            "resolves_edges": edges,
            "incident": self.incident.title,
            # Kept verbatim, and now redundant by construction: ``answerable``
            # is the same predicate, reached through the same function the
            # answer path uses, so the header and the answer strip cannot
            # disagree about whether this dataset holds anything.
            "seeded": bool(repos) and bool(ingested & slugs),
            **completeness(truncated),
            **coverage.as_dict(),
        }

    def overview(self) -> dict:
        """Everything the page needs before the first scrub."""
        repositories = [r.as_dict() for r in self.repositories()]
        return {
            "incident": self.incident.as_dict(),
            "repositories": repositories,
            "evidence": EVIDENCE,
            "caveat": CAVEAT,
            "maintainer_caveat": MAINTAINER_CAVEAT,
            "synthetic_caveat": SYNTHETIC_CAVEAT,
            "truncation_caveat": TRUNCATION_CAVEAT,
            **completeness(self._repos_truncated),
        }


def default_window() -> Window:
    return load_incident().window


__all__ = [
    "EMPTY_DATASET",
    "MAX_RANKED_MAINTAINERS",
    "NO_INGESTED_HISTORY",
    "RANK_WORKERS",
    "UNANSWERABLE_NOTES",
    "UNREACHABLE",
    "Console",
    "ConsoleError",
    "Coverage",
    "RepoRecord",
    "coverage_of",
    "humanize",
]
