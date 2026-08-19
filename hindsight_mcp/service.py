"""What each tool actually does, with no MCP types anywhere near it.

Keeping the tool bodies here rather than in :mod:`hindsight_mcp.server` means
the interesting behaviour — the read-only guard, the row cap, the honesty
fields — is testable by calling plain Python functions, and the server module
stays a thin registration layer.

Three rules are enforced at this layer and nowhere else:

**Nothing writes.** Every agent-supplied statement goes through
:func:`hindsight_mcp.guard.assert_read_only` before it reaches the client, and
the canned tools compose their Cypher from the parameterised builders in
:mod:`hindsight.queries` — the same builders the web console runs, so the two
surfaces cannot answer the same question differently.

**Nothing overstates the evidence.** A RESOLVES edge proves a lockfile pinned a
version; it does not prove the artefact was built, installed or deployed. Every
result derived from those edges therefore carries ``evidence: "resolved"`` and
an explicit caveat, and no field in this module is named or phrased as though it
described a deployment. That is a product requirement, not decoration: the whole
value of the tool is being trusted during an incident.

**Nothing states a negative it cannot back.** A tool that answers "nothing
resolved this, and that is a proven negative" is worth having only when the
dataset was in a position to say otherwise. Against an empty or mis-pointed
label namespace every read comes back empty and that sentence turns a
configuration mistake into "you were not exposed" — which is worse here than in
the console, because the agent has no screen on which to notice the empty page
and will relay the sentence verbatim. So every answer below carries the
:class:`~hindsight.coverage.Coverage` verdict, decided by the same core
predicate the console uses, and no refusal is dressed up as a result.

**Nothing states a total it only has a floor for.** Every tool below reads
under a row cap, and a capped read makes two things untrue at once: the counts
are floors rather than totals, and a name's absence from the list is a fact
about the page rather than about the graph. The console has said both of those
things since it learned to; this surface said neither, on any canned tool, and
returned bare integers an agent had no way to know were short. The vocabulary
now comes from :mod:`hindsight.envelope`, the same module the console reads it
from, and the fields appear only when the read actually was cut — an
always-present ``"counts_are_lower_bounds": false`` is noise a model will
eventually narrate.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from hindsight import queries
from hindsight.client import HydraClient, HydraError
from hindsight.coverage import Coverage, coverage_of
from hindsight.envelope import (
    EVIDENCE,
    RAW_READ_CAVEAT,
    REACH_FLOOR_NOTE,
    UNVERIFIED_ABSENCE_NOTE,
    cypher_truncation_note,
    lower_bounds,
)
from hindsight.graphbuild import DEFAULT_SCHEMA, Schema
from hindsight.ids import maintainer_id, package_id, repo_id, version_id
from hindsight.queries import Query, UnknownKind, normalise_kind

from .guard import UnsafeCypher, assert_read_only
from .schema_doc import FAR_FUTURE, graph_schema, render_markdown

#: What the graph can prove, re-exported from :mod:`hindsight.envelope` so that
#: this surface and the console cannot spell the same evidence two ways. They
#: did: the console emitted ``"RESOLVED"`` here, and an agent quoting its own
#: answer to a responder looking at the console was describing a different
#: value for the same fact.

CAVEAT = (
    "Evidence is lockfile resolution only: a committed lockfile in this "
    "repository pinned this exact version over the stated interval. That is not "
    "proof the dependency was installed, built, executed or deployed, and it is "
    "not proof of compromise. Treat this as the scope to investigate."
)

MAINTAINER_CAVEAT = (
    "Maintainer edges are a present-tense snapshot of npm registry ownership, "
    "so this reads as: the packages this account maintains TODAY were resolved "
    "by these repositories at the stated instant. It is a trust-radius estimate "
    "for 'if this account were phished tomorrow', not a historical record of who "
    "had publish rights then."
)

#: The engine caps page_size at 4096, so a single-page read cannot return more.
MAX_PAGE = 4096


class ToolInputError(ValueError):
    """A tool was called with an argument that cannot be interpreted."""


@dataclass(frozen=True)
class Limits:
    """Bounds applied to every query this server issues.

    ``max_rows`` is enforced by asking for exactly that page size and treating a
    returned cursor as truncation, rather than by rewriting the agent's query —
    injecting a ``LIMIT`` into a statement someone else wrote is how a guard
    silently changes an answer.

    ``deadline_seconds`` is the client-side deadline. The server has its own
    hard 30 s cap that no client setting can raise, so this only ever tightens.
    """

    max_rows: int = 1000
    deadline_seconds: float = 20.0

    def __post_init__(self) -> None:
        object.__setattr__(self, "max_rows", max(1, min(int(self.max_rows), MAX_PAGE)))
        object.__setattr__(
            self, "deadline_seconds", max(0.5, min(float(self.deadline_seconds), 30.0))
        )


def unwrap_cell(cell: object) -> object:
    """HydraDB wire cells are ``{"type": .., "value": ..}``, sometimes nested."""
    if isinstance(cell, dict) and "type" in cell and "value" in cell:
        return unwrap_cell(cell["value"])
    if isinstance(cell, list):
        return [unwrap_cell(c) for c in cell]
    if isinstance(cell, dict):
        return {k: unwrap_cell(v) for k, v in cell.items()}
    return cell


def iso(ts: int | None) -> str | None:
    """UTC ISO-8601 for a unix second, or ``None`` for an open bound."""
    if ts is None or ts >= FAR_FUTURE:
        return None
    return datetime.fromtimestamp(int(ts), UTC).isoformat().replace("+00:00", "Z")


def to_epoch(value: object, *, field_name: str = "timestamp") -> int:
    """Accept unix seconds or ISO-8601 and return unix seconds.

    Agents reach for ``"2025-09-08T20:33:00Z"`` far more readily than for
    ``1757363580``, and a tool that rejects the natural form burns a turn on
    arithmetic that this function can just do.
    """
    if isinstance(value, bool):
        raise ToolInputError(f"{field_name} must be unix seconds or an ISO-8601 string")
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise ToolInputError(f"{field_name} is empty")
        if text.lstrip("-").isdigit():
            return int(text)
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ToolInputError(
                f"{field_name}={value!r} is neither unix seconds nor ISO-8601: {exc}"
            ) from None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return int(parsed.timestamp())
    raise ToolInputError(f"{field_name} must be unix seconds or an ISO-8601 string")


def split_version(name: str) -> tuple[str, str]:
    """``'chalk@5.3.0'`` -> ``('chalk', '5.3.0')``, scoped names included.

    Splitting on the *last* ``@`` is what makes ``@babel/core@7.24.0`` work.
    """
    text = (name or "").strip()
    if text.count("@") == 0 or (text.startswith("@") and text.count("@") == 1):
        raise ToolInputError(
            f"kind='version' needs 'package@version' (e.g. 'chalk@5.3.0'), got {name!r}"
        )
    package, _, version = text.rpartition("@")
    if not package or not version:
        raise ToolInputError(f"could not split {name!r} into package and version")
    return package, version


def _at_instant(at: int) -> dict:
    return {"at": at, "at_iso": iso(at)}


def _interval(valid_from: object, valid_to: object) -> dict:
    """Report an interval with both its raw bounds and their readable form."""
    start = int(valid_from) if isinstance(valid_from, int) else None
    end = int(valid_to) if isinstance(valid_to, int) else None
    return {
        "valid_from": start,
        "valid_to": end,
        "valid_from_iso": iso(start),
        "valid_to_iso": iso(end),
        "open_interval": end is not None and end >= FAR_FUTURE,
    }


@dataclass
class Hindsight:
    """The tool implementations, over one HydraDB client and label schema."""

    client: HydraClient = field(default_factory=HydraClient.from_env)
    schema: Schema = DEFAULT_SCHEMA
    limits: Limits = field(default_factory=Limits)
    #: How long a populated coverage read stays good for. The graph is written
    #: by a separate ingest process, so a cached count is a claim about when this
    #: server last looked, and this is how long that is allowed to go unsaid.
    #: Deliberately the console's window: two surfaces that tolerate different
    #: amounts of staleness can disagree about whether the same graph is
    #: answerable, which is the disagreement this whole mechanism exists to stop.
    cache_ttl: float = 30.0
    #: Injected so the expiry is testable without sleeping.
    clock: Callable[[], float] = time.monotonic
    _repos: int | None = field(default=None, repr=False)
    _repos_at: float = field(default=0.0, repr=False)
    _ingested: int | None = field(default=None, repr=False)
    _ingested_at: float = field(default=0.0, repr=False)

    # ------------------------------------------------------------------ plumbing

    def _run(self, query: Query) -> tuple[list[list[object]], bool]:
        """Execute a built query under the row cap. Returns ``(rows, truncated)``."""
        result = self.client.query(
            query.cypher,
            query.params,
            timeout=self.limits.deadline_seconds,
            page_size=self.limits.max_rows,
        )
        rows = [[unwrap_cell(cell) for cell in row] for row in result.get("rows", [])]
        truncated = result.get("next_cursor") is not None or len(rows) > self.limits.max_rows
        return rows[: self.limits.max_rows], truncated

    def _dicts(self, query: Query) -> tuple[list[dict], bool]:
        rows, truncated = self._run(query)
        return query.shape(rows), truncated

    def _node(self, kind: str, name: str) -> dict:
        """Resolve a name to an id and say whether the graph actually holds it."""
        canonical = normalise_kind(kind)
        if canonical == "version":
            package, version = split_version(name)
            node_id = version_id(package, version)
        else:
            node_id = {
                "repo": repo_id,
                "package": package_id,
                "maintainer": maintainer_id,
            }[canonical](name)

        rows, _ = self._dicts(queries.node_by_id(self.schema, canonical, node_id))
        out = {
            "kind": canonical,
            "name": name,
            "label": queries.label_for(self.schema, canonical),
            "id": node_id,
            "exists": bool(rows),
        }
        if rows:
            out["properties"] = rows[0]
        return out

    # ------------------------------------------------------------------ coverage

    def _fresh(self, read_at: float) -> bool:
        """Is a cached dataset read still inside its window?"""
        return self.clock() - read_at < self.cache_ttl

    def _count(self, query: Query) -> int:
        rows, _ = self._dicts(query)
        return int(rows[0]["count"]) if rows else 0

    def coverage(self) -> Coverage:
        """Can this dataset answer a question at all, and if not, why not.

        Two ``count(*)`` reads, cached, because every tool below needs the same
        verdict and an agent works through several of them in a row.

        Counts and not lists. Reading the directory and the watermarks as rows
        and intersecting their slugs is the obvious implementation and it breaks
        at exactly the scale where it matters: past the row cap the two reads
        can return pages with nothing in common, and a dataset holding a hundred
        thousand repositories is declared to hold no ingested history at all.
        Nothing about "is there anything here" needs the rows, and a count of
        one row cannot be truncated.

        Nothing is cached while the answer is *nothing*, matching the console:
        the two directions of staleness are not equivalent, since a count short
        by one costs a number and an empty one withholds every answer this
        server has. An agent session outliving an ingest must not be stuck
        refusing questions the graph can now answer.

        A failed read is deliberately not caught: the server already turns a
        :class:`HydraError` into a tool error the agent can act on, which is
        itself a refusal to answer, whereas swallowing it here would manufacture
        exactly the confident-sounding empty result this method exists to
        prevent.
        """
        repos_q, marks_q = queries.dataset_counts(self.schema)
        if self._repos is None or not self._fresh(self._repos_at):
            found = self._count(repos_q)
            self._repos = found or None
            self._repos_at = self.clock()
        if self._ingested is None or not self._fresh(self._ingested_at):
            found = self._count(marks_q)
            self._ingested = found or None
            self._ingested_at = self.clock()
        return coverage_of(self._repos or 0, self._ingested or 0)

    # --------------------------------------------------------------------- tools

    def schema_document(self, *, as_markdown: bool = True) -> str | dict:
        return render_markdown(self.schema) if as_markdown else graph_schema(self.schema)

    def cypher(self, query: str, parameters: dict | None = None) -> dict:
        """Run one read-only statement and return plain JSON rows.

        Raises :class:`~hindsight_mcp.guard.UnsafeCypher` before touching the
        database if the statement could write, and :class:`HydraError` if the
        engine refuses it. Both messages are meant to be read by the caller and
        acted on.

        The rows come back with a caveat rather than an evidence label, because
        none of the classification the canned tools apply has happened here: the
        coverage predicate has not been consulted, so an empty result from this
        tool is not a negative and there is nothing in the response entitled to
        be read as one. Saying that costs a field and saves the failure where an
        agent writes its own ``MATCH``, gets no rows out of a mis-pointed label
        namespace, and reports an all-clear.
        """
        assert_read_only(query)
        started = time.perf_counter()
        result = self.client.query(
            query,
            parameters or {},
            timeout=self.limits.deadline_seconds,
            page_size=self.limits.max_rows,
        )
        elapsed_ms = (time.perf_counter() - started) * 1000
        rows = [[unwrap_cell(cell) for cell in row] for row in result.get("rows", [])]
        # Three ways the same read can be short, and the engine owns one of them:
        # if it reports its own truncation we take its word rather than inferring
        # completeness from a cursor it chose not to hand back.
        truncated = (
            result.get("next_cursor") is not None
            or bool(result.get("truncated"))
            or len(rows) > self.limits.max_rows
        )
        capped = rows[: self.limits.max_rows]
        out = {
            "columns": result.get("columns", []),
            "rows": capped,
            "row_count": len(capped),
            "truncated": truncated,
            "row_cap": self.limits.max_rows,
            "elapsed_ms": round(elapsed_ms, 2),
            "caveat": RAW_READ_CAVEAT,
        }
        out.update(
            lower_bounds(
                truncated, note=cypher_truncation_note(self.limits.max_rows)
            )
        )
        return out

    def resolve_id(self, kind: str, name: str) -> dict:
        """Name -> id, so an agent can write id-anchored Cypher of its own."""
        node = self._node(kind, name)
        coverage = self.coverage()
        node["how_to_use"] = (
            f"pass id={node['id']} as a parameter and anchor the pattern on it, "
            f"e.g. MATCH (n:{node['label']} {{id: $id}}) ..."
        )
        node.update(coverage.as_dict())
        if not node["exists"]:
            # "This name has never been ingested" is a claim about the history
            # that was loaded, and an empty namespace has none: there, the
            # sentence is true of every name that has ever existed, which makes
            # it worthless and, stated to an agent, misleading.
            node["note"] = coverage.note if not coverage.answerable else (
                f"the id is well-defined — ids are derived from the name, not "
                f"allocated — but no {node['label']} node with it is in the "
                "graph, so this name has never been ingested"
            )
        return node

    def exposure_asof(
        self,
        package: str,
        version: str | None = None,
        at_timestamp: object = None,
    ) -> dict:
        """Which repositories resolved this package (or exact version) at an instant.

        With ``version`` set this is the incident question — "were we exposed to
        chalk@5.6.1 during the two-hour window" — and it can prove a negative:
        an empty ``repos`` list with ``version_known: true`` means the version
        exists in the graph and nothing resolved it then.

        That proof is conditional on ``answerable``. Read before the traversal
        because it decides whether this answer is allowed to contain a verdict at
        all: an empty ``repos`` list from a dataset holding no repositories is
        not a negative, it is the absence of a question.
        """
        if at_timestamp is None:
            raise ToolInputError(
                "at_timestamp is required: this is an AS-OF question and there is "
                "no sensible default instant"
            )
        at = to_epoch(at_timestamp, field_name="at_timestamp")
        coverage = self.coverage()
        if version:
            anchor = self._node("version", f"{package}@{version}")
            query = queries.repos_resolving_version(self.schema, anchor["id"], at)
        else:
            anchor = self._node("package", package)
            query = queries.repos_resolving_package(self.schema, anchor["id"], at)

        matches, truncated = self._dicts(query)
        repos = [
            {
                "slug": row.get("slug"),
                "name": row.get("name"),
                "package": row.get("package"),
                "version": row.get("version"),
                **_interval(row.get("valid_from"), row.get("valid_to")),
            }
            for row in matches
        ]
        repos.sort(key=lambda r: (str(r["slug"]), str(r["version"])))

        out = {
            "question": "which repositories resolved this package at this instant",
            "package": package,
            "version": version,
            **_at_instant(at),
            "anchor": anchor,
            "resolved_by_repo_count": len({r["slug"] for r in repos}),
            "repos": repos,
            "truncated": truncated,
            "evidence": EVIDENCE,
            "caveat": CAVEAT,
            **coverage.as_dict(),
            **lower_bounds(truncated),
        }
        if not coverage.answerable:
            # An absence is only evidence when there was something for it to be
            # absent from. Without coverage there is no negative to state, proven
            # or otherwise, so the note says what is missing rather than what was
            # found — and says it in the console's words, so that an agent and a
            # responder reading over its shoulder are told the same thing.
            out["note"] = coverage.note
        elif truncated:
            # The third state, and the one this surface used to skip straight
            # past. The list is a page, not the answer: "repo/x is not in the
            # repos array" is the question an agent actually asks of this result,
            # and under a cap the array cannot answer it either way.
            out["note"] = UNVERIFIED_ABSENCE_NOTE
        elif not anchor["exists"]:
            out["note"] = (
                f"no {anchor['label']} node for {anchor['name']!r} is in the graph "
                "at all, so no repository has ever resolved it. This is a real "
                "negative, not a lookup failure"
            )
        elif not repos:
            out["note"] = (
                "the package is in the graph but no repository resolved it at this "
                "instant — a proven negative for this timestamp"
            )
        return out

    def blast_radius(self, package: str, at_timestamp: object = None) -> dict:
        """Everything downstream of one package at an instant, with counts.

        Same traversal as :meth:`exposure_asof` without a version, folded into
        per-repository and per-version rollups, because "17 repos across 4
        versions" is the answer an incident responder needs first and the row
        list is the follow-up.
        """
        if at_timestamp is None:
            raise ToolInputError(
                "at_timestamp is required: blast radius is only meaningful at an instant"
            )
        at = to_epoch(at_timestamp, field_name="at_timestamp")
        coverage = self.coverage()
        anchor = self._node("package", package)
        matches, truncated = self._dicts(
            queries.repos_resolving_package(self.schema, anchor["id"], at)
        )

        by_repo: dict[str, dict] = {}
        versions: set[str] = set()
        for row in matches:
            slug = str(row.get("slug"))
            version = str(row.get("version"))
            versions.add(version)
            entry = by_repo.setdefault(
                slug, {"slug": slug, "name": row.get("name"), "versions": []}
            )
            entry["versions"].append(
                {"version": version, **_interval(row.get("valid_from"), row.get("valid_to"))}
            )
        for entry in by_repo.values():
            entry["versions"].sort(key=lambda v: str(v["version"]))
            entry["version_count"] = len(entry["versions"])

        repos = sorted(by_repo.values(), key=lambda r: (-r["version_count"], r["slug"]))
        out = {
            "question": "full blast radius of this package at this instant",
            "package": package,
            **_at_instant(at),
            "anchor": anchor,
            "repo_count": len(repos),
            "version_count": len(versions),
            "resolution_count": len(matches),
            "versions": sorted(versions),
            "repos": repos,
            "truncated": truncated,
            "evidence": EVIDENCE,
            "caveat": CAVEAT,
            **coverage.as_dict(),
            **lower_bounds(truncated),
        }
        if not coverage.answerable:
            # Zero repositories, zero versions, zero resolutions: the shape of a
            # package that reaches nothing, and the shape of a dataset that holds
            # nothing. The counts cannot tell them apart, so the note must.
            out["note"] = coverage.note
        elif truncated:
            # "17 repos across 4 versions" is the headline an incident responder
            # acts on first, so a truncated blast radius is the worst place in
            # this module to hand back a number that reads like a total.
            out["note"] = UNVERIFIED_ABSENCE_NOTE
        elif not anchor["exists"]:
            out["note"] = (
                f"no {anchor['label']} node for {package!r} is in the graph, so its "
                "blast radius here is empty by construction, not by measurement"
            )
        elif not repos:
            out["note"] = (
                "the package is in the graph but nothing resolved it at this instant"
            )
        return out

    def maintainer_reach(self, maintainer: str, at_timestamp: object = None) -> dict:
        """The trust radius of one npm account: packages and repositories reached.

        ``at_timestamp`` defaults to now, which reads the still-open intervals —
        the "if this account were phished tomorrow" question. Pass an instant to
        ask it historically.
        """
        at = int(time.time()) if at_timestamp is None else to_epoch(
            at_timestamp, field_name="at_timestamp"
        )
        coverage = self.coverage()
        anchor = self._node("maintainer", maintainer)
        owned, owned_truncated = self._dicts(
            queries.maintained_packages(self.schema, anchor["id"])
        )
        matches, truncated = self._dicts(
            queries.maintainer_reach(self.schema, anchor["id"], at)
        )

        packages: set[str] = set()
        repos: dict[str, dict] = {}
        pairs: set[tuple[str, str]] = set()
        for row in matches:
            package = str(row.get("package"))
            slug = str(row.get("slug"))
            packages.add(package)
            pairs.add((slug, package))
            entry = repos.setdefault(
                slug, {"slug": slug, "name": row.get("name"), "via_packages": set()}
            )
            entry["via_packages"].add(package)
        reached = sorted(
            (
                {
                    "slug": entry["slug"],
                    "name": entry["name"],
                    "via_packages": sorted(entry["via_packages"]),
                    "package_count": len(entry["via_packages"]),
                }
                for entry in repos.values()
            ),
            key=lambda r: (-r["package_count"], r["slug"]),
        )

        out = {
            "question": "which packages and repositories does this account reach",
            "maintainer": maintainer,
            **_at_instant(at),
            "anchor": anchor,
            "maintains_package_count": len(owned),
            "maintains_packages": sorted(str(row.get("package")) for row in owned),
            "reached_package_count": len(packages),
            "reached_packages": sorted(packages),
            "reached_repo_count": len(reached),
            "reached_repos": reached,
            # The repo count saturates once a package is ubiquitous, so the
            # finer-grained surface is the one to rank accounts on.
            "repo_package_pairs": len(pairs),
            "truncated": truncated or owned_truncated,
            "evidence": EVIDENCE,
            "caveat": CAVEAT,
            "maintainer_caveat": MAINTAINER_CAVEAT,
            **coverage.as_dict(),
            **lower_bounds(
                truncated or owned_truncated, absence_note=REACH_FLOOR_NOTE
            ),
        }
        if not coverage.answerable:
            # A reach of zero is the most reassuring number this tool returns —
            # "if this account were phished tomorrow, nothing of ours moves" —
            # and it is what an unread dataset returns for every account alike.
            out["note"] = coverage.note
        elif truncated or owned_truncated:
            # And a *small* reach is what a capped read returns for a large
            # account: same reassurance, arrived at by not looking. Either of the
            # two reads being short is enough to make every number here a floor,
            # since the packages drive the repositories.
            out["note"] = REACH_FLOOR_NOTE
        return out


__all__ = [
    "CAVEAT",
    "EVIDENCE",
    "MAINTAINER_CAVEAT",
    "Hindsight",
    "HydraError",
    "Limits",
    "ToolInputError",
    "UnknownKind",
    "UnsafeCypher",
    "iso",
    "split_version",
    "to_epoch",
    "unwrap_cell",
]
