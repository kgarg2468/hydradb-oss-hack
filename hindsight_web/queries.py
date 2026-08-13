"""Cypher the console runs, as pure builders.

These are the *same shapes* the MCP server's canned tools compose. That is the
point: an incident responder scrubbing the timeline and an agent asking the
identical question over MCP must not be able to get different answers, and the
cheapest way to guarantee that is for both to emit the same statement.

Two engine rules govern every builder here:

1. **Enter through an id.** HydraDB has no secondary property index, so a
   predicate on ``v.pkg`` scans every edge of that type — measured at 7.9 s
   against 3.9 ms for the id-anchored form on the same 111k-edge graph. The
   name -> id map lives in the application (:mod:`hindsight.ids`), so every
   builder below takes an integer id, never a name. The two exceptions are the
   directory scans (:func:`repo_directory`, :func:`maintainer_directory`), which
   are label-only reads of a handful of nodes and run once at startup.
2. **Project endpoint properties, never a relationship variable.** ``RETURN e``
   and ``RETURN e.id`` are both rejected; relationship *properties* written by an
   explicit ``SET`` do project, so interval bounds come back and the console can
   say "held from X to Y" rather than merely "held".

Interval predicates are always ``valid_from <= t AND valid_to > t``: half-open,
lower inclusive, upper exclusive, so an AS-OF read at exactly the commit second
that swapped a version sees only the new one.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hindsight.graphbuild import Schema

#: Label prefixes for the demo dataset. Disjoint from the ingest pipeline's
#: ``Hs*`` production labels and from the PoC's ``Dep*`` load, because HydraDB
#: deletes at ~3 nodes/sec and label namespacing is the only workable isolation.
#:
#: Not ``Demo*``: that namespace was contaminated during development and, on an
#: append-only node, contamination is permanent. ``MERGE (n:A {id: $x})`` matches
#: an existing node carrying id ``$x`` *whatever label it has* and adds ``A`` to
#: it, so one statement that named a label literally instead of taking it from a
#: :class:`~hindsight.graphbuild.Schema` gave four integration-test repositories
#: a second, production-namespace label. Label isolation holds on read — ``MATCH
#: (r:Demo)`` never matches ``DemoRepo`` — but it does not survive a write that
#: enters through a shared id space. Hence: every label in this module comes from
#: a Schema argument, and there is a test that the seeder contains no literal.
DEMO_SCHEMA = Schema.prefixed("Replay", "REPLAY")

#: Throwaway labels for integration tests against the same shared node.
TEST_SCHEMA = Schema.prefixed("ReplayTest", "REPLAYTEST")


@dataclass(frozen=True)
class Query:
    """A statement, its parameters, and the columns it projects."""

    cypher: str
    params: dict = field(default_factory=dict)
    columns: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {"cypher": self.cypher, "parameters": dict(self.params)}


def repo_directory(schema: Schema) -> Query:
    """Every repository in the dataset, with its provenance flag.

    A label-only scan, which the engine accepts (a *bare* ``MATCH (n)`` does not)
    and which is cheap here because the org is tens of repos, not millions. The
    console loads this once and keeps it: it is the list that makes "not exposed"
    a first-class answer, since a repo that returns no rows from an exposure
    query has to be *named* to be reported at all.

    ``provenance``, ``origin`` and ``synthetic`` are written by
    ``scripts/demo-seed.py`` and are how the UI can state, on the row itself,
    that a repository is a constructed example rather than a real git history.
    """
    return Query(
        f"MATCH (r:{schema.repo}) "
        "RETURN r.id, r.slug, r.name, r.service, r.first_ts, r.last_ts, "
        "r.snapshots, r.provenance, r.origin, r.synthetic",
        {},
        (
            "id",
            "slug",
            "name",
            "service",
            "first_ts",
            "last_ts",
            "snapshots",
            "provenance",
            "origin",
            "synthetic",
        ),
    )


def maintainer_directory(schema: Schema) -> Query:
    """Every maintainer account in the dataset. Label-only scan, loaded once."""
    return Query(
        f"MATCH (m:{schema.maintainer}) RETURN m.id, m.name",
        {},
        ("id", "name"),
    )


def repos_resolving_version(schema: Schema, version_id: int, at: int) -> Query:
    """Repos whose lockfile resolved exactly this package version at ``at``."""
    return Query(
        f"MATCH (r:{schema.repo})-[e:{schema.resolves}]->"
        f"(v:{schema.version} {{id: $vid}}) "
        "WHERE e.valid_from <= $t AND e.valid_to > $t "
        "RETURN r.slug, r.name, v.pkg, v.version, e.valid_from, e.valid_to",
        {"vid": int(version_id), "t": int(at)},
        ("slug", "name", "package", "version", "valid_from", "valid_to"),
    )


def repos_resolving_package(schema: Schema, package_id: int, at: int) -> Query:
    """Repos resolving *any* version of this package at ``at``.

    Two patterns joined on ``v``: the package is entered by id, its versions are
    reached backwards along VERSION_OF, and RESOLVES is filtered by the interval.
    One repo legitimately returns several rows — a lockfile carries the whole
    transitive closure, so nested copies of the same package at different
    versions coexist, and every one of them is a separate fact.
    """
    return Query(
        f"MATCH (v:{schema.version})-[:{schema.version_of}]->"
        f"(p:{schema.package} {{id: $pid}}), "
        f"(r:{schema.repo})-[e:{schema.resolves}]->(v) "
        "WHERE e.valid_from <= $t AND e.valid_to > $t "
        "RETURN DISTINCT r.slug, r.name, v.pkg, v.version, e.valid_from, e.valid_to",
        {"pid": int(package_id), "t": int(at)},
        ("slug", "name", "package", "version", "valid_from", "valid_to"),
    )


def maintainers_of_package(schema: Schema, package_id: int) -> Query:
    """Accounts that can publish this package today. Anchored on the package id."""
    return Query(
        f"MATCH (m:{schema.maintainer})-[:{schema.maintains}]->"
        f"(p:{schema.package} {{id: $pid}}) RETURN DISTINCT m.name",
        {"pid": int(package_id)},
        ("maintainer",),
    )


def maintainer_reach(schema: Schema, maintainer_id: int, at: int) -> Query:
    """Packages and repos one maintainer account reaches at ``at``.

    Three patterns sharing ``p`` and ``v``: maintainer -> package, version ->
    package, repo -> version. This is the trust-radius query and the one shape
    that could not be written as a variable-length traversal — ``*1..n`` needs a
    fixed source id and cannot fan out from a maintainer across the org.
    """
    return Query(
        f"MATCH (m:{schema.maintainer} {{id: $mid}})-[:{schema.maintains}]->"
        f"(p:{schema.package}), "
        f"(v:{schema.version})-[:{schema.version_of}]->(p), "
        f"(r:{schema.repo})-[e:{schema.resolves}]->(v) "
        "WHERE e.valid_from <= $t AND e.valid_to > $t "
        "RETURN DISTINCT p.name, r.slug, r.name, v.version, e.valid_from, e.valid_to",
        {"mid": int(maintainer_id), "t": int(at)},
        ("package", "slug", "name", "version", "valid_from", "valid_to"),
    )


def maintained_packages(schema: Schema, maintainer_id: int) -> Query:
    """Packages an account maintains, whether or not the org resolves them.

    Kept separate from :func:`maintainer_reach` so that "maintains 34 packages,
    12 of which we resolve" stays distinguishable from "maintains 12".
    """
    return Query(
        f"MATCH (m:{schema.maintainer} {{id: $mid}})-[:{schema.maintains}]->"
        f"(p:{schema.package}) RETURN DISTINCT p.name",
        {"mid": int(maintainer_id)},
        ("package",),
    )


def package_exists(schema: Schema, package_id: int) -> Query:
    """Does this package have a node at all? A negative here is not a lookup miss."""
    return Query(
        f"MATCH (p:{schema.package} {{id: $pid}}) RETURN p.name",
        {"pid": int(package_id)},
        ("name",),
    )


def version_exists(schema: Schema, version_id: int) -> Query:
    """Does this exact version have a node?

    A malicious version with no node was never resolved by anything in the org,
    anywhere in history — the strongest negative the graph can produce, and it
    costs one id lookup rather than a scan.
    """
    return Query(
        f"MATCH (v:{schema.version} {{id: $vid}}) RETURN v.pkg, v.version",
        {"vid": int(version_id)},
        ("package", "version"),
    )


def watermarks(schema: Schema) -> Query:
    """Per-repository ingest watermarks: the health check's "is it loaded" probe.

    The ingest writes one of these at the end of a successful run, holding the
    newest commit timestamp it saw, so their presence is direct evidence that a
    seed completed rather than an inference from edge counts. Nine nodes, one
    label scan, ~5 ms — which matters, because counting the edges instead costs
    nine seconds (see :func:`resolves_edge_count`).
    """
    return Query(
        f"MATCH (w:{schema.watermark}) RETURN w.slug, w.last_commit_ts",
        {},
        ("slug", "last_commit_ts"),
    )


def resolves_edge_count(schema: Schema, repo_id: int) -> Query:
    """RESOLVES edges for one repository. Anchored, and still not cheap.

    Anchoring on the repo id is what makes this *possible* — the label-wide form
    is a scan measured at 8.8 s — but it does not make it fast, and the earlier
    claim in this docstring that nine anchored counts total under 100 ms was
    simply wrong. Measured against the demo dataset, per repository:

    ==================== ========= =========
    repository            edges     count(*)
    ==================== ========= =========
    acme/checkout-web           61     2.7 ms
    axios/axios              2,061      430 ms
    facebook/react           3,097      639 ms
    apache/superset          8,844    1,708 ms
    grafana/grafana         11,314    1,968 ms
    storybookjs/storybook   50,358    2,192 ms
    ==================== ========= =========

    ~9 s for all nine. And there is no cheaper existence probe: the same match
    with ``LIMIT 1``, and the same match read one row at a time and abandoned
    after the first, both cost within 1 % of the full count (8,964 ms and
    9,037 ms against 8,979 ms). The engine materialises the match before it
    pages or limits, so "does this repo have any edges" is exactly as expensive
    as "how many". Hence :func:`watermarks` for the health probe, and this only
    when a caller explicitly asks for the number.
    """
    return Query(
        f"MATCH (r:{schema.repo} {{id: $rid}})-[e:{schema.resolves}]->(v:{schema.version}) "
        "WHERE e.valid_from >= 0 RETURN count(*)",
        {"rid": int(repo_id)},
        ("edges",),
    )


__all__ = [
    "DEMO_SCHEMA",
    "TEST_SCHEMA",
    "Query",
    "maintained_packages",
    "maintainer_directory",
    "maintainer_reach",
    "maintainers_of_package",
    "package_exists",
    "repo_directory",
    "repos_resolving_package",
    "repos_resolving_version",
    "resolves_edge_count",
    "version_exists",
    "watermarks",
]
