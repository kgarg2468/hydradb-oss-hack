"""Every Cypher shape Hindsight runs, as pure builders. One copy, two surfaces.

The MCP server and the incident console ask the same questions of the same
graph — "which repositories resolved this package at this instant", "what does
this maintainer account reach" — and the agent's answer and the screen's answer
being able to differ is a correctness bug, not a cosmetic one. Two copies of a
statement drift the first time one of them is tuned. So the statements live
here, once, and both surfaces compose from this module.

What stays surface-side is presentation, which is genuinely different: the MCP
tools return evidence envelopes and caveats sized for a language model, the
console returns JSON shaped for a timeline and joins every answer against the
full repository directory. Only the query construction and the interpretation
of a returned row are shared.

Two engine rules govern every builder here:

1. **Enter through an id.** HydraDB has no secondary property index, so a
   predicate on ``v.pkg`` is a full scan of the label — measured at 7.9 s
   against 3.9 ms for the id-anchored form on the same 111k-edge graph. The
   name -> id map lives in the application (:mod:`hindsight.ids`), so every
   builder below takes an integer id, never a name. The exceptions are the
   directory scans (:func:`repo_directory`, :func:`maintainer_directory`,
   :func:`watermarks`), which are label-only reads of a handful of nodes and
   run once at startup. Anchoring on ``{id: ...}`` also satisfies the engine's
   rule that a node-only ``MATCH`` carries an id, label or property predicate
   inline; a bare ``MATCH (n) WHERE n.id = $id`` is rejected outright.
2. **Project endpoint properties, never a relationship variable.** ``RETURN e``
   and ``RETURN e.id`` are both rejected ("RETURN currently supports
   <binding>.<property> or count(*)" / "unbound variable e"). Relationship
   *properties* written by an explicit ``SET`` do project — so ``e.valid_from``
   and ``e.valid_to`` are returnable, and every temporal query returns the
   interval bounds, because "you were exposed from X to Y" is a far more useful
   answer than "you were exposed".

Interval predicates are always ``valid_from <= t AND valid_to > t``: half-open,
lower bound inclusive, upper bound exclusive, so an AS-OF read at exactly the
commit second that swapped a version sees only the new one.

The multi-pattern joins (:func:`repos_resolving_package`,
:func:`maintainer_reach`) are written as comma-separated patterns over a shared
binding rather than as a variable-length traversal, because ``*1..n`` needs a
fixed source id and cannot fan out from a maintainer across the org. The comma
form is executed natively and is what makes the maintainer graph viable at all.

Labels and relationship types always come from a :class:`~hindsight
.graphbuild.Schema` argument and are never written literally: ``MERGE (n:A
{id: $x})`` matches an existing node carrying that id *whatever label it has*
and then adds ``A`` to it, so a literal label in one statement can leak a
dataset into another namespace. Reads are safe either way, but the rule is
kept uniform so that no statement is one copy-paste away from being unsafe.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .graphbuild import Schema

#: Node kinds a caller can name, and the properties worth reading back for each.
#: Keyed by the canonical kind; :func:`normalise_kind` accepts the aliases.
NODE_PROPERTIES: dict[str, tuple[str, ...]] = {
    "repo": ("slug", "name", "service", "first_ts", "last_ts", "snapshots"),
    "package": ("name",),
    "version": ("pkg", "version", "key", "pkg_id"),
    "maintainer": ("name",),
}

_KIND_ALIASES: dict[str, str] = {
    "repo": "repo",
    "repository": "repo",
    "package": "package",
    "pkg": "package",
    "version": "version",
    "ver": "version",
    "packageversion": "version",
    "package_version": "version",
    "maintainer": "maintainer",
    "maint": "maintainer",
    "author": "maintainer",
}


class UnknownKind(ValueError):
    """A node kind that is not part of this graph."""


def normalise_kind(kind: str) -> str:
    """Map a user-supplied node kind onto a canonical one."""
    key = (kind or "").strip().lower().replace("-", "_")
    canonical = _KIND_ALIASES.get(key) or _KIND_ALIASES.get(key.replace("_", ""))
    if canonical is None:
        known = ", ".join(sorted(NODE_PROPERTIES))
        raise UnknownKind(f"unknown kind {kind!r}; expected one of: {known}")
    return canonical


def label_for(schema: Schema, kind: str) -> str:
    return {
        "repo": schema.repo,
        "package": schema.package,
        "version": schema.version,
        "maintainer": schema.maintainer,
    }[normalise_kind(kind)]


@dataclass(frozen=True)
class Query:
    """A statement, its parameters, and the columns it projects."""

    cypher: str
    params: dict = field(default_factory=dict)
    columns: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {"cypher": self.cypher, "parameters": dict(self.params)}

    def shape(self, rows: list[list[object]]) -> list[dict]:
        """Name the cells of each returned row.

        The other half of "one query shape": a statement and the reading of its
        rows are a single fact, and splitting them across two packages is how a
        column gets added in one place and silently misread in the other.
        """
        return [dict(zip(self.columns, row, strict=False)) for row in rows]


# --------------------------------------------------------------- id resolution


def node_by_id(schema: Schema, kind: str, node_id: int) -> Query:
    """Read one node's properties by id — the existence check behind every tool.

    ``exists`` is the interesting answer here as often as the properties are:
    ids are derived from the name rather than allocated, so a miss means the
    name has never been ingested, not that the lookup failed.
    """
    canonical = normalise_kind(kind)
    props = NODE_PROPERTIES[canonical]
    projection = ", ".join(f"n.{p}" for p in props)
    return Query(
        f"MATCH (n:{label_for(schema, canonical)} {{id: $id}}) RETURN {projection}",
        {"id": int(node_id)},
        props,
    )


def package_exists(schema: Schema, package_id: int) -> Query:
    """Does this package have a node at all? A negative here is not a lookup miss.

    Same read as :func:`node_by_id` for a package, under the ``$pid`` parameter
    name the console's traversals use, so one console answer is composed from a
    single parameter vocabulary rather than two.
    """
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


# ------------------------------------------------------- exposure / blast radius


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

    This one statement answers both the exposure question and the blast radius;
    the difference between them is entirely in how the rows are folded up.
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


# ------------------------------------------------------------------ maintainers


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

    Reported separately from :func:`maintainer_reach` so that "maintains 34
    packages, 12 of which we resolve" stays distinguishable from "maintains 12".
    """
    return Query(
        f"MATCH (m:{schema.maintainer} {{id: $mid}})-[:{schema.maintains}]->"
        f"(p:{schema.package}) RETURN DISTINCT p.name",
        {"mid": int(maintainer_id)},
        ("package",),
    )


# ------------------------------------------------------------ directories, health


def repo_directory(schema: Schema) -> Query:
    """Every repository in the dataset, with its provenance flag.

    A label-only scan, which the engine accepts (a *bare* ``MATCH (n)`` does not)
    and which is cheap here because an org is tens of repos, not millions. The
    console loads this once and keeps it: it is the list that makes "not exposed"
    a first-class answer, since a repo that returns no rows from an exposure
    query has to be *named* to be reported at all.

    ``provenance``, ``origin`` and ``synthetic`` are optional properties written
    by ``scripts/demo-seed.py``; they are how a surface can state, on the row
    itself, that a repository is a constructed example rather than a real git
    history. A dataset without them simply reads them back empty.
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
    is a scan measured at 8.8 s — but it does not make it fast. Measured against
    the demo dataset, per repository:

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
    "NODE_PROPERTIES",
    "Query",
    "UnknownKind",
    "label_for",
    "maintained_packages",
    "maintainer_directory",
    "maintainer_reach",
    "maintainers_of_package",
    "node_by_id",
    "normalise_kind",
    "package_exists",
    "repo_directory",
    "repos_resolving_package",
    "repos_resolving_version",
    "resolves_edge_count",
    "version_exists",
    "watermarks",
]
