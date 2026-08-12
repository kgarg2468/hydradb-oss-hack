"""Cypher the canned tools compose, as pure builders.

Every query here obeys the two rules the engine imposes on this dataset:

1. **Enter through an id.** There is no secondary property index, so a
   predicate on ``v.pkg`` is a full scan of the label — 7.9 s against 3.9 ms for
   the id-anchored form on the PoC's 111k-edge graph. The name -> id map lives in
   the application (:mod:`hindsight.ids`), so every builder below takes an
   integer id, never a name.
2. **Project endpoint properties, never a relationship variable.** ``RETURN e``
   and ``RETURN e.id`` are both rejected ("RETURN currently supports
   <binding>.<property> or count(*)" / "unbound variable e"). Relationship
   *properties* that were written by an explicit ``SET`` do project — so
   ``e.valid_from`` and ``e.valid_to`` are returnable, and the tools return the
   interval bounds because "you were exposed from X to Y" is a far more useful
   answer than "you were exposed".

Interval predicates are always ``valid_from <= t AND valid_to > t``: half-open,
lower bound inclusive, upper bound exclusive, so an AS-OF read at exactly the
commit timestamp that swapped a version sees only the new one.

The multi-pattern joins (``blast_radius``, ``maintainer_reach``) are written as
comma-separated patterns with a shared binding rather than as a variable-length
traversal, because ``*1..n`` needs a fixed source id and cannot fan out from a
maintainer across the org. The comma form is executed natively and is what makes
the maintainer graph viable at all.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hindsight.graphbuild import Schema

#: Node kinds an agent can name, and the properties worth reading back for each.
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
    """A statement plus its parameters, and the columns it projects."""

    cypher: str
    params: dict = field(default_factory=dict)
    columns: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {"cypher": self.cypher, "parameters": dict(self.params)}


def node_by_id(schema: Schema, kind: str, node_id: int) -> Query:
    """Read one node's properties by id — the existence check behind every tool.

    Anchoring on ``{id: ...}`` also satisfies the engine's rule that a node-only
    ``MATCH`` carries an id, label or property predicate inline; a bare
    ``MATCH (n) WHERE n.id = $id`` is rejected.
    """
    canonical = normalise_kind(kind)
    props = NODE_PROPERTIES[canonical]
    projection = ", ".join(f"n.{p}" for p in props)
    return Query(
        f"MATCH (n:{label_for(schema, canonical)} {{id: $id}}) RETURN {projection}",
        {"id": int(node_id)},
        props,
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


def maintainer_reach(schema: Schema, maintainer_id: int, at: int) -> Query:
    """Packages and repos one maintainer account reaches at ``at``.

    Three patterns sharing ``p`` and ``v``: maintainer -> package, version ->
    package, repo -> version. This is the trust-radius query, and it is the one
    shape that could not be expressed as a variable-length traversal.
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

    Reported separately from :func:`maintainer_reach` so that "maintains 12
    packages, 3 of which we resolve" stays distinguishable from "maintains 3".
    """
    return Query(
        f"MATCH (m:{schema.maintainer} {{id: $mid}})-[:{schema.maintains}]->"
        f"(p:{schema.package}) RETURN DISTINCT p.name",
        {"mid": int(maintainer_id)},
        ("package",),
    )


__all__ = [
    "NODE_PROPERTIES",
    "Query",
    "UnknownKind",
    "label_for",
    "maintained_packages",
    "maintainer_reach",
    "node_by_id",
    "normalise_kind",
    "repos_resolving_package",
    "repos_resolving_version",
]
