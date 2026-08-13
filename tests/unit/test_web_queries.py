"""The console's Cypher must stay inside the subset HydraDB executes.

Every constraint asserted here was hit for real during the PoC and is written up
in ``poc/POC-RESULTS.md`` §6. They are cheap to re-break during a refactor and
expensive to discover from a 400 at demo time, so they are tests rather than
comments.
"""

from __future__ import annotations

import re

import pytest

from hindsight.graphbuild import Schema
from hindsight_web import queries
from hindsight_web.queries import DEMO_SCHEMA, TEST_SCHEMA

SCHEMA = Schema.prefixed("Replay", "REPLAY")

#: Every builder that touches a hot path, with arguments.
BUILDERS = {
    "repos_resolving_version": lambda: queries.repos_resolving_version(SCHEMA, 7, 100),
    "repos_resolving_package": lambda: queries.repos_resolving_package(SCHEMA, 7, 100),
    "maintainer_reach": lambda: queries.maintainer_reach(SCHEMA, 7, 100),
    "maintained_packages": lambda: queries.maintained_packages(SCHEMA, 7),
    "maintainers_of_package": lambda: queries.maintainers_of_package(SCHEMA, 7),
    "package_exists": lambda: queries.package_exists(SCHEMA, 7),
    "version_exists": lambda: queries.version_exists(SCHEMA, 7),
    "resolves_edge_count": lambda: queries.resolves_edge_count(SCHEMA, 7),
    "repo_directory": lambda: queries.repo_directory(SCHEMA),
    "maintainer_directory": lambda: queries.maintainer_directory(SCHEMA),
    "watermarks": lambda: queries.watermarks(SCHEMA),
}

#: Constructs the engine rejects outright.
UNSUPPORTED = (
    r"\bIN\b",
    r"\bCONTAINS\b",
    r"\bENDS WITH\b",
    r"\bIS NULL\b",
    r"\bIS NOT NULL\b",
    r"shortestPath",
    r"\bmin\(",
    r"\bmax\(",
    r"count\(\s*DISTINCT",
    r"RETURN \*",
)


@pytest.mark.parametrize("name", sorted(BUILDERS))
def test_no_unsupported_cypher_constructs(name):
    cypher = BUILDERS[name]().cypher
    for pattern in UNSUPPORTED:
        assert not re.search(pattern, cypher), f"{name} uses {pattern}"


@pytest.mark.parametrize("name", sorted(BUILDERS))
def test_no_bare_relationship_variable_is_projected(name):
    """``RETURN e`` and ``RETURN e.id`` are both rejected; ``e.valid_from`` is not."""
    cypher = BUILDERS[name]().cypher
    projection = cypher.split("RETURN", 1)[1]
    assert not re.search(r"\be\.id\b", projection)
    assert not re.search(r"RETURN\s+e\b", cypher)


@pytest.mark.parametrize("name", sorted(BUILDERS))
def test_every_node_pattern_is_labelled_or_already_bound(name):
    """A node-only ``MATCH`` needs an inline id, label or property predicate.

    A bare ``(v)`` is legal only where ``v`` was introduced with a label earlier
    in the same statement — that is how the multi-pattern joins share a binding,
    and it is the shape that makes the maintainer graph viable at all.
    """
    cypher = BUILDERS[name]().cypher
    bound: set[str] = set()
    for variable, rest in re.findall(r"\((\w+)([^)]*)\)", cypher.split("RETURN")[0]):
        if ":" in rest or "{" in rest:
            bound.add(variable)
            continue
        assert variable in bound, f"{name}: ({variable}) is neither labelled nor bound"


HOT_PATH = (
    "repos_resolving_version",
    "repos_resolving_package",
    "maintainer_reach",
    "maintained_packages",
    "maintainers_of_package",
    "package_exists",
    "version_exists",
    "resolves_edge_count",
)


@pytest.mark.parametrize("name", HOT_PATH)
def test_hot_queries_enter_through_an_id(name):
    """No secondary index exists: 7.9 s scan vs 3.9 ms anchored on the same answer."""
    query = BUILDERS[name]()
    assert "{id: $" in query.cypher
    assert any(isinstance(v, int) for v in query.params.values())


@pytest.mark.parametrize(
    "name", ("repos_resolving_version", "repos_resolving_package", "maintainer_reach")
)
def test_interval_predicate_is_half_open(name):
    """Lower bound inclusive, upper exclusive, so a swap at exactly T shows the new pin."""
    cypher = BUILDERS[name]().cypher
    assert "e.valid_from <= $t AND e.valid_to > $t" in cypher


@pytest.mark.parametrize("name", sorted(BUILDERS))
def test_columns_match_the_projection_width(name):
    query = BUILDERS[name]()
    projected = query.cypher.split("RETURN", 1)[1]
    projected = projected.replace("DISTINCT", "")
    assert len(query.columns) == len(projected.split(","))


def test_directory_scans_are_label_scoped_and_few():
    """The three label scans are the deliberate exceptions and must stay tiny.

    Tens of nodes each. Every other query in this module enters through an id,
    because a scan over the 86k RESOLVES edges costs seconds, not milliseconds.
    """
    scans = (
        queries.repo_directory(SCHEMA),
        queries.maintainer_directory(SCHEMA),
        queries.watermarks(SCHEMA),
    )
    for query in scans:
        assert query.params == {}
        assert query.cypher.startswith("MATCH (")
        assert ":Replay" in query.cypher
        # A scan may touch nodes, never edges.
        assert "-[" not in query.cypher
    assert len(BUILDERS) - len(scans) == len(HOT_PATH)


def test_repo_directory_reads_the_provenance_properties():
    """The UI cannot label a repository synthetic if the query does not fetch it."""
    query = queries.repo_directory(SCHEMA)
    for column in ("provenance", "origin", "synthetic"):
        assert column in query.columns
        assert f"r.{column}" in query.cypher


def test_schemas_are_disjoint_from_the_other_datasets_on_the_node():
    """Label namespacing is the only isolation available: deletes run at ~3/sec.

    ``Demo`` is on the excluded list because that namespace was contaminated
    during development and, the node being append-only, contamination is
    permanent — see the note on :data:`hindsight_web.queries.DEMO_SCHEMA`.
    """
    for schema in (DEMO_SCHEMA, TEST_SCHEMA):
        for label in (schema.repo, schema.package, schema.version, schema.maintainer):
            assert not label.startswith(
                ("Hs", "Dep", "CITest", "IngTest", "McpTest", "McpProbe", "Demo")
            )
    assert DEMO_SCHEMA.repo != TEST_SCHEMA.repo
    assert DEMO_SCHEMA.resolves != TEST_SCHEMA.resolves
    # A prefix that is a prefix of the other would be safe on read but is an
    # invitation to confuse the two in a shell one-liner.
    assert not DEMO_SCHEMA.repo.startswith(TEST_SCHEMA.repo)


def test_query_as_dict_is_ready_to_post():
    query = queries.repos_resolving_package(SCHEMA, 7, 100)
    body = query.as_dict()
    assert body["parameters"] == {"pid": 7, "t": 100}
    assert body["cypher"] == query.cypher
