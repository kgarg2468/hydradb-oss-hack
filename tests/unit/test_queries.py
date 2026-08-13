"""The canonical query builders, which both surfaces now compose from.

Two things are asserted here. First, that every statement stays inside the
subset HydraDB executes: every constraint below was hit for real during the PoC
and is written up in ``poc/POC-RESULTS.md`` §6, and they are cheap to re-break
during a refactor and expensive to discover from a 400 at demo time. The engine
constraints are not stylistic — an un-anchored query is a ~2000x regression and
a projected relationship variable is a hard rejection — so they are asserted
structurally over every builder rather than spot-checked.

Second, that the builders stay canonical: no module on either surface writes
Cypher of its own. This file is the merge of what used to be two near-identical
test modules, one per surface, which is what a second copy of the statements
bought.
"""

from __future__ import annotations

import importlib
import re
import types

import pytest

from hindsight import queries
from hindsight.graphbuild import DEFAULT_SCHEMA, Schema
from hindsight_mcp import guard
from hindsight_web.queries import DEMO_SCHEMA, TEST_SCHEMA

MCP_SCHEMA = Schema.prefixed("McpTest", "MCPTEST")

#: Every builder in the module, with arguments.
BUILDERS = {
    "node_by_id(repo)": lambda s: queries.node_by_id(s, "repo", 11),
    "node_by_id(package)": lambda s: queries.node_by_id(s, "package", 12),
    "node_by_id(version)": lambda s: queries.node_by_id(s, "version", 13),
    "node_by_id(maintainer)": lambda s: queries.node_by_id(s, "maintainer", 14),
    "package_exists": lambda s: queries.package_exists(s, 7),
    "version_exists": lambda s: queries.version_exists(s, 7),
    "repos_resolving_version": lambda s: queries.repos_resolving_version(s, 21, 1000),
    "repos_resolving_package": lambda s: queries.repos_resolving_package(s, 22, 1000),
    "maintainers_of_package": lambda s: queries.maintainers_of_package(s, 7),
    "maintainer_reach": lambda s: queries.maintainer_reach(s, 23, 1000),
    "maintained_packages": lambda s: queries.maintained_packages(s, 24),
    "repo_directory": lambda s: queries.repo_directory(s),
    "maintainer_directory": lambda s: queries.maintainer_directory(s),
    "watermarks": lambda s: queries.watermarks(s),
    "resolves_edge_count": lambda s: queries.resolves_edge_count(s, 7),
}

#: The three deliberate label scans. Everything else enters through an id.
SCANS = ("repo_directory", "maintainer_directory", "watermarks")

ANCHORED = tuple(sorted(set(BUILDERS) - set(SCANS)))

#: The queries that take an instant.
TIME_QUERIES = ("repos_resolving_version", "repos_resolving_package", "maintainer_reach")

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


@pytest.fixture(
    params=[DEFAULT_SCHEMA, MCP_SCHEMA, DEMO_SCHEMA],
    ids=["production", "mcp-test", "console-demo"],
)
def schema(request):
    """The same builders, under each surface's label namespace."""
    return request.param


# ------------------------------------------------------- the executable subset


@pytest.mark.parametrize("name", sorted(BUILDERS))
def test_no_unsupported_cypher_constructs(name, schema):
    cypher = BUILDERS[name](schema).cypher
    for pattern in UNSUPPORTED:
        assert not re.search(pattern, cypher), f"{name} uses {pattern}"


@pytest.mark.parametrize("name", sorted(BUILDERS))
def test_every_query_passes_the_read_only_guard(name, schema):
    assert guard.check(BUILDERS[name](schema).cypher) is None


@pytest.mark.parametrize("name", sorted(BUILDERS))
def test_no_query_projects_a_relationship_variable(name, schema):
    """``RETURN e`` and ``RETURN e.id`` are both rejected; ``e.valid_from`` is not."""
    cypher = BUILDERS[name](schema).cypher
    projection = cypher.split("RETURN", 1)[1]
    assert not re.search(r"\be\.id\b", projection)
    assert not re.search(r"RETURN\s+e\b", cypher)
    for term in projection.split(","):
        term = term.strip().removeprefix("DISTINCT ").strip()
        if term == "count(*)":
            continue
        assert "." in term, f"{name} projects a bare variable: {term!r}"


@pytest.mark.parametrize("name", sorted(BUILDERS))
def test_every_node_pattern_is_labelled_or_already_bound(name, schema):
    """A node-only ``MATCH`` needs an inline id, label or property predicate.

    A bare ``(v)`` is legal only where ``v`` was introduced with a label earlier
    in the same statement — that is how the multi-pattern joins share a binding,
    and it is the shape that makes the maintainer graph viable at all.
    """
    cypher = BUILDERS[name](schema).cypher
    bound: set[str] = set()
    for variable, rest in re.findall(r"\((\w+)([^)]*)\)", cypher.split("RETURN")[0]):
        if ":" in rest or "{" in rest:
            bound.add(variable)
            continue
        assert variable in bound, f"{name}: ({variable}) is neither labelled nor bound"


@pytest.mark.parametrize("name", ANCHORED)
def test_every_query_that_can_enters_through_an_id(name, schema):
    """No secondary index exists: 7.9 s scan vs 3.9 ms anchored on the same answer."""
    query = BUILDERS[name](schema)
    assert "{id: $" in query.cypher, (
        f"{name} does not anchor on an id; without a secondary index this is a "
        "full label scan"
    )
    assert any(isinstance(v, int) for v in query.params.values())


@pytest.mark.parametrize("name", ANCHORED)
def test_parameters_are_integers_and_never_interpolated(name, schema):
    query = BUILDERS[name](schema)
    assert query.params, f"{name} inlines its arguments instead of parameterising them"
    for key, value in query.params.items():
        assert isinstance(value, int), f"{name}.{key} is not an int"
        assert f"${key}" in query.cypher


@pytest.mark.parametrize("name", sorted(BUILDERS))
def test_columns_match_the_projection_width(name, schema):
    query = BUILDERS[name](schema)
    projected = query.cypher.split("RETURN", 1)[1].replace("DISTINCT", "")
    assert len(query.columns) == len(projected.split(",")), (
        f"{name} declares the wrong column list"
    )


@pytest.mark.parametrize("name", sorted(BUILDERS))
def test_every_query_uses_the_schema_it_was_given(name, schema):
    """A literal label is how one dataset leaks into another's namespace."""
    cypher = BUILDERS[name](schema).cypher
    labels = (
        schema.repo,
        schema.package,
        schema.version,
        schema.maintainer,
        schema.watermark,
    )
    assert any(f":{label}" in cypher for label in labels)


# ----------------------------------------------------------- temporal semantics


@pytest.mark.parametrize("name", TIME_QUERIES)
def test_asof_queries_use_the_half_open_predicate(name, schema):
    """Lower bound inclusive, upper exclusive, so a swap at exactly T shows the new pin."""
    cypher = BUILDERS[name](schema).cypher
    assert "e.valid_from <= $t AND e.valid_to > $t" in cypher, (
        "the interval predicate must be lower-inclusive and upper-exclusive"
    )
    assert BUILDERS[name](schema).params["t"] == 1000


@pytest.mark.parametrize("name", sorted(set(BUILDERS) - set(TIME_QUERIES)))
def test_non_temporal_queries_do_not_filter_on_an_instant(name, schema):
    """``resolves_edge_count`` mentions ``valid_from``, but as a bound on the
    edge rather than as a clock: it counts every edge a repository ever had."""
    query = BUILDERS[name](schema)
    assert "$t" not in query.cypher
    assert "t" not in query.params


# --------------------------------------------------------------- the join shapes


def test_labels_come_from_the_schema(schema):
    cypher = queries.repos_resolving_package(schema, 1, 2).cypher
    assert f"(v:{schema.version})" in cypher
    assert f":{schema.version_of}]" in cypher
    assert f"(p:{schema.package} {{id: $pid}})" in cypher
    assert f"(r:{schema.repo})-[e:{schema.resolves}]" in cypher


def test_the_three_pattern_join_shares_its_bindings(schema):
    """Variable-length traversal cannot fan out from a maintainer, so the join
    has to be comma-separated patterns over shared bindings."""
    cypher = queries.maintainer_reach(schema, 1, 2).cypher
    assert cypher.count("MATCH") == 1
    assert cypher.count("), (") == 2
    assert "*" not in cypher


def test_multi_pattern_queries_deduplicate_server_side(schema):
    assert "RETURN DISTINCT" in queries.repos_resolving_package(schema, 1, 2).cypher
    assert "RETURN DISTINCT" in queries.maintainer_reach(schema, 1, 2).cypher


def test_count_distinct_is_never_used(schema):
    """``count(DISTINCT x)`` is not executable; counting is folded client-side."""
    for build in BUILDERS.values():
        assert "count(DISTINCT" not in build(schema).cypher


def test_directory_scans_are_label_scoped_and_few(schema):
    """The three label scans are the deliberate exceptions and must stay tiny.

    Tens of nodes each. Every other query in this module enters through an id,
    because a scan over the 86k RESOLVES edges costs seconds, not milliseconds.
    """
    for name in SCANS:
        query = BUILDERS[name](schema)
        assert query.params == {}
        assert query.cypher.startswith("MATCH (")
        # A scan may touch nodes, never edges.
        assert "-[" not in query.cypher
    assert len(BUILDERS) - len(SCANS) == len(ANCHORED)


def test_repo_directory_reads_the_provenance_properties(schema):
    """A surface cannot label a repository synthetic if the query does not fetch it."""
    query = queries.repo_directory(schema)
    for column in ("provenance", "origin", "synthetic"):
        assert column in query.columns
        assert f"r.{column}" in query.cypher


# ------------------------------------------------------------------- id lookup


@pytest.mark.parametrize(
    "given, expected",
    [
        ("repo", "repo"),
        ("Repository", "repo"),
        ("pkg", "package"),
        ("PACKAGE", "package"),
        ("ver", "version"),
        ("package_version", "version"),
        ("package-version", "version"),
        ("maint", "maintainer"),
        ("  Maintainer  ", "maintainer"),
    ],
)
def test_kind_aliases_resolve(given, expected):
    assert queries.normalise_kind(given) == expected


@pytest.mark.parametrize("given", ["", "commit", "file", "nonsense", None])
def test_unknown_kinds_are_rejected_with_the_valid_ones_listed(given):
    with pytest.raises(queries.UnknownKind) as excinfo:
        queries.normalise_kind(given)
    for kind in ("repo", "package", "version", "maintainer"):
        assert kind in str(excinfo.value)


def test_label_for_maps_every_kind(schema):
    assert queries.label_for(schema, "repo") == schema.repo
    assert queries.label_for(schema, "pkg") == schema.package
    assert queries.label_for(schema, "ver") == schema.version
    assert queries.label_for(schema, "maint") == schema.maintainer


def test_node_by_id_projects_the_documented_properties(schema):
    query = queries.node_by_id(schema, "version", 7)
    assert query.columns == queries.NODE_PROPERTIES["version"]
    for prop in queries.NODE_PROPERTIES["version"]:
        assert f"n.{prop}" in query.cypher
    assert query.params == {"id": 7}


# ---------------------------------------------------------------- the row shape


def test_query_serialises_for_debugging(schema):
    payload = queries.repos_resolving_version(schema, 5, 9).as_dict()
    assert payload["parameters"] == {"vid": 5, "t": 9}
    assert payload["cypher"].startswith("MATCH")


def test_query_as_dict_is_ready_to_post(schema):
    query = queries.repos_resolving_package(schema, 7, 100)
    body = query.as_dict()
    assert body["parameters"] == {"pid": 7, "t": 100}
    assert body["cypher"] == query.cypher


def test_rows_are_named_by_the_columns_the_query_declared(schema):
    """Row interpretation travels with the statement: both surfaces read a row
    through the same column list, so a projection change cannot be picked up in
    one place and misread in the other."""
    query = queries.repos_resolving_version(schema, 5, 9)
    assert query.shape([["acme/web", "web", "chalk", "5.6.1", 100, 200]]) == [
        {
            "slug": "acme/web",
            "name": "web",
            "package": "chalk",
            "version": "5.6.1",
            "valid_from": 100,
            "valid_to": 200,
        }
    ]
    assert query.shape([]) == []


# --------------------------------------------------------------- one copy only


@pytest.mark.parametrize("module", ["hindsight_mcp.service", "hindsight_web.service"])
def test_both_surfaces_build_from_this_module_and_no_other(module):
    """The unification, asserted rather than hoped for.

    Both surfaces used to carry their own copy of these statements, which is a
    correctness hazard and not a style one: an agent's answer and the console's
    answer to the same question must not be able to drift apart.
    """
    assert importlib.import_module(module).queries is queries


def test_neither_surface_still_ships_a_query_module():
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("hindsight_mcp.queries")
    console = importlib.import_module("hindsight_web.queries")
    grown = [
        name
        for name in queries.__all__
        if isinstance(getattr(console, name, None), types.FunctionType)
    ]
    assert not grown, f"hindsight_web.queries has grown builders again: {grown}"


def test_the_console_label_namespaces_are_disjoint_from_the_other_datasets():
    """Label namespacing is the only isolation available: deletes run at ~3/sec.

    ``Demo`` is on the excluded list because that namespace was contaminated
    during development and, the node being append-only, contamination is
    permanent — see the note on :mod:`hindsight_web.queries`.
    """
    for namespace in (DEMO_SCHEMA, TEST_SCHEMA):
        for label in (
            namespace.repo,
            namespace.package,
            namespace.version,
            namespace.maintainer,
        ):
            assert not label.startswith(
                ("Hs", "Dep", "CITest", "IngTest", "McpTest", "McpProbe", "Demo")
            )
    assert DEMO_SCHEMA.repo != TEST_SCHEMA.repo
    assert DEMO_SCHEMA.resolves != TEST_SCHEMA.resolves
    # A prefix that is a prefix of the other would be safe on read but is an
    # invitation to confuse the two in a shell one-liner.
    assert not DEMO_SCHEMA.repo.startswith(TEST_SCHEMA.repo)
