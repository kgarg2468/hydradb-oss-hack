"""Query builders.

The engine constraints these encode are not stylistic — an un-anchored query is
a ~2000x regression and a projected relationship variable is a hard rejection —
so they are asserted structurally over every builder rather than spot-checked.
"""

import pytest

from hindsight.graphbuild import DEFAULT_SCHEMA, Schema
from hindsight_mcp import guard, queries

PREFIXED = Schema.prefixed("McpTest", "MCPTEST")

ALL_BUILDERS = {
    "node_by_id(repo)": lambda s: queries.node_by_id(s, "repo", 11),
    "node_by_id(package)": lambda s: queries.node_by_id(s, "package", 12),
    "node_by_id(version)": lambda s: queries.node_by_id(s, "version", 13),
    "node_by_id(maintainer)": lambda s: queries.node_by_id(s, "maintainer", 14),
    "repos_resolving_version": lambda s: queries.repos_resolving_version(s, 21, 1000),
    "repos_resolving_package": lambda s: queries.repos_resolving_package(s, 22, 1000),
    "maintainer_reach": lambda s: queries.maintainer_reach(s, 23, 1000),
    "maintained_packages": lambda s: queries.maintained_packages(s, 24),
}


@pytest.fixture(params=[DEFAULT_SCHEMA, PREFIXED], ids=["production", "prefixed"])
def schema(request):
    return request.param


@pytest.mark.parametrize("name", sorted(ALL_BUILDERS))
def test_every_query_enters_through_an_id(name, schema):
    query = ALL_BUILDERS[name](schema)
    assert "{id: $" in query.cypher, (
        f"{name} does not anchor on an id; without a secondary index this is a "
        "full label scan"
    )


@pytest.mark.parametrize("name", sorted(ALL_BUILDERS))
def test_every_query_passes_the_read_only_guard(name, schema):
    assert guard.check(ALL_BUILDERS[name](schema).cypher) is None


@pytest.mark.parametrize("name", sorted(ALL_BUILDERS))
def test_no_query_projects_a_relationship_variable(name, schema):
    """`RETURN e` and `RETURN e.id` are both rejected by the engine."""
    cypher = ALL_BUILDERS[name](schema).cypher
    projection = cypher.split("RETURN", 1)[1]
    assert "e.id" not in projection
    for term in projection.split(","):
        term = term.strip().removeprefix("DISTINCT ").strip()
        assert "." in term, f"{name} projects a bare variable: {term!r}"


@pytest.mark.parametrize("name", sorted(ALL_BUILDERS))
def test_every_query_uses_the_schema_it_was_given(name, schema):
    cypher = ALL_BUILDERS[name](schema).cypher
    assert schema.repo.split("Repo")[0] in cypher or schema.resolves.split("_")[0] in cypher


@pytest.mark.parametrize("name", sorted(ALL_BUILDERS))
def test_parameters_are_integers_and_never_interpolated(name, schema):
    query = ALL_BUILDERS[name](schema)
    assert query.params, f"{name} inlines its arguments instead of parameterising them"
    for key, value in query.params.items():
        assert isinstance(value, int), f"{name}.{key} is not an int"
        assert f"${key}" in query.cypher


@pytest.mark.parametrize("name", sorted(ALL_BUILDERS))
def test_columns_match_the_projection_width(name, schema):
    query = ALL_BUILDERS[name](schema)
    projected = query.cypher.split("RETURN", 1)[1].count(",") + 1
    assert len(query.columns) == projected, f"{name} declares the wrong column list"


TIME_QUERIES = ["repos_resolving_version", "repos_resolving_package", "maintainer_reach"]


@pytest.mark.parametrize("name", TIME_QUERIES)
def test_asof_queries_use_the_half_open_predicate(name, schema):
    cypher = ALL_BUILDERS[name](schema).cypher
    assert "e.valid_from <= $t AND e.valid_to > $t" in cypher, (
        "the interval predicate must be lower-inclusive and upper-exclusive"
    )


@pytest.mark.parametrize("name", sorted(set(ALL_BUILDERS) - set(TIME_QUERIES)))
def test_non_temporal_queries_do_not_filter_on_time(name, schema):
    assert "valid_from" not in ALL_BUILDERS[name](schema).cypher


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
    """`count(DISTINCT x)` is not executable; counting is folded client-side."""
    for build in ALL_BUILDERS.values():
        assert "count(DISTINCT" not in build(schema).cypher


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


def test_query_serialises_for_debugging(schema):
    payload = queries.repos_resolving_version(schema, 5, 9).as_dict()
    assert payload["parameters"] == {"vid": 5, "t": 9}
    assert payload["cypher"].startswith("MATCH")
