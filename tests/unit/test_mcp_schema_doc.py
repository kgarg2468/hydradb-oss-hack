"""The schema document is what makes the raw `cypher` tool usable, so it is
tested for completeness rather than for prose.

Anything missing here costs the agent a turn it cannot recover on its own: a
label it does not know exists, an interval convention it gets off by one, an
operator it keeps retrying because nothing told it the engine has no `IN`.
"""

import pytest

from hindsight.graphbuild import DEFAULT_SCHEMA, Schema
from hindsight.history import SENTINEL
from hindsight_mcp import schema_doc

TEST_PREFIXED = Schema.prefixed("McpTest", "MCPTEST")


@pytest.fixture(params=[DEFAULT_SCHEMA, TEST_PREFIXED], ids=["production", "prefixed"])
def schema(request):
    return request.param


@pytest.fixture
def doc(schema):
    return schema_doc.graph_schema(schema)


@pytest.fixture
def markdown(schema):
    return schema_doc.render_markdown(schema)


def test_every_label_in_the_schema_is_documented(schema, doc, markdown):
    documented = {entry["label"] for entry in doc["labels"]}
    for label in (schema.repo, schema.package, schema.version, schema.maintainer,
                  schema.watermark):
        assert label in documented, f"{label} is in the graph but not in the schema doc"
        assert label in markdown


def test_every_relationship_type_is_documented(schema, doc, markdown):
    documented = {entry["type"] for entry in doc["relationships"]}
    for rel in (schema.resolves, schema.version_of, schema.maintains):
        assert rel in documented
        assert rel in markdown


def test_relationship_endpoints_are_stated(schema, doc):
    by_type = {entry["type"]: entry for entry in doc["relationships"]}
    assert by_type[schema.resolves]["from"] == schema.repo
    assert by_type[schema.resolves]["to"] == schema.version
    assert by_type[schema.version_of]["from"] == schema.version
    assert by_type[schema.version_of]["to"] == schema.package
    assert by_type[schema.maintains]["from"] == schema.maintainer
    assert by_type[schema.maintains]["to"] == schema.package


def test_every_node_property_the_ingest_writes_is_documented(doc, markdown):
    """Kept in step with hindsight.graphbuild.build_rowsets by hand; if a
    property is added there and not here the agent cannot see it."""
    expected = {
        "repo": {"id", "slug", "name", "service", "first_ts", "last_ts", "snapshots"},
        "package": {"id", "name"},
        "version": {"id", "pkg", "version", "key", "pkg_id"},
        "maintainer": {"id", "name"},
    }
    by_kind = {entry["kind"]: entry for entry in doc["labels"]}
    for kind, properties in expected.items():
        documented = set(by_kind[kind]["properties"])
        assert properties <= documented, f"{kind} is missing {properties - documented}"
        for name in properties:
            assert f"`{name}`" in markdown


def test_the_bitemporal_edge_properties_are_documented(schema, doc):
    by_type = {entry["type"]: entry for entry in doc["relationships"]}
    resolves = by_type[schema.resolves]
    assert resolves["bitemporal"] is True
    assert set(resolves["properties"]) == {"valid_from", "valid_to", "tx_from", "tx_to"}


def test_the_half_open_convention_is_unambiguous(doc, markdown):
    convention = doc["bitemporal"]["convention"]
    assert "INCLUSIVE" in convention and "EXCLUSIVE" in convention
    assert doc["bitemporal"]["asof_predicate"] == "e.valid_from <= $t AND e.valid_to > $t"
    assert "e.valid_from <= $t AND e.valid_to > $t" in markdown


def test_the_open_interval_sentinel_is_stated_with_its_value(doc, markdown):
    assert doc["bitemporal"]["far_future"] == SENTINEL
    assert str(SENTINEL) in doc["bitemporal"]["convention"]
    assert str(SENTINEL) in markdown
    assert "IS NULL" in doc["bitemporal"]["convention"]


def test_the_efficiency_note_tells_the_agent_how_to_get_an_id(doc, markdown):
    note = doc["how_to_query_efficiently"]
    assert "no secondary property index" in note
    assert "resolve_id" in note
    assert "{id: $id}" in note
    assert note in markdown


def test_id_derivation_is_explained(doc):
    assert "blake2b" in doc["ids"]
    for key_form in ("repo:<slug>", "pkg:<name>", "pv:<name>@<version>", "maint:<name>"):
        assert key_form in doc["ids"]


def test_the_operator_blocklist_covers_everything_the_engine_rejects(doc, markdown):
    listed = " ".join(entry["construct"] for entry in doc["unsupported"])
    for construct in ("IN", "CONTAINS", "IS NULL", "min()", "max()", "count(DISTINCT x)",
                      "shortestPath", "RETURN *", "bare MATCH (n)", "multiple statements"):
        assert construct in listed, f"{construct} is not in the blocklist"
    assert "IN" in markdown and "shortestPath" in markdown


def test_every_blocked_construct_carries_a_workaround(doc):
    for entry in doc["unsupported"]:
        assert entry["workaround"].strip(), f"{entry['construct']} has no workaround"
        assert entry["engine_error"].strip()


def test_the_relationship_projection_rule_is_spelled_out(doc):
    entry = next(e for e in doc["unsupported"] if "relationship variable" in e["construct"])
    assert "e.id" in entry["workaround"]
    assert "valid_from" in entry["workaround"]


def test_engine_limits_are_documented(doc):
    limits = {entry["limit"]: entry["detail"] for entry in doc["limits"]}
    assert "4096" in limits["page_size"]
    assert "1024" in limits["UNWIND batch"]
    assert "30000" in limits["query timeout"]


def test_recipes_are_rendered_against_the_live_schema(schema, doc, markdown):
    assert doc["recipes"], "the document ships no worked queries"
    for recipe in doc["recipes"]:
        cypher = recipe["cypher"]
        assert "{" not in cypher.replace("{id:", "").replace("{{", ""), (
            f"unsubstituted placeholder in: {cypher}"
        )
        assert schema.repo in cypher or schema.package in cypher
        assert "$" in cypher, "a recipe that hard-codes values teaches the wrong habit"
        assert cypher in markdown


def test_every_recipe_is_id_anchored_and_read_only():
    """The recipes are what an agent copies, so they must pass our own guard."""
    from hindsight_mcp import guard

    for recipe in schema_doc.graph_schema(DEFAULT_SCHEMA)["recipes"]:
        assert guard.check(recipe["cypher"]) is None, recipe["question"]
        assert "{id: $" in recipe["cypher"], recipe["question"]


def test_the_evidence_semantics_never_imply_deployment(doc, markdown):
    note = doc["evidence_semantics"]
    assert "RESOLVES" in note
    assert "does NOT mean" in note
    for word in ("installed", "built", "executed", "deployed"):
        assert word in note
    assert note in markdown
    assert markdown.index(note) < markdown.index("## Node labels"), (
        "the evidence caveat must come before the schema, not be buried after it"
    )


def test_the_maintainer_edge_is_flagged_as_present_tense(schema, doc):
    by_type = {entry["type"]: entry for entry in doc["relationships"]}
    note = by_type[schema.maintains]["note"]
    assert "PRESENT TENSE" in note
    assert by_type[schema.maintains]["bitemporal"] is False


def test_the_document_states_that_writes_are_refused(markdown):
    assert "Mutations" in markdown
    assert "append-only" in markdown


def test_markdown_is_substantial_and_well_formed(markdown):
    # A truncated or half-rendered document is worse than none: the agent would
    # trust it. Cheap structural assertions catch that.
    assert len(markdown) > 3000
    for heading in ("## Node labels", "## Relationships", "## Bitemporal convention",
                    "## How to query efficiently", "## Recipes", "## Unsupported",
                    "## Limits"):
        assert heading in markdown
    assert markdown.count("```cypher") == markdown.count("```") // 2
