"""The MCP surface itself: which tools exist, what they promise, and what an
agent gets back when it gets something wrong.

The tool *descriptions* are load-bearing here in a way they are not in ordinary
code. They are the only documentation the model reads before choosing a call, so
they are asserted on: a `cypher` tool that does not mention the id-anchoring
rule, or an evidence-bearing tool whose description implies deployment, is a
defect even though nothing throws.
"""

import asyncio

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from hindsight.graphbuild import Schema
from hindsight_mcp.server import Settings, build_server
from hindsight_mcp.service import Hindsight, Limits

SCHEMA = Schema.prefixed("McpTest", "MCPTEST")

EXPECTED_TOOLS = {
    "cypher",
    "schema",
    "resolve_id",
    "exposure_asof",
    "blast_radius",
    "maintainer_reach",
}


class FakeClient:
    """One row for anything, plus the two scans behind the coverage verdict.

    Without those two the dataset reads as empty and every tool below would be
    exercised on its refusal path, which is not what these tests are about.
    """

    def __init__(self):
        self.calls = []

    def query(self, cypher, parameters=None, **kw):
        self.calls.append(cypher)
        if "RETURN r.id" in cypher:
            rows = [[1, "repo/a"]]
        elif "RETURN w.slug" in cypher:
            rows = [["repo/a", 100]]
        else:
            rows = [["chalk"]]
        return {
            "columns": ["n.name"],
            "rows": [[{"type": "any", "value": cell} for cell in row] for row in rows],
            "next_cursor": None,
        }


class EmptyClient(FakeClient):
    """A node that answers every statement correctly and holds nothing."""

    def query(self, cypher, parameters=None, **kw):
        self.calls.append(cypher)
        return {"columns": [], "rows": [], "next_cursor": None}


@pytest.fixture
def client():
    return FakeClient()


@pytest.fixture
def server(client):
    return build_server(Hindsight(client=client, schema=SCHEMA, limits=Limits(max_rows=10)))


@pytest.fixture
def tools(server):
    return {tool.name: tool for tool in asyncio.run(server.list_tools())}


def call(server, tool, arguments):
    return asyncio.run(server.call_tool(tool, arguments))


def test_the_surface_is_small_and_deliberate(tools):
    """The differentiator is raw `cypher` plus a schema, not thirty canned
    tools; a surface that has quietly grown is worth noticing."""
    assert set(tools) == EXPECTED_TOOLS


def test_every_tool_has_a_title_and_a_real_description(tools):
    for name, tool in tools.items():
        assert tool.title, f"{name} has no title"
        assert tool.description and len(tool.description) > 80, f"{name} is underdocumented"


def test_the_cypher_tool_teaches_the_two_rules_that_matter(tools):
    description = tools["cypher"].description
    assert "{id: $id}" in description
    assert "resolve_id" in description
    assert "read-only" in description or "Mutations" in description
    assert "semicolon" in description


def test_the_schema_tool_advertises_what_it_contains(tools):
    description = tools["schema"].description
    for topic in ("bitemporal", "valid_from", "valid_to", "reject"):
        assert topic in description


def test_evidence_bearing_tools_never_promise_deployment(tools):
    """The description is what the model reads before deciding what a result
    means, so it may disclaim deployment but must never assert it."""
    overstatements = (
        "was deployed",
        "were deployed",
        "is deployed",
        "are deployed",
        "in production",
        "vulnerable",
        "compromised repositories",
    )
    for name in ("exposure_asof", "blast_radius", "maintainer_reach"):
        blob = f"{tools[name].title} {tools[name].description}".lower()
        for phrase in overstatements:
            assert phrase not in blob, f"{name}'s description overstates the evidence"
    assert "never deployment" in tools["exposure_asof"].description.lower()
    assert "lockfile" in tools["exposure_asof"].description.lower()
    assert "lockfile" in tools["blast_radius"].description.lower()


def test_the_instructions_state_the_evidence_rule(server):
    assert "RESOLVED" in server.instructions
    assert "does not prove" in server.instructions
    assert "resolve_id" in server.instructions


def test_required_arguments_match_the_questions(tools):
    assert set(tools["cypher"].input_schema["required"]) == {"query"}
    assert set(tools["exposure_asof"].input_schema["required"]) == {"package", "at_timestamp"}
    assert set(tools["blast_radius"].input_schema["required"]) == {"package", "at_timestamp"}
    assert set(tools["maintainer_reach"].input_schema["required"]) == {"maintainer"}
    assert set(tools["resolve_id"].input_schema["required"]) == {"kind", "name"}


def test_timestamps_are_accepted_in_either_form(tools):
    at = tools["blast_radius"].input_schema["properties"]["at_timestamp"]
    assert {"type": "integer"} in at["anyOf"]
    assert {"type": "string"} in at["anyOf"]


def test_the_schema_resource_is_published(server):
    resources = asyncio.run(server.list_resources())
    assert [str(r.uri) for r in resources] == ["hindsight://schema"]


def test_the_schema_resource_serves_the_configured_labels(server):
    contents = asyncio.run(server.read_resource("hindsight://schema"))
    body = "".join(str(item.content) for item in contents)
    assert SCHEMA.repo in body
    assert "valid_to" in body


def test_a_read_round_trips_through_the_tool(server, client):
    result = call(
        server,
        "cypher",
        {"query": "MATCH (n:McpTestPkg {id: $id}) RETURN n.name", "parameters": {"id": 1}},
    )
    assert result.is_error is False
    assert result.structured_content["rows"] == [["chalk"]]
    assert result.structured_content["truncated"] is False
    assert client.calls


def test_a_write_is_refused_before_the_database_sees_it(server, client):
    with pytest.raises(ToolError) as excinfo:
        call(server, "cypher", {"query": "MATCH (n:McpTestPkg {id: 1}) DELETE n"})
    message = str(excinfo.value)
    # The agent has to be able to self-correct from this string alone.
    assert "read-only" in message
    assert "DELETE" in message
    assert "rewrite the statement as a read" in message
    assert client.calls == []


def test_a_bad_argument_comes_back_as_a_correctable_error(server):
    with pytest.raises(ToolError) as excinfo:
        call(server, "resolve_id", {"kind": "commit", "name": "abc123"})
    message = str(excinfo.value)
    assert "invalid argument" in message
    assert "maintainer" in message


def test_a_canned_tool_returns_structured_content_with_its_caveat(server):
    result = call(server, "blast_radius", {"package": "chalk", "at_timestamp": 1000})
    assert result.is_error is False
    assert result.structured_content["evidence"] == "resolved"
    assert "lockfile resolution" in result.structured_content["caveat"]
    assert result.structured_content["answerable"] is True


def test_the_exposure_description_conditions_the_negative_it_promises(tools):
    """The description is the only place the agent is told, before it calls,
    that an empty result can also mean nobody ever loaded the dataset."""
    description = tools["exposure_asof"].description
    assert "proven negative" in description
    assert "answerable: true" in description
    assert "unanswerable_note" in description


def test_a_tool_over_an_empty_dataset_refuses_rather_than_reporting_an_all_clear():
    """The refusal has to survive into structured_content: that, and not the
    prose the tool body composed, is what the agent reads and relays."""
    server = build_server(
        Hindsight(client=EmptyClient(), schema=SCHEMA, limits=Limits())
    )
    result = call(server, "exposure_asof", {"package": "chalk", "at_timestamp": 1000})
    assert result.is_error is False
    body = result.structured_content
    assert body["answerable"] is False
    assert body["unanswerable_reason"] == "empty_dataset"
    assert "no question can be answered" in body["note"]
    assert "proven negative" not in body["note"]


def test_settings_come_from_the_environment():
    settings = Settings.from_env(
        {
            "HINDSIGHT_MCP_NODE_PREFIX": "McpTest",
            "HINDSIGHT_MCP_REL_PREFIX": "MCPTEST",
            "HINDSIGHT_MCP_MAX_ROWS": "42",
            "HINDSIGHT_MCP_TIMEOUT": "7",
        }
    )
    assert settings.schema == SCHEMA
    assert settings.limits == Limits(max_rows=42, deadline_seconds=7.0)


def test_settings_default_to_the_production_labels():
    settings = Settings.from_env({})
    assert settings.schema.repo == "HsRepo"
    assert settings.schema.resolves == "HS_RESOLVES"
