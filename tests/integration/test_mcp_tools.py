"""Every MCP tool, end to end against a real HydraDB node.

The unit tests prove the logic; this file proves the Cypher. That distinction
matters here more than usual, because the engine executes a restricted
OpenCypher subset and the constructs it rejects (`IN`, `IS NULL`, `min`/`max`,
relationship-variable projection) are ones a reasonable person would assume
work. A query builder that is obviously correct and quietly unexecutable is the
failure mode this file exists to catch.

The fixture is a three-repository organisation with a version bump and a
dropped dependency, so the AS-OF answers differ at T0, T1 and after — a tool
that ignored its timestamp would still pass a single-instant test.

Isolation is by label, not by cleanup: HydraDB deletes at roughly 3 nodes/sec
against 17k inserts/sec, and `MATCH (n:L) DETACH DELETE n` exceeds a hard 30 s
server cap, so the graph is append-only by design. Everything here is written
under `McpTest*` / `MCPTEST_*` with run-scoped names, so reruns cannot collide
with each other and nothing touches the production `Hs*` dataset.
"""

import asyncio
import secrets

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from hindsight.client import HydraClient, HydraError
from hindsight.graphbuild import RepoInput, Schema, build_rowsets
from hindsight.history import SENTINEL, Interval
from hindsight.ids import maintainer_id, package_id, repo_id, version_id
from hindsight.ingest import Ingestor
from hindsight_mcp import guard
from hindsight_mcp.server import build_server
from hindsight_mcp.service import Hindsight, Limits

pytestmark = pytest.mark.integration

MCP_SCHEMA = Schema.prefixed("McpTest", "MCPTEST")

RUN = secrets.token_hex(6)
T0 = 1_700_000_000
T1 = T0 + 86_400
T2 = T1 + 86_400

CHALK = f"chalk-{RUN}"
LODASH = f"lodash-{RUN}"
ALPHA = f"mcptest/alpha-{RUN}"
BETA = f"mcptest/beta-{RUN}"
GAMMA = f"mcptest/gamma-{RUN}"
QIX = f"qixtest-{RUN}"
SOLO = f"solotest-{RUN}"


def repo(slug, intervals):
    return RepoInput(
        slug=slug,
        name=slug.split("/")[-1],
        service="mcp-test",
        intervals=tuple(intervals),
        first_ts=T0,
        last_ts=T2,
        snapshots=3,
    )


#: alpha bumps chalk at T1 and keeps lodash; beta only ever had the new chalk;
#: gamma dropped lodash at T1. Every tool below therefore has an instant at
#: which its answer changes.
FIXTURE = [
    repo(
        ALPHA,
        [
            Interval(CHALK, "5.0.0", T0, T1),
            Interval(CHALK, "5.3.0", T1, SENTINEL),
            Interval(LODASH, "4.17.21", T0, SENTINEL),
        ],
    ),
    repo(BETA, [Interval(CHALK, "5.3.0", T1, SENTINEL)]),
    repo(GAMMA, [Interval(LODASH, "4.17.21", T0, T1)]),
]

MAINTAINERS = {QIX: [CHALK], SOLO: [LODASH]}


@pytest.fixture(scope="module")
def client():
    client = HydraClient.from_env()
    if not client.ping():
        pytest.skip("no HydraDB node reachable")
    return client


@pytest.fixture(scope="module")
def seeded(client):
    """Write the fixture through the real ingest path, not a hand-rolled one."""
    rowsets = build_rowsets(FIXTURE, schema=MCP_SCHEMA, maintainers=MAINTAINERS)
    report = Ingestor(client, schema=MCP_SCHEMA, batch=500).run(rowsets, tx_from=T2 + 1)
    assert report.edges_written > 0
    return report


@pytest.fixture(scope="module")
def hindsight(client, seeded):
    return Hindsight(client=client, schema=MCP_SCHEMA, limits=Limits())


@pytest.fixture(scope="module")
def server(hindsight):
    return build_server(hindsight)


def slugs(result, key="repos"):
    return sorted(row["slug"] for row in result[key])


# -------------------------------------------------------------------- resolve_id


def test_resolve_id_finds_every_seeded_kind(hindsight):
    for kind, name, expected in (
        ("repo", ALPHA, repo_id(ALPHA)),
        ("package", CHALK, package_id(CHALK)),
        ("version", f"{CHALK}@5.3.0", version_id(CHALK, "5.3.0")),
        ("maintainer", QIX, maintainer_id(QIX)),
    ):
        out = hindsight.resolve_id(kind, name)
        assert out["id"] == expected
        assert out["exists"] is True, f"{kind} {name} was seeded but not found"


def test_resolve_id_returns_the_nodes_properties(hindsight):
    out = hindsight.resolve_id("repo", ALPHA)
    assert out["properties"]["slug"] == ALPHA
    assert out["properties"]["service"] == "mcp-test"
    assert out["properties"]["snapshots"] == 3


def test_resolve_id_reports_a_name_the_graph_has_never_seen(hindsight):
    out = hindsight.resolve_id("package", f"never-ingested-{RUN}")
    assert out["exists"] is False
    assert "never been ingested" in out["note"]


def test_the_id_resolve_id_returns_is_usable_in_raw_cypher(hindsight):
    """The whole point of the tool: the id it hands back must anchor a query."""
    anchor = hindsight.resolve_id("package", CHALK)
    out = hindsight.cypher(
        f"MATCH (n:{MCP_SCHEMA.package} {{id: $id}}) RETURN n.name", {"id": anchor["id"]}
    )
    assert out["rows"] == [[CHALK]]


# ----------------------------------------------------------------- exposure_asof


def test_exposure_at_an_exact_version_finds_only_the_repo_that_had_it(hindsight):
    out = hindsight.exposure_asof(CHALK, "5.0.0", T0 + 10)
    assert slugs(out) == [ALPHA]
    assert out["repos"][0]["version"] == "5.0.0"
    assert out["resolved_by_repo_count"] == 1


def test_exposure_respects_the_half_open_boundary(hindsight):
    """valid_from inclusive, valid_to exclusive: at exactly T1 the old version
    is already gone. Getting this wrong is how an incident answer becomes a
    false positive."""
    assert hindsight.exposure_asof(CHALK, "5.0.0", T1 - 1)["repos"]
    after = hindsight.exposure_asof(CHALK, "5.0.0", T1)
    assert after["repos"] == []
    assert after["anchor"]["exists"] is True
    assert "proven negative" in after["note"]


def test_exposure_without_a_version_covers_every_version_of_the_package(hindsight):
    assert slugs(hindsight.exposure_asof(CHALK, None, T0 + 10)) == [ALPHA]
    assert slugs(hindsight.exposure_asof(CHALK, None, T1 + 10)) == sorted([ALPHA, BETA])


def test_exposure_before_the_org_existed_is_empty(hindsight):
    assert hindsight.exposure_asof(CHALK, None, T0 - 1)["repos"] == []


def test_exposure_reports_the_interval_each_resolution_held_over(hindsight):
    out = hindsight.exposure_asof(CHALK, "5.0.0", T0 + 10)
    row = out["repos"][0]
    assert (row["valid_from"], row["valid_to"]) == (T0, T1)
    assert row["open_interval"] is False
    assert row["valid_to_iso"] is not None

    still_open = hindsight.exposure_asof(CHALK, "5.3.0", T1 + 10)["repos"][0]
    assert still_open["open_interval"] is True
    assert still_open["valid_to_iso"] is None


def test_exposure_accepts_an_iso_timestamp(hindsight):
    by_epoch = hindsight.exposure_asof(CHALK, None, T1 + 10)
    by_iso = hindsight.exposure_asof(CHALK, None, by_epoch["at_iso"])
    assert slugs(by_iso) == slugs(by_epoch)


def test_a_package_nobody_ever_resolved_is_a_proven_negative(hindsight):
    out = hindsight.exposure_asof(f"absent-{RUN}", None, T1)
    assert out["anchor"]["exists"] is False
    assert out["repos"] == []
    assert "real negative" in out["note"]


# ------------------------------------------------------------------ blast_radius


def test_blast_radius_widens_as_the_package_spreads(hindsight):
    early = hindsight.blast_radius(CHALK, T0 + 10)
    assert early["repo_count"] == 1
    assert early["versions"] == ["5.0.0"]

    later = hindsight.blast_radius(CHALK, T1 + 10)
    assert later["repo_count"] == 2
    assert later["versions"] == ["5.3.0"]
    assert later["resolution_count"] == 2


def test_blast_radius_narrows_when_a_dependency_is_dropped(hindsight):
    assert hindsight.blast_radius(LODASH, T0 + 10)["repo_count"] == 2
    after = hindsight.blast_radius(LODASH, T1 + 10)
    assert after["repo_count"] == 1
    assert after["repos"][0]["slug"] == ALPHA


def test_blast_radius_rolls_up_versions_per_repository(hindsight):
    out = hindsight.blast_radius(CHALK, T1 + 10)
    by_slug = {row["slug"]: row for row in out["repos"]}
    assert by_slug[ALPHA]["versions"][0]["version"] == "5.3.0"
    assert by_slug[ALPHA]["version_count"] == 1
    assert by_slug[BETA]["name"] == BETA.split("/")[-1]


def test_blast_radius_of_an_unknown_package_says_why_it_is_empty(hindsight):
    out = hindsight.blast_radius(f"absent-{RUN}", T1)
    assert out["repo_count"] == 0
    assert "not by measurement" in out["note"]


# --------------------------------------------------------------- maintainer_reach


def test_maintainer_reach_follows_the_three_pattern_join(hindsight):
    out = hindsight.maintainer_reach(QIX, T1 + 10)
    assert out["reached_repo_count"] == 2
    assert sorted(row["slug"] for row in out["reached_repos"]) == sorted([ALPHA, BETA])
    assert out["reached_packages"] == [CHALK]
    assert out["repo_package_pairs"] == 2


def test_maintainer_reach_is_time_dependent(hindsight):
    """gamma dropped lodash at T1, so the solo maintainer's reach halves."""
    assert hindsight.maintainer_reach(SOLO, T0 + 10)["reached_repo_count"] == 2
    assert hindsight.maintainer_reach(SOLO, T1 + 10)["reached_repo_count"] == 1


def test_maintainer_reach_separates_ownership_from_reach(hindsight):
    out = hindsight.maintainer_reach(QIX, T1 + 10)
    assert out["maintains_packages"] == [CHALK]
    assert out["maintains_package_count"] == 1
    assert out["reached_repos"][0]["via_packages"] == [CHALK]


def test_maintainer_reach_defaults_to_the_open_intervals(hindsight):
    """No timestamp means 'if this account were phished tomorrow'."""
    out = hindsight.maintainer_reach(QIX)
    assert out["reached_repo_count"] == 2
    assert out["at"] > T2


def test_an_unknown_maintainer_reaches_nothing(hindsight):
    out = hindsight.maintainer_reach(f"nobody-{RUN}", T1 + 10)
    assert out["anchor"]["exists"] is False
    assert out["reached_repo_count"] == 0


# ------------------------------------------------------------------------ cypher


def test_raw_cypher_answers_a_question_no_canned_tool_covers(hindsight):
    """The differentiator: an agent composing its own traversal. Here, 'what
    else did the repo that had chalk@5.0.0 resolve at that instant'."""
    anchor = hindsight.resolve_id("repo", ALPHA)
    out = hindsight.cypher(
        f"MATCH (r:{MCP_SCHEMA.repo} {{id: $rid}})-[e:{MCP_SCHEMA.resolves}]->"
        f"(v:{MCP_SCHEMA.version}) "
        "WHERE e.valid_from <= $t AND e.valid_to > $t "
        "RETURN v.pkg, v.version, e.valid_from, e.valid_to",
        {"rid": anchor["id"], "t": T0 + 10},
    )
    assert sorted(row[:2] for row in out["rows"]) == [
        [CHALK, "5.0.0"],
        [LODASH, "4.17.21"],
    ]
    assert out["truncated"] is False
    assert out["row_count"] == 2


def test_raw_cypher_can_aggregate_server_side(hindsight):
    out = hindsight.cypher(
        f"MATCH (v:{MCP_SCHEMA.version})-[:{MCP_SCHEMA.version_of}]->"
        f"(p:{MCP_SCHEMA.package} {{id: $pid}}), "
        f"(r:{MCP_SCHEMA.repo})-[e:{MCP_SCHEMA.resolves}]->(v) "
        "WHERE e.valid_from <= $t AND e.valid_to > $t RETURN count(*)",
        {"pid": package_id(CHALK), "t": T1 + 10},
    )
    assert out["rows"] == [[2]]


def test_the_row_cap_truncates_and_admits_it(client, seeded):
    capped = Hindsight(client=client, schema=MCP_SCHEMA, limits=Limits(max_rows=1))
    out = capped.cypher(
        f"MATCH (v:{MCP_SCHEMA.version})-[:{MCP_SCHEMA.version_of}]->"
        f"(p:{MCP_SCHEMA.package} {{id: $pid}}), "
        f"(r:{MCP_SCHEMA.repo})-[e:{MCP_SCHEMA.resolves}]->(v) "
        "WHERE e.valid_from <= $t AND e.valid_to > $t RETURN DISTINCT r.slug",
        {"pid": package_id(CHALK), "t": T1 + 10},
    )
    assert out["row_count"] == 1
    assert out["truncated"] is True
    assert out["row_cap"] == 1


def test_a_write_is_refused_and_the_graph_is_untouched(hindsight):
    """The guard has to hold against a live, append-only node — a false
    negative here is unrecoverable."""
    def repo_count():
        return hindsight.cypher(
            f"MATCH (r:{MCP_SCHEMA.repo} {{id: $rid}}) RETURN count(*)",
            {"rid": hindsight.resolve_id("repo", ALPHA)["id"]},
        )["rows"][0][0]

    before = repo_count()
    for attack in (
        f"MATCH (r:{MCP_SCHEMA.repo} {{id: 1}}) DETACH DELETE r",
        f"CREATE (n:{MCP_SCHEMA.repo} {{id: 999}})",
        f"MATCH (r:{MCP_SCHEMA.repo} {{id: 1}}) RETURN r.slug; CREATE (n:Evil {{id: 998}})",
        f"MATCH (r:{MCP_SCHEMA.repo} {{name: '//'}}) DELETE r",
    ):
        with pytest.raises(guard.UnsafeCypher):
            hindsight.cypher(attack)
    assert repo_count() == before


def test_an_unsupported_construct_surfaces_the_engines_own_message(hindsight):
    """`IN` is in the schema document's blocklist; the error an agent gets back
    has to be recognisable as that same entry."""
    with pytest.raises(HydraError) as excinfo:
        hindsight.cypher(
            f"MATCH (n:{MCP_SCHEMA.package}) WHERE n.id IN [1, 2] RETURN n.name"
        )
    assert "not supported yet" in str(excinfo.value)


# --------------------------------------------------------------- the MCP surface


def call(server, tool, arguments):
    return asyncio.run(server.call_tool(tool, arguments))


def test_the_schema_resource_describes_the_graph_it_is_pointed_at(server):
    contents = asyncio.run(server.read_resource("hindsight://schema"))
    body = "".join(str(item.content) for item in contents)
    assert MCP_SCHEMA.resolves in body
    assert str(SENTINEL) in body


def test_each_canned_tool_answers_over_the_wire(server):
    exposure = call(
        server, "exposure_asof", {"package": CHALK, "version": "5.3.0", "at_timestamp": T1 + 10}
    )
    assert sorted(r["slug"] for r in exposure.structured_content["repos"]) == sorted(
        [ALPHA, BETA]
    )

    blast = call(server, "blast_radius", {"package": LODASH, "at_timestamp": T0 + 10})
    assert blast.structured_content["repo_count"] == 2

    reach = call(server, "maintainer_reach", {"maintainer": QIX, "at_timestamp": T1 + 10})
    assert reach.structured_content["reached_repo_count"] == 2

    resolved = call(server, "resolve_id", {"kind": "package", "name": CHALK})
    assert resolved.structured_content["id"] == package_id(CHALK)


def test_every_evidence_bearing_tool_ships_its_caveat_over_the_wire(server):
    for tool, arguments in (
        ("exposure_asof", {"package": CHALK, "at_timestamp": T1 + 10}),
        ("blast_radius", {"package": CHALK, "at_timestamp": T1 + 10}),
        ("maintainer_reach", {"maintainer": QIX, "at_timestamp": T1 + 10}),
    ):
        payload = call(server, tool, arguments).structured_content
        assert payload["evidence"] == "resolved"
        assert "not proof the dependency was installed" in payload["caveat"]


def test_the_cypher_tool_refuses_a_write_over_the_wire(server):
    with pytest.raises(ToolError) as excinfo:
        call(server, "cypher", {"query": f"MATCH (r:{MCP_SCHEMA.repo} {{id: 1}}) DELETE r"})
    assert "read-only" in str(excinfo.value)
