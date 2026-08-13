"""The two surfaces, asked the same question of the same data.

An incident responder scrubbing the console's timeline and an agent calling the
MCP tool are asking the graph the same thing. If those two can return different
answers, one of them is wrong at the moment it matters most, and nobody will
find out during the incident. They used to be able to: each package carried its
own copy of the Cypher, and two copies drift the first time one is tuned.

So both now compose from :mod:`hindsight.queries`, and this file is the proof
that the seam holds end to end — not by comparing statements, which would only
restate the refactor, but by comparing *answers*, through each surface's real
entry point: an MCP ``call_tool`` and an HTTP GET against the console. Anything
either surface adds on top (the console's classification and repository join,
the tools' evidence caveats) is presentation and is deliberately not compared;
the facts underneath have to be identical.

Isolation is by label, as everywhere else here: HydraDB deletes at ~3 nodes/sec
against 17k inserts/sec, so the graph is append-only and this module writes only
under ``SharedTest*`` / ``SHAREDTEST_*`` with run-scoped names, sharing no ids
with a previous run.
"""

from __future__ import annotations

import asyncio
import secrets

import pytest
from starlette.testclient import TestClient

from hindsight.client import HydraClient
from hindsight.graphbuild import RepoInput, Schema, build_rowsets
from hindsight.history import Snapshot, build_intervals
from hindsight.ingest import Ingestor
from hindsight_mcp.server import build_server
from hindsight_mcp.service import Hindsight, Limits
from hindsight_web.app import build_app
from hindsight_web.incident import build_incident
from hindsight_web.service import Console

pytestmark = pytest.mark.integration

SHARED_SCHEMA = Schema.prefixed("SharedTest", "SHAREDTEST")

RUN = secrets.token_hex(6)

CHALK = f"chalk-{RUN}"
DEBUG = f"debug-{RUN}"

EXPOSED_SLUG = f"sharedtest/{RUN}-checkout"
CLEAN_SLUG = f"sharedtest/{RUN}-webapp"
DROPPER_SLUG = f"sharedtest/{RUN}-datastore"

OWNER = f"acct-{RUN}-owner"  # publishes both incident packages
NARROW = f"acct-{RUN}-narrow"  # publishes one, reached through one repository

#: The real incident's clock, so the interval arithmetic under comparison is the
#: arithmetic the demo runs on.
W_START = 1_757_337_130  # 2025-09-08T13:12:10Z, first malicious publish
W_END = 1_757_345_400  # 2025-09-08T15:30:00Z
BEFORE = 1_756_000_000  # 2025-08-24, a routine bump
REINSTALL = W_START + 1_000  # inside the window
REMEDIATION = W_END + 5_000  # after it

#: Three instants at which the answer is different, deliberately sitting on the
#: interval boundaries rather than in the middle of a span: two surfaces
#: compared at some quiet instant in the middle of a three-month pin would agree
#: even if one of them were reading the clock wrong by an hour.
INSTANTS = (REINSTALL - 1, REINSTALL, REMEDIATION)

RAW = {
    "incident": f"surface-agreement fixture {RUN}",
    "date": "2025-09-08",
    "window": {
        "first_malicious_publish_utc": "2025-09-08T13:12:10Z",
        "practical_exposure_window_utc": [
            "2025-09-08T13:12:10Z",
            "2025-09-08T15:30:00Z",
        ],
    },
    "packages": [
        {
            "package": CHALK,
            "malicious_version": "5.6.1",
            "wave": 1,
            "published_at": "2025-09-08T13:13:05Z",
            "remediated_version": "5.6.2",
            "remediated_published_at": "2025-09-08T14:47:54Z",
        },
        {
            "package": DEBUG,
            "malicious_version": "4.4.2",
            "wave": 1,
            "published_at": "2025-09-08T13:12:39Z",
        },
    ],
}

INCIDENT = build_incident(RAW)


def snapshot(index, ts, **deps):
    return Snapshot(
        commit=f"{RUN}-{index}",
        ts=ts,
        paths=("package-lock.json",),
        entries=frozenset(deps.items()),
    )


def repo(slug, service, snapshots):
    return RepoInput(
        slug=slug,
        name=slug,
        service=service,
        intervals=tuple(build_intervals(snapshots)),
        first_ts=snapshots[0].ts,
        last_ts=snapshots[-1].ts,
        snapshots=len(snapshots),
    )


@pytest.fixture(scope="module")
def client():
    hydra = HydraClient.from_env()
    if not hydra.ping():
        pytest.skip("no HydraDB node reachable")
    return hydra


@pytest.fixture(scope="module")
def seeded(client):
    """A fixture whose answer is different at each of :data:`INSTANTS`.

    One repository bumps into the malicious version and back out again, one
    holds a clean pin throughout, and one drops a dependency — so exposure, the
    blast radius and a maintainer's reach all move between the instants
    compared, and a surface that ignored its timestamp could not pass by
    agreeing once.
    """
    inputs = [
        repo(
            EXPOSED_SLUG,
            "checkout",
            [
                snapshot(0, BEFORE, **{CHALK: "5.6.0", DEBUG: "4.3.7"}),
                snapshot(1, REINSTALL, **{CHALK: "5.6.1", DEBUG: "4.4.2"}),
                snapshot(2, REMEDIATION, **{CHALK: "5.6.2", DEBUG: "4.3.7"}),
            ],
        ),
        repo(CLEAN_SLUG, "web", [snapshot(3, BEFORE, **{CHALK: "5.6.0"})]),
        repo(
            DROPPER_SLUG,
            "storage",
            [
                snapshot(4, BEFORE, **{f"pg-{RUN}": "8.12.0", DEBUG: "4.3.7"}),
                snapshot(5, REINSTALL, **{f"pg-{RUN}": "8.12.0"}),
            ],
        ),
    ]
    rows = build_rowsets(
        inputs, schema=SHARED_SCHEMA, maintainers={OWNER: [CHALK, DEBUG], NARROW: [DEBUG]}
    )
    report = Ingestor(client, schema=SHARED_SCHEMA, batch=500).run(
        rows, tx_from=REMEDIATION + 1
    )
    assert report.edges_written > 0
    return report


@pytest.fixture(scope="module")
def agent(client, seeded):
    """The MCP surface: the real server, over the real tool call."""
    return build_server(
        Hindsight(client=client, schema=SHARED_SCHEMA, limits=Limits())
    )


@pytest.fixture(scope="module")
def console(client, seeded):
    """The web surface: the real app, over HTTP."""
    view = Console(client=client, schema=SHARED_SCHEMA, incident=INCIDENT)
    with TestClient(build_app(view)) as http:
        yield http


def tool(server, name, arguments) -> dict:
    return asyncio.run(server.call_tool(name, arguments)).structured_content


def api(http, path, **params) -> dict:
    response = http.get(path, params=params)
    assert response.status_code == 200, response.text
    return response.json()


def mine(slug: object) -> bool:
    """This run's repositories — the label holds every previous run's too."""
    return RUN in str(slug)


# --------------------------------------------------------------------- exposure


@pytest.mark.parametrize("at", INSTANTS)
def test_both_surfaces_name_the_same_repositories_for_one_package(agent, console, at):
    from_agent = {
        row["slug"]
        for row in tool(agent, "exposure_asof", {"package": CHALK, "at_timestamp": at})[
            "repos"
        ]
        if mine(row["slug"])
    }
    from_console = {
        row["slug"]
        for row in api(console, "/api/exposure", package=CHALK, at=at)["repos"]
        if mine(row["slug"]) and row["status"] != "NOT_RESOLVED"
    }
    assert from_agent == from_console
    assert from_agent, "the fixture resolves this package at every instant tested"


@pytest.mark.parametrize("at", INSTANTS)
def test_both_surfaces_report_the_same_resolution_intervals(agent, console, at):
    """The underlying fact, not the wording around it: (repo, version, [from, to))."""
    from_agent = {
        (row["slug"], row["version"], row["valid_from"], row["valid_to"])
        for row in tool(agent, "exposure_asof", {"package": CHALK, "at_timestamp": at})[
            "repos"
        ]
        if mine(row["slug"])
    }
    from_console = {
        (row["slug"], version["version"], version["valid_from"], version["valid_to"])
        for row in api(console, "/api/exposure", package=CHALK, at=at)["repos"]
        if mine(row["slug"])
        for version in row["versions"]
    }
    assert from_agent == from_console


def test_both_surfaces_agree_on_who_held_the_malicious_version(agent, console):
    at = REINSTALL + 10
    from_agent = sorted(
        row["slug"]
        for row in tool(
            agent,
            "exposure_asof",
            {"package": CHALK, "version": "5.6.1", "at_timestamp": at},
        )["repos"]
        if mine(row["slug"])
    )
    footprint = api(
        console, "/api/version-footprint", package=CHALK, version="5.6.1", at=at
    )
    assert from_agent == sorted(s for s in footprint["repos"] if mine(s))
    assert from_agent == [EXPOSED_SLUG]


def test_both_surfaces_agree_that_an_unresolved_version_has_no_node(agent, console):
    """The strongest negative the graph can produce has to read the same on both."""
    at = REINSTALL + 10
    from_agent = tool(
        agent,
        "exposure_asof",
        {"package": CHALK, "version": "9.9.9", "at_timestamp": at},
    )
    footprint = api(
        console, "/api/version-footprint", package=CHALK, version="9.9.9", at=at
    )
    assert from_agent["anchor"]["exists"] is footprint["version_in_graph"] is False
    assert from_agent["repos"] == []
    assert footprint["repos"] == []


# ----------------------------------------------------------------- blast radius


@pytest.mark.parametrize("at", INSTANTS)
def test_both_surfaces_draw_the_same_blast_radius(agent, console, at):
    from_agent = {
        (row["slug"], version["version"], version["valid_from"], version["valid_to"])
        for row in tool(agent, "blast_radius", {"package": CHALK, "at_timestamp": at})[
            "repos"
        ]
        if mine(row["slug"])
        for version in row["versions"]
    }
    graph = api(console, "/api/blast-radius", package=CHALK, at=at)
    from_console = {
        (
            edge["source"].removeprefix("repo:"),
            edge["target"].removeprefix("ver:").rsplit("@", 1)[-1],
            edge["valid_from"],
            edge["valid_to"],
        )
        for edge in graph["edges"]
        if edge["kind"] == "RESOLVES" and mine(edge["source"])
    }
    assert from_agent == from_console


def test_both_surfaces_count_the_same_versions_in_the_radius(agent, console):
    at = REINSTALL + 10
    from_agent = tool(agent, "blast_radius", {"package": CHALK, "at_timestamp": at})
    graph = api(console, "/api/blast-radius", package=CHALK, at=at)
    versions_seen = {
        node["version"] for node in graph["nodes"] if node["kind"] == "version"
    }
    assert set(from_agent["versions"]) == versions_seen == {"5.6.0", "5.6.1"}


# ------------------------------------------------------------- maintainer reach


@pytest.mark.parametrize("maintainer", [OWNER, NARROW])
@pytest.mark.parametrize("at", INSTANTS)
def test_both_surfaces_measure_the_same_trust_radius(agent, console, maintainer, at):
    from_agent = tool(
        agent, "maintainer_reach", {"maintainer": maintainer, "at_timestamp": at}
    )
    from_console = api(console, "/api/maintainer-reach", name=maintainer, at=at)

    assert from_agent["maintains_packages"] == from_console["maintains_packages"]
    assert from_agent["reached_packages"] == from_console["reached_packages"]
    assert from_agent["repo_package_pairs"] == from_console["repo_package_pairs"]
    assert {
        (row["slug"], tuple(row["via_packages"])) for row in from_agent["reached_repos"]
    } == {
        (row["slug"], tuple(row["via_packages"]))
        for row in from_console["reached_repos"]
    }


def test_the_answers_being_compared_actually_move_between_the_instants(agent):
    """Guards every comparison above: two surfaces agreeing on a constant would
    prove nothing, so the fixture has to change at each instant tested."""
    reach = [
        tool(agent, "maintainer_reach", {"maintainer": NARROW, "at_timestamp": at})[
            "reached_repo_count"
        ]
        for at in INSTANTS
    ]
    exposure = [
        sorted(
            (row["slug"], row["version"])
            for row in tool(
                agent, "exposure_asof", {"package": CHALK, "at_timestamp": at}
            )["repos"]
            if mine(row["slug"])
        )
        for at in INSTANTS
    ]
    assert len(set(reach)) > 1, f"maintainer reach is static across {INSTANTS}: {reach}"
    assert len({str(e) for e in exposure}) == len(INSTANTS), (
        f"exposure is static across {INSTANTS}: {exposure}"
    )


# ------------------------------------------------------------------- id lookups


def test_both_surfaces_resolve_a_name_to_the_same_node(agent, console):
    """Ids are derived from the name, so this is really a check that both
    surfaces ask about the same node — the anchor every other answer hangs on."""
    anchor = tool(agent, "resolve_id", {"kind": "package", "name": CHALK})
    exposure = api(console, "/api/exposure", package=CHALK, at=REINSTALL + 10)
    assert anchor["exists"] is exposure["package_in_graph"] is True

    absent = tool(agent, "resolve_id", {"kind": "package", "name": f"nothing-{RUN}"})
    missing = api(console, "/api/exposure", package=f"nothing-{RUN}", at=REINSTALL + 10)
    assert absent["exists"] is missing["package_in_graph"] is False
