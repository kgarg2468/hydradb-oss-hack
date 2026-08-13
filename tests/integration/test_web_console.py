"""The console against a real HydraDB node.

The unit tests prove the console shapes rows correctly; this proves the engine
accepts the statements that produce them. Every constraint in
``poc/POC-RESULTS.md`` §6 was discovered as a 400 from a live node, and a
console that only ever ran against a fake would rediscover them on stage.

Isolation is by label, as everywhere else in this repository: deletes run at
~3 nodes/sec against 17k inserts/sec, so the graph is append-only and this
module writes only under ``ReplayTest*`` / ``REPLAYTEST_*``. Package names,
repository slugs and maintainer accounts are all run-scoped, so a rerun shares
no ids with a previous one and the assertions below are about *this* run's
repositories rather than about whatever else the label already holds.
"""

from __future__ import annotations

import importlib.util
import secrets
import sys
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from hindsight.client import HydraClient
from hindsight.graphbuild import RepoInput, build_rowsets
from hindsight.history import Snapshot, build_intervals
from hindsight.ids import repo_id
from hindsight.ingest import Ingestor
from hindsight_web.app import build_app
from hindsight_web.incident import build_incident
from hindsight_web.paging import fetch_all
from hindsight_web.queries import TEST_SCHEMA
from hindsight_web.service import Console

pytestmark = pytest.mark.integration

ROOT = Path(__file__).resolve().parents[2]
RUN = secrets.token_hex(6)

CHALK = f"chalk-{RUN}"
DEBUG = f"debug-{RUN}"
LEFTPAD = f"left-pad-{RUN}"

EXPOSED_SLUG = f"replaytest/{RUN}-checkout"
CLEAN_SLUG = f"replaytest/{RUN}-webapp"
ABSENT_SLUG = f"replaytest/{RUN}-datastore"

OWNER = f"acct-{RUN}-owner"  # publishes both incident packages
NARROW = f"acct-{RUN}-narrow"  # publishes one, resolved by one repository
BYSTANDER = f"acct-{RUN}-bystander"  # publishes only the package nobody resolved

#: The real incident's clock, so the interval arithmetic under test is the same
#: arithmetic the demo runs on.
W_START = 1_757_337_130  # 2025-09-08T13:12:10Z, first malicious publish
W_END = 1_757_345_400  # 2025-09-08T15:30:00Z
BEFORE = 1_756_000_000  # 2025-08-24, a routine bump
REINSTALL = W_START + 1_000  # inside the window
REMEDIATION = W_END + 5_000  # after it

RAW = {
    "incident": f"integration fixture {RUN}",
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
        {
            "package": LEFTPAD,
            "malicious_version": "1.3.1",
            "wave": 1,
            "published_at": "2025-09-08T13:12:10Z",
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
    """Three repositories, one of which is exposed for exactly 2 h 20 min."""
    inputs = [
        # Resolved the malicious build at 13:28, remediated at 16:53.
        repo(
            EXPOSED_SLUG,
            "checkout",
            [
                snapshot(0, BEFORE, **{CHALK: "5.6.0", DEBUG: "4.3.7"}),
                snapshot(1, REINSTALL, **{CHALK: "5.6.1", DEBUG: "4.4.2"}),
                snapshot(2, REMEDIATION, **{CHALK: "5.6.2", DEBUG: "4.3.7"}),
            ],
        ),
        # Held one patch below the malicious version across the whole window.
        repo(CLEAN_SLUG, "web", [snapshot(3, BEFORE, **{CHALK: "5.6.0"})]),
        # Never resolved either incident package at all.
        repo(ABSENT_SLUG, "storage", [snapshot(4, BEFORE, **{f"pg-{RUN}": "8.12.0"})]),
    ]
    overlay = {OWNER: [CHALK, DEBUG], NARROW: [DEBUG], BYSTANDER: [LEFTPAD]}
    rows = build_rowsets(inputs, schema=TEST_SCHEMA, maintainers=overlay)
    report = Ingestor(client, schema=TEST_SCHEMA, batch=500).run(
        rows, tx_from=REMEDIATION + 1
    )
    assert report.dry_run is False

    seed = _load_seeder()
    seed.write_provenance(
        client,
        # Explicitly this module's schema. Passing the seeder's default would
        # MERGE these ids into the demo namespace — labels do not isolate writes.
        TEST_SCHEMA,
        [
            {
                "id": repo_id(EXPOSED_SLUG),
                "provenance": "synthetic",
                "origin": seed.SYNTHETIC_ORIGIN,
                "synthetic": 1,
            },
            {
                "id": repo_id(CLEAN_SLUG),
                "provenance": "git-lockfile-history",
                "origin": "integration fixture",
                "synthetic": 0,
            },
        ],
        500,
    )
    return report


def _load_seeder():
    spec = importlib.util.spec_from_file_location(
        "demo_seed", ROOT / "scripts" / "demo-seed.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["demo_seed"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def console(client, seeded):
    return Console(client=client, schema=TEST_SCHEMA, incident=INCIDENT)


def mine(repos):
    """This run's repositories, keyed by slug — the label holds older runs too."""
    return {r["slug"]: r for r in repos if RUN in r["slug"]}


# ----------------------------------------------------------------- the engine


def test_every_console_query_is_one_the_engine_actually_accepts(console):
    """The whole read surface, executed for real. A 400 here is the point."""
    console.repositories(refresh=True)
    console.maintainers()
    console.exposure(CHALK, REINSTALL + 10)
    console.blast_radius(CHALK, REINSTALL + 10)
    console.maintainer_reach(OWNER, REINSTALL + 10)
    console.version_footprint(CHALK, "5.6.1", REINSTALL + 10)
    console.maintainer_ranking(REINSTALL + 10, limit=5)
    console.health()


def test_paging_continues_with_the_query_id_the_server_handed_back(client, seeded):
    """A cursor without its ``query_id`` is refused as belonging to another query."""
    cypher = (
        f"MATCH (r:{TEST_SCHEMA.repo} {{id: $rid}})"
        f"-[e:{TEST_SCHEMA.resolves}]->(v:{TEST_SCHEMA.version}) "
        "WHERE e.valid_from >= 0 RETURN v.pkg, v.version, e.valid_from, e.valid_to"
    )
    whole, truncated = fetch_all(client, cypher, {"rid": repo_id(EXPOSED_SLUG)})
    assert truncated is False
    # chalk 5.6.0/5.6.1/5.6.2 and debug 4.3.7/4.4.2/4.3.7 — six intervals, and
    # debug's two stints on 4.3.7 are two distinct edges because they are two
    # distinct facts about two distinct spans of time.
    assert len(whole) == 6

    paged, _ = fetch_all(client, cypher, {"rid": repo_id(EXPOSED_SLUG)}, page_size=1)
    assert sorted(map(str, paged)) == sorted(map(str, whole))


def test_row_cap_reports_truncation_rather_than_lying_by_omission(client, seeded):
    cypher = (
        f"MATCH (r:{TEST_SCHEMA.repo} {{id: $rid}})"
        f"-[e:{TEST_SCHEMA.resolves}]->(v:{TEST_SCHEMA.version}) "
        "WHERE e.valid_from >= 0 RETURN v.pkg, v.version"
    )
    rows, truncated = fetch_all(
        client, cypher, {"rid": repo_id(EXPOSED_SLUG)}, page_size=1, row_cap=2
    )
    assert truncated is True
    assert len(rows) == 2


# ---------------------------------------------------------------- the answers


def test_before_the_reinstall_nobody_is_exposed(console):
    result = console.exposure(CHALK, W_START + 10)
    repos = mine(result["repos"])
    assert result["package_in_graph"] is True
    assert {slug: r["status"] for slug, r in repos.items()} == {
        EXPOSED_SLUG: "RESOLVED_CLEAN",
        CLEAN_SLUG: "RESOLVED_CLEAN",
        ABSENT_SLUG: "NOT_RESOLVED",
    }


def test_inside_the_window_exactly_one_repository_is_exposed(console):
    result = console.exposure(CHALK, REINSTALL + 10)
    repos = mine(result["repos"])
    assert repos[EXPOSED_SLUG]["status"] == "EXPOSED"
    assert repos[EXPOSED_SLUG]["matched_versions"] == ["5.6.1"]
    assert repos[CLEAN_SLUG]["status"] == "RESOLVED_CLEAN"
    assert repos[ABSENT_SLUG]["status"] == "NOT_RESOLVED"
    assert result["evidence"] == "RESOLVED"
    assert result["in_exposure_window"] is True


def test_the_interval_is_half_open_at_both_ends(console):
    """At exactly the reinstall second the new pin holds; one second earlier it does not."""
    at_swap = mine(console.exposure(CHALK, REINSTALL)["repos"])[EXPOSED_SLUG]
    just_before = mine(console.exposure(CHALK, REINSTALL - 1)["repos"])[EXPOSED_SLUG]
    assert at_swap["status"] == "EXPOSED"
    assert just_before["status"] == "RESOLVED_CLEAN"

    at_fix = mine(console.exposure(CHALK, REMEDIATION)["repos"])[EXPOSED_SLUG]
    assert at_fix["status"] == "RESOLVED_CLEAN"
    assert at_fix["versions"][0]["version"] == "5.6.2"


def test_the_clean_repository_can_prove_its_negative_with_a_reason(console):
    verdict = mine(console.exposure(CHALK, REINSTALL + 10)["repos"])[CLEAN_SLUG]
    assert verdict["status"] == "RESOLVED_CLEAN"
    assert verdict["versions"][0]["version"] == "5.6.0"
    assert "across the entire" in verdict["basis"]
    assert "old when the first malicious version was published" in verdict["basis"]


def test_a_package_nobody_ever_resolved_has_no_node_at_all(console):
    result = console.exposure(LEFTPAD, REINSTALL + 10)
    assert result["package_in_graph"] is False
    assert result["counts"]["exposed"] == 0
    assert "real absence, not a lookup failure" in result["note"]


def test_a_malicious_version_nothing_resolved_has_no_node_either(console):
    absent = console.version_footprint(DEBUG, "4.4.9", REINSTALL + 10)
    assert absent["version_in_graph"] is False
    assert absent["repo_count"] == 0

    present = console.version_footprint(DEBUG, "4.4.2", REINSTALL + 10)
    assert present["version_in_graph"] is True
    assert present["repos"] == [EXPOSED_SLUG]


# ---------------------------------------------------------------- provenance


def test_the_synthetic_flag_survives_the_round_trip(console):
    records = {r.slug: r for r in console.repositories(refresh=True) if RUN in r.slug}
    assert records[EXPOSED_SLUG].synthetic is True
    assert records[EXPOSED_SLUG].provenance == "synthetic"
    assert "not a real repository" in records[EXPOSED_SLUG].origin
    assert records[CLEAN_SLUG].synthetic is False

    row = mine(console.exposure(CHALK, REINSTALL + 10)["repos"])[EXPOSED_SLUG]
    assert "not a real git history" in row["synthetic_note"]
    assert "synthetic_note" not in mine(
        console.exposure(CHALK, REINSTALL + 10)["repos"]
    )[CLEAN_SLUG]


# -------------------------------------------------------- graph and maintainers


def test_blast_radius_reaches_the_maintainer_from_the_repository(console):
    result = console.blast_radius(CHALK, REINSTALL + 10)
    assert EXPOSED_SLUG in result["exposed_repos"]
    assert OWNER in result["maintainers"]
    assert BYSTANDER not in result["maintainers"]

    ids = {n["id"] for n in result["nodes"]}
    assert f"ver:{CHALK}@5.6.1" in ids
    for edge in result["edges"]:
        assert edge["source"] in ids and edge["target"] in ids
    malicious = [
        e for e in result["edges"] if e["kind"] == "RESOLVES" and e["malicious"]
    ]
    assert malicious and all(e["valid_from"] == REINSTALL for e in malicious)


def test_maintainer_reach_counts_packages_owned_and_repositories_touched(console):
    reach = console.maintainer_reach(OWNER, REINSTALL + 10)
    assert reach["exists"] is True
    assert sorted(reach["maintains_packages"]) == sorted([CHALK, DEBUG])
    assert {r["slug"] for r in reach["reached_repos"]} == {EXPOSED_SLUG, CLEAN_SLUG}
    # Two packages in the exposed repo, one in the clean one.
    assert reach["repo_package_pairs"] == 3


def test_a_narrower_account_reaches_strictly_less(console):
    reach = console.maintainer_reach(NARROW, REINSTALL + 10)
    assert reach["exists"] is True
    assert reach["maintains_packages"] == [DEBUG]
    assert [r["slug"] for r in reach["reached_repos"]] == [EXPOSED_SLUG]
    assert reach["repo_package_pairs"] == 1


def test_an_account_whose_packages_nobody_resolves_reaches_nothing(console):
    """No MAINTAINS edge is written for a package the org never resolved.

    So the account is present as a node but invisible to every question the
    console asks, and it reports that as an absence rather than raising.
    """
    reach = console.maintainer_reach(BYSTANDER, REINSTALL + 10)
    assert reach["exists"] is False
    assert reach["maintains_package_count"] == 0
    assert reach["reached_repo_count"] == 0


def test_ranking_orders_the_three_accounts_by_what_they_actually_reach(console):
    ranked = console.maintainer_ranking(REINSTALL + 10, limit=400)
    order = [e["maintainer"] for e in ranked["ranking"]]
    assert order.index(OWNER) < order.index(NARROW) < order.index(BYSTANDER)
    owner = next(e for e in ranked["ranking"] if e["maintainer"] == OWNER)
    assert owner["reached_repo_count"] == 2
    assert owner["repo_package_pairs"] == 3
    assert ranked["ranking"][0]["rank"] == 1

    # And the second call for the same instant is served from the cache.
    again = console.maintainer_ranking(REINSTALL + 10, limit=400)
    assert again["cached"] is True
    assert [e["maintainer"] for e in again["ranking"]] == order


def test_health_finds_the_dataset_from_the_watermarks(console):
    health = console.health()
    assert health["reachable"] is True
    assert health["seeded"] is True
    assert health["labels"]["repo"] == "ReplayTestRepo"
    assert health["resolves_edges"] is None  # not counted unless asked for
    assert not set(health["unwatermarked_repos"]) & {
        EXPOSED_SLUG,
        CLEAN_SLUG,
        ABSENT_SLUG,
    }


def test_the_edge_count_is_available_when_a_caller_pays_for_it(console):
    health = console.health(count_edges=True)
    assert health["resolves_edges"] >= 6


# ------------------------------------------------------------------ over HTTP


def test_the_http_surface_answers_the_same_way_the_console_does(console):
    with TestClient(build_app(console)) as http:
        response = http.get(f"/api/exposure?package={CHALK}&at=2025-09-08T13:28:50Z")
        assert response.status_code == 200
        body = response.json()
        assert body["at"] == REINSTALL
        assert mine(body["repos"])[EXPOSED_SLUG]["status"] == "EXPOSED"

        graph = http.get(f"/api/blast-radius?package={CHALK}&at={REINSTALL}").json()
        assert OWNER in graph["maintainers"]

        reach = http.get(f"/api/maintainer-reach?name={OWNER}&at={REINSTALL}").json()
        assert reach["reached_repo_count"] == 2


# ------------------------------------------------------------------ truncation


@pytest.fixture(scope="module")
def capped(client, seeded):
    """A console whose RESOLVES traversals are cut off after one row.

    Only the traversals, so the repository directory stays whole and the
    truncation under test is the interesting one — the answer still names every
    repository, it just cannot vouch for what they resolved. One row is a
    genuinely partial answer here: at the reinstall, two repositories resolve
    this package. And it is the real engine and the real cursor protocol that
    produce the flag, not a fake that was told to say so.
    """

    def clipped(hydra, cypher, parameters=None, **kw):
        if TEST_SCHEMA.resolves in cypher:
            kw.update(page_size=1, row_cap=1)
        return fetch_all(hydra, cypher, parameters, **kw)

    return Console(
        client=client, schema=TEST_SCHEMA, incident=INCIDENT, reader=clipped
    )


def test_a_real_truncated_read_is_labelled_all_the_way_out(capped):
    result = capped.exposure(CHALK, REINSTALL + 10)
    assert result["truncated"] is True
    assert "lower bound" in result["truncation_note"]
    # The directory read was not capped, so every repository is still named —
    # what is missing is the evidence about them, which is exactly the case
    # where a bare count would be most misleading.
    assert len(mine(result["repos"])) == 3


def test_a_truncated_read_never_claims_a_proven_negative(capped, console):
    """The claim that would be actively dangerous on a security console."""
    complete = console.exposure(CHALK, REINSTALL + 10)
    partial = capped.exposure(CHALK, REINSTALL + 10)
    assert complete["truncated"] is False
    assert complete["counts"]["exposed"] == 1
    # Same instant, same question, fewer rows: the counts may disagree, and only
    # the complete one is allowed to be read as a total.
    assert partial["counts"]["exposed"] <= complete["counts"]["exposed"]
    assert partial["truncation_note"]


def test_an_empty_result_is_a_proven_negative_only_because_nothing_was_cut(
    capped, console
):
    """A cap that did not bite must not raise a false alarm either."""
    before_anything = BEFORE - 1_000
    for view in (console, capped):
        result = view.exposure(CHALK, before_anything)
        assert result["counts"]["exposed"] == 0
        assert result["truncated"] is False
        assert "proven negative" in result["note"]


def test_truncation_survives_the_blast_radius(capped):
    result = capped.blast_radius(CHALK, REINSTALL + 10)
    assert result["truncated"] is True
    assert result["truncation_note"]


def test_a_footprint_the_cap_did_not_reach_is_not_flagged(capped):
    """Only one repository ever held this version, so one row is the whole answer."""
    footprint = capped.version_footprint(CHALK, "5.6.1", REINSTALL + 10)
    assert footprint["version_in_graph"] is True
    assert footprint["truncated"] is False
    assert footprint["repo_count_is_lower_bound"] is False


def test_truncation_reaches_the_browser_over_http(capped):
    with TestClient(build_app(capped)) as http:
        body = http.get(f"/api/exposure?package={CHALK}&at={REINSTALL}").json()
    assert body["truncated"] is True
    assert body["truncation_note"]
    assert body["repos"], "a partial answer is still an answer, just a labelled one"
