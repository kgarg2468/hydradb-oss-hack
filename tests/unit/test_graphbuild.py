"""Rowset construction: shapes, deduplication, watermark filtering."""

import pytest

from hindsight.graphbuild import (
    DEFAULT_SCHEMA,
    TEST_SCHEMA,
    RepoInput,
    Schema,
    build_rowsets,
    filter_by_watermark,
    stale_repos,
    stamp_tx,
)
from hindsight.history import SENTINEL, Interval
from hindsight.ids import IdRegistry, edge_id, package_id, repo_id, version_id


def repo(slug, intervals, service=""):
    return RepoInput(
        slug=slug,
        name=slug,
        service=service,
        intervals=tuple(intervals),
        first_ts=100,
        last_ts=900,
        snapshots=len(intervals),
    )


WEB = repo(
    "acme/web",
    [
        Interval("chalk", "5.0.0", 100, 500),
        Interval("chalk", "5.3.0", 500, SENTINEL),
        Interval("debug", "4.3.4", 100, SENTINEL),
    ],
    service="storefront",
)
API = repo(
    "acme/api",
    [
        Interval("chalk", "5.3.0", 300, SENTINEL),
        Interval("express", "4.19.2", 300, SENTINEL),
    ],
    service="orders",
)


def by_id(rows):
    return {row["id"]: row for row in rows}


def test_node_rows_carry_the_documented_shape():
    rows = build_rowsets([WEB])
    (r,) = rows.repos
    assert r == {
        "id": repo_id("acme/web"),
        "slug": "acme/web",
        "name": "acme/web",
        "service": "storefront",
        "first_ts": 100,
        "last_ts": 900,
        "snapshots": 3,
    }
    version = by_id(rows.versions)[version_id("chalk", "5.3.0")]
    assert version["key"] == "chalk@5.3.0"
    assert version["pkg_id"] == package_id("chalk")


def test_packages_and_versions_are_shared_across_repos():
    rows = build_rowsets([WEB, API])
    assert {p["name"] for p in rows.packages} == {"chalk", "debug", "express"}
    assert len(rows.packages) == 3
    # chalk@5.3.0 is resolved by both repos but is one node with one VERSION_OF.
    assert len(rows.versions) == 4
    assert len(rows.version_of) == 4
    assert len(rows.resolves) == 5


def test_resolves_edges_point_repo_to_version_and_keep_the_interval():
    rows = build_rowsets([WEB])
    edge = by_id(rows.resolves)[
        edge_id(DEFAULT_SCHEMA.resolves, repo_id("acme/web"), version_id("chalk", "5.0.0"), 100)
    ]
    assert edge["s"] == repo_id("acme/web")
    assert edge["d"] == version_id("chalk", "5.0.0")
    assert (edge["vf"], edge["vt"]) == (100, 500)


def test_build_is_byte_for_byte_repeatable():
    assert build_rowsets([WEB, API]).summary() == build_rowsets([API, WEB]).summary()
    first = sorted(r["id"] for r in build_rowsets([WEB, API]).resolves)
    second = sorted(r["id"] for r in build_rowsets([API, WEB]).resolves)
    assert first == second


def test_schema_changes_edge_ids_so_datasets_cannot_collide():
    prod = build_rowsets([WEB], schema=DEFAULT_SCHEMA)
    test = build_rowsets([WEB], schema=TEST_SCHEMA)
    assert {r["id"] for r in prod.resolves}.isdisjoint({r["id"] for r in test.resolves})
    # ...but the nodes are shared identity, so those ids do match.
    assert {r["id"] for r in prod.versions} == {r["id"] for r in test.versions}


def test_schema_prefixed_builds_both_namespaces():
    schema = Schema.prefixed("IngTest", "INGTEST")
    assert schema == TEST_SCHEMA
    assert schema.repo == "IngTestRepo"
    assert schema.version == "IngTestVer"
    assert schema.package == "IngTestPkg"
    assert schema.resolves == "INGTEST_RESOLVES"


def test_maintainer_overlay_only_links_packages_the_org_resolved():
    rows = build_rowsets([WEB], maintainers={"qix": ["chalk", "never-installed"]})
    assert [m["name"] for m in rows.maintainers] == ["qix"]
    assert len(rows.maintains) == 1
    assert rows.maintains[0]["d"] == package_id("chalk")


def test_summary_counts_match_the_rowsets():
    rows = build_rowsets([WEB, API])
    summary = rows.summary()
    assert summary["nodes"] == rows.node_count == len(rows.repos) + len(rows.packages) + len(
        rows.versions
    )
    assert summary["edges"] == rows.edge_count == len(rows.resolves) + len(rows.version_of)


def test_watermark_drops_only_intervals_that_can_never_change():
    rows = build_rowsets([WEB])
    mark = {repo_id("acme/web"): 500}
    kept, skipped = filter_by_watermark(rows.resolves, mark)
    # chalk@5.0.0 closed exactly at the watermark: settled, never resend.
    assert skipped == 1
    # The two still-open intervals must be resent; the next run may close them.
    assert {row["vt"] for row in kept} == {SENTINEL}


def test_watermark_absent_for_a_repo_keeps_everything():
    rows = build_rowsets([WEB, API])
    kept, skipped = filter_by_watermark(rows.resolves, {repo_id("acme/api"): 10**12})
    assert skipped == 2  # both of api's intervals are below its watermark
    assert {row["s"] for row in kept} == {repo_id("acme/web")}


def test_stale_repos_are_those_behind_the_stored_watermark():
    horizons = {repo_id("acme/web"): 900, repo_id("acme/api"): 900}
    marks = {repo_id("acme/web"): 5000, repo_id("acme/api"): 100}
    assert stale_repos(horizons, marks) == {repo_id("acme/web")}


def test_a_repo_level_with_its_watermark_is_not_stale():
    rid = repo_id("acme/web")
    assert stale_repos({rid: 900}, {rid: 900}) == set()


def test_a_repo_with_no_watermark_is_never_stale():
    assert stale_repos({repo_id("acme/web"): 0}, {}) == set()


def test_no_watermarks_is_a_pass_through():
    rows = build_rowsets([WEB])
    kept, skipped = filter_by_watermark(rows.resolves, {})
    assert skipped == 0
    assert kept is rows.resolves


def test_stamp_tx_adds_transaction_time_to_every_edge():
    rows = build_rowsets([WEB])
    stamp_tx(rows.resolves, tx_from=1234)
    assert all(row["txf"] == 1234 and row["txt"] == SENTINEL for row in rows.resolves)


def test_registry_is_shared_so_collisions_surface_before_any_write():
    reg = IdRegistry()
    build_rowsets([WEB, API], registry=reg)
    # repos + packages + versions + resolves + version_of, all minted once.
    assert len(reg) == 2 + 3 + 4 + 5 + 4


def test_repo_bookkeeping_is_exposed_for_watermark_writes():
    rows = build_rowsets([WEB, API])
    assert rows.repo_slugs == {repo_id("acme/web"): "acme/web", repo_id("acme/api"): "acme/api"}
    assert rows.repo_last_ts[repo_id("acme/web")] == 900


@pytest.mark.parametrize("intervals", [[], [Interval("a", "1", 0, SENTINEL)]])
def test_empty_and_minimal_repos_do_not_blow_up(intervals):
    rows = build_rowsets([repo("acme/tiny", intervals)])
    assert len(rows.repos) == 1
    assert len(rows.resolves) == len(intervals)
