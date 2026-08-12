"""End-to-end ingest against a real HydraDB node.

A three-commit fixture repository is built in a tmpdir, walked by the real git
extractor, turned into rowsets and written through the real batched writer, and
then interrogated with AS-OF queries. The run is then repeated verbatim to prove
idempotency: byte-identical inputs must leave the edge count unchanged.

Isolation is by label, not by cleanup. HydraDB deletes at roughly 3 nodes/sec
against 17k inserts/sec and `MATCH (n:L) DETACH DELETE n` exceeds a hard 30 s
server cap, so the graph is treated as append-only and every test writes under
`IngTest*` / `INGTEST_*`. Each run also uses a unique slug, so reruns cannot
collide with each other's ids.
"""

import json
import secrets
import subprocess

import pytest

from hindsight.client import HydraClient
from hindsight.graphbuild import TEST_SCHEMA, RepoInput, build_rowsets
from hindsight.history import SENTINEL, load_history
from hindsight.ids import repo_id, watermark_id
from hindsight.ingest import Ingestor

pytestmark = pytest.mark.integration

T0, T1, T2 = 1_700_000_000, 1_700_086_400, 1_700_172_800
RUN = secrets.token_hex(6)
SLUG = f"ingtest/{RUN}"


def lockfile(**deps):
    packages = {"": {"name": "fixture", "version": "1.0.0"}}
    for name, version in deps.items():
        packages[f"node_modules/{name}"] = {
            "version": version,
            "resolved": f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz",
        }
    return json.dumps({"lockfileVersion": 3, "packages": packages})


def git(repo, *args, ts=None):
    env = {"PATH": "/usr/bin:/bin:/usr/local/bin", "HOME": str(repo)}
    if ts is not None:
        env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = f"{ts} +0000"
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, env=env
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def commit(repo, message, ts):
    git(repo, "add", "-A")
    git(
        repo,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "-q",
        "-m",
        message,
        ts=ts,
    )


@pytest.fixture(scope="module")
def fixture_repo(tmp_path_factory):
    path = tmp_path_factory.mktemp("ingtest-repo")
    git(path, "init", "-q", "-b", "main")
    # Package names are run-scoped so parallel/repeat runs share no version ids.
    (path / "package-lock.json").write_text(
        lockfile(**{f"chalk-{RUN}": "5.0.0", f"debug-{RUN}": "4.3.4"})
    )
    commit(path, "initial", T0)
    (path / "package-lock.json").write_text(
        lockfile(**{f"chalk-{RUN}": "5.3.0", f"debug-{RUN}": "4.3.4"})
    )
    commit(path, "bump chalk", T1)
    (path / "package-lock.json").write_text(lockfile(**{f"chalk-{RUN}": "5.3.0"}))
    commit(path, "drop debug", T2)
    return path


@pytest.fixture(scope="module")
def rowsets(fixture_repo):
    history = load_history(fixture_repo, slug=SLUG)
    assert len(history.snapshots) == 3
    return build_rowsets(
        [RepoInput.from_history(history, service="ingest-test")], schema=TEST_SCHEMA
    )


@pytest.fixture(scope="module")
def ingestor():
    client = HydraClient.from_env()
    if not client.ping():
        pytest.skip("no HydraDB node reachable")
    return Ingestor(client, schema=TEST_SCHEMA, batch=500)


@pytest.fixture(scope="module")
def first_run(ingestor, rowsets):
    return ingestor.run(rowsets, tx_from=T2 + 1)


def test_first_run_writes_the_expected_shape(first_run):
    assert first_run.dry_run is False
    # 1 repo + 2 packages + 3 versions
    assert first_run.nodes_written == 6
    # 3 VERSION_OF + 3 RESOLVES
    assert first_run.edges_written == 6
    assert first_run.skipped_resolves == 0


def test_as_of_before_the_bump_sees_the_old_version(ingestor, first_run):
    assert ingestor.resolved_as_of(repo_id(SLUG), T0 + 10) == {
        f"chalk-{RUN}@5.0.0",
        f"debug-{RUN}@4.3.4",
    }


def test_as_of_after_the_bump_sees_the_new_version(ingestor, first_run):
    assert ingestor.resolved_as_of(repo_id(SLUG), T1 + 10) == {
        f"chalk-{RUN}@5.3.0",
        f"debug-{RUN}@4.3.4",
    }


def test_as_of_after_the_drop_no_longer_sees_the_removed_package(ingestor, first_run):
    assert ingestor.resolved_as_of(repo_id(SLUG), T2 + 10) == {f"chalk-{RUN}@5.3.0"}


def test_as_of_boundary_is_half_open(ingestor, first_run):
    # valid_from inclusive, valid_to exclusive: at exactly T1 only 5.3.0 holds.
    assert ingestor.resolved_as_of(repo_id(SLUG), T1) == {
        f"chalk-{RUN}@5.3.0",
        f"debug-{RUN}@4.3.4",
    }


def test_as_of_before_the_repo_existed_is_empty(ingestor, first_run):
    assert ingestor.resolved_as_of(repo_id(SLUG), T0 - 1) == set()


def test_open_intervals_survive_to_the_sentinel(ingestor, first_run):
    assert ingestor.resolved_as_of(repo_id(SLUG), SENTINEL - 1) == {f"chalk-{RUN}@5.3.0"}


def test_watermark_records_the_newest_commit(ingestor, first_run):
    rows = ingestor.client.rows(
        f"MATCH (n:{TEST_SCHEMA.watermark} {{id: $id}}) RETURN n.last_commit_ts, n.slug",
        {"id": watermark_id(SLUG)},
    )
    assert rows and rows[0][0] == T2
    assert rows[0][1] == SLUG


def _edge_count(ingestor):
    return int(
        ingestor.client.scalar(
            f"MATCH (r:{TEST_SCHEMA.repo} {{id: $rid}})"
            f"-[e:{TEST_SCHEMA.resolves}]->(v:{TEST_SCHEMA.version}) "
            "WHERE e.valid_from >= 0 RETURN count(*)",
            {"rid": repo_id(SLUG)},
            default=0,
        )
        or 0
    )


def test_rerun_is_idempotent(ingestor, rowsets, first_run):
    before = _edge_count(ingestor)
    assert before == 3

    second = ingestor.run(rowsets, tx_from=T2 + 2)
    # Both intervals that had already closed by the watermark (T2) are settled
    # and skipped; only the one still open at T2 is resent, and it MERGEs onto
    # the edge already there rather than adding a second one.
    assert second.skipped_resolves == 2
    assert _edge_count(ingestor) == before

    # A third run changes nothing either, and every AS-OF answer is unchanged.
    ingestor.run(rowsets, tx_from=T2 + 3)
    assert _edge_count(ingestor) == before
    assert ingestor.resolved_as_of(repo_id(SLUG), T0 + 10) == {
        f"chalk-{RUN}@5.0.0",
        f"debug-{RUN}@4.3.4",
    }
    assert ingestor.resolved_as_of(repo_id(SLUG), T2 + 10) == {f"chalk-{RUN}@5.3.0"}


def test_a_new_commit_closes_the_open_interval_in_place(
    ingestor, fixture_repo, rowsets, first_run
):
    """The hard case: an interval that was open must not become a second edge."""
    (fixture_repo / "package-lock.json").write_text(lockfile(**{f"chalk-{RUN}": "5.4.0"}))
    commit(fixture_repo, "bump chalk again", T2 + 1000)

    history = load_history(fixture_repo, slug=SLUG)
    later = build_rowsets(
        [RepoInput.from_history(history, service="ingest-test")], schema=TEST_SCHEMA
    )
    report = ingestor.run(later, tx_from=T2 + 2000)
    assert report.skipped_resolves == 2  # chalk@5.0.0 and debug@4.3.4, both settled

    # 3 original edges + 1 for chalk@5.4.0, not 5: chalk@5.3.0 was revised.
    assert _edge_count(ingestor) == 4
    assert ingestor.resolved_as_of(repo_id(SLUG), T2 + 10) == {f"chalk-{RUN}@5.3.0"}
    assert ingestor.resolved_as_of(repo_id(SLUG), T2 + 2000) == {f"chalk-{RUN}@5.4.0"}
