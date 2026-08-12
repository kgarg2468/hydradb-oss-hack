"""Interval construction from a real git history.

The fixture is a genuine repository built in a tmpdir rather than a stubbed
`git log`, because every bug this code has had came from git's behaviour
(rename following, commits that touch one lockfile but not another, blobs that
will not parse) and none of them would survive a mock.
"""

import json
import subprocess

import pytest

from hindsight.history import (
    SENTINEL,
    build_intervals,
    discover_lockfiles,
    extract_snapshots,
    load_history,
)

T0, T1, T2 = 1_700_000_000, 1_700_086_400, 1_700_172_800


def lock(**deps):
    packages = {"": {"name": "fixture", "version": "1.0.0"}}
    for name, version in deps.items():
        packages[f"node_modules/{name}"] = {
            "version": version,
            "resolved": f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz",
        }
    return json.dumps({"name": "fixture", "lockfileVersion": 3, "packages": packages}, indent=2)


def run(repo, *args, ts=None):
    env = {"PATH": "/usr/bin:/bin:/usr/local/bin", "HOME": str(repo)}
    if ts is not None:
        stamp = f"{ts} +0000"
        env["GIT_AUTHOR_DATE"] = stamp
        env["GIT_COMMITTER_DATE"] = stamp
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, env=env
    )
    assert proc.returncode == 0, f"git {args[0]} failed: {proc.stderr}"
    return proc.stdout


def commit(repo, message, ts):
    run(repo, "add", "-A")
    run(
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


@pytest.fixture
def repo(tmp_path):
    """Three lockfile commits: chalk 5.0.0 -> 5.3.0, and debug added then dropped."""
    path = tmp_path / "fixture-repo"
    path.mkdir()
    run(path, "init", "-q", "-b", "main")

    (path / "package-lock.json").write_text(lock(chalk="5.0.0", debug="4.3.4"))
    commit(path, "initial lockfile", T0)

    (path / "package-lock.json").write_text(lock(chalk="5.3.0", debug="4.3.4"))
    commit(path, "bump chalk", T1)

    (path / "package-lock.json").write_text(lock(chalk="5.3.0"))
    commit(path, "drop debug", T2)
    return path


def as_tuples(intervals):
    return {(iv.package, iv.version, iv.valid_from, iv.valid_to) for iv in intervals}


def test_discover_finds_the_lockfile(repo):
    assert discover_lockfiles(repo) == ["package-lock.json"]


def test_three_commits_produce_three_snapshots(repo):
    snapshots, errors, skipped = extract_snapshots(repo)
    assert errors == []
    assert skipped == []
    assert [s.ts for s in snapshots] == [T0, T1, T2]
    assert snapshots[0].entries == frozenset({("chalk", "5.0.0"), ("debug", "4.3.4")})
    assert snapshots[2].entries == frozenset({("chalk", "5.3.0")})


def test_intervals_are_half_open_and_close_on_change(repo):
    history = load_history(repo, slug="acme/fixture")
    assert as_tuples(history.intervals) == {
        # replaced at T1, so it is true over [T0, T1)
        ("chalk", "5.0.0", T0, T1),
        # still true at HEAD -> sentinel, because HydraDB has no IS NULL
        ("chalk", "5.3.0", T1, SENTINEL),
        # survived the chalk bump, removed at T2
        ("debug", "4.3.4", T0, T2),
    }


def test_intervals_partition_the_timeline_without_overlap(repo):
    history = load_history(repo, slug="acme/fixture")
    chalk = sorted(
        (iv for iv in history.intervals if iv.package == "chalk"),
        key=lambda iv: iv.valid_from,
    )
    assert chalk[0].valid_to == chalk[1].valid_from  # no gap, no double-count
    assert chalk[1].is_open


def test_since_window_trims_the_walk(repo):
    # 1_700_086_400 is 2023-11-16T00:00:00Z; ask for commits after it.
    history = load_history(repo, slug="acme/fixture", since="2023-11-16T12:00:00")
    assert [s.ts for s in history.snapshots] == [T2]
    assert as_tuples(history.intervals) == {("chalk", "5.3.0", T2, SENTINEL)}


def test_a_second_lockfile_is_resolved_at_commits_that_did_not_touch_it(repo):
    """A commit editing app/ must not look like it deleted everything in api/."""
    (repo / "api").mkdir()
    (repo / "api" / "package-lock.json").write_text(lock(express="4.19.2"))
    commit(repo, "add api lockfile", T2 + 100)
    (repo / "package-lock.json").write_text(lock(chalk="5.4.0"))
    commit(repo, "bump chalk again, api untouched", T2 + 200)

    history = load_history(repo, slug="acme/fixture")
    express = [iv for iv in history.intervals if iv.package == "express"]
    assert len(express) == 1
    assert express[0].valid_from == T2 + 100
    assert express[0].valid_to == SENTINEL  # still present, not dropped


def test_rename_is_followed_rather_than_read_as_a_deletion(repo):
    """Storybook moved code/yarn.lock to the root; that must not break an interval."""
    (repo / "frontend").mkdir()
    run(repo, "mv", "package-lock.json", "frontend/package-lock.json")
    commit(repo, "move the lockfile into frontend/", T2 + 50)

    history = load_history(repo, slug="acme/fixture")
    assert history.lockfiles == ["frontend/package-lock.json", "package-lock.json"]
    chalk = [iv for iv in history.intervals if iv.version == "5.3.0"]
    # One unbroken interval starting at the bump, not one per path.
    assert len(chalk) == 1
    assert chalk[0].valid_from == T1
    assert chalk[0].valid_to == SENTINEL


def test_empty_history_is_reported_not_raised(tmp_path):
    path = tmp_path / "bare"
    path.mkdir()
    run(path, "init", "-q", "-b", "main")
    history = load_history(path, slug="acme/empty")
    assert history.snapshots == []
    assert history.intervals == []
    assert history.errors


def test_unparseable_lockfile_does_not_close_intervals(repo):
    """A commit whose lockfile will not parse must not read as a deletion.

    Emitting the readable part of such a commit would close every interval it
    could not see and reopen it at the next good commit — a fabricated gap in
    the middle of the timeline, which is exactly the sort of thing an AS-OF
    audit would then report as "this dependency was absent that week".
    """
    (repo / "package-lock.json").write_text('{"lockfileVersion": 3, "packa')  # truncated
    commit(repo, "corrupt lockfile lands in history", T2 + 100)
    (repo / "package-lock.json").write_text(lock(chalk="5.3.0"))
    commit(repo, "back to normal", T2 + 200)

    snapshots, errors, skipped = extract_snapshots(repo)
    assert len(skipped) == 1
    assert any("did not parse" in note for note in errors)
    assert [s.ts for s in snapshots] == [T0, T1, T2, T2 + 200]

    intervals = as_tuples(build_intervals(snapshots))
    # One unbroken interval to the sentinel, not [T1, T2+100) plus [T2+200, ...).
    assert ("chalk", "5.3.0", T1, SENTINEL) in intervals
    assert not any(iv[1] == "5.3.0" and iv[3] != SENTINEL for iv in intervals)


def test_a_skipped_commit_is_reported_on_the_history(repo):
    (repo / "package-lock.json").write_text("not json at all")
    commit(repo, "corrupt", T2 + 100)

    history = load_history(repo, slug="acme/fixture")
    assert len(history.skipped_commits) == 1
    assert history.skipped_commits[0] == run(repo, "rev-parse", "HEAD").strip()
    # The dependency dropped at T2 stays dropped; nothing else is disturbed.
    assert as_tuples(history.intervals) == {
        ("chalk", "5.0.0", T0, T1),
        ("chalk", "5.3.0", T1, SENTINEL),
        ("debug", "4.3.4", T0, T2),
    }


def test_a_corrupt_second_lockfile_does_not_publish_the_readable_one(repo):
    """Partial visibility is worse than none: skip the whole commit."""
    (repo / "api").mkdir()
    (repo / "api" / "package-lock.json").write_text(lock(express="4.19.2"))
    commit(repo, "add api lockfile", T2 + 100)
    (repo / "api" / "package-lock.json").write_text("{{{ truncated")
    commit(repo, "corrupt only the api lockfile", T2 + 200)

    history = load_history(repo, slug="acme/fixture")
    assert len(history.skipped_commits) == 1
    express = [iv for iv in history.intervals if iv.package == "express"]
    assert len(express) == 1
    assert express[0].valid_to == SENTINEL  # not closed by the corrupt commit


def test_build_intervals_is_pure_and_order_independent(repo):
    snapshots, _, _ = extract_snapshots(repo)
    forward = as_tuples(build_intervals(snapshots))
    shuffled = as_tuples(build_intervals(list(reversed(snapshots))))
    assert forward == shuffled
