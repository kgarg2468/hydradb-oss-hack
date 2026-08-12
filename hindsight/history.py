"""Git lockfile history -> snapshots -> half-open validity intervals.

The valid-time axis of the graph comes from git: a repo's committed lockfile is
taken to describe the truth from the commit that wrote it until the commit that
changed it. So the extraction is

    for each lockfile, walk ``git log --follow`` ->
    resolve every lockfile's blob at every one of those commits ->
    parse -> a per-commit snapshot of the whole resolved closure ->
    diff consecutive snapshots -> intervals [valid_from, valid_to)

Two details that the PoC learned the hard way:

* **All lockfiles are resolved at every commit**, not just the one the commit
  touched. Otherwise a commit that edits ``a/yarn.lock`` would look like it
  deleted every dependency recorded in ``b/yarn.lock``.
* **Renames are followed and unioned.** Storybook moved ``code/yarn.lock`` to
  the repo root and left a 312-byte workspace stub behind; picking "the first
  candidate path that exists" silently produced empty snapshots. Taking the
  union of everything resolvable at a commit is both simpler and correct for
  monorepos with genuinely separate lockfiles.

Blob reads go through a single batched ``git cat-file`` pass per repository,
and object resolution through a single ``--batch-check`` pass, because the
naive form is one subprocess per (commit x candidate path) and that dominates
the runtime on repos with thousands of lockfile commits.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .lockparse import parse_lockfile

# 2100-01-01T00:00:00Z. HydraDB has no IS NULL, so an interval that is still
# open needs a sentinel upper bound rather than a missing property.
SENTINEL = 4102444800

LOCKFILE_NAMES = ("package-lock.json", "yarn.lock")

# A blobless partial clone plus concurrent lazy fetches trips git's commit-graph
# consistency check, which aborts the fetch. Disabling the reader avoids it.
GIT_OPTS = ("-c", "core.commitGraph=false", "-c", "fetch.writeCommitGraph=false")

_SHA_TS = re.compile(r"^([0-9a-f]{40}) (\d+)$")


class GitError(Exception):
    """A git invocation failed."""


@dataclass(frozen=True)
class Snapshot:
    """The full resolved closure of a repo at one commit."""

    commit: str
    ts: int
    paths: tuple[str, ...]
    entries: frozenset[tuple[str, str]]


@dataclass(frozen=True)
class Interval:
    """A (package, version) fact that held over the half-open [from, to)."""

    package: str
    version: str
    valid_from: int
    valid_to: int

    @property
    def is_open(self) -> bool:
        return self.valid_to == SENTINEL


@dataclass
class RepoHistory:
    slug: str
    snapshots: list[Snapshot] = field(default_factory=list)
    intervals: list[Interval] = field(default_factory=list)
    lockfiles: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def first_ts(self) -> int:
        return self.snapshots[0].ts if self.snapshots else 0

    @property
    def last_ts(self) -> int:
        return self.snapshots[-1].ts if self.snapshots else 0


def git(repo: str | Path, *args: str, check: bool = True) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *GIT_OPTS, *args],
        capture_output=True,
        text=True,
    )
    if check and proc.returncode != 0:
        raise GitError(f"git {' '.join(args[:3])} failed in {repo}: {proc.stderr.strip()[:300]}")
    return proc.stdout


def discover_lockfiles(repo: str | Path) -> list[str]:
    """Lockfile paths tracked at HEAD, shallowest first."""
    out = git(repo, "ls-files", "--", *[f"*{n}" for n in LOCKFILE_NAMES])
    paths = [p for p in out.splitlines() if p.rsplit("/", 1)[-1] in LOCKFILE_NAMES]
    return sorted(paths, key=lambda p: (p.count("/"), p))


def follow_path(
    repo: str | Path,
    path: str,
    since: str | None = None,
    until: str | None = None,
) -> tuple[dict[str, int], set[str]]:
    """Commits touching ``path`` (renames followed) plus every name it ever had.

    Returns ``({commit_sha: unix_ts}, {path, ...})``.
    """
    args = ["log", "--follow", "--format=%H %ct", "--name-only"]
    if since:
        args.append(f"--since={since}")
    if until:
        args.append(f"--until={until}")
    args += ["--", path]
    commits: dict[str, int] = {}
    names: set[str] = {path}
    current: str | None = None
    for line in git(repo, *args).splitlines():
        line = line.rstrip()
        if not line:
            continue
        m = _SHA_TS.match(line)
        if m:
            current = m.group(1)
            commits[current] = int(m.group(2))
            continue
        if current is not None:
            names.add(line)
    return commits, names


def _batch_check(repo: str | Path, specs: list[str]) -> dict[str, str]:
    """Resolve ``<sha>:<path>`` revisions to blob oids in one git pass."""
    if not specs:
        return {}
    proc = subprocess.run(
        ["git", "-C", str(repo), *GIT_OPTS, "cat-file", "--batch-check"],
        input="\n".join(specs) + "\n",
        capture_output=True,
        text=True,
    )
    resolved: dict[str, str] = {}
    for spec, line in zip(specs, proc.stdout.splitlines(), strict=False):
        parts = line.split()
        if len(parts) == 3 and parts[1] == "blob":
            resolved[spec] = parts[0]
    return resolved


def _batch_blobs(repo: str | Path, oids: list[str], chunk: int = 64) -> dict[str, bytes]:
    """Read blob contents in batched ``git cat-file --batch`` passes.

    Chunked so that one unreadable object (a blobless clone whose lazy fetch
    fails) costs a chunk rather than the whole repo, with a per-object retry.
    """
    blobs: dict[str, bytes] = {}
    for start in range(0, len(oids), chunk):
        batch = oids[start : start + chunk]
        proc = subprocess.Popen(
            ["git", "-C", str(repo), *GIT_OPTS, "cat-file", "--batch"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        try:
            proc.stdin.write(("\n".join(batch) + "\n").encode())
            proc.stdin.close()
            for oid in batch:
                header = proc.stdout.readline().decode().split()
                if len(header) != 3:
                    raise OSError(f"cat-file stream desync at {oid}")
                size = int(header[2])
                blobs[oid] = proc.stdout.read(size)
                proc.stdout.read(1)  # trailing newline
        except OSError:
            proc.kill()
            for oid in batch:
                if oid in blobs:
                    continue
                one = subprocess.run(
                    ["git", "-C", str(repo), *GIT_OPTS, "cat-file", "blob", oid],
                    capture_output=True,
                )
                if one.returncode == 0:
                    blobs[oid] = one.stdout
        finally:
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
    return blobs


def extract_snapshots(
    repo: str | Path,
    lockfiles: list[str] | None = None,
    since: str | None = None,
    until: str | None = None,
) -> tuple[list[Snapshot], list[str]]:
    """One snapshot per commit that touched any lockfile, oldest first.

    Returns ``(snapshots, errors)``; ``errors`` holds human-readable notes about
    blobs that would not parse, which happens in real history.
    """
    lockfiles = lockfiles or discover_lockfiles(repo)
    errors: list[str] = []
    if not lockfiles:
        return [], ["no lockfiles found"]

    commit_ts: dict[str, int] = {}
    aliases: list[set[str]] = []
    for path in lockfiles:
        commits, names = follow_path(repo, path, since, until)
        commit_ts.update(commits)
        aliases.append(names)

    if not commit_ts:
        return [], ["no commits touch any lockfile in the requested window"]

    order = sorted(commit_ts, key=lambda sha: (commit_ts[sha], sha))

    # One --batch-check pass resolves every (commit, candidate path) at once.
    every_name = sorted({n for group in aliases for n in group})
    specs = [f"{sha}:{name}" for sha in order for name in every_name]
    resolved = _batch_check(repo, specs)

    unique_oids = list(dict.fromkeys(resolved.values()))
    blobs = _batch_blobs(repo, unique_oids)

    parsed: dict[str, frozenset[tuple[str, str]]] = {}
    snapshots: list[Snapshot] = []
    for sha in order:
        entries: set[tuple[str, str]] = set()
        used: list[str] = []
        for name in every_name:
            oid = resolved.get(f"{sha}:{name}")
            if oid is None:
                continue
            if oid not in parsed:
                raw = blobs.get(oid)
                if raw is None:
                    errors.append(f"{sha[:8]} {name}: blob unreadable")
                    parsed[oid] = frozenset()
                else:
                    try:
                        parsed[oid] = frozenset(
                            parse_lockfile(name, raw.decode("utf-8", "replace"))
                        )
                    except (ValueError, KeyError) as exc:
                        errors.append(f"{sha[:8]} {name}: parse failed: {exc}")
                        parsed[oid] = frozenset()
            if parsed[oid]:
                entries |= parsed[oid]
                used.append(name)
        if entries:
            snapshots.append(
                Snapshot(
                    commit=sha,
                    ts=commit_ts[sha],
                    paths=tuple(used),
                    entries=frozenset(entries),
                )
            )
    return snapshots, errors


def build_intervals(snapshots: list[Snapshot]) -> list[Interval]:
    """Diff consecutive snapshots into half-open [valid_from, valid_to) facts.

    ``valid_from`` is inclusive, ``valid_to`` exclusive, so an AS-OF query at
    exactly the commit timestamp that swapped a version sees only the new one.
    An entry present in the newest snapshot is still true, and gets
    ``valid_to = SENTINEL``.
    """
    ordered = sorted(snapshots, key=lambda s: (s.ts, s.commit))
    out: list[Interval] = []
    open_at: dict[tuple[str, str], int] = {}
    for snap in ordered:
        current = snap.entries
        for key in [k for k in open_at if k not in current]:
            out.append(Interval(key[0], key[1], open_at.pop(key), snap.ts))
        for key in current:
            open_at.setdefault(key, snap.ts)
    for key, valid_from in open_at.items():
        out.append(Interval(key[0], key[1], valid_from, SENTINEL))
    out.sort(key=lambda iv: (iv.package, iv.version, iv.valid_from))
    return out


def load_history(
    repo: str | Path,
    slug: str,
    lockfiles: list[str] | None = None,
    since: str | None = None,
    until: str | None = None,
) -> RepoHistory:
    snapshots, errors = extract_snapshots(repo, lockfiles, since, until)
    used = sorted({p for s in snapshots for p in s.paths})
    return RepoHistory(
        slug=slug,
        snapshots=snapshots,
        intervals=build_intervals(snapshots),
        lockfiles=used or (lockfiles or []),
        errors=errors,
    )
