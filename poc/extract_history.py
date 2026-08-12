#!/usr/bin/env python3
"""Walk a repo's lockfile git history and emit one snapshot per commit.

Output: snapshots/<repo>.jsonl.gz, one JSON object per line, oldest first:
  {"commit": sha, "ts": unix_seconds, "path": lockfile_path, "entries": [[name, version], ...]}

Blobs are pulled from the blobless partial clone in a single `git cat-file --batch`
pass so the lazy fetch happens once per repo rather than once per commit.
"""

import gzip
import json
import os
import subprocess
import sys

from lockparse import parse_lockfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPOS = os.path.join(HERE, "repos")
OUT = os.path.join(HERE, "snapshots")

SINCE = os.environ.get("SINCE", "2024-01-01")
UNTIL = os.environ.get("UNTIL", "2025-12-31")

# repo -> candidate lockfile paths, first that resolves at a given commit wins.
SPECS = {
    "axios": ["package-lock.json"],
    "babel": ["yarn.lock"],
    "grafana": ["yarn.lock"],
    "jitsi-meet": ["package-lock.json"],
    "webpack": ["yarn.lock"],
    "superset": ["superset-frontend/package-lock.json"],
    "react": ["yarn.lock"],
    "storybook": ["yarn.lock", "code/yarn.lock"],
}


# A blobless clone plus concurrent lazy fetches trips git's commit-graph
# consistency check ("in the commit graph file but not in the object database"),
# which aborts the fetch. Disabling the commit-graph reader avoids it.
GIT_OPTS = ["-c", "core.commitGraph=false", "-c", "fetch.writeCommitGraph=false"]


def git(repo, *args):
    return subprocess.run(
        ["git", "-C", os.path.join(REPOS, repo), *GIT_OPTS, *args],
        capture_output=True,
        text=True,
    )


def fetch_blobs(repo, oids, chunk=25):
    """Fetch blobs in chunks so one bad object cannot kill the whole run."""
    cwd = os.path.join(REPOS, repo)
    blobs = {}
    failed = []
    for start in range(0, len(oids), chunk):
        batch = oids[start : start + chunk]
        proc = subprocess.Popen(
            ["git", "-C", cwd, *GIT_OPTS, "cat-file", "--batch"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        try:
            proc.stdin.write(("\n".join(batch) + "\n").encode())
            proc.stdin.close()
            for oid in batch:
                header = proc.stdout.readline().decode().strip()
                parts = header.split()
                if len(parts) != 3:
                    raise IOError(f"desync at {oid}: {header!r}")
                size = int(parts[2])
                blobs[oid] = proc.stdout.read(size)
                proc.stdout.read(1)
        except Exception:
            # Stream desynced: retry this chunk one object at a time.
            proc.kill()
            for oid in batch:
                if oid in blobs:
                    continue
                r = subprocess.run(
                    ["git", "-C", cwd, *GIT_OPTS, "cat-file", "blob", oid],
                    capture_output=True,
                )
                if r.returncode == 0:
                    blobs[oid] = r.stdout
                else:
                    failed.append(oid)
        finally:
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()
        print(f"[{repo}] fetched {len(blobs)}/{len(oids)} blobs", flush=True)
    if failed:
        print(f"[{repo}] {len(failed)} blobs unreachable", file=sys.stderr)
    return blobs


def main(repo):
    paths = SPECS[repo]
    seen = {}
    order = []
    for path in paths:
        r = git(repo, "log", "--format=%H %ct", f"--since={SINCE}", f"--until={UNTIL}", "--", path)
        for line in r.stdout.splitlines():
            sha, _, ts = line.partition(" ")
            if sha and sha not in seen:
                seen[sha] = (int(ts), path)
                order.append(sha)

    # Resolve every candidate path that exists at each commit. Which one is the
    # real lockfile changes over a repo's life (storybook moved code/yarn.lock to
    # the root and left a workspace stub behind), so the choice is deferred until
    # the blobs are parsed and the richest one wins.
    resolved = []
    for sha in order:
        ts, _ = seen[sha]
        cands = []
        for path in paths:
            r = git(repo, "rev-parse", f"{sha}:{path}")
            if r.returncode == 0 and r.stdout.strip():
                cands.append((path, r.stdout.strip()))
        if cands:
            resolved.append((sha, ts, cands))

    resolved.sort(key=lambda x: x[1])
    print(f"[{repo}] {len(resolved)} commits with a lockfile", flush=True)

    # One batched cat-file pass; identical blobs are only fetched once.
    unique = []
    unique_set = set()
    for _, _, cands in resolved:
        for _, oid in cands:
            if oid not in unique_set:
                unique_set.add(oid)
                unique.append(oid)

    blobs = fetch_blobs(repo, unique)

    os.makedirs(OUT, exist_ok=True)
    written = 0
    with gzip.open(os.path.join(OUT, f"{repo}.jsonl.gz"), "wt") as fh:
        for sha, ts, cands in resolved:
            best = None
            path = None
            for cand_path, oid in cands:
                raw = blobs.get(oid)
                if raw is None:
                    continue
                try:
                    parsed = parse_lockfile(cand_path, raw.decode("utf-8", "replace"))
                except Exception as exc:  # a malformed/partial lockfile in history
                    print(f"[{repo}] parse failed {sha[:8]} {cand_path}: {exc}",
                          file=sys.stderr)
                    continue
                if best is None or len(parsed) > len(best):
                    best, path = parsed, cand_path
            entries = best
            if not entries:
                continue
            fh.write(
                json.dumps(
                    {
                        "commit": sha,
                        "ts": ts,
                        "path": path,
                        "entries": sorted(entries),
                    }
                )
                + "\n"
            )
            written += 1
    print(f"[{repo}] wrote {written} snapshots", flush=True)


if __name__ == "__main__":
    main(sys.argv[1])
