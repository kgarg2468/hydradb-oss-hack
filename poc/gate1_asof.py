#!/usr/bin/env python3
"""Gate 1 - bitemporal AS-OF correctness.

Two independent paths are compared:

  graph  : HydraDB Cypher over RESOLVES intervals (valid_from <= T < valid_to)
  oracle : `git log` for the newest lockfile commit at or before T, `git show`
           that blob, parse it fresh with lockparse. Never touches the graph or
           the precomputed snapshot files.

Any disagreement is reported, not swallowed.
"""

import gzip
import json
import os
import random
import subprocess
import time

from hydra import query_all
from lockparse import parse_lockfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPOS_DIR = os.path.join(HERE, "repos")
GIT_OPTS = ["-c", "core.commitGraph=false"]

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

# 2025-09-08 incident anchors (unix seconds, UTC)
# Must match extract_history.py SINCE, so the oracle cannot see commits the
# graph never ingested.
WINDOW_SINCE = "2024-01-01"

T_BEFORE = 1757000000   # 2025-09-04 15:33 - well before
T_WINDOW = 1757339000   # 2025-09-08 13:43 - inside the malicious-publish window
T_AFTER = 1757600000    # 2025-09-11 14:13 - after remediation


def git(repo, *args):
    return subprocess.run(
        ["git", "-C", os.path.join(REPOS_DIR, repo), *GIT_OPTS, *args],
        capture_output=True,
    )


def oracle_state(repo, t, lo, hi):
    """Resolved (name, version) set for `repo` as of time t, straight from git.

    Mirrors the ingest rule exactly: take the newest commit at or before t that
    touched any candidate lockfile path, then at that commit parse every
    candidate path and keep the richest one. A repo can carry a workspace-stub
    lockfile alongside the real one (storybook's root yarn.lock is 312 bytes
    while code/yarn.lock is 1 MB), so "first path that exists" is wrong.
    """
    paths = SPECS[repo]
    newest = None
    for path in paths:
        r = git(repo, "log", "-1", "--format=%H %ct",
                f"--until={t}", f"--since={lo}", "--", path)
        line = r.stdout.decode().strip()
        if not line:
            continue
        sha, _, ts = line.partition(" ")
        ts = int(ts)
        if newest is None or ts > newest[1]:
            newest = (sha, ts)
    if newest is None:
        return None, None, None

    sha, ts = newest
    best = None
    for path in paths:
        blob = git(repo, "show", f"{sha}:{path}")
        if blob.returncode != 0:
            continue
        try:
            parsed = parse_lockfile(path, blob.stdout.decode("utf-8", "replace"))
        except Exception:
            continue
        if best is None or len(parsed) > len(best):
            best = parsed
    if not best:
        return None, None, None
    return best, sha, ts


def main():
    with gzip.open(os.path.join(HERE, "graph.json.gz"), "rt") as fh:
        g = json.load(fh)
    repo_by_name = {r["slug"]: r for r in g["repos"]}
    lo = WINDOW_SINCE
    hi = max(r["last_ts"] for r in g["repos"])

    results = {"checks": [], "mismatches": [], "incident": {}}

    # ---------- A. the incident question ----------
    print("=" * 72)
    print("A. Which repos resolved a COMPROMISED PackageVersion, valid at time T?")
    print("=" * 72)
    q_incident = (
        "MATCH (r:DepRepo)-[e:DEP_RESOLVES]->(pv:DepPackageVersion) "
        "WHERE pv.compromised = 1 AND e.valid_from <= $t AND e.valid_to > $t "
        "RETURN r.name AS repo, pv.key AS pkgversion"
    )
    for label, t in (("before window", T_BEFORE), ("INSIDE window", T_WINDOW),
                     ("after remediation", T_AFTER)):
        rows, _ = query_all(q_incident, {"t": t})
        print(f"  T={t} ({label:18s}) -> {len(rows)} repo/version pairs {rows[:5]}")
        results["incident"][label] = rows

    # Bitemporal variant: valid at T, as known at transaction time K.
    print("\n  bitemporal (valid at T=inside window, as KNOWN at K):")
    q_bitemporal = (
        "MATCH (r:DepRepo)-[e:DEP_RESOLVES]->(pv:DepPackageVersion) "
        "WHERE pv.known_compromised_from <= $k AND e.valid_from <= $t AND e.valid_to > $t "
        "RETURN r.name AS repo, pv.key AS pkgversion"
    )
    for label, k in (("K = during incident (13:43Z, not yet public)", 1757339000),
                     ("K = after disclosure (15:20Z)", 1757344800),
                     ("K = today", int(time.time()))):
        rows, _ = query_all(q_bitemporal, {"t": T_WINDOW, "k": k})
        print(f"    {label:46s} -> {len(rows)} rows")
        results["incident"]["bitemporal_" + label] = len(rows)

    # ---------- B. full-set AS-OF equality, graph vs git ----------
    print("\n" + "=" * 72)
    print("B. Full resolved-set equality: HydraDB AS-OF vs fresh git lockfile parse")
    print("=" * 72)
    q_full = (
        "MATCH (r:DepRepo {id: $rid})-[e:DEP_RESOLVES]->(pv:DepPackageVersion) "
        "WHERE e.valid_from <= $t AND e.valid_to > $t "
        "RETURN pv.key AS k"
    )
    fixed_probes = [T_BEFORE, T_WINDOW, T_AFTER,
                    1735689600,  # 2025-01-01
                    1751328000,  # 2025-07-01
                    1764547200]  # 2025-12-01
    rng = random.Random(20250908)
    agree = 0
    total = 0
    answer_sets = set()
    for repo in sorted(SPECS):
        if repo not in repo_by_name:
            continue
        rid = repo_by_name[repo]["id"]
        meta = repo_by_name[repo]
        # fixed anchors plus random instants inside this repo's own history
        randoms = [rng.randint(meta["first_ts"], meta["last_ts"]) for _ in range(10)]
        for t in fixed_probes + randoms:
            if t < repo_by_name[repo]["first_ts"]:
                continue
            rows, _ = query_all(q_full, {"rid": rid, "t": t})
            graph_set = {r[0] for r in rows}
            oracle, sha, ots = oracle_state(repo, t, lo, hi)
            if oracle is None:
                continue
            oracle_set = {f"{n}@{v}" for n, v in oracle}
            total += 1
            ok = graph_set == oracle_set
            agree += ok
            answer_sets.add((repo, hash(frozenset(graph_set))))
            status = "OK " if ok else "MISMATCH"
            print(f"  {status} {repo:12s} T={t} graph={len(graph_set):5d} "
                  f"oracle={len(oracle_set):5d} commit={sha[:8] if sha else '-'}")
            rec = {"repo": repo, "t": t, "graph": len(graph_set),
                   "oracle": len(oracle_set), "commit": sha, "agree": ok}
            if not ok:
                rec["only_in_graph"] = sorted(graph_set - oracle_set)[:20]
                rec["only_in_oracle"] = sorted(oracle_set - graph_set)[:20]
                results["mismatches"].append(rec)
            results["checks"].append(rec)

    # ---------- C. targeted: version of each incident package per repo at T ----------
    print("\n" + "=" * 72)
    print("C. Targeted: which version of each incident package did each repo")
    print("   resolve at incident time? (graph vs git)")
    print("=" * 72)
    incident = json.load(open(os.path.join(HERE, "incident-chalk-debug.json")))
    inc_pkgs = sorted({p["package"] for p in incident["packages"]})
    q_pkg = (
        "MATCH (r:DepRepo {id: $rid})-[e:DEP_RESOLVES]->(pv:DepPackageVersion) "
        "WHERE pv.pkg = $pkg AND e.valid_from <= $t AND e.valid_to > $t "
        "RETURN pv.version AS v"
    )
    t_agree = 0
    t_total = 0
    exposure_rows = []
    for repo in sorted(SPECS):
        if repo not in repo_by_name:
            continue
        rid = repo_by_name[repo]["id"]
        oracle, sha, _ = oracle_state(repo, T_WINDOW, lo, hi)
        if oracle is None:
            continue
        for pkg in inc_pkgs:
            rows, _ = query_all(q_pkg, {"rid": rid, "pkg": pkg, "t": T_WINDOW})
            gv = {r[0] for r in rows}
            ov = {v for n, v in oracle if n == pkg}
            t_total += 1
            ok = gv == ov
            t_agree += ok
            if not ok:
                results["mismatches"].append(
                    {"repo": repo, "pkg": pkg, "t": T_WINDOW,
                     "graph": sorted(gv), "oracle": sorted(ov), "agree": False})
                print(f"  MISMATCH {repo}/{pkg}: graph={sorted(gv)} oracle={sorted(ov)}")
            if gv:
                exposure_rows.append((repo, pkg, sorted(gv)))
    print(f"  targeted probes: {t_agree}/{t_total} agree")

    print("\n  resolved versions of incident packages at incident time:")
    for repo, pkg, vs in exposure_rows[:24]:
        print(f"    {repo:12s} {pkg:20s} {','.join(vs)}")
    print(f"    ... {len(exposure_rows)} (repo, incident-package) pairs total")

    results["full_set_checks"] = {"agree": agree, "total": total,
                                  "distinct_answer_sets": len(answer_sets)}
    results["targeted_checks"] = {"agree": t_agree, "total": t_total}
    results["exposure_rows"] = [[r, p, v] for r, p, v in exposure_rows]
    passed = (agree == total and t_agree == t_total and total > 0)
    results["gate1_pass"] = passed

    print("\n" + "=" * 72)
    print(f"  distinct (repo, resolved-set) answers across probes: {len(answer_sets)}")
    print(f"GATE 1: full-set {agree}/{total}, targeted {t_agree}/{t_total} -> "
          f"{'PASS' if passed else 'FAIL'}")
    print("=" * 72)

    with open(os.path.join(HERE, "gate1-report.json"), "w") as fh:
        json.dump(results, fh, indent=2)


if __name__ == "__main__":
    main()
