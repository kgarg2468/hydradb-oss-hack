#!/usr/bin/env python3
"""Turn lockfile snapshots into a bitemporal graph payload.

Valid time  : the interval during which the repo's committed lockfile actually
              resolved that (package, version). Taken from git commit times.
Transaction time : when this graph learned the fact. For a historical backfill
              every RESOLVES edge shares one tx_from (the ingest run); the
              meaningful transaction-time axis in this PoC lives on
              PackageVersion.known_compromised_from, which is the moment the
              compromise became public knowledge (2025-09-08T15:20Z). That lets
              a query ask "valid at T, as known at K".

Output: graph.json.gz
"""

import gzip
import json
import os
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SNAP = os.path.join(HERE, "snapshots")

# 2100-01-01T00:00:00Z. HydraDB has no IS NULL, so open-ended intervals need a
# sentinel rather than a missing property.
SENTINEL = 4102444800

# When the chalk/debug compromise became public knowledge.
DISCLOSURE_TS = 1757344800  # 2025-09-08T15:20:00Z
NEVER = SENTINEL

ID_REPO = 1_010_000_000
ID_PKG = 1_020_000_000
ID_PV = 1_030_000_000
ID_MAINT = 1_050_000_000
ID_RESOLVES = 1_100_000_000
ID_VERSION_OF = 1_300_000_000
ID_MAINTAINS = 1_400_000_000

REPOS = {
    "axios": "axios/axios",
    "babel": "babel/babel",
    "grafana": "grafana/grafana",
    "jitsi-meet": "jitsi/jitsi-meet",
    "webpack": "webpack/webpack",
    "superset": "apache/superset",
    "react": "facebook/react",
    "storybook": "storybookjs/storybook",
}


def load_snapshots(repo):
    path = os.path.join(SNAP, f"{repo}.jsonl.gz")
    if not os.path.exists(path):
        return []
    snaps = []
    with gzip.open(path, "rt") as fh:
        for line in fh:
            snaps.append(json.loads(line))
    snaps.sort(key=lambda s: s["ts"])
    return snaps


def intervals_for(snaps):
    """[(name, version, valid_from, valid_to)] from a time-ordered snapshot list."""
    out = []
    open_at = {}
    for snap in snaps:
        ts = snap["ts"]
        cur = {(n, v) for n, v in snap["entries"]}
        for key in [k for k in open_at if k not in cur]:
            out.append((key[0], key[1], open_at.pop(key), ts))
        for key in cur:
            if key not in open_at:
                open_at[key] = ts
    for key, vf in open_at.items():
        out.append((key[0], key[1], vf, SENTINEL))
    return out


def main():
    incident = json.load(open(os.path.join(HERE, "incident-chalk-debug.json")))
    compromised = {(p["package"], p["malicious_version"]) for p in incident["packages"]}
    published = {
        (p["package"], p["malicious_version"]): p.get("published_at")
        for p in incident["packages"]
    }

    repo_nodes = []
    pkg_ids = {}
    pv_ids = {}
    pv_nodes = []
    resolves = []

    stats = {}
    for i, repo in enumerate(sorted(REPOS)):
        snaps = load_snapshots(repo)
        if not snaps:
            print(f"  {repo}: NO SNAPSHOTS, skipped")
            continue
        rid = ID_REPO + i
        repo_nodes.append(
            {
                "id": rid,
                "name": REPOS[repo],
                "slug": repo,
                "snapshots": len(snaps),
                "first_ts": snaps[0]["ts"],
                "last_ts": snaps[-1]["ts"],
            }
        )
        ivs = intervals_for(snaps)
        for name, version, vf, vt in ivs:
            if name not in pkg_ids:
                pkg_ids[name] = ID_PKG + len(pkg_ids)
            key = f"{name}@{version}"
            if key not in pv_ids:
                pvid = ID_PV + len(pv_ids)
                pv_ids[key] = pvid
                is_bad = (name, version) in compromised
                pv_nodes.append(
                    {
                        "id": pvid,
                        "pkg": name,
                        "version": version,
                        "key": key,
                        "pkg_id": pkg_ids[name],
                        "compromised": 1 if is_bad else 0,
                        "known_compromised_from": DISCLOSURE_TS if is_bad else NEVER,
                    }
                )
            resolves.append(
                {
                    "id": ID_RESOLVES + len(resolves),
                    "s": rid,
                    "d": pv_ids[key],
                    "vf": vf,
                    "vt": vt,
                }
            )
        stats[repo] = {
            "snapshots": len(snaps),
            "intervals": len(ivs),
            "first": snaps[0]["ts"],
            "last": snaps[-1]["ts"],
        }
        print(
            f"  {repo:12s} snapshots={len(snaps):4d} intervals={len(ivs):7d} "
            f"span={time.strftime('%Y-%m-%d', time.gmtime(snaps[0]['ts']))}"
            f"..{time.strftime('%Y-%m-%d', time.gmtime(snaps[-1]['ts']))}"
        )

    pkg_nodes = [{"id": pid, "name": n} for n, pid in sorted(pkg_ids.items(), key=lambda x: x[1])]
    version_of = [
        {"id": ID_VERSION_OF + i, "s": pv["id"], "d": pv["pkg_id"]}
        for i, pv in enumerate(pv_nodes)
    ]

    hits = [pv for pv in pv_nodes if pv["compromised"]]
    print(f"\nrepos={len(repo_nodes)} packages={len(pkg_nodes)} versions={len(pv_nodes)}")
    print(f"RESOLVES={len(resolves)} VERSION_OF={len(version_of)}")
    print(f"compromised PackageVersion nodes present in history: {len(hits)}")
    for pv in hits:
        print(f"   !! {pv['key']}  (published {published.get((pv['pkg'], pv['version']))})")

    graph = {
        "sentinel": SENTINEL,
        "disclosure_ts": DISCLOSURE_TS,
        "repos": repo_nodes,
        "packages": pkg_nodes,
        "versions": pv_nodes,
        "resolves": resolves,
        "version_of": version_of,
        "stats": stats,
    }
    out = os.path.join(HERE, "graph.json.gz")
    with gzip.open(out, "wt") as fh:
        json.dump(graph, fh)
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
