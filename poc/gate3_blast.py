#!/usr/bin/env python3
"""Gate 3 - blast radius + maintainer reach + latency distribution.

Two query shapes are measured side by side for the same answer:

  label-scan  : MATCH (r:DepRepo)-[e:DEP_RESOLVES]->(pv:DepPackageVersion) WHERE pv.pkg = $pkg ...
  id-anchored : MATCH (pv)-[:DEP_VERSION_OF]->(p:DepPackage {id: $pid}), (r)-[e:DEP_RESOLVES]->(pv) ...

HydraDB has no secondary property index, so the first is O(all RESOLVES edges)
and the second rides typed adjacency from a known id. They must agree.
"""

import collections
import gzip
import json
import os
import statistics
import time

from hydra import query_all, scalars, timed

HERE = os.path.dirname(os.path.abspath(__file__))
T_WINDOW = 1757339000  # 2025-09-08 13:43Z, inside the malicious-publish window

Q_LABEL_SCAN = (
    "MATCH (r:DepRepo)-[e:DEP_RESOLVES]->(pv:DepPackageVersion) "
    "WHERE pv.pkg = $pkg AND e.valid_from <= $t AND e.valid_to > $t "
    "RETURN DISTINCT r.name AS repo, pv.version AS version"
)
Q_ID_ANCHORED = (
    "MATCH (pv:DepPackageVersion)-[:DEP_VERSION_OF]->(p:DepPackage {id: $pid}), "
    "(r:DepRepo)-[e:DEP_RESOLVES]->(pv) "
    "WHERE e.valid_from <= $t AND e.valid_to > $t "
    "RETURN DISTINCT r.name AS repo, pv.version AS version"
)
Q_COMPROMISED_SCAN = (
    "MATCH (r:DepRepo)-[e:DEP_RESOLVES]->(pv:DepPackageVersion) "
    "WHERE pv.compromised = 1 AND e.valid_from <= $t AND e.valid_to > $t "
    "RETURN r.name AS repo, pv.key AS pkgversion"
)


def pct(values, p):
    if not values:
        return 0.0
    s = sorted(values)
    k = (len(s) - 1) * p / 100.0
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def stat(name, lat):
    return {"query": name, "n": len(lat), "p50": round(pct(lat, 50), 2),
            "p95": round(pct(lat, 95), 2), "min": round(min(lat), 2),
            "max": round(max(lat), 2), "mean": round(statistics.mean(lat), 2)}


def main():
    with gzip.open(os.path.join(HERE, "graph.json.gz"), "rt") as fh:
        g = json.load(fh)
    incident = json.load(open(os.path.join(HERE, "incident-chalk-debug.json")))
    inc_pkgs = sorted({p["package"] for p in incident["packages"]})

    pkg_id = {p["name"]: p["id"] for p in g["packages"]}
    pv_key_id = {v["key"]: v["id"] for v in g["versions"]}
    out = {"t": T_WINDOW, "graph": {"repos": len(g["repos"]),
                                    "packages": len(g["packages"]),
                                    "versions": len(g["versions"]),
                                    "resolves": len(g["resolves"])}}

    # ---------- 3a. exact exposure ----------
    print("=" * 74)
    print("3a. EXACT EXPOSURE - repos resolving a COMPROMISED PackageVersion at T")
    print("=" * 74)
    # A compromised version that was never resolved has no PackageVersion node,
    # so the key->id map answers it without a query at all.
    present = {p["package"] + "@" + p["malicious_version"]: pv_key_id.get(
        p["package"] + "@" + p["malicious_version"]) for p in incident["packages"]}
    resolved_keys = {k: v for k, v in present.items() if v is not None}
    print(f"  compromised versions with a PackageVersion node in the graph: "
          f"{len(resolved_keys)} / {len(present)}")
    exact = []
    for key, pvid in resolved_keys.items():
        rows, _ = query_all(
            "MATCH (r:DepRepo)-[e:DEP_RESOLVES]->(pv:DepPackageVersion {id: $pvid}) "
            "WHERE e.valid_from <= $t AND e.valid_to > $t RETURN r.name AS repo",
            {"pvid": pvid, "t": T_WINDOW})
        exact.extend([[r[0], key] for r in rows])
    scan_rows, _ = query_all(Q_COMPROMISED_SCAN, {"t": T_WINDOW})
    print(f"  id-anchored answer : {len(exact)} (repo, compromised-version) pairs")
    print(f"  label-scan answer  : {len(scan_rows)} pairs   agree={sorted(exact)==sorted(scan_rows)}")
    out["exact_exposure"] = exact
    out["exact_exposure_agrees"] = sorted(exact) == sorted(scan_rows)

    # ---------- 3b. audit scope ----------
    print("\n" + "=" * 74)
    print("3b. AUDIT SCOPE - repos resolving ANY version of an incident package at T")
    print("     (no IN operator, so one id-anchored query per package)")
    print("=" * 74)
    by_pkg = {}
    lat_anchor = []
    lat_scan = []
    disagree = []
    for pkg in inc_pkgs:
        pid = pkg_id.get(pkg)
        if pid is None:
            continue
        rows, ms = None, None
        t0 = time.perf_counter()
        rows, _ = query_all(Q_ID_ANCHORED, {"pid": pid, "t": T_WINDOW})
        lat_anchor.append((time.perf_counter() - t0) * 1000)
        t0 = time.perf_counter()
        srows, _ = query_all(Q_LABEL_SCAN, {"pkg": pkg, "t": T_WINDOW})
        lat_scan.append((time.perf_counter() - t0) * 1000)
        if sorted(rows) != sorted(srows):
            disagree.append(pkg)
        if rows:
            by_pkg[pkg] = rows
    print(f"  {len(by_pkg)}/{len(inc_pkgs)} incident packages present in the org at T")
    print(f"  id-anchored vs label-scan disagreements: {len(disagree)} {disagree}")
    for pkg, rows in sorted(by_pkg.items(), key=lambda x: -len({r[0] for r in x[1]})):
        repos = sorted({r[0] for r in rows})
        vers = sorted({r[1] for r in rows})
        print(f"    {pkg:22s} repos={len(repos)} versions={len(vers)}  {','.join(vers[:6])}")
    out["audit_scope"] = by_pkg
    out["shape_agreement_disagreements"] = disagree

    # ---------- 3c. aggregation ----------
    print("\n" + "=" * 74)
    print("3c. AGGREGATION - most widely resolved packages at T (server-side count)")
    print("=" * 74)
    q_agg = (
        "MATCH (r:DepRepo)-[e:DEP_RESOLVES]->(pv:DepPackageVersion) "
        "WHERE e.valid_from <= $t AND e.valid_to > $t "
        "RETURN pv.pkg AS pkg, count(*) AS n ORDER BY n DESC LIMIT 15"
    )
    res, ms = timed(q_agg, {"t": T_WINDOW}, page_size=4000)
    print(f"  ({ms:.0f} ms, single full scan + server-side group/sort)")
    for pkg, n in scalars(res)[:15]:
        print(f"    {pkg:34s} {n}")
    out["top_packages"] = scalars(res)
    out["aggregation_ms"] = round(ms, 1)

    # ---------- 3d. maintainer reach ----------
    print("\n" + "=" * 74)
    print("3d. MAINTAINER REACH at T (3-pattern join, native)")
    print("=" * 74)
    q_reach = (
        "MATCH (m:DepMaintainer)-[:DEP_MAINTAINS]->(p:DepPackage), "
        "(pv:DepPackageVersion)-[:DEP_VERSION_OF]->(p), "
        "(r:DepRepo)-[e:DEP_RESOLVES]->(pv) "
        "WHERE e.valid_from <= $t AND e.valid_to > $t "
        "RETURN DISTINCT m.name AS maintainer, r.name AS repo, p.name AS pkg"
    )
    t0 = time.perf_counter()
    rows, pages = query_all(q_reach, {"t": T_WINDOW})
    reach_ms = (time.perf_counter() - t0) * 1000
    repos_of = collections.defaultdict(set)
    pairs_of = collections.defaultdict(set)
    pkgs_of = collections.defaultdict(set)
    for m, r, p in rows:
        repos_of[m].add(r)
        pairs_of[m].add((r, p))
        pkgs_of[m].add(p)
    # "repos reached" saturates at 8 for anything ubiquitous, so rank on the
    # finer-grained (repo, package) surface and show both.
    ranked = sorted(repos_of, key=lambda m: (-len(pairs_of[m]), -len(repos_of[m]), m))
    print(f"  {len(rows)} distinct (maintainer, repo, package) triples over {pages} "
          f"page(s) in {reach_ms:.0f} ms")
    print(f"  {sum(1 for m in repos_of if len(repos_of[m]) == len(g['repos']))} of "
          f"{len(repos_of)} maintainers reach ALL {len(g['repos'])} repos "
          f"(the metric saturates at this org size)")
    print(f"  {'maintainer':22s} {'repos':>5s} {'pkgs':>5s} {'repo x pkg':>10s}")
    for m in ranked[:15]:
        print(f"    {m:20s} {len(repos_of[m]):5d} {len(pkgs_of[m]):5d} {len(pairs_of[m]):10d}")
    out["maintainer_reach"] = [
        {"maintainer": m, "repos": len(repos_of[m]), "packages": len(pkgs_of[m]),
         "repo_package_pairs": len(pairs_of[m]), "pkg_names": sorted(pkgs_of[m])[:10]}
        for m in ranked[:25]]
    out["maintainer_reach_ms"] = round(reach_ms, 1)
    out["maintainers_reaching_all_repos"] = sum(
        1 for m in repos_of if len(repos_of[m]) == len(g["repos"]))
    out["maintainer_count"] = len(repos_of)

    # ---------- 3e. latency ----------
    print("\n" + "=" * 74)
    print("3e. LATENCY - AS-OF blast radius, 30 runs each")
    print("=" * 74)
    lat_a, lat_s = [], []
    pid = pkg_id["chalk"]
    for _ in range(30):
        _, ms = timed(Q_ID_ANCHORED, {"pid": pid, "t": T_WINDOW}, page_size=4000)
        lat_a.append(ms)
    for _ in range(30):
        _, ms = timed(Q_LABEL_SCAN, {"pkg": "chalk", "t": T_WINDOW}, page_size=4000)
        lat_s.append(ms)
    lat_c = []
    for _ in range(30):
        _, ms = timed(Q_COMPROMISED_SCAN, {"t": T_WINDOW}, page_size=4000)
        lat_c.append(ms)

    rows_a = [
        stat("blast radius, id-anchored (pkg=chalk)", lat_a),
        stat("blast radius, label-scan (pkg=chalk)", lat_s),
        stat("compromised label-scan (whole graph)", lat_c),
    ]
    if lat_anchor:
        rows_a.append(stat("per-incident-package, id-anchored", lat_anchor))
        rows_a.append(stat("per-incident-package, label-scan", lat_scan))
    print(f"  {'query':42s} {'n':>3s} {'p50 ms':>10s} {'p95 ms':>10s} {'min':>9s}")
    for s in rows_a:
        print(f"  {s['query']:42s} {s['n']:3d} {s['p50']:10.1f} {s['p95']:10.1f} {s['min']:9.1f}")
    speedup = rows_a[1]["p50"] / rows_a[0]["p50"] if rows_a[0]["p50"] else 0
    print(f"\n  id-anchored is {speedup:,.0f}x faster than the label scan "
          f"for the identical answer")
    out["latency"] = rows_a
    out["id_anchor_speedup"] = round(speedup, 1)

    with open(os.path.join(HERE, "gate3-report.json"), "w") as fh:
        json.dump(out, fh, indent=2)
    print("\nwrote gate3-report.json")


if __name__ == "__main__":
    main()
