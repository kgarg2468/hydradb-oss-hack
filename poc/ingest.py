#!/usr/bin/env python3
"""Ingest graph.json.gz into HydraDB via batched UNWIND and report throughput.

Usage:
  python3 ingest.py probe          # find the largest batch size the server accepts
  python3 ingest.py run [batch] [workers]
"""

import concurrent.futures
import gzip
import json
import os
import sys
import time

from hydra import HydraError, query

HERE = os.path.dirname(os.path.abspath(__file__))

UPSERT_REPO = (
    "UNWIND $rows AS row MERGE (n {id: row.id}) "
    "SET n:DepRepo, n.name = row.name, n.slug = row.slug"
)
UPSERT_PKG = "UNWIND $rows AS row MERGE (n {id: row.id}) SET n:DepPackage, n.name = row.name"
UPSERT_PV = (
    "UNWIND $rows AS row MERGE (n {id: row.id}) "
    "SET n:DepPackageVersion, n.pkg = row.pkg, n.version = row.version, n.key = row.key, "
    "n.compromised = row.compromised, n.known_compromised_from = row.kcf"
)
CREATE_VERSION_OF = (
    "UNWIND $rows AS row "
    "MATCH (s:DepPackageVersion {id: row.s}), (d:DepPackage {id: row.d}) "
    "CREATE (s)-[:DEP_VERSION_OF {id: row.id}]->(d)"
)
CREATE_RESOLVES = (
    "UNWIND $rows AS row "
    "MATCH (s:DepRepo {id: row.s}), (d:DepPackageVersion {id: row.d}) "
    "CREATE (s)-[:DEP_RESOLVES {id: row.id, valid_from: row.vf, valid_to: row.vt, "
    "tx_from: row.txf, tx_to: row.txt}]->(d)"
)
CREATE_MAINTAINS = (
    "UNWIND $rows AS row "
    "MATCH (s:DepMaintainer {id: row.s}), (d:DepPackage {id: row.d}) "
    "CREATE (s)-[:DEP_MAINTAINS {id: row.id}]->(d)"
)
UPSERT_MAINT = "UNWIND $rows AS row MERGE (n {id: row.id}) SET n:DepMaintainer, n.name = row.name"


def load():
    with gzip.open(os.path.join(HERE, "graph.json.gz"), "rt") as fh:
        return json.load(fh)


def chunks(rows, size):
    for i in range(0, len(rows), size):
        yield rows[i : i + size]


def send_all(cypher, rows, batch, workers, label):
    """Post rows in batches; returns (seconds, rows_written)."""
    batches = list(chunks(rows, batch))
    t0 = time.perf_counter()
    done = 0
    if workers <= 1:
        for i, b in enumerate(batches):
            query(cypher, {"rows": b})
            done += len(b)
            if (i + 1) % 20 == 0:
                el = time.perf_counter() - t0
                print(f"    {label}: {done}/{len(rows)} ({done/el:,.0f}/s)", flush=True)
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(query, cypher, {"rows": b}): len(b) for b in batches}
            for n, fut in enumerate(concurrent.futures.as_completed(futs)):
                fut.result()
                done += futs[fut]
                if (n + 1) % 20 == 0:
                    el = time.perf_counter() - t0
                    print(f"    {label}: {done}/{len(rows)} ({done/el:,.0f}/s)", flush=True)
    return time.perf_counter() - t0, done


def probe():
    """Find the largest UNWIND batch the server accepts, on throwaway nodes."""
    print("probing max batch size (throwaway :BatchProbe nodes)")
    ok = []
    for size in (100, 500, 1000, 2000, 5000, 10000, 20000, 50000):
        rows = [{"id": 1_900_000_000 + i, "name": f"p{i}"} for i in range(size)]
        q = "UNWIND $rows AS row MERGE (n {id: row.id}) SET n:BatchProbe, n.name = row.name"
        try:
            t0 = time.perf_counter()
            query(q, {"rows": rows}, timeout=300)
            el = time.perf_counter() - t0
            print(f"  batch={size:6d}  OK   {el*1000:8.0f} ms  ({size/el:,.0f} rows/s)")
            ok.append(size)
        except HydraError as exc:
            print(f"  batch={size:6d}  FAIL {str(exc)[:160]}")
            break
        except Exception as exc:
            print(f"  batch={size:6d}  ERROR {str(exc)[:160]}")
            break
    print(f"max accepted batch: {max(ok) if ok else 'none'}")
    try:
        query("MATCH (n:BatchProbe) DETACH DELETE n", timeout=600)
        print("probe nodes deleted")
    except Exception as exc:
        print(f"probe cleanup failed: {str(exc)[:200]}")


def run(batch, workers):
    g = load()
    now = int(time.time())
    sentinel = g["sentinel"]

    repos = g["repos"]
    pkgs = g["packages"]
    pvs = [
        {
            "id": v["id"],
            "pkg": v["pkg"],
            "version": v["version"],
            "key": v["key"],
            "compromised": v["compromised"],
            "kcf": v["known_compromised_from"],
        }
        for v in g["versions"]
    ]
    vof = g["version_of"]
    res = [
        {"id": r["id"], "s": r["s"], "d": r["d"], "vf": r["vf"], "vt": r["vt"],
         "txf": now, "txt": sentinel}
        for r in g["resolves"]
    ]

    print(f"ingesting: repos={len(repos)} packages={len(pkgs)} versions={len(pvs)} "
          f"VERSION_OF={len(vof)} RESOLVES={len(res)}  batch={batch} workers={workers}")

    report = {"batch": batch, "workers": workers, "tx_from": now, "phases": {}}
    steps = [
        ("Repo nodes", UPSERT_REPO, repos, "node"),
        ("Package nodes", UPSERT_PKG, pkgs, "node"),
        ("PackageVersion nodes", UPSERT_PV, pvs, "node"),
        ("VERSION_OF edges", CREATE_VERSION_OF, vof, "edge"),
        ("RESOLVES edges", CREATE_RESOLVES, res, "edge"),
    ]
    total_edges = 0
    total_edge_secs = 0.0
    for label, cypher, rows, kind in steps:
        if not rows:
            continue
        secs, n = send_all(cypher, rows, batch, workers, label)
        rate = n / secs if secs else 0
        print(f"  {label:22s} {n:8,d} rows in {secs:8.2f}s  = {rate:9,.0f} {kind}s/sec")
        report["phases"][label] = {"rows": n, "seconds": round(secs, 3),
                                   "rows_per_sec": round(rate, 1), "kind": kind}
        if kind == "edge":
            total_edges += n
            total_edge_secs += secs

    report["total_edges"] = total_edges
    report["total_edge_seconds"] = round(total_edge_secs, 3)
    report["edges_per_sec"] = round(total_edges / total_edge_secs, 1) if total_edge_secs else 0
    report["total_nodes"] = len(repos) + len(pkgs) + len(pvs)
    print(f"\nTOTAL edges={total_edges:,} in {total_edge_secs:.2f}s = "
          f"{report['edges_per_sec']:,.0f} edges/sec")

    with open(os.path.join(HERE, "ingest-report.json"), "w") as fh:
        json.dump(report, fh, indent=2)
    return report


def run_maintainers(batch, workers):
    g = load()
    pkg_ids = {p["name"]: p["id"] for p in g["packages"]}
    doc = json.load(open(os.path.join(HERE, "maintainers.json")))

    names = sorted({m for ms in doc["packages"].values() for m in ms})
    maint_ids = {n: 1_050_000_000 + i for i, n in enumerate(names)}
    mnodes = [{"id": mid, "name": n} for n, mid in maint_ids.items()]

    edges = []
    for pkg, ms in sorted(doc["packages"].items()):
        pid = pkg_ids.get(pkg)
        if pid is None:
            continue
        for m in ms:
            edges.append({"id": 1_400_000_000 + len(edges), "s": maint_ids[m], "d": pid})

    print(f"maintainers={len(mnodes)} MAINTAINS edges={len(edges)}")
    s1, _ = send_all(UPSERT_MAINT, mnodes, batch, workers, "Maintainer nodes")
    s2, _ = send_all(CREATE_MAINTAINS, edges, batch, workers, "MAINTAINS edges")
    print(f"  Maintainer nodes {len(mnodes):6,d} in {s1:.2f}s")
    print(f"  MAINTAINS edges  {len(edges):6,d} in {s2:.2f}s = {len(edges)/s2 if s2 else 0:,.0f}/s")

    path = os.path.join(HERE, "ingest-report.json")
    report = json.load(open(path)) if os.path.exists(path) else {}
    report["maintainers"] = {"nodes": len(mnodes), "edges": len(edges),
                             "node_seconds": round(s1, 3), "edge_seconds": round(s2, 3)}
    report["total_edges"] = report.get("total_edges", 0) + len(edges)
    with open(path, "w") as fh:
        json.dump(report, fh, indent=2)


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "run"
    if cmd == "probe":
        probe()
    elif cmd == "maintainers":
        run_maintainers(int(sys.argv[2]) if len(sys.argv) > 2 else 1000,
                        int(sys.argv[3]) if len(sys.argv) > 3 else 1)
    else:
        run(int(sys.argv[2]) if len(sys.argv) > 2 else 2000,
            int(sys.argv[3]) if len(sys.argv) > 3 else 1)
