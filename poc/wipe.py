#!/usr/bin/env python3
"""Delete every node/edge this PoC created, leaving pre-existing junk alone.

Deletion is the sharpest edge in the Cypher subset:

  * `MATCH (n:Label) DETACH DELETE n` over a whole label blows the server-side
    30s `client_query_runtime` cap, which the client timeout cannot raise.
  * `UNWIND ... DETACH DELETE n` runs at ~3 nodes/s while the node still has
    edges, because each node detach appears to scan for incident edges.
  * `UNWIND ... MATCH (s:Label {id: row.s})-[e:REL]->(d:Label {id: row.d}) DELETE e`
    is rejected: "UNWIND batch node patterns do not support labels" (the same
    labelled form IS accepted for UNWIND ... CREATE).

So: drop the edges first through anonymous endpoints keyed on the edge id, then
detach the now-edgeless nodes.
"""

import gzip
import json
import os
import time

from hydra import HydraError, query, scalars

HERE = os.path.dirname(os.path.abspath(__file__))
LABELS = ["DepRepo", "DepPackageVersion", "DepPackage", "DepMaintainer", "BatchProbe", "Probe"]
EDGE_BATCH = 400
NODE_BATCH = 400

DEL_EDGE = "UNWIND $rows AS row MATCH ()-[e:{rel} {{id: row.id}}]->() DELETE e"
DEL_NODE = "UNWIND $rows AS row MATCH (n {id: row.id}) DETACH DELETE n"


def count(label):
    try:
        return scalars(query(f"MATCH (n:{label}) RETURN count(*) AS c", timeout=120))[0][0]
    except HydraError:
        return -1


def run_batches(cypher, ids, batch, label):
    t0 = time.perf_counter()
    done = 0
    for i in range(0, len(ids), batch):
        rows = [{"id": x} for x in ids[i : i + batch]]
        try:
            query(cypher, {"rows": rows}, timeout=200)
        except HydraError as exc:
            print(f"  {label} batch @{i} failed: {str(exc)[:140]}", flush=True)
            continue
        done += len(rows)
        if (i // batch) % 10 == 0:
            el = time.perf_counter() - t0
            print(f"  {label}: {done}/{len(ids)} ({done/el if el else 0:,.0f}/s)", flush=True)
    el = time.perf_counter() - t0
    print(f"  {label}: {done} in {el:.1f}s ({done/el if el else 0:,.0f}/s)", flush=True)


def main():
    print("before:", {lbl: count(lbl) for lbl in LABELS})
    t0 = time.perf_counter()

    with gzip.open(os.path.join(HERE, "graph.json.gz"), "rt") as fh:
        g = json.load(fh)

    run_batches(DEL_EDGE.format(rel="DEP_RESOLVES"),
                [e["id"] for e in g["resolves"]], EDGE_BATCH, "DEP_RESOLVES")
    run_batches(DEL_EDGE.format(rel="DEP_VERSION_OF"),
                [e["id"] for e in g["version_of"]], EDGE_BATCH, "DEP_VERSION_OF")
    run_batches(DEL_EDGE.format(rel="DEP_MAINTAINS"),
                list(range(400_000_000, 400_001_000)), EDGE_BATCH, "DEP_MAINTAINS")

    node_ids = [n["id"] for key in ("repos", "packages", "versions") for n in g[key]]
    node_ids += list(range(50_000_000, 50_000_400))
    node_ids += list(range(900_000_000, 900_001_000))
    run_batches(DEL_NODE, sorted(set(node_ids)), NODE_BATCH, "nodes")

    # Sweep whatever the id lists missed.
    for label in LABELS:
        while True:
            n = count(label)
            if n <= 0:
                break
            try:
                rows = scalars(query(f"MATCH (n:{label}) RETURN n.id AS id LIMIT 400",
                                     timeout=200, page_size=400))
            except HydraError as exc:
                print(f"  {label} sweep read failed: {str(exc)[:140]}")
                break
            ids = [r[0] for r in rows if r and r[0] is not None]
            if not ids:
                break
            print(f"  sweep {label}: {n} left", flush=True)
            try:
                query(DEL_NODE, {"rows": [{"id": x} for x in ids]}, timeout=200)
            except HydraError as exc:
                print(f"  {label} sweep delete failed: {str(exc)[:140]}")
                break

    print(f"after: { {lbl: count(lbl) for lbl in LABELS} }  ({time.perf_counter()-t0:.1f}s)")


if __name__ == "__main__":
    main()
