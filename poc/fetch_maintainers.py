#!/usr/bin/env python3
"""Fetch CURRENT npm maintainers for the top-N packages in the graph.

"Top" = packages with the most distinct resolved versions across the org, which
is a decent proxy for how load-bearing a package is. Writes maintainers.json.

Only the registry's `maintainers` field is used, and it is a *current* snapshot
(the registry exposes no history), so these edges are deliberately not
bitemporal. That asymmetry is called out in POC-RESULTS.md.
"""

import collections
import concurrent.futures
import gzip
import json
import os
import sys
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
TOP_N = int(sys.argv[1]) if len(sys.argv) > 1 else 200


def registry_maintainers(pkg):
    url = "https://registry.npmjs.org/" + urllib.request.quote(pkg, safe="@")
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=40) as fh:
            doc = json.load(fh)
    except Exception as exc:
        return pkg, None, str(exc)[:120]
    names = []
    for m in doc.get("maintainers") or []:
        if isinstance(m, dict) and m.get("name"):
            names.append(m["name"])
        elif isinstance(m, str):
            names.append(m.split(" <")[0])
    return pkg, sorted(set(names)), None


def main():
    with gzip.open(os.path.join(HERE, "graph.json.gz"), "rt") as fh:
        g = json.load(fh)

    # Rank packages by distinct resolved versions, then by repos touching them.
    versions_per_pkg = collections.Counter()
    for v in g["versions"]:
        versions_per_pkg[v["pkg"]] += 1
    pv_pkg = {v["id"]: v["pkg"] for v in g["versions"]}
    repos_per_pkg = collections.defaultdict(set)
    for r in g["resolves"]:
        repos_per_pkg[pv_pkg[r["d"]]].add(r["s"])

    ranked = sorted(
        versions_per_pkg,
        key=lambda p: (-len(repos_per_pkg[p]), -versions_per_pkg[p], p),
    )
    top = ranked[:TOP_N]
    print(f"fetching maintainers for top {len(top)} of {len(versions_per_pkg)} packages")

    out = {}
    errors = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
        for i, (pkg, names, err) in enumerate(ex.map(registry_maintainers, top)):
            if err:
                errors[pkg] = err
            else:
                out[pkg] = names
            if (i + 1) % 50 == 0:
                print(f"  {i+1}/{len(top)}", flush=True)

    distinct = sorted({m for names in out.values() for m in names})
    print(f"got maintainers for {len(out)} packages, {len(errors)} errors, "
          f"{len(distinct)} distinct maintainers")
    if errors:
        print("  sample errors:", list(errors.items())[:3])

    with open(os.path.join(HERE, "maintainers.json"), "w") as fh:
        json.dump({"top_n": TOP_N, "packages": out, "errors": errors}, fh, indent=2)
    print("wrote maintainers.json")


if __name__ == "__main__":
    main()
