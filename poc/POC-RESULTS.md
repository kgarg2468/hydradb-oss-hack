# Bitemporal npm dependency graph on HydraDB — PoC results

Question the graph has to answer: **which repos resolved a compromised package
version during incident window X**, for the 2025-09-08 chalk/debug npm
compromise.

| Gate | What it tests | Result |
|---|---|---|
| **Gate 1** — AS-OF correctness | HydraDB bitemporal query vs. an independent git-lockfile oracle | **PASS** — 128/128 full-set, 192/192 targeted, 0 mismatches |
| **Gate 2** — ingest throughput | ≥100k edges, measured edges/sec | **PASS** — 111,723 edges, 5,386 edges/sec |
| **Gate 3** — blast radius + maintainer graph | incident queries + p50/p95 latency over ≥20 runs | **PASS with a large caveat** — correct answers, but the natural query shape is 7.9 s p50; an id-anchored rewrite is 3.9 ms p50 |

Everything below was produced against the live node in container `hydradb-poc`
(HTTP `127.0.0.1:8443`, namespace `default`, graph `default`, cell `cell-0`).

---

## 1. Dataset

Eight real OSS repos, each with a committed npm/yarn lockfile and dense
2024–2025 history. Lockfiles carry the **full transitive closure**, which is the
whole point — a repo is exposed through packages it never names.

| repo | lockfile | snapshots | span |
|---|---|---|---|
| grafana/grafana | `yarn.lock` (berry) | 2,112 | 2024-01-02 … 2025-12-18 |
| storybookjs/storybook | `yarn.lock` → `code/yarn.lock` | 1,481 | 2024-01-02 … 2025-12-23 |
| apache/superset | `superset-frontend/package-lock.json` | 592 | 2024-01-09 … 2025-12-23 |
| webpack/webpack | `yarn.lock` | 304 | 2024-01-11 … 2025-12-25 |
| jitsi/jitsi-meet | `package-lock.json` | 241 | 2024-01-03 … 2025-12-29 |
| babel/babel | `yarn.lock` (berry) | 173 | 2024-01-08 … 2025-12-28 |
| facebook/react | `yarn.lock` | 77 | 2024-01-02 … 2025-11-07 |
| axios/axios | `package-lock.json` | 48 | 2024-01-03 … 2025-12-30 |

**5,028 lockfile snapshots** total. Parsers cover npm package-lock v1/v2/v3,
yarn classic and yarn berry (`lockparse.py`).

### Schema

```
(:DepRepo {id, name, slug})
(:DepPackage {id, name})
(:DepPackageVersion {id, pkg, version, key, compromised, known_compromised_from})
(:DepMaintainer {id, name})

(:DepRepo)-[:DEP_RESOLVES {id, valid_from, valid_to, tx_from, tx_to}]->(:DepPackageVersion)
(:DepPackageVersion)-[:DEP_VERSION_OF {id}]->(:DepPackage)
(:DepMaintainer)-[:DEP_MAINTAINS {id}]->(:DepPackage)
```

All timestamps are integer unix seconds. Open-ended intervals use the sentinel
`4102444800` (2100-01-01) because **HydraDB has no `IS NULL`**.

**Bitemporality.** *Valid time* is the interval a repo's committed lockfile
actually resolved a `(package, version)`, taken from git commit times. *Transaction
time* for a historical backfill is degenerate — every `DEP_RESOLVES` edge shares
one `tx_from` (the ingest run). The transaction-time axis that carries real
meaning here lives on `DepPackageVersion.known_compromised_from` = the moment the
compromise became public (2025-09-08T15:20Z, `4102444800` for clean versions), so
the graph can answer *"valid at T, as known at K"*:

```cypher
MATCH (r:DepRepo)-[e:DEP_RESOLVES]->(pv:DepPackageVersion)
WHERE pv.known_compromised_from <= $k AND e.valid_from <= $t AND e.valid_to > $t
RETURN r.name AS repo, pv.key AS pkgversion
```

---

## 2. Incident data — `incident-chalk-debug.json`

24 packages across two waves. Version list taken from the public write-ups
(Aikido, Semgrep, Wiz, Sonatype, Vercel), then **every publish timestamp was
verified against the npm registry's own `time` map**, which is authoritative and
survives unpublish. `build_incident.py` re-derives this live.

Wave 1 (Qix account takeover) — 19 packages published in a **8 minute 22 second
burst**:

| | package@version | published (UTC) |
|---|---|---|
| first | `ansi-styles@6.2.2` | 2025-09-08T13:12:10.343Z |
| | `debug@4.4.2` | 2025-09-08T13:12:39.973Z |
| | `chalk@5.6.1` | 2025-09-08T13:13:05.239Z |
| last | `backslash@0.2.1` | 2025-09-08T13:20:31.923Z |

Also: `supports-color@10.2.1`, `strip-ansi@7.1.1`, `ansi-regex@6.2.1`,
`wrap-ansi@9.0.1`, `color-convert@3.1.1`, `color-name@2.0.1`, `is-arrayish@0.3.3`,
`slice-ansi@7.1.1`, `error-ex@1.3.3`, `color-string@2.1.1`, `color@5.0.1`,
`simple-swizzle@0.2.3`, `supports-hyperlinks@4.1.1`, `has-ansi@6.0.1`,
`chalk-template@1.1.1`.

Wave 2: `proto-tinker-wc@0.1.87` (16:51Z), `duckdb@1.3.3`, `@duckdb/node-api@1.3.3`,
`@duckdb/node-bindings@1.3.3`, `@duckdb/duckdb-wasm@1.29.2` (2025-09-09 ~01:11Z).

Remediation: clean versions published 14:47:54Z – 15:14:43Z; malicious versions
unpublished. **All 24 malicious versions are confirmed absent from the registry's
`versions` map today** (verified programmatically).

Practical exposure window used throughout: **13:12:10Z – 15:30:00Z**.

---

## 3. Gate 2 — ingest throughput ✅

Batched `UNWIND`, batch size 1000, single-threaded HTTP client.

| phase | rows | seconds | rate |
|---|---|---|---|
| `DepPackage` nodes | 6,381 | 0.34 | 18,767 nodes/s |
| `DepPackageVersion` nodes | 24,938 | 1.47 | 16,915 nodes/s |
| `DEP_VERSION_OF` edges | 24,938 | 8.53 | 2,923 edges/s |
| `DEP_RESOLVES` edges | 86,319 | 12.12 | 7,119 edges/s |
| `DEP_MAINTAINS` edges | 466 | 0.14 | 3,256 edges/s |
| **total edges** | **111,723** | **20.8** | **5,386 edges/s** |

Nodes: 31,327 + 154 maintainers.

**Max batch size = 1024**, a hard admission-control limit:

```
client_query_batch_items rejected by admission control: actual 2000 exceeds limit 1024
```

Concurrency (`workers > 1`) was implemented but not used for the reported figure;
the single-threaded number is the one to quote.

---

## 4. Gate 1 — AS-OF correctness ✅

Two fully independent paths are compared:

- **graph** — HydraDB Cypher over `DEP_RESOLVES` intervals.
- **oracle** — `git log` for the newest lockfile commit at or before T, `git show`
  that blob, parse it fresh. Never touches the graph or the cached snapshot files.

```cypher
-- full resolved set for one repo, as of T
MATCH (r:DepRepo {id: $rid})-[e:DEP_RESOLVES]->(pv:DepPackageVersion)
WHERE e.valid_from <= $t AND e.valid_to > $t
RETURN pv.key AS k
```

| check | probes | agreement |
|---|---|---|
| full resolved-set equality (8 repos × 16 timestamps: 6 fixed anchors + 10 random instants per repo) | 128 | **128 / 128** |
| targeted "which version of incident package P at incident time" (8 repos × 24 packages) | 192 | **192 / 192** |
| **mismatches** | | **0** |

The probes produced **98 distinct `(repo, resolved-set)` answers**, so the query
is genuinely discriminating over time rather than trivially returning a constant.

### The incident answer: zero exposure, honestly

```cypher
MATCH (r:DepRepo)-[e:DEP_RESOLVES]->(pv:DepPackageVersion)
WHERE pv.compromised = 1 AND e.valid_from <= $t AND e.valid_to > $t
RETURN r.name AS repo, pv.key AS pkgversion
```

**0 rows** at T before, inside and after the window. This is a true negative, not
a bug, and it is confirmed independently: a scan of all 5,028 snapshots finds
**zero occurrences** of any of the 24 malicious `(package, version)` pairs, and
**0 of 24** malicious versions even exist as a `DepPackageVersion` node.

That is the correct real-world result. The malicious versions were live for
roughly two hours; exposure required *resolving a floating range during that
window*. A committed lockfile pinning a pre-incident version was never exposed —
which is precisely what an as-of query has to be able to prove.

**Two repos came close.** Last lockfile commit before the first malicious publish
(13:12:10Z), and the next one after:

| repo | last commit before | gap | next commit |
|---|---|---|---|
| **webpack/webpack** | 2025-09-08 12:03Z | **1.2 h** | 2025-09-09 11:42Z |
| **grafana/grafana** | 2025-09-08 11:06Z | **2.1 h** | 2025-09-08 19:01Z |
| apache/superset | 2025-09-05 17:27Z | 67.7 h | 2025-09-11 22:34Z |
| storybookjs/storybook | 2025-09-04 09:48Z | 99.4 h | 2025-09-10 21:16Z |
| axios/axios | 2025-09-04 06:33Z | 102.6 h | 2025-09-11 19:32Z |
| jitsi/jitsi-meet | 2025-09-03 13:07Z | 120.1 h | 2025-09-09 09:46Z |
| babel/babel | 2025-08-27 18:14Z | 283.0 h | 2025-09-09 15:01Z |
| facebook/react | 2025-08-25 15:02Z | 334.2 h | 2025-09-17 13:03Z |

webpack regenerated its lockfile **69 minutes before** the first malicious
publish and did not touch it again until after remediation. grafana's next
regeneration (19:01Z) landed ~3.5 h after the clean versions went out. Both
missed by hours, and the graph is what makes that provable rather than assumed.

---

## 5. Gate 3 — blast radius + maintainer graph ✅ (with a performance caveat)

### 5a. Audit scope

Exact exposure is empty, so the actionable question becomes *which repos were
carrying any version of an incident package and therefore needed auditing*.
**18 of 24 incident packages** were resolved somewhere in the org at incident time:

| package | repos | distinct versions in org |
|---|---|---|
| chalk | 8 | 11 |
| supports-color | 8 | 11 |
| debug | 8 | 10 |
| ansi-regex | 8 | 8 |
| strip-ansi | 8 | 8 |
| ansi-styles | 8 | 7 |
| wrap-ansi | 8 | 6 |
| color-convert | 8 | 3 |
| color-name, is-arrayish | 8 | 2 |
| error-ex | 8 | 1 |
| slice-ansi | 7 | 5 |
| supports-hyperlinks | 4 | 2 |
| color, color-string | 3 | 2 |
| simple-swizzle | 3 | 1 |
| has-ansi | 2 | 1 |
| chalk-template | 1 | 1 |

111 `(repo, incident-package)` pairs in scope. The id-anchored and label-scan
query shapes agreed on **all 18 packages** (0 disagreements).

### 5b. Maintainer reach

`(:DepMaintainer)-[:DEP_MAINTAINS]->(:DepPackage)` for the top 200 packages by
org-wide footprint: 154 distinct maintainers, 466 edges, fetched from
`https://registry.npmjs.org/<pkg>` (`maintainers` field), 0 errors.

The three-pattern join runs **natively** — this was the biggest positive surprise
of the PoC:

```cypher
MATCH (m:DepMaintainer)-[:DEP_MAINTAINS]->(p:DepPackage),
      (pv:DepPackageVersion)-[:DEP_VERSION_OF]->(p),
      (r:DepRepo)-[e:DEP_RESOLVES]->(pv)
WHERE e.valid_from <= $t AND e.valid_to > $t
RETURN DISTINCT m.name AS maintainer, r.name AS repo, p.name AS pkg
```

3,565 distinct triples in 4,785 ms. **139 of 154 maintainers reach all 8 repos**,
so "repos reached" saturates at this org size; ranking on the finer
`repo × package` surface is what actually discriminates:

| maintainer | repos | packages | repo×pkg pairs |
|---|---|---|---|
| **sindresorhus** | 8 | **34** | **265** |
| existentialism / hzoo / jlhwung / nicolo-ribaudo (babel) | 8 | 25 | 173 |
| xtuc | 8 | 14 | 112 |
| ljharb | 8 | 12 | 95 |
| isaacs | 8 | 9 | 72 |

And the incident-relevant one — **`qix`, the maintainer actually phished on
2025-09-08, reaches all 8/8 repos through `debug` alone** (35 distinct
`(repo, package, version)` triples), answered in **5.9 ms p50 / 8.2 ms p95** over
20 runs. `sindresorhus` (chalk, ansi-styles, and 32 more) is the single largest
concentration of trust in this graph.

### 5c. Latency — the headline caveat

30 runs each, same answer from both shapes:

| query | n | p50 | p95 | min |
|---|---|---|---|---|
| blast radius, **id-anchored** (`pkg=chalk`) | 30 | **3.9 ms** | **6.2 ms** | 3.5 ms |
| blast radius, **label-scan** (`pkg=chalk`) | 30 | 7,880.6 ms | 8,103.3 ms | 7,769.3 ms |
| compromised scan, whole graph | 30 | 7,881.1 ms | 7,981.5 ms | 7,803.7 ms |
| per-incident-package, id-anchored | 18 | 24.2 ms | 48.1 ms | 5.0 ms |
| per-incident-package, label-scan | 18 | 7,910.6 ms | 8,476.2 ms | 7,807.2 ms |
| maintainer reach (`qix`) | 20 | 5.9 ms | 8.2 ms | — |
| aggregation `RETURN pkg, count(*) ORDER BY n DESC LIMIT 15` | 1 | 8,848 ms | — | — |

**The id-anchored rewrite is 2,047× faster for an identical answer.**

```cypher
-- 7.9 s: property predicate forces a scan of all 86k DEP_RESOLVES edges
MATCH (r:DepRepo)-[e:DEP_RESOLVES]->(pv:DepPackageVersion)
WHERE pv.pkg = $pkg AND e.valid_from <= $t AND e.valid_to > $t
RETURN DISTINCT r.name AS repo, pv.version AS version

-- 3.9 ms: same answer, entered through a known Package id
MATCH (pv:DepPackageVersion)-[:DEP_VERSION_OF]->(p:DepPackage {id: $pid}),
      (r:DepRepo)-[e:DEP_RESOLVES]->(pv)
WHERE e.valid_from <= $t AND e.valid_to > $t
RETURN DISTINCT r.name AS repo, pv.version AS version
```

HydraDB has **no secondary property index**, so any `WHERE n.prop = ...` on a
label is O(all edges of that type). Every hot query must be entered through a
node id. This is the single most important thing for the build plan: the
application has to own a `name → id` mapping and resolve it before querying.
The same trick answers exact exposure for free — a compromised version that was
never resolved has no node at all, so the key→id map returns "not present"
without a query.

---

## 6. Cypher-subset problems encountered — complete list

Everything here was hit for real during this PoC. The first four are the ones
that shaped the schema.

### Blocking — forced a schema or query design change

1. **No secondary index.** Property predicates on a label scan every edge:
   7.9 s vs 3.9 ms id-anchored at 111k edges. *Workaround:* app-side `name → id`
   map, always enter through an id.
2. **No `IS NULL`.** Open-ended validity intervals cannot be `null`.
   *Workaround:* sentinel `valid_to = 4102444800`.
3. **No `IN`.** Cannot ask "any of these 24 packages" in one query.
   *Workaround:* 24 separate id-anchored queries. (`UNION` is capped by
   "arms must project the same columns" and cannot nest, so it does not help
   past a couple of arms.)
4. **`UNWIND … CREATE` requires an explicit relationship `id` from the row:**
   `UNWIND relationship CREATE properties require id: row.<field>`.
   *Workaround:* the app assigns a unique integer id to every edge — 111,723 of
   them — and must keep that id space collision-free forever.

### Blocking — no workaround inside the subset

5. **Bulk delete is not usable.** `MATCH (n:Label) DETACH DELETE n` exceeds a
   hard server-side cap that the client timeout cannot raise:
   `client_query_runtime exceeded query timeout after 30000 ms; limit is 30000 ms`.
6. **Delete throughput ≈ 3 nodes/sec** — against 16,915 nodes/sec for insert, a
   ~5,600× asymmetry. `DELETE` and `DETACH DELETE` are equally slow, and equally
   slow on nodes that have already had all their edges removed. Batches of 100
   time out. Deleting ~25k nodes was projected at ~100 minutes, so **the PoC
   could not clean the graph** and the final load was namespaced under fresh
   labels (`Dep*`) and a disjoint id space (base 1e9) instead. Batched edge
   deletion via anonymous endpoints does work, at ~90 edges/sec:
   `UNWIND $rows AS row MATCH ()-[e:REL {id: row.id}]->() DELETE e`.
7. **`UNWIND … MATCH … DELETE` rejects labels on node patterns:**
   `UNWIND batch node patterns do not support labels` — even though the
   *identical labelled form is accepted for `UNWIND … CREATE`*. This
   inconsistency is worth fixing; it forces untyped endpoint matching on the
   delete path.
8. **Only `cell-0` exists.** `cell-1` / `cell-2` / any other name returns
   `internal query execution error`, so a scratch partition is not an option for
   test isolation.

### Annoying — workaround was cheap

9. **`count(DISTINCT x)` unsupported** (`DISTINCT aggregate arguments are not
   executable`). *Workaround:* `RETURN DISTINCT` the tuple and fold client-side.
10. **No `min` / `max` aggregates** — only `count`, `sum`, `avg`, `collect`.
11. **Variable-length MATCH needs a fixed source id:**
    `variable-length MATCH requires a fixed source id`. No org-wide `*1..n` scan;
    the maintainer→repo traversal was expressed as an explicit 3-pattern join
    instead (which works well).
12. **Node-only `MATCH` needs an inline predicate**, and `WHERE` does not count:
    `MATCH (n) WHERE n.id < 10` → `node-only MATCH requires an id, label, or
    property predicate`. Labelling every node handled this and also isolated the
    pre-existing junk nodes (ids 1–5).
13. **`page_size` capped at 4096** (`client_query_page_size … exceeds limit 4096`),
    so every read that can return >4k rows must follow `next_cursor`.
14. **`UNWIND` batch capped at 1024 items.**
15. **No `CONTAINS` / `ENDS WITH`**; only `STARTS WITH`. Not needed here, but it
    rules out substring matching on package names.
16. **`RETURN *` unsupported**, `WITH` is pass-through only (no alias, filter or
    projection) — so no multi-stage pipelines inside one statement.
17. **Vertex upsert must be `MERGE` by id then `SET`;** folding properties into
    the `MERGE` pattern is rejected.

### Positive findings

- **Multi-pattern joins work natively**, including the 3-pattern
  maintainer → package → version → repo join with a shared binding. This was not
  obvious from the docs and it is what makes the maintainer graph viable.
- Batched `UNWIND` ingest is genuinely fast (17k nodes/s, 7.1k edges/s).
- Interval predicates on relationship properties (`e.valid_from <= $t AND
  e.valid_to > $t`) work exactly as needed, including with parameters — the
  bitemporal core of this design is well supported.
- Server-side `count(*)` + `ORDER BY` + `LIMIT` aggregation works.

---

## 7. Honest caveats

- **Zero compromised versions were found.** The headline query returns empty.
  This is the correct answer for lockfile-pinned repos, and the AS-OF machinery
  is validated by 320 oracle comparisons rather than by the incident query alone.
  A dataset that actually contains a hit would need a repo that ran `npm install`
  inside the 2-hour window and committed the result; none of the 8 did.
- **Transaction time is degenerate for a backfill.** All `DEP_RESOLVES` edges
  share one `tx_from`. The meaningful "as known at K" axis is carried by
  `known_compromised_from` on `DepPackageVersion`. A production system ingesting
  live would get a real transaction-time axis for free.
- **`DEP_MAINTAINS` edges are not bitemporal.** The npm registry exposes only
  *current* maintainers, so maintainer reach is a present-tense overlay on a
  historical graph. Reading "qix reached 8 repos at incident time" strictly, it
  means *the packages qix maintains today* were resolved by 8 repos at that time.
- **Snapshot granularity is the lockfile commit.** State between two commits is
  assumed constant. That is the intended semantics, and the oracle uses the same
  rule, so the agreement figure does not paper over it.
- **The graph still contains ~24k orphaned nodes** from an earlier trial load,
  under the old `Repo` / `Package` / `PackageVersion` labels, because deletion was
  too slow to complete (finding 6). They are edgeless and carry different labels
  from the final `Dep*` dataset, so they do not affect any result above; they do
  occupy the store.
- **Storybook's lockfile moved** from `code/yarn.lock` to a root `yarn.lock`,
  leaving a 312-byte workspace stub behind. Choosing "first candidate path that
  exists" silently produced empty snapshots and 30 false mismatches on the first
  Gate 1 run. Both the extractor and the oracle now pick the candidate path with
  the most entries. Worth remembering for any repo-history ingestion.
- Latency numbers are single-client, warm, against a local single-node Docker
  container; they measure query shape, not a deployment.

---

## 8. Reproducing

```bash
cd poc

# 1. clone the 8 repos (blobless partial clones, ~550 MB)
./clone_repos.sh

# 2. walk lockfile history -> snapshots/<repo>.jsonl.gz  (~40 min, network bound)
for r in axios babel grafana jitsi-meet webpack superset react storybook; do
  SINCE=2024-01-01 UNTIL=2025-12-31 python3 extract_history.py "$r" &
done; wait

# 3. incident data, verified live against the npm registry
python3 build_incident.py                 # -> incident-chalk-debug.json

# 4. build the bitemporal payload
python3 build_graph.py                    # -> graph.json.gz

# 5. find the batch ceiling, then ingest  (Gate 2)
python3 ingest.py probe
python3 ingest.py run 1000 1              # -> ingest-report.json

# 6. maintainer overlay
python3 fetch_maintainers.py 200          # -> maintainers.json
python3 ingest.py maintainers 1000 1

# 7. gates
python3 gate1_asof.py                     # -> gate1-report.json   (~9 min)
python3 gate3_blast.py                    # -> gate3-report.json   (~13 min)

# optional: remove everything this PoC created (slow - see finding 6)
python3 wipe.py
```

Single query by hand:

```bash
curl -sS http://127.0.0.1:8443/v1/graphs/default/query \
  -H "Authorization: Bearer local-development-token-32-bytes" \
  -H 'X-Graph-Namespace: default' -H 'Content-Type: application/json' \
  --data '{"cell_id":"cell-0","page_size":4000,
           "parameters":{"t":1757339000},
           "query":"MATCH (r:DepRepo)-[e:DEP_RESOLVES]->(pv:DepPackageVersion) WHERE pv.compromised = 1 AND e.valid_from <= $t AND e.valid_to > $t RETURN r.name AS repo, pv.key AS pkgversion"}'
```

### Files

| file | role |
|---|---|
| `clone_repos.sh` | blobless clones of the 8 repos |
| `lockparse.py` | package-lock v1/v2/v3, yarn classic, yarn berry parsers |
| `extract_history.py` | git lockfile history → snapshots |
| `build_incident.py` | incident package list + registry-verified timestamps |
| `build_graph.py` | snapshots → bitemporal intervals → `graph.json.gz` |
| `hydra.py` | HydraDB HTTP client with cursor pagination |
| `ingest.py` | batched `UNWIND` ingest, batch probe, throughput report |
| `fetch_maintainers.py` | npm registry maintainer overlay |
| `gate1_asof.py` | AS-OF correctness vs. independent git oracle |
| `gate3_blast.py` | blast radius, maintainer reach, latency |
| `wipe.py` | teardown (documents the deletion limits) |
