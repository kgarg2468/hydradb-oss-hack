# Hindsight benchmark results

## The headline

> **Org-wide exposure-as-of — "which repositories in the org had a lockfile
> resolving this compromised package at instant T, and was any of those
> versions a malicious one" — across 100 repos / 950,241 interval edges:
> p95 = 36.3 ms** (warm, single node, local-directory object storage).

Full qualifying context, because every one of these changes the number:

- **warm** = after 5 warmup runs; n = 30 measured runs. The first query against a
  freshly restarted node is **568 ms**, 17x slower. See [Cold vs warm](#cold-vs-warm).
- **single node**, one cell, no replication, no concurrent load.
- **local object storage** — a directory on the Mac's SSD, *not* S3. This
  understates a real deployment; see [Threats to validity](#threats-to-validity).
- **100 repositories is the largest corpus in the linear regime.** This query
  degrades sharply above ~1 M edges: 308 ms at 150 repos, 5,277 ms at 250. That
  is a real finding, it is bisected below, and it is not hidden:
  [The cliff above ~1 M edges](#the-cliff-above-1-m-edges).
- the corpus is **synthetic**, replayed from 86,380 real lockfile intervals; the
  real-data corpus is 9 repositories and answers in **8.1 ms p95**.

A second result worth the same attention: the **version-anchored** form of the
same question stays flat all the way to 250 repositories — **46.3 ms p95 across
250 repos / 2,364,161 edges** — and it is the shape the product should ship for
large orgs.

---

## Environment

Every number below came from one machine and one node. Nothing is extrapolated.

| | |
|---|---|
| Machine | MacBook Pro, `Mac17,2` |
| Chip | Apple M5, 10 cores (4 performance / 6 efficiency) |
| Memory | 32 GB |
| OS | macOS 26.2, `macOS-26.2-arm64-arm-64bit` |
| Python | 3.12.2 (`/tmp/hs-venv`) |
| Docker | Server 27.4.0; VM has 10 CPUs / 8,217,968,640 B (7.65 GiB) |
| HydraDB image | `ghcr.io/hydra-db/hydradb@sha256:db78309a233be54662db29744047e985a39b51c45a270d1a1f47c31a62cdb709` |
| Container | `hydradb-poc`, single node `node-0`, one cell `cell-0` |
| Object storage | `CLOUD_PROVIDER=local`, `LOCAL_PATH=/data/store` — **a local directory on the Mac's SSD, not S3** |
| Endpoint | `http://127.0.0.1:8443`, namespace `default`, graph `default` |
| Node fill at measurement time | 3.6 GB store + 1.0 GB cache after compaction (13.6 GB peak during seeding) |

The client is `hindsight.client.HydraClient` over plain `urllib` — one HTTP
connection per request, no pooling, no keep-alive. That overhead is inside every
number reported here.

---

## Corpora

| corpus | labels | repos | packages | versions | maintainers | nodes | RESOLVES interval edges | all edges | real? |
|---|---|---:|---:|---:|---:|---:|---:|---:|---|
| demo | `Replay*` | 9 | 6,383 | 24,959 | 154 | 31,505 | 86,380 | 111,805 | 8 real repos + 1 synthetic |
| N10 | `BenchN10*` | 10 | 6,383 | 24,959 | 154 | 31,506 | 86,441 | 111,866 | synthetic replay |
| N50 | `BenchN50*` | 50 | 6,383 | 24,959 | 154 | 31,546 | 449,227 | 474,652 | synthetic replay |
| N100 | `BenchN100*` | 100 | 6,383 | 24,959 | 154 | 31,596 | 950,241 | 975,666 | synthetic replay |
| N150 | `BenchN150*` | 150 | 6,383 | 24,959 | 154 | 31,646 | 1,410,721 | 1,436,146 | synthetic replay |
| N250 | `BenchN250*` | 250 | 6,383 | 24,959 | 154 | 31,746 | 2,364,161 | 2,389,586 | synthetic replay |

**What "synthetic replay" means, precisely.** The 86,380 interval facts in the
demo dataset are real: they come from walking 5,028 committed lockfiles across
eight OSS repositories, and Gate 1 of the PoC validated them 320/320 against an
independent git oracle. A synthetic repository takes *one real repository's
complete interval set* and shifts the whole timeline by a deterministic offset
(0, ±5, ±7, ±11, ±13, ±17, ±19, ±23, ±29, ±31, ±37, ±43 days), so it churns its
lockfile at different moments the way a different team would. Sources are
assigned round-robin, so a synthetic org's repo-size distribution is exactly the
observed distribution of the nine sources — one storybook-sized monorepo
(50,358 intervals) per nine repositories, median 3,264.

Nothing about the *shape* of the data is invented: closure sizes, churn rates,
package co-occurrence and interval lengths are all measured. What **is**
invented is the claim that 250 repositories would resolve this particular
overlapping set of packages — see [Threats to validity](#threats-to-validity).

Corpus edge counts are exact, not sampled. N250's 2,364,161 = 27 × 86,380 (27
full round-robin cycles) + 31,901 (the seven sources of the remainder);
N150's 1,410,721 = 16 × 86,380 + 28,641. The harness's own
`resolves_edge_count` scan independently confirmed the N10 / N50 / N100 figures
(86,441 / 449,227 / 950,241).

### Isolation

HydraDB has no per-label id space: `MERGE (n:BenchN250Pkg {id: $x})` matches
whichever node already carries `$x` under *any* label and adds the new label to
it. Since `hindsight.ids` derives ids from names, a naive seed of a package
called `debug` would have landed on the demo dataset's `debug` node. Every
benchmark corpus therefore salts its id space (`benchmarks/corpus.py`,
`SaltedRegistry`). Verified against the node after seeding:

```
ReplayPkg 6383 (unchanged)   ReplayVer 24959 (unchanged)   ReplayMaint 154 (unchanged)
package_id("debug") = 3873859005066682513 -> under ReplayPkg,   absent under BenchN10Pkg
salted debug id     = 6212244960122109735 -> under BenchN10Pkg, absent under ReplayPkg
```

Nothing in `benchmarks/` deletes, and nothing writes outside `BenchN*`.

---

## Scaling

All corpora measured in a single session against the same node state, so this is
a scaling curve and not six unrelated runs. Warm = after 5 warmup runs.
Percentiles are **nearest-rank** — p95 of 30 runs is the 29th slowest run, a
value that was actually measured, never an interpolation.

### Exposure-as-of, package-anchored (the console's shipped query, **the headline**)

`hindsight_web.service.Console.exposure`: `package_exists`, then
`repos_resolving_package`, then classification of every repository in the org
against the incident's malicious-version list. Package = `debug`, a wave-1
compromised package resolved by every repository in the corpus — the worst case,
not the best. T = 2025-09-08T14:05:00Z.

| corpus | repos | RESOLVES edges | rows | n | p50 ms | **p95 ms** | p99 ms | process-cold ms | regime |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| demo | 9 | 86,380 | 36 | 30 | 7.03 | 8.07 | 8.46 | 7.18 | linear |
| N10 | 10 | 86,441 | 37 | 30 | 7.56 | 8.94 | 9.14 | 7.01 | linear |
| N50 | 50 | 449,227 | 197 | 30 | 18.71 | 21.52 | 23.60 | 20.44 | linear |
| **N100** | **100** | **950,241** | 392 | 30 | 34.13 | **36.34** | 39.73 | 35.20 | **linear — headline** |
| N150 | 150 | 1,410,721 | 592 | 30 | 307.80 | 339.34 | 378.99 | 290.90 | degraded |
| N250 | 250 | 2,364,161 | 988 | 18 | 5,171.88 | 5,276.59 | 5,276.59 | 5,144.20 | degraded |

**Shape.** Sub-linear in edges up to ~0.95 M — 86k → 950k edges is 11x the data
for 4.5x the latency — and then a regime change. Fitted as a power law
`latency ∝ edges^k` between adjacent points:

| segment | edge ratio | latency ratio | exponent k |
|---|---:|---:|---:|
| 86k → 449k | 5.20x | 2.67x | 0.60 |
| 449k → 950k | 2.11x | 1.82x | 0.80 |
| **950k → 1.41 M** | **1.48x** | **9.02x** | **5.55** |
| 1.41 M → 2.36 M | 1.68x | 16.80x | 5.44 |

Two clean regimes. **Linear or better up to 100 repositories / 950,241 RESOLVES
edges; the knee is between 100 and 150 repositories — between 950,241 and
1,410,721 edges of one relationship type.** We did not narrow that bracket
further (N150 was the one bisection point the schedule allowed; each additional
corpus costs 8–14 minutes to seed).

**Past the knee it keeps degrading, at the same rate.** Both post-knee segments
fit the same exponent — ~5.5 whether measured against edge count or repository
count, since edges grow linearly in repos here. This matters operationally: it
is *not* a one-off step onto a higher plateau that you could provision for and
then forget. Each further 1.5x of corpus costs another order of magnitude, so
past ~1 M edges of a relationship type this query shape has no usable headroom
at all — 36 ms, then 339 ms, then 5.3 s, and nothing in the data suggests the
next point is any kinder.

### Incident sweep, version-anchored — flat to 250 repositories

24 malicious versions from `poc/incident-chalk-debug.json`, one id-anchored
`repos_resolving_version` per version. 13 of the 24 have a node in the graph;
the other 11 are answered as proven absences by an id probe. Same answer as the
package-anchored route — 7 exposed repositories at N250 by either.

| corpus | repos | RESOLVES edges | rows | exposed repos | n | p50 ms | **p95 ms** | p99 ms | process-cold ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| demo | 9 | 86,380 | 13 | 1 | 30 | 21.47 | 25.12 | 27.96 | 21.04 |
| N10 | 10 | 86,441 | 13 | 1 | 30 | 24.17 | 28.26 | 28.86 | 26.02 |
| N50 | 50 | 449,227 | 26 | 2 | 30 | 28.54 | 32.14 | 42.71 | 24.73 |
| N100 | 100 | 950,241 | 39 | 3 | 30 | 29.06 | 31.75 | 33.35 | 36.73 |
| N150 | 150 | 1,410,721 | 65 | 5 | 30 | 33.01 | 55.95 | 89.75 | 113.11 |
| N250 | 250 | 2,364,161 | 91 | 7 | 30 | 35.30 | **46.27** | 54.93 | 1,476.95 |

**27x the edges and 28x the repositories buys 1.8x the latency.** The cost is 24
fixed round trips, not corpus size. This shape does not cross the cliff.

### The other query families, same session (p95 ms)

| operation | demo (9) | N10 | N50 | N100 | N150 | N250 |
|---|---:|---:|---:|---:|---:|---:|
| exposure-as-of, **scrub** (T differs every run) | 9.56 | 8.95 | 20.26 | 36.66 | 350.92 | 5,248.18 |
| exposure-as-of, **engine only** (one statement) | 7.25 | 7.74 | 19.45 | 33.03 | 323.86 | 5,424.16 |
| **blast radius** (repos + versions + maintainers) | 8.83 | 9.88 | 24.07 | 40.83 | 441.49 | 5,492.41 |

The scrub row answers "you are just measuring one warm cache entry". It re-runs
the headline query at a **different instant on every run**, spread across the
whole ingested span (2024-03-01 … 2025-11-01), so no two runs can share a
result. It matches the fixed-T row at every corpus size to within noise. There
is no result cache in play.

---

## Cold vs warm

Three different things get called "cold". Conflating them is the easiest way to
publish a dishonest benchmark, so all three are reported separately.

| kind | what is cold | where |
|---|---|---|
| **process-cold** | fresh Python process; console caches empty | `process-cold ms` column above |
| **node-cold** | `docker restart hydradb-poc`; the engine's own caches are gone | table below |
| **application cache hit** | the ranking answer is memoised in the web process — a dict lookup, not a query | maintainer table below |

### Node-cold: first query after a container restart

```
benchmarks/bench_blast_radius.py coldstart --corpora real 100 250
```

| corpus | repo directory (first read) | **node-cold exposure** | second call | cold penalty |
|---|---:|---:|---:|---:|
| demo (9 repos) | 70.30 ms | **236.82 ms** | 7.75 ms | **30.6x** |
| N100 | 25.86 ms | **568.46 ms** | 33.20 ms | **17.1x** |
| N250 | 56.28 ms | 6,703.83 ms | 5,799.02 ms | 1.2x |

The node became ready 1.0 s after `docker restart`. **A demo's very first query
costs a quarter of a second, not eight milliseconds.** Any sub-10 ms claim is a
claim about the second query onwards and must say so. Process-cold, by contrast,
is indistinguishable from warm (7.18 vs 7.03 ms at 9 repos) — the console holds
no query-result cache, so a fresh process has nothing to miss.

### Maintainer reach — where the big cold/warm gap actually lives

Measured in an earlier pass with `runs=50, warmup=5`, when the node held less
total data. The control pass re-measured the exposure family and reproduced it
to within noise (demo p95 7.75 → 8.07 ms, N100 35.91 → 36.34 ms), which is the
evidence offered that the two passes are comparable.

| corpus | one account (widest reach) p50 / p95 | ranked sweep **UNCACHED** p50 / p95 | ranked sweep **CACHE HIT** p50 |
|---|---|---|---|
| demo (9) | 365.0 / 409.0 ms (n=50) | 2,518.9 / 2,907.8 ms (n=50) | 0.000 ms |
| N10 | 364.8 / 433.8 ms (n=50) | 2,579.7 / 2,843.0 ms (n=50) | 0.000 ms |
| N50 | 1,594.8 / 1,812.5 ms (n=50) | 12,407.2 / 14,089.3 ms (n=15) | 0.000 ms |
| N100 | 2,884.2 / 2,972.5 ms (n=50) | 21,574.8 / 22,676.5 ms (n=9) | 0.000 ms |
| N250 | 28,751.4 / 28,958.4 ms (n=6) | **does not complete** — below | — |

**The 2.4 s / 1.3 ms gap reported by earlier work is an application cache, not
the database.** The CACHE HIT column is a Python dict lookup in the web process;
it reads 0.000 ms because that is what it is, and it is labelled CACHE HIT so it
can never be quoted as a query latency. The honest cost of a maintainer ranking
when the scrubber moves to a new instant is the UNCACHED column: **2.5 s at 9
repositories, 21.6 s at 100.**

**At 250 repositories the ranked sweep does not produce a complete answer.** One
sweep took 302,170 ms and **20 of 154 accounts were refused by the engine**:

```
HTTP 408 {"error":{"code":"query_timeout",
  "message":"cypher_metadata_hydration exceeded query timeout after 30000 ms; limit is 30000 ms"}}
HTTP 408 {"error":{"code":"query_timeout",
  "message":"cypher_relationship_edge_records exceeded query timeout after 30000 ms; limit is 30000 ms"}}
```

Reported as a single observation, not a percentile; the harness records
`complete_answer: false` in the JSON. An operation that cannot finish is not a
slow operation, it is a broken one, and the table says so.

---

## The cliff above ~1 M edges

The package-anchored query goes from 36.3 ms at 950,241 edges to 339.3 ms at
1,410,721 and 5,276.6 ms at 2,364,161. Here is what it is and what it is not.

### It is not global node degradation — it reproduces

Every smaller corpus was re-measured in the same session, minutes after the N250
run, on a node holding all 5.3 M edges:

| corpus | p95, first pass | p95, control pass |
|---|---:|---:|
| demo (9) | 7.75 ms | 8.07 ms |
| N10 | 7.41 ms | 8.94 ms |
| N50 | 21.18 ms | 21.52 ms |
| N100 | 35.91 ms | 36.34 ms |

Unchanged. The node is fine; the large-corpus *query* is not.

### It is not memory, and it is not I/O

Sampled from `docker stats` **during** a 5,391 ms N250 query:

```
515.4MiB / 7.654GiB | CPU 136.36%
539.8MiB / 7.654GiB | CPU 135.56%
```

The container is using **0.5 GiB of an available 7.65 GiB** and burning ~1.4
cores. That is ~7.3 CPU-seconds of compute to return 988 rows. The latency
distribution is also far too tight for I/O misses — 35 runs spanned
5,241–5,312 ms, a 1.3 % range — and the first run is indistinguishable from the
18th (cold 5,144 ms vs p50 5,172 ms), so nothing is warming up. **CPU-bound
materialisation, not paging and not disk.**

### The engine materialises the whole match before it pages

Asking for one row costs the same as asking for all of them:

| page_size | N100 | N250 |
|---|---:|---:|
| 1 | 459.8 ms | 5,696.2 ms |
| 64 | 26.2 ms | 5,472.7 ms |
| 4096 (all rows) | 27.8 ms | 5,493.1 ms |

So the cost is not in producing rows. It is a fixed cost paid before the first
row exists.

### It is the multi-pattern expansion, and entering by id avoids it

Component timings, best of 3:

| statement | N100 | N250 |
|---|---:|---:|
| `package_exists` — `MATCH (p:Pkg {id: $pid})` | 1.0 ms | 0.9 ms |
| `repos_resolving_version` — one `Ver` bound **by id** | 3.8 ms (55 rows) | **9.0 ms (139 rows)** |
| `resolves_edge_count` — one `Repo` bound **by id** | 798.1 ms | 784.6 ms |
| `repos_resolving_package` — `(v)-[:VERSION_OF]->(p {id}), (r)-[e:RESOLVES]->(v)` | 31.6 ms | **5,164.3 ms** |

Anything entered through an id is fine at 2.36 M edges. What degrades is the
*two-pattern join*, where the engine binds a `Pkg` by id, expands every `Ver` of
it, and then expands every incoming RESOLVES edge of each `Ver`. Cost tracks the
number of `Ver` nodes the first pattern binds — measured at N250:

| package | version nodes | join | rows |
|---|---:|---:|---:|
| `left-pad` | 1 | 89.5 ms | 0 |
| `backslash` | 2 | 237.0 ms | 28 |
| `color-name` | 2 | 1,356.4 ms | 445 |
| `is-arrayish` | 4 | 1,277.8 ms | 333 |
| `webpack` | 24 | 3,607.4 ms | 306 |
| `chalk` | 18 | 4,766.6 ms | 1,044 |
| `debug` | 17 | 5,311.1 ms | 988 |

The same 17-version fan-out costs 31.6 ms at N100 and 5,164.3 ms at N250: about
1.9 ms per bound version node against about 304 ms — 160x for 2.5x the edges of
that relationship type.

### Attribution

**Established by measurement:** the degradation is real and reproducible; it is
confined to the join-bound expansion of a relationship type and not to
id-anchored reads; it begins between 950,241 and 1,410,721 edges of a single
relationship type; above that it follows `latency ∝ edges^5.5` across both
measured segments; it is CPU-bound at ~1.4 cores with 0.5 GiB resident; and it
is paid in full before the first row is produced.

**Hypothesis, not established:** this looks like a per-query materialisation of
the relationship type's edge records whose cost is super-linear in the type's
size — the engine's own timeout messages name `cypher_relationship_edge_records`
and `cypher_metadata_hydration` as the stages that exceed 30 s. A GraphBLAS-style
adjacency materialisation that stops fitting a fast path above ~1 M edges would
produce exactly this signature. **We did not read the engine source, did not
profile inside the container, and did not test whether a larger container or a
different cell configuration moves the knee.** Anyone quoting the mechanism
should treat it as unattributed; only the *behaviour* above is measured.

**Actionable form of the bug report:** on a single-node HydraDB at
`ghcr.io/hydra-db/hydradb@sha256:db78309a…`, `MATCH (v:V)-[:R1]->(p:P {id: $x}),
(r:R)-[e:R2]->(v) RETURN DISTINCT …` costs 31.6 ms when `R2` holds 950,241 edges
and 5,164.3 ms when it holds 2,364,161, while the id-anchored
`MATCH (r:R)-[e:R2]->(v:V {id: $y})` over the same data stays at 9.0 ms.

### The mitigation is already in the product's grain

The incident question does not need the package-anchored shape.
`hindsight.ids.version_id(package, version)` is a hash, so the application
already knows the id of every malicious version without a lookup, and
`repos_resolving_version` enters through it. That is the version-anchored sweep
above: flat to 250 repositories, same answer.

What the package-anchored query buys that the version-anchored one does not is
the *negative* — "you resolved chalk 5.6.0, which is not on the list, and had
pinned it four days before the attack". That is the console's most valuable
output and it is the shape that degrades. Resolving a package's version ids in
the application and issuing one anchored read per version is the top follow-up.

---

## Ingest throughput

Measured on the run that actually wrote each corpus. Not re-measurable
afterwards: ids are deterministic and the writer is `MERGE`-based, so a second
run over the same corpus writes nothing.

| corpus | edge rows sent | edge-write seconds | **edges/sec** | wall seconds | batch | chunks |
|---|---:|---:|---:|---:|---:|---:|
| N10 | 111,866 | 22.1 | **5,060** | 23.7 | 1000 | 1 |
| N50 | 525,502 | 113.8 | **4,617** | 119.4 | 1000 | 3 |
| N100 | 1,077,366 | 256.1 | **4,207** | 267.7 | 1000 | 5 |
| N150 | 1,614,121 | 444.2 | **3,634** | 461.2 | 1000 | 8 |
| N250 | 2,694,686 | 824.8 | **3,267** | 853.1 | 1000 | 13 |

**Throughput degrades 35 % as the graph grows from 0.1 M to 5.3 M edges**
(5,060 → 3,267 edges/sec). Row counts are rows *sent*: package, version and
maintainer nodes are re-sent once per chunk and deduplicated by `MERGE`, so
these are the writer's real workload rather than the distinct-edge total.

For reference, the PoC measured 5,386 edges/sec with `CREATE` on a near-empty
node; this writer uses `MERGE` (about a third slower) to buy idempotency and
in-place interval closing, which on an append-only store that deletes at ~3
nodes/sec is not a close call.

---

## Threats to validity

Ordered worst first. A judge should attack these before anything else.

1. **Local-directory object storage, not S3. This is the worst one.** The node
   runs with `CLOUD_PROVIDER=local` and `LOCAL_PATH=/data/store` — a directory
   on the Mac's internal SSD reached through a Docker bind mount. Real
   deployments of a disaggregated store put S3 or equivalent on that path, where
   a cache miss costs tens of milliseconds of network round trip rather than
   microseconds of NVMe. **Every latency here understates a real deployment, and
   the understatement is largest exactly where it hurts: cold reads, and any
   case that misses cache.** Read the 236 ms node-cold figure as a floor, not an
   estimate. We have not measured against S3 at all.

2. **The synthetic corpora hold repository count constant against package
   count.** Every synthetic repository replays one of nine real dependency
   closures, so `Pkg` and `Ver` node counts stay pinned at 6,383 / 24,959 at
   every corpus size. A real org growing to 250 repositories would carry many
   more distinct packages, and this curve says nothing about that axis. The high
   package overlap also inflates org-wide fan-out (pessimistic, good) while
   keeping the package/version node space small (optimistic, bad). **The curve
   isolates "more repositories resolving the same packages" and only that.**

3. **The cliff is bracketed, not located, and the bracket is machine-specific.**
   It begins somewhere between 950,241 and 1,410,721 edges *on this container*.
   One bisection point (N150) was affordable; each further corpus costs 8–14
   minutes to seed. We do **not** know whether the knee is a configurable buffer,
   nor whether it moves with more RAM or more CPUs — the container was never
   resized, and the memory evidence above says only that the *symptom* is not
   memory pressure at 7.65 GiB, not that the *threshold* is memory-independent.
   The `^5.5` exponent is fitted from two segments and should not be
   extrapolated past 2.36 M edges.

4. **Single node, single cell, no replication, no concurrent load.** One
   `node-0`, one `cell-0`, one benchmark client. No quorum write path, no
   cross-node fan-out, no other tenant, and no concurrent reader except inside
   the maintainer sweep — which is precisely where the engine began refusing
   queries. Every number is a best case for contention.

5. **The maintainer numbers come from a different pass than the exposure
   numbers,** taken when the node held less total data. The control pass
   reproduced the exposure family to within noise, which is the evidence offered
   that the passes are comparable; the maintainer rows themselves were not
   re-run.

6. **Small samples where the operation is slow.** `n` is on every row and is not
   always 30 or 50: a 90 s (control) or 180 s (full suite) wall-clock budget caps
   measured runs, so N250's package-anchored rows are n=18 and the N100
   maintainer sweep is n=9. **p99 over 9 runs is simply the slowest run** — treat
   those cells as "worst observed", not as a percentile.

7. **The transitive closure is not traversed at query time.** "Blast radius
   including the transitive closure" sounds like a graph traversal and is not one
   here: an npm lockfile already contains the fully resolved closure, so it is
   materialised at ingest and one hop finds it. That is a legitimate design
   choice and a real advantage, but a judge expecting a variable-length traversal
   benchmark is not getting one. HydraDB also has no `shortestPath` and no
   `IN` / `CONTAINS` / `IS NULL`, which constrains what could be written.

8. **One package, one instant, for the package-anchored rows.** They use `debug`
   at 2025-09-08T14:05:00Z. `debug` is deliberately the worst case (resolved by
   every repository, 17 version nodes) and the scrub row varies the instant — but
   the package is not varied within a run, and the per-package table above shows
   the spread is wide (89 ms to 5,311 ms at N250, depending on version fan-out).

9. **`Replay*` includes one synthetic repository.** `acme/checkout-web` is
   constructed, because none of the eight real repositories regenerated a
   lockfile inside the two-hour compromise window. It is 61 of 86,380 intervals
   and is flagged `synthetic = 1` in the graph — but it is the reason the demo
   corpus has any exposed repository at all.

10. **Percentile method.** Nearest-rank, never interpolated. Stated because it is
    *unusual*, not because it flatters: interpolation would generally report a
    slightly lower p95 here.

---

## Reproducing

Node running (`scripts/start-hydradb.sh`) and the `Replay*` demo dataset seeded
(`python3 scripts/demo-seed.py --execute`), since the synthetic corpora are
replayed from it.

```bash
/tmp/hs-venv/bin/python --version          # 3.12.2

# 1. seed the synthetic corpora (append-only; safe to re-run, writes nothing twice)
for n in 10 50 100 150 250; do
  /tmp/hs-venv/bin/python benchmarks/bench_blast_radius.py seed --size "$n" \
      --out "benchmarks/results/seed-n$n.json"
done
# ~29 min total, ~14 GB of store before compaction

# 2. full suite per corpus (includes the maintainer sweep; slow at N100+)
/tmp/hs-venv/bin/python benchmarks/bench_blast_radius.py measure --corpus real \
    --runs 50 --warmup 5 --out benchmarks/results/measure-real.json

# 3. the controlled scaling curve: same node state, exposure family only
for c in real 10 50 100 150 250; do
  /tmp/hs-venv/bin/python benchmarks/bench_blast_radius.py measure --corpus "$c" \
      --runs 30 --warmup 5 --budget-s 90 --skip-edge-count --skip-maintainers \
      --out "benchmarks/results/control-$c.json"
done

# 4. node-cold: restarts the container, then one measured call per corpus
/tmp/hs-venv/bin/python benchmarks/bench_blast_radius.py coldstart \
    --corpora real 100 250 --out benchmarks/results/coldstart.json

# 5. the harness's own arithmetic (fast, no node required)
/tmp/hs-venv/bin/pytest tests/unit/test_bench_stats.py -q
/tmp/hs-venv/bin/ruff check .
```

Raw JSON for every run is committed under `benchmarks/results/`:
`control-*.json` are the scaling tables, `measure-*.json` the full suites
including maintainer reach, `seed-*.json` the ingest throughput, and
`coldstart.json` the restart measurement.

The benchmark is deliberately **not** a CI test — it needs a live node, writes
millions of edges and takes half an hour. What CI runs is
`tests/unit/test_bench_stats.py`, which drives the harness against a scripted
fake clock and asserts that warmup runs are excluded from the sample, that
percentiles are nearest-rank, that the wall-clock budget truncates a sample
rather than fabricating one, and that `cold_ms` is always present in a summary
so it cannot be quietly dropped.
