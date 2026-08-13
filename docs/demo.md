# Running the demo

Everything below has been executed end to end against a local HydraDB node; the
numbers quoted are the ones it actually returned.

## 0. What the demo answers

> At 14:05 UTC on 8 September 2025, which of our repositories had a lockfile
> resolving a compromised `chalk`/`debug` version — and which npm maintainer
> account has the largest blast radius into those repositories?

One qualification runs through the whole thing and is printed on every answer:
the evidence is **lockfile resolution**. A resolved entry is a fact about a
committed lockfile at an instant. It is not proof that the package was
installed, built, executed or shipped. The console never says otherwise.

## 1. Start a node

```bash
scripts/start-hydradb.sh                    # docker, ports 7687/8443/9090
```

It waits for a round-tripped write, so when it returns the node is genuinely up.

Those are also the defaults every tool here uses, so nothing needs exporting for
a local run. To point at another node:

```bash
export HINDSIGHT_HYDRA_URL=http://127.0.0.1:8443
export HINDSIGHT_HYDRA_TOKEN=local-development-token-32-bytes
export HINDSIGHT_HYDRA_NS=default
export HINDSIGHT_HYDRA_GRAPH=default
export HINDSIGHT_HYDRA_CELL=cell-0
```

## 2. Install

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[web]' -r requirements-dev.txt
```

The HydraDB client itself is stdlib `urllib`; the only third-party runtime
dependencies are Starlette and uvicorn, and they serve HTTP, not the graph.

## 3. Seed the demo dataset

```bash
python3 scripts/demo-seed.py                 # plan only, writes nothing
python3 scripts/demo-seed.py --execute       # write
```

Labels are `Replay*` / `REPLAY_*`, disjoint from the ingest pipeline's `Hs*` and
the PoC's `Dep*`. Nothing is ever deleted: HydraDB deletes at roughly 3 nodes/sec
against 17k inserts/sec, so label namespacing is the isolation mechanism.

Where the history comes from, in order of preference:

| `--source`   | what it reads |
|--------------|---------------|
| `file`       | committed `poc/demo-dataset.jsonl.gz` — versioned compressed JSONL; offline and reproducible |
| `snapshots`  | `poc/snapshots/<repo>.jsonl.gz` — raw per-commit lockfile closures |
| `graph-file` | ignored `poc/graph.json.gz` — the canonical PoC projection before it is loaded into HydraDB |
| `graph`      | the PoC's `Dep*` load already in the node, re-read and re-projected |
| `auto`       | current committed file, else snapshots, else the graph (default) |

The normal fresh-clone path is `auto` → `file`; it does not clone upstream
repositories and does not require `Dep*` rows. The committed artifact contains
logical repository intervals and the maintainer overlay, not HydraDB-specific
ids, so the ordinary writer still builds deterministic rowsets and watermarks.

To regenerate the artifact from the canonical PoC graph export:

```bash
python3 scripts/demo-seed.py \
  --source graph-file \
  --export poc/demo-dataset.jsonl.gz
```

`--export` writes deterministic gzip JSONL and exits without reading or writing
the output label namespace. To rebuild every ignored input first (~40 min,
~550 MB of clones):

```bash
cd poc && ./clone_repos.sh
for r in axios babel grafana jitsi-meet webpack superset react storybook; do
  SINCE=2024-01-01 UNTIL=2025-12-31 python3 extract_history.py "$r" &
done; wait
python3 build_graph.py
cd ..
python3 scripts/demo-seed.py --source graph-file --export poc/demo-dataset.jsonl.gz
```

For a round-trip verification load on a shared append-only node, both fresh
labels and fresh ids are mandatory:

```bash
python3 scripts/demo-seed.py --source file --execute \
  --node-prefix SeedCheck --rel-prefix SEEDCHECK --id-namespace seed-check-1
```

Do not omit `--id-namespace` for a scratch load. HydraDB ids are global across
labels, so a load under fresh *labels* alone still merges onto the demo's nodes
by id and adds its labels to them — permanently, on an append-only store. It
also salts the watermark's `slug`, because the watermark id is a plain function
of the slug (`hindsight.ids.watermark_id`) and an unsalted scratch load would
otherwise overwrite the demo's ingest watermarks.

That isolation is total, and deliberately so: every console read anchors on the
same unsalted deterministic ids, so a namespaced load is invisible to the
console — the repository directory (a label scan) lists nine repositories and
every exposure read returns NOT_RESOLVED. It verifies the write path only.
Verifying what the console *renders* means seeding a namespace without
`--id-namespace`, which on a shared node means a node with no demo dataset on
it. To check an artifact against the canonical projection instead, re-export it
and diff:

```bash
python3 scripts/demo-seed.py --source graph --export /tmp/check.jsonl.gz
diff <(gzcat /tmp/check.jsonl.gz | sort) <(gzcat poc/demo-dataset.jsonl.gz | sort)
```

Only the `origin` provenance strings differ, since each names the source it was
projected from. Every interval, version, maintainer and synthetic row matches.

A real run, represented by the committed file:

```
labels: ReplayRepo / ReplayVer -[REPLAY_RESOLVES]->
source: file
  axios/axios                intervals=  2,061 commits=   16
  babel/babel                intervals=  3,264 commits=  128
  facebook/react             intervals=  3,097 commits=   75
  grafana/grafana            intervals= 11,314 commits=2,003
  jitsi/jitsi-meet           intervals=  3,260 commits=  100
  apache/superset            intervals=  8,844 commits=  516
  storybookjs/storybook      intervals= 50,358 commits=1,206
  webpack/webpack            intervals=  4,121 commits=  299
  acme/checkout-web          intervals=     61 commits=    4  SYNTHETIC, 13 malicious version(s): …

built 31,505 nodes / 111,805 edges (154 maintainer accounts)
  VERSION_OF edges     24,959 rows   12.80s      1,949/s
  RESOLVES edges       86,380 rows   20.76s      4,160/s

wrote 31,505 nodes and 111,805 edges in 35.45s
```

### One repository is synthetic, and the UI says so

None of the eight real repositories regenerated a lockfile inside the two-hour
compromise window. That is the true finding of the PoC, and it means there is no
real true positive to show. `acme/checkout-web` is therefore constructed — from
the real incident file, using real npm caret semantics — and is written with
`synthetic = 1` and a provenance string that the console renders on the row:

> This repository is a constructed example, not a real git history. It exists
> because none of the real repositories in this dataset regenerated a lockfile
> inside the compromise window.

Its CI reinstall at 13:41:52 UTC picks up the malicious version of every incident
package whose caret range permits it — 13 of the 19 wave-1 packages. The other
six would need a major bump, so they do not move. Nothing about it is presented
as real.

## 4. Run the console

The console defaults to the ingest pipeline's `Hs*` / `HS_*` labels. The seeded
demo is intentionally isolated under `Replay*` / `REPLAY_*`, so select it with
the same prefix variables used by the MCP server:

```bash
export HINDSIGHT_MCP_NODE_PREFIX=Replay
export HINDSIGHT_MCP_REL_PREFIX=REPLAY
python3 -m hindsight_web                  # http://127.0.0.1:8080
python3 -m hindsight_web --port 9000 --reload
```

Startup prints every resolved node label and relationship type. If the exports
are missing or misspelled, the namespace mismatch is visible before the first
request instead of looking like an empty dataset.

Measured against the seeded dataset:

| request | latency |
|---|---|
| `GET /api/health` | 35 ms |
| `GET /api/health?edges=1` | 9.2 s — counts 86,380 RESOLVES edges, off by default |
| `GET /api/incident` | 3 ms |
| `GET /api/exposure?package=chalk&at=2025-09-08T14:05:00Z` | 8 ms |
| `GET /api/blast-radius?package=chalk&at=…` | 8 ms (23 nodes, 51 edges) |
| `GET /api/maintainer-reach?name=qix&at=…` | 26 ms |
| `GET /api/maintainer-reach?at=…` (rank all 154 accounts) | 2.4 s cold, 1.3 ms cached |

`at=` takes unix seconds or ISO-8601. A bad one is a 400 naming the field.

## 5. The story the data tells

Scrub the timeline and the answer changes underneath you:

| instant | exposed | resolved, clean | not resolved |
|---|---|---|---|
| 13:30 UTC — attack live, 19 packages already published | **0** | 9 | 0 |
| 14:05 UTC | **1** | 8 | 0 |
| 19:00 UTC — after remediation | **0** | 9 | 0 |

The one hit, and its exact interval:

```
acme/checkout-web   EXPOSED   chalk@5.6.1
  resolved 2025-09-08T13:41:52Z → 2025-09-08T18:05:33Z   held 4 h 23 min
```

The sharper half of the demo is the negative, because it comes with a reason
rather than an empty result set:

```
webpack/webpack   RESOLVED, NOT MALICIOUS   chalk@5.6.0
  pinned across the entire 2 h 17 min exposure window and none of those
  versions is a malicious one; that pin was already 4 d 1 h old when the
  first malicious version was published
```

`chalk@5.6.0` is one patch below the malicious `5.6.1`. It was pinned on
2025-09-04 and not touched again until 2025-12-15 — 102 days. That is not luck
being reported as safety; it is a specific interval with both ends on it.

Three strengths of negative, and the console distinguishes them:

1. **NOT RESOLVED** — the package is not in that repository's dependency
   closure at that instant. `chalk-template` at 14:05: 1 exposed, 1 clean,
   7 not resolved.
2. **the package has no node at all** — nothing in the dataset has ever
   resolved it, at any instant in the ingested history. A real absence, not a
   lookup failure.
3. **the version has no node at all** — the strongest available.
   `GET /api/version-footprint?package=color&version=5.0.1` returns
   `version_in_graph: false` in 1 ms: that malicious build was never resolved by
   anything, anywhere in this history.

Then pivot to the standing risk. Ranked by repo×package surface at 14:05:

| # | account | packages | repos | pairs |
|---|---|---|---|---|
| 1 | `sindresorhus` | 34 | 9 | 271 |
| 2 | `existentialism` | 25 | 8 | 173 |
| 3 | `hzoo` | 25 | 8 | 173 |

and `qix` — the account actually phished on 8 September — reaches **all 9 of 9**
repositories through `debug` alone.

## 6. Shot list, 3 minutes

| time | shot | say |
|---|---|---|
| 0:00–0:15 | top bar (Hindsight wordmark, incident title, Demo data pill, health dot with `9 repos`), the answer strip already stating the finding, timeline rail with its named event chips | "8 September 2025. Nineteen npm packages compromised in eight minutes. Here is that timeline over our real lockfile history." |
| 0:15–0:35 | drag the scrubber to **13:30** — answer strip reads **0 repositories** with stats 0 / 9 / 0 | "The attack is already live. Nothing of ours is exposed yet. That is an answer, not an absence of one." |
| 0:35–1:00 | scrub to **14:05** (or step through the event chips with the arrows). The answer strip flips to "1 repository resolved a malicious chalk version" and the exposed row sits expanded on its red-tinted surface | "One repository. `chalk@5.6.1`, resolved 13:41:52, replaced 18:05:33 — four hours twenty-three minutes." |
| 1:00–1:15 | point at the amber Synthetic pill, then click the Demo data pill in the top bar so the popover shows the provenance note | "This one is constructed, and it says so. None of the eight real repositories regenerated a lockfile inside the window — which is itself the finding." |
| 1:15–1:40 | scroll to `webpack/webpack`, read the basis line | "Here is the shot I care about. Not exposed — because it was pinned to 5.6.0, one patch below, four days before the attack started, and did not move for 102 days." |
| 1:40–2:00 | the evidence caveat line under the answer strip | "Everything here is lockfile resolution. It is the scope to investigate. It is not a claim that anything was installed, built or shipped." |
| 2:00–2:20 | impact graph — the default view is just the malicious path with clean repos aggregated; click **Show all** for the full repo → version → package → maintainer layout, malicious edges in red | "Same query, drawn. Four layers, from our repository to the npm account that can publish into it." |
| 2:20–2:45 | Standing risk card; `sindresorhus` at #1, then search `qix` | "And the standing question. One account reaches 34 packages across all nine repositories. `qix` — the account actually phished that morning — reaches nine of nine through `debug` alone." |
| 2:45–3:00 | scrub back and forth across 13:41:52 so exposure flips on and off | "Bitemporal, so every one of those answers is as-of an instant — and it is a graph traversal, not a similarity search." |

Three details worth rehearsing: the scrubber is debounced at 55 ms, so drag it
rather than clicking (arrow keys nudge a minute, shift+arrow fifteen); the
maintainer ranking takes 2.4 s the first time an instant is scored and ~1 ms
afterwards, so visit the instant once before filming; and the endpoint, label
namespace and read-completeness live in the Diagnostics drawer (top right) if
you want them on screen.

## 7. Tests

```bash
pytest tests/unit                    # 900 tests, no node required
pytest tests/integration             # 86 against a live node
ruff check .
```

The integration tests write under `ReplayTest*` with a fresh random token per
run, so they share no ids with a previous run and never touch the demo dataset,
the `Hs*` production labels, or the PoC's `Dep*` load.

## 8. Two engine behaviours worth knowing before you demo

**Ids are global; labels namespace reads, not writes.**
`MERGE (n:A {id: $x})` matches whatever node already carries `$x`, whatever label
it has, and adds `A` to it. One statement naming a label literally instead of
taking it from a `Schema` gave four integration-test repositories a second label
in the demo namespace — and on an append-only node that cannot be undone. It is
why the demo labels are `Replay*` and not `Demo*`. Pass the schema; never write a
label literal.

**There is no cheap existence probe on a large relationship set.**
Counting one repository's RESOLVES edges is ~2 s for the largest repository even
anchored on its id. The same match with `LIMIT 1`, and the same match read one
row at a time and abandoned after the first, cost within 1 % of the full count:
8,964 ms and 9,037 ms against 8,979 ms across the nine repositories. The engine
materialises the match before it limits. So the health check reads the ingest
watermarks instead — nine nodes, one label scan, 35 ms — which is better evidence
anyway, since a watermark is written *after* a run completes.
