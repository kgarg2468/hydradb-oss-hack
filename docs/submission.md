# Hack Hydra submission packet

Paste-ready copy for the submission form (forms.gle/WEwqEmmN7Bkp4HyJ6, due
20 Aug 2026 11:59pm PT), plus the claims behind it and where each one is
checkable. Every number here was measured on this machine against a real
HydraDB node; nothing is projected or rounded in our favour.

---

## The short version

**Hindsight — Blast Radius Time Machine.** Track 2A, supply-chain blast radius.

Every dependency-security tool answers *what is vulnerable now*. During the
`chalk`/`debug` compromise of 8 September 2025, that was the wrong question:
19 packages were poisoned inside eight minutes and pulled roughly two hours
later, so whether you were hit depended entirely on whether some lockfile in
your org resolved a bad version **inside that window**. Answering it took the
industry days of grep, and nobody could prove the negative.

Hindsight stores every dependency state an organisation has ever had as a
bitemporal graph in HydraDB — repos, resolved package versions carrying
half-open `valid_from`/`valid_to` intervals, and npm maintainer accounts as
first-class nodes — and answers as-of any instant in milliseconds:

- Which repositories resolved a compromised version at 14:05 UTC?
- For each one that did not: *why* not, with the interval as evidence.
- Which single maintainer account, phished tomorrow, reaches the most repos?

---

## Why this is a graph problem and not a query over a table

The interesting questions are multi-hop and they are all as-of an instant:

```
(:Repo)-[:RESOLVES {valid_from, valid_to}]->(:Version)-[:VERSION_OF]->(:Package)<-[:MAINTAINS]-(:Maintainer)
```

"Blast radius of package X at time T" is that path walked outward with an
interval predicate on every `RESOLVES` edge. "Maintainer reach" is the same
path walked backward from an account and scored by distinct repos reached.
Neither is a similarity search and neither is a join you would want to write
against a relational snapshot table, because the snapshot you need is a
different one for every instant on the scrubber.

## How HydraDB does the real work

Not a cache in front of something else — HydraDB is the only datastore.

| Thing | How it lands in HydraDB |
|---|---|
| Lockfile history | Git history → full transitive closure per commit → half-open intervals → `RESOLVES` edges, append-only, never deleted |
| Registry metadata | `(:Maintainer)-[:MAINTAINS]->(:Package)` |
| As-of exposure | OpenCypher over Bolt/HTTP with an interval predicate; no application-side filtering |
| Blast radius | Multi-hop OpenCypher traversal |
| Agent surface | MCP server exposing raw `cypher` + the schema, so an agent composes its own traversals |

**We also extended the engine.** HydraDB's query API carries a `read_epoch`
field that was rejected at the route — historical reads were not wired up. On
a fork we mapped `read_epoch` onto durable SlateDB checkpoints and added a
retention API (`POST`/`GET /v1/graphs/{graph}/cells/{cell}/retained-epochs`).
A historical query now returns the old state while head moves on, survives node
restart and compaction churn, and fails loudly (`epoch N is not retained`)
rather than silently returning current state. 464 lib + 2 integration tests
pass; clippy is clean on all six CI feature sets.

Fork: `github.com/kgarg2468/hydradb` @ `258f787`. Details in
[`engine-patch.md`](engine-patch.md).

Schema-level bitemporality is the product's foundation and works against stock
HydraDB today; the engine patch is an upgrade on top of it, not a dependency.

## What is validated, and how

- **Correctness:** 320/320 agreement between Hindsight's as-of answers and an
  independent git-based lockfile oracle, over 8 real repositories and 5,028
  historical lockfile snapshots (2024-01 → 2025-12). `poc/POC-RESULTS.md`.
- **All 24 malicious version publish timestamps** verified against the npm
  registry `time` map — the incident window is sourced, not assumed.
- **Latency** on the seeded dataset (31,505 nodes / 111,805 edges): exposure
  as-of 8 ms, blast radius 8 ms, maintainer reach 26 ms, ranking all 154
  accounts 2.4 s cold / 1.3 ms cached.
- **Scaling**, measured to 250 synthetic repos / 2.36 M interval edges
  (`benchmarks/RESULTS.md`): the incident sweep — "did any repo resolve one of
  these 24 compromised versions at T", which is the question the product exists
  to answer — is **46.3 ms p95 at 250 repos, warm**; cold, that same sweep is
  **1,090 ms**, and the first question of an incident is asked cold. The general
  per-package exposure query is **36.3 ms p95 at 100 repos, warm** and degrades
  sharply above ~1 M edges of one relationship type (339 ms at 150 repos, 5.3 s
  at 250, both warm). We bisected that,
  attributed it, built the obvious mitigation, measured that the mitigation does
  not work, and wrote all of it down.
- **Tests:** 979 passing (893 unit, 86 integration). Integration runs against a
  live HydraDB node in GitHub Actions on every PR.

## The part we are most proud of: it refuses to lie

A security tool that reports a false negative is worse than no tool. Three
places where that shaped the code:

1. **Truncation propagates.** If a read hits the row cap, `truncated` travels
   read → answer → JSON → UI; counts of matches render as floors (`≥ N`) under
   an INCOMPLETE READ banner, while classifications that rest on a row being
   absent are marked as-observed, not floors. A cut result set can never be
   presented as a proven negative.
2. **Evidence is labelled.** Every exposure answer carries
   `evidence: "resolved"` and states that a resolved lockfile entry is not
   proof of install, build or deployment. That is the scope to investigate, not
   a breach claim.
3. **The synthetic row says so.** None of the eight real repositories
   regenerated a lockfile inside the two-hour window — which is itself the
   finding. The one exposed repository in the demo is therefore constructed
   from the real incident file using real caret semantics, is stored with
   `synthetic = 1`, and the console renders that provenance on the row.

## Try it

```bash
scripts/start-hydradb.sh          # local node, docker
pip install -e '.[web]' -r requirements-dev.txt
python3 scripts/demo-seed.py --execute
python3 -m hindsight_web          # http://127.0.0.1:8080
```

Full walkthrough: [`demo.md`](demo.md). Agent surface: [`mcp.md`](mcp.md).

## Known limitations

- Evidence is lockfile resolution only. Deployment/runtime exposure is out of
  scope, deliberately and visibly.
- npm ecosystem only (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`).
  PyPI/Cargo are the same shape but unimplemented.
- Maintainer edges are a registry snapshot, not history — we know who maintains
  a package now, not who maintained it in 2024.
- Benchmarks are single-node with local-directory object storage; real S3 will
  be slower. Stated in `benchmarks/RESULTS.md` rather than left implicit.
- **The per-package exposure query has no headroom above ~1 M interval edges of
  one relationship type** — roughly 100 repositories at this dataset's shape. The
  incident sweep stays flat well past that, so the headline question scales; the
  browse-any-package question does not. We do not have a fix, and
  `benchmarks/RESULTS.md` lists the candidates we have not tried rather than
  implying one exists.

---

## Form answers

**Project name** — Hindsight — Blast Radius Time Machine

**Track** — 2: Repos, Dependencies & Code as Graphs (2A, supply-chain blast radius)

**One-line description** — A bitemporal dependency graph in HydraDB that
reconstructs exactly which repositories resolved a compromised package version
during an incident window — and proves which ones did not.

**What problem does it solve?** — Every dependency tool answers "what is
vulnerable now." Incident response needs "what did we resolve then." When
`chalk` and `debug` were compromised on 8 Sept 2025, exposure hinged on a
~2-hour window, and reconstructing it took days of grep across every repo's git
history. Nobody could prove a negative, so teams rebuilt everything by default.

**How does it use HydraDB?** — HydraDB is the only datastore. Lockfile history
becomes `RESOLVES` edges with half-open `valid_from`/`valid_to` intervals;
maintainers are first-class nodes. Exposure, blast radius and maintainer reach
are OpenCypher traversals with interval predicates — multi-hop graph work, not
similarity search. We additionally implemented engine-level historical reads
(`read_epoch` over durable SlateDB checkpoints) plus a retention API on a fork,
offered upstream.

**What is novel?** — Bitemporal supply-chain forensics. Existing tools (Socket,
Snyk, Dependabot, deps.dev) are all now-only: they cannot reconstruct a past
instant, and none of them can produce a defensible negative. Hindsight answers
"were we exposed at 14:05 UTC" org-wide in milliseconds and, for each repo that
was not, returns the interval that proves it — e.g. webpack pinned `chalk@5.6.0`
four days and one hour before the first malicious publish and did not move for
102 days.

**Repo** — github.com/kgarg2468/hydradb-oss-hack (Apache-2.0)

**Engine fork** — github.com/kgarg2468/hydradb @ 258f787

**Demo video** — 3 min, shot list in [`demo.md`](demo.md) §6
