# Progress Log

## Build phase — PR loop (from 2026-08-12 evening)
- Project name: **Hindsight — Blast Radius Time Machine**. Repo: kgarg2468/hydradb-oss-hack (origin). All work lands via PR → CI + Greptile → pr-monitor.sh (Luna condenses action items) → fix → merge.
- PR #1 (scaffold: CI, tests, monitor tooling, PoC evidence) MERGED to main (merge 48c5758). Loop proven: CI 3 jobs green incl. live-HydraDB integration; Greptile round 1 gave 4 real action items (all fixed); monitor now keys Greptile reviews to head SHA.
- **Merged so far: PR #1** scaffold/CI/PR-loop; **#2** hindsight/ ingest package (89 unit + 13 integration; Greptile caught 2 real bugs, worker's own tests caught a 3rd — stale builds reopening closed intervals); **#3** engine fork docs; **#4** hindsight_mcp/ (412 unit + 42 integration, 72 read-only guard cases).
- **Engine fork public: kgarg2468/hydradb @ 258f787** — historical reads + retention API (464 lib + 2 integration tests, clippy clean on 6 feature sets). No upstream PR opened yet — decide before Aug 20.
- Review-loop lessons: Greptile reviews are keyed to a commit; monitor must filter by head SHA (issue comments carry no commit_id → dropped entirely). One Greptile finding on #2 was a verified false positive (fix was already in at head) — dismissed on the PR with test evidence rather than churning the code.
- Engine-constraint corrections found while building (POC-RESULTS §6 is now partly stale): edge `MERGE … SET` IS executable (8.1k edges/s vs 12.1k CREATE) → exact idempotency; relationship PROPERTIES do project (`RETURN e.valid_from`), only bare `e`/`e.id` are rejected.
- **#6** hindsight_web incident console MERGED (timeline scrubber + impact graph + maintainer reach; 694 tests). **#7** build-in-public drafts MERGED.
- Demo story locked (real measured): 13:30 → 0 exposed/9 clean; 14:05 → 1 exposed (`acme/checkout-web`, chalk@5.6.1, held 13:41:52→18:05:33 = 4h23m); 19:00 → 0. Best negative: `webpack/webpack` pinned chalk@5.6.0 **4d1h before the first malicious publish**, untouched 102 days. `qix` reaches 9/9 repos via `debug` alone. Seed: 31,505 nodes / 111,805 edges in 35.5s; exposure 8ms, blast radius 8ms, ranking 2.4s cold / 1.3ms cached.
- Truncation honesty hardened after review: `truncated` propagates read→answer→JSON→UI; counts render as floors (`≥ N`) under an INCOMPLETE READ banner; **a cut empty result can no longer be reported as a proven negative** (the whole product's credibility rests on this).
- More engine findings: **ids are GLOBAL — `MERGE (n:A {id:$x})` matches that id under ANY label and ADDS label A** (irreversible on append-only; contaminated the `Demo*` namespace, which is abandoned — dataset now `Replay*`). Always scope writes through a schema object, never a literal label. Also: no cheap existence probe (`LIMIT 1` ≈ full `count(*)`, ~9s) — health reads watermarks instead (35ms).
- In flight: `refactor/shared-queries` (one canonical `hindsight/queries.py` for MCP+web, agreement test proves both surfaces answer identically; resolving a rebase conflict with the console's retry fix), `feat/benchmark` (headline number).
- Remaining: land those two, 3-min video, submission form, upstream PR decision, publish build-in-public post 1.
- Mutation idioms that HydraDB actually executes (hard-won, encode everywhere):
  - nodes: `UNWIND $rows AS row MERGE (n {id: row.id}) SET n:Label, n.prop = row.x`
  - edges (production, repeatable): `UNWIND $rows AS row MATCH (s:L1 {id: row.s}), (d:L2 {id: row.d}) MERGE (s)-[e:REL {id: row.id}]->(d) SET e.p = row.p` — MERGE pattern carries ONLY `id`, everything else in a trailing SET. Idempotent + closes intervals in place; 8.1k edges/s.
  - edges (one-shot fixtures only): `… CREATE (s)-[:REL {id: row.id, ...}]->(d)` — faster (12.1k edges/s) but duplicates on re-run. Edge `id` REQUIRED either way.
  - rejected: multi-node CREATE, non-UNWIND MATCH..CREATE, multi-hop CREATE patterns.
- Planned PR sequence: #2 ingest productionization (hindsight/ package + CLI + name→id map), #3 engine fork publication + epoch admin endpoint, #4 MCP server (cypher() + schema), #5 timeline UI, #6 benchmark ("one number") + video assets.

## Session 1 — 2026-08-12
- Created planning files.
- Starting Phase 1: fetching hackathon pages + HydraDB GitHub.
- Phases 1–3 complete: 4 research reports in .context/research/ (repo caps, memory landscape, codegraph landscape, branching+inspiration).
- Phase 5 debate: Sol round 1 running (codex bg task). Fable position written (.context/debate/fable-position.md).
- PoC env: HydraDB docker running locally (container hydradb-poc, ports 7687/8443/9090, token 'local-development-token-32-bytes', namespace=default graph=default cell=cell-0). Round-trip write+read verified via HTTP; response exposes read_epoch field (epoch surface visible in API).
