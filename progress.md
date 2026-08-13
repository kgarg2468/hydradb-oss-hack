# Progress Log

## Build phase — PR loop (from 2026-08-12 evening)
- Project name: **Hindsight — Blast Radius Time Machine**. Repo: kgarg2468/hydradb-oss-hack (origin). All work lands via PR → CI + Greptile → pr-monitor.sh (Luna condenses action items) → fix → merge.
- PR #1 (scaffold: CI, tests, monitor tooling, PoC evidence) MERGED to main (merge 48c5758). Loop proven: CI 3 jobs green incl. live-HydraDB integration; Greptile round 1 gave 4 real action items (all fixed); monitor now keys Greptile reviews to head SHA.
- **Merged so far: PR #1** scaffold/CI/PR-loop; **#2** hindsight/ ingest package (89 unit + 13 integration; Greptile caught 2 real bugs, worker's own tests caught a 3rd — stale builds reopening closed intervals); **#3** engine fork docs; **#4** hindsight_mcp/ (412 unit + 42 integration, 72 read-only guard cases).
- **Engine fork public: kgarg2468/hydradb @ 258f787** — historical reads + retention API (464 lib + 2 integration tests, clippy clean on 6 feature sets). No upstream PR opened yet — decide before Aug 20.
- Review-loop lessons: Greptile reviews are keyed to a commit; monitor must filter by head SHA (issue comments carry no commit_id → dropped entirely). One Greptile finding on #2 was a verified false positive (fix was already in at head) — dismissed on the PR with test evidence rather than churning the code.
- Engine-constraint corrections found while building (POC-RESULTS §6 is now partly stale): edge `MERGE … SET` IS executable (8.1k edges/s vs 12.1k CREATE) → exact idempotency; relationship PROPERTIES do project (`RETURN e.valid_from`), only bare `e`/`e.id` are rejected.
- In flight: `feat/timeline-ui` worker (demo web UI + demo-seed + docs/demo.md).
- Remaining: benchmark for the "one number", 3-min video, submission form, upstream PR decision, build-in-public post.
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
