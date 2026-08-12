# Progress Log

## Build phase — PR loop (from 2026-08-12 evening)
- Project name: **Hindsight — Blast Radius Time Machine**. Repo: kgarg2468/hydradb-oss-hack (origin). All work lands via PR → CI + Greptile → pr-monitor.sh (Luna condenses action items) → fix → merge.
- PR #1 (scaffold: CI, tests, monitor tooling, PoC evidence) MERGED to main (merge 48c5758). Loop proven: CI 3 jobs green incl. live-HydraDB integration; Greptile round 1 gave 4 real action items (all fixed); monitor now keys Greptile reviews to head SHA.
- In flight: worker A `feat/ingest-pipeline` (hindsight/ package, isolated worktree); worker B engine fork publication (kgarg2468/hydradb, epoch-retention admin API).
- Mutation idioms that HydraDB actually executes (hard-won, encode everywhere):
  - nodes: `UNWIND $rows AS row MERGE (n {id: row.id}) SET n:Label, n.prop = row.x`
  - edges: `UNWIND $rows AS row MATCH (s:L1 {id: row.s}), (d:L2 {id: row.d}) CREATE (s)-[:REL {id: row.id, ...}]->(d)` (edge id REQUIRED)
  - rejected: multi-node CREATE, non-UNWIND MATCH..CREATE, multi-hop CREATE patterns.
- Planned PR sequence: #2 ingest productionization (hindsight/ package + CLI + name→id map), #3 engine fork publication + epoch admin endpoint, #4 MCP server (cypher() + schema), #5 timeline UI, #6 benchmark ("one number") + video assets.

## Session 1 — 2026-08-12
- Created planning files.
- Starting Phase 1: fetching hackathon pages + HydraDB GitHub.
- Phases 1–3 complete: 4 research reports in .context/research/ (repo caps, memory landscape, codegraph landscape, branching+inspiration).
- Phase 5 debate: Sol round 1 running (codex bg task). Fable position written (.context/debate/fable-position.md).
- PoC env: HydraDB docker running locally (container hydradb-poc, ports 7687/8443/9090, token 'local-development-token-32-bytes', namespace=default graph=default cell=cell-0). Round-trip write+read verified via HTTP; response exposes read_epoch field (epoch surface visible in API).
