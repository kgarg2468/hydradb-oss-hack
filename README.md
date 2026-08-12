# Hindsight — Blast Radius Time Machine

**Hack Hydra 2026 · Track 2A (Supply Chain Blast Radius)**

When `chalk` and `debug` were compromised on September 8, 2025, exposure came down to a ~2-hour
window: you were affected only if a lockfile somewhere in your org resolved one of 24 malicious
versions between publish and takedown. The industry answered that question with days of grep and
spreadsheets. Existing tools (Socket, Snyk, Dependabot, deps.dev) can tell you what is vulnerable
*now* — none of them can reconstruct what your org resolved *then*, and none can prove a negative.

Hindsight stores every dependency state your organization ever had as a **bitemporal graph in
[HydraDB](https://github.com/hydra-db/hydradb)** and answers, in milliseconds:

- **"Were we exposed during the compromise window?"** — org-wide, with evidence either way.
  Proving you were *not* exposed is the point: a lockfile-pinned repo that never reinstalled inside
  the window was safe, and Hindsight shows exactly why.
- **"Which single maintainer account, if phished tomorrow, reaches the most of our production
  repos?"** — maintainers are first-class nodes. In our PoC the graph independently identified
  `qix` (the account actually phished in the real attack) as reaching 8/8 fixture repos through
  `debug` alone.
- **"What is the full transitive blast radius of package X at time T?"** — graph traversal,
  not similarity search.

## How it uses HydraDB

- Lockfile history from git becomes `(:DepRepo)-[:RESOLVES {valid_from, valid_to}]->(:DepVersion)`
  edges — the full transitive closure per snapshot, append-only, never deleted.
- Registry metadata becomes `(:DepMaintainer)-[:MAINTAINS]->(:DepPackage)` for trust-radius queries.
- Multi-hop blast-radius and AS-OF questions are plain OpenCypher over Bolt/HTTP.
- We additionally enabled **true engine-level time travel** (`read_epoch` historical queries backed
  by durable SlateDB checkpoints) in a HydraDB branch — see `docs/engine-patch.md` (upstream PR in
  progress).

## Repository layout

| Path | Purpose |
|---|---|
| `hindsight/` | Ingest pipeline: git lockfile history → half-open bitemporal intervals → HydraDB (CLI: `python -m hindsight`) |
| `hindsight_mcp/` | MCP server — raw `cypher()` + schema for agents, plus canned exposure / blast-radius / maintainer-reach tools (`docs/mcp.md`) |
| `poc/` | Validation proof-of-concept: parsers, ingest, oracle checks, measured results (`poc/POC-RESULTS.md`) |
| `tests/` | Unit + integration tests (integration runs against a real HydraDB node in CI) |
| `scripts/` | Dev tooling, including the PR monitor loop |
| `docs/` | `mcp.md` (agent surface), `engine-patch.md` (HydraDB time-travel fork) |
| `task_plan.md`, `findings.md`, `progress.md` | Working notes: research, adversarial idea debate, PoC gates |

## Agent surface

Hindsight ships an MCP server so a coding or security agent can traverse the graph directly.
Rather than a wall of canned tools over now-only data, it exposes **`cypher` plus the schema** —
the agent composes its own traversals — with a handful of composed tools for the common questions.
Read-only is enforced at the tool boundary (mutations rejected in any casing, after a semicolon, or
hidden in comments). Every exposure answer carries `evidence: "resolved"` and states that a resolved
lockfile entry is not proof of build or deployment. See `docs/mcp.md`.

## Validated PoC numbers (see `poc/POC-RESULTS.md`)

- AS-OF correctness: **320/320 agreement** with an independent git-based lockfile oracle
  (8 real repos, 5,028 historical lockfile snapshots, 2024-01 → 2025-12).
- Ingest: 111,723 edges + 31,481 nodes in 20.8 s (**5,386 edges/s**, single-threaded).
- Blast radius / maintainer reach: **5.9 ms p50**.
- All 24 malicious version publish timestamps verified against the npm registry `time` map.

## Running locally

```bash
# 1. Start a local HydraDB node (Docker)
./scripts/start-hydradb.sh

# 2. Run tests
pip install -r requirements-dev.txt
pytest tests/unit          # no services needed
pytest tests/integration   # needs the node from step 1
```

## License

Apache-2.0 (this repository). HydraDB itself is AGPL-3.0; our engine changes live in a fork and
are being offered upstream.
