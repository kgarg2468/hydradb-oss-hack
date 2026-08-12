# Engine-level time travel (`read_epoch`) — HydraDB patch

HydraDB's HTTP API accepts a `read_epoch` field but rejects it ("read_epoch is not a storage
snapshot selector"). We validated (and implemented, on a public fork, see below)
that historical reads are genuinely achievable:

- A `read_epoch` **is** a SlateDB sequence; retaining an epoch = creating a named SlateDB
  checkpoint (`hydradb-epoch-<seq>`). The manifest itself is the registry, so retained epochs
  survive restart with no new durable structures.
- The resolved historical snapshot is installed into the existing `ACTIVE_STORAGE_SNAPSHOT`
  task-local, so properties, indexes, and tombstones all follow with no further changes; the
  query optimizer already falls back to canonical adjacency when `read_epoch != current_epoch`.
- Evidence: historical epoch returns old state while head returns new; survives node restart and
  compaction churn (8 → 94 SSTs); after GC the query fails loudly ("epoch N is not retained")
  rather than silently returning current state.
- Scope: ~540 changed lines including a 188-line test; all 325 upstream tests pass.

## Wire API (shipped)

Published fork: **https://github.com/kgarg2468/hydradb** at commit
[`258f787`](https://github.com/kgarg2468/hydradb/commit/258f787) (branch `experiment/historical-reads`).
All results below are from that commit; the branch may move.
Auth matches `/query` (bearer + `x-graph-namespace`) and additionally requires the
`QueryTransportAction::Admin` capability.

| Route | Result |
|---|---|
| `POST /v1/graphs/{graph}/cells/{cell}/retained-epochs` | `201 {"cell_id":"cell-0","epoch":1}` — pins the current epoch. Writer-gated: `421 not_cell_writer` on a reader node, `403 permission_denied` without Admin. |
| `GET /v1/graphs/{graph}/cells/{cell}/retained-epochs` | `200 {"cell_id":"cell-0","epochs":[1,7,12]}` |
| `POST /v1/graphs/{graph}/query` | now accepts `read_epoch` (previously a hard 400). An unretained epoch returns `400` naming the retained set, rather than silently reading current state. |

Tests: 464 lib + 2 integration tests pass; clippy `-D warnings` clean across all six CI feature
sets. The HTTP test demonstrates `read_epoch=1 -> [2]` while `head -> [2, 3]`, and that a node
restart preserves both the retained-epoch list and the historical read. +563/−25 lines over 7 files.

An earlier analysis claimed HTTP already carried `read_epoch` to the shard; that was wrong in two
places — `http.rs` rejected the field outright *and* `ClientQueryService` cleared
`context.read_epoch` on every read. Both are fixed on the branch.

Not yet implemented (deliberate, disclosed): no TTL on retention and no drop/GC route
(`gc_retained_epochs` remains library-only); multi-node retain (writer/reader split) and Bolt
historical reads are unexercised by tests.

Hindsight's AS-OF queries do not depend on this patch — schema-level bitemporality
(`valid_from`/`valid_to`) answers historical questions on stock HydraDB. The engine feature adds
true storage-level snapshot pinning for incident-time forensics.
