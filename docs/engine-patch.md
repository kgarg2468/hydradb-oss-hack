# Engine-level time travel (`read_epoch`) — HydraDB patch

HydraDB's HTTP API accepts a `read_epoch` field but rejects it ("read_epoch is not a storage
snapshot selector"). We validated (and implemented, on a fork branch `experiment/historical-reads`)
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

Remaining for productization: a small admin endpoint (~60 LOC on the already-defined
`QueryTransportAction::Admin`) to create/retain epochs over the wire. The patch will be published
as a public fork and offered upstream during the hackathon; Hindsight's AS-OF queries work
without it (schema-level bitemporality), and use it when available for incident-time snapshot
pinning.
