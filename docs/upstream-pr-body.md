## What this does

`POST /v1/graphs/{graph}/query` accepts a `read_epoch` field, but the route
rejects it — `read_epoch is not a storage snapshot selector` — so historical
reads are not reachable today. This branch makes them work.

A `read_epoch` **is** a SlateDB sequence. Retaining one is therefore a named
SlateDB checkpoint (`hydradb-epoch-<seq>`), which means the manifest is already
the registry: retained epochs survive restart with no new durable structure to
persist, back up or corrupt. The resolved historical snapshot is installed into
the existing `ACTIVE_STORAGE_SNAPSHOT` task-local, so properties, indexes and
tombstones follow with no further changes, and the query optimizer already falls
back to canonical adjacency when `read_epoch != current_epoch`.

## API

| Route | Behaviour |
|---|---|
| `POST /v1/graphs/{graph}/cells/{cell}/retained-epochs` | `201 {"cell_id":"cell-0","epoch":1}` — pins the current epoch. Writer-gated (`421 not_cell_writer` on a reader node), requires `QueryTransportAction::Admin` (`403` without it). |
| `GET /v1/graphs/{graph}/cells/{cell}/retained-epochs` | `200 {"cell_id":"cell-0","epochs":[1,7,12]}` |
| `POST /v1/graphs/{graph}/query` | now accepts `read_epoch`. An unretained epoch returns `400` naming the retained set. |

Auth matches `/query`: bearer plus `x-graph-namespace`.

## The failure mode this is careful about

A time-travel read that silently returns *current* state when the requested
snapshot is gone is worse than one that errors, because the caller cannot tell
the difference and will believe the answer. So an unretained epoch is a loud
`400` that names what *is* retained. After GC reclaims a checkpoint, the query
fails; it never degrades to head.

## Evidence

- A historical epoch returns old state while head returns new: `read_epoch=1 -> [2]`, `head -> [2, 3]`.
- Survives node restart — both the retained-epoch list and the historical read.
- Survives compaction churn, 8 → 94 SSTs.
- After GC, the read fails loudly rather than silently returning current state.

464 lib + 2 integration tests pass. `clippy -D warnings` is clean across all six
CI feature sets. +563/−25 lines over 7 files, including a 188-line test.

## Deliberately not included

- No TTL on retention, and no drop/GC route — `gc_retained_epochs` stays
  library-only. Who owns retention lifetime is a policy question worth its own
  discussion rather than a default smuggled in here.
- Multi-node retain (writer/reader split) and Bolt historical reads are
  implemented but unexercised by tests.

## Context

Built during Hack Hydra for [Hindsight](https://github.com/kgarg2468/hydradb-oss-hack),
a bitemporal supply-chain forensics tool. Hindsight itself does **not** depend on
this patch — schema-level `valid_from`/`valid_to` intervals answer its historical
questions on stock HydraDB. This adds true storage-level snapshot pinning, which
is the stronger primitive for incident-time forensics.

Offered as a working branch and a design proposal rather than something anyone is
obliged to take. Happy to rework the shape, the route naming, or the retention
model.
