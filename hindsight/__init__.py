"""Hindsight — a bitemporal npm dependency graph on HydraDB.

The package turns a list of git repositories into an append-only, bitemporal
graph of "which repo resolved which package version, when", so that questions
of the form *"what did our dependency tree look like at time T?"* and *"which
services were exposed to package X between T0 and T1?"* can be answered from
history rather than from the current lockfile.

Modules:
  client      HTTP client for a HydraDB node (retries, cursor paging)
  ids         deterministic 63-bit node/edge ids with collision detection
  lockparse   npm / yarn lockfile parsers
  history     git lockfile history -> snapshots -> half-open validity intervals
  graphbuild  intervals -> node and edge rowsets for a given label schema
  ingest      batched UNWIND writer, idempotent via deterministic ids + watermarks
  cli         `python -m hindsight ingest|status --config org.yaml`
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
