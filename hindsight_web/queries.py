"""The label namespaces the console can read from.

The Cypher itself is not here: every statement the console runs is built by
:mod:`hindsight.queries`, the one module both this package and
:mod:`hindsight_mcp` compose from, so that an incident responder scrubbing the
timeline and an agent asking the identical question over MCP cannot get
different answers. What is left here is the console's *dataset*: which labels
its queries are pointed at.

The console defaults to the ingest pipeline's ``Hs*`` / ``HS_*`` production
labels. It reads the same prefix environment variables as the MCP server so an
operator can point both read surfaces at another dataset with one setting. The
seeded demo and integration-test namespaces remain disjoint because HydraDB
deletes at ~3 nodes/sec and label namespacing is the only workable isolation on
an append-only node.

Not ``Demo*``: that namespace was contaminated during development and, on an
append-only node, contamination is permanent. ``MERGE (n:A {id: $x})`` matches
an existing node carrying id ``$x`` *whatever label it has* and adds ``A`` to
it, so one statement that named a label literally instead of taking it from a
:class:`~hindsight.graphbuild.Schema` gave four integration-test repositories a
second, production-namespace label. Label isolation holds on read — ``MATCH
(r:Demo)`` never matches ``DemoRepo`` — but it does not survive a write that
enters through a shared id space. Hence: every label reaches a statement as a
Schema argument, and there is a test that the seeder contains no literal.
"""

from __future__ import annotations

import os

from hindsight.graphbuild import Schema

#: The namespace written by the seeded demo dataset.
DEMO_SCHEMA = Schema.prefixed("Replay", "REPLAY")

#: Throwaway labels for integration tests against the same shared node.
TEST_SCHEMA = Schema.prefixed("ReplayTest", "REPLAYTEST")


def schema_from_env(env: dict[str, str] | None = None) -> Schema:
    """Resolve the console schema using the MCP server's prefix settings."""
    env = os.environ if env is None else env
    return Schema.prefixed(
        env.get("HINDSIGHT_MCP_NODE_PREFIX", "Hs"),
        env.get("HINDSIGHT_MCP_REL_PREFIX", "HS"),
    )


__all__ = ["DEMO_SCHEMA", "TEST_SCHEMA", "schema_from_env"]
