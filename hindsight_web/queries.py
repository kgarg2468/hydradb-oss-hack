"""The label namespaces the console reads from.

The Cypher itself is not here: every statement the console runs is built by
:mod:`hindsight.queries`, the one module both this package and
:mod:`hindsight_mcp` compose from, so that an incident responder scrubbing the
timeline and an agent asking the identical question over MCP cannot get
different answers. What is left here is the console's *dataset*: which labels
its queries are pointed at.

Both namespaces are disjoint from the ingest pipeline's ``Hs*`` production
labels and from the PoC's ``Dep*`` load, because HydraDB deletes at ~3
nodes/sec and label namespacing is the only workable isolation on an
append-only node.

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

from hindsight.graphbuild import Schema

#: The demo dataset the console opens on.
DEMO_SCHEMA = Schema.prefixed("Replay", "REPLAY")

#: Throwaway labels for integration tests against the same shared node.
TEST_SCHEMA = Schema.prefixed("ReplayTest", "REPLAYTEST")

__all__ = ["DEMO_SCHEMA", "TEST_SCHEMA"]
