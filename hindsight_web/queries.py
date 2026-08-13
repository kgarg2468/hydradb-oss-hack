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
from pathlib import Path

import yaml

from hindsight.graphbuild import Schema

#: The namespace written by the seeded demo dataset.
DEMO_SCHEMA = Schema.prefixed("Replay", "REPLAY")

#: Throwaway labels for integration tests against the same shared node.
TEST_SCHEMA = Schema.prefixed("ReplayTest", "REPLAYTEST")


def resolve_schema(
    config_path: str | None = None, env: dict[str, str] | None = None
) -> Schema:
    """The console's dataset, from the same declaration the ingest CLI reads.

    ``org.yaml`` may carry a ``schema:`` block, and ``hindsight ingest`` writes
    whatever it says. A console that only consulted the environment would agree
    with the pipeline's *default* and diverge from every custom prefix, which is
    the original bug one layer up: the operator declares ``node_prefix: Acme``,
    ingests to ``Acme*``, and reads an empty ``Hs*``.

    Precedence is explicit-beats-declared, resolved *per prefix*: an
    environment prefix is a deployment-time override and wins, otherwise the
    org config decides, otherwise the pipeline default.
    """
    env = os.environ if env is None else env
    #: An empty variable is treated as unset. ``FOO= hindsight-web`` is how a
    #: shell says "not this one", and building the label ``Repo`` from it would
    #: silently drop the namespace the isolation depends on.
    node = (env.get("HINDSIGHT_MCP_NODE_PREFIX") or "").strip() or None
    rel = (env.get("HINDSIGHT_MCP_REL_PREFIX") or "").strip() or None

    #: Each prefix resolves on its own. Treating "any variable set" as "the
    #: environment wins" would let a half-configured shell build a hybrid
    #: namespace -- ``ReplayRepo`` joined by ``HS_RESOLVES`` -- which matches
    #: nothing and reads exactly like an empty dataset.
    if (node is None or rel is None) and config_path:
        raw = yaml.safe_load(Path(config_path).read_text()) or {}
        declared = raw.get("schema") or {}
        if node is None:
            node = str(declared.get("node_prefix", "Hs"))
        if rel is None:
            rel = str(declared.get("rel_prefix", "HS"))

    return Schema.prefixed(node or "Hs", rel or "HS")


__all__ = ["DEMO_SCHEMA", "TEST_SCHEMA", "resolve_schema"]
