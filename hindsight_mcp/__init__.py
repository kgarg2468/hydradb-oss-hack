"""Hindsight's MCP server — the agent-facing surface over the bitemporal graph.

Two layers, deliberately separable:

* :mod:`hindsight_mcp.guard`, :mod:`hindsight_mcp.queries`,
  :mod:`hindsight_mcp.schema_doc` and :mod:`hindsight_mcp.service` are plain
  Python with no MCP imports, so the read-only guard and the query builders can
  be tested directly;
* :mod:`hindsight_mcp.server` registers those functions as MCP tools over stdio
  and is the only module that needs the SDK installed.

Importing this package therefore does not require ``mcp``; importing
``hindsight_mcp.server`` does.
"""

from .guard import Rejection, UnsafeCypher, check, is_read_only
from .schema_doc import graph_schema, render_markdown
from .service import CAVEAT, EVIDENCE, Hindsight, Limits

__all__ = [
    "CAVEAT",
    "EVIDENCE",
    "Hindsight",
    "Limits",
    "Rejection",
    "UnsafeCypher",
    "check",
    "graph_schema",
    "is_read_only",
    "render_markdown",
]
