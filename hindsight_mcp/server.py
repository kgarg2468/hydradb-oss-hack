"""The stdio MCP server: tool registration and nothing else.

The shape of this surface is the whole product argument. Comparable MCP
code-graph servers ship ~30 canned tools over single-repo, present-tense data,
which caps the agent at the questions someone thought of in advance. Hindsight
ships the opposite trade: one ``cypher`` tool with the raw read surface, a
``schema`` document rich enough to make it usable, and four canned tools for the
questions that get asked under incident pressure and should not require the
agent to compose a three-pattern join from scratch.

Everything an agent could get wrong on its own is handled below it: the
read-only guard, the row cap, the deadline, and the evidence caveats that keep
"a lockfile resolved this" from being reported as "this was deployed".
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from hindsight.client import HydraClient, HydraError
from hindsight.graphbuild import Schema
from hindsight.queries import UnknownKind

from .guard import UnsafeCypher
from .schema_doc import render_markdown
from .service import Hindsight, Limits, ToolInputError

SERVER_NAME = "hindsight"

INSTRUCTIONS = """\
Hindsight answers supply-chain questions against a bitemporal graph of every
dependency state an organisation's repositories ever had: which repos resolved
which package versions, over which time intervals, and which npm maintainer
accounts sit upstream of them.

Read the `schema` tool (or the hindsight://schema resource) before writing
Cypher. It is short, and it contains the two things that otherwise cost you
several turns: the graph has NO secondary index, so every query must enter
through `{id: $id}` (use `resolve_id` to get one), and the engine executes a
restricted OpenCypher subset with no IN, CONTAINS, IS NULL, min/max or
shortestPath.

Evidence semantics, which must survive into whatever you report: an edge in
this graph proves a committed lockfile RESOLVED a version over an interval. It
does not prove the dependency was installed, built, executed or deployed. Every
result carries `evidence` and `caveat` fields saying so. Do not paraphrase them
away.
"""


@dataclass(frozen=True)
class Settings:
    """Server configuration, all overridable from the environment."""

    node_prefix: str = "Hs"
    rel_prefix: str = "HS"
    max_rows: int = 1000
    deadline_seconds: float = 20.0

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> Settings:
        env = os.environ if env is None else env
        return cls(
            node_prefix=env.get("HINDSIGHT_MCP_NODE_PREFIX", "Hs"),
            rel_prefix=env.get("HINDSIGHT_MCP_REL_PREFIX", "HS"),
            max_rows=int(env.get("HINDSIGHT_MCP_MAX_ROWS", "1000")),
            deadline_seconds=float(env.get("HINDSIGHT_MCP_TIMEOUT", "20")),
        )

    @property
    def schema(self) -> Schema:
        return Schema.prefixed(self.node_prefix, self.rel_prefix)

    @property
    def limits(self) -> Limits:
        return Limits(max_rows=self.max_rows, deadline_seconds=self.deadline_seconds)


def _fail(exc: Exception) -> ToolError:
    """Turn an internal failure into something a model can correct itself from.

    The caller is a language model, so the error string is the entire remedy
    channel: it has to name the construct that was refused and what to do
    instead, not just report that something went wrong.
    """
    if isinstance(exc, UnsafeCypher):
        return ToolError(
            f"refused by the read-only guard: {exc.rejection}. This server never "
            "writes; rewrite the statement as a read."
        )
    if isinstance(exc, (ToolInputError, UnknownKind)):
        return ToolError(f"invalid argument: {exc}")
    if isinstance(exc, HydraError):
        return ToolError(
            f"HydraDB refused or failed the query: {exc}. If this is an "
            "'OpenCypher query is not supported yet' message, check the "
            "unsupported-constructs table in the schema tool — the same text "
            "appears there with the workaround."
        )
    return ToolError(f"{type(exc).__name__}: {exc}")


def build_server(
    hindsight: Hindsight | None = None, settings: Settings | None = None
) -> MCPServer:
    """Wire the tools onto a server instance.

    Takes an optional pre-built :class:`~hindsight_mcp.service.Hindsight` so a
    test can point the whole surface at throwaway labels without going through
    the environment.
    """
    settings = settings or Settings.from_env()
    service = hindsight or Hindsight(
        client=HydraClient.from_env(), schema=settings.schema, limits=settings.limits
    )
    server = MCPServer(
        name=SERVER_NAME,
        title="Hindsight — supply-chain blast radius over time",
        instructions=INSTRUCTIONS,
        version="0.1.0",
    )

    @server.resource(
        "hindsight://schema",
        name="Hindsight graph schema",
        description=(
            "Labels, edge types, properties, the bitemporal convention, the "
            "id-anchoring rule and the engine's unsupported-construct list."
        ),
        mime_type="text/markdown",
    )
    def schema_resource() -> str:
        return render_markdown(service.schema)

    @server.tool(
        name="schema",
        title="Graph schema and query guide",
        description=(
            "The graph's labels, edge types, properties, bitemporal convention "
            "(valid_from inclusive, valid_to exclusive, FAR_FUTURE = still "
            "open), how to query it efficiently, and every OpenCypher construct "
            "this engine rejects with the workaround for each. Read this before "
            "calling `cypher`."
        ),
    )
    def schema() -> str:
        return render_markdown(service.schema)

    @server.tool(
        name="cypher",
        title="Run a read-only Cypher query",
        description=(
            "Execute one read-only OpenCypher statement and get plain JSON rows "
            "back. This is the general escape hatch: compose whatever traversal "
            "the question needs instead of hoping a canned tool covers it. "
            "Mutations (CREATE/MERGE/DELETE/SET/REMOVE/DETACH and friends) are "
            "refused before reaching the database, including after a semicolon "
            "or inside a comment, and multi-statement input is refused outright. "
            "Results are capped and the response says so when it truncates. "
            "Anchor every query on {id: $id} — see the `schema` tool for why, "
            "and `resolve_id` to get one."
        ),
    )
    def cypher(query: str, parameters: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            return service.cypher(query, parameters)
        except Exception as exc:
            raise _fail(exc) from None

    @server.tool(
        name="resolve_id",
        title="Resolve a name to its graph id",
        description=(
            "Turn a name into the integer id the graph is indexed by, so you can "
            "write id-anchored Cypher. kind is one of repo | package | version | "
            "maintainer; for a version pass 'package@version' such as "
            "'chalk@5.3.0' or '@babel/core@7.24.0'. Ids are derived from the "
            "name rather than allocated, so an id always comes back; the "
            "`exists` field tells you whether the graph actually holds that node."
        ),
    )
    def resolve_id(kind: str, name: str) -> dict[str, Any]:
        try:
            return service.resolve_id(kind, name)
        except Exception as exc:
            raise _fail(exc) from None

    @server.tool(
        name="exposure_asof",
        title="Were we exposed at this instant",
        description=(
            "Repositories whose committed lockfile resolved this package — or "
            "exactly this version, if you pass one — at a single instant. This "
            "is the incident question: pass a timestamp inside a compromise "
            "window and get the repositories in scope, each with the interval "
            "over which it held. An empty result with an existing anchor is a "
            "proven negative for that instant — but only when the response also "
            "says answerable: true. When it says false the dataset itself could "
            "not answer (it is empty, or no ingest has finished), the empty "
            "result means nothing, and unanswerable_note says so: report that, "
            "never an all-clear. at_timestamp takes unix seconds or ISO-8601. "
            "Evidence is lockfile resolution, never deployment."
        ),
    )
    def exposure_asof(
        package: str, at_timestamp: int | str, version: str | None = None
    ) -> dict[str, Any]:
        try:
            return service.exposure_asof(package, version, at_timestamp)
        except Exception as exc:
            raise _fail(exc) from None

    @server.tool(
        name="blast_radius",
        title="Full blast radius of a package at an instant",
        description=(
            "Every repository downstream of a package at one instant, across all "
            "of its versions, with repository/version/resolution counts and the "
            "interval each resolution held over. Reaches through the full "
            "transitive closure the lockfile recorded, so it finds repositories "
            "that never named the package directly. at_timestamp takes unix "
            "seconds or ISO-8601."
        ),
    )
    def blast_radius(package: str, at_timestamp: int | str) -> dict[str, Any]:
        try:
            return service.blast_radius(package, at_timestamp)
        except Exception as exc:
            raise _fail(exc) from None

    @server.tool(
        name="maintainer_reach",
        title="Trust radius of a maintainer account",
        description=(
            "The packages an npm account can publish to and the repositories "
            "those packages reach — the 'if this account were phished tomorrow' "
            "question. Defaults to now (the still-open intervals); pass "
            "at_timestamp to ask it historically. Maintainer edges are a "
            "present-tense registry snapshot, which the response states "
            "explicitly."
        ),
    )
    def maintainer_reach(
        maintainer: str, at_timestamp: int | str | None = None
    ) -> dict[str, Any]:
        try:
            return service.maintainer_reach(maintainer, at_timestamp)
        except Exception as exc:
            raise _fail(exc) from None

    return server


def main() -> None:
    """Entry point for ``hindsight-mcp`` / ``python -m hindsight_mcp``."""
    build_server().run(transport="stdio")


if __name__ == "__main__":
    main()
