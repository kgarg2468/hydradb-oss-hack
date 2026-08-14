# Hindsight MCP server

A stdio [MCP](https://modelcontextprotocol.io) server that puts the bitemporal
dependency graph in front of an agent.

## The shape of the surface, and why

Comparable MCP code-graph servers ship on the order of thirty canned tools over
single-repository, present-tense data. That caps the agent at the questions
someone thought of in advance, and supply-chain incidents are not made of
anticipated questions — they are made of "which of our repos resolved *any*
version of this thing during these two hours, and who else could publish to it".

Hindsight makes the opposite trade:

- **one `cypher` tool** giving the raw read surface, so the agent composes the
  traversal the question actually needs;
- **one `schema` document** rich enough to make that possible — labels,
  properties, the bitemporal convention, the id-anchoring rule, and every
  OpenCypher construct this engine rejects, quoted with the error text it
  returns;
- **four canned tools** for the questions that get asked under incident
  pressure, where making the agent rediscover a three-pattern join is a waste of
  a turn.

Everything the agent could get wrong on its own is handled underneath: writes
are refused before they reach the database, results are capped and say so, and
every answer carries an explicit statement of what the evidence does and does
not prove.

## Evidence semantics

**This is the load-bearing honesty rule and it is enforced in code.**

An edge in this graph proves that a *committed lockfile resolved* a version over
an interval. It does not prove the dependency was installed, built, executed or
deployed. So every result from `exposure_asof`, `blast_radius` and
`maintainer_reach` carries:

```json
{
  "evidence": "resolved",
  "caveat": "Evidence is lockfile resolution only: a committed lockfile in this repository pinned this exact version over the stated interval. That is not proof the dependency was installed, built, executed or deployed, and it is not proof of compromise. Treat this as the scope to investigate."
}
```

No field outside `caveat` uses deployment language, and there is a test that
fails if one starts to. During an incident the value of this tool is being
trusted, and a tool that quietly upgrades "a lockfile pinned this" into "this
was running in production" is worse than no tool.

`maintainer_reach` carries a second caveat: the npm registry exposes only
*current* maintainers, so ownership is a present-tense overlay on a historical
graph.

## Tools

| tool | question | notes |
|---|---|---|
| `schema` | "what is in this graph and what can I write?" | Read this first. Also published as the `hindsight://schema` resource. |
| `cypher` | anything | Read-only, single statement, row-capped, deadlined. |
| `resolve_id` | "what id does this name have?" | The prerequisite for writing efficient `cypher`. |
| `exposure_asof` | "were we exposed to X (or exactly X@V) at instant T?" | Can prove a negative. |
| `blast_radius` | "everything downstream of X at instant T" | Repo/version/resolution rollups. |
| `maintainer_reach` | "what does this npm account reach?" | Defaults to now. |

### `schema`

No arguments. Returns markdown: node labels and their properties, edge types and
their endpoints, the bitemporal convention, how ids are derived, how to query
efficiently, worked recipes verified against a live node, the unsupported-
construct table, and the engine's limits.

It is generated from the live `Schema` object rather than hand-maintained, so it
cannot drift from the labels the server is actually pointed at.

### `cypher`

```
cypher(query: str, parameters?: object) -> {columns, rows, row_count, truncated, row_cap, elapsed_ms}
```

Rows come back as plain JSON — the HydraDB `{"type": ..., "value": ...}` wire
cells are unwrapped recursively.

**Refused before the query reaches the database:**

- any of `CREATE`, `MERGE`, `DELETE`, `DETACH`, `SET`, `REMOVE`, `DROP`,
  `FOREACH`, `CALL`, `LOAD`, `ALTER`, `GRANT`, `REVOKE`, `DENY`, `TERMINATE`,
  case-insensitively;
- the same, hidden after a semicolon;
- the same, hidden behind a quote that would fool a naive comment-stripper
  (`MATCH (n:HsPkg {name: '//'}) DELETE n`);
- more than one statement (a single trailing semicolon is fine);
- an unterminated string literal or block comment, because a query that cannot
  be scanned cannot be cleared;
- a leading clause other than `MATCH`, `OPTIONAL`, `UNWIND`, `RETURN`, `WITH`.

The scan runs over a code-only view of the query in which string literals,
backtick identifiers and comments have been blanked with offsets preserved, so
mutation keywords appearing *inside* strings or comments are correctly ignored —
`MATCH (n:HsPkg {name: 'create-react-app'}) RETURN n.name` is a read and is
allowed.

Rejections name the construct and the offset, because the consumer is a model
expected to fix its own query:

```
refused by the read-only guard: [MUTATION] this server is read-only and DELETE
removes data; remove the DELETE clause at offset 24 near: 'HsPkg {id: 1}) DELETE n'.
This server never writes; rewrite the statement as a read.
```

Results are capped at `HINDSIGHT_MCP_MAX_ROWS` rows (default 1000, engine
maximum 4096) and the cap is enforced by page size rather than by rewriting the
query — injecting a `LIMIT` into someone else's statement is how a guard
silently changes an answer. When a result is cut, `truncated` is `true` and a
`truncation_note` suggests narrowing or aggregating.

### `resolve_id`

```
resolve_id(kind: "repo"|"package"|"version"|"maintainer", name: str)
  -> {kind, name, label, id, exists, properties?, how_to_use, note?}
```

For `kind="version"` pass `package@version` — `chalk@5.3.0`, or
`@babel/core@7.24.0` (the split is on the *last* `@`).

Ids are derived (`blake2b` of a namespaced key, folded to 63 bits), not
allocated by the database, so an id always comes back. `exists` tells you
whether the graph actually holds that node — which means "no rows" is a real
negative rather than a lookup failure.

### `exposure_asof`

```
exposure_asof(package: str, at_timestamp: int|str, version?: str)
```

`at_timestamp` accepts unix seconds or ISO-8601 (`"2025-09-08T20:33:00Z"`).

With `version` set this is the incident question. Each returned repository
carries the interval its resolution held over, in both raw and ISO form, with
`open_interval: true` when it is still current.

### `blast_radius`

```
blast_radius(package: str, at_timestamp: int|str)
```

Adds `repo_count`, `version_count`, `resolution_count` and a per-repository
rollup ordered widest-first. Reaches through the full transitive closure the
lockfile recorded, so it finds repositories that never named the package
directly.

### `maintainer_reach`

```
maintainer_reach(maintainer: str, at_timestamp?: int|str)
```

Defaults to now — the "if this account were phished tomorrow" question. Reports
`maintains_packages` (everything the account can publish to) separately from
`reached_packages` (the subset this organisation resolves), and
`repo_package_pairs` alongside `reached_repo_count` because the repo count
saturates once a package is ubiquitous.

## Example agent transcripts

### 1. Were we exposed during the chalk/debug compromise window?

> **User:** The chalk npm package was compromised on 2025-09-08 between about
> 20:33 and 22:30 UTC. Were we exposed?

```
→ exposure_asof {"package": "chalk", "at_timestamp": "2025-09-08T20:33:00Z"}
← {
    "package": "chalk", "version": null,
    "at": 1757363580, "at_iso": "2025-09-08T20:33:00Z",
    "anchor": {"kind": "package", "name": "chalk", "id": 4472955929141537135, "exists": true},
    "resolved_by_repo_count": 3,
    "repos": [
      {"slug": "acme/web", "version": "5.3.0", "valid_from": 1751000000,
       "valid_to": 4102444800, "valid_to_iso": null, "open_interval": true},
      ...
    ],
    "evidence": "resolved",
    "caveat": "Evidence is lockfile resolution only: ..."
  }

→ exposure_asof {"package": "chalk", "version": "5.6.1", "at_timestamp": "2025-09-08T20:33:00Z"}
← { "repos": [], "anchor": {"exists": false},
    "note": "no HsVer node for 'chalk@5.6.1' is in the graph at all, so no
             repository has ever resolved it. This is a real negative, not a
             lookup failure",
    "evidence": "resolved", "caveat": "..." }
```

> **Agent:** Three repositories resolved `chalk` during that window, all on
> 5.3.0 — none of them on the malicious 5.6.1, which never appears anywhere in
> our lockfile history. This is evidence of *resolution*: it shows what the
> committed lockfiles pinned, not what was built or deployed.

Proving the negative is the point. `anchor.exists: false` says the malicious
version is absent from the entire history, not merely absent from this instant.

### 2. Which maintainer account has the largest blast radius?

> **User:** If exactly one npm account we depend on got phished, which one hurts
> the most?

```
→ maintainer_reach {"maintainer": "qix"}
← { "maintainer": "qix", "at": 1786000000,
    "maintains_package_count": 12, "reached_package_count": 3,
    "reached_packages": ["ansi-styles", "chalk", "debug"],
    "reached_repo_count": 8,
    "reached_repos": [{"slug": "acme/web", "via_packages": ["chalk", "debug"], "package_count": 2}, ...],
    "repo_package_pairs": 14,
    "evidence": "resolved",
    "maintainer_caveat": "Maintainer edges are a present-tense snapshot of npm registry ownership..." }
```

> **Agent:** `qix` reaches all 8 repositories through 3 packages, 14
> repo×package pairs — the widest single-account radius. Note this is
> present-day registry ownership projected onto resolution history.

### 3. A question no canned tool covers

> **User:** For the repos that had chalk 5.0.0 last January, what *else* were
> they pulling at the time? I want to know if they were stale in general.

```
→ schema {}
← "# Hindsight — bitemporal npm dependency and maintainer graph ... ALWAYS enter
   the graph through {id: $id} ... AS-OF predicate: e.valid_from <= $t AND e.valid_to > $t ..."

→ resolve_id {"kind": "version", "name": "chalk@5.0.0"}
← {"id": 2298471293847120384, "label": "HsVer", "exists": true,
   "how_to_use": "pass id=2298471293847120384 as a parameter and anchor the
                  pattern on it, e.g. MATCH (n:HsVer {id: $id}) ..."}

→ cypher {"query": "MATCH (r:HsRepo)-[e:HS_RESOLVES]->(v:HsVer {id: $vid}) WHERE e.valid_from <= $t AND e.valid_to > $t RETURN r.slug, e.valid_from",
          "parameters": {"vid": 2298471293847120384, "t": 1704067200}}
← {"columns": ["r.slug", "e.valid_from"], "rows": [["acme/web", 1698000000]],
   "row_count": 1, "truncated": false, "elapsed_ms": 4.1}

→ resolve_id {"kind": "repo", "name": "acme/web"}
← {"id": 8812993017264400211, "exists": true}

→ cypher {"query": "MATCH (r:HsRepo {id: $rid})-[e:HS_RESOLVES]->(v:HsVer) WHERE e.valid_from <= $t AND e.valid_to > $t RETURN v.pkg, v.version, e.valid_from",
          "parameters": {"rid": 8812993017264400211, "t": 1704067200}}
← {"columns": [...], "rows": [["chalk", "5.0.0", 1698000000], ["lodash", "4.17.21", 1690000000], ...],
   "row_count": 847, "truncated": false, "elapsed_ms": 12.6}
```

That last question has no canned tool and needs none. The agent read the schema,
resolved two ids and composed its own AS-OF traversal — which is the entire
argument for shipping `cypher` plus a schema instead of thirty tools.

### 4. Self-correcting from a rejection

```
→ cypher {"query": "MATCH (v:HsVer) WHERE v.pkg IN ['chalk', 'debug'] RETURN v.version"}
← ERROR: HydraDB refused or failed the query: HTTP 400: OpenCypher query is not
  supported yet: WHERE currently supports boolean combinations of property
  comparisons. If this is an 'OpenCypher query is not supported yet' message,
  check the unsupported-constructs table in the schema tool — the same text
  appears there with the workaround.
```

The schema document lists that exact engine string against `IN`, with the
workaround ("ask one id-anchored question per candidate"), so the agent recovers
in one step instead of retrying variations. Attempted writes fail earlier and
more loudly:

```
→ cypher {"query": "MATCH (n:HsPkg {id: 1}) SET n.reviewed = true"}
← ERROR: refused by the read-only guard: [MUTATION] this server is read-only and
  SET writes properties or labels; remove the SET clause at offset 24.
  This server never writes; rewrite the statement as a read.
```

## Registering the server

Install the SDK and register the stdio command with your MCP client.

```bash
pip install -r requirements-dev.txt   # or: pip install -e '.[mcp]'
```

Claude Code — `.mcp.json` in the repository root, or `claude mcp add`:

```json
{
  "mcpServers": {
    "hindsight": {
      "command": "python",
      "args": ["-m", "hindsight_mcp"],
      "cwd": "/absolute/path/to/hindsight",
      "env": {
        "PYTHONPATH": "/absolute/path/to/hindsight",
        "HINDSIGHT_HYDRA_URL": "http://127.0.0.1:8443",
        "HINDSIGHT_HYDRA_TOKEN": "local-development-token-32-bytes",
        "HINDSIGHT_HYDRA_NS": "default",
        "HINDSIGHT_HYDRA_GRAPH": "default",
        "HINDSIGHT_HYDRA_CELL": "cell-0"
      }
    }
  }
}
```

`cwd`/`PYTHONPATH` are only needed when running from a checkout. If the package
is installed (`pip install -e '.[mcp]'`) both can be dropped and the console
script works instead:

```json
{ "mcpServers": { "hindsight": { "command": "hindsight-mcp", "args": [] } } }
```

Claude Desktop — the same block in `claude_desktop_config.json`. Any other MCP
client takes the same command; the server speaks stdio and needs no port.

Verify the registration without a client:

```bash
python -m hindsight_mcp    # should sit waiting on stdin, not exit
```

## Configuration

| variable | default | meaning |
|---|---|---|
| `HINDSIGHT_HYDRA_URL` | `http://127.0.0.1:8443` | node endpoint |
| `HINDSIGHT_HYDRA_TOKEN` | `local-development-token-32-bytes` | bearer token |
| `HINDSIGHT_HYDRA_NS` | `default` | graph namespace |
| `HINDSIGHT_HYDRA_GRAPH` | `default` | graph |
| `HINDSIGHT_HYDRA_CELL` | `cell-0` | cell (only `cell-0` exists) |
| `HINDSIGHT_MCP_MAX_ROWS` | `1000` | row cap, clamped to the engine's 4096 |
| `HINDSIGHT_MCP_TIMEOUT` | `20` | client deadline in seconds, clamped to the server's hard 30 s cap |
| `HINDSIGHT_NODE_PREFIX` | `Hs` | node label prefix |
| `HINDSIGHT_REL_PREFIX` | `HS` | relationship type prefix |

The prefixes exist because HydraDB deletes at ~3 nodes/sec, which makes label
namespacing the only workable form of test isolation — the integration suite
points the whole server at `McpTest*` on the same node.
The old `HINDSIGHT_MCP_NODE_PREFIX` and `HINDSIGHT_MCP_REL_PREFIX` names still
work as fallbacks, while the shared names win when both are set.

## Layout

```
hindsight_mcp/
  guard.py       read-only enforcement: the literal-aware scanner and blocklist
  queries.py     Cypher builders, all id-anchored and parameterised
  schema_doc.py  the self-description the `schema` tool and resource serve
  service.py     tool bodies: coercion, row cap, rollups, evidence fields
  server.py      MCP registration — the only module that imports the SDK
```

Only `server.py` needs `mcp` installed, so the guard, the builders and the
schema document are testable as plain Python.

## Tests

```bash
pytest tests/unit                    # no services needed
pytest tests/integration -m integration   # needs a live node
```

`tests/unit/test_mcp_guard.py` is table-driven and adversarial: plain mutations,
mixed case, writes hidden after a semicolon, writes hidden behind a quote that
fakes a comment, and a matching table of legitimate reads — including ones whose
string literals and comments contain mutation keywords — that must pass.
Integration tests seed a three-repository fixture with a version bump and a
dropped dependency under `McpTest*`, so an implementation that ignored its
timestamp could not pass them.
