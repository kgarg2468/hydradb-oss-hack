"""The graph's self-description, for an agent that is about to write Cypher.

This module is the reason the ``cypher`` tool is usable. A raw query surface
over an unfamiliar graph is a trap: the agent guesses label names, guesses that
property predicates are indexed, guesses that ``IN`` exists, and burns its turns
on parse errors. So the schema document ships three things together —

* **what is in the graph** (labels, properties, edge types, how ids are minted),
* **the bitemporal convention**, without which every interval predicate is
  off-by-one,
* **what the engine refuses**, quoted with the error text it actually returns,
  so a rejection is recognisable rather than mysterious,

— plus worked query recipes for the shapes that are known to execute.

Everything is derived from a :class:`~hindsight.graphbuild.Schema`, so the
document is correct for whichever label set the server is pointed at (production
``Hs*`` or a test prefix) rather than being a hand-maintained copy that drifts.
"""

from __future__ import annotations

from hindsight.graphbuild import DEFAULT_SCHEMA, Schema
from hindsight.history import SENTINEL

#: Open intervals end here (2100-01-01T00:00:00Z) because the engine has no
#: ``IS NULL`` and therefore no way to test for a missing upper bound.
FAR_FUTURE = SENTINEL

BITEMPORAL_NOTE = (
    "Every RESOLVES edge carries two half-open intervals. Valid time "
    "[valid_from, valid_to) is when the fact was true in the world: the commit "
    "that wrote the lockfile entry until the commit that changed it. "
    "Transaction time [tx_from, tx_to) is when this graph learned it. Both "
    "bounds are integer unix seconds, valid_from is INCLUSIVE and valid_to is "
    "EXCLUSIVE, so an AS-OF read at exactly the commit timestamp that swapped a "
    f"version sees only the new one. An interval that is still open ends at "
    f"FAR_FUTURE = {FAR_FUTURE} (2100-01-01T00:00:00Z) rather than at null, "
    "because this engine has no IS NULL. The AS-OF predicate is therefore "
    "always: WHERE e.valid_from <= $t AND e.valid_to > $t"
)

EVIDENCE_NOTE = (
    "RESOLVES means a committed lockfile in that repository pinned that exact "
    "version over that interval. It does NOT mean the code was installed, "
    "built, executed or deployed. Any answer derived from these edges is "
    "scope for investigation, not confirmed compromise, and must be reported "
    "that way."
)

ID_NOTE = (
    "Ids are not allocated by the database, they are derived: "
    "blake2b(namespaced_key) folded to 63 bits, computed by the application. "
    "The key forms are 'repo:<slug>', 'pkg:<name>', 'pv:<name>@<version>' and "
    "'maint:<name>'. The same name always yields the same id on every machine "
    "and every run, which is what makes the ingest idempotent — and it means an "
    "id can be computed for a name that is not in the graph, so a lookup "
    "returning no rows is a real 'not present', not a lookup failure. That "
    "holds only for a dataset that holds something: against an empty or "
    "mis-pointed label namespace every lookup returns no rows and 'not present' "
    "would be true of every name that has ever existed. The canned tools decide "
    "this for you and return answerable=false with an unanswerable_note instead "
    "of a negative; if you are reading zero rows from your own Cypher, call one "
    "of them, or count the repository nodes, before reporting an absence."
)

EFFICIENCY_NOTE = (
    "HydraDB has no secondary property index. A predicate on a non-id property "
    "scans the whole label: measured at 7.9 s against 3.9 ms for the id-anchored "
    "form of the same question on a 111k-edge graph, a ~2000x difference. So "
    "ALWAYS enter the graph through {id: $id}. To go from a name to an id, call "
    "the resolve_id tool (kind = repo | package | version | maintainer; for a "
    "version pass 'name@version', e.g. 'chalk@5.3.0'), then pass the integer it "
    "returns as a parameter. Never write a query whose only predicate is a name."
)

#: Constructs the engine refuses, with the message it returns. Quoting the real
#: error text matters: an agent that sees the same string back from the server
#: can match it to the entry here and correct itself in one step.
UNSUPPORTED: tuple[tuple[str, str, str], ...] = (
    (
        "IN",
        "WHERE currently supports boolean combinations of property comparisons",
        "No list membership. Ask one id-anchored question per candidate and "
        "combine the answers yourself.",
    ),
    (
        "CONTAINS / ENDS WITH",
        "WHERE currently supports boolean combinations of property comparisons",
        "Only STARTS WITH is available for string matching.",
    ),
    (
        "IS NULL / IS NOT NULL",
        "WHERE currently supports boolean combinations of property comparisons",
        f"Open intervals use the sentinel valid_to = {FAR_FUTURE} instead of null.",
    ),
    (
        "min() / max()",
        "RETURN currently supports <binding>.<property> or count(*)",
        "Only count, sum, avg and collect aggregate. Fold extremes client-side.",
    ),
    (
        "count(DISTINCT x)",
        "DISTINCT aggregate arguments are not executable in Query engine",
        "Use RETURN DISTINCT on the tuple and count the rows client-side.",
    ),
    (
        "RETURN <relationship variable>",
        "unbound variable e / RETURN currently supports <binding>.<property> or count(*)",
        "A relationship variable cannot be projected, and neither can e.id. "
        "Relationship properties written by SET (valid_from, valid_to, tx_from, "
        "tx_to) DO project. Return endpoint properties for everything else.",
    ),
    (
        "RETURN <node variable> / RETURN *",
        "RETURN * is not executable in Query engine",
        "Project explicit properties: RETURN r.slug, v.version.",
    ),
    (
        "bare MATCH (n)",
        "node-only MATCH requires an id, label, or property predicate",
        "A WHERE clause does not count. Put a label or {id: $id} in the pattern.",
    ),
    (
        "shortestPath / unbounded *",
        "unbounded variable-length MATCH requires an explicit max hop",
        "Variable-length MATCH also requires a fixed source id. Express fan-out "
        "as comma-separated patterns sharing a binding instead — that form is "
        "executed natively and is how blast_radius and maintainer_reach work.",
    ),
    (
        "multiple statements",
        "query transport requires exactly one Cypher statement",
        "One statement per call. A single trailing semicolon is fine.",
    ),
    (
        "WITH as a pipeline stage",
        "WITH is pass-through only",
        "No aliasing, filtering or projection in WITH, so no multi-stage "
        "pipelines inside one statement.",
    ),
)

#: Limits that bite in practice.
LIMITS: tuple[tuple[str, str], ...] = (
    ("page_size", "capped at 4096; larger result sets must follow next_cursor"),
    ("UNWIND batch", "capped at 1024 items"),
    ("query timeout", "hard server-side cap of 30000 ms, not raisable by the client"),
)

#: Query shapes verified against a live node. These are the same builders the
#: canned tools use, written out so an agent can adapt rather than invent.
RECIPES: tuple[tuple[str, str], ...] = (
    (
        "AS-OF: what one repo resolved at instant t",
        "MATCH (r:{repo} {{id: $rid}})-[e:{resolves}]->(v:{version}) "
        "WHERE e.valid_from <= $t AND e.valid_to > $t "
        "RETURN v.pkg, v.version, e.valid_from, e.valid_to",
    ),
    (
        "Exposure: who resolved one exact version at instant t",
        "MATCH (r:{repo})-[e:{resolves}]->(v:{version} {{id: $vid}}) "
        "WHERE e.valid_from <= $t AND e.valid_to > $t "
        "RETURN r.slug, r.name, e.valid_from, e.valid_to",
    ),
    (
        "Blast radius: who resolved ANY version of a package at instant t",
        "MATCH (v:{version})-[:{version_of}]->(p:{package} {{id: $pid}}), "
        "(r:{repo})-[e:{resolves}]->(v) "
        "WHERE e.valid_from <= $t AND e.valid_to > $t "
        "RETURN DISTINCT r.slug, v.version, e.valid_from, e.valid_to",
    ),
    (
        "Maintainer reach: the trust radius of one account at instant t",
        "MATCH (m:{maintainer} {{id: $mid}})-[:{maintains}]->(p:{package}), "
        "(v:{version})-[:{version_of}]->(p), (r:{repo})-[e:{resolves}]->(v) "
        "WHERE e.valid_from <= $t AND e.valid_to > $t "
        "RETURN DISTINCT p.name, r.slug, v.version",
    ),
    (
        "Server-side aggregation: how many edges match",
        "MATCH (v:{version})-[:{version_of}]->(p:{package} {{id: $pid}}), "
        "(r:{repo})-[e:{resolves}]->(v) "
        "WHERE e.valid_from <= $t AND e.valid_to > $t RETURN count(*)",
    ),
)


def node_labels(schema: Schema = DEFAULT_SCHEMA) -> list[dict]:
    return [
        {
            "label": schema.repo,
            "kind": "repo",
            "describes": "one source repository whose lockfile history was ingested",
            "id_key": "repo:<slug>",
            "properties": {
                "id": "int, derived, the only indexed way in",
                "slug": "str, 'org/name'",
                "name": "str, display name",
                "service": "str, e.g. the owning team or system",
                "first_ts": "int, unix seconds of the oldest lockfile snapshot",
                "last_ts": "int, unix seconds of the newest lockfile snapshot",
                "snapshots": "int, how many lockfile commits were walked",
            },
        },
        {
            "label": schema.package,
            "kind": "package",
            "describes": "an npm package, independent of version",
            "id_key": "pkg:<name>",
            "properties": {"id": "int, derived", "name": "str, npm package name"},
        },
        {
            "label": schema.version,
            "kind": "version",
            "describes": "one exact published version of a package",
            "id_key": "pv:<name>@<version>",
            "properties": {
                "id": "int, derived",
                "pkg": "str, package name",
                "version": "str, exact version",
                "key": "str, 'pkg@version'",
                "pkg_id": "int, id of the owning package node",
            },
        },
        {
            "label": schema.maintainer,
            "kind": "maintainer",
            "describes": "an npm registry account with publish rights",
            "id_key": "maint:<name>",
            "properties": {"id": "int, derived", "name": "str, npm account name"},
        },
        {
            "label": schema.watermark,
            "kind": "watermark",
            "describes": (
                "ingest bookkeeping: the newest commit timestamp already loaded "
                "for a repo. Not part of the analytical graph; ignore it when "
                "answering questions"
            ),
            "id_key": "wm:<slug>",
            "properties": {
                "id": "int, derived",
                "slug": "str",
                "repo_id": "int",
                "last_commit_ts": "int",
                "last_ingest_tx": "int",
            },
        },
    ]


def relationships(schema: Schema = DEFAULT_SCHEMA) -> list[dict]:
    return [
        {
            "type": schema.resolves,
            "from": schema.repo,
            "to": schema.version,
            "bitemporal": True,
            "describes": (
                "a committed lockfile in this repo pinned this exact version "
                "over [valid_from, valid_to). The full transitive closure is "
                "recorded, so a repo is linked to packages it never names "
                "directly"
            ),
            "properties": {
                "valid_from": "int, unix seconds, INCLUSIVE",
                "valid_to": f"int, unix seconds, EXCLUSIVE, {FAR_FUTURE} if still open",
                "tx_from": "int, unix seconds, when this graph learned the fact",
                "tx_to": f"int, unix seconds, {FAR_FUTURE} if still believed",
            },
            "note": "e.id is not projectable; the four properties above are",
        },
        {
            "type": schema.version_of,
            "from": schema.version,
            "to": schema.package,
            "bitemporal": False,
            "describes": "which package a version belongs to",
            "properties": {},
        },
        {
            "type": schema.maintains,
            "from": schema.maintainer,
            "to": schema.package,
            "bitemporal": False,
            "describes": "publish rights on a package",
            "properties": {},
            "note": (
                "PRESENT TENSE ONLY. The npm registry exposes current "
                "maintainers, so this is a present-day overlay on a historical "
                "graph. 'Account X reached 8 repos at time T' strictly means "
                "'the packages X maintains today were resolved by 8 repos at T'"
            ),
        },
    ]


def graph_schema(schema: Schema = DEFAULT_SCHEMA) -> dict:
    """The whole self-description as structured data."""
    return {
        "graph": "Hindsight — bitemporal npm dependency and maintainer graph",
        "question_shapes": [
            "were we exposed to package X (or exactly X@V) during a window",
            "what is the blast radius of package X at instant T",
            "which maintainer account reaches the most of our repos",
            "what did repo R resolve at instant T",
        ],
        "labels": node_labels(schema),
        "relationships": relationships(schema),
        "bitemporal": {
            "convention": BITEMPORAL_NOTE,
            "far_future": FAR_FUTURE,
            "asof_predicate": "e.valid_from <= $t AND e.valid_to > $t",
            "time_unit": "integer unix seconds (UTC)",
        },
        "ids": ID_NOTE,
        "how_to_query_efficiently": EFFICIENCY_NOTE,
        "unsupported": [
            {"construct": name, "engine_error": err, "workaround": fix}
            for name, err, fix in UNSUPPORTED
        ],
        "limits": [{"limit": name, "detail": detail} for name, detail in LIMITS],
        "recipes": [
            {"question": question, "cypher": body.format(**schema.__dict__)}
            for question, body in RECIPES
        ],
        "evidence_semantics": EVIDENCE_NOTE,
    }


def render_markdown(schema: Schema = DEFAULT_SCHEMA) -> str:
    """The same document as markdown, which is what the MCP resource serves."""
    doc = graph_schema(schema)
    out: list[str] = [
        f"# {doc['graph']}",
        "",
        "Questions this graph is shaped to answer:",
        "",
    ]
    out += [f"- {q}" for q in doc["question_shapes"]]
    out += ["", "## Evidence semantics (read this before phrasing any answer)", "", EVIDENCE_NOTE, ""]

    out += ["## Node labels", ""]
    for label in doc["labels"]:
        out.append(f"### `(:{label['label']})` — {label['describes']}")
        out.append("")
        out.append(f"id key: `{label['id_key']}`")
        out.append("")
        out += [f"- `{name}` — {desc}" for name, desc in label["properties"].items()]
        out.append("")

    out += ["## Relationships", ""]
    for rel in doc["relationships"]:
        out.append(
            f"### `(:{rel['from']})-[:{rel['type']}]->(:{rel['to']})` — {rel['describes']}"
        )
        out.append("")
        if rel["properties"]:
            out += [f"- `{name}` — {desc}" for name, desc in rel["properties"].items()]
        else:
            out.append("- no properties other than the internal `id`")
        if rel.get("note"):
            out += ["", f"> {rel['note']}"]
        out.append("")

    out += [
        "## Bitemporal convention",
        "",
        doc["bitemporal"]["convention"],
        "",
        f"AS-OF predicate: `{doc['bitemporal']['asof_predicate']}`",
        "",
        "## Ids",
        "",
        doc["ids"],
        "",
        "## How to query efficiently",
        "",
        doc["how_to_query_efficiently"],
        "",
        "## Recipes (verified against a live node)",
        "",
    ]
    for recipe in doc["recipes"]:
        out += [f"**{recipe['question']}**", "", "```cypher", recipe["cypher"], "```", ""]

    out += ["## Unsupported — the engine rejects these", ""]
    out += ["| construct | engine error | what to do instead |", "|---|---|---|"]
    out += [
        f"| `{item['construct']}` | {item['engine_error']} | {item['workaround']} |"
        for item in doc["unsupported"]
    ]
    out += ["", "## Limits", ""]
    out += [f"- **{item['limit']}** — {item['detail']}" for item in doc["limits"]]
    out += [
        "",
        "Mutations (`CREATE`, `MERGE`, `DELETE`, `DETACH`, `SET`, `REMOVE`, and "
        "friends) are refused by this server before they reach the database, "
        "including when they follow a semicolon or hide behind a comment. The "
        "store is append-only and deletes run at ~3 nodes/sec, so there is no "
        "undo.",
        "",
    ]
    return "\n".join(out)


__all__ = [
    "BITEMPORAL_NOTE",
    "EFFICIENCY_NOTE",
    "EVIDENCE_NOTE",
    "FAR_FUTURE",
    "ID_NOTE",
    "LIMITS",
    "RECIPES",
    "UNSUPPORTED",
    "graph_schema",
    "node_labels",
    "relationships",
    "render_markdown",
]
