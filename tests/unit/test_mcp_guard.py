"""The read-only guard is the only thing standing between an agent and an
append-only database that deletes at three nodes per second, so it is tested
adversarially rather than representatively.

Two failure directions matter equally and are both covered below:

* a write that gets through (catastrophic — there is no undo), including the
  classic tricks of hiding it after a semicolon or behind a quote that a naive
  comment-stripper would misread;
* a legitimate read that gets refused (merely bad — but it makes the raw
  `cypher` tool useless, and the raw tool is the point of this server).
"""

import pytest

from hindsight_mcp import guard

# --------------------------------------------------------------------- rejected

MUTATIONS = [
    ("plain CREATE", "CREATE (n:HsPkg {id: 1})"),
    ("CREATE after MATCH", "MATCH (n:HsPkg {id: 1}) CREATE (m:HsPkg {id: 2})"),
    ("MERGE", "MATCH (n:HsPkg {id: 1}) MERGE (m:HsPkg {id: 2})"),
    ("DELETE", "MATCH (n:HsPkg {id: 1}) DELETE n"),
    ("DETACH DELETE", "MATCH (n:HsPkg {id: 1}) DETACH DELETE n"),
    ("SET property", "MATCH (n:HsPkg {id: 1}) SET n.name = 'x'"),
    ("SET label", "MATCH (n:HsPkg {id: 1}) SET n:Compromised"),
    ("REMOVE", "MATCH (n:HsPkg {id: 1}) REMOVE n.name"),
    ("DROP", "DROP INDEX ON :HsPkg(name)"),
    ("FOREACH", "MATCH (n:HsPkg {id: 1}) FOREACH (x IN [1] | SET n.a = x)"),
    ("CALL a procedure", "CALL db.labels()"),
    ("LOAD CSV", "LOAD CSV FROM 'file:///x.csv' AS row RETURN row"),
    ("UNWIND then CREATE", "UNWIND $rows AS row CREATE (n {id: row.id})"),
    ("UNWIND then MERGE + SET", "UNWIND $rows AS row MERGE (n {id: row.id}) SET n:HsPkg"),
    # Case is not a defence.
    ("lowercase delete", "MATCH (n:HsPkg {id: 1}) delete n"),
    ("mixed case CrEaTe", "MATCH (n:HsPkg {id: 1}) CrEaTe (m:HsPkg {id: 2})"),
    ("mixed case dEtAcH", "MATCH (n:HsPkg {id: 1}) dEtAcH dElEtE n"),
    ("lowercase merge", "unwind $rows as row merge (n {id: row.id})"),
    # Hidden after a statement separator.
    (
        "CREATE after semicolon",
        "MATCH (n:HsPkg {id: 1}) RETURN n.name; CREATE (m:HsPkg {id: 2})",
    ),
    (
        "DELETE after semicolon and newline",
        "MATCH (n:HsPkg {id: 1}) RETURN n.name;\nMATCH (m:HsPkg {id: 2}) DELETE m",
    ),
    (
        "lowercase set after two semicolons",
        "MATCH (n:HsPkg {id: 1}) RETURN n.name;; match (m:HsPkg {id: 2}) set m.x = 1",
    ),
    # Comment-obfuscated: a stripper that does not understand string literals
    # would treat the rest of these lines as a comment and miss the write.
    (
        "quote opens a fake line comment",
        "MATCH (n:HsPkg {name: '//'}) DELETE n",
    ),
    (
        "quote opens a fake block comment",
        "MATCH (n:HsPkg {name: '/*'}) DELETE n",
    ),
    (
        "double-quoted fake comment",
        'MATCH (n:HsPkg {name: "// harmless"}) DETACH DELETE n',
    ),
    (
        "escaped quote keeps the literal open",
        r"MATCH (n:HsPkg {name: 'it\'s //'}) DELETE n",
    ),
    (
        "write on the line after a real comment",
        "MATCH (n:HsPkg {id: 1}) // just looking\nDELETE n",
    ),
    (
        "write after a block comment",
        "MATCH (n:HsPkg {id: 1}) /* just looking */ SET n.name = 'x'",
    ),
    (
        "backtick identifier then write",
        "MATCH (n:`HsPkg` {id: 1}) DELETE n",
    ),
    (
        "comment inside a comment marker",
        "/* MATCH */ MATCH (n:HsPkg {id: 1}) REMOVE n.name",
    ),
]

MULTI_STATEMENT = [
    (
        "two reads",
        "MATCH (n:HsPkg {id: 1}) RETURN n.name; MATCH (n:HsPkg {id: 2}) RETURN n.name",
    ),
    (
        "read then read across lines",
        "MATCH (n:HsPkg {id: 1}) RETURN n.name;\nMATCH (n:HsPkg {id: 2}) RETURN n.name",
    ),
]

MALFORMED = [
    ("unterminated single quote", "MATCH (n:HsPkg {name: 'oops}) RETURN n.name"),
    ("unterminated double quote", 'MATCH (n:HsPkg {name: "oops}) RETURN n.name'),
    ("unterminated backtick", "MATCH (n:`HsPkg {id: 1}) RETURN n.name"),
    ("unterminated block comment", "MATCH (n:HsPkg {id: 1}) /* RETURN n.name"),
]

BAD_LEADING_CLAUSE = [
    ("EXPLAIN", "EXPLAIN MATCH (n:HsPkg {id: 1}) RETURN n.name"),
    ("PROFILE", "PROFILE MATCH (n:HsPkg {id: 1}) RETURN n.name"),
    ("SHOW", "SHOW INDEXES"),
    ("USE", "USE other MATCH (n:HsPkg {id: 1}) RETURN n.name"),
]

EMPTY = [("empty", ""), ("whitespace", "   \n\t "), ("comment only", "// nothing here")]

# ---------------------------------------------------------------------- accepted

READS = [
    ("id-anchored node read", "MATCH (n:HsPkg {id: $id}) RETURN n.name"),
    (
        "AS-OF interval read",
        "MATCH (r:HsRepo {id: $rid})-[e:HS_RESOLVES]->(v:HsVer) "
        "WHERE e.valid_from <= $t AND e.valid_to > $t RETURN v.pkg, v.version",
    ),
    (
        "relationship properties projected",
        "MATCH (r:HsRepo)-[e:HS_RESOLVES]->(v:HsVer {id: $vid}) "
        "WHERE e.valid_from <= $t AND e.valid_to > $t "
        "RETURN r.slug, e.valid_from, e.valid_to",
    ),
    (
        "three-pattern maintainer join",
        "MATCH (m:HsMaint {id: $mid})-[:HS_MAINTAINS]->(p:HsPkg), "
        "(v:HsVer)-[:HS_VERSION_OF]->(p), (r:HsRepo)-[e:HS_RESOLVES]->(v) "
        "WHERE e.valid_from <= $t AND e.valid_to > $t RETURN DISTINCT p.name, r.slug",
    ),
    ("UNWIND driven read", "UNWIND $ids AS i MATCH (n:HsPkg {id: i}) RETURN n.name"),
    ("OPTIONAL MATCH", "OPTIONAL MATCH (n:HsPkg {id: $id}) RETURN n.name"),
    ("aggregate", "MATCH (n:HsPkg {id: $id}) RETURN count(*)"),
    ("order and limit", "MATCH (n:HsPkg {id: $id}) RETURN n.name AS p ORDER BY p LIMIT 10"),
    ("trailing semicolon", "MATCH (n:HsPkg {id: $id}) RETURN n.name;"),
    ("trailing semicolon and whitespace", "MATCH (n:HsPkg {id: $id}) RETURN n.name ;  \n"),
    ("lowercase read", "match (n:HsPkg {id: $id}) return n.name"),
    # Mutation keywords that are data, not clauses.
    (
        "package literally named create-react-app",
        "MATCH (n:HsPkg {name: 'create-react-app'}) RETURN n.name",
    ),
    (
        "string literal containing DELETE",
        "MATCH (n:HsPkg {id: $id}) WHERE n.name STARTS WITH 'DELETE ME' RETURN n.name",
    ),
    (
        "double-quoted string containing MERGE",
        'MATCH (n:HsPkg {id: $id}) WHERE n.name STARTS WITH "MERGE" RETURN n.name',
    ),
    (
        "line comment mentioning CREATE",
        "// I am not going to CREATE anything\nMATCH (n:HsPkg {id: $id}) RETURN n.name",
    ),
    (
        "block comment mentioning DELETE",
        "MATCH (n:HsPkg {id: $id}) /* no DELETE here */ RETURN n.name",
    ),
    (
        "trailing comment mentioning SET",
        "MATCH (n:HsPkg {id: $id}) RETURN n.name // SET is only a word here",
    ),
    # Word-boundary and property-access cases.
    ("property named settings", "MATCH (n:HsPkg {id: $id}) RETURN n.settings"),
    ("property literally named set", "MATCH (n:HsPkg {id: $id}) RETURN n.set"),
    ("property named created_at", "MATCH (n:HsPkg {id: $id}) RETURN n.created_at"),
    ("parameter named $create", "MATCH (n:HsPkg {id: $create}) RETURN n.name"),
    ("relationship type SET_BY", "MATCH (n:HsPkg {id: $id})-[:SET_BY]->(m:HsPkg) RETURN m.name"),
    ("escaped quote inside a literal", r"MATCH (n:HsPkg {name: 'it\'s fine'}) RETURN n.name"),
]


@pytest.mark.parametrize("name, query", MUTATIONS, ids=[n for n, _ in MUTATIONS])
def test_mutations_are_refused(name, query):
    rejection = guard.check(query)
    assert rejection is not None, f"{name}: a write was accepted"
    assert rejection.code == "MUTATION", f"{name}: refused for the wrong reason"
    # The message has to name the construct, because the caller is a model that
    # is expected to fix its own query from the error alone.
    assert "read-only" in rejection.message
    assert rejection.offset is not None


@pytest.mark.parametrize("name, query", MULTI_STATEMENT, ids=[n for n, _ in MULTI_STATEMENT])
def test_multi_statement_input_is_refused(name, query):
    rejection = guard.check(query)
    assert rejection is not None
    assert rejection.code == "MULTI_STATEMENT"
    assert "one Cypher statement" in rejection.message


@pytest.mark.parametrize("name, query", MALFORMED, ids=[n for n, _ in MALFORMED])
def test_unterminated_literals_are_refused(name, query):
    rejection = guard.check(query)
    assert rejection is not None
    assert rejection.code == "UNTERMINATED"
    assert "refused" in rejection.message


@pytest.mark.parametrize(
    "name, query", BAD_LEADING_CLAUSE, ids=[n for n, _ in BAD_LEADING_CLAUSE]
)
def test_unsupported_leading_clauses_are_refused(name, query):
    rejection = guard.check(query)
    assert rejection is not None
    assert rejection.code in {"LEADING_CLAUSE", "MUTATION"}


@pytest.mark.parametrize("name, query", EMPTY, ids=[n for n, _ in EMPTY])
def test_empty_input_is_refused(name, query):
    rejection = guard.check(query)
    assert rejection is not None
    assert rejection.code == "EMPTY"


@pytest.mark.parametrize("name, query", READS, ids=[n for n, _ in READS])
def test_legitimate_reads_pass(name, query):
    rejection = guard.check(query)
    assert rejection is None, f"{name}: a valid read was refused — {rejection}"
    assert guard.is_read_only(query)


def test_assert_read_only_raises_with_the_reason_attached():
    with pytest.raises(guard.UnsafeCypher) as excinfo:
        guard.assert_read_only("MATCH (n:HsPkg {id: 1}) DELETE n")
    assert excinfo.value.rejection.code == "MUTATION"
    assert "DELETE" in str(excinfo.value)


def test_assert_read_only_passes_a_read():
    guard.assert_read_only("MATCH (n:HsPkg {id: $id}) RETURN n.name")


def test_rejection_serialises_for_transport():
    rejection = guard.check("MATCH (n:HsPkg {id: 1}) SET n.x = 1")
    payload = rejection.as_dict()
    assert payload["code"] == "MUTATION"
    assert "offset" in payload and "snippet" in payload


def test_blanking_preserves_offsets_so_snippets_point_at_the_original():
    query = "MATCH (n:HsPkg {name: 'a very long literal here'}) DELETE n"
    blanked = guard.blank_literals(query)
    assert len(blanked) == len(query)
    assert "very long literal" not in blanked
    rejection = guard.check(query)
    assert query[rejection.offset :].startswith("DELETE")


def test_blanking_keeps_line_structure_of_block_comments():
    query = "MATCH (n:HsPkg {id: 1})\n/* two\nlines */\nRETURN n.name"
    assert guard.blank_literals(query).count("\n") == query.count("\n")


def test_every_declared_keyword_is_actually_refused():
    """The blocklist and the scanner must not drift apart."""
    for keyword in guard.MUTATION_KEYWORDS:
        query = f"MATCH (n:HsPkg {{id: 1}}) {keyword} n"
        assert guard.check(query).code == "MUTATION", keyword


def test_a_label_named_after_a_write_clause_is_refused_deliberately():
    """Known, accepted over-rejection.

    The scanner does not parse Cypher, so a label whose name collides with a
    write clause is refused. No label in this graph is named that way, and
    erring towards refusal is the correct direction for a guard on an
    append-only store.
    """
    assert guard.check("MATCH (n:Set {id: $id}) RETURN n.name").code == "MUTATION"
