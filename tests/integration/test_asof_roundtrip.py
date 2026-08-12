"""Bitemporal AS-OF round-trip against a real HydraDB node.

Scenario: one repo's lockfile resolves pkg v1 until T=1000, then v2 from T=1000 on
(open interval encoded as valid_to = FAR_FUTURE). AS-OF queries at T=500 and T=1500
must return different versions.

Uses the mutation idioms HydraDB's engine actually executes (validated in poc/):
- nodes:  UNWIND $rows AS row MERGE (n {id: row.id}) SET n:Label, n.prop = ...
- edges:  UNWIND $rows AS row MATCH (s {id}), (d {id}) CREATE (s)-[:REL {...}]->(d)
Plain multi-node CREATE and non-UNWIND MATCH..CREATE are rejected by the server.

Each run uses fresh random ids/keys so reruns and pre-existing data cannot collide
(HydraDB deletion is too slow for cleanup; the graph is append-only by design).
"""

import secrets

from hydra import query

FAR_FUTURE = 9_999_999_999
RUN = secrets.token_hex(6)
BASE = secrets.randbelow(1_000_000_000) + 2_000_000_000
REPO_ID, V1_ID, V2_ID = BASE, BASE + 1, BASE + 2


def _seed():
    query(
        "UNWIND $rows AS row MERGE (n {id: row.id}) SET n:CITestRepo, n.name = row.name",
        parameters={"rows": [{"id": REPO_ID, "name": RUN}]},
    )
    query(
        "UNWIND $rows AS row MERGE (n {id: row.id}) SET n:CITestVer, n.key = row.key",
        parameters={
            "rows": [
                {"id": V1_ID, "key": f"pkg@1.0.0#{RUN}"},
                {"id": V2_ID, "key": f"pkg@2.0.0#{RUN}"},
            ]
        },
    )
    query(
        "UNWIND $rows AS row "
        "MATCH (s:CITestRepo {id: row.s}), (d:CITestVer {id: row.d}) "
        "CREATE (s)-[:CITEST_RESOLVES {id: row.id, valid_from: row.vf, valid_to: row.vt}]->(d)",
        parameters={
            "rows": [
                {"id": BASE + 10, "s": REPO_ID, "d": V1_ID, "vf": 0, "vt": 1000},
                {"id": BASE + 11, "s": REPO_ID, "d": V2_ID, "vf": 1000, "vt": FAR_FUTURE},
            ]
        },
    )


def _value(cell):
    return cell["value"] if isinstance(cell, dict) else cell


def _asof(t):
    res = query(
        "MATCH (r:CITestRepo {id: $rid})-[e:CITEST_RESOLVES]->(v:CITestVer) "
        "WHERE e.valid_from <= $t AND e.valid_to > $t "
        "RETURN v.key",
        parameters={"rid": REPO_ID, "t": t},
    )
    return {_value(row[0]) for row in res["rows"]}


def test_asof_returns_different_states_at_different_times():
    _seed()
    assert _asof(500) == {f"pkg@1.0.0#{RUN}"}
    assert _asof(1500) == {f"pkg@2.0.0#{RUN}"}


def test_asof_boundary_is_half_open():
    # valid_from is inclusive, valid_to exclusive: at exactly T=1000 only v2 holds.
    assert _asof(1000) == {f"pkg@2.0.0#{RUN}"}
