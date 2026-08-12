"""Cypher generation, batching and watermark planning — no server required."""

from hindsight.graphbuild import TEST_SCHEMA, RepoInput, build_rowsets
from hindsight.history import SENTINEL, Interval
from hindsight.ids import repo_id, watermark_id
from hindsight.ingest import MAX_BATCH, Ingestor, chunks, edge_upsert, node_upsert

WEB = RepoInput(
    slug="acme/web",
    name="acme/web",
    service="storefront",
    intervals=(
        Interval("chalk", "5.0.0", 100, 500),
        Interval("chalk", "5.3.0", 500, SENTINEL),
    ),
    first_ts=100,
    last_ts=500,
    snapshots=2,
)


class FakeClient:
    """Records every statement instead of sending it."""

    def __init__(self, watermarks=None):
        self.sent = []
        self.watermarks = watermarks or {}

    def query(self, cypher, parameters=None, **kw):
        self.sent.append((cypher, parameters))
        return {"rows": []}

    def rows(self, cypher, parameters=None, **kw):
        self.sent.append((cypher, parameters))
        value = self.watermarks.get(parameters and parameters.get("id"))
        return [[value]] if value is not None else []

    def scalar(self, cypher, parameters=None, default=None):
        return default


def test_node_upsert_uses_the_merge_by_id_then_set_form():
    # Folding properties into the MERGE pattern is rejected by the engine.
    assert node_upsert("HsPkg", {"name": "name"}) == (
        "UNWIND $rows AS row MERGE (n {id: row.id}) SET n:HsPkg, n.name = row.name"
    )


def test_edge_upsert_matches_labelled_endpoints_and_merges_on_id_alone():
    got = edge_upsert("HS_RESOLVES", "HsRepo", "HsVer", {"valid_from": "vf"})
    assert got == (
        "UNWIND $rows AS row "
        "MATCH (s:HsRepo {id: row.s}), (d:HsVer {id: row.d}) "
        "MERGE (s)-[e:HS_RESOLVES {id: row.id}]->(d) SET e.valid_from = row.vf"
    )


def test_edge_upsert_without_properties_has_no_trailing_set():
    got = edge_upsert("HS_VERSION_OF", "HsVer", "HsPkg", {})
    assert got.endswith("MERGE (s)-[e:HS_VERSION_OF {id: row.id}]->(d)")


def test_batch_is_clamped_to_the_engine_limit():
    assert Ingestor(FakeClient(), batch=5000).batch == MAX_BATCH
    assert Ingestor(FakeClient(), batch=0).batch == 1
    assert Ingestor(FakeClient(), batch=250).batch == 250


def test_chunks_never_exceed_the_batch_size():
    parts = list(chunks([{"id": i} for i in range(2500)], MAX_BATCH))
    assert [len(p) for p in parts] == [1000, 1000, 500]


def test_dry_run_sends_no_mutations():
    client = FakeClient()
    ingestor = Ingestor(client, schema=TEST_SCHEMA)
    report = ingestor.run(build_rowsets([WEB], schema=TEST_SCHEMA), dry_run=True)
    assert report.dry_run
    assert report.nodes_written == 4  # 1 repo + 1 package + 2 versions
    assert report.edges_written == 4  # 2 VERSION_OF + 2 RESOLVES
    # The only statements issued were the watermark reads.
    assert all("MERGE" not in cypher for cypher, _ in client.sent)


def test_execute_writes_nodes_then_edges_then_the_watermark():
    client = FakeClient()
    ingestor = Ingestor(client, schema=TEST_SCHEMA)
    ingestor.run(build_rowsets([WEB], schema=TEST_SCHEMA), tx_from=777)
    mutations = [c for c, _ in client.sent if "MERGE" in c]
    order = [
        i
        for i, c in enumerate(mutations)
        if TEST_SCHEMA.repo in c or TEST_SCHEMA.resolves in c or TEST_SCHEMA.watermark in c
    ]
    assert order == sorted(order)
    assert TEST_SCHEMA.watermark in mutations[-1]


def test_watermark_row_records_the_newest_commit_seen():
    client = FakeClient()
    Ingestor(client, schema=TEST_SCHEMA).run(
        build_rowsets([WEB], schema=TEST_SCHEMA), tx_from=777
    )
    _, params = client.sent[-1]
    assert params["rows"] == [
        {
            "id": watermark_id("acme/web"),
            "slug": "acme/web",
            "repo_id": repo_id("acme/web"),
            "last_ts": 500,
            "txf": 777,
        }
    ]


def test_an_existing_watermark_suppresses_settled_intervals():
    client = FakeClient(watermarks={watermark_id("acme/web"): 500})
    ingestor = Ingestor(client, schema=TEST_SCHEMA)
    report = ingestor.run(build_rowsets([WEB], schema=TEST_SCHEMA), dry_run=True)
    assert report.skipped_resolves == 1  # chalk@5.0.0 closed at 500
    assert report.watermarks_before == {"acme/web": 500}
    assert report.edges_written == 3


def test_tx_from_is_stamped_on_every_resolves_edge():
    client = FakeClient()
    ingestor = Ingestor(client, schema=TEST_SCHEMA)
    ingestor.run(build_rowsets([WEB], schema=TEST_SCHEMA), tx_from=4242)
    resolves = [p for c, p in client.sent if TEST_SCHEMA.resolves in c]
    assert resolves
    for _, params in [(None, p) for p in resolves]:
        assert all(row["txf"] == 4242 and row["txt"] == SENTINEL for row in params["rows"])


def test_report_serialises_to_json_friendly_types():
    client = FakeClient()
    report = Ingestor(client, schema=TEST_SCHEMA).run(
        build_rowsets([WEB], schema=TEST_SCHEMA), tx_from=1
    )
    payload = report.as_dict()
    assert payload["edges"] == 4
    assert payload["watermarks_after"] == {"acme/web": 500}
    assert all(set(step) >= {"label", "rows", "seconds"} for step in payload["steps"])
