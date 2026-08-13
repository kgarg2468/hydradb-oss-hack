"""HTTP surface: status codes, parameter handling, and the failure paths.

The console is the fake-backed one from :mod:`test_web_service`, so these tests
are about routing and error translation only — an operator hitting a wedged node
should get a 502 with an actionable hint, and a typo in ``?at=`` should get a
400 rather than a stack trace on a projector.
"""

from __future__ import annotations

import importlib
import sys
from types import SimpleNamespace

import pytest
from starlette.testclient import TestClient

from hindsight.client import HydraError
from hindsight.graphbuild import DEFAULT_SCHEMA
from hindsight.ids import version_id
from hindsight_web.analysis import TRUNCATION_CAVEAT
from hindsight_web.app import DEFAULT_PACKAGE, build_app
from hindsight_web import queries as web_queries
from hindsight_web.queries import resolve_schema

from test_web_service import AT, FakeReader, console  # noqa: E402


@pytest.fixture
def client():
    with TestClient(build_app(console())) as c:
        yield c


def get(client, path, **params):
    response = client.get(path, params=params)
    return response.status_code, response.json()


# --------------------------------------------------------------------- routing


def test_index_serves_the_page_and_the_static_assets_it_asks_for():
    with TestClient(build_app(console())) as c:
        page = c.get("/")
        assert page.status_code == 200
        assert "text/html" in page.headers["content-type"]
        body = page.text
        for asset in ("/static/app.css", "/static/force.js", "/static/app.js"):
            assert asset in body
            assert c.get(asset).status_code == 200


def test_health_reports_the_schema_the_console_is_pointed_at(client):
    status, body = get(client, "/api/health")
    assert status == 200
    assert body["reachable"] is True
    assert body["seeded"] is True
    assert body["labels"]["repo"] == "ReplayTestRepo"


def test_web_schema_defaults_to_the_ingest_namespace():
    assert web_queries.schema_from_env({}) == DEFAULT_SCHEMA


def test_web_schema_reads_the_mcp_prefix_environment_variables():
    schema = web_queries.schema_from_env(
        {
            "HINDSIGHT_MCP_NODE_PREFIX": "Replay",
            "HINDSIGHT_MCP_REL_PREFIX": "REPLAY",
        }
    )
    assert schema.repo == "ReplayRepo"
    assert schema.resolves == "REPLAY_RESOLVES"


def test_default_app_uses_the_environment_configured_schema(monkeypatch):
    import hindsight_web.app as web_app

    def console_for_schema(*, schema, incident):
        view = console()
        view.schema = schema
        view.incident = incident
        return view

    monkeypatch.setenv("HINDSIGHT_MCP_NODE_PREFIX", "WebTest")
    monkeypatch.setenv("HINDSIGHT_MCP_REL_PREFIX", "WEBTEST")
    monkeypatch.setattr(web_app, "Console", console_for_schema)

    with TestClient(web_app.build_app()) as configured_client:
        body = configured_client.get("/api/health").json()

    assert body["labels"]["repo"] == "WebTestRepo"
    assert body["labels"]["resolves"] == "WEBTEST_RESOLVES"


def test_startup_prints_the_environment_resolved_labels(monkeypatch, capsys):
    web_main = importlib.import_module("hindsight_web.__main__")
    monkeypatch.setenv("HINDSIGHT_MCP_NODE_PREFIX", "Replay")
    monkeypatch.setenv("HINDSIGHT_MCP_REL_PREFIX", "REPLAY")
    monkeypatch.setitem(sys.modules, "uvicorn", SimpleNamespace(run=lambda *a, **kw: None))

    assert web_main.main(["--port", "8092"]) == 0

    assert capsys.readouterr().out == (
        "Hindsight console  http://127.0.0.1:8092\n"
        "Label namespace    ReplayRepo / ReplayPkg / ReplayVer / ReplayMaint / "
        "ReplayWatermark; REPLAY_RESOLVES / REPLAY_VERSION_OF / REPLAY_MAINTAINS\n"
    )


def test_incident_endpoint_carries_the_markers_the_scrubber_draws(client):
    status, body = get(client, "/api/incident")
    assert status == 200
    assert body["incident"]["window"]["duration"] == "2 h 17 min"
    assert body["incident"]["markers"]
    assert body["caveat"]
    assert body["synthetic_caveat"]


# -------------------------------------------------------------------- exposure


def test_exposure_defaults_to_chalk_at_the_start_of_the_window(client):
    status, body = get(client, "/api/exposure")
    assert status == 200
    assert body["package"] == DEFAULT_PACKAGE == "chalk"
    assert body["at_iso"] == "2025-09-08T13:12:10Z"
    assert body["in_exposure_window"] is True


def test_exposure_accepts_both_iso_and_unix_instants(client):
    _, from_iso = get(client, "/api/exposure", package="chalk", at="2025-09-08T14:02:10Z")
    _, from_unix = get(client, "/api/exposure", package="chalk", at=str(AT))
    assert from_iso["at"] == from_unix["at"] == AT
    assert from_iso["counts"] == from_unix["counts"]


def test_exposure_answer_is_labelled_evidence_with_its_caveat(client):
    _, body = get(client, "/api/exposure", package="chalk", at=str(AT))
    assert body["evidence"] == "RESOLVED"
    assert "not proof" in body["caveat"]
    assert body["counts"] == {
        "repos": 3,
        "exposed": 1,
        "resolved_clean": 1,
        "not_resolved": 1,
    }


def test_a_malformed_instant_is_a_400_with_the_field_named(client):
    status, body = get(client, "/api/exposure", package="chalk", at="last tuesday")
    assert status == 400
    assert "at" in body["error"]


def test_an_empty_package_is_a_400_not_a_crash(client):
    status, body = get(client, "/api/exposure", package="   ")
    assert status == 400
    assert "package" in body["error"]


# --------------------------------------------------- blast radius and reach


def test_blast_radius_returns_a_renderable_node_link_payload(client):
    status, body = get(client, "/api/blast-radius", package="chalk", at=str(AT))
    assert status == 200
    assert body["nodes"] and body["edges"]
    ids = {n["id"] for n in body["nodes"]}
    for edge in body["edges"]:
        assert edge["source"] in ids and edge["target"] in ids


def test_maintainer_reach_without_a_name_returns_the_ranking(client):
    status, body = get(client, "/api/maintainer-reach", at=str(AT))
    assert status == 200
    assert body["ranking"][0]["maintainer"] == "sindresorhus"
    assert body["ranking"][0]["rank"] == 1


def test_maintainer_reach_with_a_name_returns_that_one_account(client):
    status, body = get(client, "/api/maintainer-reach", name="qix", at=str(AT))
    assert status == 200
    assert body["maintainer"] == "qix"
    assert body["exists"] is True
    assert "ranking" not in body


def test_ranking_limit_is_honoured_and_validated(client):
    _, body = get(client, "/api/maintainer-reach", at=str(AT), limit="1")
    assert len(body["ranking"]) == 1
    status, error = get(client, "/api/maintainer-reach", at=str(AT), limit="many")
    assert status == 400
    assert "limit" in error["error"]


def test_version_footprint_requires_a_version(client):
    status, body = get(client, "/api/version-footprint", package="chalk")
    assert status == 400
    assert "version is required" in body["error"]


def test_version_footprint_reports_a_version_no_lockfile_ever_held(client):
    status, body = get(
        client, "/api/version-footprint", package="chalk", version="5.6.1", at=str(AT)
    )
    assert status == 200
    assert body["version_in_graph"] is False
    assert body["repo_count"] == 0


# ---------------------------------------------------------------- failure paths


def test_a_refused_query_becomes_a_502_with_an_actionable_hint():
    def refuse(*args, **kw):
        raise HydraError("400: unsupported construct")

    with TestClient(build_app(console(reader=refuse))) as c:
        response = c.get("/api/exposure?package=chalk")
        assert response.status_code == 502
        body = response.json()
        assert "HydraDB refused the query" in body["error"]
        assert "demo-seed.py" in body["hint"]


def test_an_unreachable_node_still_answers_health_with_200():
    def refuse(*args, **kw):
        raise HydraError("connection refused")

    with TestClient(build_app(console(reader=refuse))) as c:
        response = c.get("/api/health")
        assert response.status_code == 200, "health must diagnose, never 502 itself"
        assert response.json()["reachable"] is False


def test_no_endpoint_writes_to_the_graph():
    """Every route is a GET; the app never composes a mutation."""
    reader = FakeReader()
    with TestClient(build_app(console(reader=reader))) as c:
        for path in (
            "/api/health",
            "/api/incident",
            "/api/exposure?package=chalk",
            "/api/blast-radius?package=chalk",
            "/api/maintainer-reach",
        ):
            assert c.get(path).status_code == 200
        assert c.post("/api/exposure").status_code == 405
    for cypher, _ in reader.statements:
        for verb in ("CREATE", "MERGE", "SET ", "DELETE", "REMOVE"):
            assert verb not in cypher.upper()


# ------------------------------------------------------------------ truncation

#: Every endpoint whose answer is derived from a paged read, with the read whose
#: truncation must reach the client. A partial answer that serialises as a whole
#: one is the failure this list exists to prevent.
PAGED = [
    ("/api/exposure?package=chalk", "repos_resolving"),
    ("/api/blast-radius?package=chalk", "repos_resolving"),
    ("/api/blast-radius?package=chalk", "maintainers_of_package"),
    ("/api/maintainer-reach?name=qix", "maintainer_reach"),
    ("/api/maintainer-reach", "maintainer_reach"),
    ("/api/version-footprint?package=chalk&version=5.6.1", "repos_resolving"),
    ("/api/health", "repo_directory"),
    ("/api/incident", "repo_directory"),
]


@pytest.mark.parametrize(("path", "kind"), PAGED)
def test_truncation_reaches_the_client_as_json(path, kind):
    reader = FakeReader(versions={version_id("chalk", "5.6.1")}, cut={kind})
    with TestClient(build_app(console(reader=reader))) as c:
        body = c.get(path).json()
    assert body["truncated"] is True, f"{path} dropped the flag from {kind}"
    assert body["truncation_note"] == TRUNCATION_CAVEAT


@pytest.mark.parametrize(("path", "_kind"), PAGED)
def test_a_complete_answer_is_labelled_complete(path, _kind):
    reader = FakeReader(versions={version_id("chalk", "5.6.1")})
    with TestClient(build_app(console(reader=reader))) as c:
        body = c.get(path).json()
    assert body["truncated"] is False
    assert body["truncation_note"] is None


def test_a_truncated_exposure_is_still_a_200_with_usable_rows():
    """Partial is not an error: it is an answer that has to be labelled."""
    reader = FakeReader(cut={"repos_resolving"})
    with TestClient(build_app(console(reader=reader))) as c:
        response = c.get(f"/api/exposure?package=chalk&at={AT}")
    assert response.status_code == 200
    body = response.json()
    assert body["repos"]
    assert body["truncated"] is True


def test_the_page_is_shipped_the_words_it_renders_truncation_with():
    with TestClient(build_app(console())) as c:
        overview = c.get("/api/incident").json()
        script = c.get("/static/app.js").text
        style = c.get("/static/app.css").text
    assert overview["truncation_caveat"] == TRUNCATION_CAVEAT
    # The count itself must carry the qualifier, not just a banner beside it.
    assert "'≥ ' + value" in script
    assert "truncation_note" in script
    assert ".truncated {" in style


def test_the_console_reads_the_dataset_the_org_config_declares(tmp_path):
    """org.yaml's schema block is what ingest writes, so it is what we read.

    Consulting only the environment would agree with the pipeline's default and
    diverge from every custom prefix: declare ``node_prefix: Acme``, ingest to
    ``Acme*``, read an empty ``Hs*``. That is the original namespace bug one
    layer up.
    """
    config = tmp_path / "org.yaml"
    config.write_text(
        "schema:\n  node_prefix: Acme\n  rel_prefix: ACME\n"
        "repos:\n  - url: https://github.com/axios/axios\n"
    )
    schema = resolve_schema(str(config), env={})
    assert schema.repo == "AcmeRepo"
    assert schema.resolves == "ACME_RESOLVES"


def test_an_explicit_prefix_overrides_the_org_config(tmp_path):
    """Deployment-time env beats the declared dataset; it is the more specific act."""
    config = tmp_path / "org.yaml"
    config.write_text("schema:\n  node_prefix: Acme\n  rel_prefix: ACME\nrepos: []\n")
    schema = resolve_schema(str(config), env={"HINDSIGHT_MCP_NODE_PREFIX": "Replay"})
    assert schema.repo == "ReplayRepo"


def test_without_a_config_the_console_defaults_to_what_ingest_writes():
    assert resolve_schema(None, env={}).repo == "HsRepo"
