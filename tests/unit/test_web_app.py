"""HTTP surface: status codes, parameter handling, and the failure paths.

The console is the fake-backed one from :mod:`test_web_service`, so these tests
are about routing and error translation only — an operator hitting a wedged node
should get a 502 with an actionable hint, and a typo in ``?at=`` should get a
400 rather than a stack trace on a projector.
"""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from hindsight.client import HydraError
from hindsight.ids import version_id
from hindsight_web.analysis import TRUNCATION_CAVEAT
from hindsight_web.app import DEFAULT_PACKAGE, build_app

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


# -------------------------------------------------------------------- coverage
#
# The empty-dataset all-clear, over HTTP. A 200 with zero counts is the right
# status code (nothing failed) and the wrong answer unless the payload says the
# dataset could not answer at all, so this is where the field is pinned down as
# part of the API rather than as prose inside a note.


def empty_client():
    reader = FakeReader(repos=(), watermarked=(), packages=())
    return TestClient(build_app(console(reader=reader)))


def test_exposure_declares_whether_the_dataset_could_answer_at_all(client):
    status, body = get(client, "/api/exposure", package="chalk", at=AT)
    assert status == 200
    assert body["answerable"] is True
    assert body["unanswerable_reason"] is None
    assert body["coverage"] == {"repo_count": 3, "ingested_repo_count": 2}


@pytest.mark.parametrize(
    ("path", "params"),
    [
        ("/api/exposure", {"package": "chalk"}),
        ("/api/blast-radius", {"package": "chalk"}),
        ("/api/version-footprint", {"package": "chalk", "version": "5.6.1"}),
        ("/api/health", {}),
    ],
)
def test_every_answer_endpoint_reports_an_empty_dataset_as_unanswerable(path, params):
    with empty_client() as c:
        status, body = get(c, path, at=AT, **params)
    assert status == 200
    assert body["answerable"] is False
    assert body["unanswerable_reason"] == "empty_dataset"
    assert "no question can be answered" in body["unanswerable_note"]


def test_an_empty_dataset_keeps_every_existing_field_the_page_reads():
    """Additive: the front end must not have to guess which shape it received."""
    with empty_client() as c:
        body = get(c, "/api/exposure", package="chalk", at=AT)[1]
    for key in ("counts", "repos", "package_in_graph", "truncated", "truncation_note"):
        assert key in body
    assert body["counts"] == {
        "repos": 0, "exposed": 0, "resolved_clean": 0, "not_resolved": 0
    }
    assert body["truncated"] is False


def test_health_and_exposure_ship_the_same_verdict_to_the_same_page():
    with empty_client() as c:
        health = get(c, "/api/health")[1]
        exposure = get(c, "/api/exposure", package="chalk", at=AT)[1]
    assert health["seeded"] is False
    assert health["answerable"] is exposure["answerable"] is False
    assert health["unanswerable_reason"] == exposure["unanswerable_reason"]


# ------------------------------------------------------------- shareable view
#
# The console's view is a URL, which makes the URL an interface: an incident
# link pasted into a ticket has to resolve to the same screen months later. The
# rules that make that true live in the shipped JS, so they are pinned here the
# same way the truncation wording is.


def test_the_page_is_shipped_the_code_that_makes_its_view_a_link():
    with TestClient(build_app(console())) as c:
        script = c.get("/static/app.js").text
    # Exactly three pieces of state travel, and the instant travels as the unix
    # second it already is: no formatting, nothing relative, nothing re-derived
    # from the clock when the link is opened.
    assert "'?package=' + encodeURIComponent(state.package)" in script
    assert "'&at=' + encodeURIComponent(String(state.at))" in script
    assert "'&all=1'" in script
    # Dragging the scrubber must not fill the back stack; only the package
    # select, which is discrete, gets a history entry of its own. The API is
    # reached through `window` because this file has its own `history`.
    assert "var api = window.history;" in script
    assert "api.replaceState(null, '', url)" in script
    assert "api.pushState(null, '', url)" in script
    assert "window.addEventListener('popstate'" in script
    # The link is applied inside the incident load, before the first read goes
    # out, so the default view never flashes on screen first.
    assert "applyView(readView());" in script


def test_the_page_is_shipped_the_code_that_disowns_a_clamped_link():
    with TestClient(build_app(console())) as c:
        script = c.get("/static/app.js").text
        style = c.get("/static/app.css").text
    # An instant outside the incident's domain is clamped so the rest of the
    # page keeps working, and then said out loud: the answer on screen is about
    # the clamped instant, not the one that was asked for.
    assert "LINK NOT HONOURED" in script
    assert "is not an answer about the instant " in script
    # A third state, distinct from the amber cut read and the dashed refusal.
    assert ".link-notice {" in style
    assert "var(--acc-line)" in style.split(".link-notice {")[1].split("}")[0]


def test_the_copy_control_has_a_path_that_works_on_an_insecure_origin():
    with TestClient(build_app(console())) as c:
        page = c.get("/").text
        script = c.get("/static/app.js").text
    assert 'id="copy-link"' in page
    # navigator.clipboard is gated on a secure context and this console is
    # served over http, so the button falls back rather than doing nothing.
    assert "navigator.clipboard && navigator.clipboard.writeText" in script
    assert "document.execCommand('copy')" in script
    assert "window.prompt('Copy this link', url)" in script


def test_the_page_is_shipped_the_code_that_refuses_a_verdict():
    with TestClient(build_app(console())) as c:
        script = c.get("/static/app.js").text
        style = c.get("/static/app.css").text
    # The refusal is keyed on an explicit false, so an older payload without the
    # field still renders the previous behaviour rather than a blank page.
    assert "d.answerable === false" in script
    assert "CANNOT ANSWER" in script
    # A distinct state, not a second amber banner.
    assert ".unanswerable {" in style
    assert ".stat.unknown b" in style
    assert "border: 1px dashed" in style.split(".unanswerable {")[1].split("}")[0]
