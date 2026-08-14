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
    assert web_queries.resolve_schema(env={}) == DEFAULT_SCHEMA


def test_web_schema_reads_the_mcp_prefix_environment_variables():
    schema = web_queries.resolve_schema(
        env={
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
    assert "'&graph=path'" in script
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
    # A mangled link -- one a chat client truncated -- reaches the operator as
    # that notice too. `decodeURIComponent` throws on a stray percent, and the
    # one link that must not take the page down with it is the broken one.
    assert "function decodeOrRaw(" in script
    assert "catch (err) { return text; }" in script
    assert "decodeURIComponent(pair.slice" not in script


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


# ------------------------------------------------------------------- namespace


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
    """Deployment-time env beats the declared dataset; it is the more specific act.

    Per prefix, though. If either variable handed the whole decision to the
    environment, setting one would build a namespace out of two datasets --
    ``ReplayRepo`` joined by ``HS_RESOLVES`` -- which matches nothing on read
    and is indistinguishable from an empty graph.
    """
    config = tmp_path / "org.yaml"
    config.write_text("schema:\n  node_prefix: Acme\n  rel_prefix: ACME\nrepos: []\n")
    schema = resolve_schema(str(config), env={"HINDSIGHT_MCP_NODE_PREFIX": "Replay"})
    assert schema.repo == "ReplayRepo"
    assert schema.resolves == "ACME_RESOLVES"

    other = resolve_schema(str(config), env={"HINDSIGHT_MCP_REL_PREFIX": "REPLAY"})
    assert other.repo == "AcmeRepo"
    assert other.resolves == "REPLAY_RESOLVES"


def test_an_empty_prefix_variable_is_not_a_prefix(tmp_path):
    """``NODE_PREFIX= hindsight-web`` says "not this one", not "label me Repo"."""
    config = tmp_path / "org.yaml"
    config.write_text("schema:\n  node_prefix: Acme\n  rel_prefix: ACME\nrepos: []\n")
    schema = resolve_schema(str(config), env={"HINDSIGHT_MCP_NODE_PREFIX": ""})
    assert schema.repo == "AcmeRepo"
    assert resolve_schema(None, env={"HINDSIGHT_MCP_REL_PREFIX": ""}).resolves == (
        "HS_RESOLVES"
    )


def test_without_a_config_the_console_defaults_to_what_ingest_writes():
    assert resolve_schema(None, env={}).repo == "HsRepo"


# ---- what the console leads with

def test_the_graph_opens_on_the_whole_graph_and_the_link_carries_the_narrowing():
    """A drawing of the sentence directly above it is not worth its area.

    The summary view is three nodes and two curves restating a headline the
    reader has already read twice. The full layout is the only thing on the
    page a list cannot say: nine repositories, their resolved versions, the
    package, and the accounts that can publish into it, with the malicious
    path lit inside the whole. So that is the view, and focusing is the click.
    """
    with TestClient(build_app(console())) as c:
        page = c.get("/").text
        script = c.get("/static/app.js").text
    assert "showAll: true" in script
    assert ">Focus malicious path</button>" in page
    # Only the departure from the default travels in the link.
    assert "(state.showAll ? '' : '&graph=path')" in script
    assert "all: raw.graph !== 'path'" in script


def test_a_link_carries_the_question_exactly_and_the_drawing_only_if_named():
    """The asymmetry is deliberate and worth pinning.

    A link that names no drawing gets whatever the console opens on today. The
    alternative is to read "no graph named" as "the summary", which honours the
    handful of links minted between the share feature and this change at the
    cost of pinning every hand-written URL to a view we just decided was the
    wrong one. The question -- package and instant -- is honoured exactly, and
    a question that cannot be honoured still raises the link notice.
    """
    with TestClient(build_app(console())) as c:
        script = c.get("/static/app.js").text
    assert "'?package=' + encodeURIComponent(state.package)" in script
    assert "'&at=' + encodeURIComponent(String(state.at))" in script
    # No third piece of state is required for a link to be honoured.
    assert "noteLink(missing, view)" in script


def test_diagnostics_is_reached_through_the_status_it_explains():
    """A developer drawer billed as a peer of the incident is over-billed.

    The reader already looks at the health chip to ask whether the thing is
    connected, which is the same question the drawer answers at length.
    """
    with TestClient(build_app(console())) as c:
        page = c.get("/").text
    assert 'class="health" id="diag-btn"' in page
    assert 'class="ghost-btn" id="diag-btn"' not in page
    # One trigger, so the chip has to carry the dialog semantics itself.
    assert page.count('id="diag-btn"') == 1
    assert 'aria-haspopup="dialog"' in page


def test_the_diagnostics_drawer_leads_with_whether_the_reads_were_complete():
    """Endpoint, cell and label names are provenance. Read completeness is the
    one row in the drawer that changes what the numbers on screen mean, and it
    used to sit under eleven rows of connection detail."""
    with TestClient(build_app(console())) as c:
        script = c.get("/static/app.js").text
    leads = script.index("group('This answer')")
    assert leads < script.index("row('Read completeness'")
    assert script.index("row('Read completeness'") < script.index("group('Connection')")
    assert script.index("group('Connection')") < script.index("row('Endpoint'")


def test_every_named_event_stays_clickable_at_a_laptop_width():
    """Seven chips and the range toggle do not fit on one line at 1440, and the
    chip that scrolls out of reach is the public disclosure."""
    with TestClient(build_app(console())) as c:
        css = c.get("/static/app.css").text
    assert ".rail-top::after" in css
    assert ".rail-top .segmented { order: 3; margin-left: auto; }" in css


# ---- the answer as a contract

def test_the_answer_is_the_h1_and_announces_itself():
    """The conclusion is the page. It was a <p> while every subordinate panel
    had an <h2>, and a screen reader was told nothing when a committed read
    replaced it."""
    with TestClient(build_app(console())) as c:
        page = c.get("/").text
    assert '<h1 class="answer-line" id="answer-line" aria-live="polite">' in page
    assert '<p class="answer-line"' not in page


def test_the_headline_carries_its_denominator_as_a_floor_when_cut():
    """"1 repository" could be 1 of 9 or 1 of 900, and those are different
    incidents. The denominator goes through the same floor helper as the
    numerator, because a cut read bounds both from below."""
    with TestClient(build_app(console())) as c:
        script = c.get("/static/app.js").text
    assert "d.counts.exposed + d.counts.resolved_clean + d.counts.not_resolved" in script
    # Both numbers pass through count(x, floor); the denominator is guarded so
    # a payload that says "1 of 0" gets the old bare count instead.
    assert "line.appendChild(b(count(total, floor), 'n'));" in script
    assert "None of " in script


def test_the_console_never_calls_a_repository_clean():
    """What was measured is that a repository did not resolve a malicious
    version of one package at one instant. "Clean" is a bigger claim than
    that, and this console's whole pitch is not making claims it cannot
    back."""
    with TestClient(build_app(console())) as c:
        script = c.get("/static/app.js").text
    assert "Clean repo" not in script
    assert "clean repo" not in script
    assert "clean version" not in script
    assert "No malicious resolution" in script


def test_a_failed_read_names_the_instant_the_stale_panels_belong_to():
    """A failed read used to move the headline and nothing else, leaving the
    counts, repositories and drawing standing under a timestamp that had
    moved on: every panel looked like an answer about the instant on screen.
    And when nothing had ever loaded, three empty panels under a fresh
    timestamp read as a proven negative, which is the one lie this product
    exists to not tell."""
    with TestClient(build_app(console())) as c:
        script = c.get("/static/app.js").text
    assert "function readFailed(err)" in script
    assert "'READ FAILED'" in script
    assert "'at ' + humanTime(kept.at)" in script
    assert "drawMessage('No completed read to draw from')" in script
    # The ranking keeps its list on failure, so the note has to say which
    # instant that list belongs to, captured before anything is discarded.
    assert "'failed, showing ' + humanTime(showing)" in script


def test_the_steppers_disable_exactly_when_stepping_would_do_nothing():
    """A control that lights up under the cursor and then does nothing is a
    promise it cannot keep. The disabled predicate is the step predicate."""
    with TestClient(build_app(console())) as c:
        script = c.get("/static/app.js").text
        css = c.get("/static/app.css").text
    assert "$('prev-event').disabled = !nextEvent(-1);" in script
    assert "$('next-event').disabled = !nextEvent(1);" in script
    assert ".icon-btn:disabled" in css
