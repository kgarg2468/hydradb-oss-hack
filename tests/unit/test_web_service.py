"""The console's read path, driven off canned rows.

:class:`Console` takes its ``reader`` as a field, so the whole of it —
classification, the repository join that makes "not exposed" a first-class
answer, the synthetic labelling, the maintainer ranking, the honesty fields —
runs here without a database. The fake matches on the *shape* of the statement
rather than on an exact string, so a harmless reformat of the Cypher does not
break twenty tests, but a change of query *kind* does.
"""

from __future__ import annotations

import pytest

from hindsight.client import ClientConfig, HydraClient
from hindsight.history import SENTINEL
from hindsight.ids import maintainer_id, package_id, version_id
from hindsight_web.analysis import CAVEAT, EVIDENCE, MAINTAINER_CAVEAT
from hindsight_web.incident import build_incident
from hindsight_web.queries import TEST_SCHEMA
from hindsight_web.service import Console, ConsoleError

from test_web_incident import RAW  # noqa: E402  (pytest puts tests/unit on sys.path)

INCIDENT = build_incident(RAW)
WINDOW = INCIDENT.window
AT = WINDOW.start + 3_000  # inside the window

CHALK = package_id("chalk")
DEBUG = package_id("debug")

#: id -> (slug, name, service, first_ts, last_ts, snapshots, provenance, origin, synthetic)
REPOS = [
    [1, "acme/checkout-web", "acme/checkout-web", "checkout", 100, 200, 4,
     "synthetic", "constructed for the demo", 1],
    [2, "webpack/webpack", "webpack/webpack", "build", 100, 200, 299,
     "git-lockfile-history", "git lockfile history", 0],
    [3, "axios/axios", "axios/axios", "http-client", 100, 200, 16,
     "git-lockfile-history", "git lockfile history", 0],
]

#: package id -> rows of (slug, name, package, version, valid_from, valid_to)
RESOLUTIONS = {
    CHALK: [
        ["acme/checkout-web", "acme/checkout-web", "chalk", "5.6.1", AT - 100, AT + 9_000],
        ["webpack/webpack", "webpack/webpack", "chalk", "5.6.0", 1_000, SENTINEL],
    ],
    DEBUG: [
        ["axios/axios", "axios/axios", "debug", "4.4.1", 1_000, SENTINEL],
    ],
}

#: version id -> rows of (slug, name, package, version, valid_from, valid_to)
VERSION_RESOLUTIONS = {
    version_id("chalk", "5.6.1"): [
        ["acme/checkout-web", "acme/checkout-web", "chalk", "5.6.1", AT - 100, AT + 9_000],
    ],
}

MAINTAINERS = [[maintainer_id("qix"), "qix"], [maintainer_id("sindresorhus"), "sindresorhus"]]

OWNS = {
    maintainer_id("qix"): [["debug"]],
    maintainer_id("sindresorhus"): [["chalk"], ["ansi-styles"]],
}

REACH = {
    maintainer_id("qix"): [
        ["debug", "axios/axios", "axios/axios", "4.4.1", 1_000, SENTINEL],
    ],
    maintainer_id("sindresorhus"): [
        ["chalk", "acme/checkout-web", "acme/checkout-web", "5.6.1", AT - 100, AT + 9_000],
        ["chalk", "webpack/webpack", "webpack/webpack", "5.6.0", 1_000, SENTINEL],
    ],
}

MAINTAINED_BY_PACKAGE = {CHALK: [["sindresorhus"]], DEBUG: [["qix"]]}

RESOLVES_PER_REPO = 17


class FakeReader:
    """Answers a statement by its projection and parameters.

    Dispatching on the ``RETURN`` clause and the parameter names rather than on
    the whole statement means reformatting the Cypher does not break twenty
    tests, while swapping one query *kind* for another still does.
    """

    def __init__(
        self,
        *,
        packages=(CHALK, DEBUG),
        versions=(),
        watermarked=("acme/checkout-web", "webpack/webpack"),
    ):
        self.statements: list[tuple[str, dict]] = []
        self.packages = set(packages)
        self.versions = set(versions)
        self.watermarked = tuple(watermarked)

    def __call__(self, client, cypher, parameters=None, **kw):
        parameters = dict(parameters or {})
        self.statements.append((cypher, parameters))
        assert "ReplayTest" in cypher, "the fake is only wired for the test schema"
        return self._answer(cypher, parameters), False

    def _answer(self, cypher, p):
        projection = cypher.split("RETURN", 1)[1].replace("DISTINCT", "").strip()
        keys = set(p)

        if projection.startswith("r.id"):  # repo_directory
            return [list(row) for row in REPOS]
        if projection.startswith("m.id"):  # maintainer_directory
            return [list(row) for row in MAINTAINERS]
        if projection.startswith("w.slug"):  # watermarks
            return [[slug, 1_700_000_000] for slug in self.watermarked]
        if projection == "count(*)":  # resolves_edge_count
            assert keys == {"rid"}
            return [[RESOLVES_PER_REPO]]
        if projection == "m.name":  # maintainers_of_package
            return [list(r) for r in MAINTAINED_BY_PACKAGE.get(p["pid"], [])]
        if projection == "p.name":  # package_exists / maintained_packages
            if "mid" in keys:
                return [list(r) for r in OWNS.get(p["mid"], [])]
            return [["chalk"]] if p["pid"] in self.packages else []
        if projection.startswith("v.pkg, v.version"):  # version_exists
            return [["chalk", "5.6.1"]] if p["vid"] in self.versions else []
        if projection.startswith("p.name, r.slug"):  # maintainer_reach
            return self._live(REACH.get(p["mid"], []), p["t"], 4)
        if projection.startswith("r.slug"):  # repos_resolving_{package,version}
            source = (
                VERSION_RESOLUTIONS.get(p["vid"], [])
                if "vid" in keys
                else RESOLUTIONS.get(p["pid"], [])
            )
            return self._live(source, p["t"], 4)
        raise AssertionError(f"unexpected statement: {cypher}")

    @staticmethod
    def _live(rows, at, offset):
        """Apply the half-open interval predicate the engine would have applied."""
        return [list(r) for r in rows if r[offset] <= at < r[offset + 1]]


def console(**kw) -> Console:
    reader = kw.pop("reader", None) or FakeReader()
    return Console(
        client=HydraClient(config=ClientConfig(endpoint="http://unused.invalid")),
        schema=TEST_SCHEMA,
        incident=INCIDENT,
        reader=reader,
        **kw,
    )


# ------------------------------------------------------------------- directory


def test_repository_directory_is_read_once_and_cached():
    reader = FakeReader()
    view = console(reader=reader)
    assert [r.slug for r in view.repositories()] == [
        "acme/checkout-web",
        "axios/axios",
        "webpack/webpack",
    ]
    view.repositories()
    assert sum(1 for s, _ in reader.statements if "RETURN r.id" in s) == 1


def test_synthetic_repository_is_flagged_and_carries_its_provenance():
    record = next(r for r in console().repositories() if r.slug == "acme/checkout-web")
    assert record.synthetic is True
    assert record.provenance == "synthetic"
    payload = record.as_dict()
    assert "not a real git history" in payload["synthetic_note"]

    real = next(r for r in console().repositories() if r.slug == "webpack/webpack")
    assert real.synthetic is False
    assert "synthetic_note" not in real.as_dict()


# -------------------------------------------------------------------- exposure


def test_exposure_names_every_repository_including_the_ones_with_no_rows():
    result = console().exposure("chalk", AT)
    assert result["counts"] == {
        "repos": 3,
        "exposed": 1,
        "resolved_clean": 1,
        "not_resolved": 1,
    }
    assert [r["slug"] for r in result["repos"]] == [
        "acme/checkout-web",
        "webpack/webpack",
        "axios/axios",
    ]
    assert result["repos"][2]["status"] == "NOT_RESOLVED"


def test_exposure_carries_the_evidence_label_and_caveat_on_every_answer():
    for at in (WINDOW.start - 10_000, AT, WINDOW.end + 10_000):
        result = console().exposure("chalk", at)
        assert result["evidence"] == EVIDENCE == "RESOLVED"
        assert result["caveat"] == CAVEAT


def test_exposure_marks_the_synthetic_row_in_the_payload_itself():
    hit = console().exposure("chalk", AT)["repos"][0]
    assert hit["slug"] == "acme/checkout-web"
    assert hit["status"] == "EXPOSED"
    assert hit["synthetic"] is True
    assert "not a real git history" in hit["synthetic_note"]


def test_exposure_outside_every_interval_is_a_proven_negative():
    result = console().exposure("chalk", 500)  # before any RESOLVES edge opens
    assert result["counts"]["exposed"] == 0
    assert result["counts"]["not_resolved"] == 3
    assert result["package_in_graph"] is True
    assert result["in_exposure_window"] is False
    assert "proven negative" in result["note"]


def test_exposure_for_a_package_with_no_node_says_so_explicitly():
    reader = FakeReader(packages=())
    result = console(reader=reader).exposure("left-pad", AT)
    assert result["package_in_graph"] is False
    assert "real absence, not a lookup failure" in result["note"]
    # No traversal is issued once the anchor is known to be missing.
    assert not any("VERSION_OF" in s for s, _ in reader.statements)


def test_exposure_requires_a_package():
    with pytest.raises(ConsoleError):
        console().exposure("  ", AT)


def test_exposure_is_id_anchored_on_the_package():
    reader = FakeReader()
    console(reader=reader).exposure("chalk", AT)
    traversal = next(p for s, p in reader.statements if "VERSION_OF" in s)
    assert traversal["pid"] == package_id("chalk")
    assert traversal["t"] == AT


# --------------------------------------------------------------- blast radius


def test_blast_radius_builds_a_four_layer_node_link_graph():
    result = console().blast_radius("chalk", AT)
    kinds = {}
    for node in result["nodes"]:
        kinds.setdefault(node["kind"], []).append(node["id"])
    assert set(kinds) == {"repo", "version", "package", "maintainer"}
    assert kinds["package"] == ["pkg:chalk"]
    assert sorted(kinds["version"]) == ["ver:chalk@5.6.0", "ver:chalk@5.6.1"]
    assert result["exposed_repos"] == ["acme/checkout-web"]
    assert result["maintainers"] == ["sindresorhus"]


def test_blast_radius_omits_repositories_that_resolved_nothing():
    slugs = [n["id"] for n in console().blast_radius("chalk", AT)["nodes"] if n["kind"] == "repo"]
    assert "repo:axios/axios" not in slugs


def test_blast_radius_edges_carry_the_interval_and_the_malicious_flag():
    result = console().blast_radius("chalk", AT)
    resolves = [e for e in result["edges"] if e["kind"] == "RESOLVES"]
    assert {e["malicious"] for e in resolves} == {True, False}
    for edge in resolves:
        assert edge["valid_from_iso"]
    assert all(e["source"].startswith("maint:") for e in result["edges"] if e["kind"] == "MAINTAINS")


def test_blast_radius_node_ids_are_strings_so_63_bit_ids_never_reach_javascript():
    for node in console().blast_radius("chalk", AT)["nodes"]:
        assert isinstance(node["id"], str)


# ----------------------------------------------------------- maintainer reach


def test_maintainer_reach_separates_ownership_from_reach():
    result = console().maintainer_reach("sindresorhus", AT)
    assert result["maintains_package_count"] == 2
    assert result["maintains_packages"] == ["ansi-styles", "chalk"]
    assert result["reached_package_count"] == 1
    assert result["reached_repo_count"] == 2
    assert result["repo_package_pairs"] == 2
    assert result["maintainer_caveat"] == MAINTAINER_CAVEAT


def test_maintainer_reach_flags_synthetic_repositories_in_the_reached_list():
    reached = console().maintainer_reach("sindresorhus", AT)["reached_repos"]
    flags = {r["slug"]: r["synthetic"] for r in reached}
    assert flags == {"acme/checkout-web": True, "webpack/webpack": False}


def test_unknown_maintainer_is_reported_as_absent_not_as_an_error():
    result = console().maintainer_reach("nobody", AT)
    assert result["exists"] is False
    assert result["reached_repo_count"] == 0


def test_maintainer_reach_requires_a_name():
    with pytest.raises(ConsoleError):
        console().maintainer_reach("", AT)


def test_ranking_orders_by_repo_package_pairs_and_caches_by_instant():
    reader = FakeReader()
    view = console(reader=reader)
    ranked = view.maintainer_ranking(AT, limit=10)
    assert [e["maintainer"] for e in ranked["ranking"]] == ["sindresorhus", "qix"]
    assert [e["rank"] for e in ranked["ranking"]] == [1, 2]
    assert ranked["scored_accounts"] == 2

    before = len(reader.statements)
    again = view.maintainer_ranking(AT, limit=1)
    assert len(reader.statements) == before, "a cached instant must not re-query"
    assert len(again["ranking"]) == 1


def test_ranking_is_recomputed_for_a_different_instant():
    reader = FakeReader()
    view = console(reader=reader)
    view.maintainer_ranking(AT, limit=5)
    before = len(reader.statements)
    view.maintainer_ranking(AT + 1, limit=5)
    assert len(reader.statements) > before


def test_ranking_anchors_on_maintainer_ids():
    reader = FakeReader()
    console(reader=reader).maintainer_ranking(AT, limit=5)
    mids = {p["mid"] for _, p in reader.statements if "mid" in p}
    assert maintainer_id("qix") in mids


# --------------------------------------------------------- version footprint


def test_a_version_with_no_node_is_the_strongest_negative_available():
    result = console().version_footprint("chalk", "5.6.1", AT)
    assert result["version_in_graph"] is False
    assert "no lockfile in the dataset ever resolved it" in result["note"]
    assert result["repo_count"] == 0


def test_a_resolved_version_reports_the_repositories_that_held_it():
    reader = FakeReader(versions={version_id("chalk", "5.6.1")})
    result = console(reader=reader).version_footprint("chalk", "5.6.1", AT)
    assert result["version_in_graph"] is True
    assert result["note"] is None


# ------------------------------------------------------------ health, overview


def test_health_reads_watermarks_and_does_not_count_edges():
    """Counting RESOLVES costs ~9 s even anchored; the watermark scan is ~5 ms."""
    reader = FakeReader()
    health = console(reader=reader).health()
    assert health["reachable"] is True
    assert health["seeded"] is True
    assert health["repo_count"] == 3
    assert health["synthetic_repo_count"] == 1
    assert health["ingested_repo_count"] == 2
    assert health["unwatermarked_repos"] == ["axios/axios"]
    assert health["resolves_edges"] is None
    assert not [s for s, _ in reader.statements if "count(*)" in s]


def test_health_counts_edges_only_when_asked():
    reader = FakeReader()
    health = console(reader=reader).health(count_edges=True)
    assert health["resolves_edges"] == RESOLVES_PER_REPO * 3
    counts = [p for s, p in reader.statements if "count(*)" in s]
    assert len(counts) == 3
    assert all("rid" in p for p in counts)


def test_a_dataset_with_no_watermark_is_not_reported_as_seeded():
    reader = FakeReader(watermarked=())
    health = console(reader=reader).health()
    assert health["reachable"] is True
    assert health["seeded"] is False
    assert health["ingested_repo_count"] == 0


def test_health_reports_an_unreachable_node_instead_of_raising():
    def broken(*args, **kw):
        raise OSError("connection refused")

    health = console(reader=broken).health()
    assert health["reachable"] is False
    assert health["seeded"] is False
    assert "connection refused" in health["error"]


def test_overview_carries_every_caveat_the_page_renders():
    payload = console().overview()
    assert payload["caveat"] == CAVEAT
    assert payload["maintainer_caveat"] == MAINTAINER_CAVEAT
    assert "not a real git history" in payload["synthetic_caveat"]
    assert len(payload["repositories"]) == 3
    assert payload["incident"]["window"]["duration"] == "2 h 17 min"
