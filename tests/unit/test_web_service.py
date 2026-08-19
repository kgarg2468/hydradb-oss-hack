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
from hindsight_web import service
from hindsight_web.analysis import (
    CAVEAT,
    EVIDENCE,
    MAINTAINER_CAVEAT,
    TRUNCATION_CAVEAT,
)
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

    #: Every distinct query kind the fake can answer, by the name this suite
    #: uses in ``cut``. Listing them here rather than inferring keeps a new
    #: builder from silently escaping the truncation tests.
    KINDS = (
        "repo_directory",
        "maintainer_directory",
        "watermarks",
        "repo_count",
        "watermark_count",
        "resolves_edge_count",
        "maintainers_of_package",
        "package_exists",
        "maintained_packages",
        "version_exists",
        "maintainer_reach",
        "repos_resolving",
    )

    def __init__(
        self,
        *,
        packages=(CHALK, DEBUG),
        versions=(),
        watermarked=("acme/checkout-web", "webpack/webpack"),
        repos=REPOS,
        cut=(),
    ):
        self.statements: list[tuple[str, dict]] = []
        #: The repository directory this dataset holds. ``repos=()`` is the
        #: empty or mis-pointed label namespace: a node that answers every
        #: statement correctly and holds nothing.
        self.repos = [list(row) for row in repos]
        self.packages = set(packages)
        self.versions = set(versions)
        self.watermarked = tuple(watermarked)
        #: Query kinds to report as having hit the row cap.
        self.cut = set(cut)
        assert self.cut <= set(self.KINDS), f"unknown kind in cut: {self.cut}"

    def __call__(self, client, cypher, parameters=None, **kw):
        parameters = dict(parameters or {})
        self.statements.append((cypher, parameters))
        assert "ReplayTest" in cypher, "the fake is only wired for the test schema"
        kind, rows = self._answer(cypher, parameters)
        return rows, kind in self.cut

    def _answer(self, cypher, p):
        kind, rows = self._dispatch(cypher, p)
        assert kind in self.KINDS, f"undeclared kind {kind!r}"
        return kind, rows

    def _dispatch(self, cypher, p):
        projection = cypher.split("RETURN", 1)[1].replace("DISTINCT", "").strip()
        keys = set(p)

        if projection.startswith("r.id"):  # repo_directory
            return "repo_directory", [list(row) for row in self.repos]
        if projection.startswith("m.id"):
            return "maintainer_directory", [list(row) for row in MAINTAINERS]
        if projection.startswith("w.slug"):
            return "watermarks", [[slug, 1_700_000_000] for slug in self.watermarked]
        if projection == "count(*)":
            # Three statements share this projection. The anchored one carries a
            # repository id; the other two are the coverage counts, which are
            # told apart by the label they scan. They are answered from the same
            # fixtures as the directory and watermark reads, because a fake in
            # which the count and the list disagree is testing nothing real.
            if keys == {"rid"}:
                return "resolves_edge_count", [[RESOLVES_PER_REPO]]
            assert not keys
            if "Watermark" in cypher:
                return "watermark_count", [[len(self.watermarked)]]
            return "repo_count", [[len(self.repos)]]
        if projection == "m.name":
            return "maintainers_of_package", [
                list(r) for r in MAINTAINED_BY_PACKAGE.get(p["pid"], [])
            ]
        if projection == "p.name":  # package_exists / maintained_packages
            if "mid" in keys:
                return "maintained_packages", [list(r) for r in OWNS.get(p["mid"], [])]
            return "package_exists", [["chalk"]] if p["pid"] in self.packages else []
        if projection.startswith("v.pkg, v.version"):
            return "version_exists", (
                [["chalk", "5.6.1"]] if p["vid"] in self.versions else []
            )
        if projection.startswith("p.name, r.slug"):
            return "maintainer_reach", self._live(REACH.get(p["mid"], []), p["t"], 4)
        if projection.startswith("r.slug"):  # repos_resolving_{package,version}
            source = (
                VERSION_RESOLUTIONS.get(p["vid"], [])
                if "vid" in keys
                else RESOLUTIONS.get(p["pid"], [])
            )
            return "repos_resolving", self._live(source, p["t"], 4)
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
        assert result["evidence"] == EVIDENCE == "resolved"
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
    # The counts health does run are two label scans over a handful of nodes.
    # The one it must not run is the anchored edge count, which is the ~9 s one
    # and is the only count that carries a repository id.
    assert not [p for s, p in reader.statements if "count(*)" in s and "rid" in p]
    assert len([s for s, _ in reader.statements if "count(*)" in s]) == 2


def test_health_counts_edges_only_when_asked():
    reader = FakeReader()
    health = console(reader=reader).health(count_edges=True)
    assert health["resolves_edges"] == RESOLVES_PER_REPO * 3
    counts = [p for s, p in reader.statements if "count(*)" in s and "rid" in p]
    assert len(counts) == 3


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


# ------------------------------------------------------------------ truncation
#
# A read that hit the row cap produces counts that are floors. Presenting one of
# those as a total is the worst thing this console has available to it — "0 other
# repositories affected" when the result set was cut off — so every method that
# touches a paged read is checked here for carrying the flag out, and the
# UI-facing wording is checked for never claiming a proven negative from a
# partial read.


def test_exposure_carries_truncation_out_of_the_traversal():
    result = console(reader=FakeReader(cut={"repos_resolving"})).exposure("chalk", AT)
    assert result["truncated"] is True
    assert result["truncation_note"] == TRUNCATION_CAVEAT
    assert "lower bound" in result["truncation_note"]


def test_a_truncated_empty_result_is_not_reported_as_a_proven_negative():
    """The claim the console must not make: an empty cut page proves nothing."""
    whole = console().exposure("chalk", 500)
    partial = console(reader=FakeReader(cut={"repos_resolving"})).exposure("chalk", 500)

    expected = {"repos": 3, "exposed": 0, "resolved_clean": 0, "not_resolved": 3}
    assert whole["counts"] == partial["counts"] == expected
    assert "proven negative" in whole["note"]
    assert "proven negative" not in partial["note"]
    assert partial["note"] == TRUNCATION_CAVEAT


def test_a_truncated_repository_directory_poisons_every_exposure_count():
    """Repos missing from the directory are missing from all three tallies."""
    result = console(reader=FakeReader(cut={"repo_directory"})).exposure("chalk", AT)
    assert result["truncated"] is True
    assert result["counts"]["repos"] == 3  # what we saw, not what exists


def test_version_footprint_marks_its_count_as_a_lower_bound():
    reader = FakeReader(versions={version_id("chalk", "5.6.1")}, cut={"repos_resolving"})
    result = console(reader=reader).version_footprint("chalk", "5.6.1", AT)
    assert result["truncated"] is True
    assert result["repo_count_is_lower_bound"] is True
    assert result["note"] == TRUNCATION_CAVEAT


def test_an_untruncated_footprint_makes_no_lower_bound_claim():
    reader = FakeReader(versions={version_id("chalk", "5.6.1")})
    result = console(reader=reader).version_footprint("chalk", "5.6.1", AT)
    assert result["truncated"] is False
    assert result["repo_count_is_lower_bound"] is False
    assert result["truncation_note"] is None
    assert result["note"] is None


def test_a_missing_version_node_is_still_a_strong_negative_when_complete():
    result = console().version_footprint("chalk", "5.6.1", AT)
    assert result["truncated"] is False
    assert "no lockfile in the dataset ever resolved it" in result["note"]


@pytest.mark.parametrize("kind", ["repos_resolving", "maintainers_of_package"])
def test_blast_radius_is_truncated_if_either_of_its_reads_was(kind):
    result = console(reader=FakeReader(cut={kind})).blast_radius("chalk", AT)
    assert result["truncated"] is True
    assert result["truncation_note"] == TRUNCATION_CAVEAT


def test_a_complete_blast_radius_says_so():
    assert console().blast_radius("chalk", AT)["truncated"] is False


@pytest.mark.parametrize("kind", ["maintainer_reach", "maintained_packages"])
def test_maintainer_reach_is_truncated_if_either_of_its_reads_was(kind):
    result = console(reader=FakeReader(cut={kind})).maintainer_reach("sindresorhus", AT)
    assert result["truncated"] is True
    assert result["counts_are_lower_bounds"] is True


def test_one_truncated_account_makes_the_whole_ranking_untrustworthy():
    """A floor for one score means the *order* is not reliable either."""
    ranked = console(reader=FakeReader(cut={"maintainer_reach"})).maintainer_ranking(AT)
    assert ranked["truncated"] is True
    assert all(entry["truncated"] for entry in ranked["ranking"])


def test_a_truncated_account_list_truncates_the_ranking():
    reader = FakeReader(cut={"maintainer_directory"})
    ranked = console(reader=reader).maintainer_ranking(AT)
    assert ranked["truncated"] is True
    assert ranked["ranked_all_accounts"] is True  # the cap was not what cut it


def test_the_cached_ranking_keeps_its_truncation_flag():
    """A cache hit must not launder a partial answer into a complete one."""
    view = console(reader=FakeReader(cut={"maintainer_reach"}))
    first = view.maintainer_ranking(AT)
    second = view.maintainer_ranking(AT)
    assert second["cached"] is True
    assert second["truncated"] is first["truncated"] is True


def test_the_account_cap_is_reported_as_incompleteness(monkeypatch):
    monkeypatch.setattr(service, "MAX_RANKED_MAINTAINERS", 1)
    ranked = console().maintainer_ranking(AT)
    assert ranked["scored_accounts"] == 1
    assert ranked["ranked_all_accounts"] is False
    assert ranked["max_ranked_accounts"] == 1
    assert ranked["truncated"] is True


def test_a_complete_ranking_claims_completeness():
    ranked = console().maintainer_ranking(AT)
    assert ranked["truncated"] is False
    assert ranked["ranked_all_accounts"] is True
    assert ranked["truncation_note"] is None


def test_health_and_overview_report_a_truncated_directory():
    for payload in (
        console(reader=FakeReader(cut={"repo_directory"})).health(),
        console(reader=FakeReader(cut={"repo_directory"})).overview(),
    ):
        assert payload["truncated"] is True
        assert payload["truncation_note"] == TRUNCATION_CAVEAT


def test_overview_ships_the_truncation_wording_to_the_page():
    payload = console().overview()
    assert payload["truncation_caveat"] == TRUNCATION_CAVEAT
    assert payload["truncated"] is False


# -------------------------------------------------------------------- coverage
#
# The failure mode this section exists for: pointed at an empty or mis-pointed
# label namespace, every count is zero, every repository is NOT_RESOLVED and the
# console renders a confident all-clear, with *more* confidence than a genuinely
# clean estate gets, because an absent package node used to be reported as "a
# real absence, not a lookup failure". For an incident tool that turns a
# configuration mistake into "you were not exposed".
#
# So there are three states and they are kept apart here: a proven negative (the
# dataset is populated and the answer really is no), a truncated read (we saw
# some of the graph, every count is a floor) and no coverage at all (we saw
# nothing, and there is no answer to give at any confidence).


def empty_console(**kw):
    """A node that answers every statement correctly and holds nothing."""
    return console(reader=FakeReader(repos=(), watermarked=(), packages=(), **kw))


def test_an_empty_dataset_refuses_to_answer_instead_of_proving_a_negative():
    result = empty_console().exposure("chalk", AT)
    assert result["answerable"] is False
    assert result["unanswerable_reason"] == service.EMPTY_DATASET
    assert "no question can be answered" in result["note"]
    # The two sentences that made an empty graph read as an all-clear.
    assert "proven negative" not in result["note"]
    assert "real absence" not in result["note"]


def test_the_empty_dataset_note_says_the_counts_are_not_a_result():
    result = empty_console().exposure("chalk", AT)
    assert result["counts"] == {
        "repos": 0, "exposed": 0, "resolved_clean": 0, "not_resolved": 0
    }
    assert "not a result" in result["note"]
    assert result["unanswerable_note"] == result["note"]
    assert result["coverage"] == {"repo_count": 0, "ingested_repo_count": 0}


def test_a_populated_dataset_still_proves_its_negatives():
    """The regression guard: the fix must not weaken the answer it protects."""
    absent = console(reader=FakeReader(packages=())).exposure("left-pad", AT)
    assert absent["answerable"] is True
    assert absent["unanswerable_reason"] is None
    assert absent["unanswerable_note"] is None
    assert "real absence, not a lookup failure" in absent["note"]

    nobody = console().exposure("chalk", 500)
    assert nobody["answerable"] is True
    assert "proven negative" in nobody["note"]


def test_a_dataset_with_repositories_but_no_ingested_history_cannot_answer():
    """A half-loaded dataset answers NOT_RESOLVED for everything, for free."""
    result = console(reader=FakeReader(watermarked=())).exposure("chalk", AT)
    assert result["answerable"] is False
    assert result["unanswerable_reason"] == service.NO_INGESTED_HISTORY
    assert result["coverage"] == {"repo_count": 3, "ingested_repo_count": 0}
    assert "gap in coverage and not a negative result" in result["note"]


def test_one_watermarked_repository_is_enough_to_answer():
    result = console(reader=FakeReader(watermarked=("webpack/webpack",))).exposure(
        "chalk", AT
    )
    assert result["answerable"] is True
    assert result["unanswerable_reason"] is None


def test_coverage_and_truncation_are_separate_states_and_do_not_collapse():
    """Three distinct answers to "why is this empty", never merged into one."""
    proven = console().exposure("chalk", 500)
    cut = console(reader=FakeReader(cut={"repos_resolving"})).exposure("chalk", 500)
    blank = empty_console().exposure("chalk", 500)

    assert (proven["answerable"], proven["truncated"]) == (True, False)
    assert (cut["answerable"], cut["truncated"]) == (True, True)
    assert (blank["answerable"], blank["truncated"]) == (False, False)
    assert len({proven["note"], cut["note"], blank["note"]}) == 3
    assert cut["note"] == TRUNCATION_CAVEAT
    assert blank["unanswerable_reason"] == service.EMPTY_DATASET
    assert cut["unanswerable_reason"] is None


def test_status_values_are_untouched_by_the_coverage_field():
    """EXPOSED / RESOLVED_CLEAN / NOT_RESOLVED are a contract; this is additive."""
    result = console().exposure("chalk", AT)
    assert [r["status"] for r in result["repos"]] == [
        "EXPOSED",
        "RESOLVED_CLEAN",
        "NOT_RESOLVED",
    ]
    assert result["answerable"] is True


def test_version_footprint_on_an_empty_dataset_is_not_a_proven_absence():
    """The sharpest negative this product states, and the easiest to fake."""
    result = empty_console().version_footprint("chalk", "5.6.1", AT)
    assert result["answerable"] is False
    assert result["unanswerable_reason"] == service.EMPTY_DATASET
    assert result["version_in_graph"] is False
    assert "no question can be answered" in result["note"]
    assert "no lockfile in the dataset ever resolved it" not in result["note"]


def test_version_footprint_keeps_its_strong_negative_when_the_dataset_is_real():
    result = console().version_footprint("chalk", "5.6.1", AT)
    assert result["answerable"] is True
    assert "no lockfile in the dataset ever resolved it" in result["note"]


def test_blast_radius_carries_the_same_coverage_verdict_as_the_exposure_read():
    blank = empty_console().blast_radius("chalk", AT)
    assert blank["answerable"] is False
    assert blank["unanswerable_reason"] == service.EMPTY_DATASET
    # No repository reaches the drawing, so nothing in it can be read as a
    # repository that came back clean. The console refuses to draw it at all.
    assert [n for n in blank["nodes"] if n["kind"] == "repo"] == []
    assert blank["exposed_repos"] == []
    assert blank["counts"]["repos"] == 0

    real = console().blast_radius("chalk", AT)
    assert real["answerable"] is True
    assert real["unanswerable_note"] is None


def test_health_and_the_answer_path_cannot_disagree_about_the_dataset():
    """The contradiction the fix removes: a "0 repos" dot beside an all-clear."""
    for view, expected in (
        (console(), True),
        (empty_console(), False),
        (console(reader=FakeReader(watermarked=())), False),
    ):
        health = view.health()
        assert health["answerable"] is expected
        assert health["seeded"] is health["answerable"]
        assert view.exposure("chalk", AT)["answerable"] is expected


def test_health_reports_an_unreachable_node_as_unanswerable():
    def broken(*args, **kw):
        raise OSError("connection refused")

    health = console(reader=broken).health()
    assert health["reachable"] is False
    assert health["answerable"] is False
    assert health["unanswerable_reason"] == service.UNREACHABLE
    assert "did not answer" in health["unanswerable_note"]


def test_an_unreadable_dataset_raises_on_the_answer_path_rather_than_answering():
    """A 502 is itself a refusal; only health turns a failed read into a state."""
    def broken(*args, **kw):
        raise OSError("connection refused")

    with pytest.raises(OSError, match="connection refused"):
        console(reader=broken).exposure("chalk", AT)


def test_an_empty_dataset_is_never_cached_as_the_answer():
    """The console usually starts before ingest finishes; both are separate runs.

    Caching the empty read would freeze the refusal for the life of the server:
    the graph fills up, every question it can now answer is still met with "no
    coverage", and the only fix is a restart nobody knows to perform. The
    dangerous direction of staleness is the one that withholds an answer, so it
    is the one that is not cached.
    """
    reader = FakeReader(repos=(), watermarked=())
    view = console(reader=reader)
    assert view.exposure("chalk", AT)["unanswerable_reason"] == service.EMPTY_DATASET

    reader.repos = [list(row) for row in REPOS]
    assert view.exposure("chalk", AT)["unanswerable_reason"] == (
        service.NO_INGESTED_HISTORY
    )

    reader.watermarked = ("webpack/webpack",)
    answered = view.exposure("chalk", AT)
    assert answered["answerable"] is True
    assert answered["unanswerable_reason"] is None


def test_coverage_is_read_once_and_shared_with_every_answer():
    """The scrubber issues an exposure read every 55 ms; coverage is cached."""
    reader = FakeReader()
    view = console(reader=reader)
    for _ in range(3):
        view.exposure("chalk", AT)
    counts = [s for s, p in reader.statements if "count(*)" in s and "rid" not in p]
    assert len(counts) == 2
    assert sum(1 for s, _ in reader.statements if "RETURN r.id" in s) == 1
    # The watermark list is not on the answer path at all any more: coverage
    # counts them, and only health needs to name the ones that are missing.
    assert not [s for s, _ in reader.statements if "RETURN w.slug" in s]


def test_a_populated_dataset_read_expires_rather_than_outliving_the_dataset():
    """A cached count is a claim about when we looked; the window bounds it.

    Not the same hazard as the empty read above — a directory short by one
    repository costs a number, not the answer — but a console that can never
    see a tenth repository is reporting a nine-repository estate forever.
    """
    now = [1000.0]
    reader = FakeReader()
    view = console(reader=reader, clock=lambda: now[0], cache_ttl=30.0)

    view.repositories()
    now[0] += 29.0
    view.repositories()
    assert sum(1 for s, _ in reader.statements if "RETURN r.id" in s) == 1

    now[0] += 2.0
    view.repositories()
    assert sum(1 for s, _ in reader.statements if "RETURN r.id" in s) == 2


def test_the_coverage_predicate_is_decided_in_exactly_one_place():
    assert service.coverage_of(3, 2).answerable is True
    assert service.coverage_of(0, 0).reason == service.EMPTY_DATASET
    assert service.coverage_of(9, 0).reason == service.NO_INGESTED_HISTORY
    assert service.coverage_of(3, 2, reachable=False).reason == service.UNREACHABLE
    assert service.coverage_of(3, 2).note is None


def test_every_unanswerable_note_avoids_deployment_language():
    """The honesty rule that guards analysis.py, applied to the new strings."""
    from test_web_analysis import FORBIDDEN  # noqa: PLC0415

    for note in service.UNANSWERABLE_NOTES.values():
        lowered = note.lower()
        for word in FORBIDDEN:
            assert word not in lowered, f"{word!r} appears in {note[:80]!r}"
        assert "proven" not in lowered
