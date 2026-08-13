"""Tool bodies, against a recording fake client.

The live-node behaviour is covered by tests/integration/test_mcp_tools.py. What
is worth pinning down without a database is the logic that surrounds the query:
argument coercion, the row cap, and the honesty fields — the last of which is a
product requirement, so it is asserted on every tool that returns evidence.
"""

import pytest

from hindsight import coverage
from hindsight.graphbuild import Schema
from hindsight.history import SENTINEL
from hindsight.ids import maintainer_id, package_id, version_id
from hindsight_mcp import guard, service
from hindsight_mcp.service import Hindsight, Limits, ToolInputError

SCHEMA = Schema.prefixed("McpTest", "MCPTEST")

#: The two label scans behind the coverage verdict, answered as a dataset that
#: holds something. Merged under every :func:`build` unless a test overrides
#: them: every tool now reads them, and a fake that quietly presented an empty
#: graph would turn the whole suite into a test of the refusal path.
POPULATED = {
    "repos": [[1, "repo/a"], [2, "repo/b"]],
    "watermarks": [["repo/a", 100], ["repo/b", 100]],
}


class FakeClient:
    """Answers queries from a canned table and records what it was asked."""

    def __init__(self, answers=None, cursor_for=None):
        self.answers = answers or {}
        self.cursor_for = cursor_for or set()
        self.calls = []

    def query(self, cypher, parameters=None, *, timeout=None, page_size=None, cursor=None):
        self.calls.append(
            {
                "cypher": cypher,
                "parameters": parameters,
                "timeout": timeout,
                "page_size": page_size,
            }
        )
        key = self._key(cypher)
        rows = self.answers.get(key, [])
        # Coverage asks the graph to count, not to list. The fixtures still
        # describe those two labels as the rows they hold, because that is what
        # a dataset *is*; the fake does the counting the engine would.
        if "count(*)" in cypher:
            rows = [[len(rows)]]
        return {
            "columns": ["c"] * (len(rows[0]) if rows else 0),
            "rows": [[{"type": "any", "value": cell} for cell in row] for row in rows],
            "next_cursor": 1 if key in self.cursor_for else None,
        }

    @staticmethod
    def _key(cypher):
        # Before the node check: a count is also a `MATCH (n:...)`, and reading
        # it as a node lookup would hand coverage an empty answer for every
        # dataset.
        if "count(*)" in cypher:
            return "watermarks" if "Watermark" in cypher else "repos"
        if "MATCH (n:" in cypher:
            return "node"
        if "MCPTEST_MAINTAINS" in cypher and "MCPTEST_RESOLVES" in cypher:
            return "reach"
        if "MCPTEST_MAINTAINS" in cypher:
            return "owned"
        if "MCPTEST_VERSION_OF" in cypher:
            return "package"
        if "MCPTEST_RESOLVES" in cypher:
            return "version"
        # The coverage scans, told apart by their projection rather than by
        # their label, so reformatting the builder does not silently reclassify
        # them as an unanswered query and empty the dataset.
        if "RETURN r.id" in cypher:
            return "repos"
        if "RETURN w.slug" in cypher:
            return "watermarks"
        return "other"


def build(answers=None, cursor_for=None, limits=None, **kw):
    client = FakeClient({**POPULATED, **(answers or {})}, cursor_for)
    return Hindsight(client=client, schema=SCHEMA, limits=limits or Limits(), **kw), client


def build_empty(answers=None, **kw):
    """A node that answers every statement correctly and holds nothing."""
    return build(answers={**(answers or {}), "repos": [], "watermarks": []}, **kw)


# ------------------------------------------------------------------- coercion


@pytest.mark.parametrize(
    "given, expected",
    [
        (1757363580, 1757363580),
        ("1757363580", 1757363580),
        (1757363580.9, 1757363580),
        ("2025-09-08T20:33:00Z", 1757363580),
        ("2025-09-08T20:33:00+00:00", 1757363580),
        ("2025-09-08T21:33:00+01:00", 1757363580),
        ("  2025-09-08T20:33:00Z  ", 1757363580),
        # A naive datetime is read as UTC rather than as local time, so an
        # answer does not silently move with the server's timezone.
        ("2025-09-08T20:33:00", 1757363580),
    ],
)
def test_timestamps_accept_unix_seconds_or_iso(given, expected):
    assert service.to_epoch(given) == expected


@pytest.mark.parametrize("given", ["", "   ", "yesterday", "2025-13-45", True, None, []])
def test_unparseable_timestamps_are_rejected_by_name(given):
    with pytest.raises(ToolInputError) as excinfo:
        service.to_epoch(given, field_name="at_timestamp")
    assert "at_timestamp" in str(excinfo.value)


@pytest.mark.parametrize(
    "given, expected",
    [
        ("chalk@5.3.0", ("chalk", "5.3.0")),
        ("@babel/core@7.24.0", ("@babel/core", "7.24.0")),
        ("debug@4.3.4", ("debug", "4.3.4")),
        ("pkg@1.0.0-beta.1", ("pkg", "1.0.0-beta.1")),
    ],
)
def test_version_names_split_on_the_last_at_sign(given, expected):
    assert service.split_version(given) == expected


@pytest.mark.parametrize("given", ["chalk", "@babel/core", "", "   "])
def test_version_names_without_a_version_are_rejected_helpfully(given):
    with pytest.raises(ToolInputError) as excinfo:
        service.split_version(given)
    assert "package@version" in str(excinfo.value)


def test_open_interval_bounds_render_as_null_not_as_the_year_2100():
    assert service.iso(SENTINEL) is None
    assert service.iso(1757363580) == "2025-09-08T20:33:00Z"


def test_wire_cells_are_unwrapped_recursively():
    cell = {"type": "list", "value": [{"type": "string", "value": "a"},
                                      {"type": "integer", "value": 1}]}
    assert service.unwrap_cell(cell) == ["a", 1]
    assert service.unwrap_cell(7) == 7


# ----------------------------------------------------------------------- limits


def test_limits_are_clamped_to_what_the_engine_allows():
    assert Limits(max_rows=99999).max_rows == service.MAX_PAGE
    assert Limits(max_rows=0).max_rows == 1
    # The server's own 30 s cap cannot be raised by a client setting.
    assert Limits(deadline_seconds=600).deadline_seconds == 30.0
    assert Limits(deadline_seconds=0.0).deadline_seconds == 0.5


def test_the_row_cap_and_deadline_reach_the_client():
    hindsight, client = build(limits=Limits(max_rows=25, deadline_seconds=3))
    hindsight.cypher("MATCH (n:McpTestPkg {id: $id}) RETURN n.name", {"id": 1})
    assert client.calls[0]["page_size"] == 25
    assert client.calls[0]["timeout"] == 3


def test_truncation_is_reported_rather_than_hidden():
    hindsight, _ = build(
        answers={"node": [["a"], ["b"], ["c"]]}, cursor_for={"node"}
    )
    out = hindsight.cypher("MATCH (n:McpTestPkg {id: $id}) RETURN n.name", {"id": 1})
    assert out["truncated"] is True
    assert "truncation_note" in out
    assert "count(*)" in out["truncation_note"]


def test_untruncated_results_say_so_without_a_note():
    hindsight, _ = build(answers={"node": [["a"]]})
    out = hindsight.cypher("MATCH (n:McpTestPkg {id: $id}) RETURN n.name", {"id": 1})
    assert out["truncated"] is False
    assert "truncation_note" not in out
    assert out["rows"] == [["a"]]
    assert out["row_count"] == 1


def test_rows_come_back_as_plain_json():
    hindsight, _ = build(answers={"node": [["chalk", 5]]})
    out = hindsight.cypher("MATCH (n:McpTestPkg {id: $id}) RETURN n.name, n.x", {"id": 1})
    assert out["rows"] == [["chalk", 5]]
    assert isinstance(out["elapsed_ms"], float)


# ------------------------------------------------------------------------ guard


@pytest.mark.parametrize(
    "query",
    [
        "MATCH (n:McpTestPkg {id: 1}) DELETE n",
        "MATCH (n:McpTestPkg {id: 1}) RETURN n.name; CREATE (m:Evil)",
        "CREATE (n:Evil)",
    ],
)
def test_a_write_never_reaches_the_database(query):
    hindsight, client = build()
    with pytest.raises(guard.UnsafeCypher):
        hindsight.cypher(query)
    assert client.calls == [], "the guard let a write through to the client"


# ------------------------------------------------------------------- resolve_id


def test_resolve_id_returns_the_deterministic_id_and_how_to_use_it():
    hindsight, _ = build(answers={"node": [["chalk"]]})
    out = hindsight.resolve_id("package", "chalk")
    assert out["id"] == package_id("chalk")
    assert out["exists"] is True
    assert out["label"] == SCHEMA.package
    assert f"MATCH (n:{SCHEMA.package} {{id: $id}})" in out["how_to_use"]


def test_resolve_id_handles_versions_and_maintainers():
    hindsight, _ = build(answers={"node": [["chalk", "5.3.0", "chalk@5.3.0", 1]]})
    assert hindsight.resolve_id("version", "chalk@5.3.0")["id"] == version_id("chalk", "5.3.0")
    assert hindsight.resolve_id("maint", "qix")["id"] == maintainer_id("qix")


def test_an_id_for_an_unknown_name_is_still_well_defined():
    """Ids are derived, not allocated, so 'no rows' means 'never ingested'
    rather than 'lookup failed' — and the response has to say which."""
    hindsight, _ = build(answers={})
    out = hindsight.resolve_id("package", "never-seen")
    assert out["id"] == package_id("never-seen")
    assert out["exists"] is False
    assert "never been ingested" in out["note"]


# ------------------------------------------------------- honesty on every answer


EVIDENCE_BEARING = [
    ("exposure_asof", lambda h: h.exposure_asof("chalk", None, 1000)),
    ("exposure_asof exact", lambda h: h.exposure_asof("chalk", "5.3.0", 1000)),
    ("blast_radius", lambda h: h.blast_radius("chalk", 1000)),
    ("maintainer_reach", lambda h: h.maintainer_reach("qix", 1000)),
]


@pytest.mark.parametrize("name, call", EVIDENCE_BEARING, ids=[n for n, _ in EVIDENCE_BEARING])
def test_every_evidence_bearing_answer_says_what_it_proves(name, call):
    hindsight, _ = build(
        answers={
            "node": [["chalk"]],
            "version": [["repo/a", "A", "chalk", "5.3.0", 0, SENTINEL]],
            "package": [["repo/a", "A", "chalk", "5.3.0", 0, SENTINEL]],
            "reach": [["chalk", "repo/a", "A", "5.3.0", 0, SENTINEL]],
            "owned": [["chalk"]],
        }
    )
    out = call(hindsight)
    assert out["evidence"] == "resolved"
    assert "lockfile resolution" in out["caveat"]
    for word in ("installed", "built", "executed", "deployed"):
        assert word in out["caveat"]


@pytest.mark.parametrize("name, call", EVIDENCE_BEARING, ids=[n for n, _ in EVIDENCE_BEARING])
def test_no_answer_uses_deployment_language(name, call):
    """The caveat is the only place these words may appear."""
    hindsight, _ = build(
        answers={
            "node": [["chalk"]],
            "version": [["repo/a", "A", "chalk", "5.3.0", 0, SENTINEL]],
            "package": [["repo/a", "A", "chalk", "5.3.0", 0, SENTINEL]],
            "reach": [["chalk", "repo/a", "A", "5.3.0", 0, SENTINEL]],
            "owned": [["chalk"]],
        }
    )
    out = call(hindsight)
    fields = {k: v for k, v in out.items() if not k.endswith("caveat")}
    blob = repr(fields).lower()
    for word in ("deployed", "deployment", "in production", "running", "vulnerable"):
        assert word not in blob, f"{name} leaks '{word}' into a non-caveat field"


def test_maintainer_reach_flags_that_ownership_is_present_tense():
    hindsight, _ = build(answers={"node": [["qix"]], "owned": [["chalk"]], "reach": []})
    out = hindsight.maintainer_reach("qix", 1000)
    assert "PRESENT" in out["maintainer_caveat"].upper()
    assert "phished" in out["maintainer_caveat"]


# ------------------------------------------------------------------- tool shapes


def test_exposure_asof_requires_an_instant():
    hindsight, _ = build()
    with pytest.raises(ToolInputError) as excinfo:
        hindsight.exposure_asof("chalk", None, None)
    assert "AS-OF question" in str(excinfo.value)


def test_blast_radius_requires_an_instant():
    hindsight, _ = build()
    with pytest.raises(ToolInputError):
        hindsight.blast_radius("chalk", None)


def test_exposure_asof_anchors_on_the_version_when_one_is_given():
    hindsight, client = build(answers={"node": [["chalk", "5.3.0", "chalk@5.3.0", 1]]})
    hindsight.exposure_asof("chalk", "5.3.0", 1000)
    traversal = client.calls[-1]
    assert traversal["parameters"]["vid"] == version_id("chalk", "5.3.0")
    assert "MCPTEST_VERSION_OF" not in traversal["cypher"]


def test_exposure_asof_anchors_on_the_package_when_no_version_is_given():
    hindsight, client = build(answers={"node": [["chalk"]]})
    hindsight.exposure_asof("chalk", None, 1000)
    traversal = client.calls[-1]
    assert traversal["parameters"]["pid"] == package_id("chalk")
    assert "MCPTEST_VERSION_OF" in traversal["cypher"]


def test_exposure_asof_reports_intervals_in_both_forms():
    hindsight, _ = build(
        answers={
            "node": [["chalk"]],
            "package": [["repo/a", "A", "chalk", "5.3.0", 1757363580, SENTINEL]],
        }
    )
    repo = hindsight.exposure_asof("chalk", None, 1757363600)["repos"][0]
    assert repo["valid_from"] == 1757363580
    assert repo["valid_from_iso"] == "2025-09-08T20:33:00Z"
    assert repo["valid_to_iso"] is None
    assert repo["open_interval"] is True


def test_an_absent_package_is_a_proven_negative_not_a_failure():
    hindsight, _ = build(answers={})
    out = hindsight.exposure_asof("never-seen", None, 1000)
    assert out["anchor"]["exists"] is False
    assert out["repos"] == []
    assert "real negative" in out["note"]


def test_a_present_package_with_no_hits_says_the_negative_is_proven():
    hindsight, _ = build(answers={"node": [["chalk"]], "package": []})
    out = hindsight.exposure_asof("chalk", None, 1000)
    assert out["anchor"]["exists"] is True
    assert out["resolved_by_repo_count"] == 0
    assert "proven negative" in out["note"]


def test_blast_radius_rolls_up_per_repo_and_per_version():
    hindsight, _ = build(
        answers={
            "node": [["chalk"]],
            "package": [
                ["repo/a", "A", "chalk", "5.0.0", 0, 100],
                ["repo/a", "A", "chalk", "5.3.0", 100, SENTINEL],
                ["repo/b", "B", "chalk", "5.3.0", 100, SENTINEL],
            ],
        }
    )
    out = hindsight.blast_radius("chalk", 50)
    assert out["repo_count"] == 2
    assert out["version_count"] == 2
    assert out["resolution_count"] == 3
    assert out["versions"] == ["5.0.0", "5.3.0"]
    # Widest exposure first, so the first row is the one to act on.
    assert out["repos"][0]["slug"] == "repo/a"
    assert out["repos"][0]["version_count"] == 2


def test_maintainer_reach_separates_what_is_owned_from_what_is_reached():
    hindsight, _ = build(
        answers={
            "node": [["qix"]],
            "owned": [["chalk"], ["debug"], ["unused-pkg"]],
            "reach": [
                ["chalk", "repo/a", "A", "5.3.0", 0, SENTINEL],
                ["debug", "repo/a", "A", "4.3.4", 0, SENTINEL],
                ["chalk", "repo/b", "B", "5.3.0", 0, SENTINEL],
            ],
        }
    )
    out = hindsight.maintainer_reach("qix", 1000)
    assert out["maintains_package_count"] == 3
    assert out["reached_package_count"] == 2
    assert out["reached_repo_count"] == 2
    # The repo count saturates once a package is ubiquitous, so the finer
    # (repo, package) surface is what ranking should use.
    assert out["repo_package_pairs"] == 3
    assert out["reached_repos"][0]["slug"] == "repo/a"
    assert out["reached_repos"][0]["via_packages"] == ["chalk", "debug"]


def test_maintainer_reach_defaults_to_now():
    hindsight, client = build(answers={"node": [["qix"]]})
    out = hindsight.maintainer_reach("qix")
    assert out["at"] > 1_700_000_000
    assert client.calls[-1]["parameters"]["t"] == out["at"]


def test_maintainer_reach_anchors_on_the_maintainer_id():
    hindsight, client = build(answers={"node": [["qix"]]})
    hindsight.maintainer_reach("qix", 1000)
    assert client.calls[-1]["parameters"]["mid"] == maintainer_id("qix")


def test_answers_carry_the_instant_they_were_asked_about():
    hindsight, _ = build(answers={"node": [["chalk"]]})
    out = hindsight.blast_radius("chalk", "2025-09-08T20:33:00Z")
    assert out["at"] == 1757363580
    assert out["at_iso"] == "2025-09-08T20:33:00Z"


def test_the_schema_document_follows_the_configured_labels():
    hindsight, _ = build()
    markdown = hindsight.schema_document()
    assert SCHEMA.repo in markdown
    assert "HsRepo" not in markdown
    assert isinstance(hindsight.schema_document(as_markdown=False), dict)


# -------------------------------------------------------------------- coverage
#
# The failure mode this section exists for, and why it is worse here than in the
# console: pointed at an empty or mis-pointed label namespace every read comes
# back empty, and the tools above used to describe that as "a real negative, not
# a lookup failure" and "a proven negative for this timestamp". A responder at
# the console at least sees a blank page; an agent sees only the sentence, and
# relays it verbatim as "you were not exposed".
#
# So there are three states and they are kept apart here, as they are on the
# console side: a proven negative (the dataset is populated and the answer
# really is no), a truncated read (we saw some of the graph, every count is a
# floor) and no coverage at all (we saw none of it, and there is nothing to say
# at any confidence).

TOOL_CALLS = [
    ("exposure_asof", lambda h: h.exposure_asof("chalk", None, 1000)),
    ("exposure_asof exact", lambda h: h.exposure_asof("chalk", "5.3.0", 1000)),
    ("blast_radius", lambda h: h.blast_radius("chalk", 1000)),
    ("maintainer_reach", lambda h: h.maintainer_reach("qix", 1000)),
    ("resolve_id", lambda h: h.resolve_id("package", "chalk")),
]


def test_an_empty_dataset_refuses_to_answer_instead_of_proving_a_negative():
    hindsight, _ = build_empty()
    out = hindsight.exposure_asof("chalk", None, 1000)
    assert out["answerable"] is False
    assert out["unanswerable_reason"] == coverage.EMPTY_DATASET
    assert "no question can be answered" in out["note"]
    # The two sentences that turned a mis-pointed namespace into an all-clear.
    assert "real negative" not in out["note"]
    assert "proven negative" not in out["note"]


def test_a_populated_dataset_still_proves_its_negatives():
    """The regression guard: the fix must not weaken the answer it protects."""
    absent, _ = build(answers={})
    out = absent.exposure_asof("never-seen", None, 1000)
    assert out["answerable"] is True
    assert out["unanswerable_reason"] is None
    assert out["unanswerable_note"] is None
    assert "real negative, not a lookup failure" in out["note"]

    nobody, _ = build(answers={"node": [["chalk"]], "package": []})
    quiet = nobody.exposure_asof("chalk", None, 1000)
    assert quiet["answerable"] is True
    assert "a proven negative for this timestamp" in quiet["note"]


@pytest.mark.parametrize("name, call", TOOL_CALLS, ids=[n for n, _ in TOOL_CALLS])
def test_every_tool_carries_the_coverage_verdict(name, call):
    """Every absence this server reports is qualified, not just the loud ones."""
    populated, _ = build(answers={"node": [["chalk"]]})
    answered = call(populated)
    assert answered["answerable"] is True
    assert answered["unanswerable_note"] is None
    assert answered["coverage"] == {"repo_count": 2, "ingested_repo_count": 2}

    # Nothing resolves against an empty namespace, which is the point: every one
    # of these calls has an absence to describe and none of them may call it a
    # result.
    blank, _ = build_empty()
    refused = call(blank)
    assert refused["answerable"] is False
    assert refused["unanswerable_reason"] == coverage.EMPTY_DATASET
    assert refused["note"] == refused["unanswerable_note"]
    assert refused["coverage"] == {"repo_count": 0, "ingested_repo_count": 0}


def test_blast_radius_on_an_empty_dataset_is_not_an_empty_blast_radius():
    """Zero repos, zero versions, zero resolutions: the shape of both answers."""
    hindsight, _ = build_empty()
    out = hindsight.blast_radius("chalk", 1000)
    assert (out["repo_count"], out["version_count"], out["resolution_count"]) == (0, 0, 0)
    assert out["answerable"] is False
    assert "not by measurement" not in out["note"]
    assert "not a result" in out["note"]


def test_resolve_id_on_an_empty_dataset_does_not_claim_a_name_was_never_ingested():
    """True of every name that has ever existed, against a dataset with none."""
    hindsight, _ = build_empty()
    out = hindsight.resolve_id("package", "chalk")
    assert out["id"] == package_id("chalk")
    assert out["exists"] is False
    assert "never been ingested" not in out["note"]
    assert out["note"] == out["unanswerable_note"]
    # The id is still derived, so the tool's actual job is unaffected.
    assert f"MATCH (n:{SCHEMA.package} {{id: $id}})" in out["how_to_use"]


def test_maintainer_reach_on_an_empty_dataset_is_not_a_zero_trust_radius():
    """"Nothing of ours moves if this account is phished" is the reassuring
    answer, and it is what every account gets from a dataset nobody loaded."""
    hindsight, _ = build_empty(answers={"node": [["qix"]]})
    out = hindsight.maintainer_reach("qix", 1000)
    assert out["reached_repo_count"] == 0
    assert out["answerable"] is False
    assert "gap in coverage" in out["note"] or "not a result" in out["note"]


def test_a_dataset_with_repositories_but_no_ingested_history_cannot_answer():
    """A half-loaded dataset answers "nothing resolved this" for free."""
    hindsight, _ = build(answers={"watermarks": [], "node": [["chalk"]]})
    out = hindsight.exposure_asof("chalk", None, 1000)
    assert out["answerable"] is False
    assert out["unanswerable_reason"] == coverage.NO_INGESTED_HISTORY
    assert out["coverage"] == {"repo_count": 2, "ingested_repo_count": 0}
    assert "gap in coverage and not a negative result" in out["note"]


def test_one_watermarked_repository_is_enough_to_answer():
    hindsight, _ = build(answers={"watermarks": [["repo/a", 100]], "node": [["chalk"]]})
    out = hindsight.exposure_asof("chalk", None, 1000)
    assert out["answerable"] is True
    assert out["coverage"] == {"repo_count": 2, "ingested_repo_count": 1}


def test_coverage_counts_rather_than_intersecting_two_capped_reads():
    """The trade this predicate makes, stated where it can be argued with.

    Intersecting the directory with the watermarks is the more precise question
    and it inverts at scale: past the row cap the two reads can return pages
    with no slug in common, and a graph holding a hundred thousand repositories
    is declared to hold no ingested history at all. Two counts cannot be
    truncated, so the answer no longer depends on how big the dataset is.

    What is given up is the stray-watermark case: a watermark whose repository
    the directory does not list now counts as history. That state needs a
    hand-built graph -- the ingest writes both, in one namespace, and nothing
    deletes on an append-only node -- while the truncation it replaces needs
    only a customer larger than the demo.
    """
    hindsight, client = build(answers={"watermarks": [["repo/gone", 100]]})
    assert hindsight.coverage().answerable is True

    counted = [c["cypher"] for c in client.calls if "count(*)" in c["cypher"]]
    assert len(counted) == 2
    assert not any("RETURN w.slug" in c["cypher"] for c in client.calls)


def test_coverage_and_truncation_are_separate_states_and_do_not_collapse():
    """Three distinct answers to "why is this empty", never merged into one."""
    proven, _ = build(answers={"node": [["chalk"]], "package": []})
    cut, _ = build(answers={"node": [["chalk"]]}, cursor_for={"package"})
    blank, _ = build_empty(answers={"node": [["chalk"]]})

    at = [tool.exposure_asof("chalk", None, 1000) for tool in (proven, cut, blank)]
    assert [(o["answerable"], o["truncated"]) for o in at] == [
        (True, False),
        (True, True),
        (False, False),
    ]
    assert cut.exposure_asof("chalk", None, 1000)["unanswerable_reason"] is None


def test_the_coverage_read_is_shared_rather_than_repeated_per_tool():
    """An agent works through several tools in a row on one incident."""
    hindsight, client = build(answers={"node": [["chalk"]]})
    hindsight.exposure_asof("chalk", None, 1000)
    hindsight.blast_radius("chalk", 1000)
    hindsight.resolve_id("package", "chalk")
    kinds = [FakeClient._key(call["cypher"]) for call in client.calls]
    assert kinds.count("repos") == 1
    assert kinds.count("watermarks") == 1


def test_an_empty_dataset_is_never_cached_as_the_answer():
    """The server usually starts before an ingest finishes; both are separate runs.

    Caching the empty read would freeze the refusal for the life of the process:
    the graph fills up, every question it can now answer is still met with "no
    coverage", and the only fix is a restart nobody knows to perform. The
    dangerous direction of staleness is the one that withholds an answer, so it
    is the one that is not cached.
    """
    hindsight, client = build_empty(answers={"node": [["chalk"]]})
    assert hindsight.exposure_asof("chalk", None, 1000)["unanswerable_reason"] == (
        coverage.EMPTY_DATASET
    )

    client.answers["repos"] = POPULATED["repos"]
    assert hindsight.exposure_asof("chalk", None, 1000)["unanswerable_reason"] == (
        coverage.NO_INGESTED_HISTORY
    )

    client.answers["watermarks"] = POPULATED["watermarks"]
    assert hindsight.exposure_asof("chalk", None, 1000)["answerable"] is True


def test_a_populated_dataset_read_expires_rather_than_outliving_the_dataset():
    """A cached count is a claim about when we looked; the window bounds it.

    Not the same hazard as the empty read above — a directory short by one
    repository costs a number, not the answer — but a long-lived agent session
    must not keep reporting a two-repository estate after the org grew.
    """
    now = [1000.0]
    hindsight, client = build(clock=lambda: now[0], cache_ttl=30.0)

    hindsight.coverage()
    now[0] += 29.0
    hindsight.coverage()
    assert [FakeClient._key(c["cypher"]) for c in client.calls].count("repos") == 1

    now[0] += 2.0
    hindsight.coverage()
    assert [FakeClient._key(c["cypher"]) for c in client.calls].count("repos") == 2


def test_the_refusal_reaches_the_agent_in_the_console_s_words():
    """Both surfaces read the same note out of core, so a responder hearing it
    second-hand from the agent hears what the screen would have said."""
    hindsight, _ = build_empty()
    out = hindsight.exposure_asof("chalk", None, 1000)
    assert out["note"] == coverage.UNANSWERABLE_NOTES[coverage.EMPTY_DATASET]
    assert set(coverage.coverage_of(0, 0).as_dict()) <= set(out)
