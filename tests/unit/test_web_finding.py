"""The evidence packet: what it states, what it refuses to state, and in what.

These tests drive :func:`hindsight_web.finding.build_finding` and
:func:`~hindsight_web.finding.render_markdown` directly off fixture dicts, with
no console, no app and no database, because the packet is a pure function of the
payloads and its whole value is what it does with the awkward ones. Three of
those matter more than the happy path:

* a **truncated** read, where every count is a floor and the packet must say so
  on each number rather than in a footnote a reader can skip;
* an **unanswerable** dataset, where the packet must state no counts at all -
  not zeros, which are the shape of a clean estate;
* a **missing health probe**, where the absent provenance has to read as absent
  rather than as "nothing to record".

The repository rows are built by calling the real :func:`~hindsight_web.
analysis.classify`, not by hand. That keeps the fixture honest about the shape
the console actually produces, and it is also how the em dashes get in: the
basis prose is written in ``analysis.py`` and the markdown renderer has to fold
it, which is a thing this suite can only test if it does not type the dash
itself.
"""

from __future__ import annotations

import copy

import pytest

from hindsight.envelope import (
    EVIDENCE,
    TRUNCATION_NOTE,
    UNVERIFIED_ABSENCE_NOTE,
    completeness,
)
from hindsight.coverage import coverage_of
from hindsight.history import SENTINEL
from hindsight_web.analysis import (
    CAVEAT,
    SYNTHETIC_CAVEAT,
    Window,
    classify,
    iso,
    summarize,
)
from hindsight_web.finding import (
    DATASET_FACTS_UNAVAILABLE,
    NOT_INCLUDED,
    SCOPE_STATEMENT,
    ascii_only,
    build_finding,
    render_markdown,
)
from hindsight_web.incident import build_incident

from test_web_incident import RAW  # noqa: E402

INCIDENT = build_incident(RAW)
WINDOW: Window = INCIDENT.window
AT = WINDOW.start + 3_000
GENERATED_AT = WINDOW.end + 86_400
PERMALINK = "http://localhost:8080/?package=chalk&at=" + str(AT)
MALICIOUS = {"5.6.1"}


def _repo(slug, rows, **extra):
    """One repository verdict, produced the way the console produces it."""
    verdict = classify(slug, rows, MALICIOUS, WINDOW, AT)
    verdict.update(extra)
    return verdict


def repos():
    """The three shapes: exposed, resolved but not malicious, and untouched."""
    return [
        _repo(
            "acme/checkout-web",
            [{"version": "5.6.1", "valid_from": AT - 100, "valid_to": AT + 9_000}],
            name="acme/checkout-web",
            service="checkout",
            provenance="synthetic",
            origin="constructed for the demo",
            synthetic=True,
            synthetic_note=SYNTHETIC_CAVEAT,
        ),
        _repo(
            "webpack/webpack",
            [{"version": "5.6.0", "valid_from": 1_000, "valid_to": SENTINEL}],
            name="webpack/webpack",
            service="build",
            provenance="git-lockfile-history",
            origin="git lockfile history",
            synthetic=False,
        ),
        _repo(
            "axios/axios",
            [],
            name="axios/axios",
            service="http-client",
            provenance="git-lockfile-history",
            origin="git lockfile history",
            synthetic=False,
        ),
    ]


def exposure(*, truncated=False, repo_count=3, ingested=2, package="chalk"):
    """An exposure payload shaped exactly like ``Console.exposure`` returns."""
    rows = repos()
    coverage = coverage_of(repo_count, ingested)
    payload = {
        "question": (
            "which repositories had a lockfile resolving this package at this "
            "instant, and was any of those versions a malicious one"
        ),
        "package": package,
        "at": AT,
        "at_iso": iso(AT),
        "in_exposure_window": WINDOW.contains(AT),
        "package_in_graph": True,
        "malicious_versions": sorted(MALICIOUS),
        "counts": summarize(rows),
        "repos": rows,
        "elapsed_ms": 5.91,
        "evidence": EVIDENCE,
        "caveat": CAVEAT,
        **completeness(truncated),
        **coverage.as_dict(),
    }
    if not coverage.answerable:
        # The console blanks the rows it cannot vouch for the same way.
        payload["note"] = coverage.note
        payload["repos"] = []
        payload["counts"] = summarize([])
    return payload


HEALTH = {
    "reachable": True,
    "error": None,
    "endpoint": "http://127.0.0.1:8000/query",
    "namespace": "hindsight",
    "cell": "default",
    "labels": {
        "repo": "HsRepo",
        "package": "HsPkg",
        "version": "HsVer",
        "maintainer": "HsMaint",
        "watermark": "HsWatermark",
        "resolves": "HS_RESOLVES",
    },
    "repo_count": 3,
    "synthetic_repo_count": 1,
    "ingested_repo_count": 2,
    "unwatermarked_repos": ["axios/axios"],
    "resolves_edges": None,
    "incident": INCIDENT.title,
    "seeded": True,
}


def packet(*, health=HEALTH, **kw):
    return build_finding(
        exposure(**kw),
        INCIDENT.as_dict(),
        health,
        package=kw.get("package", "chalk"),
        at=AT,
        generated_at=GENERATED_AT,
        permalink=PERMALINK,
    )


# ------------------------------------------------------- (a) the clean finding


def test_an_answerable_read_states_its_counts_as_exact():
    """Every count carries the basis it was measured on, on the number itself.

    A consumer reading this JSON cannot pick up ``1`` without also picking up
    ``exact``, which is the whole reason the count is an object rather than an
    integer.
    """
    answer = packet()["answer"]
    assert answer["answerable"] is True
    assert answer["counts_are_floors"] is False
    assert answer["counts"]["exposed"] == {
        "value": 1,
        "basis": "exact",
        "label": "Resolved a malicious version",
    }
    for key in ("exposed", "resolved_clean", "not_resolved", "repos"):
        assert answer["counts"][key]["basis"] == "exact"
    assert answer["counts"]["repos"]["value"] == 3
    # No truncation vocabulary on a complete read: a caveat that appears when it
    # does not apply is one a reader learns to skip.
    assert "truncation_note" not in answer
    assert "counts_withheld" not in answer


def test_the_headline_is_the_sentence_the_console_states():
    assert packet()["answer"]["headline"] == (
        "1 of 3 repositories resolved a malicious chalk version"
    )


def test_the_question_carries_the_caveat_verbatim():
    """What "exposure" means here is not restated in this module's own words."""
    question = packet()["question"]
    assert question["package"] == "chalk"
    assert question["at"] == AT
    assert question["at_iso"] == iso(AT)
    assert question["exposure_means"] == CAVEAT
    assert question["in_exposure_window"] is True


def test_the_receipts_carry_every_repository_the_read_accounted_for():
    """Not just the exposed one. A numerator without its denominator is not an
    answer, and the two negatives are the evidence that the estate was checked
    rather than sampled."""
    receipts = packet()["receipts"]
    assert [r["slug"] for r in receipts] == [
        "acme/checkout-web",
        "webpack/webpack",
        "axios/axios",
    ]
    hit = receipts[0]
    assert hit["status"] == "EXPOSED"
    assert hit["matched_versions"] == ["5.6.1"]
    assert hit["versions"][0]["malicious"] is True
    assert hit["versions"][0]["valid_from_iso"] == iso(AT - 100)
    assert hit["versions"][0]["held_for"]
    assert hit["basis"].startswith("lockfile resolved 5.6.1")
    # The constructed repository says so in the artifact, not only on screen.
    assert hit["synthetic"] is True
    assert hit["synthetic_note"] == SYNTHETIC_CAVEAT
    assert receipts[2]["status"] == "NOT_RESOLVED"
    assert receipts[2]["matched_versions"] == []


def test_the_receipts_invent_no_field_the_payload_did_not_have():
    """A packet that fills gaps is a packet that cannot be audited."""
    source = exposure()
    built = build_finding(
        source,
        INCIDENT.as_dict(),
        HEALTH,
        package="chalk",
        at=AT,
        generated_at=GENERATED_AT,
        permalink=PERMALINK,
    )
    for receipt, row in zip(built["receipts"], source["repos"], strict=True):
        assert set(receipt) <= set(row)
        for key, value in receipt.items():
            assert value == row[key]


def test_the_authority_is_the_incident_file_and_says_it_is():
    """The graph never decides what "malicious" means, and the packet says which
    document did and on whose sources."""
    authority = packet()["authority"]
    assert authority["incident"] == "test compromise"
    assert authority["date"] == "2025-09-08"
    assert authority["sources"] == ["https://example.invalid/writeup"]
    assert authority["malicious_versions"] == ["5.6.1"]
    assert authority["window"]["start_iso"] == iso(WINDOW.start)
    assert authority["window"]["duration"] == "2 h 17 min"
    assert "not inferred from the graph" in authority["authority_note"]
    # Only the queried package's records, with the registry timestamps the
    # incident file verified.
    assert [v["key"] for v in authority["malicious_version_records"]] == [
        "chalk@5.6.1"
    ]
    assert authority["malicious_version_records"][0]["remediated_version"] == "5.6.2"


def test_the_window_notes_travel_when_the_file_states_them():
    """``window_note`` and ``remediation_note`` are the sentences that keep the
    numbers honest, so they belong on the artifact - and an empty one is dropped
    rather than exported as a qualification that got lost."""
    raw = copy.deepcopy(RAW)
    raw["window"]["note"] = "keyv@6.0.0 cannot arrive transitively"
    raw["window"]["remediation_note"] = "no clean successor exists to point at"
    with_notes = build_finding(
        exposure(),
        build_incident(raw).as_dict(),
        HEALTH,
        package="chalk",
        at=AT,
        generated_at=GENERATED_AT,
        permalink=PERMALINK,
    )["authority"]["window"]
    assert with_notes["note"] == "keyv@6.0.0 cannot arrive transitively"
    assert with_notes["remediation_note"] == "no clean successor exists to point at"
    # RAW states neither, and an empty string is not a note.
    assert "note" not in packet()["authority"]["window"]
    assert "remediation_note" not in packet()["authority"]["window"]


def test_provenance_carries_the_permalink_and_the_dataset_it_was_read_from():
    provenance = packet()["provenance"]
    assert provenance["generated_at"] == GENERATED_AT
    assert provenance["generated_at_iso"] == iso(GENERATED_AT)
    assert provenance["permalink"] == PERMALINK
    assert provenance["query_elapsed_ms"] == 5.91
    assert provenance["dataset_facts_available"] is True
    assert provenance["dataset"]["labels"]["resolves"] == "HS_RESOLVES"
    assert provenance["dataset"]["namespace"] == "hindsight"
    assert provenance["dataset"]["repo_count"] == 3
    assert provenance["dataset"]["ingested_repo_count"] == 2


def test_the_envelope_reuses_the_shared_vocabulary_rather_than_restating_it():
    envelope = packet()["envelope"]
    assert envelope["evidence"] == EVIDENCE
    assert envelope["evidence_means"] == CAVEAT
    assert envelope["completeness"] == {
        "truncated": False,
        "note": None,
        "absence_note": None,
    }
    assert envelope["coverage"]["answerable"] is True
    assert envelope["coverage"]["repo_count"] == 3
    assert envelope["scope"] == SCOPE_STATEMENT
    # The three axes are named and kept apart in the sentence itself.
    for axis in ("Evidence:", "Completeness:", "Coverage:"):
        assert axis in envelope["scope"]


def test_the_packet_names_what_it_does_not_establish():
    """The roadmap, stated inside the artifact. A finding that does not name its
    own gaps invites the reader to fill them in."""
    claims = [entry["claim"] for entry in packet()["not_included"]]
    assert claims == [
        "runtime execution",
        "resolution ambiguity",
        "cryptographic signature",
    ]
    assert len(claims) == len(NOT_INCLUDED)
    for entry in packet()["not_included"]:
        assert entry["statement"].startswith("This packet")


def test_the_top_level_order_leads_with_the_question():
    assert list(packet()) == [
        "artifact",
        "question",
        "answer",
        "receipts",
        "authority",
        "provenance",
        "envelope",
        "not_included",
    ]
    assert packet()["artifact"]["kind"] == "hindsight-evidence-packet"


# ---------------------------------------------------------- (b) a cut read


def test_a_truncated_read_marks_every_count_a_floor():
    answer = packet(truncated=True)["answer"]
    assert answer["counts_are_floors"] is True
    for key in ("exposed", "resolved_clean", "not_resolved", "repos"):
        assert answer["counts"][key]["basis"] == "floor"
    # Verbatim, from the module both read surfaces import it from.
    assert answer["truncation_note"] == TRUNCATION_NOTE
    assert answer["absence_note"] == UNVERIFIED_ABSENCE_NOTE
    assert packet(truncated=True)["envelope"]["completeness"] == {
        "truncated": True,
        "note": TRUNCATION_NOTE,
        "absence_note": UNVERIFIED_ABSENCE_NOTE,
    }


def test_the_truncated_headline_states_the_floor_in_ascii():
    """The console prints a real greater-or-equal sign; a document that gets
    pasted into a ticket and grepped gets the two characters everybody can
    type."""
    headline = packet(truncated=True)["answer"]["headline"]
    assert headline == ">= 1 of >= 3 repositories resolved a malicious chalk version"
    assert "\u2265" not in headline


def test_the_markdown_of_a_cut_read_says_so_on_the_numbers():
    document = render_markdown(packet(truncated=True))
    assert "Every count above is a floor, not a total." in document
    assert "| >= 1 | floor |" in document
    assert ascii_only(TRUNCATION_NOTE) in document
    assert ascii_only(UNVERIFIED_ABSENCE_NOTE) in document


# ------------------------------------------------------ (c) no coverage at all


def test_an_unanswerable_dataset_yields_a_packet_with_no_counts_in_it():
    """Zeros are the shape of a clean estate. There is no key here to misread:
    the block states why nothing was measured instead."""
    built = packet(repo_count=0, ingested=0)
    answer = built["answer"]
    assert answer["answerable"] is False
    assert "counts" not in answer
    assert answer["counts_withheld"] is True
    assert answer["unanswerable_reason"] == "empty_dataset"
    assert "no question can be answered" in answer["coverage_note"]
    assert "would render identically to a clean estate" in (
        answer["counts_withheld_because"]
    )
    assert answer["headline"] == (
        "No answer for chalk: this dataset contains no repositories, so nothing "
        "was checked"
    )
    assert built["envelope"]["coverage"]["answerable"] is False
    assert built["envelope"]["coverage"]["reason"] == "empty_dataset"


def test_an_ingestless_dataset_refuses_for_its_own_reason():
    answer = packet(repo_count=3, ingested=0)["answer"]
    assert answer["unanswerable_reason"] == "no_ingested_history"
    assert "ingested lockfile history" in answer["headline"]
    assert "counts" not in answer


def test_the_markdown_of_a_refusal_states_no_number_and_says_why():
    document = render_markdown(packet(repo_count=0, ingested=0))
    assert "No counts are stated." in document
    assert "| Finding | Count | Basis |" not in document
    assert "no question can be answered" in document
    assert "No repository rows accompany this answer." in document


# ---------------------------------------------------- (d) no dataset facts


def test_a_missing_health_probe_is_marked_absent_and_never_silent():
    provenance = packet(health=None)["provenance"]
    assert provenance["dataset"] is None
    assert provenance["dataset_facts_available"] is False
    assert provenance["dataset_facts_note"] == DATASET_FACTS_UNAVAILABLE
    assert "Dataset facts unavailable" in provenance["dataset_facts_note"]
    # The rest of the provenance still stands: this degrades, it does not fail.
    assert provenance["permalink"] == PERMALINK
    assert provenance["generated_at_iso"] == iso(GENERATED_AT)


def test_the_markdown_says_the_dataset_facts_are_missing():
    document = render_markdown(packet(health=None))
    assert ascii_only(DATASET_FACTS_UNAVAILABLE) in document
    assert "Label namespace" not in document
    # And the opposite, so the assertion above is about the absence and not
    # about a section that never renders.
    assert "Label namespace" in render_markdown(packet())


def test_a_partial_health_payload_carries_only_what_it_has():
    provenance = packet(health={"reachable": False, "endpoint": "http://x/query"})[
        "provenance"
    ]
    assert provenance["dataset"] == {"reachable": False, "endpoint": "http://x/query"}
    assert provenance["dataset_facts_available"] is True


# ------------------------------------------------- (e) the document itself


@pytest.mark.parametrize(
    "kwargs",
    [
        {},
        {"truncated": True},
        {"repo_count": 0, "ingested": 0},
        {"repo_count": 3, "ingested": 0},
        {"health": None},
    ],
)
def test_the_markdown_is_ascii_only_whatever_the_packet_says(kwargs):
    """Prose elsewhere in this repository uses em dashes and the console prints
    a greater-or-equal sign. A finding gets pasted into reports, committed into
    fixtures and grepped, so it is held to one encoding."""
    document = render_markdown(packet(**kwargs))
    document.encode("ascii")  # raises if anything slipped through
    assert "\u2014" not in document
    assert "\u2013" not in document
    # The fold rewrites; it does not escape. An escape in the output would mean
    # a character nobody taught `ascii_only` about.
    assert "\\u" not in document


def test_the_markdown_folds_the_em_dashes_the_basis_prose_carries():
    """The fixture never types a dash: the NOT_RESOLVED basis comes out of
    ``analysis.py`` with one, which is the case worth testing."""
    assert "\u2014" in packet()["receipts"][2]["basis"]
    document = render_markdown(packet())
    assert "this instant - the package is not in its dependency closure" in document


def test_the_markdown_is_deterministic_given_the_dict():
    built = packet()
    assert render_markdown(built) == render_markdown(built)
    assert render_markdown(built) == render_markdown(copy.deepcopy(built))


def test_the_markdown_leads_with_the_question_and_the_headline():
    document = render_markdown(packet())
    lines = document.split("\n")
    assert lines[0] == "# Hindsight evidence packet: chalk at " + iso(AT)
    assert lines[2] == "1 of 3 repositories resolved a malicious chalk version"
    # Every section an auditor is promised, in the order the packet orders them.
    for heading in (
        "## The question",
        "## The answer",
        "## Receipts",
        "## Authority for the word malicious",
        "## Provenance and reproducibility",
        "## What this packet states about itself",
        "## What this packet does not establish",
    ):
        assert heading in document
    assert document.index("## The question") < document.index("## Receipts")
    assert document.index("## Receipts") < document.index(
        "## What this packet does not establish"
    )


def test_the_markdown_receipts_table_carries_the_intervals():
    document = render_markdown(packet())
    assert "| Repository | Status | Matched versions |" in document
    assert "acme/checkout-web (constructed example) | EXPOSED | 5.6.1 |" in document
    assert iso(AT - 100) + " to " + iso(AT + 9_000) in document
    # An open interval is named as one rather than printed as a sentinel year.
    assert "still open" in document
    assert str(SENTINEL) not in document


def test_the_markdown_carries_the_permalink_and_the_sources():
    document = render_markdown(packet())
    assert PERMALINK in document
    assert "https://example.invalid/writeup" in document
    assert ascii_only(SCOPE_STATEMENT) in document
    for claim in ("runtime execution", "resolution ambiguity", "cryptographic"):
        assert claim in document


# ------------------------------------------------------------------ the fold


def test_ascii_only_folds_rather_than_drops():
    assert ascii_only("a \u2014 b") == "a - b"
    assert ascii_only("a \u2013 b") == "a - b"
    assert ascii_only("\u2265 4") == ">= 4"
    assert ascii_only("it\u2019s \u201cquoted\u201d") == "it's \"quoted\""
    assert ascii_only(None) == ""
    assert ascii_only(7) == "7"


def test_ascii_only_escapes_what_it_cannot_fold_instead_of_deleting_it():
    """A repository slug does not get to lose a letter on its way into an
    evidence document."""
    assert ascii_only("caf\u00e9") == "caf\\xe9"
    assert "caf" in ascii_only("caf\u00e9")
