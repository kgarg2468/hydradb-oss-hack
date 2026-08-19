"""Interval arithmetic, timestamp coercion, and the vocabulary the UI may use.

The last group is the unusual one. This product's credibility rests on never
implying more than a lockfile can prove, and "never" is not a code review
convention — it is a test. :func:`test_no_module_string_implies_deployment`
reads every string constant in the analysis module and fails on the words that
would turn a resolution into a deployment claim.
"""

from __future__ import annotations

import pytest

from hindsight_web import analysis
from hindsight_web.analysis import (
    EXPOSED,
    FAR_FUTURE,
    NOT_RESOLVED,
    RESOLVED_CLEAN,
    TimestampError,
    Window,
    classify,
    covers,
    describe_interval,
    humanize,
    iso,
    sort_key,
    summarize,
    to_epoch,
)

WINDOW = Window(start=1_757_337_130, end=1_757_345_400, first_publish=1_757_337_130)


# ------------------------------------------------------------------ timestamps


def test_to_epoch_accepts_unix_seconds_and_iso():
    assert to_epoch(1_757_340_300) == 1_757_340_300
    assert to_epoch("1757340300") == 1_757_340_300
    assert to_epoch("2025-09-08T14:05:00Z") == 1_757_340_300
    # A naive string is read as UTC rather than as the server's local zone; a
    # console that silently shifted an incident timestamp by an office's offset
    # would be worse than one that refused the input.
    assert to_epoch("2025-09-08T14:05:00") == 1_757_340_300


def test_to_epoch_rejects_nonsense():
    for bad in ("", "yesterday", None, True, {}):
        with pytest.raises(TimestampError):
            to_epoch(bad)


def test_iso_renders_open_bound_as_none():
    assert iso(1_757_340_300) == "2025-09-08T14:05:00Z"
    assert iso(FAR_FUTURE) is None
    assert iso(None) is None


@pytest.mark.parametrize(
    ("seconds", "expected"),
    [
        (0, "0 s"),
        (59, "59 s"),
        (60, "1 min"),
        (4_140, "69 min"),
        (7_200, "2 h"),
        (8_270, "2 h 17 min"),
        (86_400, "1 d"),
        (351_360, "4 d 1 h"),
    ],
)
def test_humanize(seconds, expected):
    assert humanize(seconds) == expected


# -------------------------------------------------------------------- intervals


def test_describe_interval_closed_and_open():
    closed = describe_interval(1_000, 4_600)
    assert closed["held_seconds"] == 3_600
    # Under 90 minutes the unit is minutes, without exception: "69 min before
    # the first malicious publish" is the sentence this product exists to say,
    # and switching to "1 h 9 min" at the top of that range would blunt it.
    assert closed["held_for"] == "60 min"
    assert closed["open_interval"] is False

    still_open = describe_interval(1_000, FAR_FUTURE)
    assert still_open["open_interval"] is True
    assert still_open["valid_to_iso"] is None
    assert still_open["held_seconds"] is None


def test_covers_is_half_open_at_both_ends():
    assert covers(100, 200, 100, 200) is True
    assert covers(101, 200, 100, 200) is False
    assert covers(100, 199, 100, 200) is False
    assert covers(None, 200, 100, 200) is False


# ---------------------------------------------------------------- classification


def resolution(version, valid_from, valid_to):
    return {"version": version, "valid_from": valid_from, "valid_to": valid_to}


def test_exposed_when_any_resolved_version_is_malicious():
    verdict = classify(
        "acme/checkout-web",
        [
            resolution("5.6.1", WINDOW.start + 1_700, WINDOW.end + 9_000),
            resolution("4.1.2", 1_700_000_000, FAR_FUTURE),
        ],
        {"5.6.1"},
        WINDOW,
        WINDOW.start + 3_000,
    )
    assert verdict["status"] == EXPOSED
    assert verdict["matched_versions"] == ["5.6.1"]
    # The malicious version sorts first: it is the thing being read.
    assert verdict["versions"][0]["version"] == "5.6.1"
    assert "2025-09-08" in verdict["basis"]


def test_not_resolved_is_a_first_class_answer_with_its_own_wording():
    verdict = classify("axios/axios", [], {"1.1.1"}, WINDOW, WINDOW.start)
    assert verdict["status"] == NOT_RESOLVED
    assert verdict["versions"] == []
    assert "not in its dependency closure" in verdict["basis"]


def test_clean_pin_spanning_the_window_says_so_and_gives_the_lead_time():
    """The demo's sharpest moment: proving a negative with the reason attached."""
    pinned_at = WINDOW.first_publish - 351_360  # 4 d 1 h before the first publish
    verdict = classify(
        "webpack/webpack",
        [resolution("5.6.0", pinned_at, 1_765_000_000)],
        {"5.6.1"},
        WINDOW,
        WINDOW.start + 3_000,
    )
    assert verdict["status"] == RESOLVED_CLEAN
    assert verdict["matched_versions"] == []
    assert "across the entire 2 h 17 min exposure window" in verdict["basis"]
    assert "4 d 1 h old when the first malicious version was published" in verdict["basis"]


def test_clean_pin_that_changed_inside_the_window_is_not_claimed_to_span_it():
    verdict = classify(
        "acme/checkout-web",
        [resolution("5.3.0", WINDOW.start - 100, WINDOW.start + 2_000)],
        {"5.6.1"},
        WINDOW,
        WINDOW.start + 100,
    )
    assert verdict["status"] == RESOLVED_CLEAN
    assert "did change at some point inside the" in verdict["basis"]
    assert "across the entire" not in verdict["basis"]


def test_summarize_and_sort_put_exposed_first():
    repos = [
        {"slug": "z/clean", "status": RESOLVED_CLEAN},
        {"slug": "a/absent", "status": NOT_RESOLVED},
        {"slug": "m/hit", "status": EXPOSED},
    ]
    assert summarize(repos) == {
        "repos": 3,
        "exposed": 1,
        "resolved_clean": 1,
        "not_resolved": 1,
    }
    assert [r["slug"] for r in sorted(repos, key=sort_key)] == [
        "m/hit",
        "z/clean",
        "a/absent",
    ]


# ----------------------------------------------------------------- honesty


#: Words that would turn "a lockfile pinned this" into a claim about a running
#: system. None of them may appear in any string this module can render.
FORBIDDEN = (
    "deployed",
    "deployment",
    "in production",
    "was running",
    "were running",
    "infected",
    "compromised system",
    "you were hacked",
)


def test_no_module_string_implies_deployment():
    haystacks = [
        value
        for name, value in vars(analysis).items()
        if isinstance(value, str) and not name.startswith("__")
    ]
    haystacks.append(analysis.classify.__doc__ or "")
    for text in haystacks:
        lowered = text.lower()
        for word in FORBIDDEN:
            assert word not in lowered, f"{word!r} appears in {text[:80]!r}"


def test_every_rendered_basis_avoids_deployment_language():
    verdicts = [
        classify("a", [resolution("5.6.1", 0, FAR_FUTURE)], {"5.6.1"}, WINDOW, 10),
        classify("b", [], {"5.6.1"}, WINDOW, 10),
        classify("c", [resolution("5.3.0", 0, FAR_FUTURE)], {"5.6.1"}, WINDOW, 10),
    ]
    for verdict in verdicts:
        lowered = verdict["basis"].lower()
        for word in FORBIDDEN:
            assert word not in lowered


def test_caveat_names_the_four_things_resolution_does_not_prove():
    for word in ("installed", "built", "executed", "shipped"):
        assert word in analysis.CAVEAT
    assert analysis.EVIDENCE == "resolved"


def test_both_surfaces_emit_the_same_evidence_value():
    """One graph, one kind of evidence, one wire value.

    They drifted: this module spelled it ``"RESOLVED"`` and the MCP tools
    spelled it ``"resolved"``, so a consumer keying on the string saw two kinds
    of evidence where the graph has one, and an agent quoting its own answer to
    a responder looking at the console was quoting a different value for the
    same fact. Nothing caught it because nothing owned the constant, so the
    assertion is here rather than in either surface's own test: it fails if
    either module reintroduces a private copy.
    """
    from hindsight import envelope
    from hindsight_mcp import service as mcp_service

    assert analysis.EVIDENCE == mcp_service.EVIDENCE == envelope.EVIDENCE
    # Not merely equal today: both read the one object, so they cannot be
    # edited apart.
    assert analysis.EVIDENCE is envelope.EVIDENCE
    assert mcp_service.EVIDENCE is envelope.EVIDENCE


def test_both_surfaces_say_the_same_thing_about_a_capped_read():
    """The truncation sentence is protocol too, not per-surface prose."""
    from hindsight import envelope

    assert analysis.TRUNCATION_CAVEAT is envelope.TRUNCATION_NOTE
    assert "lower bound" in envelope.TRUNCATION_NOTE
    # The agent surface's raw-Cypher variant leads with the identical sentence
    # and only appends a remedy that makes sense for a hand-written statement.
    assert envelope.cypher_truncation_note(1000).startswith(envelope.TRUNCATION_NOTE)


def test_the_capped_read_sentence_separates_counts_from_absence_verdicts():
    """The word "floor" is true of the match counts and false of the negatives.

    The sentence travels verbatim onto three surfaces, and on one of them - the
    console, where ``resolved_clean`` and ``not_resolved`` are classifications
    that rest on rows being *absent* - a blanket "every count is a lower bound"
    is not merely imprecise, it points the wrong way: a repository whose
    malicious edge fell past the cap is counted clean here and would move into
    exposed on a complete read. So the one sentence has to say both halves, and
    it is asserted here rather than in either surface's own test because it is
    the shared vocabulary that has to carry them.
    """
    from hindsight import envelope

    note = envelope.TRUNCATION_NOTE
    # The floor claim is attached to counts of matches, not to counts at large.
    assert "every count of matches it returned is a lower bound" in note
    # And the other half, which is the one a reader would not supply themselves.
    assert "any verdict that rests on a row being absent is unverified" in note


def test_synthetic_caveat_states_the_repo_is_not_real():
    assert "not a real git history" in analysis.SYNTHETIC_CAVEAT
    assert "fabricated" in analysis.SYNTHETIC_CAVEAT
