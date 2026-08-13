"""Whether a dataset is in a position to answer anything at all.

Both read surfaces turn an empty result into a sentence, and the sentence they
reach for is a verdict: "no repository resolved this, and here is the interval
that proves it". That claim rests on a fact neither surface was checking —
that the dataset holds anything for the answer to be absent *from*. Pointed at
an empty or mis-pointed label namespace every count is zero, every repository
reads as NOT_RESOLVED, and a configuration mistake renders exactly like a clean
estate, with more confidence than a clean estate gets, because a missing
package node used to be reported as "a real absence, not a lookup failure".

The predicate lives in core rather than in either surface because it is a
property of the dataset, not of the screen or the tool reading it. An incident
responder scrubbing the timeline and an agent calling the MCP tool have to
reach the same verdict about the same graph, and — since a refusal is prose
that the agent will relay verbatim to a human who cannot see the empty page —
they have to reach it in the same words. Core carries no third-party dependency
and imports neither surface, so this is the one place they can share it.

Nothing here touches the network. The two counts are supplied by the caller,
which is what lets each surface cache the reads behind them on its own terms.
"""

from __future__ import annotations

from dataclasses import dataclass

#: Why a dataset cannot answer a question at all. Deliberately a short list:
#: these are the ways a read comes back with nothing to *say*, as opposed to the
#: ways it comes back saying "no". They are not verdicts and must never be
#: rendered as one.
EMPTY_DATASET = "empty_dataset"
NO_INGESTED_HISTORY = "no_ingested_history"
UNREACHABLE = "unreachable"

#: The sentence that replaces the proven-negative prose when coverage is absent.
#: These strings are the honest counterpart of
#: :data:`~hindsight_web.analysis.TRUNCATION_CAVEAT` and are held to the same
#: rule: nothing here may imply anything about a running system.
UNANSWERABLE_NOTES = {
    EMPTY_DATASET: (
        "this dataset contains no repositories, so no question can be answered "
        "from it. Nothing was checked against this package and nothing was "
        "found to be absent: the counts below are the size of an empty dataset, "
        "not a result. Point Hindsight at a seeded dataset before reading "
        "anything into them"
    ),
    NO_INGESTED_HISTORY: (
        "this dataset lists repositories but not one of them carries a finished "
        "ingest watermark, so no lockfile history has been loaded for any of "
        "them. Every repository would read as 'did not resolve this package' "
        "purely because its history is missing, which is a gap in coverage and "
        "not a negative result"
    ),
    UNREACHABLE: (
        "the node did not answer, so this dataset could not be read at all. "
        "Nothing below is a statement about this package"
    ),
}


@dataclass(frozen=True)
class Coverage:
    """Whether a dataset is in a position to answer anything at all.

    The value of either surface is the strength of its negative: "no repository
    resolved this, and here is the interval that proves it". That claim is only
    available when the dataset is *known to be populated*. Pointed at an empty
    or mis-pointed label namespace, every count is zero and every repository is
    NOT_RESOLVED, which renders identically to a genuinely clean estate and, for
    an incident responder, converts a configuration mistake into an all-clear.

    So coverage travels with the answer, next to ``truncated`` and distinct from
    it. The two failure modes are not the same shape and must not be collapsed:
    truncation means *we saw some of the graph*, and absent coverage means *we
    saw none of it*. A truncated read still knows how many repositories exist;
    an empty dataset does not know anything.
    """

    answerable: bool
    reason: str | None
    repo_count: int
    ingested_repo_count: int

    @property
    def note(self) -> str | None:
        return UNANSWERABLE_NOTES.get(self.reason) if self.reason else None

    def as_dict(self) -> dict:
        """The fields every answer carries, additive to the existing shape."""
        return {
            "answerable": self.answerable,
            "unanswerable_reason": self.reason,
            "unanswerable_note": self.note,
            "coverage": {
                "repo_count": self.repo_count,
                "ingested_repo_count": self.ingested_repo_count,
            },
        }


def coverage_of(
    repo_count: int, ingested_repo_count: int, *, reachable: bool = True
) -> Coverage:
    """The one place the answerable predicate is decided.

    Identical by construction to the console's ``seeded`` health flag, because a
    header that reads "0 repos" beside an answer strip that reads "not resolved
    by any repository" is the contradiction this function exists to remove — and
    identical between the surfaces for the same reason, one step out: an agent
    that would relay a proven negative from a dataset the console refuses to
    read is the same contradiction with nobody watching.
    """
    if not reachable:
        reason = UNREACHABLE
    elif repo_count <= 0:
        reason = EMPTY_DATASET
    elif ingested_repo_count <= 0:
        reason = NO_INGESTED_HISTORY
    else:
        reason = None
    return Coverage(
        answerable=reason is None,
        reason=reason,
        repo_count=max(0, repo_count),
        ingested_repo_count=max(0, ingested_repo_count),
    )


__all__ = [
    "EMPTY_DATASET",
    "NO_INGESTED_HISTORY",
    "UNANSWERABLE_NOTES",
    "UNREACHABLE",
    "Coverage",
    "coverage_of",
]
