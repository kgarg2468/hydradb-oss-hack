"""The words both read surfaces are allowed to use about the same read.

Hindsight answers the same questions twice: once to a responder at the console
and once to an agent over MCP. The two surfaces had each grown their own
vocabulary for the same two facts — what the graph proves, and what a capped
read left unread — and that drift is not cosmetic here.

The evidence label had drifted in *value*: the console emitted
``evidence: "RESOLVED"`` and the MCP tools emitted ``evidence: "resolved"``.
One graph, one kind of evidence, two wire values, and any consumer keying on
the string sees two. Nothing rejected the mismatch because nothing owned the
constant.

The truncation vocabulary had drifted in *coverage*: the console learned to say
that a capped read makes every count a floor and every absence unverified, and
the MCP surface said it in one place, about raw Cypher, and nowhere on the
canned tools whose whole output is counts. That asymmetry is the dangerous
direction. A responder reading a truncated console page sees the caveat next to
the number; an agent reading a truncated tool result sees a bare integer, and
relays it as a total to the same responder.

So the vocabulary lives here, in core, beside :mod:`hindsight.coverage`. This
module imports neither surface and both surfaces import it, which makes the
parity a property of the protocol rather than a convention two modules are
trusted to keep. :func:`tests.unit.test_web_analysis` asserts the two emitted
evidence values are equal, so the drift cannot come back silently.

Three axes, deliberately separate and never collapsed into one flag:

* **evidence** — what the graph can prove at all (:data:`EVIDENCE`), which is
  lockfile resolution and nothing more;
* **completeness** — whether the read hit the row cap, in which case every
  count of matches seen is a floor and every verdict resting on an absence —
  the absences themselves included — is unverified;
* **coverage** — whether the dataset held anything for an answer to be absent
  *from*, which is :mod:`hindsight.coverage`'s job and not this module's.

Truncation means *we saw some of the graph*; absent coverage means *we saw none
of it*. Both hand back empty result sets, neither is a negative, and they call
for different sentences — so they stay apart everywhere below.
"""

from __future__ import annotations

#: What the graph can prove. There is exactly one value, it is spelled out on
#: every answer from either surface, and it is lowercase on purpose: the console
#: also emits an uppercase *status* taxonomy (``EXPOSED`` / ``RESOLVED_CLEAN`` /
#: ``NOT_RESOLVED``) and an uppercase ``RESOLVED`` beside those reads as a
#: fourth status rather than as an answer to a different question. Evidence is
#: not a verdict about a repository; it is the kind of fact the verdict rests
#: on, so it is spelled unlike one.
EVIDENCE = "resolved"

#: What a read that hit the row cap did to the numbers under it, in one
#: sentence, and it draws the distinction a reader will not draw for themselves:
#: a count of *matches seen* is a floor, because an omitted row can only add to
#: it, while a verdict that rests on a row being *absent* is not a floor at all
#: and a complete read can only take repositories out of it. A security answer
#: that says "0 other repositories" when the result set was cut off is worse
#: than one that refuses to answer, so this string travels with the flag on both
#: surfaces and neither is allowed to paraphrase it.
TRUNCATION_NOTE = (
    "This read hit the row cap, so the result is incomplete: every count of "
    "matches it returned is a lower bound, not a total, and any verdict that "
    "rests on a row being absent is unverified. Narrow the question — a single "
    "package, a single repository, a single instant — before drawing any "
    "conclusion from it, and in particular do not read a zero here as an absence."
)

#: The other half of a capped read, and the half that is easy to forget: not
#: only are the counts short, the *list* is short, so a name's absence from it
#: is a fact about the page rather than about the graph.
UNVERIFIED_ABSENCE_NOTE = (
    "Absence from the list above is unverified, not a negative: this read was "
    "cut at the row cap, so anything that does not appear here may simply be on "
    "a page that was never read. Do not report a missing repository, package or "
    "version as unaffected until the question is narrow enough to come back "
    "complete."
)

#: Maintainer reach under truncation. Worth its own sentence because the number
#: this tool returns is reassuring when it is small, which is exactly the shape
#: a truncated read produces by accident.
REACH_FLOOR_NOTE = (
    "The ownership or reach read hit the row cap, so every number above is a "
    "floor: this account may maintain more packages and touch more repositories "
    "than are listed. A package or repository missing from these lists was never "
    "checked and is not proven absent, so a small reach here is not evidence of "
    "a small trust radius."
)

#: The raw-Cypher passthrough returns whatever the engine returned. That is the
#: point of the tool and it is also its hazard: none of the classification the
#: canned tools apply has happened, so an agent must not read the rows as though
#: it had.
RAW_READ_CAVEAT = (
    "These rows are a raw engine read of a statement this caller wrote. They "
    "carry no evidence label and no coverage verdict: nothing has checked "
    "whether this dataset holds any repositories or any ingested history, so an "
    "empty result here is not a negative and a count here is only a count of "
    "what this statement matched. Use the canned tools when the answer needs to "
    "be trusted as a verdict."
)


def cypher_truncation_note(row_cap: int) -> str:
    """The shared truncation sentence, plus what to do about it in raw Cypher.

    The canned tools can only tell an agent to ask a narrower question; a raw
    statement can be rewritten, so this adds the two rewrites that actually
    work. The shared sentence comes first so that the meaning is identical on
    both surfaces and only the remedy differs.
    """
    return (
        f"{TRUNCATION_NOTE} This statement was cut at the {row_cap}-row cap: "
        "anchor the pattern on a more specific id, or aggregate with count(*), "
        "rather than assuming these rows are the whole answer."
    )


def completeness(truncated: bool) -> dict:
    """The two fields every console answer that touched a paged read carries.

    Both keys are always present, ``truncation_note`` simply going ``None``,
    because the consumer is a browser rendering into a fixed slot: a key that
    disappears is a slot that keeps showing the previous answer's caveat.
    """
    return {
        "truncated": bool(truncated),
        "truncation_note": TRUNCATION_NOTE if truncated else None,
    }


def lower_bounds(
    truncated: bool,
    *,
    note: str | None = None,
    absence_note: str = UNVERIFIED_ABSENCE_NOTE,
) -> dict:
    """The fields an answer whose counts came from a capped read must carry.

    Sparse where :func:`completeness` is dense, and for the same reason read the
    other way round: the consumer is a language model reading a JSON blob as
    prose, and ``"truncation_note": null`` beside ``"counts_are_lower_bounds":
    false`` is an invitation to mention a truncation that did not happen. Absent
    keys say nothing; present keys say something true. It also keeps the
    untruncated response byte-identical to what agents already parse.
    """
    if not truncated:
        return {}
    return {
        "counts_are_lower_bounds": True,
        "truncation_note": note or TRUNCATION_NOTE,
        "absence_note": absence_note,
    }


__all__ = [
    "EVIDENCE",
    "RAW_READ_CAVEAT",
    "REACH_FLOOR_NOTE",
    "TRUNCATION_NOTE",
    "UNVERIFIED_ABSENCE_NOTE",
    "completeness",
    "cypher_truncation_note",
    "lower_bounds",
]
