"""One exposure read, turned into an artifact somebody else can check.

The console answers "which repositories resolved package P at instant T" on a
screen. The deliverable after an incident is not that screen. It is a document
that carries the question, the answer, the receipts under the answer, the
authority for the word "malicious", and - the part a screenshot structurally
cannot carry - a statement of its own coverage: what this read proves, what a
capped read left unread, and whether the dataset held anything for the answer to
be absent from. A regulator, an auditor or the next responder reads the artifact
weeks later with no access to the console and no way to re-run the query.

So this module composes a packet from payloads that already exist, and it is
deliberately a pure function of them. Nothing here reaches the network, reads a
clock or opens a file: :func:`build_finding` takes the exposure payload, the
incident file's own dict, and optionally the health payload, and returns JSON.
That is what lets the packet be tested against a truncated read, an unanswerable
dataset and a missing health probe without a database, and it is why the packet
cannot drift from the screen - both are shaped from the same
:meth:`hindsight_web.service.Console.exposure` dict.

Three rules the composition follows, in the order they matter:

**Nothing is paraphrased.** The caveat, the truncation note and the coverage
note travel verbatim from the payloads that own them. This module states no
honesty sentence of its own that
:mod:`hindsight.envelope` or :mod:`hindsight.coverage` already states, because a
second wording of the same caveat is a second caveat, and the two will differ.

**A count that cannot be a total is not presented as one.** Every count in the
packet carries an explicit ``basis`` of ``exact``, ``floor`` or ``observed``,
decided by the exposure payload's own truncation flag and by what a cut read
does to that particular count, so a consumer reading the JSON cannot pick up the
number without picking up its qualifier. A cut read bounds the exposed count and
the repository total from below and does the opposite to the two negatives,
which it can only have overstated. When the dataset could not
answer at all there are no counts in the packet: not zeros, not floors, not a
null - the block says why instead, because three zeros are the shape of a clean
estate and an empty dataset must never be able to render as one.

**The packet names what it does not establish.** :data:`NOT_INCLUDED` is the
roadmap, stated inside the artifact rather than in a sales deck. A finding that
does not name its own gaps invites the reader to fill them in, and the gaps a
reader assumes closed are exactly the three below: runtime execution, resolution
ambiguity, and a signature over these bytes.

:func:`render_markdown` is the same dict as a document, and it is ASCII only.
Prose written elsewhere in this repository uses em dashes; a finding gets pasted
into incident reports, ticket bodies and test fixtures, greps run over it, and a
byte that renders differently in five places is not what an evidence artifact
should be made of. :func:`ascii_only` folds the punctuation rather than dropping
it, and anything it does not know survives as a visible escape rather than
vanishing.
"""

from __future__ import annotations

from hindsight.envelope import EVIDENCE, TRUNCATION_NOTE, UNVERIFIED_ABSENCE_NOTE

from .analysis import CAVEAT, iso

#: What kind of document this is, on the document. A JSON blob found on a shared
#: drive two years from now has to be able to say what it is without its URL.
ARTIFACT_KIND = "hindsight-evidence-packet"
ARTIFACT_VERSION = 1

#: The one sentence the packet says about itself, and it is assembled out of the
#: three axes :mod:`hindsight.envelope` keeps apart rather than out of a fourth
#: description of them. Evidence, completeness and coverage are separate
#: questions with separate answers, and collapsing them into a single
#: "confidence" is the failure this whole product is arranged against.
SCOPE_STATEMENT = (
    "This packet states what the graph proves and what it cannot, on three axes "
    "that are deliberately separate and never collapsed into one flag. "
    "Evidence: what the graph can prove at all, which is lockfile resolution "
    "and nothing more. Completeness: whether the read hit the row cap; when it "
    "did, the exposed count and the repository total are floors, and every "
    "negative - a clean classification or an absence - is unverified rather "
    "than proven. Coverage: whether the dataset held anything for an answer to "
    "be absent from. Truncation means we saw some of the graph; absent coverage "
    "means we saw none of it. Both hand back empty result sets, neither is a "
    "negative, and they call for different sentences."
)

#: Where "malicious" comes from, said on the artifact. The graph knows which
#: versions were resolved and nothing else; the incident file below is the only
#: authority in this document for which of them was poisoned, and it makes that
#: claim on its own sources rather than on anything Hindsight verified.
AUTHORITY_NOTE = (
    "Maliciousness is not inferred from the graph. A version is malicious here "
    "because the incident file identified in this section says so, on the "
    "authority of the sources it lists. The graph contributes only which "
    "versions were resolved, by which repositories, over which intervals of "
    "valid time."
)

#: Stated when the packet was composed without a dataset probe. An absent
#: provenance block must read as absent, never as a claim that there was nothing
#: to record: the label namespace is the single field that decides whether the
#: answer above is about the dataset the reader thinks it is about.
DATASET_FACTS_UNAVAILABLE = (
    "Dataset facts unavailable: this packet was generated without a health "
    "read, so the endpoint, the label namespace and the node counts behind the "
    "answer above are not recorded here. That is a gap in this document, not a "
    "statement about the dataset, and it means a reader cannot confirm from "
    "this packet alone which dataset was queried."
)

#: Stated when the dataset probe ran and failed. A failed probe hands back the
#: zeros its own failure is shaped like, and a zero repository count serialised
#: as a dataset fact is the empty-dataset lie one layer further out: the
#: measured fields are dropped and this sentence stands in their place.
HEALTH_PROBE_FAILED = (
    "The dataset probe failed while this packet was generated, so node counts "
    "are not recorded here. The identity fields above are configuration, not "
    "measurements; a reader cannot confirm from this packet how many "
    "repositories the dataset held."
)

#: How the packet relates to the screen it was exported from. The console paints
#: an answer and then holds it; this document is composed from its own read at
#: the moment the export was asked for, so the two can differ and the packet is
#: the later of them.
FRESHNESS_NOTE = (
    "Composed from a fresh read at generation time. If the estate's record "
    "changed after the console screen this was exported from was painted, this "
    "packet is the more current of the two."
)

#: What a reader would otherwise assume this document closes. These are the
#: documented roadmap, and naming them here is the point: the three assumptions
#: below are precisely the ones a finding invites when it does not disclaim
#: them, and each of them would change what a responder does next.
NOT_INCLUDED = (
    {
        "claim": "runtime execution",
        "statement": (
            "This packet does not establish that the resolved dependency was "
            "installed, built, executed or shipped. The evidence is a committed "
            "lockfile in a git repository; nothing here observed a running "
            "system, a build artifact or a deployment."
        ),
    },
    {
        "claim": "resolution ambiguity",
        "statement": (
            "This packet does not classify whether each repository's install "
            "was lockfile-authoritative or resolved inside a declared range at "
            "build time. 'npm ci' installs the lockfile exactly; 'npm install' "
            "can re-resolve inside a declared range when the lockfile is "
            "missing, stale or out of sync with the manifest, and no CI run "
            "history is joined here to tell them apart. A repository reported "
            "as not resolving a malicious version at this instant may still "
            "have resolved one in a build this graph never saw."
        ),
    },
    {
        "claim": "cryptographic signature",
        "statement": (
            "This packet is not signed and is not tamper-evident. A reader is "
            "trusting the channel it arrived over and the operator who "
            "generated it, not a signature over these bytes, and any field in "
            "it can be edited without leaving a trace."
        ),
    },
)

#: The headline counts, in the order the console states them: the finding first,
#: then the two negatives, then the denominator that makes any of them mean
#: something. "1 repository" could be 1 of 9 or 1 of 900.
COUNT_ORDER = ("exposed", "resolved_clean", "not_resolved", "repos")

#: The counts a cut read still bounds from below, and the only ones. A row that
#: fell past the cap can add an exposure and can add a repository, so those two
#: numbers can only rise on a complete read. The two negatives cannot: a
#: repository whose malicious row was the one cut is counted clean or absent
#: here and would move out of that class on a complete read, so they are
#: observations of what came back rather than floors under anything.
FLOOR_COUNTS = ("exposed", "repos")

#: Said on a cut read, next to the counts it is about. The distinction the
#: sentence draws is the one a reader will otherwise not draw for themselves:
#: "floor" reads as "at least this bad" and would quietly attach to the two
#: numbers that a complete read can only shrink.
RECLASSIFICATION_NOTE = (
    "Resolved-clean and not-resolved are classifications of what a truncated "
    "read returned: a repository counted clean or absent here may prove exposed "
    "on a complete read. Only the exposed count and the repository total are "
    "floors."
)

#: Spelled out rather than title-cased from the key, because these are the
#: claims the packet is making and a reader should not have to expand
#: "resolved_clean" into one. Note that none of them says "clean": what was
#: measured is that a repository did not resolve a malicious version of one
#: package at one instant.
COUNT_LABEL = {
    "exposed": "Resolved a malicious version",
    "resolved_clean": "Resolved this package, no malicious version",
    "not_resolved": "Did not resolve this package",
    "repos": "Repositories accounted for",
}

#: Per-repository fields carried into the receipts, when the payload has them.
#: A fixed allowlist rather than the whole row, so that a field added upstream
#: reaches the packet only when somebody decides it is evidence; and copied only
#: when present, so the packet never invents a key the read did not produce.
RECEIPT_FIELDS = (
    "slug",
    "name",
    "service",
    "status",
    "matched_versions",
    "versions",
    "basis",
    "provenance",
    "origin",
    "synthetic",
    "synthetic_note",
)

#: Attached to every non-exposed row of a cut read. The table is the part of the
#: packet a reader quotes one line out of, and a row reading "NOT_RESOLVED" out
#: of context is a proven negative unless the qualifier travels on the row
#: itself. The exposed rows need no such caveat: a row that came back is a row
#: that was found, and no omitted row can unfind it.
RECEIPT_TRUNCATION_CAVEAT = (
    "verdict from a truncated read: an omitted row may contradict this status"
)

#: Dataset facts carried out of the health payload, same rule as the receipts.
DATASET_FIELDS = (
    "reachable",
    "endpoint",
    "namespace",
    "cell",
    "labels",
    "repo_count",
    "ingested_repo_count",
    "synthetic_repo_count",
    "unwatermarked_repos",
    "resolves_edges",
    "incident",
)

#: The subset of the above that a probe knows without reaching the node. These
#: are configuration read out of this process, so they survive a failed probe;
#: every field not listed here is a measurement, and a failed probe reports
#: those as zeros that are the shape of the failure rather than of the dataset.
DATASET_IDENTITY_FIELDS = (
    "reachable",
    "endpoint",
    "namespace",
    "cell",
    "labels",
    "incident",
)

#: Punctuation this repository's prose uses that ASCII does not have. Folded
#: rather than stripped: an em dash carries a clause boundary and deleting it
#: would change the sentence, so it becomes the separator a reader would have
#: typed instead.
_FOLD = {
    "—": " - ",
    "–": " - ",
    "‘": "'",
    "’": "'",
    "“": '"',
    "”": '"',
    "…": "...",
    "≥": ">=",
    "≤": "<=",
    "·": "-",
    " ": " ",
}


def ascii_only(text: object) -> str:
    """Fold this repository's punctuation into ASCII, losing nothing silently.

    Anything outside :data:`_FOLD` that is still not ASCII survives as its
    escape rather than being dropped. A repository slug is not allowed to lose
    a letter on its way into an evidence document, and a visible ``\\u00e9`` is
    an honest rendering of a byte this function could not carry.
    """
    out = str("" if text is None else text)
    for bad, good in _FOLD.items():
        out = out.replace(bad, good)
    # A value is one line. Package names and repository slugs arrive off a query
    # string, and a newline inside one would open a markdown block of its own in
    # the middle of a table cell or a bullet, so the three characters that carry
    # document structure become the space a reader would have typed.
    out = out.replace("\r\n", " ")
    for structural in ("\r", "\n", "\t"):
        out = out.replace(structural, " ")
    # Collapse the spacing an em-dash fold can double up, so the sentence reads
    # as one a person wrote rather than as one a filter passed over.
    out = out.replace(" -  ", " - ").replace("  - ", " - ")
    return out.encode("ascii", "backslashreplace").decode("ascii")


def _present(source: dict, fields) -> dict:
    """Copy the fields this payload actually has, in a fixed order."""
    return {key: source[key] for key in fields if key in source}


def _total(counts: dict) -> int:
    """Every repository the read accounted for, exposed or not."""
    return sum(
        int(counts.get(key) or 0)
        for key in ("exposed", "resolved_clean", "not_resolved")
    )


def _floor(value: object, truncated: bool) -> str:
    """A number as the packet prints it, with the qualifier attached to it."""
    return (">= " if truncated else "") + str(int(value or 0))


def _basis(key: str, truncated: bool) -> str:
    """What kind of number this count is, given how complete the read was."""
    if not truncated:
        return "exact"
    return "floor" if key in FLOOR_COUNTS else "observed"


def _refusal_cause(exposure: dict) -> str:
    """Why nothing was measured, as a clause that finishes "no answer for X"."""
    reason = exposure.get("unanswerable_reason")
    if reason == "empty_dataset":
        return "this dataset contains no repositories, so nothing was checked"
    if reason == "no_ingested_history":
        return (
            "no repository here has ingested lockfile history, so nothing was "
            "checked"
        )
    return "this dataset could not be read, so nothing was checked"


def _headline(exposure: dict, package: str) -> str:
    """The sentence the console's answer line states, as one string.

    Written here rather than lifted off the DOM because the packet is generated
    server-side and there is no DOM, and kept branch-for-branch identical to
    ``renderAnswer`` in ``static/app.js`` for the reason every other duplicated
    string in this repository is centralised: an artifact that disagrees with
    the screen it was exported from is worse than no artifact.
    """
    if exposure.get("answerable") is False:
        return "No answer for " + package + ": " + _refusal_cause(exposure)

    counts = exposure.get("counts") or {}
    truncated = bool(exposure.get("truncated"))
    hits = int(counts.get("exposed") or 0)
    total = _total(counts)

    if hits > 0:
        noun = "repository" if (total or hits) == 1 else "repositories"
        head = _floor(hits, truncated)
        if total > 0:
            head += " of " + _floor(total, truncated)
        return head + " " + noun + " resolved a malicious " + package + " version"
    if truncated:
        return (
            "No malicious " + package + " version found before this read was cut off"
        )
    if not exposure.get("package_in_graph"):
        return package + " is not resolved by any repository in this graph"
    if total > 0:
        noun = "repository" if total == 1 else "repositories"
        return (
            "None of " + str(total) + " " + noun + " resolved a malicious "
            + package + " version"
        )
    return "No repository resolved a malicious " + package + " version"


def _question(exposure: dict, package: str, at: int) -> dict:
    """What was asked, and what the word "exposure" is allowed to mean here."""
    return {
        "package": package,
        "at": int(at),
        "at_iso": iso(at),
        "asked": exposure.get("question"),
        # Verbatim. This is the sentence that keeps every number below from
        # being read as a claim about a running system.
        "exposure_means": exposure.get("caveat") or CAVEAT,
        "in_exposure_window": exposure.get("in_exposure_window"),
    }


def _answer(exposure: dict, package: str) -> dict:
    """The headline facts, or the reason there are none.

    The two shapes are different on purpose. An answerable read produces counts,
    each carrying its own ``basis``; an unanswerable one produces no ``counts``
    key at all, because a consumer that finds the key will use the number in it
    and no amount of accompanying prose reliably stops that.

    ``truncated`` says how the read ended and nothing more. What that does to
    each number is on the number, in its ``basis``, because a cut read does not
    do the same thing to all four of them.
    """
    truncated = bool(exposure.get("truncated"))
    out: dict = {
        "answerable": exposure.get("answerable") is not False,
        "headline": _headline(exposure, package),
        "truncated": truncated,
    }

    if exposure.get("answerable") is False:
        out["counts_withheld"] = True
        out["unanswerable_reason"] = exposure.get("unanswerable_reason")
        # Verbatim, and the only explanation this block carries: the counts are
        # not zero here, they were never measured.
        out["coverage_note"] = exposure.get("unanswerable_note")
        out["counts_withheld_because"] = (
            "This dataset could not answer the question, so this packet states "
            "no counts. Zeros here would be the size of an empty dataset rather "
            "than a result, and would render identically to a clean estate."
        )
        return out

    counts = exposure.get("counts") or {}
    out["counts"] = {
        key: {
            "value": int(counts.get(key) or 0),
            "basis": _basis(key, truncated),
            "label": COUNT_LABEL[key],
        }
        for key in COUNT_ORDER
        if key in counts
    }
    out["package_in_graph"] = exposure.get("package_in_graph")
    if truncated:
        # Verbatim from hindsight.envelope, which both surfaces import, so the
        # packet says about the row cap exactly what the console and the agent
        # say about it.
        out["truncation_note"] = exposure.get("truncation_note") or TRUNCATION_NOTE
        out["absence_note"] = UNVERIFIED_ABSENCE_NOTE
        out["reclassification_note"] = RECLASSIFICATION_NOTE
    if exposure.get("note"):
        out["note"] = exposure["note"]
    return out


def _receipts(exposure: dict) -> list[dict]:
    """Per-repository rows, exactly as the read produced them.

    Two payloads produce no receipts here. An unanswerable read produces none
    because a verdict drawn from a dataset that could not answer is not a
    verdict: the payload may still carry rows, and the console refuses to draw
    them for the same reason. A read that returned nothing produces none because
    there was nothing to return.

    A truncated read produces all of them, each negative one carrying the
    qualifier its own status needs. The row is what gets quoted out of the
    packet, so the caveat travels on the row rather than only above the table.
    """
    if exposure.get("answerable") is False:
        return []

    truncated = bool(exposure.get("truncated"))
    out = []
    for repo in exposure.get("repos") or []:
        receipt = _present(repo, RECEIPT_FIELDS)
        if truncated and receipt.get("status") != "EXPOSED":
            receipt["truncation_caveat"] = RECEIPT_TRUNCATION_CAVEAT
        out.append(receipt)
    return out


def _authority(incident_payload: dict, exposure: dict, package: str) -> dict:
    """The incident file's identity, and its verdict on this package."""
    window = dict(incident_payload.get("window") or {})
    for optional in ("note", "remediation_note"):
        # Present-but-empty is the shape ``Incident.as_dict`` produces for a
        # file that made no such qualification. An empty string in an evidence
        # document reads as a qualification that got lost, so it is dropped.
        if not window.get(optional):
            window.pop(optional, None)

    versions = [
        entry
        for entry in incident_payload.get("versions") or []
        if entry.get("package") == package
    ]
    return {
        "incident": incident_payload.get("title"),
        "date": incident_payload.get("date"),
        "root_cause": incident_payload.get("root_cause"),
        "payload": incident_payload.get("payload"),
        "sources": list(incident_payload.get("sources") or []),
        "window": window,
        "malicious_versions": list(exposure.get("malicious_versions") or []),
        "malicious_version_records": versions,
        "authority_note": AUTHORITY_NOTE,
    }


def _provenance(
    exposure: dict, health: dict | None, *, generated_at: int, permalink: str
) -> dict:
    """When this was generated, how to re-ask it, and against what.

    A probe that ran and failed is a third state, and it is the one that has to
    be handled explicitly: ``health`` is a dict either way, so a failed probe
    reaching :func:`_present` unexamined would serialise its zeros as though
    somebody had counted them.
    """
    out: dict = {
        "generated_at": int(generated_at),
        "generated_at_iso": iso(generated_at),
        "permalink": permalink,
        "query_elapsed_ms": exposure.get("elapsed_ms"),
        "freshness": FRESHNESS_NOTE,
        "dataset_facts_available": health is not None,
    }
    if health is None:
        out["dataset"] = None
        out["dataset_facts_note"] = DATASET_FACTS_UNAVAILABLE
    elif health.get("reachable") is False:
        out["dataset_facts_available"] = False
        out["dataset"] = _present(health, DATASET_IDENTITY_FIELDS)
        out["probe_error"] = health.get("error")
        out["dataset_facts_note"] = HEALTH_PROBE_FAILED
    else:
        out["dataset"] = _present(health, DATASET_FIELDS)
    return out


def _envelope(exposure: dict) -> dict:
    """The three axes, each answered from the payload that owns it."""
    truncated = bool(exposure.get("truncated"))
    coverage = exposure.get("coverage") or {}
    return {
        "evidence": exposure.get("evidence") or EVIDENCE,
        "evidence_means": exposure.get("caveat") or CAVEAT,
        "completeness": {
            "truncated": truncated,
            "note": exposure.get("truncation_note") if truncated else None,
            "absence_note": UNVERIFIED_ABSENCE_NOTE if truncated else None,
        },
        "coverage": {
            "answerable": exposure.get("answerable") is not False,
            "reason": exposure.get("unanswerable_reason"),
            "note": exposure.get("unanswerable_note"),
            "repo_count": coverage.get("repo_count"),
            "ingested_repo_count": coverage.get("ingested_repo_count"),
        },
        "scope": SCOPE_STATEMENT,
    }


def build_finding(
    exposure: dict,
    incident_payload: dict,
    health: dict | None,
    *,
    package: str,
    at: int,
    generated_at: int,
    permalink: str,
) -> dict:
    """Compose the evidence packet for one exposure read.

    Pure: every fact in the result comes from an argument. ``health`` may be
    ``None``, which is the only degraded input this function accepts and which
    it reports rather than hides.

    The key order is the order the facts matter in, and it survives into the
    JSON body, because the first thing a reader sees should be the question
    rather than the machinery.
    """
    return {
        "artifact": {"kind": ARTIFACT_KIND, "version": ARTIFACT_VERSION},
        "question": _question(exposure, package, at),
        "answer": _answer(exposure, package),
        "receipts": _receipts(exposure),
        "authority": _authority(incident_payload, exposure, package),
        "provenance": _provenance(
            exposure, health, generated_at=generated_at, permalink=permalink
        ),
        "envelope": _envelope(exposure),
        "not_included": [dict(entry) for entry in NOT_INCLUDED],
    }


# ------------------------------------------------------------------- markdown


def _row(cells) -> str:
    # A pipe inside a value is content, not a column boundary. A repository slug
    # carrying one would otherwise add a column to its own row and shift every
    # cell after it under the wrong heading.
    return "| " + " | ".join(ascii_only(c).replace("|", "\\|") for c in cells) + " |"


def _bullet(label: str, value: object) -> str:
    return "- **" + ascii_only(label) + ":** " + _value(value)


def _value(value: object) -> str:
    """One field as prose, never as a Python repr.

    A list of repository slugs reaching an evidence document as
    ``['axios/axios']`` is a leak of the language this was written in, and a
    reader should not have to know which one that was.
    """
    if isinstance(value, (list, tuple)):
        return ", ".join(ascii_only(item) for item in value) if value else "none"
    if isinstance(value, bool):
        return "yes" if value else "no"
    return ascii_only(value)


def _interval(version: dict) -> str:
    """One resolution's interval, in the words the payload already carries."""
    start = version.get("valid_from_iso") or "unknown"
    if version.get("open_interval") or not version.get("valid_to_iso"):
        end = "still open"
    else:
        end = version["valid_to_iso"]
    held = version.get("held_for")
    span = str(start) + " to " + str(end)
    return span + (" (" + str(held) + ")" if held else "")


def _versions_cell(receipt: dict) -> str:
    versions = receipt.get("versions") or []
    if not versions:
        return "none"
    return "; ".join(
        str(v.get("version"))
        + (" [malicious]" if v.get("malicious") else "")
        + " " + _interval(v)
        for v in versions
    )


def render_markdown(finding: dict) -> str:
    """The same packet as a document somebody can paste into an incident report.

    Deterministic given the dict and ASCII only. Every string that reaches the
    output passes through :func:`ascii_only`, including the ones carried
    verbatim in the JSON: the JSON is the machine-readable record and keeps the
    bytes the source modules own, while this rendering is the one that gets
    pasted into a ticket, a report and a test fixture, and it is held to one
    encoding so that it greps the same everywhere.
    """
    question = finding.get("question") or {}
    answer = finding.get("answer") or {}
    authority = finding.get("authority") or {}
    provenance = finding.get("provenance") or {}
    envelope = finding.get("envelope") or {}

    package = str(question.get("package") or "")
    at_iso = str(question.get("at_iso") or question.get("at") or "")

    out: list[str] = []
    out.append("# Hindsight evidence packet: " + ascii_only(package)
               + " at " + ascii_only(at_iso))
    out.append("")
    # Bold rather than bare, because one branch of the headline opens with the
    # package name and the package name comes off a query string: a package
    # called "## anything" would mint a heading at the start of this line, and
    # emphasised text cannot become a block of its own.
    out.append("**" + ascii_only(answer.get("headline")) + "**")
    out.append("")

    out.append("## The question")
    out.append("")
    out.append(_bullet("Package", package))
    out.append(_bullet("Instant", at_iso + "  (unix " + str(question.get("at")) + ")"))
    if question.get("in_exposure_window") is not None:
        out.append(_bullet(
            "Inside the incident's exposure window",
            "yes" if question.get("in_exposure_window") else "no",
        ))
    if question.get("asked"):
        out.append(_bullet("Asked", question.get("asked")))
    out.append("")
    out.append(_bullet("What exposure means here", question.get("exposure_means")))
    out.append("")

    out.append("## The answer")
    out.append("")
    if answer.get("counts_withheld"):
        out.append("No counts are stated. " + ascii_only(
            answer.get("counts_withheld_because")))
        out.append("")
        if answer.get("coverage_note"):
            out.append(_bullet("Coverage", answer.get("coverage_note")))
            out.append("")
    else:
        counts = answer.get("counts") or {}
        out.append(_row(["Finding", "Count", "Basis"]))
        out.append(_row(["---", "---", "---"]))
        for key in COUNT_ORDER:
            entry = counts.get(key)
            if not entry:
                continue
            value = entry.get("value")
            basis = entry.get("basis")
            shown = (">= " if basis == "floor" else "") + str(value)
            out.append(_row([entry.get("label") or key, shown, basis]))
        out.append("")
        if answer.get("truncated"):
            # The reclassification note says this in the JSON; saying it twice
            # in the document would be two caveats a reader learns to skip.
            out.append(
                "The exposed count and the repository total are floors, not "
                "totals. The two negative classifications are as-observed and "
                "unverified: a complete read can only move repositories out of "
                "them into exposed."
            )
            out.append("")
            out.append(_bullet("Truncation", answer.get("truncation_note")))
            out.append(_bullet("Unverified absence", answer.get("absence_note")))
            out.append("")
        if answer.get("note"):
            out.append(_bullet("Note", answer.get("note")))
            out.append("")

    out.append("## Receipts")
    out.append("")
    receipts = finding.get("receipts") or []
    if not receipts:
        out.append("No repository rows accompany this answer.")
        out.append("")
    else:
        out.append(_row(["Repository", "Status", "Matched versions",
                         "Resolved versions and intervals", "Basis"]))
        out.append(_row(["---", "---", "---", "---", "---"]))
        for receipt in receipts:
            matched = receipt.get("matched_versions") or []
            out.append(_row([
                str(receipt.get("slug") or "")
                + (" (constructed example)" if receipt.get("synthetic") else ""),
                receipt.get("status") or "",
                ", ".join(str(m) for m in matched) if matched else "none",
                _versions_cell(receipt),
                receipt.get("basis") or "",
            ]))
        out.append("")
        if answer.get("truncated"):
            out.append(
                "This read hit the row cap: rows not marked exposed are "
                "as-observed, not proven - an omitted row may contradict them."
            )
            out.append("")
        # The rows are marked one by one in the table; the note itself is stated
        # once, because it is identical on every constructed repository and a
        # sentence repeated per row is a sentence nobody finishes.
        constructed = next(
            (r for r in receipts if r.get("synthetic") and r.get("synthetic_note")),
            None,
        )
        if constructed:
            out.append("Constructed example: "
                       + ascii_only(constructed.get("synthetic_note")))
            out.append("")

    out.append("## Authority for the word malicious")
    out.append("")
    out.append(_bullet("Incident", authority.get("incident")))
    if authority.get("date"):
        out.append(_bullet("Date", authority.get("date")))
    if authority.get("root_cause"):
        out.append(_bullet("Root cause", authority.get("root_cause")))
    if authority.get("payload"):
        out.append(_bullet("Payload", authority.get("payload")))
    versions = authority.get("malicious_versions") or []
    out.append(_bullet(
        "Malicious versions of " + package,
        ", ".join(str(v) for v in versions) if versions
        else "none listed for this package",
    ))
    window = authority.get("window") or {}
    if window:
        out.append(_bullet(
            "Exposure window",
            str(window.get("start_iso")) + " to " + str(window.get("end_iso"))
            + (" (" + str(window.get("duration")) + ")" if window.get("duration")
               else ""),
        ))
        if window.get("first_malicious_publish_iso"):
            out.append(_bullet("First malicious publish",
                               window.get("first_malicious_publish_iso")))
        if window.get("note"):
            out.append(_bullet("Window note", window.get("note")))
        if window.get("remediation_note"):
            out.append(_bullet("Remediation note", window.get("remediation_note")))
    out.append("")
    sources = authority.get("sources") or []
    if sources:
        out.append("**Sources the incident file cites:**")
        out.append("")
        for source in sources:
            out.append("- " + ascii_only(source))
        out.append("")
    out.append(ascii_only(authority.get("authority_note")))
    out.append("")

    out.append("## Provenance and reproducibility")
    out.append("")
    out.append(_bullet("Generated at", str(provenance.get("generated_at_iso"))
                       + "  (unix " + str(provenance.get("generated_at")) + ")"))
    out.append(_bullet("Permalink", provenance.get("permalink")))
    if provenance.get("query_elapsed_ms") is not None:
        out.append(_bullet("Exposure read latency",
                           str(provenance.get("query_elapsed_ms")) + " ms"))
    if provenance.get("freshness"):
        out.append(_bullet("Freshness", provenance.get("freshness")))
    dataset = provenance.get("dataset")
    if dataset:
        for key in DATASET_FIELDS:
            # ``None`` is "not measured" here, not a value: the edge count is
            # absent unless it was explicitly asked for, and an empty bullet
            # reads as a field that failed rather than one nobody requested.
            if key not in dataset or key == "labels" or dataset[key] is None:
                continue
            out.append(_bullet(key.replace("_", " "), dataset[key]))
        labels = dataset.get("labels") or {}
        if labels:
            out.append(_bullet("Label namespace", ", ".join(
                str(k) + "=" + str(labels[k]) for k in sorted(labels)
            )))
    if provenance.get("probe_error"):
        out.append(_bullet("Probe error", provenance.get("probe_error")))
    # Whenever the packet carries one, not only when the block is empty: a probe
    # that failed leaves identity fields standing above a note that says why the
    # measurements are not beside them.
    note = provenance.get("dataset_facts_note") or (
        None if dataset else DATASET_FACTS_UNAVAILABLE
    )
    if note:
        out.append("")
        out.append(ascii_only(note))
    out.append("")

    # The caveat itself is stated verbatim under "The question", where the claim
    # it qualifies is made. Repeating the whole paragraph here would train a
    # reader to skip it in both places, so this section carries the two axes
    # that the caveat does not: how complete the read was and whether the
    # dataset could answer at all.
    out.append("## What this packet states about itself")
    out.append("")
    out.append(_bullet("Evidence", envelope.get("evidence")))
    read = envelope.get("completeness") or {}
    seen = envelope.get("coverage") or {}
    out.append(_bullet("Read completeness", (
        "truncated at the row cap, so the exposed count is a floor and every "
        "negative above is unverified"
        if read.get("truncated")
        else "complete, no read hit the row cap"
    )))
    out.append(_bullet("Dataset coverage", (
        "answerable: " + str(seen.get("repo_count")) + " repositories, "
        + str(seen.get("ingested_repo_count")) + " with ingested history"
        if seen.get("answerable")
        else "not answerable (" + str(seen.get("reason")) + ")"
    )))
    out.append("")
    out.append(ascii_only(envelope.get("scope")))
    out.append("")

    out.append("## What this packet does not establish")
    out.append("")
    for entry in finding.get("not_included") or []:
        out.append("- **" + ascii_only(entry.get("claim")) + ".** "
                   + ascii_only(entry.get("statement")))
    out.append("")

    return "\n".join(out)


__all__ = [
    "ARTIFACT_KIND",
    "ARTIFACT_VERSION",
    "AUTHORITY_NOTE",
    "COUNT_LABEL",
    "COUNT_ORDER",
    "DATASET_FACTS_UNAVAILABLE",
    "DATASET_FIELDS",
    "DATASET_IDENTITY_FIELDS",
    "FLOOR_COUNTS",
    "FRESHNESS_NOTE",
    "HEALTH_PROBE_FAILED",
    "NOT_INCLUDED",
    "RECEIPT_FIELDS",
    "RECEIPT_TRUNCATION_CAVEAT",
    "RECLASSIFICATION_NOTE",
    "SCOPE_STATEMENT",
    "ascii_only",
    "build_finding",
    "render_markdown",
]
