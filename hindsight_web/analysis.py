"""Interval arithmetic, and the words the console is allowed to say.

The evidence this product has is exactly one thing: a committed lockfile in a
git repository resolved a package to an exact version over a half-open interval
of valid time. That is weaker than "was running" and much weaker than "was
compromised", and the difference is the entire credibility of the tool during an
incident. So the vocabulary is fixed here, in one module, rather than composed
ad hoc at each call site:

* every answer carries ``evidence = "RESOLVED"``;
* every answer carries :data:`CAVEAT` verbatim;
* no string in this file contains "deployed", "running", "in production",
  "affected" or "infected", and :func:`~tests.unit.test_web_analysis` asserts it.

The other half of the module is the negative. "We were not exposed" is the
answer a lockfile graph is uniquely able to *prove*, and an empty result set is
a terrible way to present a proof. :func:`classify` therefore returns, for a
repository that resolved a safe version, the version it held, the interval it
held it over, and how long before the first malicious publish that interval
started — which is the difference between "no rows" and "pinned to 5.6.0 four
days before the attack and untouched for three months after it".
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from hindsight.history import SENTINEL

#: Open intervals are stored as this sentinel because HydraDB has no IS NULL.
FAR_FUTURE = SENTINEL

#: The one kind of evidence in the graph. Rendered on every result.
EVIDENCE = "RESOLVED"

CAVEAT = (
    "Evidence is lockfile resolution only: a committed lockfile in this "
    "repository pinned this exact version over the stated interval. That is not "
    "proof the dependency was installed, built, executed or shipped, and it is "
    "not proof of compromise. Treat it as the scope to investigate."
)

MAINTAINER_CAVEAT = (
    "Maintainer edges are a present-tense snapshot of npm registry ownership, so "
    "this reads as: the packages this account maintains TODAY were resolved by "
    "these repositories at the stated instant. It is a trust-radius estimate for "
    "'if this account were phished tomorrow', not a record of who held publish "
    "rights then."
)

#: Every count derived from a read that hit the row cap is a *floor*, and has to
#: read as one. A security console that answers "0 other repositories affected"
#: when the result set was cut off is worse than one that refuses to answer, so
#: this string travels with the flag and the UI renders both.
TRUNCATION_CAVEAT = (
    "This read hit the row cap, so the result is incomplete and every count "
    "below is a lower bound, not a total. Narrow the question — a single "
    "package, a single repository, a single instant — before drawing any "
    "conclusion from it, and in particular do not read a zero here as an absence."
)

SYNTHETIC_CAVEAT = (
    "This repository is a constructed example, not a real git history. It exists "
    "because none of the real repositories in this dataset regenerated a lockfile "
    "inside the exposure window, so a true positive has to be built to be shown. "
    "Its lockfile timeline is fabricated; the package versions and publish "
    "timestamps it references are real."
)

#: Classification of one repository against one package at one instant.
EXPOSED = "EXPOSED"
RESOLVED_CLEAN = "RESOLVED_CLEAN"
NOT_RESOLVED = "NOT_RESOLVED"

STATUS_ORDER = {EXPOSED: 0, RESOLVED_CLEAN: 1, NOT_RESOLVED: 2}


class TimestampError(ValueError):
    """A timestamp argument could not be interpreted."""


def iso(ts: int | None) -> str | None:
    """UTC ISO-8601 for a unix second; ``None`` for an open upper bound."""
    if ts is None or int(ts) >= FAR_FUTURE:
        return None
    return (
        datetime.fromtimestamp(int(ts), UTC).isoformat().replace("+00:00", "Z")
    )


def to_epoch(value: object, *, field_name: str = "timestamp") -> int:
    """Accept unix seconds or ISO-8601 and return unix seconds.

    The scrubber sends integers; humans and the docs use
    ``2025-09-08T14:05:00Z``. Rejecting either form would be a papercut in a
    tool whose whole interface is a timestamp.
    """
    if isinstance(value, bool):
        raise TimestampError(f"{field_name} must be unix seconds or an ISO-8601 string")
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise TimestampError(f"{field_name} is empty")
        if text.lstrip("-").isdigit():
            return int(text)
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError as exc:
            raise TimestampError(
                f"{field_name}={value!r} is neither unix seconds nor ISO-8601: {exc}"
            ) from None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return int(parsed.timestamp())
    raise TimestampError(f"{field_name} must be unix seconds or an ISO-8601 string")


def humanize(seconds: int | float | None) -> str | None:
    """A duration a responder can read at a glance: ``4 d 1 h``, ``69 min``.

    Two units at most, largest first, and never more precision than the data
    supports — lockfile facts are commit-granular, so seconds are noise above a
    minute.
    """
    if seconds is None:
        return None
    total = int(abs(seconds))
    if total < 60:
        return f"{total} s"
    if total < 5400:  # under 90 minutes, minutes read better than "1 h 5 m"
        return f"{total // 60} min"
    days, rest = divmod(total, 86400)
    hours, rest = divmod(rest, 3600)
    minutes = rest // 60
    if days:
        return f"{days} d {hours} h" if hours else f"{days} d"
    return f"{hours} h {minutes} min" if minutes else f"{hours} h"


def describe_interval(valid_from: object, valid_to: object) -> dict:
    """Interval bounds in both machine and human form, plus how long it held."""
    start = int(valid_from) if isinstance(valid_from, int) else None
    end = int(valid_to) if isinstance(valid_to, int) else None
    open_interval = end is not None and end >= FAR_FUTURE
    held = None
    if start is not None and end is not None and not open_interval:
        held = max(0, end - start)
    return {
        "valid_from": start,
        "valid_to": end,
        "valid_from_iso": iso(start),
        "valid_to_iso": iso(end),
        "open_interval": open_interval,
        "held_seconds": held,
        "held_for": humanize(held),
    }


def covers(valid_from: int | None, valid_to: int | None, start: int, end: int) -> bool:
    """Did a half-open interval hold across the whole of ``[start, end)``?"""
    if valid_from is None or valid_to is None:
        return False
    return valid_from <= start and valid_to >= end


@dataclass(frozen=True)
class Window:
    """The incident's practical exposure window, in unix seconds."""

    start: int
    end: int
    first_publish: int

    def contains(self, at: int) -> bool:
        return self.start <= at < self.end

    def as_dict(self) -> dict:
        return {
            "start": self.start,
            "end": self.end,
            "start_iso": iso(self.start),
            "end_iso": iso(self.end),
            "first_malicious_publish": self.first_publish,
            "first_malicious_publish_iso": iso(self.first_publish),
            "duration": humanize(self.end - self.start),
        }


def _lead_time_note(resolutions: list[dict], window: Window) -> str:
    """How far ahead of the attack the surviving pin was last regenerated."""
    starts = [
        r["valid_from"]
        for r in resolutions
        if isinstance(r.get("valid_from"), int) and r["valid_from"] <= window.first_publish
    ]
    if not starts:
        return ""
    newest = max(starts)
    return (
        f"that pin was already {humanize(window.first_publish - newest)} old when "
        "the first malicious version was published"
    )


def classify(
    slug: str,
    resolutions: list[dict],
    malicious_versions: set[str],
    window: Window,
    at: int,
) -> dict:
    """Classify one repository against one package at one instant.

    ``resolutions`` is every ``(version, interval)`` the graph returned for this
    repository — plural on purpose, because a lockfile carries the full
    transitive closure and the same package routinely appears at several versions
    at once. Exposure is *any* of them matching a malicious version; safety is
    all of them not matching.

    The returned ``basis`` is the sentence the UI prints under the row. It is
    written here rather than in JavaScript so that the API, the tests and the
    screen cannot drift apart.
    """
    versions = []
    for row in resolutions:
        version = str(row.get("version"))
        interval = describe_interval(row.get("valid_from"), row.get("valid_to"))
        versions.append(
            {"version": version, "malicious": version in malicious_versions, **interval}
        )
    versions.sort(key=lambda v: (not v["malicious"], v["version"]))

    hits = [v for v in versions if v["malicious"]]
    if hits:
        spans = ", ".join(
            f"{v['version']} from {v['valid_from_iso']} "
            f"{'(still open)' if v['open_interval'] else 'to ' + str(v['valid_to_iso'])}"
            for v in hits
        )
        return {
            "slug": slug,
            "status": EXPOSED,
            "versions": versions,
            "matched_versions": [v["version"] for v in hits],
            "basis": (
                f"lockfile resolved {spans}; this instant falls inside that interval"
            ),
        }

    if not versions:
        return {
            "slug": slug,
            "status": NOT_RESOLVED,
            "versions": [],
            "matched_versions": [],
            "basis": (
                "no committed lockfile in this repository resolved this package at "
                "this instant — the package is not in its dependency closure here"
            ),
        }

    held = [v for v in versions if covers(v["valid_from"], v["valid_to"], window.start, window.end)]
    pins = ", ".join(v["version"] for v in versions)
    if held:
        note = _lead_time_note(versions, window)
        tail = f"; {note}" if note else ""
        return {
            "slug": slug,
            "status": RESOLVED_CLEAN,
            "versions": versions,
            "matched_versions": [],
            "basis": (
                f"lockfile pinned {', '.join(v['version'] for v in held)} across the "
                f"entire {humanize(window.end - window.start)} exposure window and "
                f"none of those versions is a malicious one{tail}"
            ),
        }
    return {
        "slug": slug,
        "status": RESOLVED_CLEAN,
        "versions": versions,
        "matched_versions": [],
        "basis": (
            f"lockfile resolved {pins} at this instant; no malicious version of this "
            "package appears, though the pin did change at some point inside the "
            "exposure window — scrub the window to see when"
        ),
    }


def summarize(repos: list[dict]) -> dict:
    """Headline counts. The order is the order the UI shows them in."""
    counts = {EXPOSED: 0, RESOLVED_CLEAN: 0, NOT_RESOLVED: 0}
    for repo in repos:
        counts[repo["status"]] = counts.get(repo["status"], 0) + 1
    return {
        "repos": len(repos),
        "exposed": counts[EXPOSED],
        "resolved_clean": counts[RESOLVED_CLEAN],
        "not_resolved": counts[NOT_RESOLVED],
    }


def sort_key(repo: dict) -> tuple:
    """Exposed first, then repos that carry the package, then the rest."""
    return (STATUS_ORDER.get(repo["status"], 9), str(repo.get("slug")))


def completeness(truncated: bool) -> dict:
    """The two fields every answer that touched a paged read must carry.

    A single helper rather than a literal at each call site, because the failure
    this guards against is *forgetting* — the flag existed and was simply dropped
    on the way out of three methods, and a partial answer then rendered as a
    complete one.
    """
    return {
        "truncated": bool(truncated),
        "truncation_note": TRUNCATION_CAVEAT if truncated else None,
    }


__all__ = [
    "CAVEAT",
    "EVIDENCE",
    "EXPOSED",
    "FAR_FUTURE",
    "MAINTAINER_CAVEAT",
    "NOT_RESOLVED",
    "RESOLVED_CLEAN",
    "SYNTHETIC_CAVEAT",
    "TRUNCATION_CAVEAT",
    "TimestampError",
    "Window",
    "classify",
    "completeness",
    "covers",
    "describe_interval",
    "humanize",
    "iso",
    "sort_key",
    "summarize",
    "to_epoch",
]
