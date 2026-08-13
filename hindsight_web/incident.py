"""The incident file -> a malicious-version index and a set of timeline markers.

``poc/incident-chalk-debug.json`` is the authority for what "malicious" means in
this console. Every publish timestamp in it was verified against the npm
registry's own ``time`` map (which survives unpublish), so the markers the
scrubber snaps to are real events with real seconds, not round numbers chosen to
look tidy.

The console never infers maliciousness from the graph. A version is malicious
because the incident file says so and because a named source says so; the graph
only knows which versions were resolved. Keeping those two facts in separate
places is what lets the answer be "resolved 5.6.0, which is not on the list"
rather than "looks fine".
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from .analysis import Window, humanize, iso

#: Repo-root-relative default. Overridable so a deployment can point elsewhere.
DEFAULT_INCIDENT_PATH = (
    Path(__file__).resolve().parent.parent / "poc" / "incident-chalk-debug.json"
)

#: The scrubber's default domain: the whole of the incident day, UTC.
DEFAULT_DOMAIN_START = int(datetime(2025, 9, 8, 0, 0, tzinfo=UTC).timestamp())
DEFAULT_DOMAIN_END = int(datetime(2025, 9, 9, 0, 0, tzinfo=UTC).timestamp())


class IncidentError(Exception):
    """The incident file is missing or unusable."""


def parse_iso(text: str, *, field_name: str) -> int:
    """``2025-09-08T13:12:10.343Z`` -> unix seconds, truncating sub-second parts.

    Truncation rather than rounding: the graph's valid-time axis is integer
    seconds from git commit times, and a marker that rounded *up* past a commit
    would put the scrubber on the wrong side of a version swap.
    """
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise IncidentError(f"{field_name}={text!r} is not ISO-8601: {exc}") from None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return int(parsed.timestamp())


@dataclass(frozen=True)
class MaliciousVersion:
    package: str
    version: str
    wave: int
    published_at: int
    remediated_version: str | None = None
    remediated_at: int | None = None
    still_present_in_registry: bool = False

    def as_dict(self) -> dict:
        return {
            "package": self.package,
            "version": self.version,
            "key": f"{self.package}@{self.version}",
            "wave": self.wave,
            "published_at": self.published_at,
            "published_at_iso": iso(self.published_at),
            "remediated_version": self.remediated_version,
            "remediated_at": self.remediated_at,
            "remediated_at_iso": iso(self.remediated_at),
            "still_present_in_registry": self.still_present_in_registry,
        }


@dataclass(frozen=True)
class Marker:
    """One annotated instant on the scrubber."""

    at: int
    label: str
    kind: str  # "publish" | "burst" | "remediation" | "detection"
    detail: str = ""

    def as_dict(self) -> dict:
        return {
            "at": self.at,
            "at_iso": iso(self.at),
            "label": self.label,
            "kind": self.kind,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class Incident:
    """Everything the console needs to annotate a timeline."""

    title: str
    date: str
    root_cause: str
    payload: str
    sources: tuple[str, ...]
    window: Window
    versions: tuple[MaliciousVersion, ...]
    markers: tuple[Marker, ...]
    domain_start: int = DEFAULT_DOMAIN_START
    domain_end: int = DEFAULT_DOMAIN_END
    #: package name -> the malicious versions of it, for O(1) classification
    by_package: dict[str, set[str]] = field(default_factory=dict)

    def malicious_versions(self, package: str) -> set[str]:
        return set(self.by_package.get(package, ()))

    @property
    def packages(self) -> list[str]:
        return sorted(self.by_package)

    def as_dict(self) -> dict:
        return {
            "title": self.title,
            "date": self.date,
            "root_cause": self.root_cause,
            "payload": self.payload,
            "sources": list(self.sources),
            "window": self.window.as_dict(),
            "domain": {
                "start": self.domain_start,
                "end": self.domain_end,
                "start_iso": iso(self.domain_start),
                "end_iso": iso(self.domain_end),
                "span": humanize(self.domain_end - self.domain_start),
            },
            "packages": self.packages,
            "package_count": len(self.by_package),
            "version_count": len(self.versions),
            "versions": [v.as_dict() for v in self.versions],
            "markers": [m.as_dict() for m in self.markers],
        }


def _markers(window_raw: dict, versions: tuple[MaliciousVersion, ...]) -> tuple[Marker, ...]:
    """Named instants worth snapping to, oldest first.

    Wave 1 is nineteen publishes inside 8 min 22 s. Drawing nineteen ticks a
    pixel apart would be decoration, not information, so the burst is collapsed
    to its two ends and the three packages that give the incident its name keep
    their own marks.
    """
    out: list[Marker] = []
    wave1 = [v for v in versions if v.wave == 1]
    first = min(wave1, key=lambda v: v.published_at) if wave1 else None
    last = max(wave1, key=lambda v: v.published_at) if wave1 else None

    if first:
        out.append(
            Marker(
                first.published_at,
                "first malicious publish",
                "publish",
                f"{first.package}@{first.version} — the attack becomes real; "
                "any lockfile regenerated after this instant can resolve it",
            )
        )
    named = {"debug", "chalk"}
    for v in sorted(wave1, key=lambda v: v.published_at):
        if v.package in named and v is not first:
            out.append(
                Marker(
                    v.published_at,
                    f"{v.package}@{v.version} published",
                    "publish",
                    f"wave 1, {humanize(v.published_at - first.published_at)} "
                    "after the first publish" if first else "wave 1",
                )
            )
    if last and first and last is not first:
        out.append(
            Marker(
                last.published_at,
                "wave-1 burst ends",
                "burst",
                f"{len(wave1)} packages published in "
                f"{humanize(last.published_at - first.published_at)}; "
                f"last was {last.package}@{last.version}",
            )
        )

    remediation = [v for v in versions if v.remediated_at]
    if remediation:
        earliest = min(remediation, key=lambda v: v.remediated_at)
        latest = max(remediation, key=lambda v: v.remediated_at)
        out.append(
            Marker(
                earliest.remediated_at,
                "first clean version published",
                "remediation",
                f"{earliest.package}@{earliest.remediated_version} — remediation "
                "starts, but a lockfile does not update itself",
            )
        )
        if latest is not earliest:
            out.append(
                Marker(
                    latest.remediated_at,
                    "wave-1 remediation complete",
                    "remediation",
                    f"{latest.package}@{latest.remediated_version}",
                )
            )

    detection = window_raw.get("community_detection_utc")
    if detection:
        out.append(
            Marker(
                parse_iso(detection, field_name="community_detection_utc"),
                "public disclosure",
                "detection",
                "the moment anyone could have known to look — everything before "
                "this point is what only a historical graph can reconstruct",
            )
        )
    return tuple(sorted(out, key=lambda m: m.at))


def load_incident(path: str | os.PathLike | None = None) -> Incident:
    """Read and validate the incident file."""
    target = Path(
        path
        or os.environ.get("HINDSIGHT_INCIDENT_FILE")
        or DEFAULT_INCIDENT_PATH
    )
    try:
        raw = json.loads(target.read_text())
    except FileNotFoundError:
        raise IncidentError(
            f"incident file not found at {target}; set HINDSIGHT_INCIDENT_FILE "
            "or run the console from the repository root"
        ) from None
    except json.JSONDecodeError as exc:
        raise IncidentError(f"{target} is not valid JSON: {exc}") from None
    return build_incident(raw)


def build_incident(raw: dict) -> Incident:
    """Turn the parsed file into the console's in-memory form."""
    window_raw = raw.get("window") or {}
    packages = raw.get("packages") or []
    if not packages:
        raise IncidentError("incident file lists no packages")

    versions: list[MaliciousVersion] = []
    by_package: dict[str, set[str]] = {}
    for entry in packages:
        package = str(entry["package"])
        version = str(entry["malicious_version"])
        remediated_at = entry.get("remediated_published_at")
        versions.append(
            MaliciousVersion(
                package=package,
                version=version,
                wave=int(entry.get("wave") or 1),
                published_at=parse_iso(entry["published_at"], field_name="published_at"),
                remediated_version=entry.get("remediated_version"),
                remediated_at=(
                    parse_iso(remediated_at, field_name="remediated_published_at")
                    if remediated_at
                    else None
                ),
                still_present_in_registry=bool(entry.get("still_present_in_registry")),
            )
        )
        by_package.setdefault(package, set()).add(version)

    span = window_raw.get("practical_exposure_window_utc") or []
    if len(span) != 2:
        raise IncidentError(
            "incident file has no practical_exposure_window_utc pair; the console "
            "will not guess an exposure window"
        )
    first_publish = parse_iso(
        window_raw.get("first_malicious_publish_utc") or span[0],
        field_name="first_malicious_publish_utc",
    )
    window = Window(
        start=parse_iso(span[0], field_name="practical_exposure_window_utc[0]"),
        end=parse_iso(span[1], field_name="practical_exposure_window_utc[1]"),
        first_publish=first_publish,
    )

    ordered = tuple(sorted(versions, key=lambda v: (v.published_at, v.package)))
    return Incident(
        title=str(raw.get("incident") or "supply-chain incident"),
        date=str(raw.get("date") or ""),
        root_cause=str(raw.get("root_cause") or ""),
        payload=str(raw.get("payload") or ""),
        sources=tuple(str(s) for s in raw.get("sources") or ()),
        window=window,
        versions=ordered,
        markers=_markers(window_raw, ordered),
        by_package=by_package,
    )


__all__ = [
    "DEFAULT_DOMAIN_END",
    "DEFAULT_DOMAIN_START",
    "DEFAULT_INCIDENT_PATH",
    "Incident",
    "IncidentError",
    "MaliciousVersion",
    "Marker",
    "build_incident",
    "load_incident",
    "parse_iso",
]
