"""Parsing the incident file into a malicious-version index and timeline markers.

The real ``poc/incident-chalk-debug.json`` is exercised too, because the console
is only ever as correct as the file it annotates the timeline from, and that file
was built by querying the npm registry's own ``time`` map.
"""

from __future__ import annotations

import pytest

from hindsight_web.incident import (
    DEFAULT_INCIDENT_PATH,
    IncidentError,
    build_incident,
    load_incident,
    parse_iso,
)

RAW = {
    "incident": "test compromise",
    "date": "2025-09-08",
    "root_cause": "phishing",
    "payload": "clipper",
    "sources": ["https://example.invalid/writeup"],
    "window": {
        "first_malicious_publish_utc": "2025-09-08T13:12:10.343Z",
        "community_detection_utc": "2025-09-08T15:20:00Z",
        "practical_exposure_window_utc": [
            "2025-09-08T13:12:10Z",
            "2025-09-08T15:30:00Z",
        ],
    },
    "packages": [
        {
            "package": "chalk",
            "malicious_version": "5.6.1",
            "wave": 1,
            "published_at": "2025-09-08T13:13:05.239Z",
            "remediated_version": "5.6.2",
            "remediated_published_at": "2025-09-08T14:47:54.486Z",
        },
        {
            "package": "debug",
            "malicious_version": "4.4.2",
            "wave": 1,
            "published_at": "2025-09-08T13:12:39.973Z",
            "remediated_version": None,
            "remediated_published_at": None,
        },
        {
            "package": "ansi-styles",
            "malicious_version": "6.2.2",
            "wave": 1,
            "published_at": "2025-09-08T13:12:10.343Z",
            "remediated_version": "6.2.3",
            "remediated_published_at": "2025-09-08T14:52:15.705Z",
        },
        {
            "package": "duckdb",
            "malicious_version": "1.3.3",
            "wave": 2,
            "published_at": "2025-09-09T01:11:00.000Z",
        },
    ],
}


def test_sub_second_publish_times_truncate_rather_than_round():
    """Rounding up past a commit second would put the scrubber on the wrong side."""
    assert parse_iso("2025-09-08T13:12:10.943Z", field_name="t") == 1_757_337_130
    assert parse_iso("2025-09-08T13:12:10Z", field_name="t") == 1_757_337_130


def test_malicious_index_is_keyed_by_package():
    incident = build_incident(RAW)
    assert incident.malicious_versions("chalk") == {"5.6.1"}
    assert incident.malicious_versions("debug") == {"4.4.2"}
    assert incident.malicious_versions("left-pad") == set()
    assert incident.packages == ["ansi-styles", "chalk", "debug", "duckdb"]


def test_window_bounds_come_from_the_file_and_are_never_guessed():
    incident = build_incident(RAW)
    assert incident.window.start == 1_757_337_130
    assert incident.window.end == 1_757_345_400
    assert incident.window.contains(1_757_340_300) is True
    assert incident.window.contains(incident.window.end) is False
    assert incident.window.as_dict()["duration"] == "2 h 17 min"


def test_missing_window_is_an_error_not_a_default():
    raw = {**RAW, "window": {}}
    with pytest.raises(IncidentError, match="practical_exposure_window_utc"):
        build_incident(raw)


def test_no_packages_is_an_error():
    with pytest.raises(IncidentError, match="no packages"):
        build_incident({**RAW, "packages": []})


def test_markers_are_ordered_and_cover_the_whole_arc():
    incident = build_incident(RAW)
    ats = [m.at for m in incident.markers]
    assert ats == sorted(ats)
    labels = [m.label for m in incident.markers]
    assert labels[0] == "first malicious publish"
    assert "public disclosure" in labels
    assert "first clean version published" in labels
    # Wave 2 is a day later and must not become a wave-1 burst boundary.
    assert all(m.at < 1_757_360_000 for m in incident.markers)


def test_burst_marker_reports_the_real_wave_one_span():
    incident = build_incident(RAW)
    burst = next(m for m in incident.markers if m.kind == "burst")
    assert "3 packages published in 55 s" in burst.detail


def test_markers_have_kinds_the_ui_can_style():
    incident = build_incident(RAW)
    assert {m.kind for m in incident.markers} <= {
        "publish",
        "burst",
        "remediation",
        "detection",
    }


def test_as_dict_is_json_ready_and_carries_the_domain():
    payload = build_incident(RAW).as_dict()
    assert payload["package_count"] == 4
    assert payload["version_count"] == 4
    assert payload["domain"]["start_iso"] == "2025-09-08T00:00:00Z"
    assert payload["domain"]["end_iso"] == "2025-09-09T00:00:00Z"
    assert payload["versions"][0]["key"] == "ansi-styles@6.2.2"


# ----------------------------------------------------------- the real file


def test_the_shipped_incident_file_parses_and_matches_the_write_up():
    assert DEFAULT_INCIDENT_PATH.exists(), "poc/incident-chalk-debug.json is missing"
    incident = load_incident()
    assert len(incident.versions) == 24
    assert len(incident.by_package) == 24
    assert incident.malicious_versions("chalk") == {"5.6.1"}
    assert incident.malicious_versions("debug") == {"4.4.2"}
    # The two numbers the PoC quotes: first publish, and the 8 min 22 s burst.
    assert incident.window.first_publish == 1_757_337_130  # 13:12:10Z
    wave1 = [v for v in incident.versions if v.wave == 1]
    assert len(wave1) == 19
    span = max(v.published_at for v in wave1) - min(v.published_at for v in wave1)
    assert span == 501  # 8 min 21 s between first and last wave-1 publish


def test_the_shipped_file_has_no_malicious_version_still_in_the_registry():
    for version in load_incident().versions:
        assert version.still_present_in_registry is False
