"""Parsing the incident file into a malicious-version index and timeline markers.

Both shipped incident files are exercised, because the console is only ever as
correct as the file it annotates the timeline from and both were built by
querying the npm registry's own ``time`` map. Two files rather than one is the
point: the scrubber's domain, the packages with their own markers and the
package the console opens on used to be constants in this module, and a second
incident is the only test that proves they are not any more.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from hindsight_web.incident import (
    DEFAULT_INCIDENT_PATH,
    IncidentError,
    build_incident,
    load_incident,
    parse_iso,
)

#: The second real incident: a worm wave with registry-verified timestamps, no
#: disclosure instant anyone can cite, and nothing remediated.
KEYV_INCIDENT_PATH = (
    Path(__file__).resolve().parents[2] / "poc" / "incident-keyv-shai-hulud.json"
)

RAW = {
    "incident": "test compromise",
    "date": "2025-09-08",
    "root_cause": "phishing",
    "payload": "clipper",
    "sources": ["https://example.invalid/writeup"],
    "featured_packages": ["chalk", "debug"],
    "default_package": "chalk",
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


# ------------------------------------------------- the domain, from the data


def test_the_domain_is_the_utc_day_the_exposure_window_opens_on():
    """Whole days, not a tight fit around the events.

    The scrubber has to have somewhere to travel before the first publish: the
    question this console exists to answer is what a lockfile held *before* the
    attack, and a domain that starts at the attack cannot be asked it.
    """
    incident = build_incident(RAW)
    assert incident.domain_start == parse_iso("2025-09-08T00:00:00Z", field_name="t")
    assert incident.domain_end == parse_iso("2025-09-09T00:00:00Z", field_name="t")


def test_the_domain_widens_so_a_late_marker_is_still_reachable():
    """A marker outside the domain is a chip the scrubber cannot travel to."""
    raw = {
        **RAW,
        "window": {
            **RAW["window"],
            "community_detection_utc": "2025-09-10T04:00:00Z",
        },
    }
    incident = build_incident(raw)
    assert incident.domain_start == parse_iso("2025-09-08T00:00:00Z", field_name="t")
    assert incident.domain_end == parse_iso("2025-09-11T00:00:00Z", field_name="t")
    assert max(m.at for m in incident.markers) < incident.domain_end


def test_a_file_may_state_its_own_display_domain():
    raw = {
        **RAW,
        "display_domain_utc": ["2025-09-01T00:00:00Z", "2025-09-15T00:00:00Z"],
    }
    incident = build_incident(raw)
    assert incident.domain_start == parse_iso("2025-09-01T00:00:00Z", field_name="t")
    assert incident.domain_end == parse_iso("2025-09-15T00:00:00Z", field_name="t")


def test_a_backwards_display_domain_is_an_error():
    raw = {
        **RAW,
        "display_domain_utc": ["2025-09-15T00:00:00Z", "2025-09-01T00:00:00Z"],
    }
    with pytest.raises(IncidentError, match="display_domain_utc"):
        build_incident(raw)


# --------------------------------------- which packages the file speaks about


def _own_markers(incident) -> list[str]:
    """Labels of the ``package@version published`` marks, in timeline order."""
    return [m.label for m in incident.markers if "@" in m.label]


def test_only_the_featured_packages_earn_a_marker_of_their_own():
    """The set used to be ``{"chalk", "debug"}``, written into this module."""
    incident = build_incident(RAW)
    assert _own_markers(incident) == ["debug@4.4.2 published", "chalk@5.6.1 published"]

    plain = build_incident({k: v for k, v in RAW.items() if k != "featured_packages"})
    assert _own_markers(plain) == []


def test_the_default_package_falls_back_from_stated_to_featured_to_alphabetical():
    stated = {k: v for k, v in RAW.items()}
    assert build_incident(stated).default_package == "chalk"

    featured_only = {k: v for k, v in RAW.items() if k != "default_package"}
    assert build_incident(featured_only).default_package == "chalk"

    neither = {
        k: v
        for k, v in RAW.items()
        if k not in ("default_package", "featured_packages")
    }
    assert build_incident(neither).default_package == "ansi-styles"


def test_a_default_package_this_incident_does_not_cover_is_an_error():
    """Opening on a package with no malicious version renders an all-clear the
    incident never claimed, so it is refused at load rather than served."""
    with pytest.raises(IncidentError, match="left-pad"):
        build_incident({**RAW, "default_package": "left-pad"})


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


# ------------------------------------------- the chalk file, bit for bit
#
# The domain, the named packages and the opening package were three constants
# in the module until they became three fields in the file. These three tests
# are the pin that says the move changed nothing about the incident the console
# has been demoed on: same numbers, same chips, same opening view.


def test_the_derived_domain_equals_the_constants_it_replaced():
    """``DEFAULT_DOMAIN_START/END`` said exactly this, and said it about one
    incident. Derivation has to reproduce it before it is allowed to generalise."""
    incident = load_incident(DEFAULT_INCIDENT_PATH)
    assert incident.domain_start == parse_iso("2025-09-08T00:00:00Z", field_name="t")
    assert incident.domain_end == parse_iso("2025-09-09T00:00:00Z", field_name="t")


def test_the_chalk_markers_are_unchanged_in_count_order_and_wording():
    incident = load_incident(DEFAULT_INCIDENT_PATH)
    assert [(m.label, m.kind) for m in incident.markers] == [
        ("first malicious publish", "publish"),
        ("debug@4.4.2 published", "publish"),
        ("chalk@5.6.1 published", "publish"),
        ("wave-1 burst ends", "burst"),
        ("first clean version published", "remediation"),
        ("wave-1 remediation complete", "remediation"),
        ("public disclosure", "detection"),
    ]
    assert [m.at for m in incident.markers] == [
        1_757_337_130,  # 13:12:10Z ansi-styles
        1_757_337_159,  # 13:12:39Z debug
        1_757_337_185,  # 13:13:05Z chalk
        1_757_337_631,  # 13:20:31Z backslash, the burst's far edge
        1_757_342_874,  # 14:47:54Z chalk@5.6.2
        1_757_344_483,  # 15:14:43Z supports-hyperlinks@4.1.2
        1_757_344_800,  # 15:20:00Z public disclosure
    ]


def test_the_chalk_file_still_opens_on_chalk():
    incident = load_incident(DEFAULT_INCIDENT_PATH)
    assert incident.default_package == "chalk"
    assert incident.featured_packages == ("chalk", "debug")


# ------------------------------------------------ a second real incident file
#
# keyv/cacheable, 4 August 2026. It is here because it is *unlike* the chalk
# file in every way the old constants assumed: a different year, a different
# span, no citable disclosure instant, and nothing remediated. Anything the
# console still gets right on this file, it gets right from the data.


def test_the_second_incident_file_parses_with_its_own_day_and_packages():
    assert KEYV_INCIDENT_PATH.exists(), "poc/incident-keyv-shai-hulud.json is missing"
    incident = load_incident(KEYV_INCIDENT_PATH)
    assert len(incident.by_package) == 8
    assert incident.malicious_versions("keyv") == {"6.0.0"}
    assert incident.domain_start == parse_iso("2026-08-04T00:00:00Z", field_name="t")
    assert incident.domain_end == parse_iso("2026-08-05T00:00:00Z", field_name="t")


def test_the_second_incident_opens_on_its_own_package_not_on_chalk():
    incident = load_incident(KEYV_INCIDENT_PATH)
    assert incident.default_package == "keyv"
    assert "chalk" not in incident.packages


def test_the_second_incidents_first_marker_is_its_own_first_publish():
    incident = load_incident(KEYV_INCIDENT_PATH)
    first = incident.markers[0]
    assert first.label == "first malicious publish"
    # 09:35:00.763Z truncated, not rounded: the sub-second part is dropped.
    assert first.at == parse_iso("2026-08-04T09:35:00Z", field_name="t")
    assert "keyv@6.0.0" in first.detail


def test_the_second_incidents_burst_ends_at_the_last_wave_one_publish():
    incident = load_incident(KEYV_INCIDENT_PATH)
    burst = next(m for m in incident.markers if m.kind == "burst")
    assert burst.at == parse_iso("2026-08-04T10:28:01Z", field_name="t")
    assert "ecto@5.0.1" in burst.detail
    assert "8 packages published in" in burst.detail


def test_a_featured_package_that_is_not_the_first_publish_keeps_its_own_marker():
    incident = load_incident(KEYV_INCIDENT_PATH)
    assert _own_markers(incident) == ["flat-cache@6.1.24 published"]
    own = next(m for m in incident.markers if "@" in m.label)
    assert own.at == parse_iso("2026-08-04T10:10:55Z", field_name="t")


def test_an_incident_with_no_citable_disclosure_gets_no_disclosure_marker():
    """No ``community_detection_utc`` means no verifiable instant exists. The
    console draws nothing rather than drawing a plausible one."""
    incident = load_incident(KEYV_INCIDENT_PATH)
    assert [m for m in incident.markers if m.kind == "detection"] == []


def test_an_incident_with_nothing_remediated_yet_gets_no_remediation_markers():
    """A dist-tag rollback does not update a lockfile, so there is no clean
    superseding publish to point a marker at."""
    incident = load_incident(KEYV_INCIDENT_PATH)
    assert all(v.remediated_at is None for v in incident.versions)
    assert all(v.remediated_version is None for v in incident.versions)
    assert [m for m in incident.markers if m.kind == "remediation"] == []


def test_every_marker_in_the_second_file_is_inside_its_derived_domain():
    incident = load_incident(KEYV_INCIDENT_PATH)
    for marker in incident.markers:
        assert incident.domain_start <= marker.at <= incident.domain_end
