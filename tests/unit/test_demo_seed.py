"""The seeder's two pieces of judgement: caret resolution, and honest labelling.

Everything else in ``scripts/demo-seed.py`` delegates to ``hindsight``. What it
owns is the construction of the one synthetic repository, and the provenance
stamp that keeps it from being mistaken for a real git history. Both are tested
against the real incident file, because a synthetic repo built from invented
version numbers would be worth nothing on stage.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

from hindsight_web.incident import load_incident

ROOT = Path(__file__).resolve().parents[2]


def _load():
    spec = importlib.util.spec_from_file_location(
        "demo_seed", ROOT / "scripts" / "demo-seed.py"
    )
    module = importlib.util.module_from_spec(spec)
    # Registered before execution because the module defines dataclasses, which
    # resolve annotations through ``sys.modules[cls.__module__]``.
    sys.modules["demo_seed"] = module
    spec.loader.exec_module(module)
    return module


seed = _load()
INCIDENT = load_incident()


# ---------------------------------------------------------------------- semver


@pytest.mark.parametrize(
    ("current", "candidate", "allowed"),
    [
        # Leftmost non-zero component is the one the caret pins.
        ("5.3.0", "5.6.1", True),  # chalk: reinstall picks up the malicious build
        ("5.3.0", "6.0.0", False),
        ("4.3.7", "4.4.2", True),  # debug
        ("1.1.0", "1.1.1", True),  # chalk-template
        ("0.3.2", "0.3.3", True),  # is-arrayish: ^0.x pins the minor
        ("0.3.2", "0.4.0", False),
        ("0.2.2", "0.2.3", True),  # simple-swizzle
        ("0.0.3", "0.0.3", True),  # ^0.0.x pins exactly
        ("0.0.3", "0.0.4", False),
        ("6.2.1", "6.2.2", True),  # ansi-styles
        ("4.2.3", "4.2.4", True),
        ("2.0.1", "3.1.0", False),  # color-convert: saved by the major bound
        ("1.1.4", "2.0.1", False),  # color-name
    ],
)
def test_caret_allows_follows_npm(current, candidate, allowed):
    assert seed.caret_allows(current, candidate) is allowed


def test_a_downgrade_is_never_a_caret_resolution():
    assert seed.caret_allows("5.6.1", "5.3.0") is False


def test_non_numeric_versions_are_refused_rather_than_guessed():
    for current, candidate in (("^5.3.0", "5.6.1"), ("5.3", "5.6.1"), ("5.3.0", "next")):
        assert seed.caret_allows(current, candidate) is False
    assert seed.parse_version("1.2.3-beta.1") == (1, 2, 3)
    assert seed.parse_version("workspace:*") is None


# ------------------------------------------------------------ synthetic repo


@pytest.fixture(scope="module")
def synthetic():
    return seed.synthetic_repo(INCIDENT)


def test_the_reinstall_lands_inside_the_real_compromise_window(synthetic):
    reinstall = seed.iso_to_epoch(seed.SYN_REINSTALL)
    assert INCIDENT.window.contains(reinstall)
    assert reinstall > INCIDENT.window.first_publish
    assert synthetic.snapshots == 4


def test_only_the_versions_the_caret_admits_turn_malicious(synthetic):
    """13 of the 19 wave-1 packages; the other 6 need a major bump to reach."""
    bad = [
        iv
        for iv in synthetic.intervals
        if iv.version in INCIDENT.malicious_versions(iv.package)
    ]
    assert len(bad) == 13
    packages = {iv.package for iv in bad}
    assert "chalk" in packages and "debug" in packages
    # Saved by their major bounds — the seeder must not quietly bump them.
    assert packages.isdisjoint({"color-convert", "color-name", "color"})

    wave1 = {v.package for v in INCIDENT.versions if v.wave == 1}
    assert packages < wave1


def test_every_malicious_interval_opens_at_the_reinstall_and_closes_at_remediation(
    synthetic,
):
    """Otherwise the scrubber would show exposure at instants that never happened."""
    opened = seed.iso_to_epoch(seed.SYN_REINSTALL)
    closed = seed.iso_to_epoch(seed.SYN_REMEDIATION)
    for interval in synthetic.intervals:
        if interval.version in INCIDENT.malicious_versions(interval.package):
            assert interval.valid_from == opened
            assert interval.valid_to == closed


def test_remediation_takes_the_published_fix_and_rolls_back_where_there_was_none(
    synthetic,
):
    after = {
        iv.package: iv.version
        for iv in synthetic.intervals
        if iv.valid_from == seed.iso_to_epoch(seed.SYN_REMEDIATION)
    }
    # chalk 5.6.2 was published as a clean release; debug never was, so the
    # repository goes back to the pin it held before the reinstall.
    assert after["chalk"] == "5.6.2"
    assert after["debug"] == seed.SYN_BASELINE_PINS["debug"] == "4.3.7"
    for package, version in after.items():
        assert version not in INCIDENT.malicious_versions(package)


def test_the_baseline_pins_predate_the_incident_and_are_not_malicious(synthetic):
    for package, version in seed.SYN_BASELINE_PINS.items():
        assert version not in INCIDENT.malicious_versions(package)
    assert set(seed.SYN_BASELINE_PINS) == {
        v.package for v in INCIDENT.versions if v.wave == 1
    }


def test_background_dependencies_do_not_collide_with_incident_packages():
    """The only thing moving in this repo's history must be the incident."""
    assert set(seed.SYN_BACKGROUND).isdisjoint(seed.SYN_BASELINE_PINS)


# --------------------------------------------------------------- honest labels


def test_the_synthetic_repo_declares_itself_in_its_own_provenance_string():
    origin = seed.SYNTHETIC_ORIGIN
    assert origin.startswith("SYNTHETIC")
    assert "not a real repository" in origin
    assert "fabricated" in origin
    # And it says why it has to exist at all.
    assert "none of the eight real repositories" in origin
    assert seed.SYNTHETIC == "synthetic"
    assert seed.REAL_REPO == "git-lockfile-history"


def test_the_synthetic_slug_is_not_a_real_org():
    assert seed.SYNTHETIC_SLUG == "acme/checkout-web"
    assert seed.SYNTHETIC_SLUG not in {meta.slug for meta in seed.REAL_REPOS}


class RecordingClient:
    def __init__(self):
        self.calls = []

    def query(self, cypher, parameters=None, **kw):
        self.calls.append((cypher, parameters or {}))
        return {"columns": [], "rows": []}


def test_provenance_stamp_writes_the_columns_the_console_reads_back():
    client = RecordingClient()
    seed.write_provenance(
        client,
        seed.DEMO_SCHEMA,
        [{"id": 7, "provenance": "synthetic", "origin": "x", "synthetic": 1}],
        1000,
    )
    (cypher, params), = client.calls
    assert seed.DEMO_SCHEMA.repo in cypher
    for column in ("provenance", "origin", "synthetic"):
        assert column in cypher
    # MERGE-by-id then SET is the only vertex-update shape the engine accepts.
    assert "MERGE" in cypher and "SET" in cypher
    assert params["rows"][0]["synthetic"] == 1


def test_the_provenance_stamp_uses_the_schema_it_was_given():
    """Regression: a literal label here quietly wrote into another namespace.

    ``MERGE (n:A {id: $x})`` matches whatever node already carries ``$x`` and
    adds ``A`` to it. Ids are global; labels namespace reads, not writes. A
    hardcoded label in this one statement gave four integration-test repositories
    a second label in the demo namespace, and on an append-only node that cannot
    be taken back.
    """
    other = seed.Schema.prefixed("ReplayScratch", "REPLAYSCRATCH")
    client = RecordingClient()
    seed.write_provenance(client, other, [{"id": 7, "provenance": "p", "origin": "", "synthetic": 0}], 10)
    (cypher, _), = client.calls
    assert "ReplayScratchRepo" in cypher
    assert seed.DEMO_SCHEMA.repo not in cypher


def test_the_source_dataset_is_only_ever_read():
    """The PoC's Dep* load is shared state on an append-only node."""
    text = (ROOT / "scripts" / "demo-seed.py").read_text()
    for label in seed.SOURCE_LABELS.values():
        for line in text.splitlines():
            if label not in line:
                continue
            upper = line.upper()
            for verb in ("DELETE", "CREATE", "MERGE", "SET "):
                assert verb not in upper, f"{verb} touches {label}: {line.strip()}"


# ------------------------------------------------------------------- overlay


def test_maintainer_overlay_inverts_the_poc_file():
    overlay = seed.maintainer_overlay()
    assert len(overlay) == 154
    assert "chalk" in overlay["sindresorhus"]
    assert "debug" in overlay["qix"]
    for packages in overlay.values():
        assert packages == list(packages)  # lists, as build_rowsets expects
