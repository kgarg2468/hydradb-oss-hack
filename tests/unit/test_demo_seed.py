"""The seeder's two pieces of judgement: caret resolution, and honest labelling.

Everything else in ``scripts/demo-seed.py`` delegates to ``hindsight``. What it
owns is the construction of the one synthetic repository, and the provenance
stamp that keeps it from being mistaken for a real git history. Both are tested
against the real incident file, because a synthetic repo built from invented
version numbers would be worth nothing on stage.
"""

from __future__ import annotations

import gzip
import importlib.util
import json
import sys
from pathlib import Path

import pytest

from hindsight.ids import watermark_id
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


# -------------------------------------------------------- committed file source


def _tiny_dataset():
    real = seed.RepoInput(
        slug="example/real",
        name="example/real",
        service="api",
        intervals=(seed.Interval("chalk", "5.6.0", 10, 20),),
        first_ts=10,
        last_ts=20,
        snapshots=2,
    )
    synthetic = seed.RepoInput(
        slug=seed.SYNTHETIC_SLUG,
        name=seed.SYNTHETIC_SLUG,
        service=seed.SYNTHETIC_SERVICE,
        intervals=(seed.Interval("chalk", "5.6.1", 12, 18),),
        first_ts=12,
        last_ts=18,
        snapshots=2,
    )
    return seed.Dataset(
        inputs=(real, synthetic),
        origins={
            real.slug: "real git history",
            synthetic.slug: seed.SYNTHETIC_ORIGIN,
        },
        provenance={
            real.slug: {"provenance": seed.REAL_REPO, "synthetic": 0},
            synthetic.slug: {"provenance": seed.SYNTHETIC, "synthetic": 1},
        },
        maintainers={"qix": ("chalk",)},
        source="graph",
    )


def test_dataset_file_round_trips_deterministically_with_provenance(tmp_path):
    dataset = _tiny_dataset()
    first = tmp_path / "first.jsonl.gz"
    second = tmp_path / "second.jsonl.gz"
    summary = {
        "repos": 2,
        "packages": 1,
        "versions": 2,
        "maintainers": 1,
        "resolves": 2,
        "version_of": 2,
        "maintains": 1,
        "nodes": 6,
        "edges": 5,
    }

    seed.write_dataset(first, dataset, summary)
    seed.write_dataset(second, dataset, summary)

    loaded = seed.read_dataset(first)
    assert loaded == dataset
    assert first.read_bytes() == second.read_bytes()
    assert seed.dataset_is_current(first) is True
    assert loaded.provenance[seed.SYNTHETIC_SLUG] == {
        "provenance": "synthetic",
        "synthetic": 1,
    }
    assert loaded.origins[seed.SYNTHETIC_SLUG] == seed.SYNTHETIC_ORIGIN


def test_a_failed_export_leaves_the_previous_artifact_intact(tmp_path):
    """The destination is usually the only thing a fresh clone can seed from.

    A half-written gzip there does not announce itself as a failed export: it
    loads, and seeds a dataset that is quietly short of the one it claims to be.
    """
    path = tmp_path / "demo.jsonl.gz"
    seed.write_dataset(path, _tiny_dataset(), {"repos": 2})
    good = path.read_bytes()

    # Fails inside the write loop rather than while the records are assembled,
    # which is the only failure the destination file can be caught half-way by.
    broken = _tiny_dataset()
    broken.maintainers["qix"] = (object(),)
    with pytest.raises(TypeError):
        seed.write_dataset(path, broken, {"repos": 2})

    assert path.read_bytes() == good
    assert not list(tmp_path.glob("*.partial"))


class EmptySourceClient:
    def paged_rows(self, *args, **kwargs):
        return [], False


class ExplodingSourceClient:
    def paged_rows(self, *args, **kwargs):
        raise AssertionError("the file source must not query the node")


def test_auto_prefers_a_current_file_even_when_snapshots_exist(tmp_path, monkeypatch):
    dataset_path = tmp_path / "demo.jsonl.gz"
    seed.write_dataset(dataset_path, _tiny_dataset(), {"repos": 2})
    snapshots = tmp_path / "snapshots"
    snapshots.mkdir()
    (snapshots / "present.jsonl.gz").touch()
    monkeypatch.setattr(seed, "SNAPSHOT_DIR", snapshots)
    messages = []

    loaded, chosen = seed.collect(
        "auto", ExplodingSourceClient(), messages.append, dataset_path=dataset_path
    )

    assert chosen == "file"
    assert loaded == _tiny_dataset()
    assert messages[0] == "source: file"


def test_auto_without_file_or_snapshots_reproduces_the_empty_graph_failure(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(seed, "SNAPSHOT_DIR", tmp_path / "missing-snapshots")
    messages = []
    with pytest.raises(
        SystemExit, match="no repository history found via --source graph"
    ):
        seed.collect(
            "auto",
            EmptySourceClient(),
            messages.append,
            dataset_path=tmp_path / "missing-dataset.jsonl.gz",
        )
    assert messages[0] == "source: graph"


def test_graph_file_reprojects_the_poc_export_without_a_node(tmp_path):
    graph_path = tmp_path / "graph.json.gz"
    graph = {
        "repos": [{"id": 10, "slug": "axios"}],
        "versions": [
            {"id": 20, "pkg": "chalk", "version": "5.6.0"},
            {"id": 21, "pkg": "debug", "version": "4.3.7"},
        ],
        "resolves": [
            {"s": 10, "d": 20, "vf": 100, "vt": 200},
            {"s": 10, "d": 21, "vf": 100, "vt": seed.SENTINEL},
        ],
    }
    with gzip.open(graph_path, "wt") as fh:
        json.dump(graph, fh)

    dataset, chosen = seed.collect(
        "graph-file",
        ExplodingSourceClient(),
        lambda message: None,
        graph_path=graph_path,
    )

    assert chosen == "graph-file"
    assert len(dataset.inputs) == 1
    repo = dataset.inputs[0]
    assert repo.slug == "axios/axios"
    assert repo.intervals == (
        seed.Interval("chalk", "5.6.0", 100, 200),
        seed.Interval("debug", "4.3.7", 100, seed.SENTINEL),
    )
    assert (repo.first_ts, repo.last_ts, repo.snapshots) == (100, 200, 2)
    assert "poc/graph.json.gz" in dataset.origins[repo.slug]


def test_export_is_a_pure_file_operation_that_does_not_read_the_output_graph(
    tmp_path, monkeypatch
):
    source = tmp_path / "source.jsonl.gz"
    exported = tmp_path / "exported.jsonl.gz"
    seed.write_dataset(source, _tiny_dataset(), {"repos": 2})
    monkeypatch.setattr(
        seed.HydraClient,
        "from_env",
        classmethod(lambda cls: ExplodingSourceClient()),
    )

    result = seed.main(
        [
            "--source",
            "file",
            "--dataset",
            str(source),
            "--export",
            str(exported),
        ]
    )

    assert result == 0
    assert seed.read_dataset(exported) == _tiny_dataset()


def test_id_namespace_changes_every_written_id_but_not_visible_data():
    dataset = _tiny_dataset()
    schema = seed.Schema.prefixed("Replay", "REPLAY")
    normal, normal_repo_ids = seed.build_demo_rowsets(
        dataset.inputs, schema, dataset.maintainers
    )
    isolated, isolated_repo_ids = seed.build_demo_rowsets(
        dataset.inputs, schema, dataset.maintainers, id_namespace="SeedTestB4"
    )

    def node_ids(rows):
        return {
            row["id"]
            for group in (rows.repos, rows.packages, rows.versions, rows.maintainers)
            for row in group
        }

    assert node_ids(normal).isdisjoint(node_ids(isolated))
    assert normal_repo_ids.keys() == isolated_repo_ids.keys()
    assert set(normal_repo_ids.values()).isdisjoint(isolated_repo_ids.values())
    assert [{k: v for k, v in row.items() if k != "id"} for row in normal.repos] == [
        {k: v for k, v in row.items() if k != "id"} for row in isolated.repos
    ]
    assert set(isolated.repo_slugs.values()) == {
        f"SeedTestB4:{spec.slug}" for spec in dataset.inputs
    }
    assert {watermark_id(slug) for slug in normal.repo_slugs.values()}.isdisjoint(
        watermark_id(slug) for slug in isolated.repo_slugs.values()
    )


def test_committed_dataset_answers_the_demo_offline_without_querying_hydradb():
    with gzip.open(seed.DEMO_DATASET, "rt") as fh:
        header = json.loads(next(fh))
    assert header == {
        "format": seed.DATASET_FORMAT,
        "rowsets": {
            "edges": 111_805,
            "maintainers": 154,
            "maintains": 466,
            "nodes": 31_505,
            "packages": 6_383,
            "repos": 9,
            "resolves": 86_380,
            "version_of": 24_959,
            "versions": 24_959,
        },
        "source": "graph-file",
        "type": "meta",
        "version": seed.DATASET_VERSION,
    }
    dataset, chosen = seed.collect(
        "auto", ExplodingSourceClient(), lambda message: None
    )
    assert chosen == "file"
    assert len(dataset.inputs) == 9
    assert sum(spec.slug == seed.SYNTHETIC_SLUG for spec in dataset.inputs) == 1
    assert dataset.provenance[seed.SYNTHETIC_SLUG] == {
        "provenance": seed.SYNTHETIC,
        "synthetic": 1,
    }
    for spec in dataset.inputs:
        if spec.slug == seed.SYNTHETIC_SLUG:
            assert dataset.origins[spec.slug] == seed.SYNTHETIC_ORIGIN
        else:
            assert dataset.provenance[spec.slug] == {
                "provenance": seed.REAL_REPO,
                "synthetic": 0,
            }
            assert "git lockfile history" in dataset.origins[spec.slug]
    at = seed.iso_to_epoch("2025-09-08T14:05:00Z")
    active = {
        spec.slug: {
            (iv.package, iv.version)
            for iv in spec.intervals
            if iv.valid_from <= at < iv.valid_to
        }
        for spec in dataset.inputs
    }
    exposed = {
        slug: {
            f"{package}@{version}"
            for package, version in resolved
            if package in {"chalk", "debug"}
            and version in INCIDENT.malicious_versions(package)
        }
        for slug, resolved in active.items()
    }
    assert {slug: versions for slug, versions in exposed.items() if versions} == {
        seed.SYNTHETIC_SLUG: {"chalk@5.6.1", "debug@4.4.2"}
    }

    reach = []
    for account, packages in dataset.maintainers.items():
        owned = set(packages)
        pairs = sum(
            len({package for package, _ in rows} & owned) for rows in active.values()
        )
        repos = sum(
            bool({package for package, _ in rows} & owned) for rows in active.values()
        )
        reach.append((pairs, repos, account))
    assert max(reach) == (271, 9, "sindresorhus")
