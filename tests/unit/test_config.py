"""org.yaml parsing and the shipped example."""

from pathlib import Path

import pytest

from hindsight.cli import ConfigError, build_parser, load_config, slug_from
from hindsight.graphbuild import DEFAULT_SCHEMA

EXAMPLE = Path(__file__).resolve().parents[2] / "org.example.yaml"


def write(tmp_path, text):
    path = tmp_path / "org.yaml"
    path.write_text(text)
    return path


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("https://github.com/axios/axios", "axios/axios"),
        ("https://github.com/axios/axios.git", "axios/axios"),
        ("git@github.com:apache/superset.git", "apache/superset"),
        ("/srv/checkouts/acme/web", "acme/web"),
        ("web", "web"),
    ],
)
def test_slug_is_derived_from_url_or_path(source, expected):
    assert slug_from(source) == expected


def test_minimal_config_of_bare_strings(tmp_path):
    config = load_config(
        write(tmp_path, "repos:\n  - https://github.com/axios/axios\n  - /srv/acme/web\n")
    )
    assert [r.slug for r in config.repos] == ["axios/axios", "acme/web"]
    assert config.repos[0].url and not config.repos[0].is_local
    assert config.repos[1].is_local
    assert config.schema == DEFAULT_SCHEMA


def test_full_config_round_trips_every_field(tmp_path):
    config = load_config(
        write(
            tmp_path,
            """
cache_dir: /tmp/checkouts
since: "2024-01-01"
until: "2025-12-31"
batch: 500
schema:
  node_prefix: IngTest
  rel_prefix: INGTEST
repos:
  - url: https://github.com/apache/superset
    slug: apache/superset
    service: analytics
    lockfiles:
      - superset-frontend/package-lock.json
maintainers:
  qix:
    - chalk
""",
        )
    )
    (repo,) = config.repos
    assert repo.service == "analytics"
    assert repo.lockfiles == ("superset-frontend/package-lock.json",)
    assert config.cache_dir == "/tmp/checkouts"
    assert (config.since, config.until, config.batch) == ("2024-01-01", "2025-12-31", 500)
    assert config.schema.repo == "IngTestRepo"
    assert config.maintainers == {"qix": ["chalk"]}


def test_missing_repos_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="no 'repos'"):
        load_config(write(tmp_path, "cache_dir: /tmp/x\n"))


def test_repo_without_url_or_path_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="needs a 'url' or a 'path'"):
        load_config(write(tmp_path, "repos:\n  - service: orders\n"))


def test_duplicate_slugs_are_rejected(tmp_path):
    # Two entries writing the same repo id would interleave into one timeline.
    with pytest.raises(ConfigError, match="duplicate repo slug"):
        load_config(
            write(
                tmp_path,
                "repos:\n"
                "  - url: https://github.com/axios/axios\n"
                "  - url: https://gitlab.com/axios/axios\n",
            )
        )


def test_shipped_example_is_valid_and_has_three_repos():
    config = load_config(EXAMPLE)
    assert len(config.repos) == 3
    assert all(r.url.startswith("https://") for r in config.repos)
    assert {r.service for r in config.repos} == {"http-client", "build", "analytics"}


def test_ingest_defaults_to_dry_run():
    args = build_parser().parse_args(["ingest", "--config", "org.yaml"])
    assert args.dry_run is True
    assert args.execute is False


def test_execute_and_dry_run_are_mutually_exclusive():
    args = build_parser().parse_args(["ingest", "--config", "org.yaml", "--execute"])
    assert args.execute is True
    with pytest.raises(SystemExit):
        build_parser().parse_args(["ingest", "--config", "o.yaml", "--execute", "--dry-run"])


def test_a_command_is_required():
    with pytest.raises(SystemExit):
        build_parser().parse_args([])
