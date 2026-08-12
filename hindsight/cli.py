"""Command line entry point.

    python -m hindsight ingest --config org.yaml --dry-run
    python -m hindsight ingest --config org.yaml --execute
    python -m hindsight status --config org.yaml

``--dry-run`` is the default: ingest writes nothing unless ``--execute`` is
passed. The store is append-only and deletion is impractically slow, so the
cost of an accidental write is permanent.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from dataclasses import dataclass, field, replace
from pathlib import Path

import yaml

from .client import HydraClient, HydraError
from .graphbuild import DEFAULT_SCHEMA, RepoInput, Schema, build_rowsets
from .history import GitError, load_history
from .ids import IdCollision, repo_id, watermark_id
from .ingest import MAX_BATCH, Ingestor

DEFAULT_CACHE = ".hindsight/repos"


@dataclass(frozen=True)
class RepoSpec:
    slug: str
    url: str = ""
    path: str = ""
    service: str = ""
    lockfiles: tuple[str, ...] = ()

    @property
    def is_local(self) -> bool:
        return bool(self.path)


@dataclass(frozen=True)
class OrgConfig:
    repos: tuple[RepoSpec, ...]
    cache_dir: str = DEFAULT_CACHE
    since: str | None = None
    until: str | None = None
    schema: Schema = DEFAULT_SCHEMA
    batch: int = MAX_BATCH
    maintainers: dict[str, list[str]] = field(default_factory=dict)


class ConfigError(Exception):
    """org.yaml is missing something the pipeline needs."""


def slug_from(source: str) -> str:
    """``https://github.com/axios/axios.git`` -> ``axios/axios``."""
    cleaned = source.rstrip("/")
    if cleaned.endswith(".git"):
        cleaned = cleaned[:-4]
    parts = [p for p in cleaned.replace(":", "/").split("/") if p and p not in (".", "..")]
    if len(parts) >= 2:
        return "/".join(parts[-2:])
    return parts[-1] if parts else cleaned


def load_config(path: str | Path) -> OrgConfig:
    raw = yaml.safe_load(Path(path).read_text()) or {}
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: top level must be a mapping")
    entries = raw.get("repos")
    if not entries:
        raise ConfigError(f"{path}: no 'repos' listed")

    specs: list[RepoSpec] = []
    seen: set[str] = set()
    for i, entry in enumerate(entries):
        if isinstance(entry, str):
            entry = {"path": entry} if _looks_local(entry) else {"url": entry}
        if not isinstance(entry, dict):
            raise ConfigError(f"{path}: repos[{i}] must be a string or a mapping")
        url = str(entry.get("url") or "")
        local = str(entry.get("path") or "")
        if not url and not local:
            raise ConfigError(f"{path}: repos[{i}] needs a 'url' or a 'path'")
        slug = str(entry.get("slug") or slug_from(local or url))
        if slug in seen:
            raise ConfigError(f"{path}: duplicate repo slug {slug!r}")
        seen.add(slug)
        specs.append(
            RepoSpec(
                slug=slug,
                url=url,
                path=local,
                service=str(entry.get("service") or ""),
                lockfiles=tuple(entry.get("lockfiles") or ()),
            )
        )

    schema_cfg = raw.get("schema") or {}
    schema = (
        Schema.prefixed(
            str(schema_cfg.get("node_prefix", "Hs")),
            str(schema_cfg.get("rel_prefix", "HS")),
        )
        if schema_cfg
        else DEFAULT_SCHEMA
    )
    return OrgConfig(
        repos=tuple(specs),
        cache_dir=str(raw.get("cache_dir") or DEFAULT_CACHE),
        since=raw.get("since"),
        until=raw.get("until"),
        schema=schema,
        batch=int(raw.get("batch") or MAX_BATCH),
        maintainers=raw.get("maintainers") or {},
    )


def _looks_local(value: str) -> bool:
    return value.startswith((".", "/", "~")) or "://" not in value and "@" not in value


def materialize(spec: RepoSpec, cache_dir: Path, fetch: bool = True) -> Path:
    """Return a local checkout for ``spec``, cloning or fetching if needed."""
    if spec.is_local:
        path = Path(spec.path).expanduser().resolve()
        if not (path / ".git").exists() and not (path / "HEAD").exists():
            raise GitError(f"{path} is not a git repository")
        return path

    target = cache_dir.expanduser().resolve() / spec.slug.replace("/", "__")
    if target.exists():
        if fetch:
            subprocess.run(
                ["git", "-C", str(target), "fetch", "--quiet", "--all"],
                capture_output=True,
                text=True,
            )
        return target
    target.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        ["git", "clone", "--filter=blob:none", "--quiet", spec.url, str(target)],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise GitError(f"clone {spec.url} failed: {proc.stderr.strip()[:300]}")
    return target


def collect(config: OrgConfig, fetch: bool, log) -> tuple[list[RepoInput], list[str]]:
    inputs: list[RepoInput] = []
    problems: list[str] = []
    for spec in config.repos:
        try:
            checkout = materialize(spec, Path(config.cache_dir), fetch=fetch)
            history = load_history(
                checkout,
                slug=spec.slug,
                lockfiles=list(spec.lockfiles) or None,
                since=config.since,
                until=config.until,
            )
        except GitError as exc:
            problems.append(f"{spec.slug}: {exc}")
            log(f"  {spec.slug:<28} SKIPPED ({exc})")
            continue
        for note in history.errors:
            problems.append(f"{spec.slug}: {note}")
        skipped = (
            f" skipped={len(history.skipped_commits)}" if history.skipped_commits else ""
        )
        log(
            f"  {spec.slug:<28} snapshots={len(history.snapshots):>5,d} "
            f"intervals={len(history.intervals):>7,d} "
            f"lockfiles={','.join(history.lockfiles) or '-'}{skipped}"
        )
        inputs.append(RepoInput.from_history(history, name=spec.slug, service=spec.service))
    return inputs, problems


def cmd_ingest(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    if args.batch:
        config = replace(config, batch=args.batch)
    execute = bool(args.execute)

    def log(message: str) -> None:
        if not args.json:
            print(message, flush=True)

    log(f"reading history for {len(config.repos)} repo(s)")
    inputs, problems = collect(config, fetch=not args.no_fetch, log=log)
    if not inputs:
        print("no repository produced any history", file=sys.stderr)
        return 1

    try:
        rows = build_rowsets(inputs, schema=config.schema, maintainers=config.maintainers)
    except IdCollision as exc:
        print(f"id collision: {exc}", file=sys.stderr)
        return 2

    client = HydraClient.from_env()
    ingestor = Ingestor(client, schema=config.schema, batch=config.batch, progress=log)

    log("")
    log(f"built {rows.node_count:,d} nodes / {rows.edge_count:,d} edges")
    try:
        report = ingestor.run(rows, dry_run=not execute)
    except HydraError as exc:
        print(f"hydradb: {exc}", file=sys.stderr)
        return 3

    payload = report.as_dict()
    payload["problems"] = problems
    payload["built"] = rows.summary()
    if args.json:
        print(json.dumps(payload, indent=2))
        return 0

    log("")
    verb = "would write" if report.dry_run else "wrote"
    log(f"{verb} {report.nodes_written:,d} nodes and {report.edges_written:,d} edges")
    if report.skipped_resolves:
        log(f"skipped {report.skipped_resolves:,d} settled interval(s) below the watermark")
    if report.stale_repos:
        log(
            f"skipped {report.skipped_stale:,d} interval(s) from "
            f"{len(report.stale_repos)} repo(s) whose history is behind the graph: "
            + ", ".join(report.stale_repos)
        )
    if not report.dry_run:
        log(f"in {report.seconds:.2f}s, tx_from={report.tx_from}")
    if problems:
        log(f"{len(problems)} problem(s):")
        for note in problems[:20]:
            log(f"  ! {note}")
    if report.dry_run:
        log("dry run — nothing was written. Re-run with --execute.")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    client = HydraClient.from_env()
    ingestor = Ingestor(client, schema=config.schema, batch=config.batch)

    reachable = client.ping()
    entries = []
    for spec in config.repos:
        row = {
            "slug": spec.slug,
            "service": spec.service,
            "repo_id": repo_id(spec.slug),
            "watermark_id": watermark_id(spec.slug),
            "last_commit_ts": None,
            "last_ingest_tx": None,
            "ingested": False,
        }
        if reachable:
            got = client.rows(
                f"MATCH (n:{config.schema.watermark} {{id: $id}}) "
                "RETURN n.last_commit_ts, n.last_ingest_tx",
                {"id": row["watermark_id"]},
            )
            if got and got[0]:
                row["last_commit_ts"] = got[0][0]
                row["last_ingest_tx"] = got[0][1] if len(got[0]) > 1 else None
                row["ingested"] = True
        entries.append(row)

    payload = {
        "endpoint": client.config.query_url,
        "namespace": client.config.namespace,
        "cell": client.config.cell,
        "reachable": reachable,
        "schema": config.schema.__dict__,
        "repos": entries,
        "resolves_edges": ingestor.count_edges() if reachable else None,
    }
    if args.json:
        print(json.dumps(payload, indent=2))
        return 0

    print(f"endpoint  {payload['endpoint']}  ns={payload['namespace']} cell={payload['cell']}")
    print(f"reachable {reachable}")
    if not reachable:
        print("cannot reach HydraDB; watermarks unknown", file=sys.stderr)
        return 4
    print(f"labels    {config.schema.repo}/{config.schema.version} "
          f"-[{config.schema.resolves}]->")
    print(f"edges     {payload['resolves_edges']:,d} {config.schema.resolves}")
    print()
    print(f"{'repo':<32}{'service':<14}{'ingested through':<22}{'last run'}")
    for row in entries:
        through = _fmt_ts(row["last_commit_ts"]) if row["ingested"] else "never"
        last = _fmt_ts(row["last_ingest_tx"]) if row["ingested"] else "-"
        print(f"{row['slug']:<32}{row['service'] or '-':<14}{through:<22}{last}")
    return 0


def _fmt_ts(value) -> str:
    if not isinstance(value, int) or value <= 0:
        return "-"
    return time.strftime("%Y-%m-%d %H:%M", time.gmtime(value))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m hindsight",
        description="Bitemporal npm dependency graph ingest for HydraDB.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    ingest = sub.add_parser("ingest", help="extract lockfile history and write it to HydraDB")
    ingest.add_argument("--config", required=True, help="path to org.yaml")
    mode = ingest.add_mutually_exclusive_group()
    mode.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="build everything and report, write nothing (default)",
    )
    mode.add_argument("--execute", action="store_true", help="actually write to HydraDB")
    ingest.add_argument("--batch", type=int, default=0, help=f"UNWIND batch size (<= {MAX_BATCH})")
    ingest.add_argument("--no-fetch", action="store_true", help="do not fetch cached clones")
    ingest.add_argument("--json", action="store_true", help="machine-readable report on stdout")
    ingest.set_defaults(func=cmd_ingest)

    status = sub.add_parser("status", help="show per-repo ingest watermarks")
    status.add_argument("--config", required=True, help="path to org.yaml")
    status.add_argument("--json", action="store_true", help="machine-readable report on stdout")
    status.set_defaults(func=cmd_status)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"not found: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
