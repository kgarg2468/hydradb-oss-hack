"""``python -m hindsight_web`` — one command, no build step.

    python -m hindsight_web                 # http://127.0.0.1:8080
    python -m hindsight_web --port 9000

Connection details come from the same environment variables the ingest CLI uses
(``HINDSIGHT_HYDRA_URL`` / ``_TOKEN`` / ``_NS`` / ``_GRAPH`` / ``_CELL``), so the
console and the pipeline can never be pointed at different nodes by accident.
Label prefixes come from the shared ``HINDSIGHT_NODE_PREFIX`` and
``HINDSIGHT_REL_PREFIX`` variables and default to the ingest schema.
"""

from __future__ import annotations

import argparse
import os
import sys

from .queries import resolve_schema


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m hindsight_web",
        description="Hindsight incident console (read-only) over a HydraDB dataset.",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument(
        "--reload", action="store_true", help="restart on source change (development)"
    )
    parser.add_argument(
        "--config",
        help="org.yaml whose schema block names the dataset to read "
        "(the same file the ingest CLI writes with)",
    )
    args = parser.parse_args(argv)

    try:
        import uvicorn
    except ImportError:
        print(
            "uvicorn is not installed. pip install -r requirements-dev.txt",
            file=sys.stderr,
        )
        return 2

    if args.config:
        os.environ["HINDSIGHT_WEB_CONFIG"] = args.config
    schema = resolve_schema(args.config)
    print(f"Hindsight console  http://{args.host}:{args.port}")
    print(
        "Label namespace    "
        f"{schema.repo} / {schema.package} / {schema.version} / "
        f"{schema.maintainer} / {schema.watermark}; "
        f"{schema.resolves} / {schema.version_of} / {schema.maintains}",
        flush=True,
    )
    uvicorn.run(
        "hindsight_web.app:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="warning",
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
