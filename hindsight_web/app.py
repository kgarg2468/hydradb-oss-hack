"""Starlette routing. Deliberately thin — the answers live in :mod:`service`.

Every endpoint is a GET, every response is JSON, and nothing in this process can
write to the graph: the console never composes a mutation and never accepts a
statement from the client. The graph is append-only and this is a witness to it.

**The handlers are deliberately ``def`` and not ``async def``.** The HydraDB
client is blocking ``urllib``, so an ``async`` handler would run that blocking
call directly on the event loop and stall every other request behind it — the
first version of this file did exactly that and the console wedged the moment
the page issued its four opening requests at once, because the 2.9 s maintainer
sweep held the loop. Declared synchronously, Starlette runs each handler in its
threadpool and the blocking reads overlap properly.
"""

from __future__ import annotations

import os
from pathlib import Path

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from hindsight.client import HydraError

from .analysis import TimestampError, to_epoch
from .incident import IncidentError, load_incident
from .queries import resolve_schema
from .service import Console, ConsoleError

STATIC_DIR = Path(__file__).resolve().parent / "static"


def _error(message: str, status: int = 400, **extra) -> JSONResponse:
    return JSONResponse({"error": message, **extra}, status_code=status)


def _instant(request: Request, console: Console) -> int:
    """``?at=`` as unix seconds or ISO-8601; defaults to the incident window start."""
    raw = request.query_params.get("at")
    if raw is None:
        return console.incident.window.start
    return to_epoch(raw, field_name="at")


def _package(request: Request, console: Console) -> str:
    """``?package=`` or the package the loaded incident opens on.

    There is no module-level default any more. A constant here would be a claim
    about which incident is loaded, made by the one layer that has no way to
    check it, and it would answer a request against a keyv file with ``chalk``.
    """
    return (
        request.query_params.get("package") or console.incident.default_package
    ).strip()


def build_app(console: Console | None = None) -> Starlette:
    """Construct the ASGI app. Tests pass a console backed by a fake client."""
    state = {"console": console}
    schema = resolve_schema(os.environ.get("HINDSIGHT_WEB_CONFIG"))

    def current() -> Console:
        if state["console"] is None:
            state["console"] = Console(schema=schema, incident=load_incident())
        return state["console"]

    def index(request: Request):
        return FileResponse(STATIC_DIR / "index.html")

    def health(request: Request):
        # ``?edges=1`` adds the RESOLVES count, which costs ~9 s on the demo
        # dataset. Off by default so the page's opening request stays instant.
        count_edges = request.query_params.get("edges") in ("1", "true", "yes")
        return JSONResponse(current().health(count_edges=count_edges))

    def incident(request: Request):
        return JSONResponse(current().overview())

    def exposure(request: Request):
        console = current()
        return JSONResponse(
            console.exposure(_package(request, console), _instant(request, console))
        )

    def blast_radius(request: Request):
        console = current()
        return JSONResponse(
            console.blast_radius(_package(request, console), _instant(request, console))
        )

    def maintainer_reach(request: Request):
        console = current()
        at = _instant(request, console)
        name = (request.query_params.get("name") or "").strip()
        if not name:
            limit = request.query_params.get("limit") or "12"
            if not limit.isdigit():
                return _error("limit must be a positive integer")
            return JSONResponse(console.maintainer_ranking(at, int(limit)))
        return JSONResponse(console.maintainer_reach(name, at))

    def version_footprint(request: Request):
        console = current()
        version = (request.query_params.get("version") or "").strip()
        if not version:
            return _error("version is required, e.g. ?package=chalk&version=5.6.1")
        return JSONResponse(
            console.version_footprint(
                _package(request, console), version, _instant(request, console)
            )
        )

    def on_timestamp_error(request: Request, exc: Exception):
        return _error(str(exc))

    def on_console_error(request: Request, exc: Exception):
        return _error(str(exc))

    def on_hydra_error(request: Request, exc: Exception):
        return _error(
            f"HydraDB refused the query: {exc}",
            status=502,
            hint=(
                "check the node is running (scripts/start-hydradb.sh) and that the "
                "demo dataset is seeded (scripts/demo-seed.py --execute)"
            ),
        )

    def on_incident_error(request: Request, exc: Exception):
        return _error(str(exc), status=500)

    routes = [
        Route("/", index),
        Route("/api/health", health),
        Route("/api/incident", incident),
        Route("/api/exposure", exposure),
        Route("/api/blast-radius", blast_radius),
        Route("/api/maintainer-reach", maintainer_reach),
        Route("/api/version-footprint", version_footprint),
        Mount("/static", app=StaticFiles(directory=str(STATIC_DIR)), name="static"),
    ]
    return Starlette(
        debug=bool(os.environ.get("HINDSIGHT_WEB_DEBUG")),
        routes=routes,
        exception_handlers={
            TimestampError: on_timestamp_error,
            ConsoleError: on_console_error,
            HydraError: on_hydra_error,
            IncidentError: on_incident_error,
        },
    )


app = build_app()

__all__ = ["app", "build_app"]
