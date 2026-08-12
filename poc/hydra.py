"""Minimal HydraDB HTTP client."""

import json
import os
import time
import urllib.error
import urllib.request

URL = os.environ.get("HYDRA_URL", "http://127.0.0.1:8443/v1/graphs/default/query")
TOKEN = os.environ.get("HYDRA_TOKEN", "local-development-token-32-bytes")
NS = os.environ.get("HYDRA_NS", "default")
CELL = os.environ.get("HYDRA_CELL", "cell-0")


class HydraError(Exception):
    pass


def query(cypher, parameters=None, timeout=300, page_size=None, cursor=None):
    body = {"cell_id": CELL, "query": cypher}
    if parameters:
        body["parameters"] = parameters
    if page_size:
        body["page_size"] = page_size
    if cursor is not None:
        body["cursor"] = cursor
    req = urllib.request.Request(
        URL,
        data=json.dumps(body).encode(),
        headers={
            "Authorization": "Bearer " + TOKEN,
            "X-Graph-Namespace": NS,
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as fh:
            return json.load(fh)
    except urllib.error.HTTPError as exc:
        raise HydraError(f"HTTP {exc.code}: {exc.read().decode()[:600]}") from None


def scalars(result):
    """Unwrap the {"type":..,"value":..} cells into plain python values."""
    out = []
    for row in result.get("rows", []):
        out.append([c.get("value") if isinstance(c, dict) else c for c in row])
    return out


def query_all(cypher, parameters=None, page_size=4000, timeout=300):
    """Follow next_cursor until the result set is exhausted. Returns plain rows."""
    rows = []
    cursor = None
    pages = 0
    while True:
        res = query(cypher, parameters, timeout=timeout, page_size=page_size, cursor=cursor)
        rows.extend(scalars(res))
        pages += 1
        cursor = res.get("next_cursor")
        if cursor is None:
            return rows, pages


def timed(cypher, parameters=None, **kw):
    t0 = time.perf_counter()
    res = query(cypher, parameters, **kw)
    return res, (time.perf_counter() - t0) * 1000.0
