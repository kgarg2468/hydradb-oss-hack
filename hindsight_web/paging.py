"""Cursor paging that HydraDB actually accepts.

``hindsight.client.HydraClient.all_rows`` sends ``{query, parameters, cursor}``
to continue a paged read. The node rejects that with

    400 invalid_request: ClientProtocol query is not supported yet:
        result cursor does not belong to this query request

because a continuation must also echo the ``query_id`` the *first* page returned.
Verified against the live node: identical body plus ``query_id`` pages cleanly to
exhaustion (11,314 rows over three pages for one repo's RESOLVES edges), and
without it every result larger than one page fails on page two.

That is a bug in the shared client, and the fix belongs there — but this branch
may not touch ``hindsight/``, so the console carries its own paging path. It
reuses the client's :class:`~hindsight.client.ClientConfig` for the endpoint,
token, namespace and cell so there is exactly one place to configure a node.

Everything here is read-only; nothing in this module can mutate the graph.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from hindsight.client import MAX_PAGE_SIZE, HydraClient, HydraError, rows_of

#: A read the console will not silently truncate below. Above this it reports
#: ``truncated`` rather than paging forever on a query that was mis-scoped.
DEFAULT_ROW_CAP = 20_000


def fetch_all(
    client: HydraClient,
    cypher: str,
    parameters: dict | None = None,
    *,
    page_size: int = MAX_PAGE_SIZE,
    row_cap: int = DEFAULT_ROW_CAP,
    timeout: float | None = None,
) -> tuple[list[list[object]], bool]:
    """Read a statement to exhaustion. Returns ``(rows, truncated)``.

    ``truncated`` is True only if ``row_cap`` stopped the read while the server
    still had a cursor open — an answer that was cut is never presented as a
    complete one.
    """
    config = client.config
    url = config.query_url
    headers = {
        "Authorization": f"Bearer {config.token}",
        "X-Graph-Namespace": config.namespace,
        "Content-Type": "application/json",
    }
    deadline = config.timeout if timeout is None else timeout
    page = max(1, min(int(page_size), MAX_PAGE_SIZE))

    out: list[list[object]] = []
    cursor: int | None = None
    query_id: str | None = None
    while True:
        body: dict[str, object] = {
            "cell_id": config.cell,
            "query": cypher,
            "page_size": page,
        }
        if parameters:
            body["parameters"] = parameters
        if cursor is not None:
            body["cursor"] = cursor
            body["query_id"] = query_id
        request = urllib.request.Request(
            url, data=json.dumps(body).encode(), headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(request, timeout=deadline) as fh:
                result = json.load(fh)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:600]
            raise HydraError(f"HTTP {exc.code}: {detail}", status=exc.code) from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise HydraError(f"transport error: {exc}") from None

        client.stats["queries"] = client.stats.get("queries", 0) + 1
        out.extend(rows_of(result))
        query_id = result.get("query_id")
        cursor = result.get("next_cursor")
        if cursor is None:
            return out, False
        if len(out) >= row_cap:
            return out[:row_cap], True


__all__ = ["DEFAULT_ROW_CAP", "fetch_all"]
