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
may not touch ``hindsight/``, so the console carries its own paging path. What it
does *not* carry is its own idea of how to talk to a node: the endpoint, token,
namespace and cell come from the client's
:class:`~hindsight.client.ClientConfig`, and the retry policy — which statuses
are transient, how many attempts, and the jittered exponential backoff between
them — is the client's as well. A page walk that gave up on a single 503 was
strictly worse than the shared client at the one thing paging is for, since the
longer the read the likelier it is to meet a compaction pause.

Retrying a continuation is safe: a cursor read is a pure read, so re-sending the
same ``cursor`` and ``query_id`` either returns the same page or fails again.

Everything here is read-only; nothing in this module can mutate the graph.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from hindsight.client import (
    MAX_PAGE_SIZE,
    RETRY_STATUSES,
    HydraClient,
    HydraError,
    rows_of,
)

#: A read the console will not silently truncate below. Above this it reports
#: ``truncated`` rather than paging forever on a query that was mis-scoped.
#: Callers must propagate that flag: a cut answer presented as a whole one is
#: the worst thing this console could do.
DEFAULT_ROW_CAP = 20_000


def _post(
    client: HydraClient,
    url: str,
    headers: dict[str, str],
    body: dict[str, object],
    timeout: float,
) -> dict:
    """One page, with the shared client's retry policy applied to it."""
    payload = json.dumps(body).encode()
    config = client.config
    last: Exception | None = None
    for attempt in range(config.max_retries + 1):
        request = urllib.request.Request(
            url, data=payload, headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as fh:
                client.stats["queries"] = client.stats.get("queries", 0) + 1
                return json.load(fh)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:600]
            err = HydraError(f"HTTP {exc.code}: {detail}", status=exc.code)
            if exc.code not in RETRY_STATUSES or attempt == config.max_retries:
                raise err from None
            last = err
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            err = HydraError(f"transport error: {exc}")
            if attempt == config.max_retries:
                raise err from None
            last = err
        client.stats["retries"] = client.stats.get("retries", 0) + 1
        # The client's own jittered backoff, so there is one policy and not two.
        client._sleep(attempt)  # noqa: SLF001
    raise last if last else HydraError("paged read failed with no error recorded")


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
    still had a cursor open. **Every caller must carry that flag into its
    answer.** It is the second element of the tuple rather than an exception
    because a partial answer is often still useful — but only if it is labelled,
    and the interesting failure mode is a caller writing ``rows, _ =`` and
    turning "at least 20,000" into "20,000".

    Transient failures on any page (429, 500, 502, 503, 504, socket errors) are
    retried with the shared client's backoff rather than abandoning the walk.
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
        result = _post(client, url, headers, body, deadline)
        out.extend(rows_of(result))
        query_id = result.get("query_id")
        cursor = result.get("next_cursor")
        if cursor is None:
            return out, False
        if len(out) >= row_cap:
            return out[:row_cap], True


__all__ = ["DEFAULT_ROW_CAP", "fetch_all"]
