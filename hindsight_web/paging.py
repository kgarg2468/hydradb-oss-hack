"""The console's reader: a paged read under a row cap.

The protocol belongs to :meth:`hindsight.client.HydraClient.paged_rows` — the
``query_id`` a continuation has to echo, and the retry policy that keeps a long
walk from dying on one 503. This module used to carry its own HTTP path and
therefore its own copy of both; it does not any more, so there is one place
where "how do we talk to a node" is decided and it is the shared client. That
also retires the reach into the client's private ``_sleep``: there was only
ever one backoff policy worth having, and it now runs where it lives.

What is left here is the console's *policy* rather than the protocol: a ceiling
on how much one panel will read before it stops and says it stopped.

:class:`~hindsight_web.service.Console` takes this function as its ``reader``
field, so it is also the single seam a unit test fakes to drive the whole
console off canned rows.

Everything here is read-only; nothing in this module can mutate the graph.
"""

from __future__ import annotations

from hindsight.client import MAX_PAGE_SIZE, HydraClient

#: A read the console will not silently truncate below. Above this it reports
#: ``truncated`` rather than paging forever on a query that was mis-scoped.
#: Callers must propagate that flag: a cut answer presented as a whole one is
#: the worst thing this console could do.
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
    """Read a statement to exhaustion, or to ``row_cap``. Returns ``(rows, truncated)``.

    ``truncated`` is True only if ``row_cap`` stopped the read while the server
    still had a cursor open. **Every caller must carry that flag into its
    answer.** It is the second element of the tuple rather than an exception
    because a partial answer is often still useful — but only if it is labelled,
    and the interesting failure mode is a caller writing ``rows, _ =`` and
    turning "at least 20,000" into "20,000".

    Transient failures on any page (429, 500, 502, 503, 504, socket errors) are
    retried by the client, with its own jittered backoff and resuming the same
    cursor, rather than abandoning the walk. Retrying a continuation is safe
    because a cursor read is a pure read: re-sending the same ``cursor`` and
    ``query_id`` either returns the same page or fails again.
    """
    return client.paged_rows(
        cypher,
        parameters,
        page_size=page_size,
        row_cap=row_cap,
        timeout=timeout,
    )


__all__ = ["DEFAULT_ROW_CAP", "fetch_all"]
