"""HydraDB HTTP client.

Adapted from poc/hydra.py. Differences that matter in production:

* configuration is read from the environment at construction time rather than
  at import time, so a process can talk to more than one node;
* transient failures (429, 502, 503, 504, socket errors) are retried with
  exponential backoff and jitter — a long ingest run must not die because the
  node was compacting;
* cursor paging is built in, because HydraDB caps ``page_size`` at 4096 and any
  read that can return more rows has to follow ``next_cursor`` — carrying the
  ``query_id`` with it, which the node requires and which is the whole content
  of :meth:`HydraClient.paged_rows`.
"""

from __future__ import annotations

import json
import os
import random
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

DEFAULT_ENDPOINT = "http://127.0.0.1:8443"
DEFAULT_TOKEN = "local-development-token-32-bytes"
DEFAULT_NAMESPACE = "default"
DEFAULT_GRAPH = "default"
DEFAULT_CELL = "cell-0"

# HydraDB rejects page_size > 4096.
MAX_PAGE_SIZE = 4096

# Retried transparently; everything else is surfaced immediately.
RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})


class HydraError(Exception):
    """A HydraDB query failed."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class ClientConfig:
    endpoint: str = DEFAULT_ENDPOINT
    token: str = DEFAULT_TOKEN
    namespace: str = DEFAULT_NAMESPACE
    graph: str = DEFAULT_GRAPH
    cell: str = DEFAULT_CELL
    timeout: float = 300.0
    max_retries: int = 5
    backoff_base: float = 0.25
    backoff_cap: float = 8.0

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> ClientConfig:
        env = os.environ if env is None else env

        def _f(name: str, default: float) -> float:
            raw = env.get(name)
            return default if raw is None else float(raw)

        def _i(name: str, default: int) -> int:
            raw = env.get(name)
            return default if raw is None else int(raw)

        endpoint = env.get("HINDSIGHT_HYDRA_URL") or env.get("HYDRA_URL") or DEFAULT_ENDPOINT
        return cls(
            endpoint=endpoint,
            token=env.get("HINDSIGHT_HYDRA_TOKEN") or env.get("HYDRA_TOKEN") or DEFAULT_TOKEN,
            namespace=env.get("HINDSIGHT_HYDRA_NS") or env.get("HYDRA_NS") or DEFAULT_NAMESPACE,
            graph=env.get("HINDSIGHT_HYDRA_GRAPH") or env.get("HYDRA_GRAPH") or DEFAULT_GRAPH,
            cell=env.get("HINDSIGHT_HYDRA_CELL") or env.get("HYDRA_CELL") or DEFAULT_CELL,
            timeout=_f("HINDSIGHT_HYDRA_TIMEOUT", 300.0),
            max_retries=_i("HINDSIGHT_HYDRA_RETRIES", 5),
        )

    @property
    def query_url(self) -> str:
        base = self.endpoint.rstrip("/")
        # Accept either a bare host ("http://host:8443") or a full query URL.
        if "/v1/graphs/" in base:
            return base
        return f"{base}/v1/graphs/{self.graph}/query"


def unwrap(cell: object) -> object:
    """HydraDB returns cells as {"type": .., "value": ..}; give back the value."""
    if isinstance(cell, dict) and "value" in cell:
        return cell["value"]
    return cell


def rows_of(result: dict) -> list[list[object]]:
    return [[unwrap(c) for c in row] for row in result.get("rows", [])]


@dataclass
class HydraClient:
    config: ClientConfig = field(default_factory=ClientConfig)
    # Populated as queries run; useful for reporting and for tests.
    stats: dict[str, int] = field(default_factory=lambda: {"queries": 0, "retries": 0})

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> HydraClient:
        return cls(config=ClientConfig.from_env(env))

    def query(
        self,
        cypher: str,
        parameters: dict | None = None,
        *,
        timeout: float | None = None,
        page_size: int | None = None,
        cursor: object | None = None,
        query_id: str | None = None,
    ) -> dict:
        body: dict[str, object] = {"cell_id": self.config.cell, "query": cypher}
        if parameters:
            body["parameters"] = parameters
        if page_size is not None:
            body["page_size"] = min(page_size, MAX_PAGE_SIZE)
        if cursor is not None:
            body["cursor"] = cursor
        if query_id is not None:
            body["query_id"] = query_id
        payload = json.dumps(body).encode()
        headers = {
            "Authorization": f"Bearer {self.config.token}",
            "X-Graph-Namespace": self.config.namespace,
            "Content-Type": "application/json",
        }
        deadline_timeout = self.config.timeout if timeout is None else timeout

        last: Exception | None = None
        for attempt in range(self.config.max_retries + 1):
            req = urllib.request.Request(
                self.config.query_url, data=payload, headers=headers, method="POST"
            )
            try:
                with urllib.request.urlopen(req, timeout=deadline_timeout) as fh:
                    self.stats["queries"] += 1
                    return json.load(fh)
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode("utf-8", "replace")[:600]
                err = HydraError(f"HTTP {exc.code}: {detail}", status=exc.code)
                if exc.code not in RETRY_STATUSES or attempt == self.config.max_retries:
                    raise err from None
                last = err
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                err = HydraError(f"transport error: {exc}")
                if attempt == self.config.max_retries:
                    raise err from None
                last = err
            self.stats["retries"] += 1
            self._sleep(attempt)
        raise last if last else HydraError("query failed with no error recorded")

    def _sleep(self, attempt: int) -> None:
        delay = min(self.config.backoff_base * (2**attempt), self.config.backoff_cap)
        time.sleep(delay * (0.5 + random.random() / 2))

    def rows(self, cypher: str, parameters: dict | None = None, **kw) -> list[list[object]]:
        """Single-page read, unwrapped."""
        return rows_of(self.query(cypher, parameters, **kw))

    def paged_rows(
        self,
        cypher: str,
        parameters: dict | None = None,
        *,
        page_size: int = MAX_PAGE_SIZE,
        row_cap: int | None = None,
        timeout: float | None = None,
    ) -> tuple[list[list[object]], bool]:
        """Follow next_cursor to exhaustion or to ``row_cap``. ``(rows, truncated)``.

        A continuation must echo **both** the cursor and the ``query_id`` the
        first page returned. Sending the cursor alone is refused:

            400 invalid_request: ClientProtocol query is not supported yet:
                result cursor does not belong to this query request

        which made every result larger than one page fail on page two. Verified
        against a live node: with the ``query_id`` echoed, one repository's
        11,314 RESOLVES edges page cleanly to exhaustion over three pages.

        ``truncated`` is True only when ``row_cap`` stopped the read while the
        server still had a cursor open — an answer that was cut is never
        presented as a complete one, and a result that happens to land exactly
        on the cap is not called incomplete.
        """
        page = max(1, min(int(page_size), MAX_PAGE_SIZE))
        out: list[list[object]] = []
        cursor: object | None = None
        query_id: str | None = None
        while True:
            res = self.query(
                cypher,
                parameters,
                timeout=timeout,
                page_size=page,
                cursor=cursor,
                query_id=query_id,
            )
            out.extend(rows_of(res))
            query_id = res.get("query_id") or query_id
            cursor = res.get("next_cursor")
            if cursor is None:
                return out, False
            if row_cap is not None and len(out) >= row_cap:
                return out[:row_cap], True

    def all_rows(
        self,
        cypher: str,
        parameters: dict | None = None,
        *,
        page_size: int = MAX_PAGE_SIZE,
        timeout: float | None = None,
    ) -> list[list[object]]:
        """Every row of a paged read, however many pages that takes."""
        rows, _ = self.paged_rows(
            cypher, parameters, page_size=page_size, timeout=timeout
        )
        return rows

    def scalar(self, cypher: str, parameters: dict | None = None, default=None):
        rows = self.rows(cypher, parameters)
        if not rows or not rows[0]:
            return default
        return rows[0][0]

    def ping(self) -> bool:
        """True if the node answers a trivial query.

        Counts a label that is never written: a node-only MATCH needs an id,
        label or property predicate to be accepted at all, and a bare
        ``UNWIND ... RETURN`` is rejected outright ("UNWIND batches support
        CREATE or MATCH followed by RETURN, DELETE, CREATE, or MERGE").
        """
        try:
            self.query("MATCH (n:HindsightPingNeverWritten) RETURN count(*)")
            return True
        except HydraError:
            return False
