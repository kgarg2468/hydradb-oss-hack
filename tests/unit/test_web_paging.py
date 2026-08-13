"""Cursor paging: the ``query_id`` echo, the row cap, and the retry policy.

Driven against a scripted transport rather than a node, so a 503 on page two is
a one-line fixture instead of an act of god. Sleeping is patched out; what is
asserted is that the *client's* policy — which statuses count as transient, how
many attempts, and that the backoff is the client's own — is the one applied.

Everything below the console's row cap now lives in
:meth:`hindsight.client.HydraClient.paged_rows`, so the socket is stubbed at the
client rather than in ``hindsight_web.paging``. These are still tests of what
the console gets back from :func:`~hindsight_web.paging.fetch_all`: the point of
the assertions is unchanged, only the seam they patch has moved to where the
protocol actually is.
"""

from __future__ import annotations

import io
import json
import urllib.error

import pytest

from hindsight import client as client_mod
from hindsight.client import RETRY_STATUSES, ClientConfig, HydraClient, HydraError
from hindsight_web.paging import DEFAULT_ROW_CAP, fetch_all


def page(rows, *, cursor=None, query_id="q-1"):
    body = {"columns": ["a"], "rows": [[{"type": "int", "value": v}] for v in rows]}
    if cursor is not None:
        body["next_cursor"] = cursor
    if query_id is not None:
        body["query_id"] = query_id
    return body


def http_error(status):
    return urllib.error.HTTPError(
        "http://node.invalid", status, "boom", {}, io.BytesIO(b"overloaded")
    )


class Transport:
    """A scripted ``urlopen``. Each script entry is a page dict or an exception."""

    def __init__(self, *script):
        self.script = list(script)
        self.bodies: list[dict] = []

    def __call__(self, request, timeout=None):
        self.bodies.append(json.loads(request.data))
        step = self.script.pop(0)
        if isinstance(step, Exception):
            raise step
        return _Response(step)


class _Response(io.BytesIO):
    def __init__(self, body):
        super().__init__(json.dumps(body).encode())

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


@pytest.fixture
def client():
    return HydraClient(config=ClientConfig(endpoint="http://node.invalid", max_retries=3))


@pytest.fixture(autouse=True)
def no_sleeping(monkeypatch):
    """Assert the client's own backoff is what runs, without waiting for it."""
    calls: list[int] = []
    monkeypatch.setattr(HydraClient, "_sleep", lambda self, attempt: calls.append(attempt))
    return calls


def run(monkeypatch, client, *script, **kw):
    transport = Transport(*script)
    monkeypatch.setattr(client_mod.urllib.request, "urlopen", transport)
    rows, truncated = fetch_all(client, "MATCH (n:X) RETURN n.a", {"p": 1}, **kw)
    return rows, truncated, transport


# --------------------------------------------------------------------- paging


def test_a_single_page_is_returned_whole(monkeypatch, client):
    rows, truncated, _ = run(monkeypatch, client, page([1, 2, 3]))
    assert rows == [[1], [2], [3]]
    assert truncated is False


def test_a_continuation_echoes_the_query_id_the_first_page_returned(monkeypatch, client):
    """Without it the node rejects page two as belonging to another query."""
    rows, truncated, transport = run(
        monkeypatch,
        client,
        page([1], cursor=17, query_id="q-abc"),
        page([2], query_id="q-abc"),
    )
    assert rows == [[1], [2]]
    assert truncated is False
    first, second = transport.bodies
    assert "cursor" not in first and "query_id" not in first
    assert second["cursor"] == 17
    assert second["query_id"] == "q-abc"
    assert second["query"] == first["query"]
    assert second["parameters"] == {"p": 1}


def test_the_row_cap_stops_the_walk_and_says_so(monkeypatch, client):
    rows, truncated, transport = run(
        monkeypatch,
        client,
        page([1, 2, 3], cursor=1),
        page([4, 5, 6], cursor=2),
        row_cap=4,
    )
    assert rows == [[1], [2], [3], [4]]
    assert truncated is True
    assert len(transport.bodies) == 2, "the walk must stop at the cap, not continue"


def test_a_result_that_ends_exactly_at_the_cap_is_not_truncated(monkeypatch, client):
    rows, truncated, _ = run(monkeypatch, client, page([1, 2]), row_cap=2)
    assert rows == [[1], [2]]
    assert truncated is False, "no cursor was left open, so nothing was cut"


def test_the_default_cap_is_high_enough_to_be_a_backstop_not_a_policy():
    assert DEFAULT_ROW_CAP == 20_000


def test_page_size_is_clamped_to_what_the_engine_accepts(monkeypatch, client):
    _, _, transport = run(monkeypatch, client, page([1]), page_size=99_999)
    assert transport.bodies[0]["page_size"] == 4096
    _, _, transport = run(monkeypatch, client, page([1]), page_size=0)
    assert transport.bodies[0]["page_size"] == 1


# -------------------------------------------------------------------- retries


@pytest.mark.parametrize("status", sorted(RETRY_STATUSES))
def test_a_transient_status_is_retried_rather_than_abandoning_the_walk(
    monkeypatch, client, status, no_sleeping
):
    rows, _, transport = run(monkeypatch, client, http_error(status), page([1, 2]))
    assert rows == [[1], [2]]
    assert len(transport.bodies) == 2
    assert client.stats["retries"] == 1
    assert no_sleeping == [0], "the client's backoff, with the attempt number"


def test_a_transient_failure_on_a_continuation_resumes_the_same_cursor(
    monkeypatch, client
):
    """The case that matters: the longer the read, the likelier it meets one."""
    rows, truncated, transport = run(
        monkeypatch,
        client,
        page([1], cursor=9, query_id="q-x"),
        http_error(503),
        page([2], query_id="q-x"),
    )
    assert rows == [[1], [2]]
    assert truncated is False
    retried, resumed = transport.bodies[1], transport.bodies[2]
    assert retried == resumed, "a retried page must not silently skip the cursor"
    assert resumed["cursor"] == 9 and resumed["query_id"] == "q-x"


def test_a_permanent_status_is_raised_immediately(monkeypatch, client, no_sleeping):
    transport = Transport(http_error(400), page([1]))
    monkeypatch.setattr(client_mod.urllib.request, "urlopen", transport)
    with pytest.raises(HydraError) as caught:
        fetch_all(client, "MATCH (n:X) RETURN n.a")
    assert caught.value.status == 400
    assert no_sleeping == [], "a rejected query must not be retried"
    assert len(transport.bodies) == 1


def test_a_socket_failure_is_retried_too(monkeypatch, client):
    rows, _, transport = run(
        monkeypatch, client, urllib.error.URLError("connection reset"), page([1])
    )
    assert rows == [[1]]
    assert len(transport.bodies) == 2


def test_retries_give_up_after_the_configured_number_of_attempts(
    monkeypatch, client, no_sleeping
):
    transport = Transport(*[http_error(503) for _ in range(4)])
    monkeypatch.setattr(client_mod.urllib.request, "urlopen", transport)
    with pytest.raises(HydraError) as caught:
        fetch_all(client, "MATCH (n:X) RETURN n.a")
    assert caught.value.status == 503
    # max_retries=3 means one attempt plus three retries.
    assert len(transport.bodies) == 4
    assert no_sleeping == [0, 1, 2]


def test_the_retry_budget_comes_from_the_shared_client_config(monkeypatch):
    patient = HydraClient(
        config=ClientConfig(endpoint="http://node.invalid", max_retries=6)
    )
    transport = Transport(*[http_error(502) for _ in range(6)], page([1]))
    monkeypatch.setattr(client_mod.urllib.request, "urlopen", transport)
    rows, truncated = fetch_all(patient, "MATCH (n:X) RETURN n.a")
    assert rows == [[1]]
    assert truncated is False
    assert patient.stats["retries"] == 6


def test_every_page_counts_as_a_query_but_a_retry_does_not(monkeypatch, client):
    run(monkeypatch, client, page([1], cursor=1), http_error(503), page([2]))
    assert client.stats["queries"] == 2
    assert client.stats["retries"] == 1
