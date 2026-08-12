"""Client configuration and retry behaviour, with the socket stubbed out."""

import io
import json
import urllib.error

import pytest

from hindsight import client as client_mod
from hindsight.client import (
    MAX_PAGE_SIZE,
    ClientConfig,
    HydraClient,
    HydraError,
    rows_of,
    unwrap,
)


class Recorder:
    """Stands in for urlopen; replays a scripted sequence of responses."""

    def __init__(self, script):
        self.script = list(script)
        self.calls = []

    def __call__(self, req, timeout=None):
        self.calls.append(json.loads(req.data.decode()))
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return _Response(item)


class _Response(io.BytesIO):
    def __init__(self, payload):
        super().__init__(json.dumps(payload).encode())

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture
def no_sleep(monkeypatch):
    monkeypatch.setattr(client_mod.time, "sleep", lambda _: None)


def http_error(code):
    return urllib.error.HTTPError(
        "http://x", code, "boom", {}, io.BytesIO(b'{"error":"boom"}')
    )


def test_endpoint_is_expanded_into_a_query_url():
    assert ClientConfig(endpoint="http://h:8443").query_url == "http://h:8443/v1/graphs/default/query"
    assert ClientConfig(endpoint="http://h:8443/", graph="g").query_url.endswith("/graphs/g/query")
    # An already-complete URL is left alone.
    full = "http://h:8443/v1/graphs/other/query"
    assert ClientConfig(endpoint=full).query_url == full


def test_env_overrides_every_connection_field():
    config = ClientConfig.from_env(
        {
            "HINDSIGHT_HYDRA_URL": "http://node:9",
            "HINDSIGHT_HYDRA_TOKEN": "t",
            "HINDSIGHT_HYDRA_NS": "ns",
            "HINDSIGHT_HYDRA_GRAPH": "g",
            "HINDSIGHT_HYDRA_CELL": "cell-0",
            "HINDSIGHT_HYDRA_RETRIES": "2",
        }
    )
    assert (config.endpoint, config.token, config.namespace) == ("http://node:9", "t", "ns")
    assert (config.graph, config.cell, config.max_retries) == ("g", "cell-0", 2)


def test_poc_era_env_names_still_work():
    config = ClientConfig.from_env({"HYDRA_URL": "http://old:1", "HYDRA_TOKEN": "legacy"})
    assert config.endpoint == "http://old:1"
    assert config.token == "legacy"


def test_request_carries_the_cell_and_parameters(monkeypatch):
    rec = Recorder([{"rows": [[{"type": "integer", "value": 1}]]}])
    monkeypatch.setattr(client_mod.urllib.request, "urlopen", rec)
    client = HydraClient(ClientConfig(cell="cell-0"))
    assert client.rows("RETURN 1", {"a": 2}) == [[1]]
    assert rec.calls[0] == {"cell_id": "cell-0", "query": "RETURN 1", "parameters": {"a": 2}}


def test_page_size_is_clamped_to_the_server_limit(monkeypatch):
    rec = Recorder([{"rows": [], "next_cursor": None}])
    monkeypatch.setattr(client_mod.urllib.request, "urlopen", rec)
    HydraClient().query("RETURN 1", page_size=100_000)
    assert rec.calls[0]["page_size"] == MAX_PAGE_SIZE


@pytest.mark.parametrize("status", [429, 503, 502, 504, 500])
def test_transient_statuses_are_retried(monkeypatch, no_sleep, status):
    rec = Recorder([http_error(status), {"rows": [[{"value": "ok"}]]}])
    monkeypatch.setattr(client_mod.urllib.request, "urlopen", rec)
    client = HydraClient()
    assert client.rows("RETURN 1") == [["ok"]]
    assert client.stats["retries"] == 1


def test_permanent_errors_are_not_retried(monkeypatch, no_sleep):
    rec = Recorder([http_error(400), {"rows": []}])
    monkeypatch.setattr(client_mod.urllib.request, "urlopen", rec)
    with pytest.raises(HydraError) as exc:
        HydraClient().query("BAD")
    assert exc.value.status == 400
    assert len(rec.calls) == 1


def test_retries_are_bounded(monkeypatch, no_sleep):
    rec = Recorder([http_error(503)] * 3)
    monkeypatch.setattr(client_mod.urllib.request, "urlopen", rec)
    with pytest.raises(HydraError):
        HydraClient(ClientConfig(max_retries=2)).query("RETURN 1")
    assert len(rec.calls) == 3


def test_transport_errors_are_retried_then_surfaced(monkeypatch, no_sleep):
    rec = Recorder([urllib.error.URLError("down"), {"rows": [[{"value": 7}]]}])
    monkeypatch.setattr(client_mod.urllib.request, "urlopen", rec)
    assert HydraClient().scalar("RETURN 7") == 7


def test_all_rows_follows_the_cursor(monkeypatch):
    rec = Recorder(
        [
            {"rows": [[{"value": "a"}]], "next_cursor": "c1"},
            {"rows": [[{"value": "b"}]], "next_cursor": None},
        ]
    )
    monkeypatch.setattr(client_mod.urllib.request, "urlopen", rec)
    assert HydraClient().all_rows("RETURN x") == [["a"], ["b"]]
    assert rec.calls[1]["cursor"] == "c1"


def test_ping_reports_reachability(monkeypatch, no_sleep):
    monkeypatch.setattr(client_mod.urllib.request, "urlopen", Recorder([{"rows": [[1]]}]))
    assert HydraClient().ping() is True
    monkeypatch.setattr(
        client_mod.urllib.request, "urlopen", Recorder([http_error(401)])
    )
    assert HydraClient().ping() is False


def test_cells_are_unwrapped_but_plain_values_pass_through():
    assert unwrap({"type": "integer", "value": 5}) == 5
    assert unwrap("plain") == "plain"
    assert rows_of({"rows": [[{"value": 1}, "raw"]]}) == [[1, "raw"]]
    assert rows_of({}) == []
