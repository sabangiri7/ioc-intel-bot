"""Tests for the polite HTTP Fetcher (iocbot/http.py).

Focus: retry behaviour, stale-if-error fallback, size cap, and cache hits.
"""
import time

import pytest
import requests

from iocbot.http import Fetcher


class FakeResponse:
    """Minimal stand-in for requests.Response streamed by Fetcher.get."""

    def __init__(self, chunks=(b"ok",), status_code=200):
        self._chunks = list(chunks)
        self.status_code = status_code

    def iter_content(self, chunk_size=65536):
        for c in self._chunks:
            yield c


@pytest.fixture
def fetcher(tmp_path):
    # rate=0 disables the per-host politeness sleep so tests stay fast.
    return Fetcher(tmp_path / "raw", rate=0, retries=2)


def test_get_returns_bytes_on_success(fetcher, monkeypatch):
    calls = {"n": 0}

    def fake_get(url, **kwargs):
        calls["n"] += 1
        return FakeResponse([b"hello ", b"world"])

    monkeypatch.setattr(fetcher.session, "get", fake_get)
    monkeypatch.setattr(time, "sleep", lambda *_: None)

    assert fetcher.get("https://example.test/a") == b"hello world"
    assert calls["n"] == 1


def test_retries_on_transient_error_then_succeeds(fetcher, monkeypatch):
    """Transient failure: first attempt raises, second succeeds (2 attempts)."""
    seq = [requests.ConnectionError("boom"), FakeResponse([b"ok"])]
    calls = {"n": 0}

    def fake_get(url, **kwargs):
        r = seq[calls["n"]]
        calls["n"] += 1
        if isinstance(r, Exception):
            raise r
        return r

    monkeypatch.setattr(fetcher.session, "get", fake_get)
    monkeypatch.setattr(time, "sleep", lambda *_: None)

    assert fetcher.get("https://example.test/a") == b"ok"
    assert calls["n"] == 2


def test_gives_up_after_max_retries(fetcher, monkeypatch):
    calls = {"n": 0}

    def fake_get(url, **kwargs):
        calls["n"] += 1
        raise requests.ConnectionError("down")

    monkeypatch.setattr(fetcher.session, "get", fake_get)
    monkeypatch.setattr(time, "sleep", lambda *_: None)

    assert fetcher.get("https://example.test/a") is None
    assert calls["n"] == fetcher.retries


def test_does_not_retry_on_permanent_404(fetcher, monkeypatch):
    """404 is terminal: the loop breaks after the first attempt."""
    calls = {"n": 0}

    def fake_get(url, **kwargs):
        calls["n"] += 1
        return FakeResponse(status_code=404)

    monkeypatch.setattr(fetcher.session, "get", fake_get)
    monkeypatch.setattr(time, "sleep", lambda *_: None)

    assert fetcher.get("https://example.test/missing") is None
    assert calls["n"] == 1


def test_stale_if_error_falls_back_to_cache(fetcher, monkeypatch):
    """A fresh fetch fails but a previously cached copy is returned."""
    url = "https://example.test/cached"
    path = fetcher._raw_path(url)
    path.write_bytes(b"stale-body")

    def fake_get(url, **kwargs):
        raise requests.ConnectionError("net down")

    monkeypatch.setattr(fetcher.session, "get", fake_get)
    monkeypatch.setattr(time, "sleep", lambda *_: None)

    assert fetcher.get(url) == b"stale-body"


def test_cache_hit_skips_network(fetcher, monkeypatch):
    """A fresh cache entry is served without touching the network."""
    url = "https://example.test/fresh"
    fetcher._raw_path(url).write_bytes(b"cached")

    def boom(*a, **k):
        raise AssertionError("network must not be used on a cache hit")

    monkeypatch.setattr(fetcher.session, "get", boom)

    assert fetcher.get(url, use_cache=True) == b"cached"


def test_expired_cache_triggers_fetch(fetcher, monkeypatch):
    url = "https://example.test/stale"
    path = fetcher._raw_path(url)
    path.write_bytes(b"old")
    # age the cache beyond any max_age
    old = time.time() - 10 * 86400
    import os
    os.utime(path, (old, old))

    monkeypatch.setattr(fetcher.session, "get",
                        lambda url, **kw: FakeResponse([b"new"]))
    monkeypatch.setattr(time, "sleep", lambda *_: None)

    assert fetcher.get(url, use_cache=True, cache_max_age=86400) == b"new"


def test_size_cap_truncates(fetcher, monkeypatch):
    """The cap stops the download; overshoot is bounded by one chunk.

    The size check runs *after* each chunk is appended, so the response is
    truncated at a chunk boundary rather than sliced exactly at the cap.
    """
    monkeypatch.setattr(fetcher.session, "get",
                        lambda url, **kw: FakeResponse([b"a" * 10, b"b" * 10]))
    monkeypatch.setattr(time, "sleep", lambda *_: None)

    data = fetcher.get("https://example.test/big", max_bytes=5)
    # First chunk (10 bytes) already exceeds the cap -> loop breaks immediately,
    # so the second chunk is never consumed. Result is > cap but far below the
    # full 20-byte payload.
    assert 5 < len(data) < 20


@pytest.mark.parametrize("payload,expected", [
    (b"plain", "plain"),
    # non-utf8 bytes: utf-8 fails, falls through to latin-1
    ("café".encode("latin-1"), "café"),
])
def test_get_text_decodes(fetcher, monkeypatch, payload, expected):
    monkeypatch.setattr(fetcher.session, "get",
                        lambda url, **kw: FakeResponse([payload]))
    monkeypatch.setattr(time, "sleep", lambda *_: None)
    assert fetcher.get_text("https://example.test/t") == expected


def test_get_text_keeps_bom_when_utf8_succeeds(fetcher, monkeypatch):
    """utf-8 is tried first, so a UTF-8 BOM is retained, not stripped."""
    payload = "﻿text".encode("utf-8")
    monkeypatch.setattr(fetcher.session, "get",
                        lambda url, **kw: FakeResponse([payload]))
    monkeypatch.setattr(time, "sleep", lambda *_: None)
    assert fetcher.get_text("https://example.test/bom") == "﻿text"