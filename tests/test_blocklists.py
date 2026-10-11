"""Tests for Tier-C blocklist collectors (iocbot/collectors/blocklists.py).

Focus: comment/CIDR/malformed filtering, max_entries truncation, fetch-failure
handling, and the tags/categories each mention must carry.
"""
import pytest

from iocbot.collectors.blocklists import (
    collect_domain_list,
    collect_ip_list,
    collect_url_list,
)


class FakeFetcher:
    """Returns a canned body (or None to simulate a failed download)."""

    def __init__(self, text):
        self._text = text
        self.calls = []

    def get_text(self, url, **kwargs):
        self.calls.append(url)
        return self._text


IP_LIST = """\
# Emerging Threats Compromised IPs
# Updated: 2026-10-07
203.0.113.5
198.51.100.22
10.0.0.1
999.1.1.1
192.0.2.0/24
203.0.113.5
; a semicolon comment
203.0.113.9   # trailing comment
not-an-ip
"""


def test_ip_list_filters_comments_cidrs_and_bad_octets():
    mentions, stats = collect_ip_list(
        {"name": "ET Comp", "url": "https://x/ips", "tier": "C"}, FakeFetcher(IP_LIST)
    )
    values = {m.value for m in mentions}
    # The parser only checks IPv4 syntax and octet range -- it does NOT reject
    # private/reserved space. That is the Validator's job (see test_validate.py),
    # so 10.0.0.1 is expected here and dropped downstream.
    assert values == {"203.0.113.5", "198.51.100.22", "10.0.0.1", "203.0.113.9"}
    assert "999.1.1.1" not in values   # invalid octet
    assert "192.0.2.0/24" not in values  # CIDR skipped
    assert "not-an-ip" not in values
    assert stats["fetched"] and stats["mentions"] == 4


def test_ip_list_respects_max_entries():
    mentions, stats = collect_ip_list(
        {"name": "ET Comp", "url": "https://x/ips", "max_entries": 2}, FakeFetcher(IP_LIST)
    )
    assert stats["mentions"] == 2
    # truncation keeps the lexicographically first N after sorting
    assert [m.value for m in mentions] == ["10.0.0.1", "198.51.100.22"]


def test_ip_list_carries_blocklist_tags_and_feed_date():
    mentions, _ = collect_ip_list(
        {"name": "ET Comp", "url": "https://x/ips"}, FakeFetcher(IP_LIST)
    )
    m = mentions[0]
    assert m.tags == ["blocklist", "context-only"]
    assert m.categories == ["OTHER"]
    assert m.tier == "C"
    assert m.first_seen == "2026-10-07"  # parsed from the comment header
    assert m.explicit_malware is False


def test_fetch_failure_returns_no_mentions_and_error():
    mentions, stats = collect_ip_list(
        {"name": "ET Comp", "url": "https://x/ips"}, FakeFetcher(None)
    )
    assert mentions == []
    assert stats["fetched"] is False
    assert "download failed" in stats["errors"]


DOMAIN_LIST = """\
# comment
evil.example
GOOD.EXAMPLE.ORG
has space.example
192.0.2.0/24
nodot
"""


def test_domain_list_lowercases_and_filters():
    mentions, stats = collect_domain_list(
        {"name": "ISC", "url": "https://x/doms"}, FakeFetcher(DOMAIN_LIST)
    )
    values = {m.value for m in mentions}
    assert "good.example.org" in values
    assert "has space.example" not in values
    assert "192.0.2.0/24" not in values
    assert "nodot" not in values  # no dot -> not a domain


def test_url_list_phishing_category_for_phish_sources():
    body = "https://bad.example/login\nhttp://x.example\nnot-a-url\n"
    # source name contains "phish" -> PHISHING category
    mentions, _ = collect_url_list(
        {"name": "OpenPhish feed", "url": "https://x/urls"}, FakeFetcher(body)
    )
    assert all(m.categories == ["PHISHING"] for m in mentions)
    assert {m.value for m in mentions} == {"https://bad.example/login", "http://x.example"}


def test_url_list_other_category_for_non_phish_sources():
    body = "https://bad.example/login\n"
    mentions, _ = collect_url_list(
        {"name": "ISC", "url": "https://x/urls"}, FakeFetcher(body)
    )
    assert mentions[0].categories == ["OTHER"]


@pytest.mark.parametrize("collector", [collect_ip_list, collect_domain_list, collect_url_list])
def test_all_collectors_handle_empty_body(collector):
    mentions, stats = collector({"name": "src", "url": "https://x"}, FakeFetcher(""))
    assert mentions == []
    assert stats["entries"] == 0 and stats["fetched"] is True