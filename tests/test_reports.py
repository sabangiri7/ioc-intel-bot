"""Tests for Tier-B report collection (iocbot/collectors/reports.py).

Focus: the relevance gate (articles are filtered on title+summary BEFORE the
body is fetched), the max_articles cap, and feed-fetch failure handling.
Uses a real RSS payload parsed by feedparser, so no network is involved.
"""
from datetime import datetime, timedelta, timezone

from iocbot.collectors.reports import collect_reports


RSS = """<?xml version="1.0"?>
<rss version="2.0"><channel>
  <title>Test Feed</title>
  <item>
    <title>New Mirai botnet malware C2 infrastructure observed</title>
    <link>https://vendor.test/mirai-report</link>
    <description>Researchers detail a new Mirai botnet variant.</description>
    <pubDate>{recent}</pubDate>
  </item>
  <item>
    <title>Ten practical tips for better team lunches</title>
    <link>https://blog.test/lunch</link>
    <description>Sandwich recommendations and office etiquette.</description>
    <pubDate>{recent}</pubDate>
  </item>
  <item>
    <title>Emotet ransomware dropper analysis</title>
    <link>https://vendor.test/emotet</link>
    <description>Emotet malware campaign phishing analysis.</description>
    <pubDate>{old}</pubDate>
  </item>
</channel></rss>
"""

ARTICLE = "<html><body><p>The C2 server evil.example resolves the payload.</p></body></html>"


class FeedFetcher:
    """Serves the RSS for the feed URL and a fixed article body otherwise."""

    def __init__(self, recent, old):
        self.rss = RSS.format(recent=recent, old=old)
        self.requested = []

    def get_text(self, url, **kwargs):
        self.requested.append(url)
        if url.endswith("feed.xml"):
            return self.rss
        return ARTICLE


def _rfc822(dt):
    return dt.strftime("%a, %d %b %Y %H:%M:%S +0000")


def _cfg(**kw):
    base = {"name": "Vendor Blog", "url": "https://vendor.test/feed.xml", "tier": "B",
            "max_articles": 8, "max_age_days": 21}
    base.update(kw)
    return base


def _fetcher():
    now = datetime.now(timezone.utc)
    return FeedFetcher(_rfc822(now - timedelta(days=1)), _rfc822(now - timedelta(days=200)))


def test_relevance_gate_filters_irrelevant_articles():
    """The lunch article must never be fetched (relevance gate on title+summary)."""
    f = _fetcher()
    mentions, stats = collect_reports(_cfg(), f)
    assert stats["fetched"] is True
    assert stats["relevant"] == 1  # only the Mirai article is relevant
    assert stats["articles"] == 1
    # the irrelevant URL was never requested
    assert not any("lunch" in u for u in f.requested)


def test_stale_article_skipped_by_age_window():
    """The 200-day-old Emotet item is relevant but outside max_age_days."""
    f = _fetcher()
    _, stats = collect_reports(_cfg(max_age_days=21), f)
    assert stats["relevant"] == 1  # Mirai (1 day) only; Emotet (200d) excluded


def test_old_article_included_when_window_is_wide():
    f = _fetcher()
    _, stats = collect_reports(_cfg(max_age_days=365), f)
    assert stats["relevant"] == 2  # Mirai + Emotet


def test_max_articles_caps_fetched_articles():
    f = _fetcher()
    _, stats = collect_reports(_cfg(max_articles=1), f)
    assert stats["articles"] <= 1


def test_per_cycle_max_articles_only_lowers_cap():
    """--max-articles lowers the per-feed cap; it never raises it."""
    f = _fetcher()
    _, stats = collect_reports(_cfg(max_articles=8), f, max_articles=0)
    assert stats["articles"] == 0


def test_extracts_infra_from_relevant_article():
    f = _fetcher()
    mentions, _ = collect_reports(_cfg(), f)
    values = {m.value for m in mentions}
    assert "evil.example" in values  # host from the article body


def test_feed_fetch_failure_returns_no_mentions():
    class DeadFetcher:
        def get_text(self, url, **kwargs):
            return None

    mentions, stats = collect_reports(_cfg(), DeadFetcher())
    assert mentions == []
    assert stats["fetched"] is False
    assert "feed fetch failed" in stats["errors"]