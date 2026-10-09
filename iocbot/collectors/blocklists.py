from __future__ import annotations

import logging
import re

from ..models import Mention

log = logging.getLogger("iocbot.blocklists")

_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


def _comment_date(text: str) -> str:
    m = _DATE.search(text)
    return m.group(0) if m else ""


def collect_ip_list(cfg: dict, fetcher) -> tuple[list[Mention], dict]:
    stats = {"source": cfg["name"], "kind": "ip_list", "fetched": False, "entries": 0, "mentions": 0, "errors": []}
    text = fetcher.get_text(cfg["url"])
    if text is None:
        stats["errors"].append("download failed")
        return [], stats
    stats["fetched"] = True
    feed_date = _comment_date(text)
    ips: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        token = line.split()[0].split("#")[0].strip()
        if "/" in token:
            continue
        if _IPV4.match(token):
            octets = token.split(".")
            if all(0 <= int(o) <= 255 for o in octets):
                ips.add(token)
    max_entries = int(cfg.get("max_entries") or 0)
    if max_entries:
        ips = set(sorted(ips)[:max_entries])
    stats["entries"] = len(ips)
    mentions = [
        Mention(
            value=ip, ioc_type="IPv4",
            source_name=cfg["name"], source_url=cfg["url"], tier=cfg.get("tier", "C"),
            first_seen=feed_date, last_seen="",
            explicit_malware=False,
            categories=["OTHER"], tags=["blocklist", "context-only"],
            threat="Aggregated suspicious IP",
            description=f"{cfg['name']} aggregated blocklist entry",
            evidence=f"{cfg['name']}: listed in feed",
        )
        for ip in sorted(ips)
    ]
    stats["mentions"] = len(mentions)
    return mentions, stats


def collect_domain_list(cfg: dict, fetcher) -> tuple[list[Mention], dict]:
    stats = {"source": cfg["name"], "kind": "domain_list", "fetched": False, "entries": 0, "mentions": 0, "errors": []}
    text = fetcher.get_text(cfg["url"])
    if text is None:
        stats["errors"].append("download failed")
        return [], stats
    stats["fetched"] = True
    domains: set[str] = set()
    for line in text.splitlines():
        line = line.strip().lower()
        if not line or line.startswith("#") or line.startswith(";") or "/" in line or " " in line:
            continue
        if "." in line and len(line) < 253:
            domains.add(line)
    max_entries = int(cfg.get("max_entries") or 0)
    if max_entries:
        domains = set(sorted(domains)[:max_entries])
    stats["entries"] = len(domains)
    mentions = [
        Mention(
            value=d, ioc_type="Domain",
            source_name=cfg["name"], source_url=cfg["url"], tier=cfg.get("tier", "C"),
            categories=["OTHER"], tags=["blocklist", "context-only"],
            threat="Aggregated suspicious domain",
            description=f"{cfg['name']} aggregated suspicious domain list",
            evidence=f"{cfg['name']}: listed in feed",
        )
        for d in sorted(domains)
    ]
    stats["mentions"] = len(mentions)
    return mentions, stats


def collect_url_list(cfg: dict, fetcher) -> tuple[list[Mention], dict]:
    stats = {"source": cfg["name"], "kind": "url_list", "fetched": False, "entries": 0, "mentions": 0, "errors": []}
    text = fetcher.get_text(cfg["url"])
    if text is None:
        stats["errors"].append("download failed")
        return [], stats
    stats["fetched"] = True
    urls: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("<"):
            continue
        if line.startswith(("http://", "https://")):
            urls.add(line)
    max_entries = int(cfg.get("max_entries") or 0)
    if max_entries:
        urls = set(sorted(urls)[:max_entries])
    stats["entries"] = len(urls)
    mentions = [
        Mention(
            value=u, ioc_type="URL",
            source_name=cfg["name"], source_url=cfg["url"], tier=cfg.get("tier", "C"),
            categories=["PHISHING"] if "phish" in cfg["name"].lower() else ["OTHER"],
            tags=["blocklist", "context-only"],
            threat="Aggregated suspicious URL",
            description=f"{cfg['name']} aggregated URL feed",
            evidence=f"{cfg['name']}: listed in feed",
        )
        for u in sorted(urls)
    ]
    stats["mentions"] = len(mentions)
    return mentions, stats
