from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone

import feedparser

from ..classify import (
    CATEGORIES_BY_PRIORITY,
    LEGIT_SENTENCE_RE,
    MALICIOUS_SENTENCE_RE,
    RELEVANCE_RE,
    article_flags,
    category_for_family,
    sentence_categories,
)
from ..extract import extract, refang
from ..models import Mention

log = logging.getLogger("iocbot.reports")

EXTRA_CATEGORIES_RE = re.compile(
    r"smokeloader|gu(?:loader)?loader|qakbot|qbot|emotet|icedid|bumblebee|pikabot|"
    r"lumma|redline|raccoon|vidar|stealc|asyncrat|njrat|cobalt strike|mythic|"
    r"sliver|havoc|mirai|mozi|gafgyt|lockbit|alphv|blackcat|cl0p|royal|akira|"
    r"medusa|conti|ryuk|revil|trickbot|dridex|agent tesla|lokibot|formbook|"
    r"darkgate|formbook|hijackloader|socgholish|clearfake",
    re.I,
)

_ARTICLE_FALLBACK = ("RANSOMWARE", "C2", "MALWARE-DISTRIBUTION", "MALWARE")
INFRA_TYPES = {"IPv4", "IPv6", "Domain", "URL"}


def _entry_date(entry) -> datetime:
    parsed = entry.get("published_parsed") or entry.get("updated_parsed")
    if parsed:
        return datetime(*parsed[:6], tzinfo=timezone.utc)
    return datetime.now(timezone.utc)


def _html_to_text(html: str) -> str:
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(html, "lxml")
    for tag in soup(["script", "style", "nav", "header", "footer", "aside", "figure", "form", "noscript"]):
        tag.decompose()
    root = soup.find("article") or soup.body or soup
    text = root.get_text("\n")
    lines = [ln.strip() for ln in text.splitlines()]
    lines = [ln for ln in lines if ln]
    out = "\n".join(lines)
    return re.sub(r"\n{3,}", "\n\n", out)[:400_000]


def collect_reports(cfg: dict, fetcher, mitre=None, max_articles: int | None = None) -> tuple[list[Mention], dict]:
    feed_name = cfg["name"]
    tier = cfg.get("tier", "B")
    stats = {"source": feed_name, "kind": "report", "fetched": False, "entries": 0,
             "relevant": 0, "articles": 0, "mentions": 0, "errors": []}
    text = fetcher.get_text(cfg["url"], use_cache=True, cache_max_age=3600)
    if text is None:
        stats["errors"].append("feed fetch failed")
        return [], stats
    stats["fetched"] = True
    feed = feedparser.parse(text)
    stats["entries"] = len(feed.entries)
    if feed.bozo and not feed.entries:
        stats["errors"].append("feed parse failed")
        return [], stats

    max_age = int(cfg.get("max_age_days", 21))
    per_feed_cap = int(cfg.get("max_articles", 8))
    if max_articles is not None:
        per_feed_cap = min(per_feed_cap, max_articles)
    cutoff = datetime.now(timezone.utc) - timedelta(days=max_age)

    mentions: list[Mention] = []
    considered = 0
    for entry in feed.entries:
        if considered >= per_feed_cap:
            break
        title = (entry.get("title") or "").strip()
        summary = (entry.get("summary") or "").strip()
        link = (entry.get("link") or "").strip()
        blob = refang(f"{title}\n{summary}")
        if not RELEVANCE_RE.search(blob):
            continue
        edate = _entry_date(entry)
        if edate < cutoff:
            continue
        if not link:
            continue
        considered += 1
        stats["relevant"] += 1

        article_html = fetcher.get_text(link, use_cache=True, cache_max_age=7 * 86400)
        if article_html:
            body = _html_to_text(article_html)
            stats["articles"] += 1
        else:
            body = summary
        full_text = refang(f"{title}\n\n{body}")
        if not full_text.strip():
            continue

        aflags = article_flags(full_text)
        article_cats = aflags["categories"]
        if EXTRA_CATEGORIES_RE.search(full_text):
            for m in EXTRA_CATEGORIES_RE.finditer(full_text):
                cat = category_for_family(m.group(0))
                if cat and cat not in article_cats:
                    article_cats.append(cat)
        actors = mitre.find_actors(full_text) if mitre is not None else []
        date_str = edate.strftime("%Y-%m-%d")

        exs = extract(full_text)
        for ex in exs:
            sent = ex.context or ""
            sent_cats = sentence_categories(sent)
            # sentence-scoped family attribution
            family = ""
            sent_low = sent.lower()
            for fam in aflags["families"]:
                if fam in sent_low:
                    family = fam
                    break
            if family:
                fcat = category_for_family(family)
                if fcat and fcat not in sent_cats:
                    sent_cats.append(fcat)

            infra = ex.ioc_type in INFRA_TYPES
            explicit_c2 = "C2" in sent_cats
            explicit_malware = bool(MALICIOUS_SENTENCE_RE.search(sent))

            if ex.ioc_type == "CVE":
                cats = sent_cats or [c for c in article_cats if c in _ARTICLE_FALLBACK][:1] or ["OTHER"]
            elif not sent_cats:
                # no threat context in the sentence mentioning this IOC -> skip
                continue
            else:
                cats = sent_cats[:4]

            actor_name = ""
            if mitre is not None and sent:
                sactors = mitre.find_actors(sent)
                if len(sactors) == 1:
                    actor_name = sactors[0].get("name", "")

            mtags = ["report"]
            if LEGIT_SENTENCE_RE.search(sent):
                mtags.append("legit-service-abused")

            description = f"{title} — {sent}" if sent else title
            mentions.append(Mention(
                value=ex.value, ioc_type=ex.ioc_type,
                source_name=feed_name, source_url=link, tier=tier,
                first_seen=date_str, last_seen=date_str,
                explicit_c2=explicit_c2, explicit_malware=explicit_malware,
                active=True if infra else None,
                malware_family=family,
                threat_actor=actor_name,
                categories=cats,
                tags=mtags,
                threat="",
                description=description[:400],
                evidence=sent[:300],
                derived=ex.derived,
            ))

        for fam in aflags["families"][:6]:
            fcat = category_for_family(fam)
            mentions.append(Mention(
                value=fam, ioc_type="Malware",
                source_name=feed_name, source_url=link, tier=tier,
                first_seen=date_str, last_seen=date_str,
                explicit_malware=True,
                categories=[fcat] if fcat else ["MALWARE"],
                tags=["malware-family", "report"],
                threat="Malware family",
                description=f"Family referenced in {title}"[:300],
            ))

        for act in actors[:4]:
            gname = act.get("name", "")
            gid = act.get("id", "")
            if not gname:
                continue
            mentions.append(Mention(
                value=gname, ioc_type="Threat-Actor",
                source_name=feed_name, source_url=link, tier=tier,
                first_seen=date_str, last_seen=date_str,
                explicit_malware=True,
                categories=["APT"],
                tags=["threat-actor"] + ([gid] if gid else []),
                threat="Threat actor",
                description=f"Actor referenced in {title}"[:300],
            ))

    stats["mentions"] = len(mentions)
    return mentions, stats
