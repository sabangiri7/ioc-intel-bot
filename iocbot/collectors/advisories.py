from __future__ import annotations

import json
import logging

from ..models import Mention

log = logging.getLogger("iocbot.advisories")


def collect_cisa_kev(cfg: dict, fetcher) -> tuple[list[Mention], dict]:
    stats = {"source": cfg["name"], "kind": "cisa_kev", "fetched": False, "entries": 0, "mentions": 0, "errors": []}
    data = fetcher.get(cfg["url"], use_cache=True, cache_max_age=6 * 3600, max_bytes=10 * 1024 * 1024)
    if data is None:
        stats["errors"].append("download failed")
        return [], stats
    stats["fetched"] = True
    try:
        payload = json.loads(data.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        stats["errors"].append(f"parse: {exc}")
        return [], stats
    vulns = payload.get("vulnerabilities", [])
    stats["entries"] = len(vulns)
    mentions: list[Mention] = []
    for v in vulns:
        cve = (v.get("cveID") or "").strip().upper()
        if not cve.startswith("CVE-"):
            continue
        date_added = (v.get("dateAdded") or "")[:10]
        product = f"{v.get('vendorProject', '')} {v.get('product', '')}".strip()
        name = v.get("vulnerabilityName", "")
        ransomware = v.get("knownRansomwareCampaignUse", "")
        tags = ["cisa-kev", "known-exploited"]
        if product:
            tags.append(f"product:{product}")
        if str(ransomware).lower() == "known":
            tags.append("ransomware-use")
        desc = name
        if product:
            desc = f"{name} ({product})"
        cats = ["RANSOMWARE"] if str(ransomware).lower() == "known" else ["OTHER"]
        mentions.append(Mention(
            value=cve, ioc_type="CVE",
            source_name=cfg["name"], source_url=cfg["url"],
            tier=cfg.get("tier", "A"),
            first_seen=date_added, last_seen=date_added,
            explicit_malware=False, categories=cats, tags=tags,
            threat="Known Exploited Vulnerability", description=desc,
            evidence=f"CISA KEV: {cve} added {date_added}",
        ))
    stats["mentions"] = len(mentions)
    return mentions, stats
