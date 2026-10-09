from __future__ import annotations

from datetime import date, datetime

from .classify import CATEGORIES_BY_PRIORITY
from .models import CONFIDENCE_ORDER, SEVERITY_ORDER

CS_SUPPORTED_TYPES = {"IPv4", "IPv6", "Domain", "SHA256", "MD5"}
CONFIDENCE_THRESHOLDS = ("MEDIUM", "HIGH", "CRITICAL")
SEVERITY_THRESHOLDS = ("MEDIUM", "HIGH", "CRITICAL")

_ACTIVE_DAYS = 30
_STALE_DAYS = 180
_VERY_STALE_DAYS = 365


def _parse_day(value: str) -> date | None:
    if not value:
        return None
    try:
        return datetime.strptime(value[:10], "%Y-%m-%d").date()
    except ValueError:
        return None


def _points_for_source(src: dict) -> int:
    tier = src.get("tier", "B")
    explicit = bool(src.get("explicit_c2") or src.get("explicit_malware"))
    if tier == "A":
        return 3
    if tier == "B":
        return 2 if explicit else 1
    return 0


def score_row(row: dict) -> dict:
    sources = row.get("sources_detail") or []
    categories = row.get("categories") or []
    ioc_type = row.get("ioc_type", "")
    validation = row.get("validation_status", "")

    points = 0
    publishers = set()
    any_explicit_c2 = False
    any_explicit_malware = False
    active = False
    feed_conf_min = None
    has_tier_a = False
    for src in sources:
        pts = _points_for_source(src)
        if pts:
            points += pts
        if src.get("name"):
            publishers.add(src["name"])
        if src.get("explicit_c2"):
            any_explicit_c2 = True
        if src.get("explicit_malware"):
            any_explicit_malware = True
        if src.get("active") is True:
            active = True
        if src.get("tier") == "A":
            has_tier_a = True
        fc = src.get("feed_confidence")
        if fc is not None:
            feed_conf_min = fc if feed_conf_min is None else min(feed_conf_min, fc)
    if len(publishers) >= 2:
        points += 1

    if points >= 6:
        confidence = "CRITICAL"
    elif points >= 3:
        confidence = "HIGH"
    elif points >= 2:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    if feed_conf_min is not None and feed_conf_min < 50:
        confidence = "MEDIUM" if CONFIDENCE_ORDER[confidence] > CONFIDENCE_ORDER["MEDIUM"] else confidence
    if len(publishers) == 1 and sources and sources[0].get("tier") == "C":
        confidence = "LOW"

    last_seen = _parse_day(row.get("last_seen", ""))
    first_seen = _parse_day(row.get("first_seen", ""))
    ref = last_seen or first_seen
    age_days = (date.today() - ref).days if ref else None

    if ioc_type == "CVE":
        severity = "HIGH"
        confidence = "HIGH" if has_tier_a or len(publishers) >= 2 else confidence
    elif "C2" in categories:
        if active or (age_days is not None and age_days <= _ACTIVE_DAYS):
            severity = "CRITICAL"
        elif age_days is not None and age_days > _VERY_STALE_DAYS:
            severity = "LOW"
        elif age_days is not None and age_days > _STALE_DAYS:
            severity = "MEDIUM"
        else:
            severity = "HIGH"
    elif "RANSOMWARE" in categories and has_tier_a:
        severity = "HIGH"
    elif any_explicit_malware or any_explicit_c2:
        severity = "HIGH"
    elif confidence == "MEDIUM":
        severity = "MEDIUM"
    else:
        severity = "LOW"

    if severity in ("MEDIUM", "HIGH") and age_days is not None and age_days > _STALE_DAYS:
        severity = "LOW" if age_days > _VERY_STALE_DAYS else "MEDIUM"
    if confidence == "LOW":
        severity = "LOW" if SEVERITY_ORDER[severity] > SEVERITY_ORDER["LOW"] else severity
    if categories == ["OTHER"] or categories == []:
        severity = "LOW" if has_tier_a is False and confidence == "LOW" else severity

    tier_c_only = bool(sources) and all(s.get("tier") == "C" for s in sources)
    if tier_c_only:
        confidence = "LOW"
        severity = "LOW"

    row_tags = set(row.get("tags_list") or [])
    blocked_tags = {"shared-platform", "legit-service-abused", "generic-vendor", "cdn"}
    if "legit-service-abused" in row_tags and SEVERITY_ORDER[severity] > SEVERITY_ORDER["MEDIUM"]:
        severity = "MEDIUM"

    crowdstrike_supported = ioc_type in CS_SUPPORTED_TYPES
    crowdstrike_importable = bool(
        crowdstrike_supported
        and validation == "VALID"
        and confidence in CONFIDENCE_THRESHOLDS
        and severity in SEVERITY_THRESHOLDS
        and not (row_tags & blocked_tags)
    )

    if not categories:
        categories = ["OTHER"]

    threat = compose_threat_safe(categories, row.get("malware_family", ""))

    row["confidence"] = confidence
    row["severity"] = severity
    row["crowdstrike_supported"] = "YES" if crowdstrike_supported else "NO"
    row["crowdstrike_importable"] = "YES" if crowdstrike_importable else "NO"
    row["threat"] = row.get("threat") or threat
    if not row.get("threat"):
        row["threat"] = threat
    return row


def compose_threat_safe(categories, family):
    from .classify import compose_threat

    return compose_threat(categories or [], family or "")


def priority_categories(categories: list[str]) -> list[str]:
    seen = sorted(set(categories), key=lambda c: CATEGORIES_BY_PRIORITY.index(c)
                  if c in CATEGORIES_BY_PRIORITY else 99)
    return seen
