from __future__ import annotations

from dataclasses import dataclass, field

IOC_TYPES = (
    "IPv4",
    "IPv6",
    "Domain",
    "URL",
    "SHA256",
    "SHA1",
    "MD5",
    "Email",
    "File-Name",
    "File-Path",
    "CVE",
    "Malware",
    "Threat-Actor",
    "Campaign",
)

MASTER_COLUMNS = [
    "IOC",
    "IOC_TYPE",
    "THREAT",
    "MALWARE_FAMILY",
    "THREAT_ACTOR",
    "CAMPAIGN",
    "CATEGORY",
    "CONFIDENCE",
    "SEVERITY",
    "FIRST_SEEN",
    "LAST_SEEN",
    "SOURCE",
    "SOURCE_URL",
    "DESCRIPTION",
    "TAGS",
    "MITRE_ATTACK",
    "CROWDSTRIKE_SUPPORTED",
    "CROWDSTRIKE_IMPORTABLE",
    "VALIDATION_STATUS",
]

CS_EXPORT_COLUMNS = [
    "type",
    "value",
    "action",
    "severity",
    "source",
    "description",
    "expiration",
    "platforms",
    "tags",
]

CONFIDENCE_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

CATEGORIES = [
    "C2",
    "MALWARE",
    "MALWARE-DISTRIBUTION",
    "CRACKED-SOFTWARE",
    "PIRATED-SOFTWARE",
    "FAKE-SOFTWARE",
    "FAKE-UPDATE",
    "INFOSTEALER",
    "RAT",
    "LOADER",
    "BOTNET",
    "RANSOMWARE",
    "PHISHING",
    "PAYLOAD-HOSTING",
    "REDIRECTOR",
    "APT",
    "OTHER",
]

# Categories that make up the "malware distribution" view (flag_malware column).
MALWARE_VIEW_CATEGORIES = frozenset({
    "MALWARE-DISTRIBUTION",
    "CRACKED-SOFTWARE",
    "PIRATED-SOFTWARE",
    "FAKE-SOFTWARE",
    "FAKE-UPDATE",
    "LOADER",
    "INFOSTEALER",
    "RAT",
    "BOTNET",
    "MALWARE",
    "PAYLOAD-HOSTING",
    "RANSOMWARE",
})


def view_flags(categories) -> tuple[int, int]:
    """(flag_c2, flag_malware) for the materialized category views."""
    cats = set(categories or ())
    return (
        1 if "C2" in cats else 0,
        1 if cats & MALWARE_VIEW_CATEGORIES else 0,
    )


@dataclass(slots=True)
class Mention:
    value: str
    ioc_type: str
    source_name: str
    source_url: str = ""
    tier: str = "B"
    first_seen: str = ""
    last_seen: str = ""
    explicit_c2: bool = False
    explicit_malware: bool = False
    active: bool | None = None
    malware_family: str = ""
    threat_actor: str = ""
    campaign: str = ""
    threat: str = ""
    categories: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    description: str = ""
    evidence: str = ""
    feed_confidence: int | None = None
    derived: bool = False


@dataclass(slots=True)
class Extraction:
    ioc_type: str
    value: str
    context: str
    derived: bool = False
