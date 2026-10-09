from __future__ import annotations

import logging
from pathlib import Path

log = logging.getLogger("iocbot.export")

from .models import MALWARE_VIEW_CATEGORIES as MALWARE_DOWNLOAD_CATEGORIES  # noqa: E402

HEADER = "IOC"

# Only real indicator values go into the daily lists: network IOCs, hashes,
# and CVEs. Entity/context rows (Malware families, threat actors, file
# names/paths, campaigns) stay in the database but are never exported.
DAILY_IOC_TYPES = {"IPv4", "IPv6", "Domain", "URL", "MD5", "SHA1", "SHA256", "CVE"}

# Full feed: value + severity + category (+ group folders) for SIEM ingestion.
FEED_COLUMNS = [
    "IOC", "IOC_TYPE", "SEVERITY", "CONFIDENCE", "CATEGORY", "MALWARE_FAMILY",
    "THREAT_ACTOR", "FOLDERS", "VALIDATION_STATUS", "CROWDSTRIKE_IMPORTABLE",
    "FIRST_SEEN", "LAST_SEEN", "SOURCE", "TAGS",
]

MAX_FOLDER_FILES = 500


def _eligible(rows: list[dict]) -> list[dict]:
    return [r for r in rows if r.get("ioc_type") in DAILY_IOC_TYPES]


def _unique_sorted(values: list[str]) -> list[str]:
    return sorted({v for v in values if v})


def _write_values(path: Path, values: list[str]) -> int:
    vals = _unique_sorted(values)
    with path.open("w", encoding="utf-8", newline="") as fh:
        fh.write(HEADER + "\n")
        for v in vals:
            fh.write(v + "\n")
    return len(vals)


def _master_values(rows: list[dict]) -> list[str]:
    return [r.get("ioc", "") for r in _eligible(rows)]


def _cs_values(rows: list[dict], cfg: dict) -> list[str]:
    conf_ok = set(cfg.get("confidence_threshold", ["MEDIUM", "HIGH", "CRITICAL"]))
    sev_ok = set(cfg.get("severity_threshold", ["MEDIUM", "HIGH", "CRITICAL"]))
    out = []
    for r in _eligible(rows):
        if r.get("crowdstrike_importable") != "YES":
            continue
        if r.get("confidence") not in conf_ok or r.get("severity") not in sev_ok:
            continue
        out.append(r.get("ioc", ""))
    return out


def _c2_values(rows: list[dict]) -> list[str]:
    return [r.get("ioc", "") for r in _eligible(rows)
            if "C2" in (r.get("categories") or [])]


def _malware_download_values(rows: list[dict]) -> list[str]:
    return [
        r.get("ioc", "")
        for r in _eligible(rows)
        if set(r.get("categories") or []) & MALWARE_DOWNLOAD_CATEGORIES
    ]


def _sources(r) -> str:
    v = r.get("source_list") or r.get("sources")
    if isinstance(v, list):
        return " | ".join(x for x in v if x)
    if v:
        return str(v)
    return str(r.get("source") or "")


def _tags(r) -> str:
    v = r.get("tags_list") or r.get("tags")
    if isinstance(v, list):
        return ";".join(x for x in v if x)
    if isinstance(v, str):
        return v
    return ""

def _write_feed(path: Path, rows: list[dict], folders_of: dict) -> int:
    import csv

    n = 0
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(FEED_COLUMNS)
        for r in rows:
            if r.get("ioc_type") not in DAILY_IOC_TYPES:
                continue
            key = (r.get("ioc_type", ""), r.get("ioc", ""))
            writer.writerow([
                r.get("ioc", ""), r.get("ioc_type", ""), r.get("severity", ""),
                r.get("confidence", ""), ";".join(r.get("categories") or []),
                r.get("malware_family", ""), r.get("threat_actor", ""),
                ";".join(folders_of.get(key, [])), r.get("validation_status", ""),
                r.get("crowdstrike_importable", ""), r.get("first_seen", ""),
                r.get("last_seen", ""), _sources(r), _tags(r),
            ])
            n += 1
    return n


def _slug(name: str, seen: dict) -> str:
    import re

    base = re.sub(r"[^A-Za-z0-9._-]+", "-", name.strip()).strip("-") or "folder"
    slug = base
    i = 1
    while slug in seen:
        i += 1
        slug = f"{base}-{i}"
    seen[slug] = name
    return slug


def _write_folders(output_dir: Path, buckets: dict[str, list[dict]]) -> dict:
    """One CSV per malware-group folder plus an index of every folder."""
    import csv
    from collections import Counter

    folder_dir = output_dir / "folders"
    folder_dir.mkdir(parents=True, exist_ok=True)
    ordered = sorted(buckets.items(), key=lambda kv: (-len(kv[1]), kv[0].lower()))
    slugs: dict = {}
    index_rows = []
    written = 0
    for name, rows in ordered:
        sev = Counter(r.get("severity", "") for r in rows)
        index_rows.append([name, len(rows), sev.get("CRITICAL", 0), sev.get("HIGH", 0),
                           sev.get("MEDIUM", 0), sev.get("LOW", 0)])
        if written >= MAX_FOLDER_FILES:
            continue
        slug = _slug(name, slugs)
        with (folder_dir / f"{slug}.csv").open("w", encoding="utf-8", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(FEED_COLUMNS)
            for r in rows:
                writer.writerow([
                    r.get("ioc", ""), r.get("ioc_type", ""), r.get("severity", ""),
                    r.get("confidence", ""), ";".join(r.get("categories") or []),
                    r.get("malware_family", ""), r.get("threat_actor", ""), name,
                    r.get("validation_status", ""), r.get("crowdstrike_importable", ""),
                    r.get("first_seen", ""), r.get("last_seen", ""),
                    _sources(r), _tags(r),
                ])
        written += 1
    with (output_dir / "FOLDERS_INDEX.csv").open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["FOLDER", "COUNT", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
        writer.writerows(index_rows)
    return {"folders/": written, "FOLDERS_INDEX.csv": len(index_rows)}


def write_all(output_dir: Path, rows: list[dict], new_rows: list[dict], cs_cfg: dict,
              folder_buckets: dict | None = None) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    folders_of: dict = {}
    if folder_buckets:
        for name, members in folder_buckets.items():
            for r in members:
                folders_of.setdefault((r.get("ioc_type", ""), r.get("ioc", "")),
                                      []).append(name)
    counts = {
        "MASTER_IOC_DATABASE.csv": _write_values(output_dir / "MASTER_IOC_DATABASE.csv",
                                                 _master_values(rows)),
        "CROWDSTRIKE_IOC_IMPORT.csv": _write_values(output_dir / "CROWDSTRIKE_IOC_IMPORT.csv",
                                                    _cs_values(rows, cs_cfg)),
        "NEW_IOCS.csv": _write_values(output_dir / "NEW_IOCS.csv", _master_values(new_rows)),
        "C2_IOCS.csv": _write_values(output_dir / "C2_IOCS.csv", _c2_values(rows)),
        "MALWARE_DOWNLOAD_IOCS.csv": _write_values(output_dir / "MALWARE_DOWNLOAD_IOCS.csv",
                                                   _malware_download_values(rows)),
        "IOC_FEED.csv": _write_feed(output_dir / "IOC_FEED.csv", rows, folders_of),
    }
    if folder_buckets:
        counts.update(_write_folders(output_dir, folder_buckets))
    return counts
