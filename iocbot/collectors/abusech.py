from __future__ import annotations

import csv
import io
import json
import logging
import re
import zipfile
from datetime import datetime, timedelta, timezone

from ..classify import category_for_family, FAMILY_TAG_NOISE
from ..extract import refang
from ..models import Mention

log = logging.getLogger("iocbot.abusech")

NOISE_TAGS = {
    "elf", "win", "linux", "macos", "android", "upx", "packed", "32-bit", "64-bit",
    "arm", "x86", "x64", "exe", "dll", "zip", "rar", "7z", "html", "doc", "pdf",
    "github", "issue-attachment", "opendir", "censys", "ua-wget", "backdoor",
    "drb-ra", "threatview-io", "anonymous", "compromised", "victim", "sepolia",
    "clickfix", "malware_download", "payload", "botnet_cc", "email", "spam",
    "phishing", "screenshot", "js", "vbs", "ps1", "apk", "jar", "bat", "scr",
    "iso", "docx", "xlsx", "php", "py", "sh", "oneNote", "onenote", "vhd",
    "amta", "imphash", "ssdeep", "tlsh", "clamav", "elf64", "loader", "stealer",
    "rat", "ransomware", "apt", "c2", "hijacker", "adware", "pup", "pua",
}


def _days_ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")


def _day(value: str | None) -> str:
    if not value:
        return ""
    return str(value).strip()[:10]


def _family_from_tags(tags: list[str], default: str = "") -> str:
    # Only accept a tag as a malware family when it matches a known family
    # in the classification map; URLhaus tags are free-form (#image, .jar, ...).
    from ..classify import FAMILY_CATEGORY

    for tag in tags:
        t = tag.strip().lower().lstrip("#").strip()
        if not t or t in NOISE_TAGS or t in FAMILY_TAG_NOISE:
            continue
        for key in FAMILY_CATEGORY:
            if t == key or (len(key) >= 5 and key in t):
                return tag.strip().lstrip("#").strip()
    return default


def _split_tags(raw: str | None) -> list[str]:
    if not raw or raw == "None":
        return []
    parts = re.split(r"[,\s]+", str(raw))
    out = []
    for t in parts:
        t = t.strip().lstrip("#").strip().lower()
        if t:
            out.append(t)
    return out


def _family_category(family: str) -> list[str]:
    cat = category_for_family(family)
    return [cat] if cat else []


def _read_maybe_zip(data: bytes) -> bytes:
    if data[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            name = zf.namelist()[0]
            return zf.read(name)
    return data


# --------------------------------------------------------------------------
# ThreatFox
# --------------------------------------------------------------------------
def collect_threatfox(cfg: dict, fetcher, first_run: bool = False) -> tuple[list[Mention], dict]:
    url = cfg.get("first_run_url") if first_run else cfg["url"]
    stats = {"source": cfg["name"], "kind": "threatfox", "fetched": False, "entries": 0, "mentions": 0, "errors": []}
    data = fetcher.get(url or cfg["url"], max_bytes=60 * 1024 * 1024)
    if data is None:
        if url != cfg["url"]:
            data = fetcher.get(cfg["url"], max_bytes=60 * 1024 * 1024)
    if data is None:
        stats["errors"].append("download failed")
        return [], stats
    stats["fetched"] = True
    try:
        payload = json.loads(_read_maybe_zip(data).decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, zipfile.BadZipFile) as exc:
        stats["errors"].append(f"parse error: {exc}")
        return [], stats

    entries = []
    if isinstance(payload, dict):
        for value in payload.values():
            if isinstance(value, list):
                entries.extend(value)
            elif isinstance(value, dict):
                entries.append(value)
    elif isinstance(payload, list):
        entries = payload

    mentions: list[Mention] = []
    type_map = {
        "ip:port": "IPv4", "domain": "Domain", "url": "URL",
        "sha256_hash": "SHA256", "md5_hash": "MD5", "sha1_hash": "SHA1",
        "email": "Email",
    }
    for e in entries:
        if not isinstance(e, dict):
            continue
        raw_value = refang(str(e.get("ioc_value", "")).strip())
        ioc_type = type_map.get(str(e.get("ioc_type", "")).strip())
        if not raw_value or not ioc_type:
            continue
        port = ""
        if e.get("ioc_type") == "ip:port" and ":" in raw_value:
            raw_value, _, port = raw_value.rpartition(":")
        threat_type = str(e.get("threat_type", "")).strip()
        explicit_c2 = threat_type == "botnet_cc"
        explicit_malware = True
        family = str(e.get("malware_printable") or e.get("malware") or "").strip()
        family = re.sub(r"^(win|elf|osx|android)\.", "", family, flags=re.I).strip()
        tags = _split_tags(e.get("tags"))
        first = _day(e.get("first_seen_utc")) or _days_ago(0)
        last = _day(e.get("last_seen_utc")) or first
        try:
            active = (datetime.now(timezone.utc).date() - datetime.strptime(last, "%Y-%m-%d").date()).days <= 30
        except ValueError:
            active = None
        categories: list[str] = []
        if explicit_c2:
            categories.append("C2")
        elif threat_type in ("payload", "payload_delivery"):
            categories.extend(["MALWARE-DISTRIBUTION", "PAYLOAD-HOSTING" if ioc_type == "URL" else "MALWARE"])
        categories.extend(_family_category(family))
        tags_out = list(tags)
        if port:
            tags_out.append(f"port:{port}")
        if e.get("is_compromised"):
            tags_out.append("compromised-host")
        threat = "Botnet C2" if explicit_c2 else (
            "Malware payload delivery" if threat_type in ("payload", "payload_delivery") else "Malware")
        reference = str(e.get("reference") or "").strip()
        description = f"ThreatFox {threat_type} ({family or 'unknown family'})"
        if port:
            description += f", port {port}"
        if e.get("is_compromised"):
            description += ", reported on a compromised host"
        mentions.append(Mention(
            value=raw_value, ioc_type=ioc_type,
            source_name=cfg["name"], source_url=reference or cfg["url"],
            tier=cfg.get("tier", "A"),
            first_seen=first, last_seen=last,
            explicit_c2=explicit_c2, explicit_malware=explicit_malware,
            active=active, malware_family=family,
            categories=categories, tags=tags_out,
            threat=threat, description=description,
            evidence=f"{threat_type}: {raw_value} ({family or 'unspecified'})",
            feed_confidence=e.get("confidence_level"),
        ))
        if family:
            mentions.append(Mention(
                value=family, ioc_type="Malware",
                source_name=cfg["name"], source_url=reference or cfg["url"],
                tier=cfg.get("tier", "A"), first_seen=first, last_seen=last,
                categories=_family_category(family) or ["MALWARE"],
                tags=["malware-family"], threat=threat,
                description=f"Malware family reported by ThreatFox: {family}",
            ))

    stats["entries"] = len(entries)
    stats["mentions"] = len(mentions)
    return mentions, stats


# --------------------------------------------------------------------------
# URLhaus
# --------------------------------------------------------------------------
def collect_urlhaus(cfg: dict, fetcher) -> tuple[list[Mention], dict]:
    stats = {"source": cfg["name"], "kind": "urlhaus", "fetched": False, "entries": 0, "mentions": 0, "errors": []}
    data = fetcher.get(cfg["url"], max_bytes=40 * 1024 * 1024, timeout=180)
    if data is None:
        stats["errors"].append("download failed")
        return [], stats
    stats["fetched"] = True
    text = data.decode("utf-8", errors="replace")
    header = None
    body_lines = []
    for line in text.splitlines():
        if line.startswith("# id,"):
            header = line.lstrip("# ").strip()
        elif line and not line.startswith("#"):
            body_lines.append(line)
    if header is None:
        stats["errors"].append("header not found")
        return [], stats
    fieldnames = next(csv.reader([header]))
    reader = csv.DictReader(body_lines, fieldnames=fieldnames)
    mentions: list[Mention] = []
    for row in reader:
        try:
            url = refang((row.get("url") or "").strip())
        except Exception:  # noqa: BLE001
            continue
        if not url.startswith(("http://", "https://")):
            continue
        tags = _split_tags(row.get("tags"))
        family = _family_from_tags(tags)
        status = (row.get("url_status") or "").strip().lower()
        first = _day(row.get("dateadded")) or _days_ago(0)
        last = _day(row.get("last_online")) or first
        active = status == "online"
        categories = ["MALWARE-DISTRIBUTION", "PAYLOAD-HOSTING"] + _family_category(family)
        threat = "Malware download URL"
        mentions.append(Mention(
            value=url, ioc_type="URL",
            source_name=cfg["name"], source_url=row.get("urlhaus_link") or cfg["url"],
            tier=cfg.get("tier", "A"),
            first_seen=first, last_seen=last,
            explicit_malware=True, active=active, malware_family=family,
            categories=categories, tags=tags + [f"url-status:{status or 'unknown'}"],
            threat=threat,
            description=f"URLhaus malware_download ({family or 'unreported family'}), status {status or 'unknown'}",
            evidence=f"urlhaus threat=malware_download tags={','.join(tags[:6])}",
        ))
        if family:
            mentions.append(Mention(
                value=family, ioc_type="Malware",
                source_name=cfg["name"], source_url=row.get("urlhaus_link") or cfg["url"],
                tier=cfg.get("tier", "A"), first_seen=first, last_seen=last,
                categories=_family_category(family) or ["MALWARE"],
                tags=["malware-family"], threat=threat,
                description=f"Malware family seen distributing via URLhaus: {family}",
            ))
    stats["entries"] = len(body_lines)
    stats["mentions"] = len(mentions)
    return mentions, stats


# --------------------------------------------------------------------------
# Feodo Tracker
# --------------------------------------------------------------------------
def collect_feodo(cfg: dict, fetcher) -> tuple[list[Mention], dict]:
    stats = {"source": cfg["name"], "kind": "feodo", "fetched": False, "entries": 0, "mentions": 0, "errors": []}
    hosts: dict[str, dict] = {}

    ip_data = fetcher.get_text(cfg["ip_url"])
    if ip_data:
        stats["fetched"] = True
        for line in ip_data.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            hosts.setdefault(line, {})
    else:
        stats["errors"].append("ipblocklist failed")

    browse_html = fetcher.get_text(cfg["browse_url"])
    if browse_html:
        stats["fetched"] = True
        try:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(browse_html, "lxml")
            for table in soup.find_all("table"):
                header = [th.get_text(strip=True).lower() for th in table.find_all("th")]
                if not header or "host" not in header:
                    continue
                for tr in table.find_all("tr"):
                    cells = [td.get_text(strip=True) for td in tr.find_all("td")]
                    if len(cells) < 4:
                        continue
                    record = dict(zip(header, cells))
                    host = record.get("host", "")
                    if host:
                        hosts[host] = record
        except Exception as exc:  # noqa: BLE001
            stats["errors"].append(f"browse parse: {exc}")
    else:
        stats["errors"].append("browse failed")

    mentions: list[Mention] = []
    for host, record in hosts.items():
        family = record.get("malware", "") or ""
        status = (record.get("status") or "").strip()
        first = _day(record.get("firstseen (utc)", record.get("firstseen", "")))
        active = status.lower() == "active"
        if not first:
            first = _days_ago(180)
        last = first if not active else _days_ago(0)
        cats = ["C2"] + _family_category(family)
        tags = ["feodo-tracker"]
        if status:
            tags.append(f"status:{status.lower()}")
        desc = f"Feodo Tracker botnet C2: {family or 'unknown family'}"
        if status:
            desc += f", status {status}"
        if record.get("network (asn)", ""):
            desc += f", {record.get('network (asn)')}"
        mentions.append(Mention(
            value=host, ioc_type="IPv4",
            source_name=cfg["name"], source_url=cfg["browse_url"],
            tier=cfg.get("tier", "A"),
            first_seen=first, last_seen=last,
            explicit_c2=True, explicit_malware=True,
            active=active, malware_family=family,
            categories=cats, tags=tags, threat="Botnet C2",
            description=desc,
            evidence=f"feodo tracker: {host} {family} {status}".strip(),
        ))
    stats["entries"] = len(hosts)
    stats["mentions"] = len(mentions)
    return mentions, stats


# --------------------------------------------------------------------------
# MalwareBazaar
# --------------------------------------------------------------------------
def collect_malwarebazaar(cfg: dict, fetcher) -> tuple[list[Mention], dict]:
    stats = {"source": cfg["name"], "kind": "malwarebazaar", "fetched": False, "entries": 0, "mentions": 0, "errors": []}
    data = fetcher.get(cfg["url"], max_bytes=20 * 1024 * 1024)
    if data is None:
        stats["errors"].append("download failed")
        return [], stats
    stats["fetched"] = True
    text = data.decode("utf-8", errors="replace")
    header = None
    body = []
    for line in text.splitlines():
        if line.startswith("# \"first_seen_utc\""):
            header = line.lstrip("# ").strip()
        elif line and not line.startswith("#"):
            body.append(line)
    if header is None:
        stats["errors"].append("header not found")
        return [], stats
    fieldnames = next(csv.reader([header]))
    reader = csv.DictReader(body, fieldnames=fieldnames, skipinitialspace=True)
    mentions: list[Mention] = []
    for row in reader:
        sha256 = (row.get("sha256_hash") or "").strip().lower()
        if len(sha256) != 64:
            continue
        family = (row.get("signature") or "").strip()
        if family.lower() in ("n/a", "none", "unknown", "-"):
            family = ""
        file_name = (row.get("file_name") or "").strip()
        first = _day(row.get("first_seen_utc")) or _days_ago(0)
        cats = ["MALWARE"] + _family_category(family)
        vt = (row.get("vtpercent") or "").strip()
        desc = f"MalwareBazaar sample ({family or 'no AV signature'}), file {file_name}" if file_name else \
            f"MalwareBazaar sample ({family or 'no AV signature'})"
        if vt and vt.lower() not in ("", "none", "n/a"):
            desc += f", VT {vt}/70"
        for htype, col in (("SHA256", "sha256_hash"), ("MD5", "md5_hash"), ("SHA1", "sha1_hash")):
            hval = (row.get(col) or "").strip().lower()
            if len(hval) not in (32, 40, 64):
                continue
            expected = {"MD5": 32, "SHA1": 40, "SHA256": 64}[htype]
            if len(hval) != expected:
                continue
            mentions.append(Mention(
                value=hval, ioc_type=htype,
                source_name=cfg["name"], source_url=cfg["url"],
                tier=cfg.get("tier", "A"),
                first_seen=first, last_seen=first,
                explicit_malware=True, active=True, malware_family=family,
                categories=cats, tags=["malware-sample"],
                threat="Malware sample", description=desc,
                evidence=f"malwarebazaar signature={family or 'none'} file={file_name}",
            ))
        if file_name and len(file_name) <= 100:
            mentions.append(Mention(
                value=file_name, ioc_type="File-Name",
                source_name=cfg["name"], source_url=cfg["url"],
                tier=cfg.get("tier", "A"), first_seen=first, last_seen=first,
                explicit_malware=True, malware_family=family,
                categories=cats, tags=["malware-sample"], threat="Malware sample",
                description=f"Malware filename: {file_name}",
                evidence=f"malwarebazaar file_name={file_name}",
            ))
        if family:
            mentions.append(Mention(
                value=family, ioc_type="Malware",
                source_name=cfg["name"], source_url=cfg["url"],
                tier=cfg.get("tier", "A"), first_seen=first, last_seen=first,
                categories=_family_category(family) or ["MALWARE"],
                tags=["malware-family"], threat="Malware family",
                description=f"MalwareBazaar AV signature: {family}",
            ))
    stats["entries"] = len(body)
    stats["mentions"] = len(mentions)
    return mentions, stats
