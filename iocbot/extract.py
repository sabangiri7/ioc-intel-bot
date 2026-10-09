from __future__ import annotations

import ipaddress
import re

from .models import Extraction

_DEFANG_MAP = [
    (re.compile(r"\bhxxp(?=s?://|[\[(.:])", re.I), "http"),
    (re.compile(r"\bfxp(?=s?://)", re.I), "http"),
    (re.compile(r"\bhtp(?=s?://)", re.I), "http"),
    (re.compile(r"\bhtttp(?=s?://)", re.I), "http"),
    (re.compile(r"\[[\s]*\.[\s]*\]"), "."),
    (re.compile(r"\(\s*\.\s*\)"), "."),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\[\s*//\s*\]"), "://"),
    (re.compile(r"\[\s*@\s*\]"), "@"),
    (re.compile(r"\[\s*dot\s*\]", re.I), "."),
    (re.compile(r"\[\s*scheme\s*\]", re.I), "http"),
    (re.compile(r"\\\."), "."),
]

URL_RE = re.compile(r"\b(?:https?|ftps?|sftp)://[^\s<>\"'\`\]\[{}]+", re.I)
IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?(?!\.\d)(?!\w)")
IPV6_RE = re.compile(
    r"(?<![\w:])(?:[A-Fa-f0-9]{1,4}:){2,7}(?::|[A-Fa-f0-9]{1,4})(?![\w:])"
)
DOMAIN_RE = re.compile(
    r"(?<![\w./@-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}(?![\w@-])"
)
EMAIL_RE = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,24}(?![\w.-])")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
SHA256_RE = re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{64}(?![A-Fa-f0-9])")
SHA1_RE = re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{40}(?![A-Fa-f0-9])")
MD5_RE = re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{32}(?![A-Fa-f0-9])")
FILENAME_RE = re.compile(
    r"(?<![\w\-./\\])[A-Za-z0-9][A-Za-z0-9_\-]{0,60}\.(?:exe|dll|msi|scr|bat|cmd|ps1|psm1|vbs|vbe|js|jse|wsf|jar|hta|lnk|zip|rar|7z|iso|img|docm|docx|xls|xlsm|xlsx|pptm|apk|dmg|pkg|run|bin|py|pyc|sh|elf|so|accde|reg|sys|cpl|ocx|dat|db|txt|html|php|asp|aspx|jsp|json|xml|pdf|msix|appx|sfx)(?![\w/\\])",
    re.I,
)
WINPATH_RE = re.compile(r"(?<![\w])[A-Za-z]:\\[^\s\"'<>|]{3,200}")
UNIXPATH_RE = re.compile(r"(?<![\w/])/(?:usr|var|etc|tmp|opt|home|root|Users|ProgramData|AppData|Windows|System32|SysWOW64|Library|private|dev|proc|run|srv|mnt|media)(?:/[\w.~+-]+){1,12}(?![\w])")

_SENT_SPLIT = re.compile(r"(?<=[.!?])\s+|\n{2,}")
_URL_TAIL_RE = re.compile(r"[.,;:!?)\"'>\]]+$")


def refang(text: str) -> str:
    out = text
    for rx, repl in _DEFANG_MAP:
        out = rx.sub(repl, out)
    return out


def sentence_at(text: str, start: int, end: int, limit: int = 400) -> str:
    left = 0
    for m in _SENT_SPLIT.finditer(text):
        if m.start() <= start:
            left = m.end()
        else:
            break
    right = len(text)
    for m in _SENT_SPLIT.finditer(text):
        if m.start() >= end:
            right = m.start()
            break
    sent = text[left:right].strip()
    sent = re.sub(r"\s+", " ", sent)
    if len(sent) > limit:
        rel = start - left
        s = max(0, rel - limit // 2)
        sent = sent[s : s + limit]
    return sent


def _valid_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def _valid_ipv6(value: str) -> bool:
    try:
        ipaddress.IPv6Address(value)
        return True
    except ValueError:
        return False


def _clean_url(url: str) -> str:
    url = _URL_TAIL_RE.sub("", url)
    return url


def _looks_like_ipv6(value: str) -> bool:
    if value.count(":") < 2:
        return False
    if ":" not in value:
        return False
    if value.count(":") == 2 and re.fullmatch(r"\d{1,2}:\d{1,2}:\d{1,2}", value):
        return False
    if value.count(":") >= 5:
        return True
    if re.search(r"[A-Fa-f]", value):
        return True
    return value.count(":") >= 4


def extract(text: str) -> list[Extraction]:
    text = refang(text)
    results: list[Extraction] = []
    seen: set[tuple[str, str]] = set()
    spans: list[tuple[int, int]] = []

    def add(ioc_type: str, value: str, pos_start: int, pos_end: int, derived: bool = False) -> None:
        value = value.strip().strip(".,;:!?\"'<>")
        if not value:
            return
        key = (ioc_type, value.lower())
        if key in seen:
            return
        seen.add(key)
        ctx = sentence_at(text, pos_start, pos_end)
        results.append(Extraction(ioc_type=ioc_type, value=value, context=ctx, derived=derived))

    # URLs first, then mask them so their components are not re-extracted as
    # standalone domains/IPs from inside the URL (host derivation is explicit).
    masked = list(text)
    for m in URL_RE.finditer(text):
        url = _clean_url(m.group(0))
        if not url or len(url) < 10:
            continue
        add("URL", url, m.start(), m.end())
        spans.append((m.start(), m.start() + len(url)))
        host = _url_host(url)
        if host:
            if _valid_ipv4(host):
                add("IPv4", host, m.start(), m.start() + 1, derived=True)
            elif _valid_ipv6(host):
                add("IPv6", host, m.start(), m.start() + 1, derived=True)
            else:
                add("Domain", host, m.start(), m.start() + 1, derived=True)
        for i in range(m.start(), min(m.start() + len(url), len(masked))):
            masked[i] = " "
    masked_text = "".join(masked)

    # Mask file paths so their components are never re-extracted as domains.
    path_spans: list[tuple[int, int]] = []
    for rx in (WINPATH_RE, UNIXPATH_RE):
        for m in rx.finditer(masked_text):
            add("File-Path", m.group(0), m.start(), m.end())
            path_spans.append((m.start(), m.end()))
    if path_spans:
        chars = list(masked_text)
        for a, b in path_spans:
            for i in range(a, b):
                chars[i] = " "
        masked_text = "".join(chars)

    def scan(rx: re.Pattern[str], ioc_type: str, transform=None):
        for m in rx.finditer(masked_text):
            raw = m.group(0)
            if transform:
                val = transform(raw)
            else:
                val = raw
            if val:
                add(ioc_type, val, m.start(), m.end(), derived=False)

    scan(SHA256_RE, "SHA256", lambda v: v.lower())
    scan(SHA1_RE, "SHA1", lambda v: v.lower())
    scan(MD5_RE, "MD5", lambda v: v.lower())
    scan(CVE_RE, "CVE", lambda v: v.upper())
    scan(EMAIL_RE, "Email", lambda v: v.lower())

    for m in IPV4_RE.finditer(masked_text):
        raw = m.group(0)
        ip_part = raw.split(":", 1)[0] if ":" in raw else raw
        if _valid_ipv4(ip_part):
            add("IPv4", ip_part, m.start(), m.end())

    for m in IPV6_RE.finditer(masked_text):
        raw = m.group(0)
        if _looks_like_ipv6(raw) and _valid_ipv6(raw):
            add("IPv6", raw.lower(), m.start(), m.end())

    filename_values: set[str] = set()
    for m in FILENAME_RE.finditer(masked_text):
        val = m.group(0).strip().lower()
        filename_values.add(val)
        add("File-Name", val, m.start(), m.end())

    for m in DOMAIN_RE.finditer(masked_text):
        val = m.group(0).lower().rstrip(".")
        if val in filename_values:
            continue
        if ".".join(val.split(".")[-2:]) in filename_values:
            continue
        add("Domain", val, m.start(), m.end())

    return results


def _url_host(url: str) -> str | None:
    from urllib.parse import urlsplit

    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    host = parts.hostname
    if not host:
        return None
    return host.lower().rstrip(".")
