from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path

import tldextract
import yaml

_extract = tldextract.TLDExtract(suffix_list_urls=())

_DOMAIN_SHAPE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$"
)
_EMAIL_SHAPE = re.compile(r"^[a-z0-9._%+-]+@[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,24}$")
_HEX = re.compile(r"^[0-9a-f]+$")
_HASH_LEN = {"MD5": 32, "SHA1": 40, "SHA256": 64}
_CVE_SHAPE = re.compile(r"^CVE-(\d{4})-\d{4,7}$")

SHARED_PLATFORM = "SHARED-PLATFORM"
VALID = "VALID"


@dataclass(slots=True)
class ValidationResult:
    status: str
    flags: set[str] = field(default_factory=set)
    note: str = ""

    @property
    def valid(self) -> bool:
        return self.status in (VALID, SHARED_PLATFORM)

    @property
    def importable_status(self) -> bool:
        return self.status == VALID


class Validator:
    def __init__(self, config_path: Path):
        path = Path(config_path)
        cfg = yaml.safe_load(path.read_text()) if path.exists() else {}
        self.doc_domains = {str(d).lower() for d in cfg.get("doc_domains", [])}
        self.blocked_literals = {str(d).lower() for d in cfg.get("blocked_literals", [])}
        self.blocked_suffixes = {str(d).lower() for d in cfg.get("blocked_suffixes", [])}
        self.generic_vendor = {str(d).lower() for d in cfg.get("generic_vendor_domains", [])}
        self.shared_platform = {str(d).lower() for d in cfg.get("shared_platform_domains", [])}
        self.cdn_suffixes = [str(d).lower() for d in cfg.get("cdn_suffixes", [])]
        self.placeholder_hashes = {str(h).lower() for h in cfg.get("placeholder_hashes", [])}
        self.blocked_cidrs = []
        for cidr in cfg.get("blocked_ip_cidrs", []):
            try:
                self.blocked_cidrs.append(ipaddress.ip_network(str(cidr), strict=False))
            except ValueError:
                continue

    def validate(self, value: str, ioc_type: str, explicit_malicious: bool = False) -> ValidationResult:
        fn = getattr(self, f"_v_{ioc_type.lower().replace('-', '_')}", None)
        if fn is None:
            return ValidationResult("REJECTED:unsupported-type")
        return fn(value, explicit_malicious)

    # -- IPv4 / IPv6 -----------------------------------------------------
    def _v_ipv4(self, value: str, explicit: bool) -> ValidationResult:
        return self._validate_ip(value, 4)

    def _v_ipv6(self, value: str, explicit: bool) -> ValidationResult:
        return self._validate_ip(value, 6)

    def _validate_ip(self, value: str, version: int) -> ValidationResult:
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return ValidationResult("REJECTED:syntax")
        if ip.version != version:
            return ValidationResult("REJECTED:syntax")
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
            return ValidationResult("REJECTED:private-or-reserved")
        if ip.is_reserved or ip.is_unspecified:
            return ValidationResult("REJECTED:private-or-reserved")
        for net in self.blocked_cidrs:
            if net.version == ip.version and ip in net:
                return ValidationResult("REJECTED:private-or-reserved")
        if version == 4 and ip.is_global is False:
            return ValidationResult("REJECTED:private-or-reserved")
        if version == 6 and str(ip) in ("::1", "::"):
            return ValidationResult("REJECTED:private-or-reserved")
        return ValidationResult(VALID)

    # -- Domain ----------------------------------------------------------
    def _v_domain(self, value: str, explicit: bool) -> ValidationResult:
        v = value.strip().lower().rstrip(".")
        if not v or not _DOMAIN_SHAPE.match(v):
            return ValidationResult("REJECTED:syntax")
        labels = v.split(".")
        if any(len(l) > 63 for l in labels):
            return ValidationResult("REJECTED:syntax")
        if v in self.blocked_literals or labels[0] in self.blocked_literals:
            return ValidationResult("REJECTED:localhost-or-literal")
        ext = _extract(v)
        suffix = (ext.suffix or "").lower()
        if not suffix:
            return ValidationResult("REJECTED:unknown-tld")
        if suffix in self.blocked_suffixes or suffix.split(".")[-1] in self.blocked_suffixes:
            return ValidationResult("REJECTED:reserved-tld")
        if v in self.doc_domains or f"{ext.domain}.{suffix}" in self.doc_domains:
            return ValidationResult("REJECTED:documentation-domain")
        shared = self._matches_suffixes(v, self.shared_platform)
        cdn = self._matches_suffixes(v, self.cdn_suffixes)
        if shared or cdn:
            flags = set()
            if shared:
                flags.add("shared-platform")
            if cdn:
                flags.add("cdn")
            if not explicit:
                return ValidationResult("REJECTED:shared-infrastructure", flags)
            return ValidationResult(SHARED_PLATFORM, flags, "shared/CDN infra, master only")
        if v in self.generic_vendor or f"{ext.domain}.{suffix}" in self.generic_vendor:
            if explicit:
                return ValidationResult(VALID, {"generic-vendor"}, "explicitly flagged by source")
            return ValidationResult("REJECTED:generic-vendor")
        return ValidationResult(VALID)

    @staticmethod
    def _matches_suffixes(domain: str, suffixes) -> bool:
        for s in suffixes:
            if domain == s or domain.endswith("." + s):
                return True
        return False

    # -- Hashes ----------------------------------------------------------
    def _v_sha256(self, value: str, explicit: bool) -> ValidationResult:
        return self._validate_hash(value, "SHA256")

    def _v_sha1(self, value: str, explicit: bool) -> ValidationResult:
        return self._validate_hash(value, "SHA1")

    def _v_md5(self, value: str, explicit: bool) -> ValidationResult:
        return self._validate_hash(value, "MD5")

    def _validate_hash(self, value: str, kind: str) -> ValidationResult:
        v = value.strip().lower()
        if len(v) != _HASH_LEN[kind] or not _HEX.match(v):
            return ValidationResult("REJECTED:syntax")
        if v in self.placeholder_hashes:
            return ValidationResult("REJECTED:placeholder-hash")
        if len(set(v)) <= 2:
            return ValidationResult("REJECTED:placeholder-hash")
        return ValidationResult(VALID)

    # -- URL -------------------------------------------------------------
    def _v_url(self, value: str, explicit: bool) -> ValidationResult:
        from urllib.parse import urlsplit

        v = value.strip()
        try:
            parts = urlsplit(v)
        except ValueError:
            return ValidationResult("REJECTED:syntax")
        if parts.scheme not in ("http", "https", "ftp"):
            return ValidationResult("REJECTED:scheme")
        host = parts.hostname
        if not host:
            return ValidationResult("REJECTED:syntax")
        try:
            ipaddress.ip_address(host)
            return self._validate_ip(host, 4 if ":" not in host else 6)
        except ValueError:
            pass
        res = self._v_domain(host, explicit)
        if res.status.startswith("REJECTED"):
            return ValidationResult(f"REJECTED:host-{res.status.split(':', 1)[1]}", res.flags, res.note)
        return ValidationResult(res.status, res.flags | {"url"}, res.note)

    # -- Email -----------------------------------------------------------
    def _v_email(self, value: str, explicit: bool) -> ValidationResult:
        v = value.strip().lower()
        if not _EMAIL_SHAPE.match(v):
            return ValidationResult("REJECTED:syntax")
        domain = v.split("@", 1)[1]
        res = self._v_domain(domain, explicit)
        if not res.valid:
            return ValidationResult(f"REJECTED:email-{res.status.split(':', 1)[1] if ':' in res.status else res.status}",
                                    res.flags, res.note)
        return ValidationResult(VALID, res.flags)

    # -- CVE -------------------------------------------------------------
    def _v_cve(self, value: str, explicit: bool) -> ValidationResult:
        import datetime

        v = value.strip().upper()
        m = _CVE_SHAPE.match(v)
        if not m:
            return ValidationResult("REJECTED:syntax")
        year = int(m.group(1))
        if year < 1999 or year > datetime.date.today().year:
            return ValidationResult("REJECTED:bad-year")
        return ValidationResult(VALID)

    # -- Files -----------------------------------------------------------
    def _v_file_name(self, value: str, explicit: bool) -> ValidationResult:
        v = value.strip()
        if not v or len(v) > 120 or "/" in v or "\\" in v or "\n" in v:
            return ValidationResult("REJECTED:syntax")
        if not re.match(r"^[A-Za-z0-9][\w\- .()]{1,118}\.[A-Za-z0-9]{1,10}$", v):
            return ValidationResult("REJECTED:syntax")
        return ValidationResult(VALID)

    def _v_file_path(self, value: str, explicit: bool) -> ValidationResult:
        v = value.strip()
        if len(v) < 5 or ("/" not in v and "\\" not in v):
            return ValidationResult("REJECTED:syntax")
        if "\n" in v or '"' in v:
            return ValidationResult("REJECTED:syntax")
        if v.startswith("/etc/") or v.startswith("/proc/") or v.startswith("/sys/"):
            return ValidationResult(VALID, {"system-path"})
        return ValidationResult(VALID)

    # -- Entities (master only) ------------------------------------------
    def _v_malware(self, value: str, explicit: bool) -> ValidationResult:
        return self._validate_entity(value)

    def _v_threat_actor(self, value: str, explicit: bool) -> ValidationResult:
        return self._validate_entity(value)

    def _v_campaign(self, value: str, explicit: bool) -> ValidationResult:
        return self._validate_entity(value)

    @staticmethod
    def _validate_entity(value: str) -> ValidationResult:
        v = value.strip()
        if not 1 < len(v) < 120:
            return ValidationResult("REJECTED:syntax")
        return ValidationResult(VALID, {"entity"})
