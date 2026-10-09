from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit

DEFAULT_PORTS = {"http": "80", "https": "443", "ftp": "21"}

_WS = re.compile(r"\s+")
_TRAILING_DOT = re.compile(r"\.+$")


def norm_domain(value: str) -> str:
    v = value.strip().lower().rstrip(".")
    if v.startswith("www."):
        v = v[4:]
    return _TRAILING_DOT.sub("", v)


def norm_ip(value: str) -> str:
    import ipaddress

    v = value.strip()
    try:
        ip = ipaddress.ip_address(v.split("%")[0])
        return str(ip)
    except ValueError:
        return v.lower()


def norm_hash(value: str) -> str:
    return value.strip().lower()


def norm_email(value: str) -> str:
    return value.strip().lower()


def norm_cve(value: str) -> str:
    return value.strip().upper()


def norm_url(value: str) -> str:
    v = _WS.sub("", value.strip().strip("<>\"'"))
    try:
        parts = urlsplit(v)
    except ValueError:
        return v
    scheme = (parts.scheme or "http").lower()
    host = (parts.hostname or "").lower().rstrip(".")
    port = parts.port
    netloc = host
    if port and str(port) != DEFAULT_PORTS.get(scheme):
        netloc = f"{host}:{port}"
    path = parts.path or ""
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def norm_value(value: str, ioc_type: str) -> str:
    if ioc_type in ("Domain",):
        return norm_domain(value)
    if ioc_type in ("IPv4", "IPv6"):
        return norm_ip(value)
    if ioc_type in ("SHA256", "SHA1", "MD5"):
        return norm_hash(value)
    if ioc_type == "Email":
        return norm_email(value)
    if ioc_type == "CVE":
        return norm_cve(value)
    if ioc_type == "URL":
        return norm_url(value)
    return _WS.sub(" ", value.strip())
