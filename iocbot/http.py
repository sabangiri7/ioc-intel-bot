from __future__ import annotations

import hashlib
import logging
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

import requests

log = logging.getLogger("iocbot.http")

UA = "IOC-Intel-Bot/1.0 (public threat-intelligence collector; outputs require manual review)"


class Fetcher:
    def __init__(
        self,
        raw_dir: Path,
        rate: float = 1.0,
        timeout: int = 30,
        max_bytes: int = 30 * 1024 * 1024,
        retries: int = 2,
    ):
        self.raw_dir = Path(raw_dir)
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.rate = rate
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.retries = retries
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": UA, "Accept-Encoding": "gzip, deflate"})
        self._last: dict[str, float] = {}
        self._lock = threading.Lock()

    def _polite(self, url: str) -> None:
        host = urlparse(url).netloc
        with self._lock:
            wait = self.rate - (time.time() - self._last.get(host, 0.0))
            if wait > 0:
                time.sleep(wait)
            self._last[host] = time.time()

    def _raw_path(self, url: str) -> Path:
        return self.raw_dir / (hashlib.sha256(url.encode()).hexdigest()[:24] + ".bin")

    def get(self, url: str, use_cache: bool = False, cache_max_age: int = 7 * 86400,
            max_bytes: int | None = None, timeout: int | None = None) -> bytes | None:
        cap = max_bytes or self.max_bytes
        path = self._raw_path(url)
        if use_cache and path.exists() and time.time() - path.stat().st_mtime < cache_max_age:
            log.debug("cache hit %s", url)
            return path.read_bytes()
        read_timeout = timeout or max(self.timeout, 60)
        last_err = None
        for attempt in range(1, self.retries + 1):
            try:
                self._polite(url)
                resp = self.session.get(url, timeout=(10, read_timeout), stream=True,
                                        allow_redirects=True)
                if resp.status_code != 200:
                    last_err = f"HTTP {resp.status_code}"
                    log.warning("GET %s -> %s", url, last_err)
                    if resp.status_code in (404, 403, 410):
                        break
                    time.sleep(2 * attempt)
                    continue
                buf = bytearray()
                for chunk in resp.iter_content(chunk_size=65536):
                    buf.extend(chunk)
                    if len(buf) > cap:
                        log.warning("GET %s exceeded size cap %d, truncating", url, cap)
                        break
                data = bytes(buf)
                path.write_bytes(data)
                return data
            except Exception as exc:  # noqa: BLE001
                last_err = str(exc)
                log.warning("GET %s failed (try %d/%d): %s", url, attempt, self.retries, exc)
                time.sleep(2 * attempt)
        log.error("GET %s giving up: %s", url, last_err)
        # stale-if-error: fall back to any previously cached copy
        if path.exists():
            log.warning("GET %s using stale cache (%d bytes)", url, path.stat().st_size)
            return path.read_bytes()
        return None

    def get_text(self, url: str, use_cache: bool = False, cache_max_age: int = 7 * 86400,
                 timeout: int | None = None) -> str | None:
        data = self.get(url, use_cache=use_cache, cache_max_age=cache_max_age, timeout=timeout)
        if data is None:
            return None
        for enc in ("utf-8", "utf-8-sig", "latin-1"):
            try:
                return data.decode(enc)
            except UnicodeDecodeError:
                continue
        return data.decode("utf-8", errors="replace")
