"""Push collected IOCs to SIEM destinations (Splunk HEC, Elasticsearch, webhook).

The pull API in ``iocbot.api`` is the primary integration; this module is for
SIEMs that should receive the feed instead (or in addition). Targets live in
``config/push.yaml`` and authenticate with their own tokens / API keys.
"""
from __future__ import annotations

import argparse
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import requests
import yaml

log = logging.getLogger("iocbot.push")

ROOT = Path(__file__).resolve().parent.parent
SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
TIMEOUT = 30


def load_push_config(config_dir: Path | None = None) -> dict:
    cfg_dir = Path(config_dir) if config_dir else ROOT / "config"
    path = cfg_dir / "push.yaml"
    if not path.is_file():
        return {"enabled": False, "targets": []}
    cfg = yaml.safe_load(path.read_text()) or {}
    if not isinstance(cfg, dict):
        return {"enabled": False, "targets": []}
    cfg.setdefault("enabled", False)
    cfg.setdefault("targets", [])
    cfg.setdefault("min_severity", "HIGH")
    cfg.setdefault("view", "importable")
    cfg.setdefault("batch_limit", 5000)
    return cfg


def _rows(config_dir: Path | None, cfg: dict) -> list[dict]:
    from . import query

    root = ROOT
    db = query.Database(root / "data" / "state.db")
    filters = {
        "view": cfg.get("view", "importable"),
        "min_severity": cfg.get("min_severity", "HIGH"),
        "limit": int(cfg.get("batch_limit", 5000)),
        "sort": "updated_at",
        "order": "desc",
    }
    return query.search_iocs(db.conn, filters)["items"]


def _event(row: dict) -> dict:
    return {
        "ioc": row["ioc"],
        "ioc_type": row["ioc_type"],
        "severity": row.get("severity", ""),
        "confidence": row.get("confidence", ""),
        "categories": row.get("categories", []),
        "malware_family": row.get("malware_family", ""),
        "threat_actor": row.get("threat_actor", ""),
        "folders": row.get("folders", []),
        "validation_status": row.get("validation_status", ""),
        "crowdstrike_importable": row.get("crowdstrike_importable", ""),
        "first_seen": row.get("first_seen", ""),
        "last_seen": row.get("last_seen", ""),
        "sources": row.get("sources", []),
        "tags": row.get("tags", []),
        "description": row.get("description", ""),
    }


def _send(target: dict, rows: list[dict], now: str) -> tuple[str, int, str]:
    kind = (target.get("type") or "webhook").lower()
    headers = {"Content-Type": "application/json"}
    headers.update({str(k): str(v) for k, v in (target.get("headers") or {}).items()})
    verify = target.get("verify_tls", True)
    url = target.get("url") or ""

    if kind == "splunk_hec":
        headers = {"Authorization": f"Bearer {target.get('token', '')}",
                   "Content-Type": "application/json"}
        body = "\n".join(
            json.dumps({"event": _event(row), "sourcetype": target.get("sourcetype",
                                                                      "ioc:intel"),
                        "time": now})
            for row in rows
        )
    elif kind == "elastic":
        if target.get("api_key"):
            headers["Authorization"] = f"ApiKey {target['api_key']}"
        index = target.get("index", "ioc-indicators")
        lines = []
        for row in rows:
            lines.append(json.dumps({"index": {"_index": index}}))
            lines.append(json.dumps(_event(row)))
        body = "\n".join(lines) + "\n"
        url = url.rstrip("/") + "/_bulk"
        headers["Content-Type"] = "application/x-ndjson"
    else:
        if target.get("api_key"):
            headers.setdefault("Authorization", f"Bearer {target['api_key']}")
        body = json.dumps({
            "generated_at": now,
            "target": target.get("name", ""),
            "count": len(rows),
            "iocs": [_event(r) for r in rows],
        })

    resp = requests.post(url, data=body.encode("utf-8"), headers=headers,
                         timeout=TIMEOUT, verify=verify)
    if resp.status_code >= 400:
        return "error", len(rows), f"HTTP {resp.status_code}: {resp.text[:300]}"
    return "ok", len(rows), f"HTTP {resp.status_code}"


def _log(config_dir: Path | None, name: str, status: str, sent: int, detail: str) -> None:
    from .store import open_db

    try:
        conn = open_db(ROOT / "data" / "state.db")
        conn.execute(
            "INSERT INTO push_log (target, status, sent, detail, pushed_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (name, status, sent, detail[:500],
             datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")),
        )
        conn.commit()
        conn.close()
    except Exception:  # noqa: BLE001
        log.exception("failed to write push log")


def push_now(config_dir: Path | None = None, target_names: list[str] | None = None,
             dry_run: bool = False) -> dict:
    cfg = load_push_config(config_dir)
    targets = cfg.get("targets") or []
    if target_names:
        wanted = {t.lower() for t in target_names}
        targets = [t for t in targets if str(t.get("name", "")).lower() in wanted]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if not cfg.get("enabled") or not targets:
        return {"enabled": False, "sent": 0, "targets": [],
                "detail": "push disabled or no targets configured (config/push.yaml)"}

    rows = _rows(config_dir, cfg)
    results = []
    total = 0
    for target in targets:
        name = str(target.get("name") or target.get("type") or "target")
        if dry_run:
            results.append({"target": name, "status": "dry-run", "sent": len(rows),
                            "detail": "not sent"})
            continue
        try:
            status, sent, detail = _send(target, rows, now)
        except Exception as exc:  # noqa: BLE001
            status, sent, detail = "error", 0, str(exc)[:300]
            log.warning("push to %s failed: %s", name, exc)
        results.append({"target": name, "status": status, "sent": sent,
                        "detail": detail})
        if status == "ok":
            total += sent
        if not dry_run:
            _log(config_dir, name, status, sent, detail)
    return {"enabled": True, "sent": total, "rows": len(rows),
            "min_severity": cfg.get("min_severity"), "view": cfg.get("view"),
            "results": results}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="iocbot.push", description="Push the IOC feed to configured SIEM targets"
    )
    parser.add_argument("--config-dir", default=None)
    parser.add_argument("--target", action="append", default=None,
                        help="only push to this target name (repeatable)")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    result = push_now(args.config_dir, args.target, args.dry_run)
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        if not result.get("enabled"):
            print(result.get("detail"))
            return 0
        for r in result.get("results", []):
            print(f"{r['target']}: {r['status']} ({r['sent']} rows) {r['detail']}")
        print(f"total rows: {result.get('rows', 0)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
