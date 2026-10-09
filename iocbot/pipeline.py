from __future__ import annotations

import logging
import time
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from .collectors import COLLECTORS
from .collectors.reports import collect_reports
from .export import write_all
from .http import Fetcher
from .models import Mention
from .normalize import norm_value
from .score import score_row
from .store import Store
from .validate import Validator

log = logging.getLogger("iocbot.pipeline")

INFRA_FROM_URL = {"IPv4", "IPv6", "Domain"}


class Pipeline:
    def __init__(self, root: Path, config_dir: Path, data_dir: Path, output_dir: Path):
        self.root = root
        self.config_dir = Path(config_dir)
        self.data_dir = Path(data_dir)
        self.output_dir = Path(output_dir)
        (self.data_dir / "cache").mkdir(parents=True, exist_ok=True)
        (self.data_dir / "logs").mkdir(parents=True, exist_ok=True)
        (self.output_dir).mkdir(parents=True, exist_ok=True)

        self.sources_cfg = yaml.safe_load((self.config_dir / "sources.yaml").read_text())
        self.cs_cfg = yaml.safe_load((self.config_dir / "crowdstrike.yaml").read_text())
        self.validator = Validator(self.config_dir / "validation.yaml")
        self.fetcher = Fetcher(self.data_dir / "cache" / "raw")
        self.store = Store(self.data_dir / "state.db")
        self.mitre = None

    # -- MITRE ------------------------------------------------------------
    def _load_mitre(self) -> None:
        mcfg = (self.sources_cfg or {}).get("mitre") or {}
        if not mcfg.get("enabled", False):
            return
        from .mitre import MitreIndex

        self.mitre = MitreIndex(
            self.fetcher,
            self.data_dir / "cache" / "enterprise-attack.json",
            int(mcfg.get("refresh_days", 30)),
        )
        ok = self.mitre.load(mcfg["url"])
        log.info("MITRE ATT&CK index loaded: %s (%d malware, %d actors)",
                 ok, len(self.mitre.malware), len(self.mitre.group_aliases))

    # -- URL derivation ---------------------------------------------------
    def _derive_from_url(self, m: Mention) -> list[Mention]:
        if m.ioc_type != "URL" or m.derived:
            return []
        try:
            host = (urlsplit(m.value).hostname or "").strip().lower().rstrip(".")
        except ValueError:
            return []
        if not host:
            return []
        import ipaddress

        try:
            ipaddress.ip_address(host)
            itype = "IPv4" if ":" not in host else "IPv6"
        except ValueError:
            itype = "Domain"
        if itype not in INFRA_FROM_URL:
            return []
        return [Mention(
            value=host, ioc_type=itype,
            source_name=m.source_name, source_url=m.source_url, tier=m.tier,
            first_seen=m.first_seen, last_seen=m.last_seen,
            explicit_c2=m.explicit_c2, explicit_malware=m.explicit_malware,
            active=m.active, malware_family=m.malware_family,
            threat_actor=m.threat_actor, categories=list(m.categories),
            tags=list(m.tags) + ["derived-from-url"],
            threat=m.threat,
            description=f"Host of malicious URL {m.value} ({m.source_name})",
            evidence=m.evidence,
            derived=True,
        )]

    # -- processing -------------------------------------------------------
    def _process_mentions(self, mentions: list[Mention], cycle_id: int) -> dict:
        stats = {"accepted": 0, "rejected": 0, "reject_reasons": {}, "normalized": 0}
        for m in mentions:
            if not m.value or not m.ioc_type:
                stats["rejected"] += 1
                continue
            res = self.validator.validate(m.value, m.ioc_type, explicit_malicious=m.explicit_malware)
            if not res.valid:
                stats["rejected"] += 1
                reason = res.status.split(":", 1)[1] if ":" in res.status else res.status
                stats["reject_reasons"][reason] = stats["reject_reasons"].get(reason, 0) + 1
                log.debug("reject %s (%s): %s", m.value[:80], m.ioc_type, res.status)
                continue
            new_value = norm_value(m.value, m.ioc_type)
            if not new_value:
                stats["rejected"] += 1
                continue
            m.value = new_value
            if res.status != "VALID" and "shared-platform" not in m.tags:
                m.tags = list(m.tags) + ["shared-platform"]
            self.store.upsert(m, res.status, res.flags)
            stats["accepted"] += 1
            if m.tier in ("A", "B"):
                for extra in self._derive_from_url(m):
                    res2 = self.validator.validate(extra.value, extra.ioc_type,
                                                   explicit_malicious=True)
                    if res2.valid:
                        extra.value = norm_value(extra.value, extra.ioc_type)
                        if res2.status != "VALID" and "shared-platform" not in extra.tags:
                            extra.tags = list(extra.tags) + ["shared-platform"]
                        self.store.upsert(extra, res2.status, res2.flags)
                        stats["accepted"] += 1
        return stats

    def _score_touched(self) -> int:
        count = 0
        for key in list(self.store.touched):
            row = self.store.rows.get(key)
            if not row:
                continue
            score_row(row)
            family = row.get("malware_family", "")
            actor = row.get("threat_actor", "")
            if self.mitre and self.mitre.loaded:
                techs = []
                if family:
                    techs += self.mitre.techniques_for_malware(family)
                if actor:
                    gid = self.mitre.group_id(actor)
                    if gid and gid not in row["mitre_list"]:
                        row["mitre_list"].append(gid)
                    techs += self.mitre.techniques_for_actor(actor)
                for t in techs:
                    if t not in row["mitre_list"]:
                        row["mitre_list"].append(t)
                row["mitre_list"] = row["mitre_list"][:12]
                if actor and not row.get("threat_actor"):
                    row["threat_actor"] = actor
            count += 1
        return count

    @staticmethod
    def _merge_proc(total: dict, batch: dict) -> dict:
        total["accepted"] += batch.get("accepted", 0)
        total["rejected"] += batch.get("rejected", 0)
        for reason, count in batch.get("reject_reasons", {}).items():
            total["reject_reasons"][reason] = total["reject_reasons"].get(reason, 0) + count
        return total

    # -- main -------------------------------------------------------------
    def run(self, sources_filter: str | None = None, max_articles: int | None = None,
            skip_reports: bool = False, skip_blocklists: bool = False) -> dict:
        start = time.time()
        cycle_id = self.store.begin_cycle()
        self.store.load_all()
        first_run = len(self.store.rows) == 0
        log.info("cycle %d started (existing rows: %d, first_run=%s)",
                 cycle_id, len(self.store.rows), first_run)

        self._load_mitre()

        all_mentions = 0
        proc: dict = {"accepted": 0, "rejected": 0, "reject_reasons": {}}
        source_stats: list[dict] = []

        def match(name: str) -> bool:
            if not sources_filter:
                return True
            return sources_filter.lower() in name.lower()

        for cfg in (self.sources_cfg or {}).get("feeds", []):
            if not cfg.get("enabled", True) or not match(cfg.get("name", "")):
                continue
            kind = cfg.get("kind")
            fn = COLLECTORS.get(kind)
            if fn is None:
                continue
            try:
                if kind == "threatfox":
                    m, s = fn(cfg, self.fetcher, first_run=first_run)
                else:
                    m, s = fn(cfg, self.fetcher)
            except Exception as exc:  # noqa: BLE001
                log.exception("collector %s failed", cfg.get("name"))
                m, s = [], {"source": cfg.get("name"), "kind": kind,
                            "fetched": False, "mentions": 0, "errors": [str(exc)]}
            source_stats.append(s)
            self._merge_proc(proc, self._process_mentions(m, cycle_id))
            all_mentions += len(m)
            del m
            log.info("feed %s: %d mentions (%s)", cfg.get("name"), all_mentions,
                     "ok" if s.get("fetched") else "FAILED")

        if not skip_blocklists:
            for cfg in (self.sources_cfg or {}).get("blocklists", []):
                if not cfg.get("enabled", True) or not match(cfg.get("name", "")):
                    continue
                fn = COLLECTORS.get(cfg.get("kind"))
                if fn is None:
                    continue
                try:
                    m, s = fn(cfg, self.fetcher)
                except Exception as exc:  # noqa: BLE001
                    log.exception("collector %s failed", cfg.get("name"))
                    m, s = [], {"source": cfg.get("name"), "fetched": False,
                                "mentions": 0, "errors": [str(exc)]}
                source_stats.append(s)
                self._merge_proc(proc, self._process_mentions(m, cycle_id))
                all_mentions += len(m)
                del m
                log.info("blocklist %s: %d mentions (%s)", cfg.get("name"), all_mentions,
                         "ok" if s.get("fetched") else "FAILED")

        if not skip_reports:
            for cfg in (self.sources_cfg or {}).get("reports", []):
                if not cfg.get("enabled", True) or not match(cfg.get("name", "")):
                    continue
                try:
                    m, s = collect_reports(cfg, self.fetcher, mitre=self.mitre,
                                           max_articles=max_articles)
                except Exception as exc:  # noqa: BLE001
                    log.exception("report collector %s failed", cfg.get("name"))
                    m, s = [], {"source": cfg.get("name"), "fetched": False,
                                "mentions": 0, "errors": [str(exc)]}
                source_stats.append(s)
                self._merge_proc(proc, self._process_mentions(m, cycle_id))
                all_mentions += len(m)
                del m
                log.info("report feed %s: %d mentions (%d articles)",
                         cfg.get("name"), all_mentions, s.get("articles", 0))

        scored = self._score_touched()
        self.mitre = None  # free the ATT&CK index before persistence/export
        written = self.store.flush(cycle_id)
        self.store.rows.clear()
        self.store.touched.clear()

        rows = self.store.all_rows()
        new_rows = self.store.new_rows(cycle_id)
        from datetime import date as _date

        from .folders import build_folder_buckets, sync_auto_folders

        sync_auto_folders(self.store.conn)
        folder_buckets = build_folder_buckets(self.store.conn, rows)

        daily_dir = self.output_dir / "daily" / _date.today().isoformat()
        export_counts = write_all(daily_dir, rows, new_rows, self.cs_cfg,
                                  folder_buckets)

        from collections import Counter

        totals: dict[str, int] = {"total": len(rows)}
        for t, c in Counter(r.get("ioc_type", "") for r in rows).most_common():
            totals[f"type:{t}"] = c
        for label, field in (
            ("confidence", "confidence"),
            ("severity", "severity"),
            ("crowdstrike_importable", "crowdstrike_importable"),
            ("validation_status", "validation_status"),
        ):
            for k, v in Counter(str(r.get(field, "")) for r in rows).most_common():
                totals[f"{label}:{k}"] = v

        distribution = {
            "confidence": dict(Counter(r.get("confidence", "") for r in rows)),
            "severity": dict(Counter(r.get("severity", "") for r in rows)),
            "crowdstrike_importable": dict(
                Counter(r.get("crowdstrike_importable", "") for r in rows)
            ),
            "validation_status": dict(
                Counter(r.get("validation_status", "") for r in rows)
            ),
        }

        duration = round(time.time() - start, 1)
        stats = {
            "cycle_id": cycle_id,
            "duration_seconds": duration,
            "first_run": first_run,
            "sources": source_stats,
            "mentions_total": all_mentions,
            "processing": proc,
            "rows_scored": scored,
            "rows_written": written,
            "export_counts": export_counts,
            "totals": totals,
            "distribution": distribution,
        }
        from .summary import write_summary

        write_summary(daily_dir / "IOC_SUMMARY.txt", stats)
        self.store.close_cycle(cycle_id, stats)
        log.info("cycle %d finished in %ss: %s", cycle_id, duration, export_counts)
        return stats
