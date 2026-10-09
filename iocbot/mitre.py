from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path

log = logging.getLogger("iocbot.mitre")

_TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


class MitreIndex:
    def __init__(self, fetcher, cache_path: Path, refresh_days: int = 30):
        self.fetcher = fetcher
        self.cache_path = Path(cache_path)
        self.refresh_days = refresh_days
        self.malware: dict[str, dict] = {}
        self.groups: dict[str, dict] = {}
        self.group_aliases: dict[str, dict] = {}
        self.technique_names: dict[str, str] = {}
        self.loaded = False

    def load(self, url: str) -> bool:
        if self.loaded:
            return True
        try:
            if self._cache_fresh():
                raw = self.cache_path.read_bytes()
            else:
                raw = self.fetcher.get(url, max_bytes=80 * 1024 * 1024)
                if raw:
                    self.cache_path.write_bytes(raw)
            if not raw:
                if self.cache_path.exists():
                    raw = self.cache_path.read_bytes()
                else:
                    return False
            self._parse(raw)
            self.loaded = True
            return True
        except Exception as exc:  # noqa: BLE001
            log.error("MITRE ATT&CK load failed: %s", exc)
            if self.cache_path.exists():
                try:
                    self._parse(self.cache_path.read_bytes())
                    self.loaded = True
                    return True
                except Exception:  # noqa: BLE001
                    return False
            return False

    def _cache_fresh(self) -> bool:
        return (
            self.cache_path.exists()
            and time.time() - self.cache_path.stat().st_mtime < self.refresh_days * 86400
        )

    def _parse(self, raw: bytes) -> None:
        bundle = json.loads(raw.decode("utf-8", errors="replace"))
        objects = bundle.get("objects", [])
        del bundle

        attack_patterns: dict[str, str] = {}
        for obj in objects:
            if obj.get("type") == "attack-pattern" and not obj.get("revoked"):
                tid = None
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                        tid = ref["external_id"]
                        break
                if tid:
                    attack_patterns[obj["id"]] = tid
                name = obj.get("name", "")
                if name:
                    self.technique_names[name.lower()] = tid or name

        malware_ids: dict[str, dict] = {}
        for obj in objects:
            if obj.get("type") == "malware" and not obj.get("revoked"):
                info = {
                    "name": obj.get("name", ""),
                    "techniques": set(),
                }
                malware_ids[obj["id"]] = info
                for alias in [obj.get("name", "")] + list(obj.get("aliases", []) or []):
                    if alias:
                        self.malware.setdefault(alias.lower(), info)

        group_ids: dict[str, dict] = {}
        for obj in objects:
            if obj.get("type") == "intrusion-set" and not obj.get("revoked"):
                gid = ""
                gname = obj.get("name", "")
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                        gid = ref["external_id"]
                        break
                info = {"id": gid, "name": gname, "techniques": set()}
                group_ids[obj["id"]] = info
                aliases = [gname] + list(obj.get("aliases") or [])
                for alias in aliases:
                    if alias:
                        self.group_aliases.setdefault(alias.lower(), info)

        for obj in objects:
            if obj.get("type") != "relationship":
                continue
            if obj.get("relationship_type") != "uses":
                continue
            src, tgt = obj.get("source_ref", ""), obj.get("target_ref", "")
            tid = attack_patterns.get(tgt)
            if not tid:
                continue
            if src in malware_ids:
                malware_ids[src]["techniques"].add(tid)
            if src in group_ids:
                group_ids[src]["techniques"].add(tid)

        for info in self.malware.values():
            info["techniques"] = sorted(info["techniques"])
        for info in self.group_aliases.values():
            info["techniques"] = sorted(info["techniques"])
        del objects, attack_patterns, malware_ids, group_ids

    def techniques_for_malware(self, family: str) -> list[str]:
        if not family or not self.loaded:
            return []
        info = self.malware.get(family.lower())
        if not info:
            for key, val in self.malware.items():
                if family.lower() in key or key in family.lower():
                    info = val
                    break
        return list(info["techniques"])[:8] if info else []

    def resolve_actor(self, name: str) -> dict | None:
        if not name or not self.loaded:
            return None
        return self.group_aliases.get(name.lower())

    def techniques_for_actor(self, name: str) -> list[str]:
        info = self.resolve_actor(name)
        return list(info["techniques"])[:8] if info else []

    def group_id(self, name: str) -> str:
        info = self.resolve_actor(name)
        return info["id"] if info else ""

    def find_actors(self, text: str) -> list[dict]:
        if not self.loaded:
            return []
        found = []
        low = text.lower()
        for alias, info in self.group_aliases.items():
            if len(alias) < 5:
                continue
            if re.search(r"(?<![\w-])" + re.escape(alias) + r"(?![\w-])", low):
                if info not in found:
                    found.append(info)
            if len(found) >= 5:
                break
        return found

    @staticmethod
    def technique_ids_in(text: str) -> list[str]:
        return sorted(set(_TECH_RE.findall(text)))
