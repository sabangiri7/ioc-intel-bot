from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .models import Mention, MALWARE_VIEW_CATEGORIES, view_flags

log = logging.getLogger("iocbot.store")

PRAGMAS = (
    ("journal_mode", "WAL"),
    ("synchronous", "NORMAL"),
    ("busy_timeout", "30000"),
    ("cache_size", "-16000"),
    ("mmap_size", "134217728"),
    ("temp_store", "MEMORY"),
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS iocs (
    ioc TEXT NOT NULL,
    ioc_type TEXT NOT NULL,
    threat TEXT DEFAULT '',
    malware_family TEXT DEFAULT '',
    threat_actor TEXT DEFAULT '',
    campaign TEXT DEFAULT '',
    category TEXT DEFAULT '',
    confidence TEXT DEFAULT '',
    severity TEXT DEFAULT '',
    first_seen TEXT DEFAULT '',
    last_seen TEXT DEFAULT '',
    source TEXT DEFAULT '',
    source_url TEXT DEFAULT '',
    description TEXT DEFAULT '',
    tags TEXT DEFAULT '',
    mitre_attack TEXT DEFAULT '',
    crowdstrike_supported TEXT DEFAULT 'NO',
    crowdstrike_importable TEXT DEFAULT 'NO',
    validation_status TEXT DEFAULT '',
    sources_detail TEXT DEFAULT '[]',
    evidence TEXT DEFAULT '[]',
    first_cycle INTEGER DEFAULT 0,
    last_cycle INTEGER DEFAULT 0,
    updated_at TEXT DEFAULT '',
    flag_c2 INTEGER NOT NULL DEFAULT 0,
    flag_malware INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (ioc_type, ioc)
);
CREATE TABLE IF NOT EXISTS cycles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started TEXT,
    finished TEXT,
    stats TEXT
);
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS folders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL DEFAULT 'manual',
    field TEXT DEFAULT '',
    value TEXT DEFAULT '',
    description TEXT DEFAULT '',
    color TEXT DEFAULT '',
    created_at TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS folder_iocs (
    folder_id INTEGER NOT NULL,
    ioc_type TEXT NOT NULL,
    ioc TEXT NOT NULL,
    added_at TEXT DEFAULT '',
    PRIMARY KEY (folder_id, ioc_type, ioc)
);
CREATE TABLE IF NOT EXISTS ioc_categories (
    ioc_type TEXT NOT NULL,
    ioc TEXT NOT NULL,
    category TEXT NOT NULL,
    PRIMARY KEY (ioc_type, ioc, category)
);
CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    prefix TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    scopes TEXT NOT NULL DEFAULT 'read',
    platform TEXT DEFAULT '',
    created_at TEXT DEFAULT '',
    last_used_at TEXT DEFAULT '',
    uses INTEGER DEFAULT 0,
    last_ip TEXT DEFAULT '',
    revoked INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS push_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT,
    status TEXT,
    sent INTEGER DEFAULT 0,
    detail TEXT DEFAULT '',
    pushed_at TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    full_name TEXT DEFAULT '',
    created_at TEXT DEFAULT '',
    last_login_at TEXT DEFAULT ''
);
CREATE VIRTUAL TABLE IF NOT EXISTS iocs_fts USING fts5(
    ioc, malware_family, threat_actor, description, tags
);
"""

INDEXES = """
CREATE INDEX IF NOT EXISTS idx_iocs_ioc ON iocs(ioc);
CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(ioc_type);
CREATE INDEX IF NOT EXISTS idx_iocs_severity ON iocs(severity);
CREATE INDEX IF NOT EXISTS idx_iocs_confidence ON iocs(confidence);
CREATE INDEX IF NOT EXISTS idx_iocs_family ON iocs(malware_family);
CREATE INDEX IF NOT EXISTS idx_iocs_actor ON iocs(threat_actor);
CREATE INDEX IF NOT EXISTS idx_iocs_last_seen ON iocs(last_seen);
CREATE INDEX IF NOT EXISTS idx_iocs_first_seen ON iocs(first_seen);
CREATE INDEX IF NOT EXISTS idx_iocs_updated ON iocs(updated_at);
CREATE INDEX IF NOT EXISTS idx_iocs_importable ON iocs(crowdstrike_importable);
CREATE INDEX IF NOT EXISTS idx_iocs_validation ON iocs(validation_status);
CREATE INDEX IF NOT EXISTS idx_iocs_first_cycle ON iocs(first_cycle);
CREATE INDEX IF NOT EXISTS idx_cat_category ON ioc_categories(category);
CREATE INDEX IF NOT EXISTS idx_folder_iocs_ioc ON folder_iocs(ioc_type, ioc);
CREATE INDEX IF NOT EXISTS idx_push_log_at ON push_log(pushed_at);
"""

FLAG_INDEXES = (
    "CREATE INDEX IF NOT EXISTS idx_iocs_flag_c2 ON iocs(flag_c2)",
    "CREATE INDEX IF NOT EXISTS idx_iocs_flag_malware ON iocs(flag_malware)",
)

CREATE_TRIGGERS = """
CREATE TRIGGER IF NOT EXISTS iocs_fts_insert AFTER INSERT ON iocs BEGIN
    INSERT INTO iocs_fts(rowid, ioc, malware_family, threat_actor, description, tags)
    VALUES (new.rowid, new.ioc, new.malware_family, new.threat_actor,
            new.description, new.tags);
END;
CREATE TRIGGER IF NOT EXISTS iocs_fts_delete AFTER DELETE ON iocs BEGIN
    DELETE FROM iocs_fts WHERE rowid = old.rowid;
END;
CREATE TRIGGER IF NOT EXISTS iocs_fts_update AFTER UPDATE ON iocs BEGIN
    DELETE FROM iocs_fts WHERE rowid = old.rowid;
    INSERT INTO iocs_fts(rowid, ioc, malware_family, threat_actor, description, tags)
    VALUES (new.rowid, new.ioc, new.malware_family, new.threat_actor,
            new.description, new.tags);
END;
"""

DROP_STALE_TRIGGERS = """
DROP TRIGGER IF EXISTS iocs_fts_insert;
DROP TRIGGER IF EXISTS iocs_fts_delete;
DROP TRIGGER IF EXISTS iocs_fts_update;
"""


def open_db(path: Path) -> sqlite3.Connection:
    """Open the shared state database with speed-oriented pragmas (WAL)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=30)
    conn.row_factory = sqlite3.Row
    for pragma, value in PRAGMAS:
        conn.execute(f"PRAGMA {pragma} = {value}")
    return conn


def _backfill(conn: sqlite3.Connection) -> None:
    """One-time migration/backfill, serialized across processes with a write lock."""
    try:
        conn.execute("BEGIN IMMEDIATE")
    except sqlite3.ProgrammingError:
        pass
    else:
        try:
            _ensure_columns(conn)
            for stmt in FLAG_INDEXES:
                conn.execute(stmt)
            _backfill_locked(conn)
            _backfill_flags(conn)
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise


FLAG_COLUMNS = {
    "flag_c2": "INTEGER NOT NULL DEFAULT 0",
    "flag_malware": "INTEGER NOT NULL DEFAULT 0",
}


def _ensure_columns(conn: sqlite3.Connection) -> None:
    existing = {r[1] for r in conn.execute("PRAGMA table_info(iocs)")}
    for name, decl in FLAG_COLUMNS.items():
        if name not in existing:
            log.info("adding column iocs.%s", name)
            conn.execute(f"ALTER TABLE iocs ADD COLUMN {name} {decl}")
    for table, name, decl in (
        ("api_keys", "uses", "INTEGER DEFAULT 0"),
        ("api_keys", "last_ip", "TEXT DEFAULT ''"),
        ("api_keys", "platform", "TEXT DEFAULT ''"),
    ):
        cols = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
        if name not in cols:
            log.info("adding column %s.%s", table, name)
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")


def _flagged(conn: sqlite3.Connection, key: str) -> bool:
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return bool(row and row[0])


def _backfill_flags(conn: sqlite3.Connection) -> None:
    if _flagged(conn, "flags_backfilled"):
        return
    log.info("backfilling category view flags")
    conn.execute(
        "UPDATE iocs SET flag_c2 = 1 WHERE (ioc_type, ioc) IN "
        "(SELECT ioc_type, ioc FROM ioc_categories WHERE category = 'C2')"
    )
    marks = ", ".join("?" for _ in MALWARE_VIEW_CATEGORIES)
    conn.execute(
        f"UPDATE iocs SET flag_malware = 1 WHERE (ioc_type, ioc) IN "
        f"(SELECT ioc_type, ioc FROM ioc_categories WHERE category IN ({marks}))",
        tuple(sorted(MALWARE_VIEW_CATEGORIES)),
    )
    conn.execute(
        "INSERT OR REPLACE INTO meta (key, value) VALUES ('flags_backfilled', ?)",
        (datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),),
    )


def _backfill_locked(conn: sqlite3.Connection) -> None:
    total = conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
    if not total:
        return
    cats = conn.execute("SELECT COUNT(*) FROM ioc_categories").fetchone()[0]
    if not cats:
        log.info("backfilling category index for %d rows", total)
        cur = conn.execute(
            "SELECT ioc_type, ioc, category FROM iocs WHERE category != ''"
        )
        batch: list[tuple[str, str, str]] = []
        for row in cur:
            for cat in str(row["category"]).split(";"):
                cat = cat.strip()
                if cat:
                    batch.append((row["ioc_type"], row["ioc"], cat))
            if len(batch) >= 20000:
                conn.executemany(
                    "INSERT OR IGNORE INTO ioc_categories (ioc_type, ioc, category) "
                    "VALUES (?, ?, ?)", batch)
                batch = []
        if batch:
            conn.executemany(
                "INSERT OR IGNORE INTO ioc_categories (ioc_type, ioc, category) "
                "VALUES (?, ?, ?)", batch)
    fts = conn.execute("SELECT COUNT(*) FROM iocs_fts").fetchone()[0]
    if not fts:
        log.info("backfilling full-text index for %d rows", total)
        conn.execute(
            "INSERT INTO iocs_fts(rowid, ioc, malware_family, threat_actor, "
            "description, tags) SELECT rowid, ioc, malware_family, threat_actor, "
            "description, tags FROM iocs"
        )


def _ensure_triggers(conn: sqlite3.Connection) -> None:
    rows = list(conn.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name LIKE 'iocs_fts_%'"
    ))
    sqls = [r[0] or "" for r in rows]
    stale = len(sqls) != 3 or any("'delete'" in s or "iocs_fts(iocs_fts," in s for s in sqls)
    if stale:
        conn.executescript(DROP_STALE_TRIGGERS)
    conn.executescript(CREATE_TRIGGERS)


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    conn.executescript(INDEXES)
    _ensure_triggers(conn)
    conn.commit()
    _backfill(conn)

MAX_DESC = 1500
MAX_SOURCES = 12
MAX_EVIDENCE = 5


def _uniq_append(existing: list, new_items, cap: int | None = None) -> list:
    out = list(existing)
    for item in new_items:
        if item and item not in out:
            out.append(item)
    if cap is not None and len(out) > cap:
        out = out[:cap]
    return out


def _today(value: str) -> str:
    if not value:
        return ""
    v = value.strip()
    return v[:10] if len(v) >= 10 else v


class Store:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.conn = open_db(self.path)
        ensure_schema(self.conn)
        self.rows: dict[tuple[str, str], dict] = {}
        self.touched: set[tuple[str, str]] = set()

    def close(self) -> None:
        self.conn.close()

    # -- cycles -----------------------------------------------------------
    def begin_cycle(self) -> int:
        cur = self.conn.execute(
            "INSERT INTO cycles (started, stats) VALUES (?, '')",
            (datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def close_cycle(self, cycle_id: int, stats: dict) -> None:
        self.conn.execute(
            "UPDATE cycles SET finished = ?, stats = ? WHERE id = ?",
            (
                datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                json.dumps(stats, default=str)[:20000],
                cycle_id,
            ),
        )
        self.conn.commit()

    def previous_cycle_before(self, cycle_id: int) -> int | None:
        row = self.conn.execute(
            "SELECT MAX(id) AS m FROM cycles WHERE id < ?", (cycle_id,)
        ).fetchone()
        return row["m"] if row and row["m"] else None

    # -- loading ----------------------------------------------------------
    def load_all(self) -> None:
        self.rows = {}
        for r in self.conn.execute("SELECT * FROM iocs"):
            key = (r["ioc_type"], r["ioc"])
            row = dict(r)
            row["categories"] = [c for c in (row.get("category") or "").split(";") if c]
            row["tags_list"] = [t for t in (row.get("tags") or "").split(";") if t]
            row["source_list"] = [s for s in (row.get("source") or "").split(" | ") if s]
            row["source_url_list"] = [s for s in (row.get("source_url") or "").split(" | ") if s]
            row["description_list"] = [s for s in (row.get("description") or "").split(" || ") if s]
            row["mitre_list"] = [s for s in (row.get("mitre_attack") or "").split(";") if s]
            try:
                row["sources_detail"] = json.loads(row.get("sources_detail") or "[]")
            except json.JSONDecodeError:
                row["sources_detail"] = []
            try:
                row["evidence"] = json.loads(row.get("evidence") or "[]")
            except json.JSONDecodeError:
                row["evidence"] = []
            self.rows[key] = row

    # -- upsert -----------------------------------------------------------
    def upsert(self, mention: Mention, status: str, flags: set[str]) -> tuple[str, str]:
        key = (mention.ioc_type, mention.value)
        src_detail = {
            "name": mention.source_name,
            "url": mention.source_url,
            "tier": mention.tier,
            "explicit_c2": mention.explicit_c2,
            "explicit_malware": mention.explicit_malware,
            "active": mention.active,
            "feed_confidence": mention.feed_confidence,
        }
        first_seen = _today(mention.first_seen)
        last_seen = _today(mention.last_seen)
        if not last_seen:
            last_seen = first_seen

        row = self.rows.get(key)
        if row is None:
            row = {
                "ioc": mention.value,
                "ioc_type": mention.ioc_type,
                "threat": mention.threat,
                "malware_family": mention.malware_family,
                "threat_actor": mention.threat_actor,
                "campaign": mention.campaign,
                "categories": [],
                "tags_list": [],
                "source_list": [],
                "source_url_list": [],
                "description_list": [],
                "mitre_list": [],
                "confidence": "",
                "severity": "",
                "first_seen": first_seen,
                "last_seen": last_seen,
                "validation_status": status,
                "sources_detail": [],
                "evidence": [],
            }
            self.rows[key] = row
        else:
            if status == "VALID":
                row["validation_status"] = "VALID"
            elif not row.get("validation_status"):
                row["validation_status"] = status

        row["categories"] = _uniq_append(row["categories"], mention.categories)
        row["tags_list"] = _uniq_append(row["tags_list"], mention.tags, 30)
        row["source_list"] = _uniq_append(row["source_list"], [mention.source_name], MAX_SOURCES)
        row["source_url_list"] = _uniq_append(row["source_url_list"], [mention.source_url], MAX_SOURCES)
        if mention.description:
            row["description_list"] = _uniq_append(row["description_list"], [mention.description], 6)
        if mention.evidence:
            row["evidence"] = _uniq_append(row["evidence"], [mention.evidence], MAX_EVIDENCE)
        existing_src = {s.get("name") for s in row["sources_detail"]}
        if mention.source_name not in existing_src:
            row["sources_detail"].append(src_detail)
        else:
            row["sources_detail"] = [
                src_detail if s.get("name") == mention.source_name else s
                for s in row["sources_detail"]
            ]
        if not row.get("malware_family") and mention.malware_family:
            row["malware_family"] = mention.malware_family
        if not row.get("threat_actor") and mention.threat_actor:
            row["threat_actor"] = mention.threat_actor
        if not row.get("campaign") and mention.campaign:
            row["campaign"] = mention.campaign
        if first_seen and (not row.get("first_seen") or first_seen < row["first_seen"]):
            row["first_seen"] = first_seen
        if last_seen and (not row.get("last_seen") or last_seen > row["last_seen"]):
            row["last_seen"] = last_seen

        for f in sorted(flags):
            if f and f not in row["tags_list"]:
                row["tags_list"].append(f)

        self.touched.add(key)
        return key

    def add_entity(self, value: str, ioc_type: str, source_name: str, source_url: str,
                   tier: str, first_seen: str, last_seen: str, categories: list[str],
                   tags: list[str], description: str) -> None:
        if not value:
            return
        from .validate import VALID

        m = Mention(
            value=value, ioc_type=ioc_type, source_name=source_name, source_url=source_url,
            tier=tier, first_seen=first_seen, last_seen=last_seen,
            categories=categories, tags=tags, description=description,
        )
        self.upsert(m, VALID, {"entity"})

    # -- persist ----------------------------------------------------------
    def flush(self, cycle_id: int) -> int:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        count = 0
        for key in self.touched:
            row = self.rows[key]
            desc = " || ".join(row.get("description_list", []))[:MAX_DESC]
            evs = row.get("evidence") or []
            if evs and isinstance(evs, list):
                ev_text = str(evs[0])
                if ev_text and ev_text not in desc:
                    desc = f"{desc} || EVIDENCE: {ev_text}"[:MAX_DESC]
            flag_c2, flag_malware = view_flags(row.get("categories", []))
            payload = {
                "ioc": row["ioc"],
                "ioc_type": row["ioc_type"],
                "threat": row.get("threat", ""),
                "malware_family": row.get("malware_family", ""),
                "threat_actor": row.get("threat_actor", ""),
                "campaign": row.get("campaign", ""),
                "category": ";".join(row.get("categories", [])),
                "confidence": row.get("confidence", ""),
                "severity": row.get("severity", ""),
                "first_seen": row.get("first_seen", ""),
                "last_seen": row.get("last_seen", ""),
                "source": " | ".join(row.get("source_list", [])),
                "source_url": " | ".join(row.get("source_url_list", [])),
                "description": desc,
                "tags": ";".join(row.get("tags_list", [])),
                "mitre_attack": ";".join(row.get("mitre_list", [])),
                "crowdstrike_supported": row.get("crowdstrike_supported", "NO"),
                "crowdstrike_importable": row.get("crowdstrike_importable", "NO"),
                "validation_status": row.get("validation_status", ""),
                "sources_detail": json.dumps(row.get("sources_detail", []))[:8000],
                "evidence": json.dumps(row.get("evidence", []))[:4000],
                "flag_c2": flag_c2,
                "flag_malware": flag_malware,
                "first_cycle": self._first_cycle(key, cycle_id),
                "last_cycle": cycle_id,
                "updated_at": now,
            }
            cols = ", ".join(payload)
            placeholders = ", ".join("?" for _ in payload)
            updates = ", ".join(f"{c} = excluded.{c}" for c in payload if c not in ("ioc", "ioc_type"))
            self.conn.execute(
                f"INSERT INTO iocs ({cols}) VALUES ({placeholders}) "
                f"ON CONFLICT(ioc_type, ioc) DO UPDATE SET {updates}",
                tuple(payload.values()),
            )
            self.conn.execute(
                "DELETE FROM ioc_categories WHERE ioc_type = ? AND ioc = ?",
                (row["ioc_type"], row["ioc"]),
            )
            cats = [c for c in row.get("categories", []) if c]
            if cats:
                self.conn.executemany(
                    "INSERT OR IGNORE INTO ioc_categories (ioc_type, ioc, category) "
                    "VALUES (?, ?, ?)",
                    [(row["ioc_type"], row["ioc"], c) for c in cats],
                )
            count += 1
        self.conn.commit()
        return count

    def _first_cycle(self, key: tuple[str, str], cycle_id: int) -> int:
        row = self.conn.execute(
            "SELECT first_cycle FROM iocs WHERE ioc_type = ? AND ioc = ?",
            (key[0], key[1]),
        ).fetchone()
        if row and row["first_cycle"]:
            return row["first_cycle"]
        existing = self.rows.get(key)
        if existing and existing.get("first_cycle"):
            return existing["first_cycle"]
        return cycle_id

    # -- queries ----------------------------------------------------------
    def _hydrate(self, row: dict) -> dict:
        row["categories"] = [c for c in (row.get("category") or "").split(";") if c]
        row["tags_list"] = [t for t in (row.get("tags") or "").split(";") if t]
        for field in ("sources_detail", "evidence", "mitre_list"):
            val = row.get(field)
            if isinstance(val, str):
                try:
                    row[field] = json.loads(val) if val else []
                except json.JSONDecodeError:
                    row[field] = []
        if row.get("mitre_attack"):
            row["mitre_list"] = [m for m in row["mitre_attack"].split(";") if m]
        return row

    def all_rows(self) -> list[dict]:
        return [self._hydrate(dict(r)) for r in self.conn.execute("SELECT * FROM iocs")]

    def new_rows(self, cycle_id: int) -> list[dict]:
        return [
            self._hydrate(dict(r))
            for r in self.conn.execute(
                "SELECT * FROM iocs WHERE first_cycle = ? ORDER BY ioc_type, ioc",
                (cycle_id,),
            )
        ]

    def counts(self) -> dict:
        total = self.conn.execute("SELECT COUNT(*) c FROM iocs").fetchone()["c"]
        by_type = {
            r["ioc_type"]: r["c"]
            for r in self.conn.execute(
                "SELECT ioc_type, COUNT(*) c FROM iocs GROUP BY ioc_type ORDER BY c DESC"
            )
        }
        return {"total": total, "by_type": by_type}
