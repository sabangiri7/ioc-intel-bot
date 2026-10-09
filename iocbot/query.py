from __future__ import annotations

import datetime as _dt
import re
import sqlite3
import threading
from pathlib import Path

from .models import IOC_TYPES, MALWARE_VIEW_CATEGORIES, view_flags
from .store import ensure_schema, open_db

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
CONFIDENCES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

SEVERITY_SQL = (
    "CASE {col} WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 "
    "WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END"
)

SORTABLE = {
    "ioc": "i.ioc",
    "ioc_type": "i.ioc_type",
    "severity": SEVERITY_SQL.format(col="i.severity"),
    "confidence": SEVERITY_SQL.format(col="i.confidence"),
    "first_seen": "i.first_seen",
    "last_seen": "i.last_seen",
    "updated_at": "i.updated_at",
    "malware_family": "i.malware_family",
    "threat_actor": "i.threat_actor",
}

MAX_LIMIT = 5000
AUTO_FIELDS = {"malware_family", "threat_actor"}


class Database:
    """Thread-local connections to the shared WAL database."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._local = threading.local()

    @property
    def conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = open_db(self.path)
            ensure_schema(conn)
            self._local.conn = conn
        return conn


def _today() -> str:
    return _dt.date.today().isoformat()


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _split(value: str | None, sep: str) -> list[str]:
    return [v for v in (value or "").split(sep) if v]


def _as_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    return [str(v) for v in value if str(v)]


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _fts_expr(q: str) -> str | None:
    tokens = re.findall(r"[0-9A-Za-z_.\-:]+", q)
    parts = []
    for token in tokens:
        inner = re.sub(r"[^0-9A-Za-z_]+", "", token)
        if inner:
            parts.append(f'"{inner}"')
    if not parts:
        return None
    parts[-1] = f"{parts[-1]}*"
    return " AND ".join(parts)


def serialize_row(row, folders: list[str] | None = None) -> dict:
    d = dict(row)
    return {
        "ioc": d.get("ioc", ""),
        "ioc_type": d.get("ioc_type", ""),
        "threat": d.get("threat", ""),
        "malware_family": d.get("malware_family", ""),
        "threat_actor": d.get("threat_actor", ""),
        "campaign": d.get("campaign", ""),
        "categories": _split(d.get("category"), ";"),
        "confidence": d.get("confidence", ""),
        "severity": d.get("severity", ""),
        "first_seen": d.get("first_seen", ""),
        "last_seen": d.get("last_seen", ""),
        "sources": _split(d.get("source"), " | "),
        "source_urls": _split(d.get("source_url"), " | "),
        "description": d.get("description", ""),
        "tags": _split(d.get("tags"), ";"),
        "mitre_attack": _split(d.get("mitre_attack"), ";"),
        "crowdstrike_supported": d.get("crowdstrike_supported", "NO"),
        "crowdstrike_importable": d.get("crowdstrike_importable", "NO"),
        "validation_status": d.get("validation_status", ""),
        "first_cycle": d.get("first_cycle", 0),
        "last_cycle": d.get("last_cycle", 0),
        "updated_at": d.get("updated_at", ""),
        "folders": list(folders or []),
    }


# -- search -----------------------------------------------------------------
def folder_row(conn: sqlite3.Connection, folder_id: int):
    return conn.execute("SELECT * FROM folders WHERE id = ?", (folder_id,)).fetchone()


def build_where(conn: sqlite3.Connection, filters: dict) -> tuple[str, list]:
    where: list[str] = []
    params: list = []

    q = (filters.get("q") or "").strip()
    if q:
        clauses = ["i.ioc = ?", "i.ioc LIKE ? ESCAPE '\\'"]
        params.extend([q, _escape_like(q) + "%"])
        fts = _fts_expr(q)
        if fts:
            clauses.append(
                "i.rowid IN (SELECT rowid FROM iocs_fts WHERE iocs_fts MATCH ?)"
            )
            params.append(fts)
        where.append("(" + " OR ".join(clauses) + ")")

    for col, key in (("ioc_type", "ioc_type"), ("severity", "severity"),
                     ("confidence", "confidence"), ("malware_family", "malware_family"),
                     ("threat_actor", "threat_actor"), ("campaign", "campaign")):
        values = _as_list(filters.get(key))
        if values:
            marks = ", ".join("?" for _ in values)
            where.append(f"i.{col} IN ({marks})")
            params.extend(values)

    categories = _as_list(filters.get("category"))
    if categories:
        marks = ", ".join("?" for _ in categories)
        where.append(
            "(i.ioc_type, i.ioc) IN (SELECT c.ioc_type, c.ioc FROM ioc_categories c "
            f"WHERE c.category IN ({marks}))"
        )
        params.extend(categories)

    if filters.get("validation"):
        where.append("i.validation_status = ?")
        params.append(str(filters["validation"]))
    if filters.get("importable"):
        where.append("i.crowdstrike_importable = 'YES'")
    if filters.get("supported"):
        where.append("i.crowdstrike_supported = 'YES'")
    if filters.get("unreviewed"):
        where.append("(i.validation_status = '' OR i.validation_status = 'UNVERIFIED')")

    view = filters.get("view") or "master"
    if view == "c2":
        where.append("i.flag_c2 = 1")
    elif view == "malware":
        where.append("i.flag_malware = 1")
    elif view == "importable":
        where.append("i.crowdstrike_importable = 'YES'")

    since = filters.get("since")
    if since:
        where.append("i.updated_at > ?")
        params.append(str(since))
    seen_since = filters.get("seen_since")
    if seen_since:
        where.append("i.last_seen >= ?")
        params.append(str(seen_since))

    folder_id = filters.get("folder_id")
    if folder_id:
        folder = folder_row(conn, int(folder_id))
        if folder is None:
            where.append("0 = 1")
        elif folder["kind"] == "auto" and folder["field"] in AUTO_FIELDS:
            where.append(f"i.{folder['field']} = ?")
            params.append(folder["value"])
        else:
            where.append(
                "EXISTS (SELECT 1 FROM folder_iocs fi WHERE fi.folder_id = ? "
                "AND fi.ioc_type = i.ioc_type AND fi.ioc = i.ioc)"
            )
            params.append(int(folder_id))

    if not where:
        where.append("1 = 1")
    return " AND ".join(where), params


def search_iocs(conn: sqlite3.Connection, filters: dict) -> dict:
    where, params = build_where(conn, filters)
    order_col = SORTABLE.get(filters.get("sort") or "", "i.last_seen")
    direction = "ASC" if str(filters.get("order", "desc")).lower() == "asc" else "DESC"
    try:
        limit = int(filters.get("limit") or 100)
    except (TypeError, ValueError):
        limit = 100
    limit = max(1, min(limit, MAX_LIMIT))
    try:
        offset = max(0, int(filters.get("offset") or 0))
    except (TypeError, ValueError):
        offset = 0

    total = conn.execute(f"SELECT COUNT(*) FROM iocs i WHERE {where}", params).fetchone()[0]
    rows = conn.execute(
        f"SELECT i.* FROM iocs i WHERE {where} "
        f"ORDER BY {order_col} {direction}, i.ioc ASC LIMIT ? OFFSET ?",
        [*params, limit, offset],
    ).fetchall()
    mapping = folders_for_rows(conn, rows)
    items = [
        serialize_row(dict(row), mapping.get((row["ioc_type"], row["ioc"]), []))
        for row in rows
    ]
    return {"total": total, "limit": limit, "offset": offset, "items": items}


def _values_for(conn: sqlite3.Connection, column: str, values: set[str],
                extra: str = "", extra_params: tuple = ()) -> dict[str, str]:
    out: dict[str, str] = {}
    ordered = [v for v in sorted(values) if v]
    for start in range(0, len(ordered), 500):
        chunk = ordered[start:start + 500]
        marks = ", ".join("?" for _ in chunk)
        sql = (f"SELECT value, name FROM folders WHERE kind = 'auto' AND field = ? "
               f"AND value IN ({marks}) {extra}")
        for r in conn.execute(sql, (column, *chunk, *extra_params)):
            out[r["value"]] = r["name"]
    return out


def folders_for_rows(conn: sqlite3.Connection, rows: list) -> dict[tuple[str, str], list[str]]:
    """Map (ioc_type, ioc) -> folder names (auto families/actors + manual)."""
    dicts = [dict(r) for r in rows]
    fam_names = _values_for(conn, "malware_family",
                            {d.get("malware_family") or "" for d in dicts} - {""})
    act_names = _values_for(conn, "threat_actor",
                            {d.get("threat_actor") or "" for d in dicts} - {""})

    mapping: dict[tuple[str, str], list[str]] = {}
    for d in dicts:
        names = []
        family = d.get("malware_family") or ""
        actor = d.get("threat_actor") or ""
        if family in fam_names:
            names.append(fam_names[family])
        if actor in act_names and act_names[actor] not in names:
            names.append(act_names[actor])
        mapping[(d.get("ioc_type", ""), d.get("ioc", ""))] = names

    if dicts:
        flat: list = []
        for row in rows:
            d = dict(row)
            flat.extend([d.get("ioc_type", ""), d.get("ioc", "")])
        for start in range(0, len(flat), 1500):
            chunk = flat[start:start + 1500]
            marks = ", ".join("(?, ?)" for _ in range(len(chunk) // 2))
            for r in conn.execute(
                "SELECT fi.ioc_type, fi.ioc, f.name FROM folder_iocs fi "
                "JOIN folders f ON f.id = fi.folder_id "
                f"WHERE (fi.ioc_type, fi.ioc) IN ({marks})",
                chunk,
            ):
                mapping.setdefault((r["ioc_type"], r["ioc"]), []).append(r["name"])
    return mapping


def get_ioc(conn: sqlite3.Connection, ioc_type: str, ioc: str, detail: bool = True):
    row = conn.execute(
        "SELECT * FROM iocs WHERE ioc_type = ? AND ioc = ?", (ioc_type, ioc)
    ).fetchone()
    if row is None:
        return None
    d = dict(row)
    mapping = folders_for_rows(conn, [d])
    out = serialize_row(d, mapping.get((ioc_type, ioc), []))
    if detail:
        import json

        for field in ("sources_detail", "evidence"):
            try:
                out[field] = json.loads(d.get(field) or "[]")
            except ValueError:
                out[field] = []
    return out


# -- write ------------------------------------------------------------------
WRITABLE = {
    "ioc", "ioc_type", "threat", "malware_family", "threat_actor", "campaign",
    "category", "confidence", "severity", "first_seen", "last_seen", "source",
    "source_url", "description", "tags", "mitre_attack", "crowdstrike_supported",
    "crowdstrike_importable", "validation_status", "sources_detail", "evidence",
}


def _sync_categories(conn: sqlite3.Connection, ioc_type: str, ioc: str, categories: list[str]):
    conn.execute(
        "DELETE FROM ioc_categories WHERE ioc_type = ? AND ioc = ?", (ioc_type, ioc)
    )
    if categories:
        conn.executemany(
            "INSERT OR IGNORE INTO ioc_categories (ioc_type, ioc, category) VALUES (?, ?, ?)",
            [(ioc_type, ioc, c) for c in categories if c],
        )


def insert_ioc(conn: sqlite3.Connection, data: dict) -> None:
    payload = {k: data.get(k, "") for k in WRITABLE}
    payload.setdefault("ioc", "")
    payload.setdefault("ioc_type", "")
    payload["first_seen"] = payload.get("first_seen") or _today()
    payload["last_seen"] = payload.get("last_seen") or payload["first_seen"]
    payload["updated_at"] = _now()
    payload.setdefault("sources_detail", "[]")
    payload.setdefault("evidence", "[]")
    flag_c2, flag_malware = view_flags(_split(payload.get("category"), ";"))
    payload["flag_c2"] = flag_c2
    payload["flag_malware"] = flag_malware
    cols = ", ".join(payload)
    marks = ", ".join("?" for _ in payload)
    conn.execute(f"INSERT INTO iocs ({cols}) VALUES ({marks})", tuple(payload.values()))
    _sync_categories(conn, payload["ioc_type"], payload["ioc"],
                     _split(payload.get("category"), ";"))
    conn.commit()


def update_ioc(conn: sqlite3.Connection, ioc_type: str, ioc: str, changes: dict) -> bool:
    fields = {k: v for k, v in changes.items() if k in WRITABLE and k not in ("ioc", "ioc_type")}
    if not fields:
        return False
    fields["updated_at"] = _now()
    if "category" in fields:
        fields["category"] = ";".join(_as_list(fields["category"]))
    if isinstance(fields.get("tags"), list):
        fields["tags"] = ";".join(fields["tags"])
    if isinstance(fields.get("mitre_attack"), list):
        fields["mitre_attack"] = ";".join(fields["mitre_attack"])
    if isinstance(fields.get("source"), list):
        fields["source"] = " | ".join(fields["source"])
    if isinstance(fields.get("source_url"), list):
        fields["source_url"] = " | ".join(fields["source_url"])
    if isinstance(fields.get("sources_detail"), (list, dict)):
        import json

        fields["sources_detail"] = json.dumps(fields["sources_detail"])[:8000]
    if isinstance(fields.get("evidence"), list):
        import json

        fields["evidence"] = json.dumps(fields["evidence"])[:4000]

    sets = [f"{c} = ?" for c in fields]
    if "category" in fields:
        cats = _split(fields["category"], ";")
        flag_c2, flag_malware = view_flags(cats)
        sets.append("flag_c2 = ?")
        sets.append("flag_malware = ?")
        params = [*fields.values(), flag_c2, flag_malware]
    else:
        params = list(fields.values())
    cur = conn.execute(
        f"UPDATE iocs SET {', '.join(sets)} WHERE ioc_type = ? AND ioc = ?",
        [*params, ioc_type, ioc],
    )
    if "category" in fields:
        _sync_categories(conn, ioc_type, ioc, _split(fields["category"], ";"))
    conn.commit()
    return cur.rowcount > 0


def delete_ioc(conn: sqlite3.Connection, ioc_type: str, ioc: str) -> bool:
    conn.execute("DELETE FROM folder_iocs WHERE ioc_type = ? AND ioc = ?", (ioc_type, ioc))
    conn.execute("DELETE FROM ioc_categories WHERE ioc_type = ? AND ioc = ?", (ioc_type, ioc))
    cur = conn.execute("DELETE FROM iocs WHERE ioc_type = ? AND ioc = ?", (ioc_type, ioc))
    conn.commit()
    return cur.rowcount > 0


# -- stats ------------------------------------------------------------------
def stats(conn: sqlite3.Connection) -> dict:
    def group(sql, key="k", val="c"):
        return {r[key]: r[val] for r in conn.execute(sql)}

    total = conn.execute("SELECT COUNT(*) c FROM iocs").fetchone()["c"]
    last_cycle = dict(conn.execute(
        "SELECT id, started, finished, stats FROM cycles ORDER BY id DESC LIMIT 1"
    ).fetchone() or {})
    if last_cycle.get("stats"):
        import json

        try:
            last_cycle["stats"] = json.loads(last_cycle["stats"])
        except ValueError:
            last_cycle["stats"] = {}
    return {
        "total": total,
        "by_severity": group(
            "SELECT severity k, COUNT(*) c FROM iocs GROUP BY severity ORDER BY c DESC"),
        "by_confidence": group(
            "SELECT confidence k, COUNT(*) c FROM iocs GROUP BY confidence ORDER BY c DESC"),
        "by_type": group(
            "SELECT ioc_type k, COUNT(*) c FROM iocs GROUP BY ioc_type ORDER BY c DESC"),
        "by_category": group(
            "SELECT category k, COUNT(*) c FROM ioc_categories GROUP BY category "
            "ORDER BY c DESC LIMIT 40"),
        "by_validation": group(
            "SELECT validation_status k, COUNT(*) c FROM iocs GROUP BY validation_status "
            "ORDER BY c DESC"),
        "importable": conn.execute(
            "SELECT COUNT(*) c FROM iocs WHERE crowdstrike_importable = 'YES'"
        ).fetchone()["c"],
        "new_today": conn.execute(
            "SELECT COUNT(*) c FROM iocs WHERE first_seen >= ?", (_today(),)
        ).fetchone()["c"],
        "c2": conn.execute(
            "SELECT COUNT(*) c FROM iocs WHERE flag_c2 = 1"
        ).fetchone()["c"],
        "malware": conn.execute(
            "SELECT COUNT(*) c FROM iocs WHERE flag_malware = 1"
        ).fetchone()["c"],
        "unreviewed": conn.execute(
            "SELECT COUNT(*) c FROM iocs WHERE validation_status IN ('', 'UNVERIFIED')"
        ).fetchone()["c"],
        "folders": conn.execute("SELECT COUNT(*) c FROM folders").fetchone()["c"],
        "last_cycle": last_cycle,
        "generated_at": _now(),
    }


def recent_cycles(conn: sqlite3.Connection, limit: int = 10) -> list[dict]:
    import json

    out = []
    for r in conn.execute(
        "SELECT id, started, finished, stats FROM cycles ORDER BY id DESC LIMIT ?",
        (max(1, min(int(limit), 100)),),
    ):
        d = dict(r)
        try:
            d["stats"] = json.loads(d["stats"] or "{}")
        except ValueError:
            d["stats"] = {}
        out.append(d)
    return out


def valid_ioc_types() -> tuple[str, ...]:
    return IOC_TYPES
