from __future__ import annotations

import datetime as _dt
import re
import sqlite3

AUTO_FIELDS = (("malware_family", "malware"), ("threat_actor", "actor"))


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def slugify(name: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", name.strip()).strip("-")
    return slug or "folder"


def sync_auto_folders(conn: sqlite3.Connection) -> dict:
    """Create a folder for every malware family / threat actor seen in the data."""
    created = 0
    for field, _kind in AUTO_FIELDS:
        for row in conn.execute(
            f"SELECT {field} AS v FROM iocs WHERE {field} != '' GROUP BY 1"
        ):
            value = str(row["v"]).strip()
            if not value:
                continue
            cur = conn.execute(
                "INSERT OR IGNORE INTO folders "
                "(name, kind, field, value, description, created_at) "
                "VALUES (?, 'auto', ?, ?, ?, ?)",
                (value, field, value,
                 f"Auto-grouped by {field.replace('_', ' ')}", _now()),
            )
            created += cur.rowcount
    conn.commit()
    return {"created": created, "total": folder_count(conn)}


def folder_count(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) FROM folders").fetchone()[0]


def list_folders(conn: sqlite3.Connection, include_zero: bool = True) -> list[dict]:
    folders = [dict(r) for r in conn.execute("SELECT * FROM folders")]
    counts = {"malware_family": {}, "threat_actor": {}}
    for field in counts:
        counts[field] = {
            r[0]: r[1]
            for r in conn.execute(
                f"SELECT {field}, COUNT(*) FROM iocs WHERE {field} != '' GROUP BY 1"
            )
        }
    manual = {
        r[0]: r[1]
        for r in conn.execute("SELECT folder_id, COUNT(*) FROM folder_iocs GROUP BY 1")
    }
    out = []
    for f in folders:
        if f["kind"] == "auto":
            f["count"] = counts.get(f["field"], {}).get(f["value"], 0)
            f["group"] = "malware" if f["field"] == "malware_family" else "actor"
        else:
            f["count"] = manual.get(f["id"], 0)
            f["group"] = "manual"
        if include_zero or f["count"]:
            out.append(f)
    out.sort(key=lambda f: ({"malware": 0, "actor": 1, "manual": 2}.get(f["group"], 3),
                            -f["count"], f["name"].lower()))
    return out


def get_folder(conn: sqlite3.Connection, folder_id: int):
    row = conn.execute("SELECT * FROM folders WHERE id = ?", (folder_id,)).fetchone()
    if row is None:
        return None
    f = dict(row)
    members = conn.execute(
        "SELECT COUNT(*) FROM folder_iocs WHERE folder_id = ?", (folder_id,)
    ).fetchone()[0]
    f["count"] = members if f["kind"] == "manual" else f.get("count", 0)
    if f["kind"] == "auto":
        f["count"] = conn.execute(
            f"SELECT COUNT(*) FROM iocs WHERE {f['field']} = ?", (f["value"],)
        ).fetchone()[0]
        f["group"] = "malware" if f["field"] == "malware_family" else "actor"
    else:
        f["group"] = "manual"
    return f


def create_folder(conn: sqlite3.Connection, name: str, description: str = "",
                  color: str = "") -> dict:
    name = (name or "").strip()
    if not name:
        raise ValueError("folder name is required")
    cur = conn.execute(
        "INSERT INTO folders (name, kind, field, value, description, color, created_at) "
        "VALUES (?, 'manual', '', '', ?, ?, ?)",
        (name, description or "", color or "", _now()),
    )
    conn.commit()
    return get_folder(conn, int(cur.lastrowid))


def update_folder(conn: sqlite3.Connection, folder_id: int, changes: dict) -> dict | None:
    folder = get_folder(conn, folder_id)
    if folder is None:
        return None
    fields = {}
    if "name" in changes and str(changes["name"]).strip():
        fields["name"] = str(changes["name"]).strip()
    if "description" in changes:
        fields["description"] = str(changes["description"] or "")
    if "color" in changes:
        fields["color"] = str(changes["color"] or "")
    if fields:
        marks = ", ".join(f"{c} = ?" for c in fields)
        conn.execute(f"UPDATE folders SET {marks} WHERE id = ?", [*fields.values(), folder_id])
        conn.commit()
    return get_folder(conn, folder_id)


def delete_folder(conn: sqlite3.Connection, folder_id: int) -> bool:
    folder = get_folder(conn, folder_id)
    if folder is None:
        raise ValueError("folder not found")
    if folder["kind"] == "auto":
        raise ValueError("auto folders cannot be deleted (recreated on every sync)")
    conn.execute("DELETE FROM folder_iocs WHERE folder_id = ?", (folder_id,))
    conn.execute("DELETE FROM folders WHERE id = ?", (folder_id,))
    conn.commit()
    return True


def add_to_folder(conn: sqlite3.Connection, folder_id: int,
                  items: list[tuple[str, str]]) -> dict:
    folder = get_folder(conn, folder_id)
    if folder is None:
        raise ValueError("folder not found")
    added, skipped = 0, []
    for ioc_type, ioc in items:
        exists = conn.execute(
            "SELECT 1 FROM iocs WHERE ioc_type = ? AND ioc = ?", (ioc_type, ioc)
        ).fetchone()
        if not exists:
            skipped.append(f"{ioc_type}:{ioc}")
            continue
        if folder["kind"] == "auto":
            if folder["field"] not in ("malware_family", "threat_actor"):
                skipped.append(f"{ioc_type}:{ioc}")
                continue
            conn.execute(
                f"UPDATE iocs SET {folder['field']} = ?, updated_at = ? "
                "WHERE ioc_type = ? AND ioc = ?",
                (folder["value"], _now(), ioc_type, ioc),
            )
            added += 1
            continue
        cur = conn.execute(
            "INSERT OR IGNORE INTO folder_iocs (folder_id, ioc_type, ioc, added_at) "
            "VALUES (?, ?, ?, ?)",
            (folder_id, ioc_type, ioc, _now()),
        )
        added += cur.rowcount
    conn.commit()
    return {"added": added, "skipped": skipped}


def remove_from_folder(conn: sqlite3.Connection, folder_id: int,
                       ioc_type: str, ioc: str) -> bool:
    folder = get_folder(conn, folder_id)
    if folder is None:
        raise ValueError("folder not found")
    if folder["kind"] == "auto":
        if folder["field"] not in ("malware_family", "threat_actor"):
            return False
        field = folder["field"]
        cur = conn.execute(
            f"UPDATE iocs SET {field} = '', updated_at = ? "
            "WHERE ioc_type = ? AND ioc = ? AND " + field + " = ?",
            (_now(), ioc_type, ioc, folder["value"]),
        )
    else:
        cur = conn.execute(
            "DELETE FROM folder_iocs WHERE folder_id = ? AND ioc_type = ? AND ioc = ?",
            (folder_id, ioc_type, ioc),
        )
    conn.commit()
    return cur.rowcount > 0


def build_folder_buckets(conn: sqlite3.Connection, rows: list[dict]) -> dict[str, list[dict]]:
    """Group rows by malware-group folder name (auto families/actors + manual)."""
    buckets: dict[str, list[dict]] = {}
    for row in rows:
        family = (row.get("malware_family") or "").strip()
        actor = (row.get("threat_actor") or "").strip()
        for name in {family, actor} - {""}:
            buckets.setdefault(name, []).append(row)
    manual = conn.execute(
        "SELECT f.name, fi.ioc_type, fi.ioc FROM folder_iocs fi "
        "JOIN folders f ON f.id = fi.folder_id WHERE f.kind = 'manual'"
    ).fetchall()
    if manual:
        index = {(r.get("ioc_type"), r.get("ioc")): r for r in rows}
        for m in manual:
            row = index.get((m["ioc_type"], m["ioc"]))
            if row is not None:
                bucket = buckets.setdefault(m["name"], [])
                if not any(r is row for r in bucket):
                    bucket.append(row)
    for rows_ in buckets.values():
        rows_.sort(key=lambda r: (r.get("ioc_type", ""), r.get("ioc", "")))
    return buckets
