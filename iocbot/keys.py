from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import hmac
import logging
import secrets
import sqlite3
from pathlib import Path

from .store import open_db

log = logging.getLogger("iocbot.keys")

KEY_PREFIX = "iok_"
ALL_SCOPES = ("read", "write", "admin")
PBKDF2_ITER = 260_000


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def generate_key() -> str:
    return KEY_PREFIX + secrets.token_hex(20)


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _normalize_scopes(scopes) -> str:
    if isinstance(scopes, str):
        scopes = [s.strip() for s in scopes.replace(";", ",").split(",")]
    out = []
    for s in scopes or []:
        s = str(s).strip().lower()
        if s and s not in out:
            if s not in ALL_SCOPES:
                raise ValueError(f"unknown scope: {s}")
            out.append(s)
    if not out:
        out = ["read"]
    if "admin" in out:
        out = ["admin", "read", "write"]
    return ",".join(sorted(set(out), key=lambda x: ("admin", "write", "read").index(x)))


def create_key(conn: sqlite3.Connection, name: str, scopes="read",
               platform: str = "") -> dict:
    name = (name or "").strip()
    if not name:
        raise ValueError("key name is required")
    plain = generate_key()
    scope_str = _normalize_scopes(scopes)
    try:
        conn.execute(
            "INSERT INTO api_keys (name, prefix, key_hash, scopes, platform, "
            "created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (name, plain[:11], hash_key(plain), scope_str,
             (platform or "").strip(), _now()),
        )
    except sqlite3.IntegrityError as exc:
        raise ValueError(f"a key named {name!r} already exists") from exc
    conn.commit()
    row = conn.execute("SELECT * FROM api_keys WHERE name = ?", (name,)).fetchone()
    out = _public(row)
    out["key"] = plain  # shown exactly once
    return out


def list_keys(conn: sqlite3.Connection, include_revoked: bool = False) -> list[dict]:
    sql = "SELECT * FROM api_keys WHERE name NOT LIKE 'session:%'"
    if not include_revoked:
        sql += " AND revoked = 0"
    sql += " ORDER BY id"
    return [_public(r) for r in conn.execute(sql)]


def _public(row) -> dict:
    d = dict(row)
    return {
        "id": d["id"],
        "name": d["name"],
        "prefix": d["prefix"],
        "scopes": [s for s in (d.get("scopes") or "").split(",") if s],
        "platform": d.get("platform", ""),
        "created_at": d.get("created_at", ""),
        "last_used_at": d.get("last_used_at", ""),
        "uses": int(d.get("uses") or 0),
        "last_ip": d.get("last_ip", ""),
        "revoked": bool(d.get("revoked")),
    }


def revoke_key(conn: sqlite3.Connection, key_id: int) -> bool:
    cur = conn.execute(
        "UPDATE api_keys SET revoked = 1 WHERE id = ? AND revoked = 0", (key_id,)
    )
    conn.commit()
    return cur.rowcount > 0


def rotate_key(conn: sqlite3.Connection, key_id: int) -> str | None:
    row = conn.execute(
        "SELECT id FROM api_keys WHERE id = ? AND revoked = 0", (key_id,)
    ).fetchone()
    if row is None:
        return None
    plain = generate_key()
    conn.execute(
        "UPDATE api_keys SET key_hash = ?, prefix = ?, last_used_at = '', "
        "last_ip = '' WHERE id = ?",
        (hash_key(plain), plain[:11], key_id),
    )
    conn.commit()
    return plain


def verify_key(conn: sqlite3.Connection, plain: str | None):
    if not plain:
        return None
    row = conn.execute(
        "SELECT * FROM api_keys WHERE key_hash = ? AND revoked = 0",
        (hash_key(plain.strip()),),
    ).fetchone()
    return row


def touch_key(conn: sqlite3.Connection, key_id: int, ip: str = "") -> None:
    try:
        conn.execute(
            "UPDATE api_keys SET last_used_at = ?, uses = uses + 1, "
            "last_ip = CASE WHEN ? != '' THEN ? ELSE last_ip END "
            "WHERE id = ?",
            (_now(), ip, ip, key_id),
        )
        conn.commit()
    except sqlite3.Error:  # pragma: no cover - never break a request on this
        pass


def ensure_admin_key(conn: sqlite3.Connection, key_file: Path | None = None) -> str | None:
    """Create a first admin key on a fresh install; return it only in that case."""
    row = conn.execute("SELECT COUNT(*) FROM api_keys").fetchone()[0]
    if row:
        return None
    plain = create_key(conn, "admin", "admin")["key"]
    if key_file:
        key_file.parent.mkdir(parents=True, exist_ok=True)
        key_file.write_text(plain + "\n", encoding="utf-8")
        key_file.chmod(0o600)
    return plain


def ensure_bootstrap_key(conn: sqlite3.Connection) -> str:
    """Return a valid bootstrap key for first-run dashboard provisioning.

    Used when no dashboard user exists yet but the bootstrap key file is gone
    (claimed, or wiped with a restored database). Rotates the placeholder key
    so the plaintext is only ever re-issued while provisioning is still open.
    """
    row = conn.execute(
        "SELECT id FROM api_keys WHERE name = 'bootstrap' AND revoked = 0"
    ).fetchone()
    if row:
        plain = rotate_key(conn, row["id"])
        if plain:
            return plain
    return create_key(conn, "bootstrap", "admin")["key"]


# -- passwords & dashboard sessions ----------------------------------------
def hash_password(password: str) -> str:
    """pbkdf2-sha256 hash, format: pbkdf2$<iter>$<salt-hex>$<digest-hex>"""
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"),
        bytes.fromhex(salt), PBKDF2_ITER,
    ).hex()
    return f"pbkdf2${PBKDF2_ITER}${salt}${digest}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, iters, salt, expect = stored.split("$")
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"),
            bytes.fromhex(salt), int(iters),
        ).hex()
        return hmac.compare_digest(digest, expect)
    except (ValueError, TypeError):
        return False


def create_user(conn: sqlite3.Connection, username: str, password: str,
                full_name: str = "") -> dict:
    username = (username or "").strip().lower()
    if not username or len(username) < 2:
        raise ValueError("username must be at least 2 characters")
    if not password or len(password) < 8:
        raise ValueError("password must be at least 8 characters")
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if row is not None:
        raise ValueError(f"user {username!r} already exists")
    conn.execute(
        "INSERT INTO users (username, password_hash, full_name, created_at) "
        "VALUES (?, ?, ?, ?)",
        (username, hash_password(password), full_name.strip(), _now()),
    )
    conn.commit()
    return get_user(conn, username)


def get_user(conn: sqlite3.Connection, username: str) -> dict | None:
    row = conn.execute("SELECT * FROM users WHERE username = ?",
                       (username.strip().lower(),)).fetchone()
    return dict(row) if row else None


def auth_user(conn: sqlite3.Connection, username: str, password: str) -> dict | None:
    user = get_user(conn, username or "")
    if user is None or not verify_password(password or "", user["password_hash"]):
        return None
    conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (_now(), user["id"]))
    conn.commit()
    return user


def has_users(conn: sqlite3.Connection) -> bool:
    return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] > 0


def session_key_name(username: str) -> str:
    return f"session:{username.strip().lower()}"


def create_session_key(conn: sqlite3.Connection, username: str) -> str:
    """Issue a fresh admin-scoped dashboard session (one active per user)."""
    name = session_key_name(username)
    plain = generate_key()
    row = conn.execute("SELECT id FROM api_keys WHERE name = ?", (name,)).fetchone()
    if row:
        # name is UNIQUE — reuse the existing session row instead of inserting
        conn.execute(
            "UPDATE api_keys SET key_hash = ?, prefix = ?, scopes = 'admin,write,read', "
            "platform = 'session', revoked = 0, created_at = ?, last_used_at = '', "
            "last_ip = '', uses = 0 WHERE id = ?",
            (hash_key(plain), plain[:11], _now(), row["id"]),
        )
    else:
        conn.execute(
            "INSERT INTO api_keys (name, prefix, key_hash, scopes, platform, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (name, plain[:11], hash_key(plain), "admin,write,read", "session", _now()),
        )
    conn.commit()
    return plain


def revoke_session(conn: sqlite3.Connection, key_id: int) -> bool:
    cur = conn.execute(
        "UPDATE api_keys SET revoked = 1 WHERE id = ? AND name LIKE 'session:%' "
        "AND revoked = 0",
        (key_id,),
    )
    conn.commit()
    return cur.rowcount > 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="iocbot.keys", description="Manage API keys for the IOC feed/dashboard"
    )
    parser.add_argument("--db", default=None, help="path to state.db")
    parser.add_argument(
        "command", choices=["create", "list", "revoke", "rotate", "verify"],
        help="action to perform",
    )
    parser.add_argument("target", nargs="?", default=None,
                        help="key name (create) or key id (revoke/rotate) or key (verify)")
    parser.add_argument("--scopes", default="read",
                        help="comma list: read,write,admin (default: read)")
    parser.add_argument("--platform", default="",
                        help="SIEM platform (splunk, elastic, wazuh, fortiSIEM, ...)")
    parser.add_argument("--include-revoked", action="store_true")
    args = parser.parse_args(argv)

    root = Path(__file__).resolve().parent.parent
    db_path = Path(args.db) if args.db else root / "data" / "state.db"
    conn = open_db(db_path)
    from .store import ensure_schema

    ensure_schema(conn)

    if args.command == "create":
        if not args.target:
            print("error: name required (python3 -m iocbot.keys create <name> --scopes read)",
                  flush=True)
            return 2
        try:
            key = create_key(conn, args.target, args.scopes, args.platform)
        except ValueError as exc:
            print(f"error: {exc}", flush=True)
            return 1
        print(f"created key {key['name']} (scopes: {','.join(key['scopes'])})"
              + (f" platform: {key['platform']}" if key.get("platform") else ""))
        print(f"key (shown once): {key['key']}")
    elif args.command == "list":
        for k in list_keys(conn, args.include_revoked):
            print(f"{k['id']:>3}  {k['name']:<24} {','.join(k['scopes']):<16} "
                  f"prefix={k['prefix']}... last_used={k['last_used_at'] or 'never'}"
                  f"{'  [REVOKED]' if k['revoked'] else ''}")
    elif args.command == "revoke":
        if not args.target or not args.target.isdigit():
            print("error: numeric key id required", flush=True)
            return 2
        print("revoked" if revoke_key(conn, int(args.target)) else "not found / already revoked")
    elif args.command == "rotate":
        if not args.target or not args.target.isdigit():
            print("error: numeric key id required", flush=True)
            return 2
        plain = rotate_key(conn, int(args.target))
        if not plain:
            print("not found", flush=True)
            return 1
        print(f"new key (shown once): {plain}")
    elif args.command == "verify":
        row = verify_key(conn, args.target or "")
        print("valid" if row else "invalid")
        return 0 if row else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
