"""Tests for role-based access control (users, roles, registration).

Focus: privilege-escalation guards, role->scope mapping, the last-admin lockout
protection, and account disabling. These are security-critical.
"""
import pytest
from fastapi.testclient import TestClient

from iocbot.api.server import create_app
from iocbot import keys as keys_mod
from iocbot.store import ensure_schema, Store
import sqlite3


def _app(tmp_path, allow_registration=True):
    app = create_app({
        "root": tmp_path, "config_dir": tmp_path / "config",
        "server": {"host": "127.0.0.1", "port": 8080},
        "auth": {"required": True, "allow_registration": allow_registration,
                 "bootstrap_key_file": str(tmp_path / "admin.key")},
    })
    return TestClient(app)


def _reg(c, username, role=None):
    body = {"username": username, "password": "password123"}
    if role:
        body["role"] = role
    return c.post("/api/v1/auth/register", json=body)


@pytest.fixture
def client(tmp_path):
    return _app(tmp_path)


# -- registration ----------------------------------------------------------

def test_first_registrant_becomes_admin(client):
    r = _reg(client, "alice")
    assert r.status_code == 200 and r.json()["role"] == "admin"


def test_registration_cannot_self_assign_admin(client):
    _reg(client, "alice")  # admin exists now
    r = _reg(client, "mallory", "admin")
    assert r.status_code == 400
    assert "viewer, analyst" in r.json()["detail"]


def test_registration_allows_viewer_and_analyst(client):
    _reg(client, "alice")
    assert _reg(client, "vic", "viewer").json()["role"] == "viewer"
    assert _reg(client, "ana", "analyst").json()["role"] == "analyst"


def test_registration_can_be_disabled(tmp_path):
    c = _app(tmp_path, allow_registration=False)
    r = _reg(c, "alice")
    assert r.status_code == 403


def test_registration_rejects_weak_password(client):
    r = client.post("/api/v1/auth/register",
                    json={"username": "alice", "password": "short"})
    assert r.status_code == 400 and "8 characters" in r.json()["detail"]


def test_registration_rejects_reserved_username(client):
    r = _reg(client, "admin")
    assert r.status_code == 400 and "reserved" in r.json()["detail"]


def test_duplicate_username_rejected(client):
    _reg(client, "alice")
    assert _reg(client, "alice").status_code == 400


# -- role -> scope mapping -------------------------------------------------

def test_session_scopes_match_role(client):
    ak = _reg(client, "alice").json()["key"]
    vk = _reg(client, "viewer1", "viewer").json()["key"]
    ak_scopes = client.get("/api/v1/auth/me", headers={"X-API-Key": ak}).json()
    vk_scopes = client.get("/api/v1/auth/me", headers={"X-API-Key": vk}).json()
    assert ak_scopes["role"] == "admin"
    assert set(ak_scopes["scopes"]) == {"admin", "write", "read"}
    assert vk_scopes["role"] == "viewer"
    assert vk_scopes["scopes"] == ["read"]


def test_viewer_cannot_write(client):
    _reg(client, "alice")  # ensure an admin exists so "vic" is not the first user
    vk = _reg(client, "vic", "viewer").json()["key"]
    r = client.post("/api/v1/iocs", headers={"X-API-Key": vk},
                    json={"ioc": "1.2.3.4", "ioc_type": "IPv4"})
    assert r.status_code == 403


def test_viewer_can_read(client):
    _reg(client, "alice")
    vk = _reg(client, "vic", "viewer").json()["key"]
    assert client.get("/api/v1/stats", headers={"X-API-Key": vk}).status_code == 200


def test_analyst_can_write_but_not_manage_keys(client):
    ak = _reg(client, "alice").json()["key"]
    ak2 = _reg(client, "bob", "analyst").json()["key"]
    r = client.post("/api/v1/iocs", headers={"X-API-Key": ak2},
                    json={"ioc": "5.6.7.8", "ioc_type": "IPv4"})
    assert r.status_code == 201
    assert client.get("/api/v1/keys", headers={"X-API-Key": ak2}).status_code == 403
    assert client.get("/api/v1/users", headers={"X-API-Key": ak}).status_code == 200


# -- admin user management -------------------------------------------------

def _uid(c, key, username):
    users = c.get("/api/v1/users", headers={"X-API-Key": key}).json()["users"]
    return next(u["id"] for u in users if u["username"] == username)


def test_admin_can_promote_user(client):
    ak = _reg(client, "alice").json()["key"]
    _reg(client, "bob", "analyst")
    uid = _uid(client, ak, "bob")
    r = client.put(f"/api/v1/users/{uid}/role", headers={"X-API-Key": ak},
                   json={"role": "admin"})
    assert r.status_code == 200 and r.json()["user"]["role"] == "admin"


def test_non_admin_cannot_change_roles(client):
    ak = _reg(client, "alice").json()["key"]
    bk = _reg(client, "bob", "analyst").json()["key"]
    uid = _uid(client, ak, "bob")
    r = client.put(f"/api/v1/users/{uid}/role", headers={"X-API-Key": bk},
                   json={"role": "admin"})
    assert r.status_code == 403


def test_cannot_demote_last_admin(client):
    ak = _reg(client, "alice").json()["key"]
    uid = _uid(client, ak, "alice")
    r = client.put(f"/api/v1/users/{uid}/role", headers={"X-API-Key": ak},
                   json={"role": "viewer"})
    assert r.status_code == 409 and "last remaining admin" in r.json()["detail"]


def test_cannot_disable_last_admin(client):
    ak = _reg(client, "alice").json()["key"]
    uid = _uid(client, ak, "alice")
    r = client.put(f"/api/v1/users/{uid}/disabled", headers={"X-API-Key": ak},
                   json={"disabled": True})
    assert r.status_code == 409


def test_disabled_user_cannot_login(client):
    ak = _reg(client, "alice").json()["key"]
    _reg(client, "bob", "viewer")
    uid = _uid(client, ak, "bob")
    client.put(f"/api/v1/users/{uid}/disabled", headers={"X-API-Key": ak},
               json={"disabled": True})
    r = client.post("/api/v1/auth/login",
                    json={"username": "bob", "password": "password123"})
    assert r.status_code == 401


def test_invalid_role_rejected(client):
    ak = _reg(client, "alice").json()["key"]
    _reg(client, "bob", "viewer")
    uid = _uid(client, ak, "bob")
    r = client.put(f"/api/v1/users/{uid}/role", headers={"X-API-Key": ak},
                   json={"role": "superuser"})
    assert r.status_code == 400


def test_set_user_role_to_unknown_raises(tmp_path):
    store = Store(tmp_path / "state.db")
    user = keys_mod.create_user(store.conn, "uu", "password123", role="viewer")
    with pytest.raises(ValueError):
        keys_mod.set_user_role(store.conn, user["id"], "nope")
    store.close()


# -- migration -------------------------------------------------------------

def test_preexisting_user_upgraded_to_admin(tmp_path):
    """An account predating roles keeps its old full-admin behavior."""
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL, full_name TEXT DEFAULT '', created_at TEXT DEFAULT '',
            last_login_at TEXT DEFAULT '');
        CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
        INSERT INTO users (username, password_hash, created_at) VALUES ('op', 'x', '2020');
    """)
    conn.commit(); conn.close()
    conn = sqlite3.connect(path); conn.row_factory = sqlite3.Row
    ensure_schema(conn)
    role = conn.execute("SELECT role FROM users WHERE username='op'").fetchone()["role"]
    assert role == "admin"
    conn.close()


def test_role_migration_sentinel_protects_new_users(tmp_path):
    """After migration, newly created viewers are not force-promoted."""
    path = tmp_path / "old2.db"
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL, full_name TEXT DEFAULT '', created_at TEXT DEFAULT '',
            last_login_at TEXT DEFAULT '');
        CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
        INSERT INTO users (username, password_hash, created_at) VALUES ('op', 'x', '2020');
    """)
    conn.commit(); conn.close()
    conn = sqlite3.connect(path); conn.row_factory = sqlite3.Row
    ensure_schema(conn)
    keys_mod.create_user(conn, "fresh", "password123", role="viewer")
    ensure_schema(conn)  # second run must not promote 'fresh'
    assert conn.execute("SELECT role FROM users WHERE username='fresh'").fetchone()["role"] == "viewer"
    assert conn.execute("SELECT role FROM users WHERE username='op'").fetchone()["role"] == "admin"
    conn.close()