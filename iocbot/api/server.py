"""IOC feed API + dashboard server.

Any SIEM can pull the same data the bot collects by authenticating with an
API key (``X-API-Key`` header, ``Authorization: Bearer`` or ``?apikey=``):

    curl -H "X-API-Key: iok_..." \
         "http://127.0.0.1:8080/api/v1/iocs?severity=CRITICAL,HIGH&format=csv"
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import logging
import socket
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import yaml
from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .. import folders as folders_mod
from .. import keys as keys_mod
from .. import query
from ..models import IOC_TYPES
from ..store import ensure_schema, open_db

log = logging.getLogger("iocbot.api")

ROOT = Path(__file__).resolve().parents[2]
WEB_DIR = Path(__file__).resolve().parents[1] / "web"

SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

CSV_COLUMNS = [
    "IOC", "IOC_TYPE", "SEVERITY", "CONFIDENCE", "CATEGORY", "MALWARE_FAMILY",
    "THREAT_ACTOR", "CAMPAIGN", "FOLDERS", "VALIDATION_STATUS",
    "CROWDSTRIKE_IMPORTABLE", "FIRST_SEEN", "LAST_SEEN", "SOURCE", "TAGS",
    "MITRE_ATTACK", "DESCRIPTION",
]

STIX_PATTERNS = {
    "IPv4": "ipv4-addr:value = '{v}'",
    "IPv6": "ipv6-addr:value = '{v}'",
    "Domain": "domain-name:value = '{v}'",
    "URL": "url:value = '{v}'",
    "MD5": "file:hashes.'MD5' = '{v}'",
    "SHA1": "file:hashes.'SHA-1' = '{v}'",
    "SHA256": "file:hashes.'SHA-256' = '{v}'",
    "Email": "email-addr:value = '{v}'",
    "CVE": "vulnerability:name = '{v}'",
    "File-Name": "file:name = '{v}'",
}

STIX_CONFIDENCE = {"LOW": 30, "MEDIUM": 50, "HIGH": 75, "CRITICAL": 95}

# Usernames that can never be claimed by registration (they collide with
# internal key/session naming).
RESERVED_USERNAMES = ("admin", "root", "session", "api", "system", "bootstrap")


# -- config -----------------------------------------------------------------
def load_config(config_dir: Path | None = None) -> dict:
    cfg_dir = Path(config_dir) if config_dir else ROOT / "config"
    path = cfg_dir / "api.yaml"
    cfg = {}
    if path.is_file():
        cfg = yaml.safe_load(path.read_text()) or {}
    server = cfg.get("server") or {}
    auth = cfg.get("auth") or {}
    return {
        "host": str(server.get("host", "127.0.0.1")),
        "port": int(server.get("port", 8080)),
        "auth_required": bool(auth.get("required", True)),
        "allow_registration": bool(auth.get("allow_registration", True)),
        "bootstrap_key_file": str(auth.get("bootstrap_key_file", "data/keys/admin.key")),
        "config_dir": cfg_dir,
        "root": ROOT,
    }


def session_id_of(conn, username: str) -> int:
    row = conn.execute("SELECT id FROM api_keys WHERE name = ?",
                       (f"session:{username.strip().lower()}",)).fetchone()
    return row["id"] if row else 0


# -- request models ---------------------------------------------------------
class IocCreate(BaseModel):
    ioc: str
    ioc_type: str
    severity: str = "MEDIUM"
    confidence: str = "MEDIUM"
    categories: list[str] = Field(default_factory=list)
    malware_family: str = ""
    threat_actor: str = ""
    campaign: str = ""
    threat: str = ""
    description: str = ""
    tags: list[str] = Field(default_factory=list)
    source: str = "manual"
    source_url: str = ""
    validation_status: str = ""
    first_seen: str = ""
    last_seen: str = ""
    force: bool = False


class IocUpdate(BaseModel):
    severity: str | None = None
    confidence: str | None = None
    categories: list[str] | None = None
    malware_family: str | None = None
    threat_actor: str | None = None
    campaign: str | None = None
    threat: str | None = None
    description: str | None = None
    tags: list[str] | None = None
    source: list[str] | None = None
    source_url: list[str] | None = None
    validation_status: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    crowdstrike_importable: str | None = None


class FolderCreate(BaseModel):
    name: str
    description: str = ""
    color: str = ""


class FolderUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    color: str | None = None


class FolderIocs(BaseModel):
    iocs: list[dict] | None = None
    filter: dict | None = None


class KeyCreate(BaseModel):
    name: str
    scopes: str = "read"
    platform: str = ""


class LoginRequest(BaseModel):
    username: str
    password: str


class ProvisionRequest(BaseModel):
    username: str
    password: str
    full_name: str = ""


class RegisterRequest(BaseModel):
    username: str
    password: str
    full_name: str = ""
    role: str = "viewer"


class UserRoleRequest(BaseModel):
    role: str


class UserDisabledRequest(BaseModel):
    disabled: bool


class PushRequest(BaseModel):
    targets: list[str] | None = None


# -- app --------------------------------------------------------------------
def create_app(config: dict | None = None) -> FastAPI:
    cfg = load_config()
    if config:
        for k, v in config.items():
            if isinstance(v, dict) and isinstance(cfg.get(k), dict):
                cfg[k].update(v)
            else:
                cfg[k] = v
        server = config.get("server") or {}
        if "host" in server:
            cfg["host"] = server["host"]
        if "port" in server:
            cfg["port"] = int(server["port"])
        auth = config.get("auth") or {}
        if "required" in auth:
            cfg["auth_required"] = bool(auth["required"])
        if "allow_registration" in auth:
            cfg["allow_registration"] = bool(auth["allow_registration"])
        if "bootstrap_key_file" in auth:
            cfg["bootstrap_key_file"] = auth["bootstrap_key_file"]
    data_dir = cfg["root"] / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    app = FastAPI(
        title="IOC Intelligence API",
        version="1.0.0",
        description="Pull (and manage) the collected IOC set with an API key.",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    db = query.Database(data_dir / "state.db")
    ensure_schema(db.conn)
    folders_mod.sync_auto_folders(db.conn)

    from ..validate import Validator

    validator = Validator(cfg["config_dir"] / "validation.yaml")
    runner = _Runner(cfg)

    app.state.cfg = cfg
    app.state.db = db
    app.state.validator = validator
    app.state.runner = runner
    app.state.auth = {}

    if cfg["auth_required"]:
        key_file = cfg["root"] / cfg["bootstrap_key_file"]
        fresh = keys_mod.ensure_admin_key(db.conn, key_file)
        if fresh:
            log.warning("bootstrap admin key created: %s", fresh)
        # No dashboard user yet and the bootstrap file is gone: reissue it so
        # the first-run provisioning flow on the login page stays usable.
        if not keys_mod.has_users(db.conn) and not key_file.is_file():
            plain = keys_mod.ensure_bootstrap_key(db.conn)
            key_file.parent.mkdir(parents=True, exist_ok=True)
            key_file.write_text(plain + "\n", encoding="utf-8")
            key_file.chmod(0o600)
            log.warning("bootstrap key reinstated at %s (no users exist yet)", key_file)

    # -- auth ---------------------------------------------------------------
    def require(scope: str):
        def dependency(
            request: Request,
            x_api_key: str | None = Header(default=None),
            authorization: str | None = Header(default=None),
            apikey: str | None = Query(default=None),
        ):
            if not cfg["auth_required"]:
                return None
            token = x_api_key or apikey
            if not token and authorization and authorization.lower().startswith("bearer "):
                token = authorization[7:].strip()
            row = keys_mod.verify_key(db.conn, token)
            if row is None:
                raise HTTPException(
                    status_code=401,
                    detail="missing or invalid API key (use X-API-Key header)",
                )
            scopes = [s for s in (row["scopes"] or "").split(",") if s]
            if scope not in scopes:
                raise HTTPException(
                    status_code=403, detail=f"key is missing the {scope!r} scope"
                )
            last = app.state.auth.get(row["id"], 0)
            if time.time() - last > 60:
                client_ip = request.client.host if request.client else ""
                forwarded = request.headers.get("x-real-ip") or request.headers.get("x-forwarded-for")
                if forwarded:
                    client_ip = forwarded.split(",")[0].strip() or client_ip
                keys_mod.touch_key(db.conn, row["id"], client_ip)
                app.state.auth[row["id"]] = time.time()
            return dict(row)

        return dependency

    # -- helpers ------------------------------------------------------------
    def search_filters(params) -> dict:
        def multi(value) -> list[str]:
            if not value:
                return []
            return [v.strip() for v in str(value).split(",") if v.strip()]

        def single(value) -> str:
            return str(params.get(value) or "").strip()

        folder_id = single("folder_id")
        if folder_id and not folder_id.isdigit():
            folder_id = ""
        return {
            "q": single("q"),
            "ioc_type": multi(params.get("ioc_type")),
            "severity": [v.upper() for v in multi(params.get("severity"))],
            "confidence": [v.upper() for v in multi(params.get("confidence"))],
            "category": [v.upper() for v in multi(params.get("category"))],
            "malware_family": multi(params.get("malware_family")),
            "threat_actor": multi(params.get("threat_actor")),
            "validation": single("validation").upper(),
            "importable": single("importable").lower() in ("1", "true", "yes"),
            "unreviewed": single("unreviewed").lower() in ("1", "true", "yes"),
            "view": (single("view") or "master").lower(),
            "since": single("since"),
            "seen_since": single("seen_since"),
            "folder_id": folder_id,
            "min_severity": single("min_severity").upper(),
            "sort": single("sort"),
            "order": single("order") or "desc",
            "limit": params.get("limit") or 100,
            "offset": params.get("offset") or 0,
        }

    def apply_min_severity(filters: dict) -> dict:
        rank = SEV_RANK.get(filters.get("min_severity") or "")
        if not rank:
            return filters
        allowed = [s for s, r in SEV_RANK.items() if r >= rank]
        filters["severity"] = sorted(
            set(filters.get("severity") or []) | set(allowed),
            key=lambda s: SEV_RANK.get(s, 0),
        )
        return filters

    def csv_response(items: list[dict], filename: str) -> StreamingResponse:
        def generate():
            buf = io.StringIO()
            writer = csv.writer(buf, lineterminator="\r\n")
            writer.writerow(CSV_COLUMNS)
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate()
            for item in items:
                writer.writerow(_csv_row(item))
                yield buf.getvalue()
                buf.seek(0)
                buf.truncate()

        return StreamingResponse(
            generate(),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    def _csv_row(item: dict) -> list:
        return [
            item["ioc"], item["ioc_type"], item.get("severity", ""),
            item.get("confidence", ""), ";".join(item.get("categories", [])),
            item.get("malware_family", ""), item.get("threat_actor", ""),
            item.get("campaign", ""), ";".join(item.get("folders", [])),
            item.get("validation_status", ""), item.get("crowdstrike_importable", ""),
            item.get("first_seen", ""), item.get("last_seen", ""),
            " | ".join(item.get("sources", [])), ";".join(item.get("tags", [])),
            ";".join(item.get("mitre_attack", [])), item.get("description", ""),
        ]

    def stix_bundle(items: list[dict]) -> dict:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        objects = []
        for item in items:
            template = STIX_PATTERNS.get(item["ioc_type"])
            if not template:
                continue
            value = item["ioc"].replace("'", "\\'")
            first = _stix_time(item.get("first_seen")) or now
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid5(uuid.NAMESPACE_URL, item['ioc_type'] + item['ioc'])}",
                "created": first,
                "modified": _stix_time(item.get("updated_at")) or first,
                "name": item["ioc"],
                "description": (item.get("description") or "")[:1000],
                "indicator_types": ["malicious-activity"],
                "pattern": template.format(v=value),
                "pattern_type": "stix",
                "valid_from": first,
                "confidence": STIX_CONFIDENCE.get(item.get("confidence", "LOW"), 30),
                "labels": item.get("categories", []) + [item["ioc_type"].lower()],
                "x_severity": item.get("severity", ""),
                "x_malware_family": item.get("malware_family", ""),
                "x_threat_actor": item.get("threat_actor", ""),
                "x_validation_status": item.get("validation_status", ""),
                "x_sources": item.get("sources", []),
                "x_folders": item.get("folders", []),
            })
        return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}

    def render(items: list[dict], fmt: str, filename_base: str,
               total: int | None = None) -> Response:
        fmt = (fmt or "json").lower()
        if fmt == "csv":
            return csv_response(items, f"{filename_base}.csv")
        if fmt == "stix":
            return JSONResponse(stix_bundle(items))
        body = {"count": len(items), "items": items}
        if total is not None:
            body["total"] = total
        return JSONResponse(body)

    # -- meta ---------------------------------------------------------------
    @app.get("/api/v1/health")
    def health() -> dict:
        total = db.conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
        return {"status": "ok", "iocs": total, "version": "1.0.0"}

    @app.get("/api/v1/auth/status")
    def auth_status() -> dict:
        return {
            "auth_required": bool(cfg["auth_required"]),
            "has_users": keys_mod.has_users(db.conn),
            "allow_registration": bool(cfg["allow_registration"]) and bool(cfg["auth_required"]),
            "bootstrap_available": (
                (cfg["root"] / cfg["bootstrap_key_file"]).is_file()
                if cfg["auth_required"] else False
            ),
        }

    @app.post("/api/v1/auth/provision")
    def provision(body: ProvisionRequest) -> dict:
        """Create the first dashboard user (guarded by the bootstrap key file)."""
        if not cfg["auth_required"]:
            raise HTTPException(400, "auth is disabled")
        key_file = cfg["root"] / cfg["bootstrap_key_file"]
        if not key_file.is_file():
            raise HTTPException(
                409, "no bootstrap key available (first account already set up)"
            )
        if keys_mod.has_users(db.conn):
            raise HTTPException(409, "users already exist")
        username = body.username.strip().lower()
        if username in ("admin", "root", "session", "api"):
            raise HTTPException(400, f"{username!r} is a reserved username")
        try:
            keys_mod.create_user(db.conn, username, body.password, body.full_name,
                                 role="admin")
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        try:
            key_file.unlink()
        except OSError as exc:  # pragma: no cover
            raise HTTPException(500, "could not remove bootstrap key file") from exc
        return {"ok": True, "username": username}

    @app.post("/api/v1/auth/login")
    def login(body: LoginRequest) -> dict:
        """Normal username/password login; issues a session key scoped to the role."""
        if not cfg["auth_required"]:
            raise HTTPException(400, "auth is disabled")
        user = keys_mod.auth_user(db.conn, body.username, body.password)
        if user is None:
            raise HTTPException(
                401, "invalid username or password", headers={"WWW-Authenticate": "Bearer"}
            )
        plain = keys_mod.create_session_key(db.conn, user["username"])
        return {"name": f"session:{user['username']}", "key": plain,
                "username": user["username"], "role": user.get("role", "viewer")}

    @app.post("/api/v1/auth/logout")
    def logout(key: dict = Depends(require("read"))) -> dict:
        """Revoke the current session key (no-op for non-session keys)."""
        if not key or str(key.get("name", "")).startswith("session:"):
            if key:
                keys_mod.revoke_session(db.conn, key["id"])
            return {"ok": True}
        return {"ok": True}

    @app.get("/api/v1/auth/me")
    def me(key: dict = Depends(require("read"))) -> dict:
        username = ""
        role = ""
        if key and str(key.get("name", "")).startswith("session:"):
            username = key["name"][len("session:"):]
            row = db.conn.execute("SELECT role, disabled FROM users WHERE username = ?",
                                  (username,)).fetchone()
            if row is not None:
                role = row["role"]
        return {
            "name": (key or {}).get("name", ""),
            "scopes": [s for s in ((key or {}).get("scopes") or "").split(",") if s],
            "username": username,
            "role": role,
            "method": "session" if username else "api_key",
        }

    @app.post("/api/v1/auth/bootstrap")
    def bootstrap(request: Request) -> dict:
        """Claim the auto-created admin key from the login page (first run only).

        Available only while the bootstrap key file still exists on disk. The
        file is deleted once claimed, so the plaintext is issued exactly once.
        """
        if not cfg["auth_required"]:
            raise HTTPException(400, "auth is disabled, no bootstrap key")
        key_file = cfg["root"] / cfg["bootstrap_key_file"]
        if not key_file.is_file():
            raise HTTPException(404, "no bootstrap key available (already claimed or not first run)")
        plain = key_file.read_text(encoding="utf-8").strip().splitlines()[0]
        try:
            key_file.unlink()
        except OSError as exc:  # pragma: no cover
            raise HTTPException(500, "could not remove bootstrap key file") from exc
        if keys_mod.verify_key(db.conn, plain) is None:
            raise HTTPException(500, "bootstrap key file did not verify")
        return {"name": "admin", "key": plain}

    # -- registration / user management -----------------------------------
    @app.post("/api/v1/auth/register")
    def register(body: RegisterRequest) -> dict:
        """Self-service account registration.

        A registrant picks their own role, but only from the non-privileged
        set (viewer/analyst). "admin" can never be self-assigned here — an
        existing admin must grant it via PUT /api/v1/users/{id}/role.
        """
        if not cfg["auth_required"]:
            raise HTTPException(400, "auth is disabled")
        if not cfg["allow_registration"]:
            raise HTTPException(403, "registration is disabled by the administrator")
        # First account behaves like the old bootstrap flow (full admin).
        first = not keys_mod.has_users(db.conn)
        allowed = keys_mod.ROLES if first else keys_mod.SELF_REGISTER_ROLES
        username = body.username.strip().lower()
        if username in RESERVED_USERNAMES:
            raise HTTPException(400, f"{username!r} is a reserved username")
        try:
            user = keys_mod.create_user(
                db.conn, username, body.password, body.full_name,
                role="admin" if first else body.role,
                allowed_roles=allowed,
            )
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        key = keys_mod.create_session_key(db.conn, username)
        return {"ok": True, "username": user["username"], "role": user["role"],
                "key": key, "first_user": first}

    @app.get("/api/v1/users")
    def list_users(_: dict = Depends(require("admin"))) -> dict:
        """List dashboard accounts (admin only)."""
        return {"users": keys_mod.list_users(db.conn),
                "roles": [{"role": r, "label": keys_mod.ROLE_LABELS[r],
                           "scopes": keys_mod.ROLE_SCOPES[r]}
                          for r in keys_mod.ROLES]}

    @app.put("/api/v1/users/{user_id}/role")
    def set_role(user_id: int, body: UserRoleRequest, _: dict = Depends(require("admin"))) -> dict:
        """Change a user's role (admin only). The last admin cannot be demoted."""
        target = next((u for u in keys_mod.list_users(db.conn) if u["id"] == user_id), None)
        if target is None:
            raise HTTPException(404, "user not found")
        if target["role"] == "admin" and body.role != "admin" and \
                keys_mod.user_count(db.conn, "admin") <= 1:
            raise HTTPException(409, "cannot demote the last remaining admin")
        try:
            updated = keys_mod.set_user_role(db.conn, user_id, body.role)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        return {"ok": True, "user": updated}

    @app.put("/api/v1/users/{user_id}/disabled")
    def set_disabled(user_id: int, body: UserDisabledRequest,
                     _: dict = Depends(require("admin"))) -> dict:
        """Enable/disable an account (admin only)."""
        target = next((u for u in keys_mod.list_users(db.conn) if u["id"] == user_id), None)
        if target is None:
            raise HTTPException(404, "user not found")
        if body.disabled and target["role"] == "admin" and \
                keys_mod.user_count(db.conn, "admin") <= 1:
            raise HTTPException(409, "cannot disable the last remaining admin")
        keys_mod.set_user_disabled(db.conn, user_id, body.disabled)
        if body.disabled:
            keys_mod.revoke_session(db.conn, session_id_of(db.conn, target["username"]))
        return {"ok": True}

    @app.get("/api/v1/stats")
    def stats(_: dict = Depends(require("read"))) -> dict:
        return query.stats(db.conn)

    @app.get("/api/v1/cycles")
    def cycles(limit: int = 10, _: dict = Depends(require("read"))) -> dict:
        return {"items": query.recent_cycles(db.conn, limit)}

    # -- feed / search ------------------------------------------------------
    @app.get("/api/v1/feed")
    def feed(request: Request, format: str = "json", _: dict = Depends(require("read"))):
        filters = apply_min_severity(search_filters(request.query_params))
        filters["limit"] = request.query_params.get("limit") or 1000
        result = query.search_iocs(db.conn, filters)
        response = render(result["items"], format, "ioc_feed", result["total"])
        response.headers["X-IOC-Total"] = str(result["total"])
        response.headers["X-IOC-Generated-At"] = datetime.now(timezone.utc).isoformat()
        return response

    @app.get("/api/v1/iocs")
    def list_iocs(request: Request, format: str = "json",
                  _: dict = Depends(require("read"))):
        filters = apply_min_severity(search_filters(request.query_params))
        result = query.search_iocs(db.conn, filters)
        if format != "json":
            response = render(result["items"], format, "iocs")
            response.headers["X-IOC-Total"] = str(result["total"])
            return response
        return result

    @app.get("/api/v1/iocs/{ioc_type}/{ioc:path}")
    def get_ioc_endpoint(ioc_type: str, ioc: str, _: dict = Depends(require("read"))):
        item = query.get_ioc(db.conn, ioc_type, ioc)
        if item is None:
            raise HTTPException(404, "IOC not found")
        return item

    # -- CRUD ---------------------------------------------------------------
    @app.post("/api/v1/iocs", status_code=201)
    def create_ioc(body: IocCreate, _: dict = Depends(require("write"))):
        ioc_type = body.ioc_type.strip()
        if ioc_type not in IOC_TYPES:
            raise HTTPException(422, f"ioc_type must be one of {', '.join(IOC_TYPES)}")
        from ..normalize import norm_value

        value = norm_value(body.ioc.strip(), ioc_type)
        if not value:
            raise HTTPException(422, "could not normalize the IOC value")
        if query.get_ioc(db.conn, ioc_type, value, detail=False):
            raise HTTPException(409, "IOC already exists")
        status = body.validation_status
        if not status:
            res = validator.validate(value, ioc_type, explicit_malicious=True)
            if not res.valid and not body.force:
                raise HTTPException(422, f"validation failed: {res.status}")
            status = res.status
        tags = [t for t in body.tags if t]
        supported, importable = _cs_flags(
            ioc_type, body.severity, body.confidence, status, tags
        )
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        query.insert_ioc(db.conn, {
            "ioc": value,
            "ioc_type": ioc_type,
            "threat": body.threat,
            "malware_family": body.malware_family,
            "threat_actor": body.threat_actor,
            "campaign": body.campaign,
            "category": ";".join(body.categories),
            "confidence": body.confidence.upper(),
            "severity": body.severity.upper(),
            "first_seen": body.first_seen or today,
            "last_seen": body.last_seen or body.first_seen or today,
            "source": body.source or "manual",
            "source_url": body.source_url,
            "description": body.description,
            "tags": ";".join(tags),
            "mitre_attack": "",
            "crowdstrike_supported": supported,
            "crowdstrike_importable": importable,
            "validation_status": status,
            "sources_detail": json.dumps(
                [{"name": body.source or "manual", "url": body.source_url,
                  "tier": "B", "explicit_malware": True}]
            ),
            "evidence": "[]",
        })
        folders_mod.sync_auto_folders(db.conn)
        return query.get_ioc(db.conn, ioc_type, value)

    @app.put("/api/v1/iocs/{ioc_type}/{ioc:path}")
    def update_ioc_endpoint(ioc_type: str, ioc: str, body: IocUpdate,
                            _: dict = Depends(require("write"))):
        existing = query.get_ioc(db.conn, ioc_type, ioc)
        if existing is None:
            raise HTTPException(404, "IOC not found")
        changes = {k: v for k, v in body.model_dump(exclude_none=True).items()}
        if not changes:
            raise HTTPException(422, "no fields to update")
        severity = changes.get("severity", existing["severity"])
        confidence = changes.get("confidence", existing["confidence"])
        categories = changes.get("categories", existing["categories"])
        validation = changes.get("validation_status", existing["validation_status"])
        if "tags" in changes:
            tags = [t for t in (changes["tags"] or []) if t]
        else:
            tags = existing["tags"]
        if "categories" in changes:
            changes["category"] = ";".join(categories or [])
            changes.pop("categories", None)
        if changes.get("severity"):
            changes["severity"] = changes["severity"].upper()
        if changes.get("confidence"):
            changes["confidence"] = changes["confidence"].upper()
        if changes.get("validation_status"):
            changes["validation_status"] = changes["validation_status"].upper()
        if body.crowdstrike_importable is None:
            supported, importable = _cs_flags(
                ioc_type, str(severity).upper(), str(confidence).upper(),
                str(validation).upper(), tags,
            )
            changes["crowdstrike_supported"] = supported
            changes["crowdstrike_importable"] = importable
        if not query.update_ioc(db.conn, ioc_type, ioc, changes):
            raise HTTPException(404, "IOC not found")
        if "malware_family" in changes or "threat_actor" in changes:
            folders_mod.sync_auto_folders(db.conn)
        return query.get_ioc(db.conn, ioc_type, ioc)

    @app.delete("/api/v1/iocs/{ioc_type}/{ioc:path}")
    def delete_ioc_endpoint(ioc_type: str, ioc: str,
                            _: dict = Depends(require("write"))):
        if not query.delete_ioc(db.conn, ioc_type, ioc):
            raise HTTPException(404, "IOC not found")
        return {"deleted": True, "ioc": ioc, "ioc_type": ioc_type}

    # -- folders ------------------------------------------------------------
    @app.get("/api/v1/folders")
    def list_folders(include_zero: bool = True,
                      _: dict = Depends(require("read"))) -> dict:
        return {"items": folders_mod.list_folders(db.conn, include_zero=include_zero)}

    @app.get("/api/v1/folders/{folder_id}")
    def get_folder(folder_id: int, _: dict = Depends(require("read"))):
        folder = folders_mod.get_folder(db.conn, folder_id)
        if folder is None:
            raise HTTPException(404, "folder not found")
        return folder

    @app.get("/api/v1/folders/{folder_id}/iocs")
    def folder_iocs(folder_id: int, request: Request, format: str = "json",
                    _: dict = Depends(require("read"))):
        if folders_mod.get_folder(db.conn, folder_id) is None:
            raise HTTPException(404, "folder not found")
        filters = apply_min_severity(search_filters(request.query_params))
        filters["folder_id"] = folder_id
        result = query.search_iocs(db.conn, filters)
        if format != "json":
            response = render(result["items"], format, f"folder_{folder_id}")
            response.headers["X-IOC-Total"] = str(result["total"])
            return response
        return result

    @app.post("/api/v1/folders", status_code=201)
    def create_folder(body: FolderCreate, _: dict = Depends(require("write"))):
        try:
            return folders_mod.create_folder(db.conn, body.name, body.description,
                                             body.color)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.put("/api/v1/folders/{folder_id}")
    def update_folder(folder_id: int, body: FolderUpdate,
                      _: dict = Depends(require("write"))):
        try:
            folder = folders_mod.update_folder(db.conn, folder_id,
                                               body.model_dump(exclude_none=True))
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(409, str(exc)) from exc
        if folder is None:
            raise HTTPException(404, "folder not found")
        return folder

    @app.delete("/api/v1/folders/{folder_id}")
    def delete_folder(folder_id: int, _: dict = Depends(require("write"))):
        try:
            folders_mod.delete_folder(db.conn, folder_id)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        return {"deleted": True, "id": folder_id}

    @app.post("/api/v1/folders/{folder_id}/iocs")
    def add_folder_iocs(folder_id: int, body: FolderIocs,
                        _: dict = Depends(require("write"))):
        items: list[tuple[str, str]] = []
        if body.iocs:
            for entry in body.iocs:
                if entry.get("ioc") and entry.get("ioc_type"):
                    items.append((entry["ioc_type"], entry["ioc"]))
        elif body.filter:
            filters = apply_min_severity(search_filters(body.filter))
            filters["limit"] = query.MAX_LIMIT
            result = query.search_iocs(db.conn, filters)
            items = [(i["ioc_type"], i["ioc"]) for i in result["items"]]
        else:
            raise HTTPException(422, "provide iocs[] or filter{}")
        try:
            return folders_mod.add_to_folder(db.conn, folder_id, items)
        except ValueError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.delete("/api/v1/folders/{folder_id}/iocs/{ioc_type}/{ioc:path}")
    def remove_folder_ioc(folder_id: int, ioc_type: str, ioc: str,
                          _: dict = Depends(require("write"))):
        try:
            removed = folders_mod.remove_from_folder(db.conn, folder_id, ioc_type, ioc)
        except ValueError as exc:
            raise HTTPException(404, str(exc)) from exc
        if not removed:
            raise HTTPException(404, "membership not found")
        return {"removed": True}

    @app.post("/api/v1/folders/sync")
    def sync_folders(_: dict = Depends(require("write"))):
        return folders_mod.sync_auto_folders(db.conn)

    # -- api keys -----------------------------------------------------------
    @app.get("/api/v1/keys")
    def list_keys(include_revoked: bool = False,
                  _: dict = Depends(require("admin"))):
        return {"items": keys_mod.list_keys(db.conn, include_revoked)}

    @app.post("/api/v1/keys", status_code=201)
    def create_key(body: KeyCreate, _: dict = Depends(require("admin"))):
        try:
            return keys_mod.create_key(db.conn, body.name, body.scopes,
                                       body.platform)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.delete("/api/v1/keys/{key_id}")
    def revoke_key(key_id: int, _: dict = Depends(require("admin"))):
        if not keys_mod.revoke_key(db.conn, key_id):
            raise HTTPException(404, "key not found or already revoked")
        return {"revoked": True, "id": key_id}

    @app.post("/api/v1/keys/{key_id}/rotate")
    def rotate_key(key_id: int, _: dict = Depends(require("admin"))):
        plain = keys_mod.rotate_key(db.conn, key_id)
        if not plain:
            raise HTTPException(404, "key not found")
        name = db.conn.execute(
            "SELECT name FROM api_keys WHERE id = ?", (key_id,)
        ).fetchone()[0]
        return {"id": key_id, "name": name, "key": plain}

    # -- push / run ---------------------------------------------------------
    @app.get("/api/v1/push")
    def push_status(_: dict = Depends(require("read"))):
        from ..push import load_push_config

        push_cfg = load_push_config(cfg["config_dir"])
        log_rows = [
            dict(r) for r in db.conn.execute(
                "SELECT * FROM push_log ORDER BY id DESC LIMIT 20"
            )
        ]
        return {
            "enabled": push_cfg.get("enabled", False),
            "min_severity": push_cfg.get("min_severity", "HIGH"),
            "targets": [
                {"name": t.get("name"), "type": t.get("type"), "url": t.get("url"),
                 "enabled": t.get("enabled", True)}
                for t in push_cfg.get("targets", [])
            ],
            "log": log_rows,
        }

    @app.post("/api/v1/push")
    def push_now(body: PushRequest | None = None, _: dict = Depends(require("write"))):
        from ..push import push_now

        result = push_now(cfg["config_dir"], (body.targets if body else None))
        return result

    @app.get("/api/v1/run")
    def run_status(_: dict = Depends(require("read"))):
        return runner.status()

    @app.post("/api/v1/run")
    def run_collection(_: dict = Depends(require("write"))):
        if not runner.start():
            raise HTTPException(409, "a collection cycle is already running")
        return {"started": True}

    # -- dashboard ----------------------------------------------------------
    # The dashboard is a Vite + React build (see iocbot/web/). In production we
    # serve `web/dist`; during `npm run dev` the Vite dev server proxies /api
    # here instead, so both paths hit the same backend.
    dist = WEB_DIR / "dist"
    web_root = dist if (dist / "index.html").is_file() else WEB_DIR

    if web_root.is_dir():
        app.mount("/static", StaticFiles(directory=str(web_root)), name="static")

        @app.get("/", include_in_schema=False)
        def index():
            return FileResponse(web_root / "index.html")

    return app


def _stix_time(value: str | None) -> str | None:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    if "T" in text:
        return text if text.endswith("Z") else text + "Z" if "+" not in text else text
    return f"{text[:10]}T00:00:00.000Z"


def _cs_flags(ioc_type: str, severity: str, confidence: str, validation: str,
              tags) -> tuple[str, str]:
    from ..score import CONFIDENCE_THRESHOLDS, CS_SUPPORTED_TYPES, SEVERITY_THRESHOLDS

    blocked = {"shared-platform", "legit-service-abused", "generic-vendor", "cdn"}
    supported = ioc_type in CS_SUPPORTED_TYPES
    importable = bool(
        supported
        and str(validation).upper() == "VALID"
        and str(severity).upper() in SEVERITY_THRESHOLDS
        and str(confidence).upper() in CONFIDENCE_THRESHOLDS
        and not (set(tags or []) & blocked)
    )
    return ("YES" if supported else "NO", "YES" if importable else "NO")


class _Runner:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self.last_stats: dict | None = None
        self.last_error: str | None = None
        self.started_at: str = ""
        self.finished_at: str = ""

    def status(self) -> dict:
        with self._lock:
            return {
                "running": bool(self._thread and self._thread.is_alive()),
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "last_stats": self.last_stats,
                "last_error": self.last_error,
            }

    def start(self) -> bool:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return False
            self.started_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            self.finished_at = ""
            self.last_error = None
            self._thread = threading.Thread(target=self._run, daemon=True,
                                            name="iocbot-collect")
            self._thread.start()
        return True

    def _run(self) -> None:
        try:
            from ..pipeline import Pipeline

            root = self.cfg["root"]
            pipe = Pipeline(root, self.cfg["config_dir"], root / "data",
                            root / "output")
            stats = pipe.run()
            self.last_stats = stats
            try:
                folders_mod.sync_auto_folders(open_db(root / "data" / "state.db"))
            except Exception:  # noqa: BLE001
                log.exception("folder sync after collection failed")
        except Exception as exc:  # noqa: BLE001
            log.exception("collection run failed")
            self.last_error = str(exc)
        finally:
            self.finished_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _lan_ips() -> list[str]:
    """Best-effort non-loopback IPv4 addresses for the startup banner."""
    found: list[str] = []

    def add(ip: str) -> None:
        if ip and not ip.startswith("127.") and ip not in found:
            found.append(ip)

    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            add(info[4][0])
    except OSError:
        pass
    for target in ("192.168.1.1", "10.0.0.1", "172.16.0.1"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.1)
            s.connect((target, 80))
            add(s.getsockname()[0])
            s.close()
        except OSError:
            pass
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="iocbot.api",
        description="Serve the IOC feed API and analyst dashboard",
    )
    parser.add_argument("--host", default=None, help="bind address (default from config/api.yaml)")
    parser.add_argument("--port", type=int, default=None, help="port (default from config/api.yaml)")
    parser.add_argument("--config-dir", default=None, help="config directory")
    parser.add_argument("--no-auth", action="store_true", help="disable API-key auth")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )

    cfg = load_config(args.config_dir)
    if args.host:
        cfg["host"] = args.host
    if args.port:
        cfg["port"] = args.port
    if args.no_auth:
        cfg["auth_required"] = False

    import uvicorn

    app = create_app(cfg)
    host, port = str(cfg["host"]), int(cfg["port"])
    local = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    print(f"IOC dashboard: http://{local}:{port}/", flush=True)
    print(f"IOC feed API:  http://{local}:{port}/api/v1/iocs", flush=True)
    if local != host:
        for ip in _lan_ips():
            print(f"LAN dashboard: http://{ip}:{port}/", flush=True)
    uvicorn.run(app, host=host, port=port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
