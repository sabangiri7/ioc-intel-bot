import csv

import pytest
from fastapi.testclient import TestClient

from iocbot.api.server import create_app
from iocbot.folders import build_folder_buckets, sync_auto_folders
from iocbot import keys as keys_mod
from iocbot.models import Mention
from iocbot.store import Store


@pytest.fixture
def client(tmp_path):
    store = Store(tmp_path / "data" / "state.db")
    cid = store.begin_cycle()
    rows = [
        Mention(value="1.2.3.4", ioc_type="IPv4", source_name="ThreatFox",
                source_url="https://src", tier="A", categories=["C2"],
                malware_family="Mirai", description="d", evidence="e"),
        Mention(value="evil.example", ioc_type="Domain", source_name="URLhaus",
                source_url="https://src", tier="A", categories=["MALWARE"],
                explicit_malware=True, description="d", evidence="e"),
    ]
    for m in rows:
        store.upsert(m, "VALID", set())
    store.flush(cid)
    store.close_cycle(cid, {})
    store.close()

    app = create_app({
        "root": tmp_path,
        "config_dir": tmp_path / "config",
        "server": {"host": "127.0.0.1", "port": 8080},
        "auth": {"required": True,
                 "bootstrap_key_file": str(tmp_path / "admin.key")},
    })
    db = app.state.db
    sync_auto_folders(db.conn)
    key = keys_mod.create_key(db.conn, "tester", "admin")["key"]
    return TestClient(app), key


def _h(key):
    return {"X-API-Key": key}


def test_feed_defaults_to_json_but_csv_is_exportable(client):
    c, key = client
    h = _h(key)
    # No format param -> JSON. The dashboard's export button must ask for csv.
    assert c.get("/api/v1/feed", headers=h).headers["content-type"].startswith(
        "application/json"
    )
    out = c.get("/api/v1/feed?format=csv", headers=h).text
    lines = out.strip().splitlines()
    assert lines[0].startswith("IOC,")
    assert len(lines) == 3  # header + IPv4 + Domain


def test_feed_csv_can_scope_ioc_types(client):
    c, key = client
    h = _h(key)
    ips = c.get("/api/v1/feed?format=csv&ioc_type=IPv4", headers=h).text
    lines = ips.strip().splitlines()
    assert lines[0].startswith("IOC,")
    assert len(lines) == 2 and "1.2.3.4" in lines[1]

    hashes = c.get("/api/v1/feed?format=csv&ioc_type=SHA256,SHA1,MD5", headers=h).text
    assert len(hashes.strip().splitlines()) == 1  # header only

    domains = c.get("/api/v1/feed?format=csv&ioc_type=Domain", headers=h).text
    assert "evil.example" in domains and "1.2.3.4" not in domains


def test_folder_iocs_csv_export(client):
    c, key = client
    h = _h(key)
    folders = c.get("/api/v1/folders?include_zero=false", headers=h).json()["items"]
    mirai = next(f for f in folders if f["name"] == "Mirai")
    out = c.get(f"/api/v1/folders/{mirai['id']}/iocs?format=csv", headers=h)
    assert out.headers["content-type"].startswith("text/csv")
    lines = out.text.strip().splitlines()
    assert lines[0].startswith("IOC,")
    assert any("1.2.3.4" in line for line in lines[1:])


def test_health_no_key(client):
    c, _ = client
    r = c.get("/api/v1/health", headers={"X-API-Key": ""})
    assert r.status_code == 200


def test_auth_required(client):
    c, key = client
    assert c.get("/api/v1/stats", headers=_h("nope")).status_code == 401
    assert c.get("/api/v1/stats", headers=_h("")).status_code in (401, 403)


def test_stats_and_feed(client):
    c, key = client
    h = _h(key)
    s = c.get("/api/v1/stats", headers=h).json()
    assert s["total"] == 2
    f = c.get("/api/v1/feed?limit=1", headers=h).json()
    assert f["count"] == 1 and f["total"] == 2
    out = c.get("/api/v1/feed?format=csv&limit=5", headers=h).text
    assert out.splitlines()[0].startswith("IOC,")


def test_ioc_search_and_stix(client):
    c, key = client
    h = _h(key)
    j = c.get("/api/v1/iocs?q=1.2.3.4&format=json", headers=h).json()
    assert j["total"] == 1
    b = c.get("/api/v1/iocs?view=malware&format=stix", headers=h).json()
    assert b["type"] == "bundle"
    assert any(o["type"] == "indicator" for o in b["objects"])


def test_ioc_crud(client):
    c, key = client
    h = _h(key)
    r = c.post("/api/v1/iocs", json={
        "ioc_type": "Domain", "ioc": "crud-c2.example",
        "categories": ["C2"], "severity": "LOW", "confidence": "MEDIUM",
        "validation_status": "VALID", "description": "created via api",
    }, headers=h)
    assert r.status_code == 201, r.text
    assert c.get("/api/v1/iocs?q=crud-c2.example", headers=h).json()["total"] == 1
    r = c.put("/api/v1/iocs/Domain/crud-c2.example", json={"severity": "HIGH"},
              headers=h)
    assert r.status_code == 200, r.text
    assert c.get("/api/v1/iocs/Domain/crud-c2.example", headers=h).json()["severity"] == "HIGH"
    assert c.delete("/api/v1/iocs/Domain/crud-c2.example", headers=h).status_code == 200
    assert c.get("/api/v1/iocs?q=crud-c2.example", headers=h).json()["total"] == 0


def test_folder_create_add_remove(client):
    c, key = client
    h = _h(key)
    r = c.post("/api/v1/folders", json={"name": "My Group",
                                        "description": "blue team watchlist"},
               headers=h)
    assert r.status_code == 201, r.text
    fid = r.json()["id"]
    r = c.post("/api/v1/iocs", json={
        "ioc_type": "IPv4", "ioc": "8.8.8.8", "categories": ["C2"],
        "validation_status": "VALID", "severity": "LOW",
    }, headers=h)
    assert r.status_code == 201, r.text
    add = c.post(f"/api/v1/folders/{fid}/iocs",
                 json={"iocs": [{"ioc_type": "IPv4", "ioc": "8.8.8.8"}]}, headers=h)
    assert add.status_code == 200
    assert c.post(f"/api/v1/folders/{fid}/iocs",
                  json={"filter": {"ioc_type": "IPv4"}},
                  headers=h).status_code == 200
    items = c.get(f"/api/v1/folders/{fid}/iocs?limit=50", headers=h).json()
    assert {i["ioc"] for i in items["items"]} >= {"1.2.3.4", "8.8.8.8"}
    r = c.delete(f"/api/v1/folders/{fid}/iocs/IPv4/8.8.8.8", headers=h)
    assert r.status_code == 200
    assert c.delete(f"/api/v1/folders/{fid}", headers=h).status_code == 200


def test_keys_endpoints(client):
    c, key = client
    h = _h(key)
    r = c.post("/api/v1/keys",
               json={"name": "siem-qa", "scopes": "read", "platform": "FortiSIEM"},
               headers=h)
    assert r.status_code == 201, r.text
    kid = r.json()["id"]
    assert r.json()["platform"] == "FortiSIEM"
    names = {i["name"]: i for i in c.get("/api/v1/keys", headers=h).json()["items"]}
    assert "siem-qa" in names
    assert names["siem-qa"]["platform"] == "FortiSIEM"
    rot = c.post(f"/api/v1/keys/{kid}/rotate", headers=h)
    assert rot.status_code == 200 and rot.json()["name"] == "siem-qa"
    assert rot.json()["key"].startswith("iok_")
    assert c.delete(f"/api/v1/keys/{kid}", headers=h).status_code == 200
    tracked = {i["name"]: i for i in
               c.get("/api/v1/keys?include_revoked=true", headers=h).json()["items"]}
    assert "siem-qa" in tracked and tracked["siem-qa"]["revoked"] is True
    tester = tracked["tester"]
    assert tester["uses"] >= 1 and tester["last_ip"] != ""


def test_unreviewed_view_and_stats_fields(client):
    c, key = client
    h = _h(key)
    from iocbot import query
    conn = c.app.state.db.conn
    query.insert_ioc(conn, {
        "ioc": "no-val-123.example", "ioc_type": "Domain",
        "category": "C2", "severity": "LOW", "confidence": "MEDIUM",
        "validation_status": "", "first_seen": "2026-01-01",
        "last_seen": "2026-01-01", "source": "test",
    })
    query.insert_ioc(conn, {
        "ioc": "val-ok.example", "ioc_type": "Domain",
        "category": "C2", "severity": "LOW", "confidence": "MEDIUM",
        "validation_status": "VALID", "first_seen": "2026-01-01",
        "last_seen": "2026-01-01", "source": "test",
    })
    s = c.get("/api/v1/stats", headers=h).json()
    assert {"c2", "malware", "unreviewed"} <= set(s)
    assert s["unreviewed"] == 1
    j = c.get("/api/v1/iocs?unreviewed=true", headers=h).json()
    assert j["total"] == 1
    assert j["items"][0]["ioc"] == "no-val-123.example"
    assert c.get("/api/v1/iocs?view=c2&limit=50", headers=h).json()["total"] >= 1


def test_pull_and_push_endpoints_smoke(client):
    c, key = client
    h = _h(key)
    import time

    def blocker():
        time.sleep(0.5)

    c.app.state.runner._run = blocker
    assert c.get("/api/v1/push", headers=h).json()["enabled"] is False
    assert c.post("/api/v1/run", headers=h).status_code == 200
    assert c.get("/api/v1/run", headers=h).json()["running"] is True


def test_bootstrap_claims_admin_key_once(tmp_path):
    app = create_app({
        "root": tmp_path,
        "config_dir": tmp_path / "config",
        "server": {"host": "127.0.0.1", "port": 8080},
        "auth": {"required": True,
                 "bootstrap_key_file": str(tmp_path / "admin.key")},
    })
    kfile = tmp_path / "admin.key"
    assert kfile.is_file()
    c = TestClient(app)
    r1 = c.post("/api/v1/auth/bootstrap")
    assert r1.status_code == 200 and r1.json()["key"].startswith("iok_")
    assert not kfile.exists()  # plaintext issued exactly once
    assert c.post("/api/v1/auth/bootstrap").status_code == 404
    assert c.get("/api/v1/stats",
                 headers=_h(r1.json()["key"])).status_code == 200


def test_export_feed_and_folder_csvs(tmp_path):
    store = Store(tmp_path / "data" / "state.db")
    cid = store.begin_cycle()
    store.upsert(Mention(value="1.2.3.4", ioc_type="IPv4", source_name="T",
                         source_url="u", tier="A", categories=["C2"],
                         malware_family="Mirai", description="d", evidence="e"),
                 "VALID", set())
    store.flush(cid)
    store.close_cycle(cid, {})
    rows = [dict(r) for r in store.all_rows()]
    from iocbot.score import score_row
    for r in rows:
        score_row(r)
    buckets = build_folder_buckets(store.conn, rows)
    out = tmp_path / "out"
    from iocbot.export import write_all
    counts = write_all(out, rows, rows, {"confidence_threshold": ["HIGH"],
                                         "severity_threshold": ["HIGH"]},
                       folder_buckets=buckets)
    with open(out / "IOC_FEED.csv") as fh:
        rows_feed = list(csv.DictReader(fh))
    assert rows_feed[0]["IOC"] == "1.2.3.4"
    assert rows_feed[0]["SEVERITY"] != ""
    assert "Mirai" in rows_feed[0]["FOLDERS"]
    assert counts["IOC_FEED.csv"] == 1
    folder_files = list((out / "folders").glob("*.csv"))
    assert len(folder_files) == 1
    assert (out / "FOLDERS_INDEX.csv").is_file()
    with open(folder_files[0]) as fh:
        assert list(csv.DictReader(fh))[0]["IOC"] == "1.2.3.4"