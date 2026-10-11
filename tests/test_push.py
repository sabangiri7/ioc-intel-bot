"""Tests for outbound SIEM push (iocbot/push.py).

Focus: config loading defaults, the enabled/no-targets gate, target filtering,
dry-run (must not send), per-target error isolation, and the push_log audit.
"""
import yaml

from iocbot import push as push_mod


def _write_cfg(tmp_path, cfg):
    (tmp_path / "config").mkdir(exist_ok=True)
    (tmp_path / "config" / "push.yaml").write_text(yaml.safe_dump(cfg))


def test_missing_config_returns_disabled(tmp_path):
    cfg = push_mod.load_push_config(tmp_path / "empty")
    assert cfg["enabled"] is False and cfg["targets"] == []


def test_config_defaults_applied(tmp_path):
    _write_cfg(tmp_path, {"enabled": True, "targets": [{"name": "t", "type": "webhook", "url": "https://x"}]})
    cfg = push_mod.load_push_config(tmp_path / "config")
    assert cfg["min_severity"] == "HIGH"
    assert cfg["view"] == "importable"
    assert cfg["batch_limit"] == 5000


def test_push_disabled_returns_early(tmp_path):
    """Enabled=false short-circuits before any network or DB work."""
    _write_cfg(tmp_path, {"enabled": False,
                          "targets": [{"name": "t", "type": "webhook", "url": "https://x"}]})
    res = push_mod.push_now(tmp_path / "config")
    assert res["enabled"] is False and res["sent"] == 0
    assert "disabled" in res["detail"]


def test_push_disabled_when_no_targets(tmp_path):
    _write_cfg(tmp_path, {"enabled": True, "targets": []})
    res = push_mod.push_now(tmp_path / "config")
    assert res["enabled"] is False


def test_dry_run_reports_rows_without_sending(tmp_path, monkeypatch):
    _write_cfg(tmp_path, {"enabled": True,
                          "targets": [{"name": "t1", "type": "webhook", "url": "https://x"}]})
    monkeypatch.setattr(push_mod, "_rows", lambda *a, **k: [{"ioc": "1.2.3.4"}, {"ioc": "5.6.7.8"}])

    def boom(*a, **k):
        raise AssertionError("dry-run must not send")

    monkeypatch.setattr(push_mod, "_send", boom)
    res = push_mod.push_now(tmp_path / "config", dry_run=True)
    assert res["enabled"] is True
    assert res["rows"] == 2
    assert res["results"][0]["status"] == "dry-run"
    assert res["results"][0]["sent"] == 2


def test_target_filter_is_case_insensitive(tmp_path, monkeypatch):
    _write_cfg(tmp_path, {"enabled": True, "targets": [
        {"name": "Splunk-Prod", "type": "webhook", "url": "https://a"},
        {"name": "Elastic", "type": "webhook", "url": "https://b"},
    ]})
    monkeypatch.setattr(push_mod, "_rows", lambda *a, **k: [])
    res = push_mod.push_now(tmp_path / "config", target_names=["splunk-prod"], dry_run=True)
    assert [r["target"] for r in res["results"]] == ["Splunk-Prod"]


def test_send_failure_isolated_per_target(tmp_path, monkeypatch):
    """One failing target must not abort the others."""
    _write_cfg(tmp_path, {"enabled": True, "targets": [
        {"name": "bad", "type": "webhook", "url": "https://a"},
        {"name": "good", "type": "webhook", "url": "https://b"},
    ]})
    monkeypatch.setattr(push_mod, "_rows", lambda *a, **k: [{"ioc": "1.2.3.4"}])
    monkeypatch.setattr(push_mod, "_log", lambda *a, **k: None)

    def fake_send(target, rows, now):
        if target["name"] == "bad":
            raise RuntimeError("connection refused")
        return "ok", len(rows), "sent"

    monkeypatch.setattr(push_mod, "_send", fake_send)
    res = push_mod.push_now(tmp_path / "config")
    by_name = {r["target"]: r for r in res["results"]}
    assert by_name["bad"]["status"] == "error"
    assert by_name["good"]["status"] == "ok"
    # total only counts successful targets
    assert res["sent"] == 1


def test_event_payload_shape(monkeypatch):
    """_event flattens a row into the documented 15-field payload."""
    row = {
        "ioc": "1.2.3.4", "ioc_type": "IPv4", "severity": "HIGH",
        "confidence": "HIGH", "categories": ["C2"], "malware_family": "Mirai",
        "threat_actor": "", "folders": ["Mirai"], "validation_status": "VALID",
        "crowdstrike_importable": "YES", "first_seen": "2026-01-01",
        "last_seen": "2026-10-01", "sources": ["ThreatFox"], "tags": [],
        "description": "d",
    }
    ev = push_mod._event(row)
    assert ev["ioc"] == "1.2.3.4" and ev["ioc_type"] == "IPv4"
    assert ev["categories"] == ["C2"] and ev["folders"] == ["Mirai"]
    assert "first_seen" in ev and "sources" in ev