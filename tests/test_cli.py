"""Tests for the CLI entry point (iocbot/cli.py).

Focus: the missing-config exit code (2), the --json stats output, and the
path-override flags. A Pipeline stub keeps these tests fast and offline.
"""
import json

import pytest

from iocbot import cli


@pytest.fixture
def stub_pipeline(monkeypatch):
    """Replace Pipeline with a stub that records the kwargs it was called with."""
    captured = {}

    class StubPipeline:
        def __init__(self, root, config_dir, data_dir, output_dir):
            captured["paths"] = (root, config_dir, data_dir, output_dir)

        def run(self, **kwargs):
            captured["run"] = kwargs
            return {"export_counts": {"MASTER_IOC_DATABASE.csv": 3}, "sources": []}

    monkeypatch.setattr("iocbot.pipeline.Pipeline", StubPipeline)
    return captured


def _config_dir(tmp_path):
    cfg = tmp_path / "config"
    cfg.mkdir()
    for f in ("sources.yaml", "validation.yaml", "crowdstrike.yaml"):
        (cfg / f).write_text("{}")
    return cfg


def test_missing_required_config_returns_exit_code_2(tmp_path):
    # no config dir at all
    rc = cli.main(["--root", str(tmp_path), "--config-dir", str(tmp_path / "nope")])
    assert rc == 2


def test_json_flag_prints_stats(tmp_path, capsys, stub_pipeline):
    cfg = _config_dir(tmp_path)
    rc = cli.main(["--root", str(tmp_path), "--config-dir", str(cfg), "--json"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["export_counts"]["MASTER_IOC_DATABASE.csv"] == 3


def test_run_flags_are_forwarded(tmp_path, stub_pipeline):
    cfg = _config_dir(tmp_path)
    cli.main(["--root", str(tmp_path), "--config-dir", str(cfg),
              "--skip-reports", "--skip-blocklists",
              "--max-articles", "3", "--sources", "threatfox", "--json"])
    kw = stub_pipeline["run"]
    assert kw["skip_reports"] is True
    assert kw["skip_blocklists"] is True
    assert kw["max_articles"] == 3
    assert kw["sources_filter"] == "threatfox"


def test_path_override_flags_used(tmp_path, stub_pipeline):
    cfg = _config_dir(tmp_path)
    data = tmp_path / "mydata"
    out = tmp_path / "myout"
    cli.main(["--root", str(tmp_path), "--config-dir", str(cfg),
              "--data-dir", str(data), "--output-dir", str(out), "--json"])
    _, got_cfg, got_data, got_out = stub_pipeline["paths"]
    assert got_cfg == cfg and got_data == data and got_out == out


def test_summary_printed_when_not_json(tmp_path, capsys, stub_pipeline):
    cfg = _config_dir(tmp_path)
    # no daily summary on disk -> falls back to export_counts JSON
    cli.main(["--root", str(tmp_path), "--config-dir", str(cfg)])
    out = capsys.readouterr().out
    assert "MASTER_IOC_DATABASE.csv" in out