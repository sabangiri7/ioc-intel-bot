"""Tests for the collection orchestrator (iocbot/pipeline.py).

Focus: collector-failure isolation (a broken source must not abort the cycle),
the sources_filter substring match, skip flags, and end-to-end export output.
Collectors and the fetcher are stubbed so no network access occurs.
"""
import shutil

import pytest

from iocbot import pipeline as pipeline_mod
from iocbot.models import Mention
from iocbot.pipeline import Pipeline


@pytest.fixture
def pipe(tmp_path):
    """A Pipeline wired to a minimal config dir; collector modules are stubbed."""
    cfg = tmp_path / "config"
    cfg.mkdir()
    # copy the real validation + crowdstrike configs so gates behave normally
    for f in ("validation.yaml", "crowdstrike.yaml"):
        shutil.copy(f"config/{f}", cfg / f)
    # one good feed, one broken feed, one good + one broken blocklist
    (cfg / "sources.yaml").write_text(
        """
feeds:
  - name: GoodFeed
    kind: urlhaus
    tier: A
    url: https://x/good
  - name: BadFeed
    kind: threatfox
    tier: A
    url: https://x/bad
blocklists:
  - name: GoodList
    kind: ip_list
    tier: C
    url: https://x/ips
  - name: BadList
    kind: domain_list
    tier: C
    url: https://x/doms
reports: []
mitre:
  enabled: false
"""
    )
    p = Pipeline(tmp_path, cfg, tmp_path / "data", tmp_path / "out")
    yield p
    try:
        p.store.close()
    except Exception:
        pass


def _stub_collectors(monkeypatch, fail_kinds=()):
    """Replace the collector registry with deterministic stubs.

    `fail_kinds` names that should raise, to prove failure isolation.
    """
    def good(cfg, fetcher, **kw):
        return ([Mention(value="1.2.3.4", ioc_type="IPv4", source_name=cfg["name"],
                        source_url=cfg["url"], tier="A", categories=["C2"],
                        malware_family="TestFam", description="d", evidence="e")],
                {"source": cfg["name"], "kind": cfg.get("kind"), "fetched": True,
                 "mentions": 1, "errors": []})

    def bad(cfg, fetcher, **kw):
        raise RuntimeError("collector exploded")

    registry = {}
    for kind in ("urlhaus", "threatfox", "ip_list", "domain_list", "url_list"):
        registry[kind] = bad if kind in fail_kinds else good
    monkeypatch.setattr(pipeline_mod, "COLLECTORS", registry)


def test_collector_failure_does_not_abort_cycle(pipe, monkeypatch):
    """A raising collector is recorded as failed; the cycle still completes."""
    _stub_collectors(monkeypatch, fail_kinds={"threatfox", "domain_list"})
    stats = pipe.run(skip_reports=True)

    names = {s["source"] for s in stats["sources"]}
    assert {"GoodFeed", "BadFeed", "GoodList", "BadList"} <= names

    failed = {s["source"] for s in stats["sources"] if not s.get("fetched")}
    assert failed == {"BadFeed", "BadList"}

    # the good feed still produced and stored a row
    assert stats["export_counts"]["MASTER_IOC_DATABASE.csv"] >= 1


def test_sources_filter_matches_name_substring(pipe, monkeypatch):
    _stub_collectors(monkeypatch)
    stats = pipe.run(sources_filter="goodfeed", skip_reports=True)
    names = {s["source"] for s in stats["sources"]}
    assert names == {"GoodFeed"}  # only the matching feed ran


def test_skip_blocklists_excludes_blocklist_sources(pipe, monkeypatch):
    _stub_collectors(monkeypatch)
    stats = pipe.run(skip_reports=True, skip_blocklists=True)
    names = {s["source"] for s in stats["sources"]}
    assert "GoodList" not in names and "GoodFeed" in names


def test_cycle_writes_daily_exports(pipe, monkeypatch):
    _stub_collectors(monkeypatch, fail_kinds={"threatfox", "domain_list"})
    pipe.run(skip_reports=True)
    from datetime import date
    daily = pipe.output_dir / "daily" / date.today().isoformat()
    assert (daily / "MASTER_IOC_DATABASE.csv").is_file()
    assert (daily / "IOC_SUMMARY.txt").is_file()
    assert (daily / "IOC_FEED.csv").is_file()


def test_validation_gate_rejects_reserved_ip(pipe, monkeypatch):
    """10.0.0.1 passes the blocklist parser but is rejected by the Validator."""
    def stub(cfg, fetcher, **kw):
        return ([Mention(value="10.0.0.1", ioc_type="IPv4", source_name=cfg["name"],
                        source_url=cfg["url"], tier="C", categories=["OTHER"],
                        tags=["blocklist"], description="d", evidence="e")],
                {"source": cfg["name"], "kind": cfg.get("kind"), "fetched": True,
                 "mentions": 1, "errors": []})

    monkeypatch.setattr(pipeline_mod, "COLLECTORS",
                        {"ip_list": stub, "domain_list": stub, "url_list": stub,
                         "urlhaus": stub, "threatfox": stub})
    stats = pipe.run(sources_filter="GoodList", skip_reports=True, skip_blocklists=False)
    # reserved IP rejected -> nothing exportable from it
    assert stats["export_counts"]["MASTER_IOC_DATABASE.csv"] == 0
    assert stats["processing"]["rejected"] >= 1
    assert "private-or-reserved" in str(stats["processing"]["reject_reasons"])