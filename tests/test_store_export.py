import csv
from datetime import datetime, timedelta, timezone
from pathlib import Path

from iocbot.export import write_all
from iocbot.models import Mention
from iocbot.store import Store


def _mk_store(tmp_path):
    return Store(tmp_path / "state.db")


def _mention(value, itype, source="Feed A", tier="B", first="2026-01-01",
             last="2026-01-02", cats=None, explicit_malware=True, **kw):
    return Mention(
        value=value, ioc_type=itype, source_name=source, source_url="https://src",
        tier=tier, first_seen=first, last_seen=last,
        explicit_malware=explicit_malware, categories=cats or ["C2"],
        description="desc", evidence="because", **kw,
    )


def test_upsert_merges_sources_and_dates(tmp_path):
    store = _mk_store(tmp_path)
    store.upsert(_mention("1.2.3.4", "IPv4", source="A", first="2026-03-01", last="2026-03-05"), "VALID", set())
    store.upsert(_mention("1.2.3.4", "IPv4", source="B", first="2026-01-01", last="2026-06-01"), "VALID", set())
    cid = store.begin_cycle()
    store.flush(cid)
    rows = store.all_rows()
    assert len(rows) == 1
    row = rows[0]
    assert row["first_seen"] == "2026-01-01"
    assert row["last_seen"] == "2026-06-01"
    assert set(row["sources_detail"][i]["name"] for i in range(2)) == {"A", "B"}
    store.close_cycle(cid, {})


def test_new_rows_only_first_cycle(tmp_path):
    store = _mk_store(tmp_path)
    c1 = store.begin_cycle()
    store.upsert(_mention("9.9.9.9", "IPv4"), "VALID", set())
    store.flush(c1)
    store.close_cycle(c1, {})
    c2 = store.begin_cycle()
    store.upsert(_mention("8.8.8.8", "IPv4"), "VALID", set())
    store.flush(c2)
    assert [r["ioc"] for r in store.new_rows(c2)] == ["8.8.8.8"]
    assert len(store.new_rows(c1)) == 1
    store.close_cycle(c2, {})


def test_write_all_single_column(tmp_path):
    store = _mk_store(tmp_path)
    cid = store.begin_cycle()
    store.upsert(_mention("1.2.3.4", "IPv4", source="ThreatFox", tier="A"), "VALID", set())
    store.upsert(_mention("bad-c2.example", "Domain", source="ThreatFox", tier="A"), "VALID", set())
    store.upsert(
        _mention("http://bad.example/x", "URL", source="URLhaus", tier="A",
                 cats=["MALWARE-DISTRIBUTION"]),
        "VALID", set(),
    )
    store.upsert(
        _mention("CVE-2024-1234", "CVE", source="KEV", tier="A", cats=["RANSOMWARE"]),
        "VALID", set(),
    )
    store.upsert(
        _mention("NotSupported", "SHA1", source="MB", tier="A", cats=["MALWARE"]),
        "VALID", set(),
    )
    store.upsert(
        _mention("agenttesla", "Malware", source="MB", tier="A", cats=["INFOSTEALER"]),
        "VALID", set(),
    )
    store.upsert(
        _mention("/tmp/helper", "File-Path", source="MB", tier="A", cats=["MALWARE"]),
        "VALID", set(),
    )
    store.flush(cid)
    rows = store.all_rows()
    for r in rows:
        from iocbot.score import score_row

        score_row(r)
    out = tmp_path / "out"
    counts = write_all(out, rows, rows, {
        "confidence_threshold": ["MEDIUM", "HIGH", "CRITICAL"],
        "severity_threshold": ["MEDIUM", "HIGH", "CRITICAL"],
    })

    def read(name):
        lines = (out / name).read_text().splitlines()
        assert lines[0] == "IOC"
        return set(lines[1:])

    master = read("MASTER_IOC_DATABASE.csv")
    assert master == {"1.2.3.4", "bad-c2.example", "http://bad.example/x",
                      "CVE-2024-1234", "NotSupported"}
    # entity rows (Malware family, file paths) are never exported
    assert "agenttesla" not in master and "/tmp/helper" not in master
    assert counts["MASTER_IOC_DATABASE.csv"] == len(master)

    cs = read("CROWDSTRIKE_IOC_IMPORT.csv")
    assert "1.2.3.4" in cs and "bad-c2.example" in cs
    assert "NotSupported" not in cs and "CVE-2024-1234" not in cs
    assert counts["CROWDSTRIKE_IOC_IMPORT.csv"] == len(cs)

    c2 = read("C2_IOCS.csv")
    assert c2 == {"1.2.3.4", "bad-c2.example"}

    dl = read("MALWARE_DOWNLOAD_IOCS.csv")
    assert "http://bad.example/x" in dl
