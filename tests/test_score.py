from datetime import date, timedelta

from iocbot.score import score_row
from iocbot.store import Store
from iocbot.models import Mention


def _row(**kw):
    row = {
        "ioc": kw.get("ioc", "1.2.3.4"),
        "ioc_type": kw.get("ioc_type", "IPv4"),
        "threat": "",
        "malware_family": kw.get("malware_family", ""),
        "threat_actor": "",
        "campaign": "",
        "categories": kw.get("categories", ["C2"]),
        "validation_status": kw.get("validation_status", "VALID"),
        "first_seen": kw.get("first_seen", ""),
        "last_seen": kw.get("last_seen", ""),
        "sources_detail": kw.get("sources_detail", []),
        "confidence": "",
        "severity": "",
        "crowdstrike_supported": "",
        "crowdstrike_importable": "",
    }
    return row


def _src(name="S", tier="B", explicit_malware=False, explicit_c2=False, active=None,
         feed_confidence=None):
    return {
        "name": name, "url": "u", "tier": tier,
        "explicit_c2": explicit_c2, "explicit_malware": explicit_malware,
        "active": active, "feed_confidence": feed_confidence,
    }


def test_single_tier_a_high_confidence():
    today = date.today().isoformat()
    row = score_row(_row(last_seen=today, sources_detail=[_src(tier="A", active=True)]))
    assert row["confidence"] == "HIGH"
    assert row["severity"] == "CRITICAL"
    assert row["crowdstrike_importable"] == "YES"


def test_two_publishers_high():
    row = score_row(_row(
        categories=["MALWARE"],
        last_seen=date.today().isoformat(),
        sources_detail=[_src("A", "B", explicit_malware=True), _src("B", "B", explicit_malware=True)],
    ))
    assert row["confidence"] == "HIGH"
    assert row["severity"] == "HIGH"
    assert row["crowdstrike_importable"] == "YES"


def test_single_incidental_source_low():
    row = score_row(_row(last_seen=date.today().isoformat(), sources_detail=[_src("X", "B")]))
    assert row["confidence"] == "LOW"
    assert row["severity"] == "LOW"
    assert row["crowdstrike_importable"] == "NO"


def test_tier_c_only_never_importable():
    row = score_row(_row(
        last_seen=date.today().isoformat(),
        categories=["C2"],
        sources_detail=[_src("block", "C", explicit_malware=True, active=True)],
    ))
    assert row["confidence"] == "LOW"
    assert row["severity"] == "LOW"
    assert row["crowdstrike_importable"] == "NO"


def test_stale_c2_downgraded():
    stale = (date.today() - timedelta(days=200)).isoformat()
    row = score_row(_row(last_seen=stale, sources_detail=[_src(tier="A", active=False)]))
    assert row["severity"] in ("MEDIUM", "LOW")
    assert row["crowdstrike_importable"] == "NO" or row["severity"] == "MEDIUM"


def test_cve_high():
    row = score_row(_row(ioc="CVE-2024-1234", ioc_type="CVE", categories=[],
                         sources_detail=[_src(tier="A")]))
    assert row["severity"] == "HIGH"
    assert row["confidence"] == "HIGH"


def test_unsupported_type_not_importable():
    row = score_row(_row(ioc="http://x.example/a", ioc_type="URL",
                         last_seen=date.today().isoformat(),
                         sources_detail=[_src(tier="A", active=True)]))
    assert row["crowdstrike_supported"] == "NO"
    assert row["crowdstrike_importable"] == "NO"


def test_shared_platform_not_importable():
    row = score_row(_row(
        ioc="evil.com", ioc_type="Domain",
        validation_status="SHARED-PLATFORM",
        last_seen=date.today().isoformat(),
        sources_detail=[_src(tier="A", active=True)],
    ))
    assert row["crowdstrike_importable"] == "NO"


def test_legit_service_abused_not_importable_and_capped():
    row = _row(last_seen=date.today().isoformat(), categories=["C2"],
               sources_detail=[_src(tier="A", active=True)])
    row["tags_list"] = ["report", "legit-service-abused"]
    score_row(row)
    assert row["severity"] == "MEDIUM"
    assert row["crowdstrike_importable"] == "NO"
