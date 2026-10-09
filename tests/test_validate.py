from pathlib import Path

from iocbot.validate import Validator

CFG = Path(__file__).resolve().parent.parent / "config" / "validation.yaml"


def v():
    return Validator(CFG)


def test_valid_malicious_ip():
    res = v().validate("45.155.205.99", "IPv4", explicit_malicious=True)
    assert res.valid and res.status == "VALID"


def test_private_ip_rejected():
    res = v().validate("192.168.1.10", "IPv4", explicit_malicious=True)
    assert not res.valid
    assert res.status.startswith("REJECTED")


def test_doc_domain_rejected():
    res = v().validate("example.com", "Domain", explicit_malicious=True)
    assert not res.valid


def test_google_cdn_shared_platform():
    res = v().validate("storage.googleapis.com", "Domain", explicit_malicious=True)
    assert res.valid
    assert res.status == "SHARED-PLATFORM"


def test_github_shared_platform():
    res = v().validate("raw.githubusercontent.com", "Domain", explicit_malicious=True)
    assert res.valid and res.status == "SHARED-PLATFORM"


def test_placeholder_hash_rejected():
    res = v().validate("44d88612fea8a8f36de82e1278abb02f", "MD5", explicit_malicious=True)
    assert not res.valid


def test_valid_domain_accepted():
    res = v().validate("malicious-c2-host.xyz", "Domain", explicit_malicious=True)
    assert res.valid and res.status == "VALID"


def test_cdn_domain_shared():
    res = v().validate("cdn.jsdelivr.net", "Domain", explicit_malicious=True)
    assert res.valid and res.status == "SHARED-PLATFORM"


def test_valid_sha256():
    h = "0badf00d" * 8
    res = v().validate(h, "SHA256", explicit_malicious=True)
    assert res.valid and res.status == "VALID"
