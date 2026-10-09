from pathlib import Path

from iocbot.extract import extract, refang
from iocbot.normalize import norm_domain, norm_ip, norm_value


def test_refang():
    assert refang("hxxps://example[.]com/a") == "https://example.com/a"
    assert refang("1.2.3[.]4") == "1.2.3.4"
    assert refang("evil(.)com") == "evil.com"


def test_extract_url_and_domain_and_ip():
    text = "We observed http://evil-c2[.]example-port.net:8443/gate.php serving the payload from 203.0.113.9."
    vals = {(m.value, m.ioc_type) for m in extract(text)}
    assert ("http://evil-c2.example-port.net:8443/gate.php", "URL") in vals
    assert ("evil-c2.example-port.net", "Domain") in vals
    assert ("203.0.113.9", "IPv4") in vals


def test_extract_hash_and_cve():
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    text = f"sha256 {sha256} for eicar, md5 44d88612fea8a8f36de82e1278abb02f, CVE-2024-12345 exploited."
    vals = {(m.value, m.ioc_type) for m in extract(text)}
    assert (sha256, "SHA256") in vals
    assert ("44d88612fea8a8f36de82e1278abb02f", "MD5") in vals
    assert ("CVE-2024-12345", "CVE") in vals


def test_filename_before_domain_ignored():
    text = "The installer is setup_v3.2.exe dropped in C:\\Users\\Public\\Downloads\\app.exe."
    types = {m.ioc_type for m in extract(text)}
    assert "Domain" not in types


def test_invalid_ip_not_extracted_but_private_kept_for_validator():
    text = "callback to 192.168.1.10 and 10.0.0.5 and 999.1.1.1"
    ips = [m.value for m in extract(text) if m.ioc_type == "IPv4"]
    assert "999.1.1.1" not in ips
    # private IPs survive extraction and are rejected later by Validator
    from iocbot.validate import Validator

    val = Validator(Path(__file__).resolve().parent.parent / "config" / "validation.yaml")
    assert not val.validate("192.168.1.10", "IPv4", explicit_malicious=True).valid
    assert not val.validate("10.0.0.5", "IPv4", explicit_malicious=True).valid


def test_port_split_keeps_url():
    text = "C2 at hxxps://bad-host[.]xyz:8080/beacon"
    vals = {(m.value, m.ioc_type) for m in extract(text)}
    assert ("https://bad-host.xyz:8080/beacon", "URL") in vals
    assert ("bad-host.xyz", "Domain") in vals


def test_ipv6_not_confused_with_timestamp():
    text = "observed at 2024-01-01 12:00:00 traffic from 2001:db8::1"
    types = [m.ioc_type for m in extract(text)]
    assert "IPv6" not in types or any(
        m.value == "2001:db8::1" for m in extract(text)
    )


def test_norm_domain_strips_www_and_case():
    assert norm_domain("WWW.Example.COM") == "example.com"
    assert norm_value("WWW.Example.COM", "Domain") == "example.com"


def test_norm_ip_and_hash():
    assert norm_ip("203.0.113.9") == "203.0.113.9"
    assert norm_value("ABCDEF1234", "MD5") == "abcdef1234"
