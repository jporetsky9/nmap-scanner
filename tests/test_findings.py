from datetime import date

from scanner import findings
from scanner.runner import HostResult, PortResult

TODAY = date(2026, 6, 1)

CIPHERS_OLD = """TLSv1.0: 
    ciphers: 
      TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 2048) - C
  TLSv1.2: 
    ciphers: 
      TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (secp256r1) - A
  least strength: C"""

CIPHERS_MODERN = """TLSv1.2: 
    ciphers: 
      TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (secp256r1) - A
  TLSv1.3: 
    ciphers: 
      TLS_AKE_WITH_AES_128_GCM_SHA256 (ecdh_x25519) - A
  least strength: A"""


def checks(port, host="10.0.0.5"):
    return {f.check: f for f in findings.check_port(host, port, TODAY)}


def test_legacy_tls_and_weak_ciphers_are_flagged():
    port = PortResult(443, "tcp", "open", "https", scripts={"ssl-enum-ciphers": CIPHERS_OLD})
    found = checks(port)
    assert found[findings.OLD_TLS].detail == "TLSv1.0"
    assert found[findings.WEAK_CIPHERS].severity == "medium"
    assert findings.OLD_SSL not in found


def test_modern_tls_has_no_findings():
    port = PortResult(443, "tcp", "open", "https", scripts={"ssl-enum-ciphers": CIPHERS_MODERN})
    assert checks(port) == {}


def test_sslv3_is_high_severity():
    port = PortResult(443, "tcp", "open", "https",
                      scripts={"ssl-enum-ciphers": "SSLv3: \n  least strength: F"})
    found = checks(port)
    assert found[findings.OLD_SSL].severity == "high"
    assert found[findings.WEAK_CIPHERS].severity == "high"


def test_certificate_expiry():
    expired = PortResult(443, "tcp", "open", "https",
                         scripts={"ssl-cert": "Not valid after:  2026-05-01T00:00:00"})
    soon = PortResult(443, "tcp", "open", "https",
                      scripts={"ssl-cert": "Not valid after:  2026-06-20T00:00:00"})
    later = PortResult(443, "tcp", "open", "https",
                       scripts={"ssl-cert": "Not valid after:  2027-06-20T00:00:00"})
    assert findings.CERT_EXPIRED in checks(expired)
    assert findings.CERT_EXPIRING in checks(soon)
    assert checks(later) == {}


def test_missing_hsts_only_flagged_on_tls_ports():
    headers = "Server: nginx\n  Content-Type: text/html\n  (Request type: HEAD)"
    https = PortResult(443, "tcp", "open", "http", tunnel="ssl", scripts={"http-headers": headers})
    plain = PortResult(80, "tcp", "open", "http", scripts={"http-headers": headers})
    assert findings.NO_HSTS in checks(https)
    assert checks(plain) == {}

    with_hsts = headers + "\n  Strict-Transport-Security: max-age=31536000"
    https.scripts["http-headers"] = with_hsts
    assert checks(https) == {}


def test_smtp_without_starttls():
    no_tls = PortResult(25, "tcp", "open", "smtp",
                        scripts={"smtp-commands": "mail.lab.test, PIPELINING, SIZE 10240000, 8BITMIME"})
    with_tls = PortResult(25, "tcp", "open", "smtp",
                          scripts={"smtp-commands": "mail.lab.test, PIPELINING, STARTTLS, 8BITMIME"})
    assert findings.NO_STARTTLS in checks(no_tls)
    assert checks(with_tls) == {}


def test_closed_ports_are_skipped_and_hosts_are_compared():
    weak = {"ssl-enum-ciphers": CIPHERS_OLD}
    results = [
        HostResult("10.0.0.1", "up", [PortResult(443, "tcp", "open", "https", scripts=weak)]),
        HostResult("10.0.0.2", "up", [PortResult(443, "tcp", "open", "https", scripts=weak)]),
        HostResult("10.0.0.3", "up", [PortResult(443, "tcp", "closed", "https", scripts=weak)]),
    ]
    found = findings.find_issues(results, TODAY)
    per_check = findings.hosts_per_check(found)
    assert per_check[findings.OLD_TLS] == {"10.0.0.1", "10.0.0.2"}
    assert found[0].severity == "medium"


def test_render_findings_lists_and_compares(capsys):
    from scanner import report

    weak = {"ssl-enum-ciphers": CIPHERS_OLD}
    results = [HostResult("10.0.0.1", "up", [PortResult(443, "tcp", "open", "https", scripts=weak)]),
               HostResult("10.0.0.2", "up")]
    text = report.render_findings(findings.find_issues(results, TODAY), results)
    assert "MEDIUM" in text and "10.0.0.1" in text
    assert "Hosts affected (of 2 up):" in text
    assert report.render_findings([], results).startswith("Findings: none")
