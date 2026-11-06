"""Flag common TLS, HTTP, and mail misconfigurations from NSE script output.

These are heuristic checks on the text that nmap's scripts return. They point to
things worth reviewing; confirm each one before reporting it.

Each check only runs when the script it needs was part of the scan (for example,
the HSTS check needs http-headers), so a missing script never produces a finding.
"""
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import date

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}
EXPIRY_WARNING_DAYS = 30

_PROTOCOL_RE = re.compile(r"^\s*(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1):\s*$", re.MULTILINE)
_LEAST_STRENGTH_RE = re.compile(r"least strength:\s*([A-F])")
_NOT_AFTER_RE = re.compile(r"Not valid after:\s*(\d{4}-\d{2}-\d{2})")
_HSTS_RE = re.compile(r"^\s*Strict-Transport-Security:", re.IGNORECASE | re.MULTILINE)

# Check names, used to group results across hosts.
OLD_SSL = "SSLv2/SSLv3 enabled"
OLD_TLS = "TLS 1.0/1.1 enabled"
WEAK_CIPHERS = "Weak cipher suites offered"
CERT_EXPIRED = "Certificate expired"
CERT_EXPIRING = f"Certificate expires within {EXPIRY_WARNING_DAYS} days"
NO_HSTS = "HTTPS without HSTS header"
NO_STARTTLS = "SMTP without STARTTLS"


@dataclass
class Finding:
    host: str
    port: str  # e.g. "443/tcp"
    severity: str  # "high", "medium", or "low"
    check: str
    detail: str


def _uses_tls(port):
    return (
        port.tunnel == "ssl"
        or port.service in ("https", "imaps", "pop3s", "smtps")
        or "ssl-cert" in port.scripts
        or "ssl-enum-ciphers" in port.scripts
    )


def check_port(host, port, today=None):
    """Return the findings for one open port."""
    today = today or date.today()
    label = f"{port.port}/{port.protocol}"
    found = []

    def add(severity, check, detail):
        found.append(Finding(host, label, severity, check, detail))

    ciphers = port.scripts.get("ssl-enum-ciphers")
    if ciphers:
        protocols = _PROTOCOL_RE.findall(ciphers)
        old_ssl = [p for p in protocols if p.startswith("SSL")]
        old_tls = [p for p in protocols if p.startswith("TLS")]
        if old_ssl:
            add("high", OLD_SSL, ", ".join(old_ssl))
        if old_tls:
            add("medium", OLD_TLS, ", ".join(old_tls))
        grade = _LEAST_STRENGTH_RE.search(ciphers)
        if grade and grade.group(1) >= "C":
            severity = "medium" if grade.group(1) == "C" else "high"
            add(severity, WEAK_CIPHERS, f"weakest cipher graded {grade.group(1)}")

    cert = port.scripts.get("ssl-cert")
    if cert:
        match = _NOT_AFTER_RE.search(cert)
        if match:
            try:
                not_after = date.fromisoformat(match.group(1))
            except ValueError:
                not_after = None
            if not_after and not_after < today:
                add("high", CERT_EXPIRED, f"expired {not_after}")
            elif not_after and (not_after - today).days <= EXPIRY_WARNING_DAYS:
                add("low", CERT_EXPIRING, f"expires {not_after}")

    headers = port.scripts.get("http-headers")
    if headers and _uses_tls(port) and not _HSTS_RE.search(headers):
        add("low", NO_HSTS, "no Strict-Transport-Security header")

    smtp = port.scripts.get("smtp-commands")
    if smtp and port.port in (25, 587) and "STARTTLS" not in smtp.upper():
        add("medium", NO_STARTTLS, "server does not advertise STARTTLS")

    return found


def find_issues(results, today=None):
    """Run every check on every open port, most severe first."""
    found = [
        finding
        for result in results
        for port in result.ports
        if port.state == "open"
        for finding in check_port(result.host, port, today)
    ]
    return sorted(found, key=lambda f: (SEVERITY_ORDER[f.severity], f.check, f.host))


def hosts_per_check(findings):
    """Map each check to the set of hosts it was found on (for comparing hosts)."""
    hosts = defaultdict(set)
    for finding in findings:
        hosts[finding.check].add(finding.host)
    return hosts
