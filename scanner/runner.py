"""Run nmap against hosts in parallel and parse its XML output."""
import re
import subprocess
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

PORTS_RE = re.compile(r"^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$")
SCRIPTS_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]*(,[a-z0-9][a-z0-9_.-]*)*$")

# Convenience presets that cover common web and mail service checks.
PRESETS = {
    "web": {
        "ports": "80,443,8080,8443",
        "scripts": "http-title,http-headers,ssl-cert,ssl-enum-ciphers",
    },
    "mail": {
        "ports": "25,110,143,465,587,993,995",
        "scripts": "smtp-commands,ssl-cert,ssl-enum-ciphers,banner",
    },
}


@dataclass
class PortResult:
    port: int
    protocol: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""
    scripts: dict = field(default_factory=dict)

    def version_string(self):
        return f"{self.product} {self.version}".strip()


@dataclass
class HostResult:
    host: str
    status: str  # "up", "down", or "error"
    ports: list = field(default_factory=list)
    error: str = ""


def validate_ports(ports):
    if ports and not PORTS_RE.match(ports):
        raise ValueError(f"invalid port list: {ports!r} (example: 22,80,443 or 1-1024)")
    return ports


def validate_scripts(scripts):
    if scripts and not SCRIPTS_RE.match(scripts):
        raise ValueError(f"invalid script list: {scripts!r} (example: http-title,ssl-cert)")
    return scripts


def build_command(host, ports=None, scripts=None, nmap_path="nmap"):
    """Build the nmap argument list. It is passed as a list, never through a shell."""
    command = [nmap_path, "-sV", "-oX", "-"]
    if ports:
        command += ["-p", validate_ports(ports)]
    if scripts:
        command += ["--script", validate_scripts(scripts)]
    command.append(host)
    return command


def parse_nmap_xml(xml_text, target):
    """Convert nmap XML for a single-target scan into a HostResult."""
    root = ET.fromstring(xml_text)
    host_el = root.find("host")
    if host_el is None:
        return HostResult(target, "down")

    status_el = host_el.find("status")
    status = status_el.get("state", "up") if status_el is not None else "up"

    ports = []
    for port_el in host_el.findall("./ports/port"):
        state_el = port_el.find("state")
        service_el = port_el.find("service")
        service = service_el.attrib if service_el is not None else {}
        ports.append(
            PortResult(
                port=int(port_el.get("portid")),
                protocol=port_el.get("protocol", "tcp"),
                state=state_el.get("state", "unknown") if state_el is not None else "unknown",
                service=service.get("name", ""),
                product=service.get("product", ""),
                version=service.get("version", ""),
                scripts={
                    s.get("id", ""): s.get("output", "").strip()
                    for s in port_el.findall("script")
                },
            )
        )
    return HostResult(target, status, ports)


def run_scan(host, ports=None, scripts=None, timeout=300, nmap_path="nmap"):
    """Scan one host. Failures become an 'error' result instead of an exception."""
    command = build_command(host, ports, scripts, nmap_path)
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired:
        return HostResult(host, "error", error=f"timed out after {timeout}s")
    except OSError as err:
        return HostResult(host, "error", error=f"could not run nmap: {err}")

    if completed.returncode != 0:
        message = completed.stderr.strip().splitlines()[-1:] or ["nmap failed"]
        return HostResult(host, "error", error=message[0][:200])

    try:
        return parse_nmap_xml(completed.stdout, host)
    except ET.ParseError as err:
        return HostResult(host, "error", error=f"could not parse nmap output: {err}")


def scan_all(hosts, threads=4, ports=None, scripts=None, timeout=300,
             nmap_path="nmap", progress=None):
    """Scan hosts concurrently (one nmap process per host); results keep input order."""
    results = {}
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {
            pool.submit(run_scan, host, ports, scripts, timeout, nmap_path): host
            for host in hosts
        }
        for done, future in enumerate(as_completed(futures), start=1):
            host = futures[future]
            results[host] = future.result()
            if progress:
                progress(done, len(hosts), host)
    return [results[host] for host in hosts]
