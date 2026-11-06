import subprocess
from pathlib import Path

import pytest

from scanner import runner

FIXTURE = (Path(__file__).parent / "fixtures" / "sample_scan.xml").read_text()


def test_build_command_is_an_argument_list_with_target_last():
    command = runner.build_command("10.0.0.5", ports="80,443", scripts="http-title,ssl-cert")
    assert command == [
        "nmap", "-sV", "-oX", "-", "-p", "80,443", "--script", "http-title,ssl-cert", "10.0.0.5",
    ]


@pytest.mark.parametrize("bad", ["80; rm -rf /", "80,,443", "-oN", "http", "80-"])
def test_invalid_ports_are_rejected(bad):
    with pytest.raises(ValueError):
        runner.validate_ports(bad)


@pytest.mark.parametrize("bad", ["http-title; id", "$(whoami)", "-oN x", "A B", "a,,b"])
def test_invalid_scripts_are_rejected(bad):
    with pytest.raises(ValueError):
        runner.validate_scripts(bad)


def test_parse_nmap_xml():
    result = runner.parse_nmap_xml(FIXTURE, "192.168.1.10")

    assert result.status == "up"
    assert [(p.port, p.state) for p in result.ports] == [
        (22, "open"), (25, "closed"), (80, "open"), (443, "open"),
    ]
    ssh = result.ports[0]
    assert (ssh.service, ssh.version_string()) == ("ssh", "OpenSSH 8.9p1")
    assert result.ports[2].scripts == {"http-title": "Welcome to nginx!"}
    assert "commonName=lab.example.test" in result.ports[3].scripts["ssl-cert"]


def test_ipv6_target_adds_dash_6():
    assert "-6" in runner.build_command("fd00::5")
    assert "-6" not in runner.build_command("10.0.0.5")


def test_no_ping_adds_pn():
    assert "-Pn" in runner.build_command("10.0.0.5", no_ping=True)
    assert "-Pn" not in runner.build_command("10.0.0.5")


def test_unresolved_hostname_is_an_error_not_down():
    xml = ('<?xml version="1.0"?><nmaprun><runstats>'
           '<hosts up="0" down="0" total="0"/></runstats></nmaprun>')
    result = runner.parse_nmap_xml(xml, "nope.invalid")
    assert result.status == "error"
    assert "resolved" in result.error


def test_down_host_with_runstats_is_down():
    xml = ('<?xml version="1.0"?><nmaprun><runstats>'
           '<hosts up="0" down="1" total="1"/></runstats></nmaprun>')
    assert runner.parse_nmap_xml(xml, "10.0.0.9").status == "down"


def test_tunnel_attribute_is_parsed():
    xml = ('<nmaprun><host><status state="up"/><ports><port protocol="tcp" portid="443">'
           '<state state="open"/><service name="http" tunnel="ssl"/></port></ports></host></nmaprun>')
    port = runner.parse_nmap_xml(xml, "10.0.0.5").ports[0]
    assert port.service_label() == "ssl/http"


def test_host_with_no_results_is_down():
    xml = '<?xml version="1.0"?><nmaprun></nmaprun>'
    assert runner.parse_nmap_xml(xml, "10.0.0.9").status == "down"


def completed(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


def test_run_scan_success(monkeypatch):
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **k: completed(stdout=FIXTURE))
    assert runner.run_scan("192.168.1.10").status == "up"


def test_run_scan_never_uses_a_shell(monkeypatch):
    seen = {}

    def fake_run(command, **kwargs):
        seen.update(kwargs, command=command)
        return completed(stdout=FIXTURE)

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    runner.run_scan("192.168.1.10")
    assert isinstance(seen["command"], list)
    assert not seen.get("shell")


def test_run_scan_reports_nonzero_exit(monkeypatch):
    monkeypatch.setattr(
        runner.subprocess, "run", lambda *a, **k: completed(2, stderr="Failed to resolve host")
    )
    result = runner.run_scan("nope.invalid")
    assert result.status == "error"
    assert "Failed to resolve" in result.error


def test_run_scan_reports_timeout(monkeypatch):
    def timeout(*a, **k):
        raise subprocess.TimeoutExpired(cmd="nmap", timeout=1)

    monkeypatch.setattr(runner.subprocess, "run", timeout)
    assert "timed out" in runner.run_scan("10.0.0.1", timeout=1).error


def test_run_scan_reports_bad_xml(monkeypatch):
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **k: completed(stdout="<oops"))
    assert runner.run_scan("10.0.0.1").status == "error"


def test_scan_all_keeps_input_order_and_reports_progress(monkeypatch):
    def fake_run_scan(host, *args, **kwargs):
        return runner.HostResult(host, "up")

    monkeypatch.setattr(runner, "run_scan", fake_run_scan)
    seen = []
    hosts = [f"10.0.0.{i}" for i in range(1, 9)]
    results = runner.scan_all(hosts, threads=4, progress=lambda d, t, h: seen.append((d, t)))

    assert [r.host for r in results] == hosts
    assert sorted(seen) == [(i, 8) for i in range(1, 9)]
